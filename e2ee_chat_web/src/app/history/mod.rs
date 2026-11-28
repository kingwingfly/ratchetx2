//! Browser session-history integration for opening and closing chats.
//!
//! Entering a chat stamps chat-list entries with an opaque session-scoped list token and pushes a
//! single same-URL chat entry with an opaque session-scoped chat token so mobile "go back"
//! gestures (and browser Back) return to the chat list instead of closing or leaving the site,
//! without putting peer identity keys into URLs or persistent history state.
//!
//! Pure navigation transitions live in [`machine`]; this module holds the thin Leptos/DOM adapter.

mod machine;
#[cfg(test)]
mod tests;

use std::{cell::RefCell, time::Duration};

use leptos::{ev, prelude::*, task::spawn_local};
use session::PublicKey;
use wasm_bindgen::JsValue;

use crate::{
    engine::OpenOutcome,
    state::{Dialog, Phase, Ui},
    util::hex,
};

use self::machine::{ChatEntry, ChatHistory, HistoryOp, UiAction};
use super::{engine, media::cancel_pending_previews, ui};

pub(super) use self::machine::Reservation;

/// Time to wait for `popstate` after a programmatic `history.back()` before assuming the browser
/// silently ignored it (e.g. Chromium history rate-limiting) and recovering directly.
const BACK_SETTLE_TIMEOUT: Duration = Duration::from_millis(500);

fn fallback_session_bytes(now_ms: u64, mono_ms: u64, counter: u64) -> [u8; 8] {
    let mut z = now_ms
        .wrapping_add(mono_ms.rotate_left(21))
        .wrapping_add(counter.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        .wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    if z == 0 {
        z = 1;
    }
    z.to_le_bytes()
}

fn random_session_id() -> String {
    use std::cell::Cell;
    thread_local! {
        static FALLBACK_SEQ: Cell<u64> = const { Cell::new(0) };
    }
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() || bytes == [0u8; 8] {
        let seq = FALLBACK_SEQ.with(|c| {
            let next = c.get().wrapping_add(1);
            c.set(next);
            next
        });
        bytes = fallback_session_bytes(crate::util::now(), crate::util::monotonic_now_ms(), seq);
    }
    hex(&bytes)
}

fn current_history_state() -> Option<String> {
    window()
        .history()
        .ok()
        .and_then(|history| history.state().ok())
        .and_then(|value| value.as_string())
}

fn current_location_hash() -> String {
    window().location().hash().unwrap_or_default()
}

thread_local! {
    static CHAT_HISTORY: RefCell<ChatHistory> = RefCell::new(ChatHistory::new(
        random_session_id(),
        current_history_state().as_deref(),
        current_location_hash(),
    ));
}

fn is_closing() -> bool {
    crate::glue::lock_released() || super::is_shutting_down()
}

fn apply_history_op(op: &HistoryOp, current_hash: &str) -> bool {
    if is_closing() {
        return false;
    }
    let Ok(history) = window().history() else {
        return false;
    };
    match op {
        HistoryOp::Push {
            tag_list,
            chat_token,
        } => {
            if let Some(list_token) = tag_list {
                let tagged = history
                    .replace_state_with_url(&JsValue::from_str(list_token), "", None)
                    .is_ok()
                    && current_history_state().as_deref() == Some(list_token.as_str());
                if !tagged {
                    CHAT_HISTORY.with(|state| state.borrow_mut().on_list_tag_failed(current_hash));
                }
            }
            history
                .push_state_with_url(&JsValue::from_str(chat_token), "", None)
                .is_ok()
                && current_history_state().as_deref() == Some(chat_token.as_str())
        }
        HistoryOp::Replace(token) | HistoryOp::Tag(token) => {
            history
                .replace_state_with_url(&JsValue::from_str(token), "", None)
                .is_ok()
                && current_history_state().as_deref() == Some(token.as_str())
        }
        HistoryOp::Back(_) => history.back().is_ok(),
    }
}

/// Dismiss chat-scoped overlays (file viewer and per-chat dialogs for any peer other than
/// `keep_peer`) and invalidate pending file previews so closing or switching chats never leaves
/// stale modals or late-arriving previews over the new view.
fn close_chat_overlays(ui: Ui, keep_peer: Option<PublicKey>) {
    cancel_pending_previews();
    if ui.viewer.with_untracked(Option::is_some) {
        ui.viewer.set(None);
    }
    if ui.opening.with_untracked(Option::is_some) {
        ui.opening.set(None);
    }
    if ui.streaming.with_untracked(Option::is_some) {
        ui.streaming.set(None);
    }
    let stale_dialog = ui.dialog.with_untracked(|dialog| {
        matches!(
            dialog,
            Some(Dialog::Contact(peer) | Dialog::Files(peer) | Dialog::ShareContact(peer))
                if Some(*peer) != keep_peer
        )
    });
    if stale_dialog {
        ui.dialog.set(None);
    }
}

/// Immediately return to the chat list without waiting for the engine mutex.
fn close_chat_immediately(ui: Ui) {
    close_chat_overlays(ui, None);
    engine().close_chat();
}

/// Synchronously cancel any active startup submission (suppressing late 403 sign-in prompts or
/// greetings), mark sign-in prompts declined when backing out of `Dialog::SignIn`, and dismiss a
/// currently displayed `NewChat` / `SignIn` modal.
fn dismiss_startup_dialog(ui: Ui) {
    engine().cancel_active_startup_submission();
    let (startup, was_sign_in) = ui.dialog.with_untracked(|dialog| {
        (
            matches!(dialog, Some(Dialog::NewChat { .. } | Dialog::SignIn)),
            matches!(dialog, Some(Dialog::SignIn)),
        )
    });
    if was_sign_in {
        engine().decline_sign_in_prompts();
    }
    if startup {
        ui.dialog.set(None);
    }
}

/// Apply `op` (if any), verifying synchronous writes against `fallback_active` and scheduling
/// timeout recovery for programmatic `history.back()`. Returns any recovery [`UiAction`] if
/// `history.back()` failed synchronously.
fn execute_history_op(
    op: Option<&HistoryOp>,
    fallback_active: Option<ChatEntry>,
    current_hash: &str,
    ui: Ui,
) -> Option<UiAction> {
    if is_closing() {
        return None;
    }
    let op = op?;
    if apply_history_op(op, current_hash) {
        if let HistoryOp::Back(attempt) = *op {
            schedule_back_recovery(attempt, ui);
        }
        return None;
    }
    match op {
        HistoryOp::Push { .. } | HistoryOp::Replace(_) | HistoryOp::Tag(_) => {
            CHAT_HISTORY.with(|history| {
                history
                    .borrow_mut()
                    .on_write_failed(op, fallback_active, current_hash);
            });
            None
        }
        HistoryOp::Back(attempt) => recover_aborted_back(*attempt, ui),
    }
}

fn schedule_back_recovery(attempt: u64, ui: Ui) {
    set_timeout(
        move || {
            if is_closing() {
                return;
            }
            if let Some(action) = recover_aborted_back(attempt, ui) {
                execute_ui_action(action, false, ui);
            }
        },
        BACK_SETTLE_TIMEOUT,
    );
}

fn recover_aborted_back(attempt: u64, ui: Ui) -> Option<UiAction> {
    let raw = current_history_state();
    let hash = current_location_hash();
    let transition = CHAT_HISTORY.with(|history| {
        history
            .borrow_mut()
            .on_back_aborted(attempt, raw.as_deref(), &hash, |peer| {
                ui.contact(peer).is_some()
            })
    });
    if let Some(op) = transition.history.as_ref()
        && !matches!(op, HistoryOp::Back(_))
        && !apply_history_op(op, &hash)
    {
        CHAT_HISTORY.with(|history| {
            history
                .borrow_mut()
                .on_write_failed(op, transition.fallback_active, &hash);
        });
    }
    (transition.ui != UiAction::None).then_some(transition.ui)
}

fn execute_ui_action(action: UiAction, dismiss_startup: bool, ui: Ui) {
    if dismiss_startup {
        dismiss_startup_dialog(ui);
    }
    match action {
        UiAction::None => {}
        UiAction::Close => close_chat_immediately(ui),
        UiAction::Open(peer) => {
            // Skip redundant reloads only when `peer` is already displayed AND no conflicting
            // open for another peer is waiting on the engine mutex.
            if !engine().is_settled_on(peer) {
                if ui.open.get_untracked() != Some(peer) {
                    cancel_pending_previews();
                }
                spawn_local(open_and_reconcile(peer));
            }
        }
    }
}

async fn open_and_reconcile(peer: PublicKey) {
    let outcome = engine().open(Some(peer)).await;
    if outcome == OpenOutcome::Ignored {
        let ui = ui();
        let actual_open = ui.open.get_untracked();
        let hash = current_location_hash();
        let transition =
            CHAT_HISTORY.with(|history| history.borrow_mut().on_open_failed(peer, actual_open));
        if let Some(action) = execute_history_op(
            transition.history.as_ref(),
            transition.fallback_active,
            &hash,
            ui,
        ) {
            execute_ui_action(action, false, ui);
        }
    }
}

fn tag_current_list_entry(ui: Ui, hash: &str) {
    let op = CHAT_HISTORY.with(|history| history.borrow_mut().tag_current_list_entry());
    let _ = execute_history_op(op.as_ref(), None, hash, ui);
}

/// Wire up browser `popstate` handling and peer-change / external-close reconciliation (such as
/// deleting the open chat or dismissing stale overlays when switching peers). Call once when
/// mounting [`App`](super::App).
pub(super) fn install(ui: Ui) {
    let initial_hash = current_location_hash();
    tag_current_list_entry(ui, &initial_hash);

    let _ = window_event_listener(ev::popstate, move |event: ev::PopStateEvent| {
        if is_closing() {
            return;
        }
        let raw = event.state().as_string();
        let hash = current_location_hash();
        if ui.phase.get_untracked() != Phase::Unlocked {
            let op = CHAT_HISTORY
                .with(|history| history.borrow_mut().on_locked_popstate(raw.as_deref()));
            let _ = execute_history_op(op.as_ref(), None, &hash, ui);
            return;
        }
        let startup_dialog_open = ui.dialog.with_untracked(|dialog| {
            matches!(dialog, Some(Dialog::NewChat { .. } | Dialog::SignIn))
        });
        let transition = CHAT_HISTORY.with(|history| {
            history
                .borrow_mut()
                .on_popstate(raw.as_deref(), &hash, startup_dialog_open, |peer| {
                    ui.contact(peer).is_some()
                })
        });
        let recovery = execute_history_op(
            transition.history.as_ref(),
            transition.fallback_active,
            &hash,
            ui,
        );
        execute_ui_action(
            recovery.unwrap_or(transition.ui),
            transition.dismiss_startup,
            ui,
        );
    });

    Effect::new(move |prev_open: Option<Option<PublicKey>>| {
        let current = ui.open.get();
        if is_closing() {
            return current;
        }
        if let Some(Some(prev_peer)) = prev_open
            && current != Some(prev_peer)
        {
            // Clear the previous chat's viewer/contact/files overlays on both `Some(A) -> None`
            // and `Some(A) -> Some(B)` transitions.
            close_chat_overlays(ui, current);
            if current.is_none() {
                let hash = current_location_hash();
                let op = CHAT_HISTORY.with(|history| history.borrow_mut().on_ui_closed(prev_peer));
                if let Some(action) = execute_history_op(op.as_ref(), None, &hash, ui) {
                    execute_ui_action(action, false, ui);
                }
            }
        }
        current
    });

    Effect::new(move |prev_startup: Option<bool>| {
        let is_startup = ui
            .dialog
            .with(|dialog| matches!(dialog, Some(Dialog::NewChat { .. } | Dialog::SignIn)));
        if is_closing() {
            return is_startup;
        }
        if prev_startup == Some(true) && !is_startup {
            // A startup modal closed without committing a chat: unwind any retained
            // (`ReservationOwner::Retained`) history slot back to the chat list.
            cancel_retained_reservation();
        }
        is_startup
    });

    Effect::new(move || {
        if let Some((_, peer)) = ui.deleted_peer.get() {
            forget_peer(peer);
        }
    });
}

/// Invalidate all Forward chat tokens and fragment markers for a deleted peer (even if the user
/// already navigated back to the list before deletion committed).
pub(super) fn forget_peer(peer: PublicKey) {
    CHAT_HISTORY.with(|history| history.borrow_mut().on_peer_deleted(peer));
}

/// Reserve a chat-level history entry during a form submit gesture (`NewChat` or `SignIn`
/// auto-start), returning the [`Reservation`] handle to pass to [`commit_reservation`] or
/// [`cancel_reservation`].
pub(super) fn reserve() -> Reservation {
    let hash = current_location_hash();
    let (reservation, op) = CHAT_HISTORY.with(|history| history.borrow_mut().reserve(&hash));
    if let Some(op) = op
        && !apply_history_op(&op, &hash)
    {
        return CHAT_HISTORY
            .with(|history| history.borrow_mut().on_reserve_push_failed(&op, &hash));
    }
    reservation
}

/// Whether `reservation` is still owned by the submission that created it.
pub(super) fn is_reservation_owned(reservation: Option<Reservation>) -> bool {
    CHAT_HISTORY.with(|history| history.borrow().is_reservation_owned(reservation))
}

/// Commit a reserved chat entry to `peer` (honoring any Back, Forward, native dismissal, or newer
/// navigation that happened while startup waited on the relay) and open `peer`.
pub(super) async fn commit_reservation(reservation: Option<Reservation>, peer: PublicKey) {
    let ui = ui();
    let hash = current_location_hash();
    let transition = CHAT_HISTORY.with(|history| {
        history
            .borrow_mut()
            .commit_reservation(reservation, peer, &hash)
    });
    let recovery = execute_history_op(
        transition.history.as_ref(),
        transition.fallback_active,
        &hash,
        ui,
    );
    if transition.dismiss_startup {
        dismiss_startup_dialog(ui);
    }
    match recovery.unwrap_or(transition.ui) {
        UiAction::None => {}
        UiAction::Close => close_chat_immediately(ui),
        UiAction::Open(peer) => {
            if !engine().is_settled_on(peer) {
                if ui.open.get_untracked() != Some(peer) {
                    cancel_pending_previews();
                }
                open_and_reconcile(peer).await;
            }
        }
    }
}

/// Release ownership of a reservation while keeping its gesture-pushed slot retained for a
/// still-open startup modal (`NewChat` retry or `NewChat <-> SignIn` transition).
pub(super) fn retain_reservation(reservation: Option<Reservation>) -> bool {
    CHAT_HISTORY.with(|history| history.borrow_mut().retain_reservation(reservation))
}

/// Revoke any active submission's ownership while keeping a pushed slot retained for a restored
/// startup modal (e.g. dismissing `SignInDialog` back to `NewChat`).
pub(super) fn retain_active_reservation() {
    CHAT_HISTORY.with(|history| history.borrow_mut().retain_active_reservation());
}

/// Unwind an idle retained startup slot (`ReservationOwner::Retained`) back to the chat list when
/// the startup modal closes without starting a chat.
pub(super) fn cancel_retained_reservation() {
    let ui = ui();
    let hash = current_location_hash();
    let op = CHAT_HISTORY.with(|history| history.borrow_mut().cancel_retained_reservation());
    if let Some(action) = execute_history_op(op.as_ref(), None, &hash, ui) {
        execute_ui_action(action, false, ui);
    }
}

/// Release an uncommitted reservation after startup is cancelled or closes without opening a chat.
/// Returns whether the reservation was still owned by this submission (rather than superseded by
/// Back, Forward, native dismissal, or a newer submission).
pub(super) fn cancel_reservation(reservation: Option<Reservation>) -> bool {
    let ui = ui();
    let hash = current_location_hash();
    let (still_owned, op) =
        CHAT_HISTORY.with(|history| history.borrow_mut().cancel_reservation(reservation));
    if let Some(action) = execute_history_op(op.as_ref(), None, &hash, ui) {
        execute_ui_action(action, false, ui);
    }
    still_owned
}

/// Revoke any currently active startup reservation (e.g. when a native `<dialog>` is dismissed via
/// Escape or an OS close request rather than `popstate`), unwinding a pushed entry to the list.
pub(super) fn cancel_active_reservation() {
    let ui = ui();
    let hash = current_location_hash();
    let op = CHAT_HISTORY.with(|history| history.borrow_mut().cancel_active_reservation());
    if let Some(action) = execute_history_op(op.as_ref(), None, &hash, ui) {
        execute_ui_action(action, false, ui);
    }
}

/// Navigate to `peer` (or back to the chat list when `None`), synchronizing browser history
/// synchronously inside the caller's user-gesture event handler.
pub(super) fn navigate(peer: Option<PublicKey>) {
    let ui = ui();
    let hash = current_location_hash();
    if peer.is_none() {
        // Synchronously invalidate any in-flight `Engine::open` (e.g. Bob loading while Alice is
        // displayed) so it cannot open and send read receipts before `history.back()` settles.
        engine().cancel_pending_open();
    }
    let transition = CHAT_HISTORY.with(|history| {
        let mut history = history.borrow_mut();
        match peer {
            Some(peer) => history.user_open(peer, &hash),
            None => history.user_close(),
        }
    });
    let recovery = execute_history_op(
        transition.history.as_ref(),
        transition.fallback_active,
        &hash,
        ui,
    );
    if transition.dismiss_startup {
        dismiss_startup_dialog(ui);
    }
    match recovery.unwrap_or(transition.ui) {
        UiAction::None => {}
        UiAction::Close => close_chat_immediately(ui),
        UiAction::Open(peer) => {
            if !engine().is_settled_on(peer) {
                if ui.open.get_untracked() != Some(peer) {
                    cancel_pending_previews();
                }
                spawn_local(open_and_reconcile(peer));
            }
        }
    }
}

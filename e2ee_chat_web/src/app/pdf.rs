use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    ops::Range,
    rc::Rc,
    sync::Arc,
};

use leptos::{html, prelude::*, task::spawn_local};
use wasm_bindgen::{JsCast, closure::Closure};
use web_sys::{
    CanvasRenderingContext2d, HtmlCanvasElement, IntersectionObserver, IntersectionObserverEntry,
    IntersectionObserverInit,
};

use crate::{util::js_error, workers};

const PDF_PAGE_BUFFER: usize = 2;
const PDF_MAX_ACTIVE_CANVASES: usize = 9;

fn pdf_aspect_ratio(width: f64, height: f64) -> String {
    if width.is_finite() && height.is_finite() && width > 0.0 && height > 0.0 {
        format!("{width} / {height}")
    } else {
        "612 / 792".to_string()
    }
}

/// Keep a buffer around the visible pages, centered on the last anchor during a gap.
fn pdf_active_window(
    total_pages: usize,
    visible: &BTreeSet<usize>,
    anchor: usize,
    buffer: usize,
    max_active: usize,
) -> Range<usize> {
    if total_pages == 0 || max_active == 0 {
        return 0..0;
    }
    let mut valid = visible.range(..total_pages);
    let first = valid.next().copied().unwrap_or(anchor.min(total_pages - 1));
    let last = valid.next_back().copied().unwrap_or(first);
    let start = first.saturating_sub(buffer);
    let end = (last + 1).saturating_add(buffer).min(total_pages);
    if end - start <= max_active {
        return start..end;
    }

    let mid = first + (last - first) / 2;
    let start = mid
        .saturating_sub(max_active / 2)
        .min(total_pages - max_active);
    start..start + max_active
}

/// Every page has a sized slot. A single observer selects the slots that need canvases.
#[component]
pub(super) fn PdfView(data: Arc<Vec<u8>>) -> impl IntoView {
    let container = NodeRef::<html::Div>::new();
    let pdf_handle = StoredValue::new_local(None::<workers::Pdf>);
    let pages = RwSignal::new(Vec::<(usize, f64, f64)>::new());
    let active_window = RwSignal::new(0..0);
    let failed = RwSignal::new(None::<String>);
    let here = StoredValue::new(());

    let observer = StoredValue::new_local(None::<IntersectionObserver>);
    let observer_ready = RwSignal::new(false);
    let visible_pages = Rc::new(RefCell::new(BTreeSet::new()));
    let last_anchor = Rc::new(Cell::new(0));
    let on_intersection = StoredValue::new_local(Closure::<dyn FnMut(js_sys::Array)>::new(
        move |entries: js_sys::Array| {
            let Some(total) = pages.try_with_untracked(Vec::len) else {
                return;
            };
            let mut visible = visible_pages.borrow_mut();
            for entry in entries.iter() {
                let entry: IntersectionObserverEntry = entry.unchecked_into();
                let Some(index) = entry
                    .target()
                    .get_attribute("data-page")
                    .and_then(|s| s.parse::<usize>().ok())
                    .filter(|&index| index < total)
                else {
                    continue;
                };
                if entry.is_intersecting() {
                    visible.insert(index);
                } else {
                    visible.remove(&index);
                }
            }
            if let (Some(&first), Some(&last)) = (visible.first(), visible.last()) {
                last_anchor.set(first + (last - first) / 2);
            }
            let next = pdf_active_window(
                total,
                &visible,
                last_anchor.get(),
                PDF_PAGE_BUFFER,
                PDF_MAX_ACTIVE_CANVASES,
            );
            if active_window.with_untracked(|current| *current != next) {
                active_window.set(next);
            }
        },
    ));
    container.on_load(move |element| {
        let options = IntersectionObserverInit::new();
        let root = element.closest(".viewer-content").ok().flatten();
        options.set_root(root.as_ref());
        options.set_root_margin("200px 0px");
        let result = on_intersection.with_value(|callback| {
            IntersectionObserver::new_with_options(callback.as_ref().unchecked_ref(), &options)
        });
        match result {
            Ok(shared) => {
                observer.set_value(Some(shared));
                observer_ready.set(true);
            }
            Err(e) => failed.set(Some(js_error(e))),
        }
    });

    spawn_local(async move {
        match workers::open_pdf(&data).await {
            Ok((pdf, dims)) => {
                if here.try_get_value().is_none() {
                    workers::close_pdf(pdf);
                    return;
                }
                pdf_handle.set_value(Some(pdf));
                active_window.set(pdf_active_window(
                    dims.len(),
                    &BTreeSet::new(),
                    0,
                    PDF_PAGE_BUFFER,
                    PDF_MAX_ACTIVE_CANVASES,
                ));
                pages.set(
                    dims.into_iter()
                        .enumerate()
                        .map(|(index, (width, height))| (index, width, height))
                        .collect(),
                );
            }
            Err(e) => {
                failed.try_set(Some(e));
            }
        }
    });
    on_cleanup(move || {
        if let Some(shared) = observer.try_update_value(Option::take).flatten() {
            shared.disconnect();
            // Discard pending entries before the callback is dropped.
            shared.take_records();
        }
        if let Some(pdf) = pdf_handle.try_update_value(Option::take).flatten() {
            workers::close_pdf(pdf);
        }
    });
    view! {
        <div class="pdf" node_ref=container>
            <For
                each=move || pages.get()
                key=|(index, _, _)| *index
                children=move |(index, width, height)| {
                    let pdf = pdf_handle.get_value().expect("the PDF is open before its pages are listed");
                    view! {
                        <PdfPageSlot pdf index width height active_window observer observer_ready />
                    }
                }
            />
        </div>
        {move || {
            failed.get().map(|e| view! { <p class="no-preview">{format!("The PDF does not show: {e}")}</p> })
        }}
    }
}

#[component]
fn PdfPageSlot(
    pdf: workers::Pdf,
    index: usize,
    width: f64,
    height: f64,
    active_window: RwSignal<Range<usize>>,
    observer: StoredValue<Option<IntersectionObserver>, LocalStorage>,
    observer_ready: RwSignal<bool>,
) -> impl IntoView {
    let slot_ref = NodeRef::<html::Div>::new();
    let aspect = pdf_aspect_ratio(width, height);
    let is_active = Memo::new(move |_| active_window.with(|w| w.contains(&index)));
    Effect::new(move || {
        if observer_ready.get()
            && let Some(el) = slot_ref.get()
            && let Some(shared) = observer.get_value()
        {
            shared.observe(&el);
        }
    });
    on_cleanup(move || {
        if let Some(el) = slot_ref.try_get_untracked().flatten()
            && let Some(shared) = observer.try_get_value().flatten()
        {
            shared.unobserve(&el);
        }
    });
    view! {
        // A flex item's automatic minimum height can otherwise let the initial canvas
        // dimensions stretch short pages.
        <div
            class="pdf-page"
            node_ref=slot_ref
            style:aspect-ratio=aspect
            style:min-height="0"
            data-page=index.to_string()
        >
            <Show when=move || is_active.get()>
                <PdfPageCanvas pdf index />
            </Show>
        </div>
    }
}

#[component]
fn PdfPageCanvas(pdf: workers::Pdf, index: usize) -> impl IntoView {
    let canvas = NodeRef::<html::Canvas>::new();
    let element = StoredValue::new_local(None::<HtmlCanvasElement>);
    let mounted = StoredValue::new(true);
    let drawn = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);
    Effect::new(move || {
        let Some(canvas_el) = canvas.get() else {
            return;
        };
        element.set_value(Some(canvas_el.clone()));
        let needs_layout = canvas_el.client_width() == 0;
        let render = move || {
            spawn_local(async move {
                if mounted.try_get_value() != Some(true) || !canvas_el.is_connected() {
                    return;
                }
                let result = draw_page(pdf, index, &canvas_el, mounted).await;
                if mounted.try_get_value() == Some(true) && canvas_el.is_connected() {
                    match result {
                        Ok(()) => drawn.set(true),
                        Err(e) => error.set(Some(e)),
                    }
                }
            });
        };
        if needs_layout {
            request_animation_frame(render);
        } else {
            render();
        }
    });
    on_cleanup(move || {
        mounted.try_set_value(false);
        if let Some(el) = element
            .try_update_value(Option::take)
            .flatten()
            .or_else(|| canvas.try_get_untracked().flatten())
        {
            el.set_width(0);
            el.set_height(0);
        }
    });
    view! {
        <canvas
            node_ref=canvas
            style:display="block"
            style:width="100%"
            style:height="100%"
            data-page=index.to_string()
            data-drawn=move || drawn.get().then_some("yes")
            data-error=move || error.get()
        ></canvas>
    }
}

/// Draw page `index` of `pdf` onto `canvas`, as sharp as the screen shows it, at most twice as
/// sharp as CSS pixels.
async fn draw_page(
    pdf: workers::Pdf,
    index: usize,
    canvas: &HtmlCanvasElement,
    mounted: StoredValue<bool>,
) -> Result<(), String> {
    let ratio = web_sys::window()
        .map_or(1.0, |window| window.device_pixel_ratio())
        .min(2.0);
    let width = (f64::from(canvas.client_width()) * ratio).round().max(1.0) as u32;
    let image = workers::render_pdf(pdf, index, width).await?;
    if mounted.try_get_value() != Some(true) || !canvas.is_connected() {
        return Ok(());
    }
    canvas.set_width(image.width());
    canvas.set_height(image.height());
    let context: CanvasRenderingContext2d = canvas
        .get_context("2d")
        .map_err(js_error)?
        .ok_or("no 2D context")?
        .unchecked_into();
    context.put_image_data(&image, 0.0, 0.0).map_err(js_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(
        total: usize,
        visible: impl IntoIterator<Item = usize>,
        anchor: usize,
    ) -> Range<usize> {
        pdf_active_window(
            total,
            &visible.into_iter().collect(),
            anchor,
            PDF_PAGE_BUFFER,
            PDF_MAX_ACTIVE_CANVASES,
        )
    }

    #[test]
    fn empty_document_or_zero_canvas_budget_has_an_empty_window() {
        assert_eq!(window(0, [0], 0), 0..0);
        assert_eq!(pdf_active_window(20, &BTreeSet::from([7]), 7, 2, 0), 0..0);
    }

    #[test]
    fn small_documents_stay_within_their_page_count() {
        assert_eq!(window(1, [], 0), 0..1);
        assert_eq!(window(4, [1, 2], 0), 0..4);
    }

    #[test]
    fn visible_pages_are_buffered_and_clamped_at_either_end() {
        assert_eq!(window(200, [50], 0), 48..53);
        assert_eq!(window(200, [50, 52], 0), 48..55);
        assert_eq!(window(200, [199], 0), 197..200);
        assert_eq!(window(200, [0], 199), 0..3);
    }

    #[test]
    fn many_visible_pages_share_a_capped_window_at_their_midpoint() {
        assert_eq!(window(200, 10..=30, 0), 16..25);
        assert_eq!(window(200, 0..=8, 0), 0..9);
        assert_eq!(window(200, 191..200, 0), 191..200);
    }

    #[test]
    fn gaps_use_the_last_anchor_with_the_same_buffer_and_cap() {
        assert_eq!(window(200, [], 0), 0..3);
        assert_eq!(window(200, [], 50), 48..53);
        assert_eq!(pdf_active_window(200, &BTreeSet::new(), 50, 10, 9), 46..55);
        assert_eq!(
            pdf_active_window(200, &BTreeSet::new(), 199, 10, 9),
            191..200
        );
    }

    #[test]
    fn invalid_indices_and_oversized_buffers_stay_in_bounds() {
        assert_eq!(window(200, [50, 200, usize::MAX], usize::MAX), 48..53);
        assert_eq!(window(200, [200, usize::MAX], 7), 5..10);
        assert_eq!(window(200, [], usize::MAX), 197..200);
        let total = usize::MAX;
        assert_eq!(
            pdf_active_window(total, &BTreeSet::from([total - 1]), total, usize::MAX, 9),
            total - 9..total
        );
    }

    #[test]
    fn page_aspect_ratio_uses_letter_only_for_invalid_dimensions() {
        assert_eq!(pdf_aspect_ratio(595.5, 842.0), "595.5 / 842");
        for invalid in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(pdf_aspect_ratio(invalid, 842.0), "612 / 792");
            assert_eq!(pdf_aspect_ratio(595.5, invalid), "612 / 792");
        }
    }
}

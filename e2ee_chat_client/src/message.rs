/// What a message carries: `protocol::content`, which the web client writes too.
pub use session::protocol::content::{
    self, AttachmentPointer, Content, Events, File, Hello, Kind, stamp,
};
use unicode_width::UnicodeWidthStr;

#[derive(Debug)]
pub struct Message {
    pub content: Kind,
    pub state: MessageState,
    /// Its place in the chat, which both sides show it by: its Lamport clock, see [`Chat`]; 0
    /// if it has none, as it could not be sent.
    pub place: u64,
    /// The clock its sender gave it, which events name it by.
    pub clock: u64,
}

#[derive(Debug, Clone)]
pub enum MessageState {
    /// The server has it: one tick.
    Sent,
    /// The peer read it: two ticks.
    Read,
    /// The peer downloaded its attachment whole, having read it.
    Downloaded,
    /// The peer's; whether the peer was told it is read.
    Received {
        told: bool,
    },
    Error(String),
}

impl MessageState {
    /// Whether it is of a message this client sent.
    pub fn outgoing(&self) -> bool {
        !matches!(self, Self::Received { .. })
    }
}

/// A chat with a peer: its messages, in the order both sides show them, and its Lamport clock.
/// A message's clock is one more than the highest of the chat's so far, both ways, as the web
/// client gives it, so both show a message after what its sender had seen; and a sender's
/// clocks only go up, so events name messages by them.
#[derive(Debug, Default)]
pub struct Chat {
    pub messages: Vec<Message>,
    /// The highest place so far, both ways.
    pub clock: u64,
    /// The place of the peer's last message, which its next goes after.
    pub peer_last: u64,
    /// The highest place of this client's messages that the peer said it read, which its next
    /// message goes after.
    pub read_by_peer: u64,
}

impl Chat {
    /// The clock of a message this client sends now.
    pub fn tick(&mut self) -> u64 {
        self.clock = self.clock.saturating_add(1);
        self.clock
    }

    /// Put `message` where it goes: by place, then by sender, the one with the lower identity
    /// key first, which `mine_first` tells; one without a place last.
    pub fn insert(&mut self, message: Message, mine_first: bool) {
        let key = |message: &Message| {
            (
                message.place == 0,
                message.place,
                message.state.outgoing() != mine_first,
            )
        };
        let at = self
            .messages
            .partition_point(|other| key(other) <= key(&message));
        self.messages.insert(at, message);
    }

    /// The place of the peer's message whose clock is `clock`, as the web client places it: its
    /// clock, but never before the peer's previous message, nor before a message of this
    /// client's that the peer said it read; one without a clock where it came.
    pub fn place_of(&self, clock: u64) -> u64 {
        content::place(clock, self.peer_last.max(self.read_by_peer), self.clock)
    }

    /// Take `content`, the peer's, at its place, and what it tells of this client's messages.
    /// Greetings, which start a session, and kinds this client does not know only move the
    /// clock.
    pub fn receive(&mut self, content: Content, mine_first: bool) {
        if let Some(events) = &content.events {
            self.told(events);
        }
        let Some(kind) = content.kind else {
            return;
        };
        let place = self.place_of(content.clock);
        self.clock = self.clock.max(place);
        self.peer_last = place;
        if !matches!(kind, Kind::Hello(_)) {
            let message = Message {
                content: kind,
                state: MessageState::Received { told: false },
                place,
                clock: content.clock,
            };
            self.insert(message, mine_first);
        }
    }

    /// Take what the peer told of this client's messages, by their places.
    pub fn told(&mut self, events: &Events) {
        for (clocks, downloaded) in [(&events.read, false), (&events.downloaded, true)] {
            for clock in clocks {
                let Some(message) = self
                    .messages
                    .iter_mut()
                    .find(|message| message.state.outgoing() && message.place == *clock)
                else {
                    continue;
                };
                self.read_by_peer = self.read_by_peer.max(*clock);
                message.state = match (&message.state, downloaded) {
                    (MessageState::Sent, false) => MessageState::Read,
                    (MessageState::Sent | MessageState::Read, true) => MessageState::Downloaded,
                    (state, _) => state.clone(),
                };
            }
        }
    }

    /// The clocks of the peer's messages to read that the peer was not told of, now told.
    pub fn read(&mut self) -> Vec<u64> {
        self.messages
            .iter_mut()
            .filter(|message| message.clock > 0 && message.content.is_readable())
            .filter_map(|message| match &mut message.state {
                MessageState::Received { told } if !*told => {
                    *told = true;
                    Some(message.clock)
                }
                _ => None,
            })
            .collect()
    }

    /// The peer was not told of its messages at `clocks` after all.
    pub fn untold(&mut self, clocks: &[u64]) {
        for message in &mut self.messages {
            if let MessageState::Received { told } = &mut message.state
                && clocks.contains(&message.clock)
            {
                *told = false;
            }
        }
    }
}

/// The bytes of a greeting, the session's first message, which shows the peer that the initial
/// message is this client's, and lets the peer write back, at `clock`. This client goes by no
/// name.
pub fn greeting(clock: u64) -> Vec<u8> {
    let mut greeting = Kind::Hello(Hello::default()).to_bytes();
    stamp(&mut greeting, clock);
    greeting
}

impl Message {
    pub fn line_num(&self, width: u16) -> u16 {
        let mut lines = 0;
        match &self.content {
            Kind::Text(text) => {
                for line in text.lines() {
                    lines += line.width_cjk() as u16 / width + 1;
                }
            }
            Kind::Hello(_) | Kind::Deleted(_) => lines += 1,
            Kind::Image(_) => lines += 16,
            // Its name, then its size.
            Kind::File(_) | Kind::Attachment(_) => lines += 2,
        }
        if let MessageState::Error(err) = &self.state {
            lines += err.width_cjk() as u16 / width + 1;
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(text: &str, clock: u64) -> Content {
        Content {
            clock,
            kind: Some(Kind::Text(text.to_string())),
            events: None,
        }
    }

    #[test]
    fn a_chat_shows_by_place_then_sender() {
        let mut chat = Chat::default();
        // This client's key is the lower: at one place, its message goes first.
        let clock = chat.tick();
        chat.insert(
            Message {
                content: Kind::Text("mine".into()),
                state: MessageState::Sent,
                place: clock,
                clock,
            },
            true,
        );
        chat.receive(text("theirs, at once", 1), true);
        chat.receive(text("theirs, after", 2), true);
        let texts: Vec<_> = chat
            .messages
            .iter()
            .map(|message| (message.place, message.state.outgoing()))
            .collect();
        assert_eq!(texts, [(1, true), (1, false), (2, false)]);
        // Backdated, the peer's next goes after its last.
        chat.receive(text("backdated", 1), true);
        assert_eq!(chat.messages.last().unwrap().place, 3);
        assert_eq!(chat.tick(), 4);
    }

    #[test]
    fn events_move_messages_on() {
        let mut chat = Chat::default();
        for _ in 0..2 {
            let clock = chat.tick();
            chat.insert(
                Message {
                    content: Kind::Text("hi".into()),
                    state: MessageState::Sent,
                    place: clock,
                    clock,
                },
                true,
            );
        }
        chat.told(&Events {
            read: vec![1, 9],
            downloaded: vec![2],
        });
        assert!(matches!(chat.messages[0].state, MessageState::Read));
        assert!(matches!(chat.messages[1].state, MessageState::Downloaded));
        assert_eq!(chat.read_by_peer, 2);
        // Told once, unless it did not go.
        chat.receive(text("yours", 3), true);
        assert_eq!(chat.read(), [3]);
        assert!(chat.read().is_empty());
        chat.untold(&[3]);
        assert_eq!(chat.read(), [3]);
    }
}

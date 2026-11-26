//! What a message carries, encrypted: `protocol::content`, which the TUI client reads too, and
//! which drops the kinds it does not know.

#[cfg(test)]
pub use session::protocol::content::File;
pub use session::protocol::content::{
    AttachmentPointer, Contact, Content, Deleted, Events, Kind, place, stamp,
};

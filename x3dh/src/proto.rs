//! [`LocalPrekeys`](crate::LocalPrekeys) as protobuf messages, generated from `proto/x3dh.proto`
//! (package `x3dh.v1`), so other languages can read them.
//!
//! Convert with `proto::LocalPrekeys::from(&prekeys)` and `LocalPrekeys::try_from(&message)`.
//! The messages hold private keys, so keep them secret: they are zeroized on drop, and their
//! `Debug` shows no keys.
use core::fmt;

include!(concat!(env!("OUT_DIR"), "/x3dh.v1.rs"));

impl fmt::Debug for LocalPrekeys {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalPrekeys")
            .field("generations", &self.generations.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Generation {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Generation")
            .field("one_time_prekeys", &self.one_time_prekeys.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for OneTimePrekey {
    /// Shows no keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneTimePrekey").finish_non_exhaustive()
    }
}

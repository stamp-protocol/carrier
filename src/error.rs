//! The main error enum for carrier lives here, and documents the various
//! conditions that can arise while interacting with the library.

use thiserror::Error;

/// This is our error enum. It contains an entry for any part of the system in
/// which an expectation is not met or a problem occurs.
#[derive(Error, Debug)]
pub enum Error {
    /// A packet was encountered that doesn't make any sense
    #[error("invalid packet")]
    PacketInvalid,

    /// A key packet has been tampered with
    #[error("key packet tampered with")]
    KeyPacketTampered,

    /// An error occured in the Stamp protocol itself
    #[error("stamp error: {0}")]
    Stamp(#[from] stamp_core::error::Error),
}

/// Wraps `std::result::Result` around our `Error` enum
pub type Result<T> = std::result::Result<T, Error>;

//! The main error enum for carrier lives here, and documents the various
//! conditions that can arise while interacting with the library.

use crate::{DeviceID, Permission};
use stamp_core::{dag::TransactionID, identity::IdentityID};
use thiserror::Error;

/// This is our error enum. It contains an entry for any part of the system in
/// which an expectation is not met or a problem occurs.
#[derive(Error, Debug)]
pub enum Error {
    /// A key packet has been tampered with
    #[error("key packet tampered with")]
    KeyPacketTampered,

    /// We tried to pull up a full identity from a transaction's identity id, but came up blank.
    /// This will happen if the identity map doesn't include all the needed identities when we're
    /// calling `Topic::push_transaction()`.
    #[error("missing identity in identity list: {0}")]
    IdentityMissing(IdentityID),

    /// We tried to open a member rekey entry with a device id that it wasn't encrypted for.
    #[error("missing member device {0:?}")]
    MemberMissingDevice(DeviceID),

    /// An operation on a member couldn't continue because they were not found.
    #[error("member not found: {0}")]
    MemberNotFound(IdentityID),

    /// Failed to open a rekey message sent to our identity/device
    #[error("rekey open failed ({0} / {1:?})")]
    MemberRekeyOpenFailed(TransactionID, DeviceID),

    /// A packet was encountered that doesn't make any sense
    #[error("invalid packet: {0}")]
    PacketInvalid(TransactionID),

    /// We're assigning someone permissions we do not have.
    #[error("permission change failed (identity {0}, permission {1:?})")]
    PermissionChangeFailed(IdentityID, Permission),

    /// A permission check failed when running a transaction
    #[error("permission check failed (transaction {0} / permission {1:?})")]
    PermissionCheckFailed(TransactionID, Permission),

    /// A snapshot failed to generate
    #[error("snapshot failed (did you pass a valid replacement id?)")]
    SnapshotFailed,

    /// A snapshot has been tampered with
    #[error("snapshot tampered with")]
    SnapshotTampered,

    /// An error occured in the Stamp protocol itself
    #[error("stamp error: {0}")]
    Stamp(#[from] stamp_core::error::Error),

    /// A topic is missing some transactions. Be a dear and grab them, would you?
    #[error("topic is missing transactions: {0:?}")]
    TopicMissingTransactions(Vec<TransactionID>),
}

/// Wraps `std::result::Result` around our `Error` enum
pub type Result<T> = std::result::Result<T, Error>;

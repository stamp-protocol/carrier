//! The main error enum for carrier lives here, and documents the various
//! conditions that can arise while interacting with the library.

use crate::{DeviceID, Permission};
use stamp_core::{dag::TransactionID, identity::IdentityID};
use thiserror::Error;

/// This is our error enum. It contains an entry for any part of the system in
/// which an expectation is not met or a problem occurs.
#[derive(Error, Debug)]
pub enum Error {
    /// Key packet is missing data/fields
    #[error("key packet is malformed")]
    KeyPacketMalformed,

    /// A key packet has been tampered with
    #[error("key packet tampered with")]
    KeyPacketTampered,

    /// We tried to pull up a full identity from a transaction's identity id, but came up blank.
    /// This will happen if the identity map doesn't include all the needed identities when we're
    /// calling `Topic::push_transaction()`.
    #[error("missing identity in identity list: {0}")]
    IdentityMissing(IdentityID),

    /// We tried to open a member rekey entry with a device id that it wasn't encrypted for.
    #[error("missing member device {0} / {1:?}")]
    MemberMissingDevice(TransactionID, DeviceID),

    /// An operation on a member couldn't continue because they were not found.
    #[error("member not found: {0}")]
    MemberNotFound(IdentityID),

    /// Failed to open a rekey message sent to our identity/device
    #[error("rekey open failed ({0} / {1:?})")]
    MemberRekeyOpenFailed(TransactionID, DeviceID),

    /// When trying to create a `MemberRekey` entry we ran into a case where a
    /// member's device was missing from the device -> crypto pubkey mapping which caused a rift in
    /// the time-space vortex.
    #[error("rekey generation failed, missing device key map for identity {0} / device {1:?}")]
    MemberRekeyMissingDevicePubkeyMappingEntry(IdentityID, DeviceID),

    /// We're assigning someone permissions we do not have.
    #[error("permission change failed (identity {0}, permission {1:?})")]
    PermissionChangeFailed(IdentityID, Permission),

    /// A permission check failed when running a transaction
    #[error("permission check failed (transaction {0} / permission {1:?})")]
    PermissionCheckFailed(TransactionID, Permission),

    /// An attempt is being made to snapshot a subset of an existing snapshot.
    #[error("snapshot failed: attempting to create snapshot subset of existing snapshot on tx {0}")]
    SnapshotCollision(TransactionID),

    /// A snapshot failed to generate
    #[error("snapshot failed (did you pass a valid replacement id?)")]
    SnapshotFailed,

    /// A snapshot has been tampered with
    #[error("snapshot tampered with")]
    SnapshotTampered,

    /// An error occured in the Stamp protocol itself
    #[error("stamp error: {0}")]
    Stamp(#[from] stamp_core::error::Error),

    /// A topic is missing a state object that we expected to be there.
    #[error("topic is missing a state object for transaction {0}")]
    TopicMissingState(TransactionID),

    /// A topic is missing some transactions. Be a dear and grab them, would you?
    #[error("topic is missing transactions: {0:?}")]
    TopicMissingTransactions(Vec<TransactionID>),

    /// A topic secret entry is missing a needed transaction ID
    #[error("topic secret is missing transaction id")]
    TopicSecretMissingTransactionID,

    /// A topic secret wasn't found under a certain transaction ID we expected to exist
    #[error("topic secret required but not found for transaction {0}")]
    TopicSecretNotFound(TransactionID),

    /// A topic with no actual packet data is being read. No-data transactions are created by
    /// snapshot expansion to fill in blanks in the DAG, but they cannot be read or used in any
    /// meaningful way. You can test this via `TopicTransaction.is_empty()`
    #[error("cannot read an empty transaction: {0}")]
    TransactionIsEmpty(TransactionID),

    /// We're trying to get the `TopicID` of a transaction that doesn't have that set into it.
    #[error("transaction {0} does not have a topic id associated with it")]
    TransactionMissingTopicID(TransactionID),

    /// Someone is attempting to unset a control packet
    #[error("cannot unset a control packet: {0}")]
    TransactionUnsetNonDataPacket(TransactionID),

    /// Trying to unset a transaction that's not within the causal chain of the removal.
    #[error("transaction {0} trying to unset transaction which is not in its causal chain ({1})")]
    TransactionUnsetNotCausal(TransactionID, TransactionID),
}

/// Wraps `std::result::Result` around our `Error` enum
pub type Result<T> = std::result::Result<T, Error>;

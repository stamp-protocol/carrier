#![doc = include_str!("../README.md")]

pub mod error;

use crate::error::{Error, Result};
use getset;
use rasn::{AsnType, Decode, Encode};
use stamp_core::{
    crypto::base::{
        rng::{CryptoRng, RngCore},
        CryptoKeypair, CryptoKeypairPublic, Hash, HashAlgo, Sealed, SecretKey, SignKeypair, SignKeypairPublic, SignKeypairSignature,
    },
    dag::{Dag, DagNode, Transaction, TransactionBody, TransactionID, Transactions},
    identity::IdentityID,
    util::{Binary, BinarySecret, BinaryVec, HashMapAsn1, SerdeBinary, Timestamp},
};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::ops::Deref;

/// Defines a permission a member can have within a group.
#[derive(Clone, Debug, PartialEq, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum Permission {
    /// Allows creating new data on the topic.
    #[rasn(tag(explicit(0)))]
    DataSet,
    /// Allows marking old packets as deleted. This doesn't fully remove the packet (as this might
    /// break the DAG chain), but does wipe out its data.
    #[rasn(tag(explicit(1)))]
    DataUnset,
    /// Allows a member to change devices in their own profile.
    #[rasn(tag(explicit(2)))]
    MemberDevicesUpdate,
    /// Allows changing member's permissions
    #[rasn(tag(explicit(3)))]
    MemberPermissionsChange,
    /// Allows re-keying the topic
    #[rasn(tag(explicit(4)))]
    TopicRekey,
}

/// Represents a unique ID for a member device. Randomly generated.
#[derive(Debug, Clone, AsnType, Encode, Decode, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[rasn(delegate)]
pub struct DeviceID(Binary<16>);

impl DeviceID {
    /// Create a new random TopicID.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut randbuf = [0u8; 16];
        rng.fill_bytes(&mut randbuf);
        Self(Binary::new(randbuf))
    }
}

impl SerdeBinary for DeviceID {}

/// Represent's a member's device.
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Device {
    /// The device's unique ID
    #[rasn(tag(explicit(0)))]
    id: DeviceID,
    /// The device's member-supplied name
    #[rasn(tag(explicit(1)))]
    name: String,
}

impl Device {
    /// Create a new random TopicID.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, name: String) -> Self {
        let id = DeviceID::new(rng);
        Self { id, name }
    }
}

/// Information on a member of a topic.
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Member {
    /// The Stamp identity id of the member
    #[rasn(tag(explicit(0)))]
    identity_id: IdentityID,
    /// An additive list of permissions this member can perform on the topic
    #[rasn(tag(explicit(1)))]
    permissions: Vec<Permission>,
    /// A list of this member's devices.
    #[rasn(tag(explicit(2)))]
    devices: Vec<Device>,
}

impl Member {
    /// Create a new member object.
    pub fn new(identity_id: IdentityID, permissions: Vec<Permission>, devices: Vec<Device>) -> Self {
        Self {
            identity_id,
            permissions,
            devices,
        }
    }
}

/// A topic's secret seed.
#[derive(Debug, AsnType, Encode, Decode)]
#[rasn(delegate)]
pub struct TopicSecret(BinarySecret<32>);

impl TopicSecret {
    /// Create a new random topic secret.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut randbuf = [0u8; 32];
        rng.fill_bytes(&mut randbuf);
        Self(BinarySecret::new(randbuf))
    }

    /// Derive a symmetric encryption key from a topic secret.
    pub(crate) fn derive_secret_key(&self) -> Result<SecretKey> {
        let mut out = [0u8; 32];
        stamp_core::crypto::base::stretch_key(&self.0.expose_secret()[..], &mut out, Some(b"/stamp/sync/topic-derive-secret-key"), None)?;
        Ok(SecretKey::new_xchacha20poly1305_from_bytes(out)?)
    }
}

impl Clone for TopicSecret {
    fn clone(&self) -> Self {
        Self(BinarySecret::new(self.0.expose_secret().clone()))
    }
}

/// An object that maps a secret seed to a transaction ID (the transaction pointed to should be a
/// control packet that contains rekey data).
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct SecretEntry {
    /// The transaction ID this entry references. If this is `None` then it means the *current*
    /// transaction is being referenced.
    #[rasn(tag(explicit(0)))]
    transaction_id: Option<TransactionID>,
    /// The secret attached to this transaction.
    #[rasn(tag(explicit(1)))]
    secret: TopicSecret,
}

impl SecretEntry {
    /// Creates a new `SecretEntry` with a blank transaction ID.
    pub fn new_current_transaction(secret: TopicSecret) -> Self {
        Self {
            transaction_id: None,
            secret,
        }
    }
}

impl SerdeBinary for SecretEntry {}

/// Holds information about a public cryptographic encryption key.
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct KeyPacketEntry {
    /// The identity id that owns the included public key
    #[rasn(tag(explicit(0)))]
    identity_id: IdentityID,
    /// The device this key packet was generated from/for.
    #[rasn(tag(explicit(1)))]
    device_id: DeviceID,
    /// The cryptographic public key we're advertising others to use to send us messages.
    #[rasn(tag(explicit(1)))]
    pubkey: CryptoKeypairPublic,
}

impl SerdeBinary for KeyPacketEntry {}

/// Describes a cryptographic encryption public key, signed with a well-known identity (sync) key.
/// This allows a (potential) member to publish a number of random pre-generated cryptographic keys
/// that others can verify that they own, enabling participants to avoid using the long-lived sync
/// crypto key (if possible).
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct KeyPacket {
    /// The cryptographic hash of the serialized `entry`.
    #[rasn(tag(explicit(0)))]
    id: Hash,
    /// Holds the actual key packet data (basically a crypto public key)
    #[rasn(tag(explicit(1)))]
    entry: KeyPacketEntry,
    /// A signature on the `id` field (the hash of the entry), signed yb a well-known sync signing
    /// key.
    #[rasn(tag(explicit(2)))]
    signature: SignKeypairSignature,
}

impl KeyPacket {
    /// Create a new key packet, advertising a public crypto key we own that's signed with our
    /// signing keypair (so others can verify it is actually owned by us).
    pub fn new(
        master_key: &SecretKey,
        sign_keypair: &SignKeypair,
        identity_id: IdentityID,
        device_id: DeviceID,
        pubkey: CryptoKeypairPublic,
    ) -> Result<Self> {
        let entry = KeyPacketEntry {
            identity_id,
            device_id,
            pubkey,
        };
        let entry_ser = entry.serialize_binary()?;
        let id = Hash::new_blake3(&entry_ser[..])?;
        let id_ser = id.serialize_binary()?;
        let signature = sign_keypair.sign(master_key, &id_ser[..])?;
        Ok(Self { id, entry, signature })
    }

    /// Verify a key packet comes from the key we think it does, returning the crypto pubkey if so.
    pub fn verify(&self, sign_pubkey: &SignKeypairPublic) -> Result<&CryptoKeypairPublic> {
        let entry_ser = self.entry().serialize_binary()?;
        let our_hash = Hash::new_blake3(&entry_ser[..])?;
        if &our_hash != self.id() {
            Err(Error::KeyPacketTampered)?;
        }

        let hash_ser = self.id().serialize_binary()?;
        sign_pubkey.verify(self.signature(), &hash_ser[..])?;
        Ok(self.entry().pubkey())
    }
}

/// A message sent to a member containing a topic secret.
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
struct RekeyMessage {
    /// The key we're using to encrypt the message
    #[rasn(tag(explicit(0)))]
    to_key: CryptoKeypairPublic,
    /// The encrypted message
    #[rasn(tag(explicit(1)))]
    message: BinaryVec,
}

impl RekeyMessage {
    /// Create a new `RekeyMessage`.
    pub fn new(to_key: CryptoKeypairPublic, message: Vec<u8>) -> Self {
        Self {
            to_key,
            message: message.into(),
        }
    }
}

/// A member re-key entry, allowing an existing member of a topic to get a new shared secret, or
/// allowing a new member to be initiated into the topic via a collection of past shared secrets
/// (along with the latest secret).
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct MemberRekey {
    /// The full member object
    #[rasn(tag(explicit(0)))]
    member: Member,
    /// Any secret(s) this member needs to read the topic's data, encrypted with the member's
    /// public sync key.
    #[rasn(tag(explicit(1)))]
    secrets: HashMapAsn1<DeviceID, RekeyMessage>,
}

impl MemberRekey {
    /// Create a new member reykey structure, encrypting the secrets passed in with the member's
    /// syncing cryptographic public key.
    pub fn seal<R: RngCore + CryptoRng>(
        rng: &mut R,
        member: Member,
        recipient_crypto_pubkeys: &BTreeMap<&DeviceID, &CryptoKeypairPublic>,
        secrets: Vec<SecretEntry>,
    ) -> Result<Self> {
        let secret_ser = secrets.serialize_binary()?;
        let secrets = recipient_crypto_pubkeys
            .iter()
            .map(|(device_id, crypto_pubkey)| {
                let enc = crypto_pubkey.seal_anonymous(rng, &secret_ser[..]).map_err(|e| Error::Stamp(e))?;
                #[allow(suspicious_double_ref_op)]
                let msg = RekeyMessage::new(crypto_pubkey.clone().clone(), enc);
                #[allow(suspicious_double_ref_op)]
                Ok((device_id.clone().clone(), msg))
            })
            .collect::<Result<BTreeMap<_, _>>>()?
            .into();
        Ok(Self { member, secrets })
    }

    /// Open a rekey entry given the proper crypto secret key and master key.
    pub fn open(
        self,
        recipient_master_key: &SecretKey,
        recipient_crypto_keypairs: &[&CryptoKeypair],
        our_device_id: &DeviceID,
        transaction_id: &TransactionID,
    ) -> Result<(Member, Vec<SecretEntry>)> {
        let msg = self
            .secrets()
            .get(our_device_id)
            .ok_or_else(|| Error::MemberMissingDevice(transaction_id.clone(), our_device_id.clone()))?;
        let enc = msg.message().deref();
        let dec = recipient_crypto_keypairs
            .iter()
            .find_map(|crypto| crypto.open_anonymous(recipient_master_key, &enc[..]).ok())
            .ok_or_else(|| Error::MemberRekeyOpenFailed(transaction_id.clone(), our_device_id.clone()))?;
        let entries: Vec<SecretEntry> = SerdeBinary::deserialize_binary(&dec[..])?;
        let Self { member, .. } = self;
        Ok((member, entries))
    }

    /// Consumes this member rekey object, returning the member.
    pub fn consume(self) -> Member {
        let Self { member, .. } = self;
        member
    }
}

/// Defines packet types that can be sent on a topic.
#[derive(Debug, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum Packet {
    /// An (encrypted) application-specific data entry, sealed with a topic key derived from a
    /// topic secret sent in a control packet.
    #[rasn(tag(explicit(0)))]
    DataSet {
        /// A reference to the transaction ID of the control packet containing the key that
        /// encrypts this packet.
        #[rasn(tag(explicit(0)))]
        key_ref: TransactionID,
        /// The data packet's payload, encrypted with a key distributed from one of the control
        /// packets.
        #[rasn(tag(explicit(1)))]
        payload: Sealed,
    },
    /// Marks packets as no longer needed, allowing their garbage collection via a snapshot.
    #[rasn(tag(explicit(1)))]
    DataUnset {
        /// The id of the packet we're unsetting
        #[rasn(tag(explicit(0)))]
        transaction_ids: Vec<TransactionID>,
    },
    /// Allows a member to add/remove devices to their own profile. We omit the identity id of the
    /// member being modified because members can only update their own devices with this
    /// permission, so the identity id is stored in the transaction carrying the packet.
    #[rasn(tag(explicit(2)))]
    MemberDevicesUpdate {
        /// The member's device list
        #[rasn(tag(explicit(0)))]
        devices: Vec<Device>,
    },
    /// Changes a member's permissions
    #[rasn(tag(explicit(3)))]
    MemberPermissionsChange {
        /// The identity ID of the member we're editing
        #[rasn(tag(explicit(0)))]
        identity_id: IdentityID,
        /// The new permissions this member is getting.
        #[rasn(tag(explicit(1)))]
        permissions: Vec<Permission>,
    },
    /// Re-keys a topic, assigning a new topic key for future packets and potentially changing
    /// membership (adding/removing members).
    #[rasn(tag(explicit(4)))]
    TopicRekey {
        /// The new member list of this topic, complete with the secret(s) required to decrypt
        /// the data in the topic, encrypted for each member individually via their public sync
        /// key.
        #[rasn(tag(explicit(0)))]
        members: Vec<MemberRekey>,
    },
}

impl Packet {
    /// Determine if this is a control packet (as opposed to a data packet).
    pub fn is_control_packet(&self) -> bool {
        match self {
            Packet::MemberDevicesUpdate { .. } | Packet::MemberPermissionsChange { .. } | Packet::TopicRekey { .. } => true,
            Packet::DataSet { .. } | Packet::DataUnset { .. } => false,
        }
    }
}

impl SerdeBinary for Packet {}

/// Represents a unique ID for a [`Snapshot`].
#[derive(Debug, Clone, AsnType, Encode, Decode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct SnapshotID(Hash);

impl SerdeBinary for SnapshotID {}

/// An entry for an ordered snapshot reference.
#[derive(Clone, Debug, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum SnapshotOrderedOp {
    /// Transactions we're keeping
    #[rasn(tag(explicit(0)))]
    Keep { id: TransactionID },
    /// `Remove` (either actions or targets) that we are removing (but want to preserve their
    /// ID/timestamp so we can rebuild them later)
    #[rasn(tag(explicit(1)))]
    Remove {
        #[rasn(tag(explicit(0)))]
        id: TransactionID,
        #[rasn(tag(explicit(1)))]
        timestamp: Timestamp,
    },
}

impl SnapshotOrderedOp {
    /// Return a ref to the operation id
    pub fn transaction_id(&self) -> &TransactionID {
        match self {
            Self::Keep { ref id } => id,
            Self::Remove { ref id, .. } => id,
        }
    }

    /// Checks if this is a `Set`
    pub fn is_keep(&self) -> bool {
        matches!(self, &Self::Keep { .. })
    }
}

/// Holds the actual snapshot data, as well as the [`TransactionID`] of the operation we're replacing
/// with this snapshot.
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct SnapshotEntry {
    /// The operations we're rolling into this snapshot **in causal order**. This is effectively
    /// all operations that have occurred before the operation being snapshotted *on the same DAG
    /// ancestry as the operation*. In other words, operations that came before this one that are
    /// *not* in any of the backlinks should *not* be snapshotted.
    ///
    /// Note although the snapshot erases nodes that are unsets or are targets of unsets, we will
    /// also jam those into this list (in order, of course) along with their timestamps such that
    /// later on we can fully rebuild the order of the nodes within the DAG by creating "phantom"
    /// nodes that take the place of the old deleted nodes.
    ///
    /// The operation that's being replaced with this snapshot must have its [`TransactionID`] in
    /// the *last position* of this list.
    #[rasn(tag(explicit(0)))]
    ordered_transactions: Vec<SnapshotOrderedOp>,
}

impl SnapshotEntry {
    fn new(ordered_transactions: Vec<SnapshotOrderedOp>) -> Self {
        Self { ordered_transactions }
    }
}

impl SerdeBinary for SnapshotEntry {}

/// A snapshot of the current state of the DAG with all previous operations rolled up into one
/// state object. This allows compression by removing deleted transactions and combining edits on the
/// same object.
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Snapshot {
    /// This snapshot's ID, which is a hash of the `entry` field. This prevents tampering.
    #[rasn(tag(explicit(0)))]
    id: SnapshotID,
    /// The snapshot data/metadata. This holds the snapshot state and also the [`TransactionID`] of
    /// the operation the snapshot is replacing. This prevents the snapshot from being tampered
    /// with by anyone without the sign keys.
    #[rasn(tag(explicit(1)))]
    entry: SnapshotEntry,
    /// A signature on the `id` field.
    #[rasn(tag(explicit(2)))]
    signature: SignKeypairSignature,
}

impl Snapshot {
    /// Create a new, valid, signed snapshot.
    pub fn new(master_key: &SecretKey, sign_key: &SignKeypair, ordered_transactions: Vec<SnapshotOrderedOp>) -> Result<Self> {
        let entry = SnapshotEntry::new(ordered_transactions);
        let entry_ser = entry.serialize_binary()?;
        let id = SnapshotID(Hash::new_blake3(&entry_ser)?);
        let id_ser = id.serialize_binary()?;
        let signature = sign_key.sign(master_key, &id_ser)?;
        Ok(Self { id, entry, signature })
    }

    /// Verify that this snapshot is valid (its ID and signature on that ID). Returns the *last*
    /// [`TransactionID`] in the snapshot's `ordered_transactions` chain.
    pub fn verify(&self, sign_pubkey: &SignKeypairPublic) -> Result<TransactionID> {
        let entry_ser = self.entry().serialize_binary()?;
        let id_comp = SnapshotID(Hash::new_blake3(&entry_ser)?);
        if self.id() != &id_comp {
            Err(Error::SnapshotTampered)?;
        }
        let id_ser = self.id().serialize_binary()?;
        sign_pubkey.verify(&self.signature(), &id_ser)?;
        let ops = self.all_transactions();
        let last = ops[ops.len() - 1].clone();
        Ok(last)
    }

    /// A list of all the active nodes this snapshot holds (set operations)
    pub fn active_transactions(&self) -> Vec<&TransactionID> {
        self.entry()
            .ordered_transactions()
            .iter()
            .filter(|x| matches!(x, SnapshotOrderedOp::Keep { .. }))
            .map(|x| x.transaction_id())
            .collect::<Vec<_>>()
    }

    /// A list of all the nodes referenced in this snapshot (active and removed)
    pub fn all_transactions(&self) -> Vec<&TransactionID> {
        self.entry()
            .ordered_transactions()
            .iter()
            .map(|x| x.transaction_id())
            .collect::<Vec<_>>()
    }
}

/// A wrapper around the [`Transaction`] type, allowing for snapshots and custom DAG ordering.
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct TopicTransaction {
    /// The transaction we're wrapping
    #[rasn(tag(explicit(0)))]
    transaction: Transaction,
    /// A snapshot. This rolls up all previous transactions, *including this one* into a single
    /// state.
    ///
    /// Note that a snapshot doesn't explicitely *store* transactions or their data, but rather
    /// preserves their order as a signed (tamperproof) container, allowing deletion of unset data
    /// but preserving the exact order from the original DAG.
    #[rasn(tag(explicit(1)))]
    snapshot: Option<Snapshot>,
}

impl TopicTransaction {
    /// Returns this transaction's id
    pub fn id(&self) -> &TransactionID {
        self.transaction().id()
    }

    /// Returns this transaction's create time
    pub fn timestamp(&self) -> &Timestamp {
        self.transaction().entry().created()
    }

    /// Create a new topic transaction.
    pub fn new(transaction: Transaction) -> Self {
        Self {
            transaction,
            snapshot: None,
        }
    }

    /// Return's this transaction's packet data.
    pub fn get_packet(&self) -> Result<Packet> {
        match self.transaction().entry().body() {
            TransactionBody::ExtV1 { ref payload, .. } => {
                let packet = Packet::deserialize_binary(payload.deref())?;
                Ok(packet)
            }
            _ => Err(Error::PacketInvalid(self.id().clone()))?,
        }
    }

    /// Returns the identity id of this transaction.
    pub fn identity_id(&self) -> Result<&IdentityID> {
        match self.transaction().entry().body() {
            TransactionBody::ExtV1 { ref creator, .. } => Ok(creator),
            _ => Err(Error::PacketInvalid(self.id().clone()))?,
        }
    }

    /// Return the transactions that came before this one within the topic DAG. In other words, we
    /// don't use `transaction.entry().previous_transactions()` but rather
    /// `transaction.entry().body::<ExtV1>().previous_transactions()`.
    pub fn previous_transactions(&self) -> Result<Vec<&TransactionID>> {
        match self.transaction().entry().body() {
            TransactionBody::ExtV1 {
                ref previous_transactions, ..
            } => Ok(previous_transactions.iter().collect::<Vec<_>>()),
            _ => Err(Error::PacketInvalid(self.id().clone()))?,
        }
    }

    /// Returns whether or not this transaction houses a control packet.
    pub fn is_control_packet(&self) -> Result<bool> {
        Ok(self.get_packet()?.is_control_packet())
    }

    /// Returns if this is an unset packet or not.
    pub fn is_unset(&self) -> Result<bool> {
        match self.transaction().entry().body() {
            TransactionBody::ExtV1 { payload, .. } => {
                let packet = Packet::deserialize_binary(payload.as_slice())?;
                Ok(matches!(packet, Packet::DataUnset { .. }))
            }
            _ => Err(Error::PacketInvalid(self.id().clone()))?,
        }
    }

    /// Returns the `TransactionID`s being unset IF this is an unset
    pub fn unset_ids(&self) -> Result<Vec<TransactionID>> {
        match self.transaction().entry().body() {
            TransactionBody::ExtV1 { payload, .. } => {
                let packet = Packet::deserialize_binary(payload.as_slice())?;
                match packet {
                    Packet::DataUnset { transaction_ids } => Ok(transaction_ids.clone()),
                    _ => Ok(Vec::new()),
                }
            }
            _ => Err(Error::PacketInvalid(self.id().clone()))?,
        }
    }
}

impl From<Transaction> for TopicTransaction {
    fn from(t: Transaction) -> Self {
        Self::new(t)
    }
}

impl<'a> From<&'a TopicTransaction> for DagNode<'a, TransactionID, TopicTransaction> {
    fn from(t: &'a TopicTransaction) -> Self {
        DagNode::new(t.id(), t, t.previous_transactions().unwrap_or_else(|_| Vec::new()), t.timestamp())
    }
}

impl PartialEq for TopicTransaction {
    fn eq(&self, rhs: &Self) -> bool {
        self.id() == rhs.id()
    }
}

/// Represents a unique ID for a [`Topic`]. Randomly generated.
#[derive(Debug, Clone, AsnType, Encode, Decode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct TopicID(Binary<16>);

impl TopicID {
    /// Create a new random TopicID.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut randbuf = [0u8; 16];
        rng.fill_bytes(&mut randbuf);
        Self(Binary::new(randbuf))
    }

    /// Create a `TopicID` from a byte array.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Binary::new(bytes))
    }
}

impl SerdeBinary for TopicID {}

/// Holds secret and member state for a topic. A topic will generally have one or more copies of
/// this, each corresponding to a branch/merge of the topic if eventual consistency finds us
/// creating simultaneous updates in the DAG. These generally all get merged together in the
/// topic's master state (`Topic.state`) however we use this master state mainly for authoring new
/// transactions, NOT for validating old ones, because the old ones should be validated against the
/// state corresponding to the branch they live in.
///
/// Imagine the following:
///
/// ```text
///    A
///  /  \
/// B    C
/// |    |
/// D    E
///  \  /
///    F
/// ```
///
/// Let's say `B` removes all participants' ability to post new transactions (except themself), but
/// in the meantime, `C` & `E` are created on another branch that derives from `A`. `C`/`E` are
/// *valid* in the context of `A`, but not in the context of `B`. If we were to just play the
/// transactions in order and update a single state and validate off that state, `C`/`E` would get
/// flagged as invalid, even though they are valid in the context of their state.
///
/// So the purpose of tracking per-branch state is to make sure that transactions that are valid
/// given their ancestry will actually validate, as opposed to building a single global state and
/// discarding transactions that might have been valid in their context but then get invalidated
/// due to another branch. This of state tracking, although much more involved and less performant,
/// significantly decreases the risk of causing invalid transactions. It's a much more permissive
/// model. Yes, it's vulnerable to someone branching off of `E` to add their data and purposefully
/// not including `B` or its descendants to avoid permissions adjustments. However, in the case of
/// global state validation, someone malicious could just as easily branch off of `A` and remove
/// everyone's ability to write transactions, which would invalidate the entire topic tree
/// instantly...a much more devastating problem.
///
/// Given that topics are meant to be synced between known identities with a prior relationship, it
/// makes sense that we use the permissive model that assumes mostly good actors.
#[derive(Clone, Debug, Default, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct TopicState {
    /// A collection of secret seeds, in order of the DAG control packets, that allow deriving the
    /// topic's current (or past) secret key(s).
    secrets: Vec<SecretEntry>,
    /// Tracks who is a member of this topic and what their permissions are.
    members: HashMap<IdentityID, Member>,
}

impl TopicState {
    /// Create anew
    fn new() -> Self {
        Default::default()
    }

    /// Check if the permissions on a transaction are valid.
    pub fn check_permissions(
        members: &HashMap<IdentityID, Member>,
        permission: Permission,
        identity_id: &IdentityID,
        transaction_id: &TransactionID,
    ) -> Result<()> {
        let member = members
            .get(identity_id)
            .ok_or_else(|| Error::PermissionCheckFailed(transaction_id.clone(), permission.clone()))?;
        if !member.permissions().contains(&permission) {
            Err(Error::PermissionCheckFailed(transaction_id.clone(), permission))?;
        }
        Ok(())
    }

    /// Push a new secret into the topic
    fn push_secret(&mut self, secret: SecretEntry) -> Result<()> {
        // only add the secret if it's unique
        let secret_exists = self
            .secrets()
            .iter()
            .find(|existing| existing.transaction_id() == secret.transaction_id())
            .is_some();
        if secret_exists {
            return Ok(());
        }
        self.secrets.push(secret);
        Ok(())
    }

    /// Validate a transaction against the current state (meaning, check permissions).
    fn validate_transaction(&self, transaction: &TopicTransaction) -> Result<()> {
        let is_initial_packet = transaction.previous_transactions()?.len() == 0;

        let packet = transaction.get_packet()?;
        let identity_id = transaction.identity_id()?;
        match packet {
            Packet::DataSet { .. } => {
                Self::check_permissions(self.members(), Permission::DataSet, &identity_id, transaction.id())?;
            }
            Packet::DataUnset { .. } => {
                Self::check_permissions(self.members(), Permission::DataUnset, &identity_id, transaction.id())?;
            }
            Packet::MemberDevicesUpdate { .. } => {
                Self::check_permissions(self.members(), Permission::MemberDevicesUpdate, &identity_id, transaction.id())?;
            }
            Packet::MemberPermissionsChange { .. } => {
                Self::check_permissions(self.members(), Permission::MemberPermissionsChange, &identity_id, transaction.id())?;
            }
            Packet::TopicRekey { .. } => {
                if !is_initial_packet {
                    Self::check_permissions(self.members(), Permission::TopicRekey, &identity_id, transaction.id())?;
                }
            }
        }
        Ok(())
    }

    /// Apply a previously-validated transaction to this state.
    fn apply_transaction(
        &mut self,
        transaction: &TopicTransaction,
        our_master_key: &SecretKey,
        our_crypto_keypairs: &[&CryptoKeypair],
        our_identity_id: &IdentityID,
        our_device_id: &DeviceID,
    ) -> Result<()> {
        let packet = transaction.get_packet()?;
        let identity_id = transaction.identity_id()?;
        match packet {
            Packet::DataSet { .. } => {}
            Packet::DataUnset { .. } => {
                // TODO:
                // - don't allow Unset on non-data packets
            }
            Packet::MemberDevicesUpdate { devices } => {
                self.members_mut()
                    .get_mut(identity_id)
                    .map(|member| {
                        member.set_devices(devices);
                    })
                    .ok_or_else(|| Error::MemberNotFound(identity_id.clone()))?;
            }
            Packet::MemberPermissionsChange {
                identity_id: identity_id_changee,
                permissions: new_permissions,
            } => {
                if !self.members().contains_key(&identity_id_changee) {
                    Err(Error::MemberNotFound(identity_id_changee.clone()))?;
                }
                let initiator_permissions = self
                    .members()
                    .get(identity_id)
                    .ok_or_else(|| Error::MemberNotFound(identity_id.clone()))?
                    .permissions();
                for new_permission in &new_permissions {
                    if !initiator_permissions.contains(new_permission) {
                        Err(Error::PermissionChangeFailed(identity_id.clone(), new_permission.clone()))?;
                    }
                }
                self.members_mut()
                    .get_mut(&identity_id_changee)
                    .map(|member| member.set_permissions(new_permissions))
                    .ok_or_else(|| Error::MemberNotFound(identity_id_changee))?;
            }
            Packet::TopicRekey { members } => {
                // every rekey necessarily rebuilds the entire member set
                self.members_mut().clear();
                for member_rekey in members {
                    let rekey_is_relevant_to_us =
                        member_rekey.member().identity_id() == our_identity_id && member_rekey.secrets().contains_key(our_device_id);
                    let member = if rekey_is_relevant_to_us {
                        let (member, secrets) = member_rekey.open(our_master_key, our_crypto_keypairs, our_device_id, transaction.id())?;
                        for mut secret in secrets {
                            if secret.transaction_id().is_none() {
                                // make sure the secret entry gets set to the current transaction
                                // *if its transaction_id field is empty*
                                secret.set_transaction_id(Some(transaction.id().clone()));
                            }
                            self.push_secret(secret)?;
                        }
                        member
                    } else {
                        member_rekey.consume()
                    };
                    self.members_mut().insert(member.identity_id().clone(), member);
                }
            }
        }
        Ok(())
    }
}

/// Determines how the DAG of a [`Topic`] was modified while pushing transactions.
///
/// You can probably generally ignore this unless you're hitting performance issues, in which case
/// you'll want to investigate why your DAG is branching so much.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TopicDagState {
    /// The DAG was rebuilt from scratch. This happens when new transactions reference (or branch
    /// off of) non-tail nodes, ie nodes that are in the middle of the chain somewhere as opposed
    /// to the end of the chain.
    ///
    /// When this branching happens, it's necessary to re-run the DAG from scratch which can be an
    /// expensive operation, depending on how many updates there are.
    DagRebuilt,
    /// The DAG was incrementally updated. This is the most efficient operational mode and
    /// hopefully the most common for any given use-case.
    DagUpdated,
}

/// A data topic. This is a structure built from running a DAG of transactions in order. It tracks
/// the keys used to decrypt data contained in the topic, information on members of the topic and
/// their permissions within the topic, as well as the data contained within the topic itself.
#[derive(Clone, Debug, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Topic {
    /// This topic's unique ID
    id: TopicID,
    /// This topic's global state.
    state: TopicState,
    /// This topic's keychain. This starts off empty and is populated as control packets come in
    /// that give access to various identities via their sync keys. A new entry is created whenever
    /// a member is added to or removed from the topic.
    keychain: HashMap<TransactionID, SecretKey>,
    /// The actual transactions (control or data) in this topic.
    transactions: Vec<TopicTransaction>,
    /// Tracks the state for the various branches in the topic DAG we can have, allowing
    /// transactions to have branch-local validation as opposed to requiring consistent state. This
    /// mapping exists largely as a cache so we don't have to re-run all the transactions from
    /// start to finish each time we need to add a new transaction to the topic.
    branch_state: HashMap<TransactionID, TopicState>,
    /// Tracks the tail references of the most recent state update to the topic DAG. You mostly
    /// shouldn't think about this at all since its function is purely for internal optimization.
    last_tail_nodes: Vec<TransactionID>,
}

impl Topic {
    /// Create a new empty `Topic` object.
    pub fn new(id: TopicID) -> Self {
        Self {
            id,
            state: TopicState::new(),
            keychain: HashMap::new(),
            transactions: Vec::new(),
            branch_state: HashMap::new(),
            last_tail_nodes: Vec::new(),
        }
    }

    /// Create a new `Topic` with the given transaction list.
    ///
    /// This takes a list of the full identities of the participants in the topic and a list of our
    /// crypto keypairs and a) verifies each transaction against the identity it came from and b)
    /// uses our crypto keypairs to decrypt any topic secrets in the control packets. This allows
    /// us to full build our topic state.
    pub fn new_from_transactions(
        id: TopicID,
        transactions: Vec<TopicTransaction>,
        identities: &HashMap<IdentityID, &Transactions>,
        our_master_key: &SecretKey,
        our_crypto_keypairs: &[&CryptoKeypair],
        our_identity_id: &IdentityID,
        our_device_id: &DeviceID,
    ) -> Result<Self> {
        Self::new(id).push_transactions(transactions, identities, our_master_key, our_crypto_keypairs, our_identity_id, our_device_id)
    }

    /// Return a ref to this topic's secret collection
    pub fn secrets(&self) -> &Vec<SecretEntry> {
        self.state().secrets()
    }

    /// Create a new packet that re-keys the topic.
    ///
    /// This does not apply the packet, it's your responsibility to call [`Topic::transaction_from_packet()`]
    /// / [`Topic::push_transactions()`] yourself.
    pub fn rekey<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        members: Vec<(Member, &BTreeMap<&DeviceID, &CryptoKeypairPublic>)>,
    ) -> Result<Packet> {
        let mut secrets = self.secrets().clone();
        secrets.push(SecretEntry::new_current_transaction(TopicSecret::new(rng)));
        let rekeys = members
            .into_iter()
            .map(|(member, recipient_device_pubkeys)| MemberRekey::seal(rng, member, recipient_device_pubkeys, secrets.clone()))
            .collect::<Result<Vec<_>>>()?;
        Ok(Packet::TopicRekey { members: rekeys })
    }

    /// Returns the topic's current [`SecretKey`] (if the topic has any secret entries).
    pub fn current_secret_key(&self) -> Result<Option<SecretKey>> {
        self.secrets().last().map(|x| x.secret().derive_secret_key()).transpose()
    }

    /// Push a set of *finalized* transactions into this topic, consuming the topic and returning a
    /// new one with the transactions applied.
    ///
    /// This verifies the transactions at the top-level with their issuing identities, so have
    /// those handy when calling. We also need to pass in our master key to unlock our crypto
    /// keypairs, allowing us to apply key changes in the topic sent to us.
    pub fn push_transactions(
        mut self,
        transactions: Vec<TopicTransaction>,
        identities: &HashMap<IdentityID, &Transactions>,
        our_master_key: &SecretKey,
        our_crypto_keypairs: &[&CryptoKeypair],
        our_identity_id: &IdentityID,
        our_device_id: &DeviceID,
    ) -> Result<Self> {
        self.push_transactions_mut(transactions, identities, our_master_key, our_crypto_keypairs, our_identity_id, our_device_id)?;
        Ok(self)
    }

    /// Push a set of *finalized* transactions into this topic, consuming the topic and returning a
    /// new one with the transactions applied.
    ///
    /// This verifies the transactions at the top-level with their issuing identities, so have
    /// those handy when calling. We also need to pass in our master key to unlock our crypto
    /// keypairs, allowing us to apply key changes in the topic sent to us.
    ///
    /// This is exactly like [`Topic::push_transactions()`] but works without consuming the topic.
    pub fn push_transactions_mut(
        &mut self,
        transactions: Vec<TopicTransaction>,
        identities: &HashMap<IdentityID, &Transactions>,
        our_master_key: &SecretKey,
        our_crypto_keypairs: &[&CryptoKeypair],
        our_identity_id: &IdentityID,
        our_device_id: &DeviceID,
    ) -> Result<TopicDagState> {
        // index transactions we've already processed here
        let mut exists_idx: HashSet<&TransactionID> = HashSet::new();
        let nodes_old = self
            .transactions()
            .iter()
            .map(|x| {
                exists_idx.insert(x.id());
                x.into()
            })
            .collect::<Vec<DagNode<_, _>>>();
        let mut nodes_new_idx = transactions
            .into_iter()
            .filter(|t| !exists_idx.contains(t.id()))
            .map(|t| (t.id().clone(), t))
            .collect::<HashMap<TransactionID, TopicTransaction>>();
        let mut contains_key_changes = false;
        for trans in nodes_new_idx.values() {
            // verify our transactions against their respective identities
            let trans_identity_id = trans.identity_id()?;
            let prev = trans.transaction().entry().previous_transactions();
            let identity_tx = identities
                .get(trans_identity_id)
                .ok_or_else(|| Error::IdentityMissing(trans_identity_id.clone()))?;
            let identity = identity_tx.build_identity_at_point_in_history(&prev)?;
            trans.transaction().verify(Some(&identity))?;
            // also, look for any key changes
            match trans.get_packet()? {
                Packet::TopicRekey { .. } => {
                    contains_key_changes = true;
                }
                _ => {}
            }
        }

        // if our new transactions *only* reference either tail nodes in the existing DAG OR
        // each other, then we can safely update this DAG using the existing state tracking and
        // skip a whole lot of processing. however, if our new nodes reference any non-tail,
        // non-new state, then we need to re-process the entire DAG.
        let new_transactions_only_reference_tail_nodes = {
            // index our DAG's tail transactions AND our new transactions into a set that we'll
            // use to check if we need to re-run the entire DAG.
            let mut tail_or_self_idx = self.last_tail_nodes.iter().collect::<HashSet<_>>();
            for trans in nodes_new_idx.values() {
                tail_or_self_idx.insert(trans.id());
            }
            // now loop over our new transactions and check the previous_transactions of each,
            // looking for any references to tx outside of our tail/new set. if we find any,
            // we've got to reprocess the DAG =[ =[ =[. sad!
            let mut only_tail_referenced = true;
            for trans in nodes_new_idx.values() {
                let prev = trans.previous_transactions()?;
                for txid in prev {
                    if !tail_or_self_idx.contains(txid) {
                        only_tail_referenced = false;
                        break;
                    }
                }
                if !only_tail_referenced {
                    break;
                }
            }
            only_tail_referenced
        };

        let mut branch_state = if new_transactions_only_reference_tail_nodes {
            self.branch_state().clone()
        } else {
            HashMap::new()
        };

        let (global_state, last_tail_nodes) = {
            self.with_expanded_snapshots(|transactions_modified, _tx_idx, recreated| {
                let nodes_new = nodes_new_idx
                    .values()
                    // don't re-run transactions we've already processed
                    .filter(|n| !exists_idx.contains(n.id()))
                    .map(|x| x.into())
                    .collect::<Vec<_>>();
                let nodes_modified = transactions_modified.iter().map(|x| x.into()).collect::<Vec<_>>();

                let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_old, &nodes_new, &nodes_modified]);
                if dag.missing().len() > 0 {
                    Err(Error::TopicMissingTransactions(dag.missing().iter().cloned().cloned().collect::<Vec<_>>()))?;
                }
                let global_state = dag.apply(
                    &mut branch_state,
                    |node| {
                        let mut state = TopicState::new();
                        state.apply_transaction(node.node(), our_master_key, our_crypto_keypairs, our_identity_id, our_device_id)?;
                        Ok(state)
                    },
                    |node| (new_transactions_only_reference_tail_nodes && exists_idx.contains(node.id())) || recreated.contains(node.id()),
                    |state, node| state.validate_transaction(node.node()),
                    |state, node| state.apply_transaction(node.node(), our_master_key, our_crypto_keypairs, our_identity_id, our_device_id),
                )?;
                let tail_nodes = dag.tail().clone().into_iter().cloned().collect();
                Ok((global_state.clone(), tail_nodes))
            })?
        };
        for (_, trans) in nodes_new_idx.drain() {
            self.transactions.push(trans);
        }
        // save our global state into the topic. this is our state with every known transaction
        // applied to it, which gives a final look at the current state of the topic.
        self.set_state(global_state.clone());
        // save all of our various branch states back into the topic.
        self.set_branch_state(branch_state);
        // save our last tail nodes so we don't have to build our DAG *twice* next time (once with
        // just the existing transactions to get the tail nodes, and again with the existing AND
        // new transactions to get the final state)
        self.set_last_tail_nodes(last_tail_nodes);
        if !new_transactions_only_reference_tail_nodes || contains_key_changes {
            // regenerate our keychain, which helps us decrypt our heroic data transactions
            self.generate_keychain()?;
        }
        let dag_state = if new_transactions_only_reference_tail_nodes {
            TopicDagState::DagUpdated
        } else {
            TopicDagState::DagRebuilt
        };
        Ok(dag_state)
    }

    fn generate_keychain(&mut self) -> Result<()> {
        let keychain = self
            .state()
            .secrets()
            .iter()
            .filter_map(|s| {
                s.transaction_id()
                    .as_ref()
                    .map(|txid| (txid.clone(), s.secret().derive_secret_key()))
            })
            .map(|(txid, res)| Ok((txid, res?)))
            .collect::<Result<HashMap<_, _>>>()?;
        self.set_keychain(keychain);
        Ok(())
    }

    /// Find operations that are not referenced in any other operation's `previous` list.
    fn find_leaves<'a>(&'a self) -> Vec<&'a TransactionID> {
        let mut seen: HashSet<&TransactionID> = HashSet::new();
        for tx in self.transactions() {
            // account for snapshots when finding leaves
            if let Some(snapshot) = tx.snapshot() {
                let ops = snapshot.entry().ordered_transactions();
                for op in ops.iter().take(ops.len() - 1) {
                    seen.insert(op.transaction_id());
                }
            } else {
                match tx.transaction().entry().body() {
                    TransactionBody::ExtV1 { previous_transactions, .. } => {
                        for prev in previous_transactions {
                            seen.insert(prev);
                        }
                    }
                    _ => {}
                }
            }
        }
        self.transactions()
            .iter()
            .filter_map(|t| if seen.get(t.id()).is_some() { None } else { Some(t.id()) })
            .collect::<Vec<_>>()
    }

    /// Create a Stamp transaction from a packet.
    pub fn transaction_from_packet<T: Into<Timestamp> + Clone>(
        &self,
        transactions: &Transactions,
        hash_with: &HashAlgo,
        previous_transactions: Option<Vec<TransactionID>>,
        now: T,
        packet: &Packet,
    ) -> Result<Transaction> {
        let packet_ser = packet.serialize_binary()?;
        let prev = previous_transactions.unwrap_or_else(|| self.find_leaves().into_iter().cloned().collect::<Vec<_>>());
        let ty = Vec::from(b"/stamp/sync/v1/packet");
        let topic_id_ser = self.id().serialize_binary()?;
        let trans = transactions.ext(
            hash_with,
            now,
            prev,
            Some(ty.into()),
            Some([(b"topic_id".as_slice(), &topic_id_ser[..])]),
            packet_ser.into(),
        )?;
        Ok(trans)
    }

    /// Expands our snapshot(s), lifting the existing transactions out such that they can be
    /// included in a DAG, recreating any missing transactions into the chain, and making sure the
    /// causal order of all the transactions is preserved by modifying `previous_transactions`
    /// where necessary. This effectively reverses the process of snapshotting so a DAG can be made
    /// "whole" again after its transactions are snapshotted.
    ///
    /// The modified transactions, an id->tx index of all current/modified transactions, and a set
    /// of re-created transaction ids is passed into the given callback which can then reconstruct
    /// the DAG and walk/apply it as needed.
    fn with_expanded_snapshots<'a, F, T>(&'a self, mut cb: F) -> Result<T>
    where
        F: FnMut(Vec<TopicTransaction>, HashMap<&'a TransactionID, &'a TopicTransaction>, HashSet<TransactionID>) -> Result<T>,
    {
        let mut tx_index: HashMap<&TransactionID, &TopicTransaction> = HashMap::new();
        let mut unsets: HashSet<TransactionID> = HashSet::new();
        let mut snapshots: HashMap<&TransactionID, Vec<&TransactionID>> = HashMap::new();

        if self.transactions().len() == 0 {
            return cb(Vec::new(), HashMap::new(), HashSet::new());
        }

        for tx in self.transactions() {
            tx_index.insert(tx.id(), tx);
            if let Some(snapshot) = tx.snapshot.as_ref() {
                snapshots.insert(tx.id(), snapshot.active_transactions());
            } else {
                for txid in tx.unset_ids()? {
                    unsets.insert(txid);
                }
            }
        }

        // this collection will house transactions from two sources:
        //
        // 1. transactions that contain snapshots. the snapshots are removed and expended, and the
        //    raw transaction is then added to this vec. note that although the original
        //    transaction will will exist, this vec will be fed to the DAG builder after the
        //    originals (self.transactions()) which effectively overrides the previous entries.
        // 2. removed transactions that are then recreated by our heroic snapshot(s).
        let mut transactions_modified = Vec::new();
        // a store for saving mods to operations that we can't do inline because of borrow checker
        // stuff
        let mut tx_set_prev: HashMap<TransactionID, Vec<TransactionID>> = HashMap::new();
        // any tx that we need to recreate. see comment below for deets.
        let mut recreate_unset_tx: Vec<(TransactionID, Timestamp)> = Vec::new();
        // any tx that have been recreated. this is passed into our callback.
        let mut recreated: HashSet<TransactionID> = HashSet::new();
        // things are going to get weird here. because we can delete items in our DAG via
        // snapshotting, that means our DAG can have broken chains that might leave a whole lot of
        // nodes "unvisited."
        //
        // so what we do is:
        //
        //   1. "lift" the nodes from the snapshot out of the snap and into their own individual
        //      nodes. they should already exist, so really what we're doing is overwriting the
        //      backlinks such that the nodes proceed in causal order as defined by the snapshot.
        //   2. for any missing nodes (unset) we recreate them using the id/timestamp information
        //      in the snapshot.
        //
        // doing the above, we can effectively entirely rebuild our DAG from snapshot using
        // sequential backlinks in such a way that non-snapshotted nodes can still reference the
        // snapshotted nodes, preserving causal ordering.
        //
        // let's see an example:
        //
        //   D (prev: [], snapshot: [A, B (unset), C])
        //   E (prev: [B, D])
        //   F (prev: [E, C])
        //
        // D snapshotted A, B, and C in order. We can assume the A->B->C causal chain is messed up
        // because snapshots will often remove links. E and F reference operations that are
        // contained in snapshot D.
        //
        // So we do something nobody has ever done before: we lift A, B, and C out of D and jerry
        // rig them back into the DAG *in causal order* (keep in mind causal order was preserved
        // when we ran the snapshot), so now we have a full DAG chain. We have to re-create B
        // because it was unset, but we have all the information we need to do so effectively:
        //
        //   A (prev: [])
        //   B (prev: [A])
        //   C (prev: [B])
        //   D (prev: [C])
        //   E (prev: [B, D])
        //   F (prev: [E, C])
        //
        // Note that in this case, D is no longer a snapshot but a regular tx...just like any of
        // them.
        for tx in self.transactions() {
            // skip any transaction that doesn't contain a snapshot
            if !tx.snapshot().is_some() {
                continue;
            }
            // clone the transaction since we're going to modify it and push it into our mods list
            let tx_cloned = tx.clone();
            let mut snapshot = tx_cloned.snapshot().as_ref().expect("snapshot should definitely exist").clone();
            let mut last_snap_transaction_id = None;
            for snap_op in snapshot.entry_mut().ordered_transactions_mut().drain(..) {
                // if this is a removal, we need to mark it for re-creation, otherwise we assume
                // that the tx already exists in the original transactions list and can be
                // referenced directly (since snapshots don't actually store transactions, just
                // ordered transaction ids).
                let prev_new = last_snap_transaction_id.unwrap_or_else(|| Vec::new());
                let modify_prev = match &snap_op {
                    SnapshotOrderedOp::Remove { id, timestamp } => {
                        if !tx_index.contains_key(id) {
                            recreate_unset_tx.push((id.clone(), timestamp.clone()));
                        }
                        // when re-creating, we always request setting previous_transactions
                        true
                    }
                    _ => {
                        let snap_tx = tx_index
                            .get(snap_op.transaction_id())
                            .ok_or_else(|| Error::TopicMissingTransactions(vec![snap_op.transaction_id().clone()]))?;
                        let prev_current = snap_tx.previous_transactions()?;
                        let prev_eq = (prev_current.len() == 0 && prev_new.len() == 0)
                            || (prev_current.len() == 1 && prev_new.len() == 1 && prev_current[0] == &prev_new[0]);
                        !prev_eq
                    }
                };

                // if our new previsout_transactions value is actually different from the original
                // transaction, set it to be modified later. otherwise, don't bother.
                if modify_prev {
                    tx_set_prev.insert(snap_op.transaction_id().clone(), prev_new);
                }

                last_snap_transaction_id = Some(vec![snap_op.transaction_id().clone()]);
            }
            transactions_modified.push(tx_cloned);
        }

        // now, recreate any transactions that were unset/removed to fill in the blanks in our DAG
        for (id, timestamp) in recreate_unset_tx {
            let trans = Transaction::create_raw_with_id(
                id,
                timestamp,
                vec![],
                TransactionBody::ExtV1 {
                    creator: TransactionID::from(Hash::new_blake3_from_bytes([0u8; 32])).into(),
                    ty: None,
                    // we set this a bit later
                    previous_transactions: vec![],
                    context: None,
                    payload: Vec::new().into(),
                },
            );

            let recreated_op = TopicTransaction {
                transaction: trans,
                snapshot: None,
            };
            recreated.insert(recreated_op.id().clone());
            transactions_modified.push(recreated_op);
        }

        // now, modify any previous_transactions fields as dictated by our expanded snapshot
        for tx in transactions_modified.iter_mut() {
            if let Some(prev) = tx_set_prev.remove(tx.id()) {
                let _ = tx.transaction_mut().try_mod_ext_previous_transaction(prev)?;
            }
        }
        for tx in self.transactions() {
            if let Some(prev) = tx_set_prev.remove(tx.id()) {
                let mut tx_clone = tx.clone();
                let _ = tx_clone.transaction_mut().try_mod_ext_previous_transaction(prev)?;
                transactions_modified.push(tx_clone);
            }
        }

        cb(transactions_modified, tx_index, recreated)
    }

    /// Return all operations in this set, ordered causally. This will return an error if we have
    /// any breaks in our causal chain (ie, missing transactions).
    pub fn get_transactions_ordered<'a>(&'a self) -> Result<Vec<&'a TopicTransaction>> {
        let mut output: Vec<&'a TopicTransaction> = Vec::with_capacity(self.transactions().len());
        self.with_expanded_snapshots(|transactions_modified, mut tx_index, _recreated| {
            let nodes_existing = self.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
            let nodes_modified = transactions_modified.iter().map(|x| x.into()).collect::<Vec<_>>();

            // NOTE: we explicitely pass `nodes_modified` second here!
            let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_existing, &nodes_modified]);
            if dag.missing().len() > 0 {
                Err(Error::TopicMissingTransactions(dag.missing().iter().cloned().cloned().collect::<Vec<_>>()))?;
            }
            for node_id in dag.visited() {
                #[allow(suspicious_double_ref_op)]
                let node = dag
                    .index()
                    .get(node_id)
                    .ok_or_else(|| Error::TopicMissingTransactions(vec![node_id.clone().clone()]))?;
                // NOTE: we can't push `node.node()` directly here because it's a clone of our
                // original list, so instead we pull from our dumb tx index.
                if let Some(tx) = tx_index.remove(node.node().id()) {
                    output.push(tx);
                }
            }
            Ok(())
        })?;
        Ok(output)
    }

    /// Returns all `DataSet` operations, in order, decrypted.
    pub fn get_data<T>(&self) -> Result<Vec<Result<T>>>
    where
        T: SerdeBinary,
    {
        let data_ops = self
            .get_transactions_ordered()?
            .iter()
            .map(|t| match t.get_packet() {
                Ok(packet) => match packet {
                    Packet::DataSet { key_ref, payload } => {
                        let secret_key = self.keychain.get(&key_ref).ok_or_else(|| Error::TopicSecretNotFound(key_ref))?;
                        let plaintext = secret_key.open(&payload)?;
                        let des = T::deserialize_binary(&plaintext)?;
                        Ok(Some(des))
                    }
                    _ => Ok(None),
                },
                Err(e) => Err(e),
            })
            .filter_map(|t| match t {
                Ok(Some(val)) => Some(Ok(val)),
                Err(e) => Some(Err(e)),
                _ => None,
            })
            .collect::<Vec<Result<_>>>();
        Ok(data_ops)
    }

    /// Create a snapshot at a specific point in the operation chain.
    ///
    /// It's important to note that this operation doesn't snapshot all previous temporal
    /// operations, but rather just the ones that causally happened before the `replaces`
    /// operation. In other words, given:
    ///
    /// ```text
    /// A -> B -> C \
    ///              -> G -> H
    /// D -> E -> F /
    /// ```
    ///
    /// If a snapshot is created at `C`, it will snapshot `A`, `B`, and `C` but will NOT include
    /// `D`, `E`, or `F` because they are on a different causal chain. Snapshotting `G` would
    /// include `A`, `B`, `C`, `D`, `E`, `F` and `G`.
    ///
    /// This returns a list of all operations that have been removed by the snapshot process,
    /// allowing deletion in whatever storage mechanism.
    pub fn snapshot(&mut self, master_key: &SecretKey, sign_key: &SignKeypair, replaces: &TransactionID) -> Result<HashSet<TransactionID>> {
        let (final_nodes, removed) = self.with_expanded_snapshots(|transactions_modified, _tx_index, _recreated| {
            // this tracks nodes that either a) unset other nodes or b) have been unset
            let mut unsets_in_causal_chain: HashSet<TransactionID> = HashSet::new();
            // tracks transactions that are part of another snapshot
            let mut in_existing_snapshot: HashMap<&TransactionID, &SnapshotOrderedOp> = HashMap::new();
            // a set of all transactions that this snapshot will encompass
            let mut include_in_current_snapshot: HashSet<&TransactionID> = HashSet::new();
            // track transactions that have been removed as part of other previous snapshots. we
            // need to do this so we don't go trying to load data from these removals (which will
            // be expanded to fake transactions by `with_expanded_snapshots()`)
            let mut previously_snapshotted_removals: HashMap<&TransactionID, &SnapshotOrderedOp> = HashMap::new();
            // a list of transactions that are being removed by this snapshot. this is returned to the
            // caller so these transactions can be wiped from storage.
            let mut removed = HashSet::new();

            let nodes_old = self.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
            let nodes_modified = transactions_modified.iter().map(|x| x.into()).collect::<Vec<_>>();
            let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_old, &nodes_modified]);
            if dag.missing().len() > 0 {
                Err(Error::TopicMissingTransactions(dag.missing().iter().cloned().cloned().collect::<Vec<_>>()))?;
            }
            if !dag.visited().contains(&replaces) {
                Err(Error::SnapshotFailed)?;
            }

            // find and index all nodes causally preceding (and including) `replaces`.
            // this gives is a big fat list we can compare against when creating the final snapshot
            // list.
            let mut walk_queue = VecDeque::new();
            walk_queue.push_back(replaces);
            while let Some(id) = walk_queue.pop_front() {
                include_in_current_snapshot.insert(id);
                let tx = match dag.index().get(id) {
                    Some(x) => x.node(),
                    None => continue,
                };
                for prev in tx.previous_transactions()? {
                    walk_queue.push_back(prev);
                }
            }

            // sorry for all the loops
            //
            // we're going to index all transactions that exist in previous snapshots, as well as find
            // all nodes in this snapshot's causal chain that have been unset
            for tx in self.transactions() {
                // only track unsets *if the unsetting node is in the snapshot's causal chain*
                if include_in_current_snapshot.contains(tx.id()) {
                    for txid in tx.unset_ids()? {
                        unsets_in_causal_chain.insert(txid);
                    }
                }
                // track and save a) all previously snapshotted tx and b) all removals
                if let Some(snapshot) = tx.snapshot() {
                    for op in snapshot.entry().ordered_transactions() {
                        in_existing_snapshot.insert(op.transaction_id(), op);
                        match op {
                            SnapshotOrderedOp::Remove { id, .. } => {
                                previously_snapshotted_removals.insert(id, op);
                            }
                            _ => {}
                        }
                    }
                }
            }

            // this list will replace `self.transactions`
            let mut final_nodes: Vec<TopicTransaction> = Vec::with_capacity(self.transactions().len());
            // this is our final snapshot list
            let mut snapshot_ordered_operations: Vec<SnapshotOrderedOp> = Vec::new();
            // marks whether or not we actually found our replacement node
            for node_id in dag.visited() {
                #[allow(suspicious_double_ref_op)]
                let node = dag
                    .index()
                    .get(node_id)
                    .ok_or_else(|| Error::TopicMissingTransactions(vec![node_id.clone().clone()]))?;
                #[allow(suspicious_double_ref_op)]
                let mut tx: TopicTransaction = node.node().clone().clone();
                // just remove any existing snapshots. we don't need them anymore.
                tx.snapshot_mut().take();
                if tx.id() == replaces {
                    // this is our replacement node! create our snapshot.
                    let save = SnapshotOrderedOp::Keep { id: tx.id().clone() };
                    snapshot_ordered_operations.push(save);
                    tx.snapshot = Some(Snapshot::new(master_key, sign_key, snapshot_ordered_operations.clone())?);
                    final_nodes.push(tx);
                } else if include_in_current_snapshot.contains(tx.id()) {
                    if let Some(op) = in_existing_snapshot.remove(tx.id()) {
                        match op {
                            SnapshotOrderedOp::Keep { .. } => {
                                final_nodes.push(tx);
                            }
                            _ => {}
                        }
                        snapshot_ordered_operations.push(op.clone());
                    } else if tx.is_unset()? || unsets_in_causal_chain.contains(tx.id()) {
                        // if we still haven't found our replacement node and the current tx is
                        // eligible, push it onto the ordered tx list
                        let save = SnapshotOrderedOp::Remove {
                            id: tx.id().clone(),
                            timestamp: tx.timestamp().clone(),
                        };
                        snapshot_ordered_operations.push(save);
                        // notify the caller this tx can be removed.
                        removed.insert(tx.id().clone());
                    } else {
                        let save = SnapshotOrderedOp::Keep { id: tx.id().clone() };
                        snapshot_ordered_operations.push(save);
                        final_nodes.push(tx);
                    }
                } else {
                    final_nodes.push(tx);
                }
            }
            Ok((final_nodes, removed))
        })?;
        self.transactions = final_nodes;
        Ok(removed)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use stamp_core::{
        crypto::base::{
            rng::{self, ChaCha20Rng, CryptoRng, RngCore},
            Hash, HashAlgo, SecretKey,
        },
        dag::tx_chain,
        identity::keychain::{AdminKey, ExtendKeypair, Key},
    };
    use std::cell::{Ref, RefCell};
    use std::str::FromStr;

    fn ts(time: &'static str) -> Timestamp {
        Timestamp::from_str(time).unwrap()
    }

    fn create_fake_identity_with_master<R: RngCore + CryptoRng>(
        rng: &mut R,
        now: Timestamp,
        master_key: SecretKey,
    ) -> (SecretKey, Transactions, AdminKey) {
        let transactions = stamp_core::dag::Transactions::new();
        let admin = stamp_core::identity::keychain::AdminKeypair::new_ed25519(rng, &master_key).unwrap();
        let admin_key = stamp_core::identity::keychain::AdminKey::new(admin, "Alpha", None);
        let policy = stamp_core::policy::Policy::new(
            vec![stamp_core::policy::Capability::Permissive],
            stamp_core::policy::MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![admin_key.key().clone().into()],
            },
        );
        let sign_key = Key::new_sign(SignKeypair::new_ed25519(rng, &master_key).unwrap());
        let crypto_key = Key::new_crypto(CryptoKeypair::new_curve25519xchacha20poly1305(rng, &master_key).unwrap());
        let transactions = transactions
            .clone()
            .push_transaction(
                transactions
                    .create_identity(&HashAlgo::Blake3, now.clone(), vec![admin_key.clone()], vec![policy])
                    .unwrap()
                    .sign(&master_key, &admin_key)
                    .unwrap(),
            )
            .unwrap();
        let transactions = transactions
            .clone()
            .push_transaction(
                transactions
                    .add_subkey(&HashAlgo::Blake3, now.clone(), sign_key, "/stamp/sync/v1/sign", None)
                    .unwrap()
                    .sign(&master_key, &admin_key)
                    .unwrap(),
            )
            .unwrap();
        let transactions = transactions
            .clone()
            .push_transaction(
                transactions
                    .add_subkey(&HashAlgo::Blake3, now.clone(), crypto_key, "/stamp/sync/v1/crypto", None)
                    .unwrap()
                    .sign(&master_key, &admin_key)
                    .unwrap(),
            )
            .unwrap();
        (master_key, transactions, admin_key)
    }

    fn create_fake_identity<R: RngCore + CryptoRng>(rng: &mut R, now: Timestamp) -> (SecretKey, Transactions, AdminKey) {
        let master_key = SecretKey::new_xchacha20poly1305(rng).unwrap();
        create_fake_identity_with_master(rng, now, master_key)
    }

    #[allow(dead_code)]
    fn ids_to_names(map: &HashMap<TransactionID, &'static str>, ops: &[&TransactionID]) -> Vec<&'static str> {
        ops.iter().map(|x| map.get(x).cloned().unwrap_or("??")).collect::<Vec<_>>()
    }

    #[allow(dead_code)]
    fn dump_tx_(id_to_name: &HashMap<TransactionID, &'static str>, transactions: &[Transaction]) {
        for tx in transactions {
            println!("- idx: {} -> {}", id_to_name.get(tx.id()).unwrap(), tx.id());
            match tx.entry().body() {
                TransactionBody::ExtV1 { previous_transactions, .. } => {
                    for prev in previous_transactions {
                        println!("  - previous: {}", prev);
                    }
                }
                _ => println!("  - <bad trans> -- {:?}", tx),
            }
        }
    }

    #[allow(dead_code)]
    fn dump_tx(tx: &[(&'static str, &Transaction)]) {
        let name_map = tx.iter().map(|(name, tx)| (tx.id().clone(), name)).collect::<HashMap<_, _>>();
        for (name, trans) in tx {
            #[allow(suspicious_double_ref_op)]
            let tt = TopicTransaction::new(trans.clone().clone());
            let next = tt
                .previous_transactions()
                .expect("previous_transactions()")
                .iter()
                .map(|prev| {
                    let name = name_map.get(prev).unwrap_or(&&"<missing>");
                    format!("{}", name)
                })
                .collect::<Vec<_>>()
                .join(", ");
            println!("- {}:    {}    prev: [{}]", trans.id(), name, next);
        }
    }

    fn packet_body(
        transactions: &Transactions,
        now: Timestamp,
        previous_transactions: Vec<TransactionID>,
        topic_id: &TopicID,
        packet: &Packet,
    ) -> Transaction {
        let packet_ser = packet.serialize_binary().unwrap();
        let topic_id_ser = topic_id.serialize_binary().unwrap();
        transactions
            .ext(
                &HashAlgo::Blake3,
                now,
                previous_transactions,
                Some(Vec::from(b"/stamp/sync/v1/packet").into()),
                Some([(b"topic_id".as_slice(), &topic_id_ser[..])]),
                packet_ser.into(),
            )
            .unwrap()
    }

    // TODO: rm and replace all instances with `Peer`
    struct PacketGen<'a, 'b, 'c> {
        rng: ChaCha20Rng,
        transactions: &'a Transactions,
        topic_id: &'b TopicID,
        topic_seckey: &'c SecretKey,
    }

    impl<'a, 'b, 'c> PacketGen<'a, 'b, 'c> {
        fn new<R: RngCore + CryptoRng>(
            rng: &mut R,
            transactions: &'a Transactions,
            topic_id: &'b TopicID,
            topic_seckey: &'c SecretKey,
        ) -> Self {
            let mut randbuf = [0u8; 32];
            rng.fill_bytes(&mut randbuf);

            Self {
                rng: rng::chacha20_seeded(randbuf),
                transactions,
                topic_id,
                topic_seckey,
            }
        }

        fn tx(&self, now: Timestamp, prev: Vec<TransactionID>, packet: Packet) -> Transaction {
            packet_body(self.transactions, now, prev, self.topic_id, &packet)
        }

        fn tx_data(&mut self, now: Timestamp, prev: Vec<TransactionID>, id: &TransactionID, payload_plaintext: &[u8]) -> Transaction {
            let packet = Packet::DataSet {
                key_ref: id.clone(),
                payload: self.topic_seckey.seal(&mut self.rng, payload_plaintext).unwrap(),
            };
            self.tx(now, prev, packet)
        }
    }

    #[derive(Clone, Debug, getset::Getters, getset::MutGetters, getset::Setters)]
    #[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
    struct Peer {
        rng: ChaCha20Rng,
        #[getset(skip)]
        topic: RefCell<Topic>,
        master_passphrase: &'static str,
        master_key: SecretKey,
        identity: Transactions,
        device: Device,
        crypto_keys: Vec<CryptoKeypair>,
        key_packets: Vec<KeyPacket>,
    }

    impl Peer {
        fn topic(&self) -> Ref<'_, Topic> {
            self.topic.borrow()
        }

        fn passphrase_to_key(passphrase: &'static str) -> SecretKey {
            let bytes: [u8; 32] = Hash::new_blake3(passphrase.as_bytes()).unwrap().as_bytes().try_into().unwrap();
            SecretKey::new_xchacha20poly1305_from_bytes(bytes).unwrap()
        }

        fn new_identity<R: RngCore + CryptoRng>(rng_seed: &mut R, master_passphrase: &'static str, device_name: &str) -> Self {
            let mut randbuf = [0u8; 32];
            rng_seed.fill_bytes(&mut randbuf);
            let mut rng = rng::chacha20_seeded(randbuf);

            let topic = Topic::new(TopicID::new(&mut rng));

            let (master_key, transactions, _admin_key) = create_fake_identity_with_master(
                &mut rng,
                Timestamp::from_str("2024-01-01T00:00:06Z").unwrap(),
                Self::passphrase_to_key(master_passphrase),
            );

            let identity = transactions.build_identity().unwrap();
            let sign_key = identity
                .keychain()
                .subkey_by_name("/stamp/sync/v1/sign")
                .unwrap()
                .key()
                .as_signkey()
                .unwrap();

            let device = Device::new(&mut rng, device_name.into());
            let crypto_keys = (0..5)
                .into_iter()
                .map(|_| CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap())
                .collect::<Vec<_>>();
            let key_packets = crypto_keys
                .iter()
                .map(|k| KeyPacket::new(&master_key, sign_key, identity.id().clone(), device.id().clone(), k.clone().into()).unwrap())
                .collect::<Vec<_>>();
            Self {
                rng,
                topic: RefCell::new(topic),
                master_passphrase,
                master_key,
                identity: transactions,
                device,
                crypto_keys,
                key_packets,
            }
        }

        fn new_device(&mut self, device_name: &str) -> Self {
            let mut randbuf = [0u8; 32];
            self.rng_mut().fill_bytes(&mut randbuf);
            let mut rng = rng::chacha20_seeded(randbuf);

            let topic = Topic::new(self.topic().id().clone());
            let master_key = Self::passphrase_to_key(self.master_passphrase());

            let identity = self.identity().build_identity().unwrap();
            let sign_key = identity
                .keychain()
                .subkey_by_name("/stamp/sync/v1/sign")
                .unwrap()
                .key()
                .as_signkey()
                .unwrap();

            let device = Device::new(&mut rng, device_name.into());
            let crypto_keys = (0..5)
                .into_iter()
                .map(|_| CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap())
                .collect::<Vec<_>>();
            let key_packets = crypto_keys
                .iter()
                .map(|k| KeyPacket::new(&master_key, sign_key, identity.id().clone(), device.id().clone(), k.clone().into()).unwrap())
                .collect::<Vec<_>>();

            Self {
                rng,
                topic: RefCell::new(topic),
                master_passphrase: self.master_passphrase(),
                master_key,
                identity: self.identity.clone(),
                device,
                crypto_keys,
                key_packets,
            }
        }

        fn as_member(&self, permissions: Vec<Permission>, devices: Vec<Device>) -> Member {
            Member::new(self.identity().identity_id().unwrap().clone(), permissions, devices)
        }

        fn tx(&self, now: Timestamp, prev: Option<Vec<TransactionID>>, packet: Packet) -> Transaction {
            let identity = self.identity().build_identity().unwrap();
            let admin_key = identity.keychain().admin_key_by_name("Alpha").unwrap();
            let transaction = self
                .topic()
                .transaction_from_packet(self.identity(), &HashAlgo::Blake3, prev, now, &packet)
                .unwrap();
            transaction.sign(self.master_key(), admin_key).unwrap()
        }

        fn tx_data<T: SerdeBinary>(
            &mut self,
            now: Timestamp,
            payload: T,
            prev: Option<Vec<TransactionID>>,
            control_id: Option<TransactionID>,
        ) -> Transaction {
            let payload_plaintext = payload.serialize_binary().unwrap();
            let topic_seckey = self.topic().current_secret_key().unwrap().unwrap();
            let control_id =
                control_id.unwrap_or_else(|| self.topic().secrets().last().unwrap().transaction_id().as_ref().unwrap().clone());
            let packet = Packet::DataSet {
                key_ref: control_id,
                payload: topic_seckey.seal(&mut self.rng_mut(), &payload_plaintext[..]).unwrap(),
            };
            self.tx(now, prev, packet)
        }

        fn push_tx(&self, identities: &HashMap<IdentityID, &Transactions>, transactions: &[&Transaction]) -> Result<TopicDagState> {
            let topic_tx = transactions.iter().cloned().map(|t| t.clone().into()).collect::<Vec<_>>();
            let fake_topic = Topic::new(TopicID::from_bytes([0; 16]));
            let mut topic = self.topic.replace(fake_topic);
            let dag_state = topic.push_transactions_mut(
                topic_tx,
                identities,
                self.master_key(),
                &self.crypto_keys().iter().collect::<Vec<_>>(),
                &self.identity.identity_id().unwrap(),
                &self.device().id().clone(),
            )?;
            // take the topic out of the peer so we can mutate it without the borrow checker
            // blowing a gasket
            self.topic.replace(topic);
            Ok(dag_state)
        }

        fn snapshot(&self, replaces: &TransactionID) -> Result<HashSet<TransactionID>> {
            let identity = self.identity().build_identity().unwrap();
            let sign_key = identity
                .keychain()
                .subkey_by_name("/stamp/sync/v1/sign")
                .unwrap()
                .key()
                .as_signkey()
                .unwrap();
            let fake_topic = Topic::new(TopicID::from_bytes([0; 16]));
            let mut topic = self.topic.replace(fake_topic);
            let res = topic.snapshot(self.master_key(), &sign_key, replaces)?;
            self.topic.replace(topic);
            Ok(res)
        }
    }

    /// A quick structure we can use for creating data within a topic.
    #[derive(Clone, Debug, PartialEq, AsnType, Encode, Decode)]
    struct AppData {
        data: String,
    }
    impl AppData {
        fn new<T: Into<String>>(data: T) -> Self {
            Self { data: data.into() }
        }
    }
    impl SerdeBinary for AppData {}

    fn create_1p_topic(
        topic_id: &TopicID,
        master_key: &SecretKey,
        admin_key: &AdminKey,
        identity: &Transactions,
        crypto_key: &CryptoKeypair,
        device_id: &DeviceID,
        transactions: Vec<Transaction>,
    ) -> Topic {
        let identity_id = identity.identity_id().unwrap();
        let transactions = transactions
            .into_iter()
            .map(|t| t.sign(master_key, admin_key).unwrap())
            .map(|t| TopicTransaction::new(t))
            .collect::<Vec<_>>();
        let identity_map = HashMap::from([(identity.identity_id().unwrap(), identity)]);
        Topic::new_from_transactions(topic_id.clone(), transactions, &identity_map, master_key, &[&crypto_key], &identity_id, device_id)
            .unwrap()
    }

    // creates a device_id -> crypto pubkey mapping
    fn device_lookup<'a>(packets: &[&'a KeyPacket]) -> BTreeMap<&'a DeviceID, &'a CryptoKeypairPublic> {
        packets
            .iter()
            .map(|p| (p.entry().device_id(), p.entry().pubkey()))
            .collect::<BTreeMap<_, _>>()
    }

    // creates a lookup table for a set of peers
    fn id_lookup<'a>(peers: &[&'a Peer]) -> HashMap<IdentityID, &'a Transactions> {
        peers
            .iter()
            .map(|p| (p.identity().identity_id().unwrap(), p.identity()))
            .collect::<HashMap<_, _>>()
    }

    fn admin_perms() -> Vec<Permission> {
        vec![
            Permission::DataSet,
            Permission::DataUnset,
            Permission::MemberDevicesUpdate,
            Permission::MemberPermissionsChange,
            Permission::TopicRekey,
        ]
    }

    // reduces some boilerplate when creating re-key entries
    macro_rules! rkmember {
        ($peer:expr, $permissions:expr, $keyidx:expr) => {
            (
                $peer.as_member($permissions, vec![$peer.device().clone()]),
                &device_lookup(&[&$peer.key_packets()[$keyidx]]),
            )
        };
    }

    macro_rules! topicdata {
        ($peer:expr) => {{
            $peer.topic().get_data::<AppData>().unwrap().into_iter().collect::<Result<Vec<_>>>()
        }};
    }

    #[test]
    fn topic_push_transaction() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"get a job").unwrap().as_bytes().try_into().unwrap());
        let (master_key, transactions, admin_key) = create_fake_identity(&mut rng, ts("2024-01-01T00:00:06Z"));
        let node_a_sync_crypto = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();

        let topic_id = TopicID::new(&mut rng);
        let topic_secret = TopicSecret::new(&mut rng);
        let topic_seckey = topic_secret.derive_secret_key().unwrap();

        let mut pkt = PacketGen::new(&mut rng, &transactions, &topic_id, &topic_seckey);

        let member = Member::new(
            transactions.identity_id().unwrap(),
            vec![
                Permission::DataSet,
                Permission::DataUnset,
                Permission::MemberDevicesUpdate,
                Permission::MemberPermissionsChange,
                Permission::TopicRekey,
            ],
            vec![Device::new(&mut rng, "laptop".into())],
        );

        let node_a_member = MemberRekey::seal(
            &mut rng,
            member.clone(),
            &BTreeMap::from([(member.devices[0].id(), &node_a_sync_crypto.clone().into())]),
            vec![SecretEntry::new_current_transaction(topic_secret.clone())],
        )
        .unwrap();

        let (topic_tx, _name_to_tx, _id_to_name) = tx_chain! {
            [
                A = ("2024-01-03T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::TopicRekey { members: vec![node_a_member.clone()] }));
                B = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"pardon me"));
                C = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"may i use your bathroom??!"));
                D = ("2024-01-04T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::DataUnset { transaction_ids: vec![C.id().clone()] }));
                E = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"thank you!!"));
                F = ("2024-01-02T00:01:02Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"aughh!"));
                G = ("2024-01-04T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::DataUnset { transaction_ids: vec![E.id().clone()] }));
            ],
            [
                [A] <- [B],
                [A, B] <- [C],
                [C] <- [D, E],
                [E] <- [F],
                [D, F] <- [G],
            ],
        };

        let push = |topic: &mut Topic, tx: Vec<Transaction>| {
            let txt = tx
                .into_iter()
                .map(|t| t.sign(&master_key, &admin_key).unwrap())
                .map(|t| TopicTransaction::new(t))
                .collect::<Vec<_>>();
            let identity_id = transactions.identity_id().unwrap();
            let identity_map = HashMap::from([(identity_id.clone(), &transactions)]);
            topic.push_transactions_mut(txt, &identity_map, &master_key, &[&node_a_sync_crypto], &identity_id, member.devices()[0].id())
        };
        {
            let mut topic = Topic::new(topic_id.clone());
            push(&mut topic, Vec::from(&topic_tx[0..3])).unwrap();
            push(&mut topic, Vec::from(&topic_tx[3..])).unwrap();
        }
        {
            let mut topic = Topic::new(topic_id.clone());
            push(&mut topic, Vec::from(&topic_tx[0..3])).unwrap();
            let res = push(&mut topic, Vec::from(&topic_tx[4..]));
            match res.err().unwrap() {
                Error::TopicMissingTransactions(tx1) => {
                    assert_eq!(tx1, vec![topic_tx[3].id().clone()]);
                }
                _ => panic!("unexpected"),
            }
        }
    }

    #[test]
    fn key_packet_new_verify() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"get a job").unwrap().as_bytes().try_into().unwrap());
        let (master_key, transactions, _admin_key) = create_fake_identity(&mut rng, ts("2024-01-01T00:00:06Z"));
        let node_a_sync_sig = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let node_a_sync_crypto = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();

        let device = Device::new(&mut rng, "laptop".into());
        let packet = KeyPacket::new(
            &master_key,
            &node_a_sync_sig,
            transactions.identity_id().unwrap(),
            device.id().clone(),
            node_a_sync_crypto.clone().into(),
        )
        .unwrap();

        packet.verify(&node_a_sync_sig.clone().into()).unwrap();
        assert_eq!(packet.entry().pubkey(), &node_a_sync_crypto.clone().into());

        {
            let mut packet = packet.clone();
            let fake_identity_id = IdentityID::from(TransactionID::from(Hash::new_blake3(b"zing").unwrap()));
            packet.entry_mut().set_identity_id(fake_identity_id.clone());
            let res = packet.verify(&node_a_sync_sig.clone().into());
            match res {
                Err(Error::KeyPacketTampered) => {}
                _ => panic!("unexpected: {:?}", res),
            }
        }
    }

    #[test]
    fn topic_get_transactions_ordered() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"get a job").unwrap().as_bytes().try_into().unwrap());
        let (master_key, transactions, admin_key) = create_fake_identity(&mut rng, ts("2024-01-01T00:00:06Z"));
        let node_a_sync_crypto = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();

        let topic_id = TopicID::new(&mut rng);
        let topic_secret = TopicSecret::new(&mut rng);
        let topic_seckey = topic_secret.derive_secret_key().unwrap();

        let mut pkt = PacketGen::new(&mut rng, &transactions, &topic_id, &topic_seckey);

        let member = Member::new(
            transactions.identity_id().unwrap(),
            vec![
                Permission::DataSet,
                Permission::DataUnset,
                Permission::MemberDevicesUpdate,
                Permission::MemberPermissionsChange,
                Permission::TopicRekey,
            ],
            vec![Device::new(&mut rng, "laptop".into())],
        );

        let node_a_member = MemberRekey::seal(
            &mut rng,
            member.clone(),
            &BTreeMap::from([(member.devices[0].id(), &node_a_sync_crypto.clone().into())]),
            vec![SecretEntry::new_current_transaction(topic_secret.clone())],
        )
        .unwrap();

        let (topic_tx, name_to_tx, id_to_name) = tx_chain! {
            [
                A = ("2024-01-03T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::TopicRekey { members: vec![node_a_member.clone()] }));
                B = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"pardon me"));
                C = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"may i use your bathroom??!"));
                D = ("2024-01-04T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::DataUnset { transaction_ids: vec![C.id().clone()] }));
                E = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"thank you!!"));
                F = ("2024-01-02T00:01:02Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"aughh!"));
                G = ("2024-01-04T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::DataUnset { transaction_ids: vec![E.id().clone()] }));
            ],
            [
                [A] <- [B],
                [A, B] <- [C],
                [C] <- [D, E],
                [E] <- [F],
                [D, F] <- [G],
            ],
        };
        let topic = create_1p_topic(
            &topic_id,
            &master_key,
            &admin_key,
            &transactions,
            &node_a_sync_crypto,
            member.devices()[0].id(),
            topic_tx.clone(),
        );
        {
            let ordered = topic
                .get_transactions_ordered()
                .unwrap()
                .into_iter()
                .map(|x| id_to_name.get(x.id()).unwrap())
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(ordered, vec!["A", "B", "C", "E", "F", "D", "G"]);
        }
        {
            let mut topic = create_1p_topic(
                &topic_id,
                &master_key,
                &admin_key,
                &transactions,
                &node_a_sync_crypto,
                member.devices()[0].id(),
                topic_tx,
            );
            let e_id = name_to_tx.get("E").unwrap().id();
            topic.transactions_mut().retain(|t| t.id() != e_id);
            let res = topic.get_transactions_ordered();
            match res {
                Err(Error::TopicMissingTransactions(tx)) => {
                    assert_eq!(tx, vec![e_id.clone()]);
                }
                _ => panic!("oh no"),
            }
        }
    }

    #[test]
    fn topic_multi_user_e2e_workflow() {
        // grab the transaction ids currently within a peer's topic
        macro_rules! txids {
            ($peer:expr) => {{
                $peer
                    .topic()
                    .get_transactions_ordered()
                    .unwrap()
                    .iter()
                    .map(|t| t.id())
                    .collect::<Vec<&TransactionID>>()
            }};
        }

        // because we can't infer types for some reason
        let empty_tx = Vec::<&TransactionID>::new();

        // ---------------------------------------------------------------------

        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"get a job").unwrap().as_bytes().try_into().unwrap());

        let mut butch_laptop = Peer::new_identity(&mut rng, "butch123", "laptop");
        let butch_phone = butch_laptop.new_device("phone");
        let mut dotty_laptop = Peer::new_identity(&mut rng, "dotty666", "laptop");
        let mut jerry_laptop = Peer::new_identity(&mut rng, "jerjer1", "laptop");
        let mut frankie_phone = Peer::new_identity(&mut rng, "frankiehankie", "phone");

        let genesis = {
            let packet = butch_laptop
                .topic()
                .rekey(&mut rng, vec![rkmember!(&butch_laptop, admin_perms(), 0)])
                .unwrap();
            butch_laptop.tx(ts("2024-12-08T01:00:00Z"), None, packet)
        };

        assert_eq!(butch_laptop.topic().secrets().len(), 0);
        assert_eq!(butch_phone.topic().secrets().len(), 0);
        assert_eq!(dotty_laptop.topic().secrets().len(), 0);
        assert_eq!(jerry_laptop.topic().secrets().len(), 0);
        assert_eq!(frankie_phone.topic().secrets().len(), 0);

        assert_eq!(txids!(&butch_laptop), empty_tx);
        assert_eq!(txids!(&butch_phone), empty_tx);
        assert_eq!(txids!(&dotty_laptop), empty_tx);
        assert_eq!(txids!(&jerry_laptop), empty_tx);
        assert_eq!(txids!(&frankie_phone), empty_tx);

        // make sure we can only add transactions from identities we've indexed
        {
            let res = butch_laptop.push_tx(&id_lookup(&[]), &[&genesis]);
            match res {
                Err(Error::IdentityMissing(id)) => {
                    assert_eq!(id, butch_laptop.identity().identity_id().unwrap());
                }
                _ => panic!("unexpected: {:?}", res),
            }
        }
        butch_laptop.push_tx(&id_lookup(&[&butch_laptop]), &[&genesis]).unwrap();

        assert_eq!(butch_laptop.topic().secrets().len(), 1);
        assert_eq!(butch_phone.topic().secrets().len(), 0);
        assert_eq!(dotty_laptop.topic().secrets().len(), 0);
        assert_eq!(jerry_laptop.topic().secrets().len(), 0);
        assert_eq!(frankie_phone.topic().secrets().len(), 0);

        assert_eq!(txids!(&butch_laptop), vec![genesis.id()]);
        assert_eq!(txids!(&butch_phone), empty_tx);
        assert_eq!(txids!(&dotty_laptop), empty_tx);
        assert_eq!(txids!(&jerry_laptop), empty_tx);
        assert_eq!(txids!(&frankie_phone), empty_tx);

        let data1 = butch_laptop.tx_data(ts("2024-12-08T01:00:01Z"), AppData::new("hi i'm butch"), None, None);
        butch_laptop.push_tx(&id_lookup(&[&butch_laptop]), &[&data1]).unwrap();
        assert_eq!(butch_laptop.topic().secrets().len(), 1);

        let rekey1 = {
            let packet = butch_laptop
                .topic()
                .rekey(
                    &mut rng,
                    vec![
                        rkmember!(&butch_laptop, admin_perms(), 0),
                        rkmember!(&dotty_laptop, admin_perms(), 0),
                    ],
                )
                .unwrap();
            butch_laptop.tx(ts("2024-12-08T01:00:00Z"), None, packet)
        };

        assert_eq!(butch_laptop.topic().secrets().len(), 1);
        assert_eq!(butch_phone.topic().secrets().len(), 0);
        assert_eq!(dotty_laptop.topic().secrets().len(), 0);
        assert_eq!(jerry_laptop.topic().secrets().len(), 0);
        assert_eq!(frankie_phone.topic().secrets().len(), 0);
        butch_laptop
            .push_tx(&id_lookup(&[&butch_laptop, &dotty_laptop]), &[&genesis, &rekey1])
            .unwrap();
        dotty_laptop
            .push_tx(&id_lookup(&[&butch_laptop, &dotty_laptop]), &[&data1, &genesis, &rekey1])
            .unwrap();

        assert_eq!(butch_laptop.topic().secrets().len(), 2);
        assert_eq!(butch_phone.topic().secrets().len(), 0);
        assert_eq!(dotty_laptop.topic().secrets().len(), 2);
        assert_eq!(jerry_laptop.topic().secrets().len(), 0);
        assert_eq!(frankie_phone.topic().secrets().len(), 0);

        assert_eq!(topicdata!(butch_laptop).unwrap(), vec![AppData::new("hi i'm butch")]);
        assert_eq!(topicdata!(butch_phone).unwrap(), vec![]);
        assert_eq!(topicdata!(dotty_laptop).unwrap(), vec![AppData::new("hi i'm butch")]);
        assert_eq!(topicdata!(jerry_laptop).unwrap(), vec![]);
        assert_eq!(topicdata!(frankie_phone).unwrap(), vec![]);

        // test peer getting packets they cannot decrypt
        {
            // test adding transactions with a bad identity set/list
            {
                let butch_phone = butch_phone.clone();
                // try to push transactions without having butch in the id list.
                {
                    let res = butch_phone.push_tx(&id_lookup(&[&dotty_laptop]), &[&genesis, &rekey1, &data1]);
                    match res {
                        Err(Error::IdentityMissing(ref id)) => {
                            assert_eq!(id, &butch_laptop.identity().identity_id().unwrap());
                        }
                        _ => panic!("unexpected: {:?}", res),
                    }
                }
            }
            // try adding our transactions to a device/identity we have no concept of yet
            {
                let jerry_laptop = jerry_laptop.clone();
                {
                    // this should work.
                    //
                    // after all, we don't know we don't have the keys we need until we have all
                    // the transactions for a particular topic. and we can't get all the
                    // transactions for a particular topic because there might always be a new
                    // transaction we don't have just around the corner with the keys we want. so
                    // really we have no good way of detecting missing secrets until we try to grab
                    // our data.
                    jerry_laptop
                        .push_tx(&id_lookup(&[&butch_laptop, &dotty_laptop, &jerry_laptop]), &[&genesis, &rekey1, &data1])
                        .unwrap();
                    // this should fail
                    let res = topicdata!(jerry_laptop);
                    match res {
                        Err(Error::TopicSecretNotFound(txid)) => {
                            assert_eq!(txid, genesis.id().clone());
                        }
                        _ => panic!("unexpected: {:?}", res),
                    }
                }
            }
        }

        // this timestamp is before data1, but should be ordered AFTER because Dotty has data1
        // already and is going to set it as the prev to data2.
        let data2 = dotty_laptop.tx_data(ts("2024-12-08T01:00:00Z"), AppData::new("dotty is best"), None, None);
        dotty_laptop
            .push_tx(&id_lookup(&[&butch_laptop, &dotty_laptop]), &[&data2])
            .unwrap();
        assert_eq!(butch_laptop.topic().secrets().len(), 2);
        assert_eq!(butch_phone.topic().secrets().len(), 0);
        assert_eq!(dotty_laptop.topic().secrets().len(), 2);
        assert_eq!(jerry_laptop.topic().secrets().len(), 0);
        assert_eq!(frankie_phone.topic().secrets().len(), 0);

        assert_eq!(topicdata!(butch_laptop).unwrap(), vec![AppData::new("hi i'm butch")]);
        assert_eq!(topicdata!(butch_phone).unwrap(), vec![]);
        assert_eq!(topicdata!(dotty_laptop).unwrap(), vec![AppData::new("hi i'm butch"), AppData::new("dotty is best")]);
        assert_eq!(topicdata!(jerry_laptop).unwrap(), vec![]);
        assert_eq!(topicdata!(frankie_phone).unwrap(), vec![]);

        let data3 = dotty_laptop.tx_data(ts("2024-12-08T01:00:00Z"), AppData::new("it is plain to see"), None, None);
        dotty_laptop
            .push_tx(&id_lookup(&[&butch_laptop, &dotty_laptop]), &[&data3])
            .unwrap();

        assert_eq!(topicdata!(butch_laptop).unwrap(), vec![AppData::new("hi i'm butch")]);
        assert_eq!(topicdata!(butch_phone).unwrap(), vec![]);
        assert_eq!(
            topicdata!(dotty_laptop).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see")
            ]
        );
        assert_eq!(topicdata!(jerry_laptop).unwrap(), vec![]);
        assert_eq!(topicdata!(frankie_phone).unwrap(), vec![]);

        // test out of roerd packets
        {
            let butch_laptop = butch_laptop.clone();
            let res = butch_laptop.push_tx(&id_lookup(&[&butch_laptop, &dotty_laptop]), &[&data3]);
            // should give us a list of transactions we need to complete the chain
            match res {
                Err(Error::TopicMissingTransactions(txids)) => {
                    assert_eq!(txids, vec![data2.id().clone()]);
                }
                _ => panic!("unexpected: {:?}", res),
            }
        }

        butch_laptop
            .push_tx(&id_lookup(&[&butch_laptop, &dotty_laptop]), &[&data3, &data2])
            .unwrap();
        assert_eq!(
            topicdata!(butch_laptop).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see")
            ]
        );
        assert_eq!(topicdata!(butch_phone).unwrap(), vec![]);
        assert_eq!(
            topicdata!(dotty_laptop).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see")
            ]
        );
        assert_eq!(topicdata!(jerry_laptop).unwrap(), vec![]);
        assert_eq!(topicdata!(frankie_phone).unwrap(), vec![]);

        // now add butch's phone, jerry, and frankie to the topic
        let rekey2 = {
            let packet = butch_laptop
                .topic()
                .rekey(
                    &mut rng,
                    vec![
                        (
                            butch_laptop.as_member(admin_perms(), vec![butch_laptop.device().clone(), butch_phone.device().clone()]),
                            &device_lookup(&[&butch_laptop.key_packets()[0], &butch_phone.key_packets()[0]]),
                        ),
                        rkmember!(&dotty_laptop, admin_perms(), 0),
                        rkmember!(&jerry_laptop, vec![Permission::DataSet, Permission::DataUnset], 0),
                        rkmember!(&frankie_phone, vec![Permission::DataSet, Permission::DataUnset], 0),
                    ],
                )
                .unwrap();
            butch_laptop.tx(ts("2024-12-09T00:00:00Z"), None, packet)
        };

        {
            let all_ids_lookup = id_lookup(&[&butch_laptop, &butch_phone, &dotty_laptop, &jerry_laptop, &frankie_phone]);
            butch_laptop.push_tx(&all_ids_lookup, &[&rekey2]).unwrap();
            dotty_laptop.push_tx(&all_ids_lookup, &[&rekey2]).unwrap();
            assert_eq!(butch_laptop.topic().secrets().len(), 3);
            assert_eq!(butch_phone.topic().secrets().len(), 0);
            assert_eq!(dotty_laptop.topic().secrets().len(), 3);
            assert_eq!(jerry_laptop.topic().secrets().len(), 0);
            assert_eq!(frankie_phone.topic().secrets().len(), 0);
            butch_phone
                .push_tx(&all_ids_lookup, &[&genesis, &rekey1, &rekey2, &data1, &data2, &data3])
                .unwrap();
            assert_eq!(butch_laptop.topic().secrets().len(), 3);
            assert_eq!(butch_phone.topic().secrets().len(), 3);
            assert_eq!(dotty_laptop.topic().secrets().len(), 3);
            assert_eq!(jerry_laptop.topic().secrets().len(), 0);
            assert_eq!(frankie_phone.topic().secrets().len(), 0);

            assert_eq!(
                topicdata!(butch_laptop).unwrap(),
                vec![
                    AppData::new("hi i'm butch"),
                    AppData::new("dotty is best"),
                    AppData::new("it is plain to see")
                ]
            );
            assert_eq!(
                topicdata!(butch_phone).unwrap(),
                vec![
                    AppData::new("hi i'm butch"),
                    AppData::new("dotty is best"),
                    AppData::new("it is plain to see")
                ]
            );
            assert_eq!(
                topicdata!(dotty_laptop).unwrap(),
                vec![
                    AppData::new("hi i'm butch"),
                    AppData::new("dotty is best"),
                    AppData::new("it is plain to see")
                ]
            );
            assert_eq!(topicdata!(jerry_laptop).unwrap(), vec![]);
            assert_eq!(topicdata!(frankie_phone).unwrap(), vec![]);

            // now catch up everyone in the gang
            jerry_laptop
                .push_tx(&all_ids_lookup, &[&genesis, &rekey1, &rekey2, &data1, &data2, &data3])
                .unwrap();
            frankie_phone
                .push_tx(&all_ids_lookup, &[&genesis, &rekey1, &rekey2, &data1, &data2, &data3])
                .unwrap();
        }

        assert_eq!(butch_laptop.topic().secrets().len(), 3);
        assert_eq!(butch_phone.topic().secrets().len(), 3);
        assert_eq!(dotty_laptop.topic().secrets().len(), 3);
        assert_eq!(jerry_laptop.topic().secrets().len(), 3);
        assert_eq!(frankie_phone.topic().secrets().len(), 3);

        assert_eq!(
            topicdata!(butch_laptop).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see")
            ]
        );
        assert_eq!(
            topicdata!(butch_phone).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see")
            ]
        );
        assert_eq!(
            topicdata!(dotty_laptop).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see")
            ]
        );
        assert_eq!(
            topicdata!(jerry_laptop).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see")
            ]
        );
        assert_eq!(
            topicdata!(frankie_phone).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see")
            ]
        );

        // we're going to test some branching madness now. jerry and frankie have access to write
        // data, so they're going to do just that. in the meantime, dotty is going to issue a
        // transaction *timestamped before their data edits* that restricts them from writing data.
        // this transaction will not be merged by the others until they've all seen the new data.
        // the goal of this is to test if the jerry/frankie data transactions remain valid even
        // after becoming aware of dotty's skylarkings.
        let perms1 = dotty_laptop.tx(
            ts("2024-12-09T18:00:00Z"),
            None,
            Packet::MemberPermissionsChange {
                identity_id: jerry_laptop.identity().identity_id().unwrap(),
                permissions: vec![],
            },
        );
        dotty_laptop.push_tx(&id_lookup(&[&dotty_laptop]), &[&perms1]).unwrap();
        let perms2 = dotty_laptop.tx(
            ts("2024-12-09T18:00:01Z"),
            None,
            Packet::MemberPermissionsChange {
                identity_id: frankie_phone.identity().identity_id().unwrap(),
                permissions: vec![],
            },
        );
        dotty_laptop.push_tx(&id_lookup(&[&dotty_laptop]), &[&perms2]).unwrap();

        let data4 = jerry_laptop.tx_data(ts("2024-12-10T00:00:00Z"), AppData::new("jerry reporting in"), None, None);
        {
            let all_ids_lookup = id_lookup(&[&butch_laptop, &butch_phone, &dotty_laptop, &jerry_laptop, &frankie_phone]);
            assert_eq!(butch_laptop.push_tx(&all_ids_lookup, &[&data4]).unwrap(), TopicDagState::DagUpdated);
            assert_eq!(butch_phone.push_tx(&all_ids_lookup, &[&data4]).unwrap(), TopicDagState::DagUpdated);
            assert_eq!(jerry_laptop.push_tx(&all_ids_lookup, &[&data4]).unwrap(), TopicDagState::DagUpdated);
            assert_eq!(frankie_phone.push_tx(&all_ids_lookup, &[&data4]).unwrap(), TopicDagState::DagUpdated);
        }
        let data5 = jerry_laptop.tx_data(ts("2024-12-10T00:01:00Z"), AppData::new("just saw a cat"), None, None);
        {
            let all_ids_lookup = id_lookup(&[&butch_laptop, &butch_phone, &dotty_laptop, &jerry_laptop, &frankie_phone]);
            assert_eq!(butch_laptop.push_tx(&all_ids_lookup, &[&data5]).unwrap(), TopicDagState::DagUpdated);
            assert_eq!(butch_phone.push_tx(&all_ids_lookup, &[&data5]).unwrap(), TopicDagState::DagUpdated);
            assert_eq!(jerry_laptop.push_tx(&all_ids_lookup, &[&data5]).unwrap(), TopicDagState::DagUpdated);
            assert_eq!(frankie_phone.push_tx(&all_ids_lookup, &[&data5]).unwrap(), TopicDagState::DagUpdated);
        }
        let data6 = frankie_phone.tx_data(ts("2024-12-10T00:02:00Z"), AppData::new("i hate cats"), None, None);
        {
            let all_ids_lookup = id_lookup(&[&butch_laptop, &butch_phone, &dotty_laptop, &jerry_laptop, &frankie_phone]);
            assert_eq!(butch_laptop.push_tx(&all_ids_lookup, &[&data6]).unwrap(), TopicDagState::DagUpdated);
            assert_eq!(butch_phone.push_tx(&all_ids_lookup, &[&data6]).unwrap(), TopicDagState::DagUpdated);
            assert_eq!(jerry_laptop.push_tx(&all_ids_lookup, &[&data6]).unwrap(), TopicDagState::DagUpdated);
            assert_eq!(frankie_phone.push_tx(&all_ids_lookup, &[&data6]).unwrap(), TopicDagState::DagUpdated);
        }

        assert_eq!(
            topicdata!(butch_laptop).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see"),
                AppData::new("jerry reporting in"),
                AppData::new("just saw a cat"),
                AppData::new("i hate cats"),
            ]
        );
        assert_eq!(
            topicdata!(butch_phone).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see"),
                AppData::new("jerry reporting in"),
                AppData::new("just saw a cat"),
                AppData::new("i hate cats"),
            ]
        );
        assert_eq!(
            topicdata!(dotty_laptop).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see")
            ]
        );
        assert_eq!(
            topicdata!(jerry_laptop).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see"),
                AppData::new("jerry reporting in"),
                AppData::new("just saw a cat"),
                AppData::new("i hate cats"),
            ]
        );
        assert_eq!(
            topicdata!(frankie_phone).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("dotty is best"),
                AppData::new("it is plain to see"),
                AppData::new("jerry reporting in"),
                AppData::new("just saw a cat"),
                AppData::new("i hate cats"),
            ]
        );

        // now we combine our hot branches with a cool island merge
        {
            let all_ids_lookup = id_lookup(&[&butch_laptop, &butch_phone, &dotty_laptop, &jerry_laptop, &frankie_phone]);
            assert_eq!(butch_laptop.push_tx(&all_ids_lookup, &[&perms1, &perms2]).unwrap(), TopicDagState::DagRebuilt);
            assert_eq!(butch_phone.push_tx(&all_ids_lookup, &[&perms1, &perms2]).unwrap(), TopicDagState::DagRebuilt);
            assert_eq!(dotty_laptop.push_tx(&all_ids_lookup, &[&data4, &data5, &data6]).unwrap(), TopicDagState::DagRebuilt);
            assert_eq!(jerry_laptop.push_tx(&all_ids_lookup, &[&perms1, &perms2]).unwrap(), TopicDagState::DagRebuilt);
            assert_eq!(frankie_phone.push_tx(&all_ids_lookup, &[&perms1, &perms2]).unwrap(), TopicDagState::DagRebuilt);
        }
    }

    #[test]
    fn topic_dag_rebuild_with_snapshot() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"dupe dupe").unwrap().as_bytes().try_into().unwrap());
        let mut dotty = Peer::new_identity(&mut rng, "dupedupe123", "dogphone");
        let mut butch = Peer::new_identity(&mut rng, "butch6969", "laptop");
        let genesis = {
            let packet = dotty.topic().rekey(&mut rng, vec![rkmember!(&dotty, admin_perms(), 0)]).unwrap();
            dotty.tx(ts("2024-12-08T01:00:00Z"), None, packet)
        };
        dotty.push_tx(&id_lookup(&[&dotty]), &[&genesis]).unwrap();

        let rekey1 = {
            let packet = dotty
                .topic()
                .rekey(&mut rng, vec![rkmember!(&dotty, admin_perms(), 0), rkmember!(&butch, admin_perms(), 0)])
                .unwrap();
            dotty.tx(ts("2024-12-09T01:00:00Z"), None, packet)
        };

        dotty.push_tx(&id_lookup(&[&dotty, &butch]), &[&rekey1]).unwrap();
        butch.push_tx(&id_lookup(&[&dotty, &butch]), &[&rekey1, &genesis]).unwrap();

        let data1 = butch.tx_data(ts("2024-12-10T01:00:00Z"), AppData::new("hi i'm butch"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data1]).unwrap();
        dotty.push_tx(&id_lookup(&[&butch]), &[&data1]).unwrap();
        let data2 = dotty.tx_data(ts("2024-12-10T02:00:00Z"), AppData::new("haiii!"), None, None);
        dotty.push_tx(&id_lookup(&[&dotty]), &[&data2]).unwrap();
        butch.push_tx(&id_lookup(&[&dotty]), &[&data2]).unwrap();

        let rm1 = dotty.tx(
            ts("2024-12-10T02:30:00Z"),
            None,
            Packet::DataUnset {
                transaction_ids: vec![data2.id().clone()],
            },
        );
        dotty.push_tx(&id_lookup(&[&dotty]), &[&rm1]).unwrap();
        butch.push_tx(&id_lookup(&[&dotty]), &[&rm1]).unwrap();

        let data3 = dotty.tx_data(ts("2024-12-10T03:00:00Z"), AppData::new("nice knowing you"), None, None);
        let data4 = butch.tx_data(ts("2024-12-10T03:00:00Z"), AppData::new("oh, what's this????"), None, None);
        butch.push_tx(&id_lookup(&[&butch, &dotty]), &[&data3, &data4]).unwrap();
        dotty.push_tx(&id_lookup(&[&butch, &dotty]), &[&data3, &data4]).unwrap();

        let data5 = butch.tx_data(ts("2024-12-10T03:00:00Z"), AppData::new("i'm not to be disturbed."), None, None);
        butch.push_tx(&id_lookup(&[&butch, &dotty]), &[&data5]).unwrap();
        dotty.push_tx(&id_lookup(&[&butch, &dotty]), &[&data5]).unwrap();

        // make sure we got a merge. not technically required for this test but i want to cover the
        // bases anyway
        assert_eq!(TopicTransaction::new(data5.clone()).previous_transactions().unwrap().len(), 2);
        assert_eq!(dotty.topic().transactions().len(), 8);
        assert_eq!(dotty.topic().find_leaves(), vec![data5.id()]);

        // ok now we create a dumb snapshot
        dotty.snapshot(data3.id()).unwrap();

        assert_eq!(
            topicdata!(dotty).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("oh, what's this????"),
                AppData::new("nice knowing you"),
                AppData::new("i'm not to be disturbed."),
            ]
        );

        // make sure our leaves are still legit
        assert_eq!(dotty.topic().find_leaves(), vec![data5.id()]);

        // snapshot should kick out our remover and removee transactions
        assert_eq!(dotty.topic().transactions().len(), 6);

        let data6 = dotty.tx_data(ts("2024-12-11T00:00:00Z"), AppData::new("wise and shine"), None, None);

        // data6's prev should ONLY be data5
        assert_eq!(TopicTransaction::new(data6.clone()).previous_transactions().unwrap(), vec![data5.id()]);

        dotty.push_tx(&id_lookup(&[&dotty]), &[&data6]).unwrap();

        assert_eq!(
            topicdata!(dotty).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("oh, what's this????"),
                AppData::new("nice knowing you"),
                AppData::new("i'm not to be disturbed."),
                AppData::new("wise and shine"),
            ]
        );

        // wow the DAG is getting very bloated again, let's snapshot
        dotty.snapshot(data6.id()).unwrap();
        assert_eq!(dotty.topic().transactions().len(), 7);

        assert_eq!(
            dotty
                .topic()
                .transactions()
                .iter()
                .find(|t| t.id() == data6.id())
                .unwrap()
                .snapshot()
                .as_ref()
                .unwrap()
                .all_transactions(),
            vec![&genesis, &rekey1, &data1, &data2, &rm1, &data4, &data3, &data5, &data6,]
                .into_iter()
                .map(|t| t.id())
                .collect::<Vec<_>>()
        );

        // and push another tx
        let data7 = dotty.tx_data(ts("2024-12-12T00:00:00Z"), AppData::new("this way, please"), None, None);
        dotty.push_tx(&id_lookup(&[&dotty]), &[&data7]).unwrap();

        assert_eq!(
            topicdata!(dotty).unwrap(),
            vec![
                AppData::new("hi i'm butch"),
                AppData::new("oh, what's this????"),
                AppData::new("nice knowing you"),
                AppData::new("i'm not to be disturbed."),
                AppData::new("wise and shine"),
                AppData::new("this way, please"),
            ]
        );
    }

    #[test]
    fn topic_branch_with_snapshot() {
        todo!("Test what happens when multiple transaction branches are snapshotted and merged");
    }

    #[test]
    fn topic_empty_dag() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"get a job").unwrap().as_bytes().try_into().unwrap());
        let (master_key, transactions, admin_key) = create_fake_identity(&mut rng, ts("2024-01-01T00:00:06Z"));
        let node_a_sync_crypto = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();

        let topic_id = TopicID::new(&mut rng);
        let topic_secret = TopicSecret::new(&mut rng);
        let topic_seckey = topic_secret.derive_secret_key().unwrap();

        let mut pkt = PacketGen::new(&mut rng, &transactions, &topic_id, &topic_seckey);

        let member = Member::new(
            transactions.identity_id().unwrap(),
            vec![
                Permission::DataSet,
                Permission::DataUnset,
                Permission::MemberDevicesUpdate,
                Permission::MemberPermissionsChange,
                Permission::TopicRekey,
            ],
            vec![Device::new(&mut rng, "laptop".into())],
        );

        let node_a_member = MemberRekey::seal(
            &mut rng,
            member.clone(),
            &BTreeMap::from([(member.devices[0].id(), &node_a_sync_crypto.clone().into())]),
            vec![SecretEntry::new_current_transaction(topic_secret.clone())],
        )
        .unwrap();

        let (topic_tx, _name_to_tx, id_to_name) = tx_chain! {
            [
                A = ("2024-01-03T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::TopicRekey { members: vec![node_a_member.clone()] }));
                B = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"get a"));
                C = ("2024-01-03T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"job"));
                D = ("2024-01-04T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::DataUnset { transaction_ids: vec![C.id().clone()] }));
                E = ("2024-01-08T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"lol"));
                F = ("2024-01-05T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"gfffft"));
                G = ("2024-01-09T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::DataUnset { transaction_ids: vec![E.id().clone()] }));
            ],
            [
                [A] <- [B, C, D, E, F, G],
            ],
        };
        let topic = create_1p_topic(
            &topic_id,
            &master_key,
            &admin_key,
            &transactions,
            &node_a_sync_crypto,
            member.devices()[0].id(),
            topic_tx.clone(),
        );

        {
            let ordered = topic
                .get_transactions_ordered()
                .unwrap()
                .into_iter()
                .map(|x| id_to_name.get(x.id()).unwrap())
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(ordered, vec!["A", "B", "C", "D", "F", "E", "G"]);
        }
    }

    #[test]
    fn topic_snapshot_and_order() {
        let mut rng = rng::chacha20_seeded(
            Hash::new_blake3(b"i am sleeping under the stars with my dog. he is happy. so am i.")
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap(),
        );
        let (master_key, transactions, admin_key) = create_fake_identity(&mut rng, ts("2024-01-01T00:00:06Z"));
        let node_a_sync_sig = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let node_a_sync_crypto = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();

        let topic_id = TopicID::new(&mut rng);
        let topic_secret = TopicSecret::new(&mut rng);
        let topic_seckey = topic_secret.derive_secret_key().unwrap();

        let mut pkt = PacketGen::new(&mut rng, &transactions, &topic_id, &topic_seckey);

        let member = Member::new(
            transactions.identity_id().unwrap(),
            vec![
                Permission::DataSet,
                Permission::DataUnset,
                Permission::MemberDevicesUpdate,
                Permission::MemberPermissionsChange,
                Permission::TopicRekey,
            ],
            vec![Device::new(&mut rng, "laptop".into())],
        );

        let node_a_member = MemberRekey::seal(
            &mut rng,
            member.clone(),
            &BTreeMap::from([(member.devices[0].id(), &node_a_sync_crypto.clone().into())]),
            vec![SecretEntry::new_current_transaction(topic_secret.clone())],
        )
        .unwrap();

        let (topic_tx, name_to_tx, id_to_name) = tx_chain! {
            [
                A = ("2024-01-03T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::TopicRekey { members: vec![node_a_member.clone()] }));
                B = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"00"));
                C = ("2024-01-03T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"01"));
                D = ("2024-01-04T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"02"));
                E = ("2024-01-08T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"03"));
                F = ("2024-01-05T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::DataUnset { transaction_ids: vec![B.id().clone()] }));
                G = ("2024-01-09T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"05"));
                H = ("2024-01-09T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"06"));
                I = ("2024-01-09T00:01:02Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"07"));
                J = ("2024-01-09T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"08"));
                K = ("2024-01-09T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"09"));
                L = ("2024-01-09T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::DataUnset { transaction_ids: vec![J.id().clone()] }));
                M = ("2024-01-09T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"10"));
            ],
            [
                // branch1
                [A] <- [B],
                [B] <- [C],
                [C] <- [D, E],
                [E] <- [F],

                // branch2
                [A] <- [G],
                [G] <- [H, I],
                [H, I] <- [J],
                [J] <- [K],

                // merge the branches. let's get weird
                [K, F] <- [L],
                [L, D] <- [M],
            ],
        };
        macro_rules! assert_op {
            ($topic_tx:expr, $id_to_name:expr, $idx:expr, $name:expr, $is_snapshot:expr) => {
                assert_eq!($id_to_name.get($topic_tx.transactions()[$idx].id()), Some(&$name));
                assert_eq!($topic_tx.transactions()[$idx].snapshot().is_some(), $is_snapshot);
            };
        }
        macro_rules! mktopic {
            ($topic_tx:expr) => {{
                create_1p_topic(
                    &topic_id,
                    &master_key,
                    &admin_key,
                    &transactions,
                    &node_a_sync_crypto,
                    member.devices()[0].id(),
                    $topic_tx,
                )
            }};
        }

        {
            let topic = mktopic!(topic_tx.clone());
            assert_eq!(
                topic
                    .get_transactions_ordered()
                    .unwrap()
                    .iter()
                    .map(|x| id_to_name.get(x.id()).unwrap())
                    .cloned()
                    .collect::<Vec<_>>(),
                vec!["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"],
            );
        }

        // this test is interesting because E snapshots A, B, & C, but D is E's peer and D
        // references C *but is timestamped before E*. so in the old way of doing things, this
        // means that D would come AFTER E because D's prev references that point to any node
        // snapshotted by E would be overridden to point to E. this means that D would come before
        // E pre-snapshot but post-snapshot E comes before D (using this previous link overriding
        // technique). this changes the order of snapshotted nodes, which ultimately should be
        // preserved (a bug). so we test to make sure that this doesn't happen, because the better
        // way of doing things is to preserve the links/timestamps for all nodes and let the dag do
        // the ordering as if those nodes weren't snapshotted at all.
        {
            let mut topic = mktopic!(topic_tx.clone());
            let e_id = name_to_tx.get("E").unwrap().id();
            topic.snapshot(&master_key, &node_a_sync_sig, e_id).unwrap();
            assert_eq!(
                topic
                    .transactions()
                    .iter()
                    .map(|x| id_to_name.get(x.id()).unwrap())
                    .cloned()
                    .collect::<Vec<_>>(),
                vec!["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"],
            );
            assert_op!(topic, id_to_name, 0, "A", false);
            assert_op!(topic, id_to_name, 1, "B", false);
            assert_op!(topic, id_to_name, 2, "C", false);
            assert_op!(topic, id_to_name, 3, "D", false);
            assert_op!(topic, id_to_name, 4, "E", true);
            assert_eq!(
                ids_to_names(&id_to_name, &topic.transactions()[4].snapshot().as_ref().unwrap().active_transactions()),
                vec!["A", "B", "C", "E"],
            );
            assert_op!(topic, id_to_name, 5, "F", false);
            assert_op!(topic, id_to_name, 6, "G", false);
            assert_op!(topic, id_to_name, 7, "H", false);
            assert_op!(topic, id_to_name, 8, "I", false);
            assert_op!(topic, id_to_name, 9, "J", false);
            assert_op!(topic, id_to_name, 10, "K", false);
            assert_op!(topic, id_to_name, 11, "L", false);
            assert_op!(topic, id_to_name, 12, "M", false);
            assert_eq!(topic.transactions().get(13), None);
            {
                let ordered = topic
                    .get_transactions_ordered()
                    .unwrap()
                    .into_iter()
                    .map(|x| id_to_name.get(x.id()).unwrap())
                    .cloned()
                    .collect::<Vec<_>>();
                // NOTE: this is messed up now because E houses B, A, & C and injects them into
                // E's position instead of naturally sorting them into the DAG as they were previously.
                // this is because the snapshots only operate on the branch level
                assert_eq!(ordered, vec!["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"]);
            }
        }
        {
            let mut topic = mktopic!(topic_tx.clone());
            let h_id = name_to_tx.get("J").unwrap().id();
            topic.snapshot(&master_key, &node_a_sync_sig, h_id).unwrap();
            assert_op!(topic, id_to_name, 0, "A", false);
            assert_op!(topic, id_to_name, 1, "B", false);
            assert_op!(topic, id_to_name, 2, "C", false);
            assert_op!(topic, id_to_name, 3, "D", false);
            assert_op!(topic, id_to_name, 4, "E", false);
            assert_op!(topic, id_to_name, 5, "F", false);
            assert_op!(topic, id_to_name, 6, "G", false);
            assert_op!(topic, id_to_name, 7, "H", false);
            assert_op!(topic, id_to_name, 8, "I", false);
            assert_op!(topic, id_to_name, 9, "J", true);
            assert_eq!(
                ids_to_names(&id_to_name, &topic.transactions()[9].snapshot().as_ref().unwrap().active_transactions()),
                vec!["A", "G", "H", "I", "J"],
            );
            assert_op!(topic, id_to_name, 10, "K", false);
            assert_op!(topic, id_to_name, 11, "L", false);
            assert_op!(topic, id_to_name, 12, "M", false);
            assert_eq!(topic.transactions().get(13), None);
            {
                let ordered = topic
                    .get_transactions_ordered()
                    .unwrap()
                    .into_iter()
                    .map(|x| id_to_name.get(x.id()).unwrap())
                    .cloned()
                    .collect::<Vec<_>>();
                assert_eq!(ordered, vec!["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"]);
            }
        }
    }
}

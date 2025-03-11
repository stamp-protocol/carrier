#![doc = include_str!("../README.md")]

pub mod error;

use crate::error::{Error, Result};
use rasn::{AsnType, Decode, Encode};
use stamp_core::{
    ahash::{AHashMap, AHashSet},
    crypto::base::{
        rng::{CryptoRng, RngCore},
        CryptoKeypair, CryptoKeypairPublic, Hash, HashAlgo, Sealed, SecretKey, SignKeypair, SignKeypairPublic, SignKeypairSignature,
    },
    dag::{Dag, DagNode, Transaction, TransactionBody, TransactionID, Transactions},
    identity::IdentityID,
    util::{Binary, BinarySecret, BinaryVec, HashMapAsn1, SerdeBinary, Timestamp},
};
use std::collections::{BTreeMap, BTreeSet};
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

impl SerdeBinary for Device {}

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
        Self(BinarySecret::new(*self.0.expose_secret()))
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

impl SerdeBinary for KeyPacket {}

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
        /// The ids of the packets we're unsetting
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
    /// Determine if this is a data packet.
    pub fn is_data_packet(&self) -> bool {
        matches!(self, Packet::DataSet { .. })
    }

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

    /// Checks if this has been `Unset`
    pub fn is_remove(&self) -> bool {
        matches!(self, &Self::Remove { .. })
    }
}

/// Holds the actual snapshot data, as well as the [`TransactionID`] of the operation we're replacing
/// with this snapshot.
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct SnapshotEntry {
    /// The operations we're rolling into this snapshot **in causal order**. This is effectively
    /// all operations that have occurred before the operation being snapshotted *on the same DAG

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
        sign_pubkey.verify(self.signature(), &id_ser)?;
        let ops = self.all_transactions();
        let last = ops[ops.len() - 1].clone();
        Ok(last)
    }

    /// An ordered list of all the active nodes this snapshot holds (set operations)
    pub fn active_transactions(&self) -> Vec<&TransactionID> {
        self.entry()
            .ordered_transactions()
            .iter()
            .filter(|x| x.is_keep())
            .map(|x| x.transaction_id())
            .collect::<Vec<_>>()
    }

    /// An ordered list of all the active nodes this snapshot holds (set operations)
    pub fn removed_transactions(&self) -> Vec<&TransactionID> {
        self.entry()
            .ordered_transactions()
            .iter()
            .filter(|x| x.is_remove())
            .map(|x| x.transaction_id())
            .collect::<Vec<_>>()
    }

    /// An ordered list of all the nodes referenced in this snapshot (active and removed)
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
        if self.is_empty() {
            Err(Error::TransactionIsEmpty(self.id().clone()))?;
        }
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
    pub fn is_data_packet(&self) -> Result<bool> {
        Ok(self.get_packet()?.is_data_packet())
    }

    /// Returns whether or not this transaction houses a control packet.
    pub fn is_control_packet(&self) -> Result<bool> {
        Ok(self.get_packet()?.is_control_packet())
    }

    /// Returns if this is an unset packet or not.
    pub fn is_unset(&self) -> Result<bool> {
        if self.is_empty() {
            Err(Error::TransactionIsEmpty(self.id().clone()))?;
        }
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
        if self.is_empty() {
            Err(Error::TransactionIsEmpty(self.id().clone()))?;
        }
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

    /// Get the raw (serialized) payload for this transaction if it exists.
    pub fn get_payload(&self) -> Option<&BinaryVec> {
        match self.transaction().entry().body() {
            TransactionBody::ExtV1 { payload, .. } => Some(payload),
            _ => None,
        }
    }

    /// Determines if this is a blank (fake) transaction re-created by a snapshot to preserve
    /// causal structure of a DAG. Transactions like this will look normal to the untrained eye,
    /// but have no actual data to speak of and can make things go haywire if we try to deserialize
    /// them.
    pub fn is_empty(&self) -> bool {
        match self.transaction().entry().body() {
            TransactionBody::ExtV1 { payload, .. } => payload.len() == 0,
            // we're going to lump anything non-ExtV1 into the "is blank" bucket. sue me.
            _ => true,
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

impl SerdeBinary for TopicTransaction {}

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

impl std::fmt::Display for TopicID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", stamp_core::util::base64_encode(self.0.deref()))
    }
}

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
#[derive(Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct TopicState {
    /// A collection of secret seeds, in order of the DAG control packets, that allow deriving the
    /// topic's current (or past) secret key(s).
    #[rasn(tag(explicit(0)))]
    secrets: Vec<SecretEntry>,
    /// Tracks who is a member of this topic and what their permissions are.
    #[rasn(tag(explicit(1)))]
    members: HashMapAsn1<IdentityID, Member>,
}

impl TopicState {
    /// Create anew
    fn new() -> Self {
        Self {
            secrets: Default::default(),
            members: BTreeMap::new().into(),
        }
    }

    /// Check if the permissions on a transaction are valid.
    pub fn check_permissions(
        members: &HashMapAsn1<IdentityID, Member>,
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
        let is_initial_packet = transaction.previous_transactions()?.is_empty();

        let packet = transaction.get_packet()?;
        let identity_id = transaction.identity_id()?;
        match packet {
            Packet::DataSet { .. } => {
                Self::check_permissions(self.members(), Permission::DataSet, identity_id, transaction.id())?;
            }
            Packet::DataUnset { .. } => {
                Self::check_permissions(self.members(), Permission::DataUnset, identity_id, transaction.id())?;
            }
            Packet::MemberDevicesUpdate { .. } => {
                Self::check_permissions(self.members(), Permission::MemberDevicesUpdate, identity_id, transaction.id())?;
            }
            Packet::MemberPermissionsChange { .. } => {
                Self::check_permissions(self.members(), Permission::MemberPermissionsChange, identity_id, transaction.id())?;
            }
            Packet::TopicRekey { .. } => {
                if !is_initial_packet {
                    Self::check_permissions(self.members(), Permission::TopicRekey, identity_id, transaction.id())?;
                }
            }
        }
        Ok(())
    }

    /// Apply a previously-validated transaction to this state.
    #[tracing::instrument(level = "trace", skip_all, fields(txid = %&format!("{}", transaction.id())[0..8]))]
    fn apply_transaction(
        &mut self,
        transaction: &TopicTransaction,
        dag: &Dag<TransactionID, TopicTransaction>,
        our_master_key: &SecretKey,
        our_crypto_keypairs: &[&CryptoKeypair],
        our_identity_id: &IdentityID,
        our_device_id: &DeviceID,
    ) -> Result<()> {
        let packet = transaction.get_packet()?;
        let identity_id = transaction.identity_id()?;
        match packet {
            Packet::DataSet { .. } => {}
            Packet::DataUnset { transaction_ids, .. } => {
                let causal_chain = dag.get_causal_chain(transaction.id());
                for unset_id in transaction_ids {
                    let unset = dag
                        .index()
                        .get(&unset_id)
                        .ok_or_else(|| Error::TopicMissingTransactions(vec![unset_id.clone()]))?;
                    // don't allow Unset on non-data packets
                    if !unset.node().is_empty() && !unset.node().is_data_packet()? {
                        Err(Error::TransactionUnsetNonDataPacket(transaction.id().clone()))?;
                    }
                    // don't allow rm on a tx not in the current causal chain
                    if !causal_chain.contains(&unset_id) {
                        Err(Error::TransactionUnsetNotCausal(transaction.id().clone(), unset_id.clone()))?;
                    }
                }
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

impl SerdeBinary for TopicState {}

/// Determines how the DAG of a [`Topic`] was modified while pushing transactions.
///
/// You can probably generally ignore this unless you're hitting performance issues, in which case
/// you'll want to investigate why your DAG is branching so much.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TopicDagModificationResult {
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
    keychain: AHashMap<TransactionID, SecretKey>,
    /// The actual transactions (control or data) in this topic.
    transactions: Vec<TopicTransaction>,
    /// Tracks the state for the various branches in the topic DAG we can have, allowing
    /// transactions to have branch-local validation as opposed to requiring consistent state. This
    /// mapping exists largely as a cache so we don't have to re-run all the transactions from
    /// start to finish each time we need to add a new transaction to the topic.
    branch_state: AHashMap<TransactionID, TopicState>,
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
            keychain: AHashMap::new(),
            transactions: Vec::new(),
            branch_state: AHashMap::new(),
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
        identities: &AHashMap<IdentityID, &Transactions>,
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
    #[tracing::instrument(err, skip_all, fields(topic_id = %&format!("{}", self.id())[0..8], members = %members.iter().map(|(m, _)| String::from(&format!("{}", m.identity_id())[0..8])).collect::<Vec<_>>().join(",")))]
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
    #[tracing::instrument(err(Debug), skip_all, fields(topic_id = %&format!("{}", self.id())[0..8], num_transactions = %transactions.len()))]
    pub fn push_transactions(
        mut self,
        transactions: Vec<TopicTransaction>,
        identities: &AHashMap<IdentityID, &Transactions>,
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
    #[tracing::instrument(err(Debug), skip_all, fields(topic_id = %&format!("{}", self.id())[0..8], num_transactions = %transactions.len()))]
    pub fn push_transactions_mut(
        &mut self,
        transactions: Vec<TopicTransaction>,
        identities: &AHashMap<IdentityID, &Transactions>,
        our_master_key: &SecretKey,
        our_crypto_keypairs: &[&CryptoKeypair],
        our_identity_id: &IdentityID,
        our_device_id: &DeviceID,
    ) -> Result<TopicDagModificationResult> {
        // index transactions we've already processed here
        let mut exists_idx: AHashSet<&TransactionID> = AHashSet::with_capacity(self.transactions().len());
        let nodes_old = self
            .transactions()
            .iter()
            .map(|x| {
                exists_idx.insert(x.id());
                // also push known snapshotted transactions into our existing list
                if let Some(snap) = x.snapshot().as_ref() {
                    for op in snap.entry().ordered_transactions() {
                        exists_idx.insert(op.transaction_id());
                    }
                }
                x.into()
            })
            .collect::<Vec<DagNode<_, _>>>();
        let transactions_new_filtered_deduped = transactions
            .into_iter()
            .filter(|t| !exists_idx.contains(t.id()))
            .map(|t| (t.id().clone(), t))
            // dedupe/sort
            .collect::<BTreeMap<TransactionID, TopicTransaction>>()
            .into_values()
            .collect::<Vec<_>>();
        let mut contains_key_changes = false;
        for trans in &transactions_new_filtered_deduped {
            // verify our transactions against their respective identities
            let trans_identity_id = trans.identity_id()?;
            let prev = trans.transaction().entry().previous_transactions();
            let identity_tx = identities
                .get(trans_identity_id)
                .ok_or_else(|| Error::IdentityMissing(trans_identity_id.clone()))?;
            let identity = identity_tx.build_identity_at_point_in_history(prev)?;
            trans.transaction().verify(Some(&identity))?;
            // also, look for any key changes
            if let Packet::TopicRekey { .. } = trans.get_packet()? {
                contains_key_changes = true;
            }
        }

        // if our new transactions *only* reference either tail nodes in the existing DAG OR
        // each other, then we can safely update this DAG using the existing state tracking and
        // skip a whole lot of processing. however, if our new nodes reference any non-tail,
        // non-new state, then we need to re-process the entire DAG.
        let new_transactions_only_reference_tail_nodes = {
            // index our DAG's tail transactions AND our new transactions into a set that we'll
            // use to check if we need to re-run the entire DAG.
            let mut tail_or_self_idx = self.last_tail_nodes.iter().collect::<AHashSet<_>>();
            for trans in &transactions_new_filtered_deduped {
                tail_or_self_idx.insert(trans.id());
            }
            // now loop over our new transactions and check the previous_transactions of each,
            // looking for any references to tx outside of our tail/new set. if we find any,
            // we've got to reprocess the DAG =[ =[ =[. sad!
            let mut only_tail_referenced = true;
            for trans in &transactions_new_filtered_deduped {
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
            AHashMap::new()
        };

        let (global_state, last_tail_nodes) = {
            // make sure we expand snapshots for our new transactions here (as well as old) since
            // it's possible for a peer to send a snapshot as part of a tx dump.
            Self::with_expanded_snapshots(
                &[self.transactions(), &transactions_new_filtered_deduped],
                |transactions_modified, _tx_idx, recreated| {
                    let nodes_new = transactions_new_filtered_deduped.iter().map(|x| x.into()).collect::<Vec<_>>();
                    let nodes_modified = transactions_modified.iter().map(|x| x.into()).collect::<Vec<_>>();

                    let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_old, &nodes_new, &nodes_modified]);
                    if !dag.missing().is_empty() {
                        Err(Error::TopicMissingTransactions(dag.missing().iter().cloned().cloned().collect::<Vec<_>>()))?;
                    }

                    let global_state = dag.apply(
                        &mut branch_state,
                        |node| {
                            let mut state = TopicState::new();
                            state.apply_transaction(
                                node.node(),
                                &dag,
                                our_master_key,
                                our_crypto_keypairs,
                                our_identity_id,
                                our_device_id,
                            )?;
                            Ok(state)
                        },
                        |node| new_transactions_only_reference_tail_nodes && exists_idx.contains(node.id()),
                        |state, node| {
                            // skip validation if this is a recreated node
                            if recreated.contains(node.id()) {
                                Ok(())
                            } else {
                                state.validate_transaction(node.node())
                            }
                        },
                        |state, node| {
                            // skip modifying state if this is a recreated node
                            if recreated.contains(node.id()) {
                                Ok(())
                            } else {
                                state.apply_transaction(
                                    node.node(),
                                    &dag,
                                    our_master_key,
                                    our_crypto_keypairs,
                                    our_identity_id,
                                    our_device_id,
                                )
                            }
                        },
                    )?;
                    let tail_nodes = dag.tail().clone().into_iter().cloned().collect();
                    Ok((global_state.clone(), tail_nodes))
                },
            )?
        };
        for trans in transactions_new_filtered_deduped {
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
            TopicDagModificationResult::DagUpdated
        } else {
            TopicDagModificationResult::DagRebuilt
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
            .collect::<Result<AHashMap<_, _>>>()?;
        self.set_keychain(keychain);
        Ok(())
    }

    /// Find operations that are not referenced in any other operation's `previous` list.
    #[tracing::instrument(level = "debug", ret, err(Debug), skip_all, fields(topic_id = %&format!("{}", self.id())[0..8]))]
    fn find_leaves(&self) -> Result<Vec<TransactionID>> {
        Self::with_expanded_snapshots(&[self.transactions()], |transactions_modified, _tx_idx, _recreated| {
            let nodes_orig = self.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
            let nodes_modified = transactions_modified.iter().map(|x| x.into()).collect::<Vec<_>>();

            let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_orig, &nodes_modified]);
            if !dag.missing().is_empty() {
                Err(Error::TopicMissingTransactions(dag.missing().iter().cloned().cloned().collect::<Vec<_>>()))?;
            }
            let mut leaves = dag.tail().iter().cloned().cloned().collect::<Vec<_>>();
            leaves.sort_unstable();
            Ok(leaves)
        })
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
        let prev = match previous_transactions {
            Some(prev) => prev,
            None => self.find_leaves()?.into_iter().collect::<Vec<_>>(),
        };
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
    fn with_expanded_snapshots<'a, F, T>(transactions: &[&'a [TopicTransaction]], mut cb: F) -> Result<T>
    where
        F: FnMut(Vec<TopicTransaction>, AHashMap<&'a TransactionID, &'a TopicTransaction>, AHashSet<TransactionID>) -> Result<T>,
    {
        /// Defines what actions we can do to modify a transaction.
        ///
        /// Note that the order of the variants here is NOT alphabetical because we want `Ord` to
        /// order these exactly as defined here when sorted:
        ///
        ///   1. `Resurrect` should always be first
        ///   2. `ClearPrevious` should be second
        ///   3. `PushPrevious` third
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
        enum Modification {
            /// Re-create a transaction using just its id and timestamp
            Resurrect(Timestamp),
            /// Wipe `previous_transactions`
            ClearPrevious,
            /// Push a txid into a transaction's `previous_transactions` list
            PushPrevious(TransactionID),
        }

        let mut tx_index: AHashMap<&TransactionID, &TopicTransaction> = AHashMap::new();
        let mut snapshot_unsets: AHashMap<TransactionID, Timestamp> = AHashMap::new();
        let mut snapshots: Vec<&Snapshot> = Vec::new();

        let num_tx = transactions.iter().fold(0, |acc, x| acc + x.len());
        if num_tx == 0 {
            return cb(Vec::new(), AHashMap::new(), AHashSet::new());
        }

        for tx_list in transactions {
            for tx in tx_list.iter() {
                tx_index.insert(tx.id(), tx);
                if let Some(snapshot) = tx.snapshot.as_ref() {
                    snapshots.push(snapshot);
                    //{
                    //let entry = snapshots.entry(tx.id()).or_insert_with(|| Vec::new());
                    //entry.push(snapshot);
                    //}
                    for op in snapshot.entry().ordered_transactions() {
                        if let SnapshotOrderedOp::Remove { id, timestamp } = op {
                            snapshot_unsets.insert(id.clone(), timestamp.clone());
                        }
                    }
                }
            }
        }

        // we loop over our snapshots and log a list of modifications we can make to a transaction
        // that we save here.
        let mut modifications: BTreeMap<TransactionID, Vec<Modification>> = BTreeMap::new();

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
        for snapshot in snapshots {
            // stores the transaction id of the previous loop's operation. this allows us to
            // set previous_transactions for each of our snapshotted tx
            let mut last_snap_transaction_id: Option<TransactionID> = None;
            for snap_op in snapshot.entry().ordered_transactions() {
                let mut mods = Vec::new();
                // if this is a removal, we need to mark it for re-creation, otherwise we assume
                // that the tx already exists in the original transactions list and can be
                // referenced directly (since snapshots don't actually store transactions, just
                // ordered transaction ids).
                match &snap_op {
                    SnapshotOrderedOp::Remove { timestamp, .. } => {
                        mods.push(Modification::Resurrect(timestamp.clone()));
                        mods.push(Modification::ClearPrevious);
                        if let Some(prev_tx_id) = last_snap_transaction_id.as_ref() {
                            mods.push(Modification::PushPrevious(prev_tx_id.clone()));
                        }
                    }
                    _ => {
                        match tx_index.get(snap_op.transaction_id()) {
                            // if we have it, great.
                            Some(snap_tx) => {
                                let prev_current = snap_tx.previous_transactions()?;
                                if let Some(prev_tx_id) = last_snap_transaction_id.as_ref() {
                                    // this is not the first transaction in this snapshot, so
                                    // determine if the current transaction's prev_tx is equal
                                    // to what we'd set it to anyway. if so, do nothing, if
                                    // not, mark prev_tx for modification
                                    let prev_eq = prev_current.len() == 1 && prev_current[0] == prev_tx_id;
                                    if !prev_eq {
                                        mods.push(Modification::ClearPrevious);
                                        mods.push(Modification::PushPrevious(prev_tx_id.clone()));
                                    }
                                } else if prev_current.len() != 0 {
                                    // the prev list is blank, but our tx has a non-blank prev.
                                    // we need to clear the prev tx for this tx
                                    mods.push(Modification::ClearPrevious);
                                }
                            }
                            // if we don't have it, it's possible that it was removed at some
                            // point, snapshotted, and no longer exists. it would not be
                            // onboarded from another peer because push_tx() checks for
                            // existing tx even if snapshotted (this is desired), BUT it's
                            // possible another snap from another peer from a time *before* the
                            // tx was removed references it. this is how None happens here, and
                            // if so, we can check our `unset` index. if it was removed, great,
                            // mark it as such. if not, something's off (shouldn't happen, but
                            // hey, even *I* make mistakes) so throw an err.
                            None => {
                                if let Some(timestamp) = snapshot_unsets.get(snap_op.transaction_id()) {
                                    mods.push(Modification::Resurrect(timestamp.clone()));
                                    if let Some(prev_tx_id) = last_snap_transaction_id.as_ref() {
                                        mods.push(Modification::PushPrevious(prev_tx_id.clone()));
                                    }
                                } else {
                                    Err(Error::TopicMissingTransactions(vec![snap_op.transaction_id().clone()]))?;
                                }
                            }
                        }
                    }
                };
                if mods.len() > 0 {
                    let mods_entry = modifications.entry(snap_op.transaction_id().clone()).or_insert_with(|| Vec::new());
                    mods_entry.append(&mut mods);
                }
                // let the next iteration know what came before it
                last_snap_transaction_id = Some(snap_op.transaction_id().clone());
            }
        }

        // holds modified transactions
        let mut transactions_modified: Vec<TopicTransaction> = Vec::new();
        // a set of ids of any transactions that have been re-created
        let mut recreated: AHashSet<TransactionID> = AHashSet::new();
        for (tx_id, mut mods) in modifications {
            // get our resurrections first, then clears, then pushes
            mods.sort_unstable();
            mods.dedup();
            // generate a transaction we're going to be modifying. if we have a `Resurrect` mod
            // (notice we check position 0 which is why sorting is important) we give it priority
            // and *creater a new blank transaction* which will override any existing transactions
            // in the topic's tx chain. if we didn't do this, it's possible a dangling tx that has
            // been marked for removal would inject its data into the chain, which we do not want.
            // if we DON'T have a Resurrect, we attempt to pull and existing transaction from our
            // tx index. if that doesn't exist, we cry about it.
            let mut tx = if let Modification::Resurrect(ref timestamp) = mods[0] {
                let trans = Transaction::create_raw_with_id(
                    tx_id.clone(),
                    timestamp.clone(),
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
                let topic_trans = TopicTransaction {
                    transaction: trans,
                    snapshot: None,
                };
                recreated.insert(tx_id.clone());
                topic_trans
            } else {
                if let Some(tx) = tx_index.get(&tx_id) {
                    #[allow(suspicious_double_ref_op)]
                    tx.clone().clone()
                } else {
                    // this transaction doesn't exist in our index and we don't have any
                    // resurrect actions for it. that's an error =[
                    Err(Error::TopicMissingTransactions(vec![tx_id.clone()]))?
                }
            };

            let mut previous: BTreeSet<TransactionID> = tx.previous_transactions()?.into_iter().cloned().collect();
            for modification in mods {
                match modification {
                    // ignore these, we already dealt with resurrection
                    Modification::Resurrect(..) => {}
                    Modification::ClearPrevious => {
                        previous.clear();
                    }
                    Modification::PushPrevious(id) => {
                        previous.insert(id);
                    }
                }
            }
            tx.transaction_mut()
                .try_mod_ext_previous_transaction(previous.into_iter().collect())?;
            transactions_modified.push(tx);
        }
        cb(transactions_modified, tx_index, recreated)
    }

    /// Return all operations in this set, ordered causally. This will return an error if we have
    /// any breaks in our causal chain (ie, missing transactions).
    pub fn get_transactions_ordered<'a>(&'a self) -> Result<Vec<&'a TopicTransaction>> {
        let mut output: Vec<&'a TopicTransaction> = Vec::with_capacity(self.transactions().len());
        Self::with_expanded_snapshots(&[self.transactions()], |transactions_modified, mut tx_index, _recreated| {
            let nodes_existing = self.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
            let nodes_modified = transactions_modified.iter().map(|x| x.into()).collect::<Vec<_>>();

            // NOTE: we explicitely pass `nodes_modified` last here! order matters.
            let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_existing, &nodes_modified]);
            if !dag.missing().is_empty() {
                Err(Error::TopicMissingTransactions(dag.missing().iter().cloned().cloned().collect::<Vec<_>>()))?;
            }

            for node_id in dag.visited() {
                #[allow(suspicious_double_ref_op)]
                let node = dag
                    .index()
                    .get(node_id)
                    .ok_or_else(|| Error::TopicMissingTransactions(vec![node_id.clone().clone()]))?;
                // ignore nodes that have been unset
                if !node.node().is_empty() {
                    // NOTE: we can't push `node.node()` directly here because it's a clone of our
                    // original list, so instead we pull from our dumb tx index.
                    if let Some(tx) = tx_index.remove(node.node().id()) {
                        output.push(tx);
                    }
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
        let ordered = self.get_transactions_ordered()?;
        let has_been_unset = ordered
            .iter()
            .filter_map(|t| match t.get_packet() {
                Ok(Packet::DataUnset { transaction_ids }) => Some(transaction_ids),
                _ => None,
            })
            .flatten()
            .collect::<AHashSet<_>>();
        let data_ops = ordered
            .into_iter()
            .filter(|t| !has_been_unset.contains(t.id()))
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
    #[tracing::instrument(ret, err(Debug), skip_all, fields(topic_id = %&format!("{}", self.id())[0..8], replaces = %&format!("{}", replaces)[0..8]))]
    pub fn snapshot(
        &mut self,
        master_key: &SecretKey,
        sign_key: &SignKeypair,
        replaces: &TransactionID,
    ) -> Result<BTreeSet<TransactionID>> {
        // if our replacement node is inside of an existing snapshot, that's basically a NOP and we
        // just return without touching anything.
        for trans in self.transactions() {
            if let Some(snap) = trans.snapshot().as_ref() {
                if snap.all_transactions().contains(&replaces) {
                    Err(Error::SnapshotCollision(trans.id().clone()))?;
                }
            }
        }
        let (final_nodes, removed) =
            Self::with_expanded_snapshots(&[self.transactions()], |transactions_modified, tx_index, recreated| {
                // this tracks nodes that either a) unset other nodes or b) have been unset
                let mut unsets_in_causal_chain: AHashSet<TransactionID> = AHashSet::new();
                // tracks transactions that are part of another snapshot
                let mut in_existing_snapshot: AHashMap<&TransactionID, &SnapshotOrderedOp> = AHashMap::new();
                // track transactions that have been removed as part of other previous snapshots. we
                // need to do this so we don't go trying to load data from these removals (which will
                // be expanded to fake transactions by `with_expanded_snapshots()`)
                let mut previously_snapshotted_removals: AHashMap<&TransactionID, &SnapshotOrderedOp> = AHashMap::new();
                // a list of transactions that are being removed by this snapshot. this is returned to the
                // caller so these transactions can be wiped from storage.
                let mut removed = BTreeSet::new();

                let nodes_old = self.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
                let nodes_modified = transactions_modified.iter().map(|x| x.into()).collect::<Vec<_>>();
                let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_old, &nodes_modified]);
                if !dag.missing().is_empty() {
                    Err(Error::TopicMissingTransactions(dag.missing().iter().cloned().cloned().collect::<Vec<_>>()))?;
                }
                if !dag.visited().contains(&replaces) {
                    Err(Error::SnapshotFailed)?;
                }

                // a set of all transactions that this snapshot will encompass
                let include_in_current_snapshot = dag.get_causal_chain(replaces);

                // sorry for all the loops
                //
                // we're going to index all transactions that exist in previous snapshots, as well as find
                // all nodes in this snapshot's causal chain that have been unset
                for tx in self.transactions() {
                    // only track unsets *if the unsetting node is in the snapshot's causal chain*
                    if include_in_current_snapshot.contains(tx.id()) {
                        for txid in tx.unset_ids()? {
                            if include_in_current_snapshot.contains(&txid) {
                                unsets_in_causal_chain.insert(txid);
                            }
                        }
                    }
                    // track and save a) all previously snapshotted tx and b) all removals
                    if let Some(snapshot) = tx.snapshot() {
                        for op in snapshot.entry().ordered_transactions() {
                            in_existing_snapshot.insert(op.transaction_id(), op);
                            if let SnapshotOrderedOp::Remove { id, .. } = op {
                                previously_snapshotted_removals.insert(id, op);
                            }
                        }
                    }
                }

                // this list will replace `self.transactions`
                let mut final_nodes: Vec<TopicTransaction> = Vec::with_capacity(self.transactions().len());
                // this is our final snapshot list
                let mut snapshot_ordered_operations: Vec<SnapshotOrderedOp> = Vec::new();
                for node_id in dag.visited() {
                    #[allow(suspicious_double_ref_op)]
                    let node_id = node_id.clone().clone();
                    // pull from our index, which stores the *original* transactions, NOT OUR MODIFIED
                    // ONES WITH TAMPERED `previous_transactions()` fields that
                    // `with_expanded_snapshots()` sullied.
                    #[allow(suspicious_double_ref_op)]
                    let mut tx = tx_index
                        .get(&node_id)
                        .or_else(|| {
                            // we might not have this tx in the main index if it's a re-created
                            // removal. in that case, let's pull a fake from the dag index.
                            if recreated.contains(&node_id) {
                                dag.index().get(&node_id).map(|x| x.node())
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| Error::TopicMissingTransactions(vec![node_id.clone()]))?
                        .clone()
                        .clone();
                    if &node_id == replaces {
                        // this is our replacement node! create our snapshot.
                        let save = SnapshotOrderedOp::Keep { id: node_id };
                        snapshot_ordered_operations.push(save);
                        let snapshot_ops = snapshot_ordered_operations;
                        snapshot_ordered_operations = Vec::new();
                        tx.snapshot = Some(Snapshot::new(master_key, sign_key, snapshot_ops)?);
                        final_nodes.push(tx);
                    } else if include_in_current_snapshot.contains(&node_id) {
                        // the current tx should be included in the current snapshot we're
                        // building.

                        // just remove any existing snapshots. we don't need them anymore.
                        //
                        // BUT!! only take them if they're in the causal chain for THIS snapshot,
                        // otherwise we're going to erase data.
                        tx.snapshot_mut().take();
                        if let Some(op) = previously_snapshotted_removals.remove(&node_id) {
                            // this tx was removed and its removal is being tracked by another
                            // snapshot. in this case, we pluck the original snapshot's removal op
                            // and dump it directly into ours
                            snapshot_ordered_operations.push(op.clone());
                        } else if in_existing_snapshot.contains_key(&node_id) && !unsets_in_causal_chain.contains(&node_id) {
                            // if this tx is part of another snapshot AND it has NOT been marked as
                            // removed, pluck the op and shove it into our snapshot list (and push
                            // the tx itself if it's a keeper).
                            //
                            // if we do NOT filter out removed nodes (by checking unsets_in_causal_chain)
                            // we run the risk of allowing a keeper tx from an earlier snapshot
                            // overriding a later removal, which can make removed data re-appear.
                            let op = in_existing_snapshot
                                .remove(&node_id)
                                // could probs `expect()` here but it makes my skin crawl
                                .ok_or_else(|| Error::TopicMissingTransactions(vec![node_id.clone()]))?;
                            if let SnapshotOrderedOp::Keep { .. } = op {
                                final_nodes.push(tx);
                            }
                            snapshot_ordered_operations.push(op.clone());
                        } else if tx.is_unset()? || unsets_in_causal_chain.contains(&node_id) {
                            // if this is an unsetter or unsettee node, mark it for removal
                            let save = SnapshotOrderedOp::Remove {
                                id: node_id.clone().clone(),
                                timestamp: tx.timestamp().clone(),
                            };
                            snapshot_ordered_operations.push(save);
                            // notify the caller this tx can be removed from whatever storage
                            removed.insert(node_id.clone().clone());
                        } else {
                            // none of the above applies, so we're going to assume we should create
                            // a Keep op for this tx and push the tx itself to the final list.
                            let save = SnapshotOrderedOp::Keep {
                                id: node_id.clone().clone(),
                            };
                            snapshot_ordered_operations.push(save);
                            final_nodes.push(tx);
                        }
                    } else if !recreated.contains(&node_id) {
                        // if this isn't a node we're snapshotting and it hasn't been re-created by
                        // the expansion of our in-chain snapshots, push it to the tx list.
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
    use rayon::prelude::*;
    use stamp_core::{
        crypto::base::{
            rng::{self, ChaCha20Rng, CryptoRng, RngCore},
            Hash, HashAlgo, SecretKey,
        },
        dag::tx_chain,
        identity::keychain::{AdminKey, ExtendKeypair, Key},
    };
    use std::cell::{Ref, RefCell};
    use std::collections::HashMap;
    use std::ops::Add;
    use std::str::FromStr;
    use std::sync::{mpsc, Arc, Mutex};
    use tracing::{
        log::{info, warn},
        {event, Level},
    };
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    #[allow(dead_code)]
    fn setup() {
        tracing_subscriber::registry()
            .with(fmt::layer().with_span_events(fmt::format::FmtSpan::CLOSE))
            .with(EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("info")).unwrap())
            .try_init()
            .unwrap_or_else(|_| ())
    }

    fn ts(time: &str) -> Timestamp {
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
    fn dump_tx(tx: &[(&'static str, &Transaction)]) {
        let name_map = tx.iter().map(|(name, tx)| (tx.id().clone(), name)).collect::<AHashMap<_, _>>();
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
            println!("- {}:    {}    prev: [{}]", &format!("{}", trans.id())[0..8], name, next);
        }
    }

    #[allow(dead_code)]
    fn dump_dag(transactions: &[TopicTransaction]) {
        #[derive(PartialEq, Eq)]
        enum Output {
            D2,
            Mermaid,
            PlantUML,
        }
        let output = Output::D2;
        // 7 because we use the timestamp as a mod and nobody is divisible by 7
        let link_colors = ["#0066ff", "#009933", "#9900cc", "#e6b800", "#0066ff", "#009933", "#9900cc"];

        let short = |txid: &TransactionID| -> String { format!("{}", txid)[0..8].replace("-", "_") };

        let mut transactions = Vec::from(transactions);
        transactions.sort_unstable_by(|a, b| a.transaction().cmp(b.transaction()));
        let idx = transactions
            .iter()
            .map(|tx| (tx.id().clone(), tx.transaction().entry().created().timestamp()))
            .collect::<AHashMap<_, _>>();

        struct GraphNode {
            id: String,
            ypos: i64,
            title: String,
            fill: Option<String>,
        }

        let nodes = transactions
            .iter()
            .map(|tx| GraphNode {
                id: short(tx.id()),
                ypos: tx.transaction().entry().created().timestamp(),
                title: format!(
                    "{}{}",
                    short(tx.id()),
                    if let Some(snap) = tx.snapshot().as_ref() {
                        format!(" ({})", snap.entry().ordered_transactions().len())
                    } else {
                        format!("")
                    }
                ),
                fill: if tx.snapshot().is_some() { Some(format!("#cc8")) } else { None },
            })
            .collect::<Vec<_>>();
        let mut grouped = BTreeMap::new();
        for node in nodes {
            let entry = grouped.entry(node.ypos).or_insert(Vec::new());
            (*entry).push(node);
        }
        let max_group_size = grouped.values().fold(0, |acc, x| if acc < x.len() { x.len() } else { acc });
        match output {
            Output::D2 => {
                println!("grid-columns: 2");
                println!("classes: {{ hide-full: {{ style.opacity: 0; label: aaaaaaaa; }} }} ");
                println!("classes: {{ hide-half: {{ style.opacity: 0; label: a; }} }} ");
                println!(
                    "classes: {{ {} }}",
                    link_colors
                        .iter()
                        .enumerate()
                        .map(|(i, color)| format!("link{}: {{ style.stroke: '{}' }}", i, color))
                        .collect::<Vec<_>>()
                        .join("; ")
                );
                println!("missing {{ grid-columns: 1; label.near: top-left;");
                for tx in &transactions {
                    for prev in tx.previous_transactions().unwrap() {
                        if !idx.contains_key(prev) {
                            println!("    {} : {}", short(prev), short(prev));
                        }
                    }
                }
                println!("}}");
                println!("nodes {{");
                println!("    grid-columns: 1");
            }
            Output::Mermaid => {
                println!("flowchart");
            }
            Output::PlantUML => {
                println!("@startuml");
            }
        }
        let mut last_ypos = None;
        for (ypos, nodes) in grouped.iter() {
            match output {
                Output::D2 => {
                    println!("t-{} {{  grid-rows: 1; label.near: top-right;", ypos);
                }
                Output::Mermaid => {
                    println!("subgraph t-{}", ypos);
                    println!("direction TB");
                }
                _ => {}
            }
            if (max_group_size - nodes.len()) & 1 == 1 {
                println!("    hide0.class: hide-half");
            }
            for i in 0..((max_group_size - nodes.len()) / 2) {
                println!("    hide{}.class: hide-full", i + 1);
            }
            for node in nodes {
                match output {
                    Output::D2 => {
                        println!("    {} : {}", node.id, node.title);
                        if let Some(fill) = node.fill.as_ref() {
                            println!("    {}.style.fill: '{}'", node.id, fill);
                        }
                    }
                    Output::Mermaid => {
                        println!("    {}[{}]", node.id, node.title);
                        if let Some(fill) = node.fill.as_ref() {
                            println!("    style {} fill:{}", node.id, fill);
                        }
                    }
                    Output::PlantUML => {
                        println!(
                            "rectangle {} as \"{}\" {}",
                            node.id,
                            node.title,
                            node.fill.as_ref().map(|x| x.as_str()).unwrap_or("")
                        );
                    }
                }
            }
            match output {
                Output::D2 => {
                    println!("}}");
                }
                Output::Mermaid => {
                    println!("end");
                    if let Some(last) = last_ypos {
                        println!("t-{} ~~~ t-{}", last, ypos);
                    }
                }
                _ => {}
            }
            last_ypos = Some(ypos);
        }
        match output {
            Output::D2 => {
                println!("}}");
            }
            _ => {}
        }
        for tx in &transactions {
            let ypos = tx.transaction().entry().created().timestamp();
            for prev in tx.previous_transactions().unwrap() {
                let prev_ypos = idx.get(prev);
                match output {
                    Output::D2 => {
                        if let Some(prev_ypos) = prev_ypos {
                            let color_num = *prev_ypos as usize % link_colors.len();
                            println!(
                                "nodes.t-{}.{} --> nodes.t-{}.{} {{ class: link{} }}",
                                prev_ypos,
                                short(prev),
                                ypos,
                                short(tx.id()),
                                color_num,
                            );
                        } else {
                            println!("missing.{} --> nodes.t-{}.{} {{ style.stroke: red }}", short(prev), ypos, short(tx.id()));
                        }
                    }
                    Output::Mermaid | Output::PlantUML => {
                        println!("{} --> {}", short(prev), short(tx.id()));
                    }
                }
            }
        }
        match output {
            Output::PlantUML => {
                println!("@enduml");
            }
            _ => {}
        }
    }

    #[allow(dead_code)]
    fn dump_dag_expanded(transactions: &[&[TopicTransaction]]) {
        fn short(txid: &TransactionID) -> String {
            format!("{}", txid)[0..8].replace("-", "_")
        }

        Topic::with_expanded_snapshots(transactions, |modified, _idx, _recreated| {
            let mut nodes_collections: Vec<Vec<DagNode<TransactionID, TopicTransaction>>> = transactions
                .iter()
                .map(|list| list.iter().map(|t| t.into()).collect::<Vec<_>>())
                .collect::<Vec<_>>();
            nodes_collections.push(modified.iter().map(|t| t.into()).collect::<Vec<_>>());
            let dag: Dag<TransactionID, TopicTransaction> =
                Dag::from_nodes(&nodes_collections.iter().map(|c| c.as_slice()).collect::<Vec<_>>());
            #[allow(suspicious_double_ref_op)]
            let dumpme = dag.index().values().map(|x| x.node().clone().clone()).collect::<Vec<_>>();
            dump_dag(&dumpme);
            Ok(())
        })
        .unwrap();
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

        fn new_identity<R: RngCore + CryptoRng>(
            rng_seed: &mut R,
            topic_id: &TopicID,
            master_passphrase: &'static str,
            device_name: &str,
        ) -> Self {
            let mut randbuf = [0u8; 32];
            rng_seed.fill_bytes(&mut randbuf);
            let mut rng = rng::chacha20_seeded(randbuf);

            let topic = Topic::new(topic_id.clone());

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

        fn push_tx<T: Into<TopicTransaction> + Clone + std::fmt::Debug>(
            &self,
            identities: &AHashMap<IdentityID, &Transactions>,
            transactions: &[&T],
        ) -> Result<TopicDagModificationResult> {
            #[allow(suspicious_double_ref_op)]
            let topic_tx = transactions.iter().map(|t| t.clone().clone().into()).collect::<Vec<_>>();
            let fake_topic = Topic::new(TopicID::from_bytes([0; 16]));
            // take the topic out of the peer so we can mutate it without the borrow checker
            // blowing a gasket
            let mut topic = self.topic.replace(fake_topic);
            let dag_state = match topic.push_transactions_mut(
                topic_tx,
                identities,
                self.master_key(),
                &self.crypto_keys().iter().collect::<Vec<_>>(),
                &self.identity.identity_id().unwrap(),
                &self.device().id().clone(),
            ) {
                Ok(s) => {
                    self.topic.replace(topic);
                    s
                }
                Err(e) => {
                    self.topic.replace(topic);
                    Err(e)?
                }
            };
            Ok(dag_state)
        }

        fn snapshot(&self, replaces: &TransactionID) -> Result<BTreeSet<TransactionID>> {
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
            let res = match topic.snapshot(self.master_key(), &sign_key, replaces) {
                Ok(res) => {
                    self.topic.replace(topic);
                    res
                }
                Err(e) => {
                    self.topic.replace(topic);
                    Err(e)?
                }
            };
            Ok(res)
        }

        #[allow(dead_code)]
        fn hash(&self) -> Hash {
            let mut ser_bytes = Vec::new();
            let mut rng_bytes = {
                let mut rng = self.rng.clone();
                let mut buf = [0u8; 16];
                rng.fill_bytes(&mut buf);
                Vec::from(buf)
            };
            ser_bytes.append(&mut rng_bytes);
            ser_bytes.append(&mut self.topic().id().serialize_binary().unwrap());
            ser_bytes.append(&mut self.topic().state().serialize_binary().unwrap());
            ser_bytes.append(&mut self.topic().transactions().serialize_binary().unwrap());
            ser_bytes.append(&mut self.topic().last_tail_nodes().serialize_binary().unwrap());
            ser_bytes.append(&mut Vec::from(self.master_passphrase().as_bytes()));
            ser_bytes.append(&mut Vec::from(self.master_key().as_ref()));
            ser_bytes.append(&mut self.identity().serialize_binary().unwrap());
            ser_bytes.append(&mut self.device().serialize_binary().unwrap());
            ser_bytes.append(&mut self.key_packets().serialize_binary().unwrap());
            Hash::new_blake3(&ser_bytes[..]).unwrap()
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
        let identity_map = AHashMap::from([(identity.identity_id().unwrap(), identity)]);
        Topic::new_from_transactions(topic_id.clone(), transactions, &identity_map, master_key, &[&crypto_key], &identity_id, device_id)
            .unwrap()
    }

    fn probability<R: RngCore + CryptoRng>(rng: &mut R, chance: f32) -> bool {
        let mut byte = [0u8; 1];
        rng.fill_bytes(&mut byte);
        byte[0] < (chance * 256.0) as u8
    }

    fn choice<R: RngCore + CryptoRng>(rng: &mut R, one_of: usize) -> usize {
        let mut byte = [0u8; 2];
        rng.fill_bytes(&mut byte);
        let val: u16 = ((byte[0] as u16) << 8) + (byte[1] as u16);
        ((one_of as u32) * (val as u32) / (u16::MAX as u32)) as usize
    }

    // creates a device_id -> crypto pubkey mapping
    fn device_lookup<'a>(packets: &[&'a KeyPacket]) -> BTreeMap<&'a DeviceID, &'a CryptoKeypairPublic> {
        packets
            .iter()
            .map(|p| (p.entry().device_id(), p.entry().pubkey()))
            .collect::<BTreeMap<_, _>>()
    }

    // creates a lookup table for a set of peers
    fn id_lookup<'a>(peers: &[&'a Peer]) -> AHashMap<IdentityID, &'a Transactions> {
        peers
            .iter()
            .map(|p| (p.identity().identity_id().unwrap(), p.identity()))
            .collect::<AHashMap<_, _>>()
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
            let identity_map = AHashMap::from([(identity_id.clone(), &transactions)]);
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
        let topic_id = TopicID::new(&mut rng);

        let mut butch_laptop = Peer::new_identity(&mut rng, &topic_id, "butch123", "laptop");
        let butch_phone = butch_laptop.new_device("phone");
        let mut dotty_laptop = Peer::new_identity(&mut rng, &topic_id, "dotty666", "laptop");
        let mut jerry_laptop = Peer::new_identity(&mut rng, &topic_id, "jerjer1", "laptop");
        let mut frankie_phone = Peer::new_identity(&mut rng, &topic_id, "frankiehankie", "phone");

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
            assert_eq!(butch_laptop.push_tx(&all_ids_lookup, &[&data4]).unwrap(), TopicDagModificationResult::DagUpdated);
            assert_eq!(butch_phone.push_tx(&all_ids_lookup, &[&data4]).unwrap(), TopicDagModificationResult::DagUpdated);
            assert_eq!(jerry_laptop.push_tx(&all_ids_lookup, &[&data4]).unwrap(), TopicDagModificationResult::DagUpdated);
            assert_eq!(frankie_phone.push_tx(&all_ids_lookup, &[&data4]).unwrap(), TopicDagModificationResult::DagUpdated);
        }
        let data5 = jerry_laptop.tx_data(ts("2024-12-10T00:01:00Z"), AppData::new("just saw a cat"), None, None);
        {
            let all_ids_lookup = id_lookup(&[&butch_laptop, &butch_phone, &dotty_laptop, &jerry_laptop, &frankie_phone]);
            assert_eq!(butch_laptop.push_tx(&all_ids_lookup, &[&data5]).unwrap(), TopicDagModificationResult::DagUpdated);
            assert_eq!(butch_phone.push_tx(&all_ids_lookup, &[&data5]).unwrap(), TopicDagModificationResult::DagUpdated);
            assert_eq!(jerry_laptop.push_tx(&all_ids_lookup, &[&data5]).unwrap(), TopicDagModificationResult::DagUpdated);
            assert_eq!(frankie_phone.push_tx(&all_ids_lookup, &[&data5]).unwrap(), TopicDagModificationResult::DagUpdated);
        }
        let data6 = frankie_phone.tx_data(ts("2024-12-10T00:02:00Z"), AppData::new("i hate cats"), None, None);
        {
            let all_ids_lookup = id_lookup(&[&butch_laptop, &butch_phone, &dotty_laptop, &jerry_laptop, &frankie_phone]);
            assert_eq!(butch_laptop.push_tx(&all_ids_lookup, &[&data6]).unwrap(), TopicDagModificationResult::DagUpdated);
            assert_eq!(butch_phone.push_tx(&all_ids_lookup, &[&data6]).unwrap(), TopicDagModificationResult::DagUpdated);
            assert_eq!(jerry_laptop.push_tx(&all_ids_lookup, &[&data6]).unwrap(), TopicDagModificationResult::DagUpdated);
            assert_eq!(frankie_phone.push_tx(&all_ids_lookup, &[&data6]).unwrap(), TopicDagModificationResult::DagUpdated);
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
            assert_eq!(
                butch_laptop.push_tx(&all_ids_lookup, &[&perms1, &perms2]).unwrap(),
                TopicDagModificationResult::DagRebuilt
            );
            assert_eq!(
                butch_phone.push_tx(&all_ids_lookup, &[&perms1, &perms2]).unwrap(),
                TopicDagModificationResult::DagRebuilt
            );
            assert_eq!(
                dotty_laptop.push_tx(&all_ids_lookup, &[&data4, &data5, &data6]).unwrap(),
                TopicDagModificationResult::DagRebuilt
            );
            assert_eq!(
                jerry_laptop.push_tx(&all_ids_lookup, &[&perms1, &perms2]).unwrap(),
                TopicDagModificationResult::DagRebuilt
            );
            assert_eq!(
                frankie_phone.push_tx(&all_ids_lookup, &[&perms1, &perms2]).unwrap(),
                TopicDagModificationResult::DagRebuilt
            );
        }
    }

    #[test]
    fn topic_dag_rebuild_with_snapshot() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"dupe dupe").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut dotty = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dogphone");
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "butch6969", "laptop");
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
        assert_eq!(dotty.topic().find_leaves().unwrap(), vec![data5.id().clone()]);

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
        assert_eq!(dotty.topic().find_leaves().unwrap(), vec![data5.id().clone()]);

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
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut dotty = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dogphone");
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "butch6969", "laptop");
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
        dotty.push_tx(&id_lookup(&[&dotty]), &[&rekey1]).unwrap();
        butch.push_tx(&id_lookup(&[&dotty]), &[&rekey1, &genesis]).unwrap();

        let mut all_tx: AHashMap<String, TopicTransaction> = AHashMap::new();
        all_tx.insert("gen0".to_string(), genesis.into());
        all_tx.insert("rek1".to_string(), rekey1.into());
        for i in 0..5 {
            let tx_ts = format!("2024-12-10T01:00:{:0>2}.000Z", i * 2);
            let data = butch.tx_data(ts(&tx_ts), AppData::new(format!("data: butch 1: {}", i)), None, None);
            butch.push_tx(&id_lookup(&[&butch]), &[&data]).unwrap();
            all_tx.insert(format!("butch-1-{}", i), data.into());
        }
        let mut butch_clone = butch.clone();
        for i in 5..10 {
            let tx_ts = format!("2024-12-10T01:00:{:0>2}.000Z", i * 2);
            let data = butch.tx_data(ts(&tx_ts), AppData::new(format!("data: butch 1: {}", i)), None, None);
            butch.push_tx(&id_lookup(&[&butch]), &[&data]).unwrap();
            all_tx.insert(format!("butch-1-{}", i), data.into());
        }
        for i in 5..10 {
            let tx_ts = format!("2024-12-10T01:00:{:0>2}.500Z", i * 2);
            let data = butch_clone.tx_data(ts(&tx_ts), AppData::new(format!("data: butch 2: {}", i)), None, None);
            butch_clone.push_tx(&id_lookup(&[&butch]), &[&data]).unwrap();
            all_tx.insert(format!("butch-2-{}", i), data.into());
        }
        for i in 0..10 {
            let tx_ts = format!("2024-12-10T01:00:{:0>2}.000Z", (i * 2) + 1);
            let data = dotty.tx_data(ts(&tx_ts), AppData::new(format!("data: dotty: {}", i)), None, None);
            dotty.push_tx(&id_lookup(&[&dotty]), &[&data]).unwrap();
            all_tx.insert(format!("dotty-1-{}", i), data.into());
        }

        assert_eq!(
            topicdata!(butch).unwrap(),
            vec![
                AppData::new("data: butch 1: 0"),
                AppData::new("data: butch 1: 1"),
                AppData::new("data: butch 1: 2"),
                AppData::new("data: butch 1: 3"),
                AppData::new("data: butch 1: 4"),
                AppData::new("data: butch 1: 5"),
                AppData::new("data: butch 1: 6"),
                AppData::new("data: butch 1: 7"),
                AppData::new("data: butch 1: 8"),
                AppData::new("data: butch 1: 9"),
            ]
        );
        assert_eq!(
            topicdata!(butch_clone).unwrap(),
            vec![
                AppData::new("data: butch 1: 0"),
                AppData::new("data: butch 1: 1"),
                AppData::new("data: butch 1: 2"),
                AppData::new("data: butch 1: 3"),
                AppData::new("data: butch 1: 4"),
                AppData::new("data: butch 2: 5"),
                AppData::new("data: butch 2: 6"),
                AppData::new("data: butch 2: 7"),
                AppData::new("data: butch 2: 8"),
                AppData::new("data: butch 2: 9"),
            ]
        );
        assert_eq!(
            topicdata!(dotty).unwrap(),
            vec![
                AppData::new("data: dotty: 0"),
                AppData::new("data: dotty: 1"),
                AppData::new("data: dotty: 2"),
                AppData::new("data: dotty: 3"),
                AppData::new("data: dotty: 4"),
                AppData::new("data: dotty: 5"),
                AppData::new("data: dotty: 6"),
                AppData::new("data: dotty: 7"),
                AppData::new("data: dotty: 8"),
                AppData::new("data: dotty: 9"),
            ]
        );

        butch
            .push_tx(&id_lookup(&[&dotty, &butch]), &all_tx.values().collect::<Vec<_>>())
            .unwrap();
        dotty
            .push_tx(&id_lookup(&[&dotty, &butch]), &all_tx.values().collect::<Vec<_>>())
            .unwrap();

        assert_eq!(
            topicdata!(butch).unwrap(),
            vec![
                AppData::new("data: butch 1: 0"),
                AppData::new("data: dotty: 0"),
                AppData::new("data: butch 1: 1"),
                AppData::new("data: dotty: 1"),
                AppData::new("data: butch 1: 2"),
                AppData::new("data: dotty: 2"),
                AppData::new("data: butch 1: 3"),
                AppData::new("data: dotty: 3"),
                AppData::new("data: butch 1: 4"),
                AppData::new("data: dotty: 4"),
                AppData::new("data: butch 1: 5"),
                AppData::new("data: butch 2: 5"),
                AppData::new("data: dotty: 5"),
                AppData::new("data: butch 1: 6"),
                AppData::new("data: butch 2: 6"),
                AppData::new("data: dotty: 6"),
                AppData::new("data: butch 1: 7"),
                AppData::new("data: butch 2: 7"),
                AppData::new("data: dotty: 7"),
                AppData::new("data: butch 1: 8"),
                AppData::new("data: butch 2: 8"),
                AppData::new("data: dotty: 8"),
                AppData::new("data: butch 1: 9"),
                AppData::new("data: butch 2: 9"),
                AppData::new("data: dotty: 9"),
            ]
        );

        dotty.snapshot(all_tx.get("butch-2-7").as_ref().unwrap().id()).unwrap();

        assert_eq!(
            topicdata!(butch).unwrap(),
            vec![
                AppData::new("data: butch 1: 0"),
                AppData::new("data: dotty: 0"),
                AppData::new("data: butch 1: 1"),
                AppData::new("data: dotty: 1"),
                AppData::new("data: butch 1: 2"),
                AppData::new("data: dotty: 2"),
                AppData::new("data: butch 1: 3"),
                AppData::new("data: dotty: 3"),
                AppData::new("data: butch 1: 4"),
                AppData::new("data: dotty: 4"),
                AppData::new("data: butch 1: 5"),
                AppData::new("data: butch 2: 5"),
                AppData::new("data: dotty: 5"),
                AppData::new("data: butch 1: 6"),
                AppData::new("data: butch 2: 6"),
                AppData::new("data: dotty: 6"),
                AppData::new("data: butch 1: 7"),
                AppData::new("data: butch 2: 7"),
                AppData::new("data: dotty: 7"),
                AppData::new("data: butch 1: 8"),
                AppData::new("data: butch 2: 8"),
                AppData::new("data: dotty: 8"),
                AppData::new("data: butch 1: 9"),
                AppData::new("data: butch 2: 9"),
                AppData::new("data: dotty: 9"),
            ]
        );

        let dotty_tx = dotty.topic();
        let snap_tx = dotty_tx
            .transactions()
            .iter()
            .find(|t| t.id() == all_tx.get("butch-2-7").as_ref().unwrap().id())
            .unwrap();
        assert_eq!(
            snap_tx
                .snapshot()
                .as_ref()
                .unwrap()
                .all_transactions()
                .iter()
                .map(|t| format!("{}", t))
                .collect::<Vec<_>>(),
            vec![
                "gen0",
                "rek1",
                "butch-1-0",
                "butch-1-1",
                "butch-1-2",
                "butch-1-3",
                "butch-1-4",
                "butch-2-5",
                "butch-2-6",
                "butch-2-7",
            ]
            .into_iter()
            .map(|n| format!("{}", all_tx.get(n).as_ref().unwrap().id()))
            .collect::<Vec<_>>()
        );
    }

    // ok! this test procedurally generates a topic with multiple peers and tries to simulate them
    // talking to each other over variably-semi-reliable channels to mimic the creation of branches
    // and merges.
    //
    // for now this only tests rm/data/snapshot transactions, not things like changing perms and
    // all that.
    #[test]
    fn topic_procedural_peer_channels() {
        /// Like `Peer`, but with channels
        #[derive(Debug, getset::Getters, getset::MutGetters, getset::Setters)]
        #[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
        struct PeerOuter {
            peer: Peer,
            recv: mpsc::Receiver<TopicTransaction>,
            send: mpsc::SyncSender<TopicTransaction>,
        }

        impl PeerOuter {
            fn new(peer: Peer) -> Self {
                let (send, recv) = mpsc::sync_channel(5000);
                Self { peer, recv, send }
            }

            #[tracing::instrument(level = "info", skip_all, fields(%iter, peer = %&format!("{}", self.peer().identity().identity_id().unwrap())[0..8]))]
            fn step<R: RngCore + CryptoRng + Clone>(
                &mut self,
                lookup: &AHashMap<IdentityID, &Transactions>,
                rng: &mut R,
                timestamp: Timestamp,
                iter: usize,
            ) -> Result<Vec<(TopicTransaction, Option<AppData>)>> {
                // first, process any incoming transactions
                let mut incoming = Vec::new();
                loop {
                    match self.recv.try_recv() {
                        Ok(tx) => incoming.push(tx),
                        _ => break,
                    }
                }
                let tx_ref = incoming.iter().collect::<Vec<_>>();

                let old_ids = self
                    .peer()
                    .topic()
                    .transactions()
                    .iter()
                    .map(|t| t.id().clone())
                    .collect::<AHashSet<_>>();

                self.peer.push_tx(lookup, &tx_ref)?;

                info!(
                    "incoming {} -- new [{}]",
                    incoming.len(),
                    self.peer()
                        .topic()
                        .transactions()
                        .iter()
                        .filter(|t| !old_ids.contains(t.id()))
                        .map(|t| format!("{}{}", &format!("{}", t.id())[0..8], if t.snapshot().is_some() { "(s)" } else { "" }))
                        .collect::<Vec<_>>()
                        .join(", "),
                );

                let mut tx_return = Vec::new();

                // add a new transaction?
                if probability(rng, 0.5) {
                    let tx_data = AppData::new(format!("{} -- {}", self.peer().device().name(), iter));
                    let tx = TopicTransaction::new(self.peer_mut().tx_data(timestamp, tx_data.clone(), None, None));
                    info!(
                        "new tx {} [{}] :: \"{}\"",
                        &format!("{}", tx.id())[0..8],
                        tx.previous_transactions()
                            .unwrap()
                            .iter()
                            .map(|p| String::from(&format!("{}", p)[0..8]))
                            .collect::<Vec<_>>()
                            .join(", "),
                        &tx_data.data,
                    );
                    self.peer().push_tx(lookup, &[&tx])?;
                    tx_return.push((tx, Some(tx_data)));
                } else if probability(rng, 0.1) && self.peer().topic().transactions().len() > 2 {
                    let removals = {
                        let mut tx_ids = self
                            .peer()
                            .topic()
                            .transactions()
                            .iter()
                            .filter(|t| t.is_data_packet().unwrap())
                            .map(|t| t.id().clone())
                            .collect::<Vec<_>>();
                        tx_ids.sort_unstable();
                        let mut removals = Vec::with_capacity(5);
                        for _ in 0..(choice(rng, 3) + 1) {
                            // we could try to get UNIQUE transaction ids but i really don't care
                            // that much TBH
                            removals.push(tx_ids[choice(rng, tx_ids.len() - 1) + 1].clone());
                        }
                        removals
                    };
                    let tx_rm = TopicTransaction::new(self.peer().tx(
                        timestamp,
                        None,
                        Packet::DataUnset {
                            transaction_ids: removals.clone(),
                        },
                    ));
                    info!(
                        "rm {} [{}]",
                        &format!("{}", tx_rm.id())[0..8],
                        removals
                            .iter()
                            .map(|p| String::from(&format!("{}", p)[0..8]))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    self.peer().push_tx(lookup, &[&tx_rm])?;
                    tx_return.push((tx_rm, None));
                }

                // create snapshot?
                if probability(rng, 0.05) {
                    let eligible = {
                        let topic = self.peer().topic();
                        let in_existing_snap = topic
                            .transactions()
                            .iter()
                            .filter_map(|t| t.snapshot().as_ref().map(|s| s.all_transactions()))
                            .flatten()
                            .collect::<AHashSet<_>>();
                        topic
                            .transactions()
                            .iter()
                            .filter(|t| !in_existing_snap.contains(t.id()))
                            .map(|t| t.id().clone())
                            .collect::<Vec<_>>()
                    };
                    if eligible.len() > 0 {
                        let tx_id = eligible[choice(rng, eligible.len())].clone();
                        let rm = self.peer().snapshot(&tx_id).unwrap();
                        info!(
                            "snapshot {} [{}] (rm [{}])",
                            &format!("{}", tx_id)[0..8],
                            self.peer()
                                .topic()
                                .transactions()
                                .iter()
                                .find(|t| t.id() == &tx_id)
                                .unwrap()
                                .snapshot()
                                .as_ref()
                                .map(|s| {
                                    s.all_transactions()
                                        .iter()
                                        .map(|id| String::from(&format!("{}", id)[0..8]))
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                })
                                .unwrap_or(String::from("-")),
                            rm.iter()
                                .map(|t| String::from(&format!("{}", t)[0..8]))
                                .collect::<Vec<_>>()
                                .join(", "),
                        );
                    }
                }
                Ok(tx_return)
            }
        }

        #[tracing::instrument(level = "warn")]
        fn run_topic(seed_val: usize) {
            let seed = format!(
                "eternal life offers nothing, instead shadowing a neverendingly affluent zombie infestation:{}",
                seed_val
            );
            let mut rng_outer = rng::chacha20_seeded(Hash::new_blake3(seed.as_bytes()).unwrap().as_bytes().try_into().unwrap());
            let rng = &mut rng_outer;
            let mut setup_vals = [0u8; 3];
            let peer_names = vec![
                "butch", "dotty", "jerry", "frankie", "timmy", "wookie", "lucy", "sven", "nils", "wendall", "roxanne",
            ];
            rng.fill_bytes(&mut setup_vals);
            let num_peers = (setup_vals[0] as usize % (peer_names.len() - 2)) + 2;
            let num_iterations = (setup_vals[1] % 80) as usize + 5;
            let chatter_probability = (setup_vals[2] as f32) / (u8::MAX as f32);
            event!(Level::WARN, num_peers, num_iterations, chatter_probability);

            let topic_id = TopicID::new(rng);

            let tx_ordered: Arc<Mutex<Vec<(TopicTransaction, Option<AppData>)>>> = Arc::new(Mutex::new(Vec::new()));

            assert!(peer_names.len() >= num_peers);

            let mut peers = Vec::new();
            for i in 0..num_peers {
                let peer = PeerOuter::new(Peer::new_identity(rng, &topic_id, "PASSWORD1", peer_names[i]));
                peers.push(peer);
            }

            let mut cur_ts: chrono::DateTime<chrono::Utc> = "1999-10-01T00:00:00Z".parse().unwrap();
            let mut ts_next = || {
                cur_ts = cur_ts.add(std::time::Duration::from_secs(3600));
                Timestamp::from(cur_ts.clone())
            };

            let genesis = {
                let rekey_entries = peers
                    .iter()
                    .map(|po| {
                        (
                            po.peer().as_member(admin_perms(), vec![po.peer().device().clone()]),
                            device_lookup(&[&po.peer().key_packets()[0]]),
                        )
                    })
                    .collect::<Vec<_>>();
                let packet = peers[0]
                    .peer()
                    .topic()
                    .rekey(rng, rekey_entries.iter().map(|(x, y)| (x.clone(), y)).collect::<Vec<_>>())
                    .unwrap();
                TopicTransaction::new(peers[0].peer().tx(ts_next(), None, packet))
            };

            let peers_clone = peers.iter().map(|po| po.peer().clone()).collect::<Vec<_>>();
            let peers_lookup = id_lookup(&peers_clone.iter().collect::<Vec<_>>());
            for peer in &peers {
                peer.send().try_send(genesis.clone()).expect("peer channel buffer full");
            }
            tx_ordered.lock().unwrap().push((genesis, None));

            for i in 0..num_iterations {
                let ts = ts_next();
                // this will house any returned transactions from each of the peers as we step them
                let mut transactions = Vec::new();
                for peer in &mut peers {
                    let mut output = peer.step(&peers_lookup, rng, ts.clone(), i).unwrap();
                    // append any transaction this peer returned into our run-local list
                    transactions.append(&mut output);
                }
                // now we sort the returned transactions by id, which gives us accurate ordering
                // for transactions created at the same time
                transactions.sort_unstable_by_key(|x| x.0.id().clone());
                // append the ordered transactions to our final ordered list
                tx_ordered.lock().unwrap().append(&mut transactions);

                // every once in a while, a peer will dump its full herstory to another peer.
                for peer_tx in &peers {
                    for peer_rx in &peers {
                        if probability(rng, chatter_probability) {
                            let topic = peer_tx.peer().topic();
                            for tx in topic.transactions() {
                                peer_rx.send().try_send(tx.clone()).expect("peer channel buffer full");
                            }
                        }
                    }
                }
            }

            // ok we're done iterating, make sure all peers have all the same transactions
            let all_tx_clone = tx_ordered.lock().unwrap().clone();
            let all_tx_ref = all_tx_clone.iter().map(|e| &e.0).collect::<Vec<_>>();
            for peer in &peers {
                info!("Peer({}) -- full sync", peer.peer().identity().identity_id().unwrap());
                peer.peer().push_tx(&peers_lookup, &all_tx_ref).unwrap();
            }

            let final_data: Vec<AppData> = {
                let mut topic = Topic::new(topic_id.clone());
                topic
                    .push_transactions_mut(
                        all_tx_clone.iter().map(|x| &x.0).cloned().collect::<Vec<_>>(),
                        &peers_lookup,
                        peers[0].peer().master_key(),
                        &peers[0].peer().crypto_keys().iter().collect::<Vec<_>>(),
                        &peers[0].peer().identity().identity_id().unwrap(),
                        peers[0].peer().device().id(),
                    )
                    .unwrap();
                topic.get_data().unwrap().into_iter().collect::<Result<Vec<_>>>().unwrap()
            };

            {
                let has_been_unset = all_tx_clone
                    .iter()
                    .filter_map(|(t, _)| match t.get_packet() {
                        Ok(packet) => match packet {
                            Packet::DataUnset { transaction_ids } => Some(transaction_ids),
                            _ => None,
                        },
                        _ => None,
                    })
                    .flatten()
                    .collect::<AHashSet<_>>();
                let ordered_minus_removed = all_tx_clone
                    .iter()
                    .filter(|(tx, _)| !has_been_unset.contains(tx.id()))
                    .filter(|e| e.1.is_some())
                    .map(|e| e.1.clone().unwrap())
                    .collect::<Vec<_>>();
                let data0 = topicdata!(peers[0].peer()).unwrap();
                assert_eq!(final_data, ordered_minus_removed);
                assert_eq!(data0, ordered_minus_removed);
            }
            // make sure we all have the same view of the data
            for peer1 in &peers {
                let data1 = topicdata!(peer1.peer()).unwrap();
                assert_eq!(final_data, data1);
                for peer2 in &peers {
                    if peer1.peer().identity().identity_id() == peer2.peer().identity().identity_id() {
                        continue;
                    }
                    let data2 = topicdata!(peer2.peer()).unwrap();
                    assert_eq!(data1, data2);
                }
            }
        }

        let start: usize = std::env::var("CARRIER_PROC_TEST_START")
            .map(|v| v.parse::<usize>().unwrap())
            .unwrap_or(0);
        let end: usize = std::env::var("CARRIER_PROC_TEST_END")
            .map(|v| v.parse::<usize>().unwrap())
            .unwrap_or(4);
        if std::env::var("CARRIER_PROC_TEST_LOG") == Ok(String::from("1")) {
            setup();
        }

        warn!("run procedural tests {}..{}", start, end);
        (start..end).into_par_iter().for_each(|i| run_topic(i));
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
                D = ("2024-01-04T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"DDDD"));
                E = ("2024-01-08T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"lol"));
                F = ("2024-01-05T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"gfffft"));
                G = ("2024-01-09T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"GFFFFFF"));
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

    #[test]
    fn topic_snapshot_after_rm() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dogphone");
        let genesis = {
            let packet = butch.topic().rekey(&mut rng, vec![rkmember!(&butch, admin_perms(), 0)]).unwrap();
            butch.tx(ts("2024-12-08T01:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&genesis]).unwrap();
        let data1 = butch.tx_data(ts("2012-03-04T09:56:23Z"), AppData::new("get a job"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data1]).unwrap();
        let rm1 = TopicTransaction::new(butch.tx(
            ts("2012-03-04T09:57:00Z"),
            None,
            Packet::DataUnset {
                transaction_ids: vec![data1.id().clone()],
            },
        ));
        butch.push_tx(&id_lookup(&[&butch]), &[&rm1]).unwrap();
        butch.snapshot(rm1.id()).unwrap();
        let data2 = butch.tx_data(ts("2012-03-04T09:58:44Z"), AppData::new("marvelous"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data2]).unwrap();
        butch.snapshot(data2.id()).unwrap();
    }

    #[test]
    fn topic_rm_non_data() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dogphone");
        let genesis = {
            let packet = butch.topic().rekey(&mut rng, vec![rkmember!(&butch, admin_perms(), 0)]).unwrap();
            butch.tx(ts("2024-12-08T01:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&genesis]).unwrap();
        let perms1 = {
            let packet = Packet::MemberPermissionsChange {
                identity_id: butch.identity().identity_id().unwrap(),
                permissions: vec![Permission::DataSet, Permission::DataUnset, Permission::TopicRekey],
            };
            butch.tx(ts("2024-12-08T02:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&perms1]).unwrap();
        let data1 = butch.tx_data(ts("2024-12-08T03:00:00Z"), AppData::new("get a job"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data1]).unwrap();
        let rm1 = butch.tx(
            ts("2024-12-08T04:00:00Z"),
            None,
            Packet::DataUnset {
                transaction_ids: vec![data1.id().clone()],
            },
        );
        butch.push_tx(&id_lookup(&[&butch]), &[&rm1]).unwrap();

        // cannot unset perms
        {
            let rm = butch.tx(
                ts("2024-12-08T04:00:00Z"),
                None,
                Packet::DataUnset {
                    transaction_ids: vec![perms1.id().clone()],
                },
            );
            let res = butch.push_tx(&id_lookup(&[&butch]), &[&rm]);
            match res {
                Err(Error::TransactionUnsetNonDataPacket(txid)) => assert_eq!(txid, rm.id().clone()),
                _ => panic!("unexpected result: {:?}", res),
            }
        }

        // cannot unset genesis
        {
            let rm = butch.tx(
                ts("2024-12-08T04:00:00Z"),
                None,
                Packet::DataUnset {
                    transaction_ids: vec![genesis.id().clone()],
                },
            );
            let res = butch.push_tx(&id_lookup(&[&butch]), &[&rm]);
            match res {
                Err(Error::TransactionUnsetNonDataPacket(txid)) => assert_eq!(txid, rm.id().clone()),
                _ => panic!("unexpected result: {:?}", res),
            }
        }

        // cannot unset an unset
        {
            let rm = butch.tx(
                ts("2024-12-08T04:00:00Z"),
                None,
                Packet::DataUnset {
                    transaction_ids: vec![rm1.id().clone()],
                },
            );
            let res = butch.push_tx(&id_lookup(&[&butch]), &[&rm]);
            match res {
                Err(Error::TransactionUnsetNonDataPacket(txid)) => assert_eq!(txid, rm.id().clone()),
                _ => panic!("unexpected result: {:?}", res),
            }
        }
    }

    // tests a case where snapshots will erase data from other snapshots that are NOT in the
    // current snapshot's causal chain, causing data loss. snapshots should only be removed *if
    // they are in the current causal chain and can be incorporated into the current snapshot*.
    #[test]
    fn topic_snapshot_with_other_snapshot_outside_causal_chain() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dogphone");
        let genesis = {
            let packet = butch.topic().rekey(&mut rng, vec![rkmember!(&butch, admin_perms(), 0)]).unwrap();
            butch.tx(ts("2024-12-08T01:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&genesis]).unwrap();
        // create two branches
        let data1 = butch.tx_data(ts("2012-03-04T09:56:23Z"), AppData::new("get a job"), None, None);
        let data2 = butch.tx_data(ts("2012-03-04T09:56:59Z"), AppData::new("ZING"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data1, &data2]).unwrap();

        // rm data2 on branch2
        let rm1 = butch.tx(
            ts("2012-03-04T09:57:00Z"),
            Some(vec![data2.id().clone()]),
            Packet::DataUnset {
                transaction_ids: vec![data2.id().clone()],
            },
        );
        butch.push_tx(&id_lookup(&[&butch]), &[&rm1]).unwrap();

        // now merge our branches
        let data3 = butch.tx_data(ts("2012-03-04T09:57:23Z"), AppData::new("OOPS"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data3]).unwrap();

        assert_eq!(topicdata!(butch).unwrap(), vec![AppData::new("get a job"), AppData::new("OOPS")],);

        // now snapshot branch 2 (which has our removal)
        butch.snapshot(rm1.id()).unwrap();

        assert_eq!(topicdata!(butch).unwrap(), vec![AppData::new("get a job"), AppData::new("OOPS")],);

        // now snapshot branch 1.
        //
        // if snapshots are not discriminating when erasing prior snapshots, the next time we try
        // to run the DAG it should break
        butch.snapshot(data1.id()).unwrap();

        assert_eq!(topicdata!(butch).unwrap(), vec![AppData::new("get a job"), AppData::new("OOPS")],);
    }

    // tests a case where a snapshot is made in a previous point in a DAG chain of another
    // snapshot. in other words, trying to snapshot a subset of an existing snapshot. if this
    // happens we should return an error and refuse to snapshot, instead of attempting to move
    // forward with the snapshot.
    #[test]
    fn topic_snapshot_subset_of_existing_snapshot() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dogphone");
        let genesis = {
            let packet = butch.topic().rekey(&mut rng, vec![rkmember!(&butch, admin_perms(), 0)]).unwrap();
            butch.tx(ts("2024-12-08T01:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&genesis]).unwrap();
        let data1 = butch.tx_data(ts("2012-03-04T09:56:23Z"), AppData::new("get a job"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data1]).unwrap();
        let data2 = butch.tx_data(ts("2012-03-04T09:56:59Z"), AppData::new("ZING"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data2]).unwrap();

        butch.snapshot(data2.id()).unwrap();

        let res = butch.snapshot(data1.id());
        match res {
            Err(Error::SnapshotCollision(txid)) => {
                assert_eq!(&txid, data2.id());
            }
            _ => panic!("expected error, got Ok tsk tsk"),
        }
    }

    // scenario: peer1 adds data1, syncs it with peer2. peer2 adds data2, snapshots it with data1.
    // peer1 then later removes data1 and snapshots its removal, THEN syncs data2 from peer2.
    //
    // the snapshot from peer2 references data1 as an included snap, but the tx will be absent from
    // peer1 so if it tries to pull it from index it will fail. this test makes sure that in this
    // scenario, the snapshot expansion can happen even with data1 missing.
    #[test]
    fn topic_snapshot_rm_switcheroo() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dogphone");
        let mut dotty = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dupephone");
        let genesis = {
            let packet = butch
                .topic()
                .rekey(&mut rng, vec![rkmember!(&butch, admin_perms(), 0), rkmember!(&dotty, admin_perms(), 0)])
                .unwrap();
            butch.tx(ts("2012-03-04T09:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&genesis]).unwrap();
        dotty.push_tx(&id_lookup(&[&butch]), &[&genesis]).unwrap();
        // butch and dotty both get data1
        let data1 = butch.tx_data(ts("2012-03-04T09:56:23Z"), AppData::new("hi im butch"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data1]).unwrap();
        dotty.push_tx(&id_lookup(&[&butch]), &[&data1]).unwrap();

        // now, butch snapshots data1 into data2.
        let data2 = butch.tx_data(ts("2012-03-04T09:57:00Z"), AppData::new("pweased to make your acquaintance"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data2]).unwrap();
        butch.snapshot(data2.id()).unwrap();
        let data2_snapshotted = butch.topic().transactions().iter().find(|t| t.id() == data2.id()).unwrap().clone();

        // meanwhile, dotty removes data1, snapshots the removal, then syncs butch's snapshotted
        // data2 (which refs the now-removed data1)
        let rm1 = dotty.tx(
            ts("2012-03-04T09:57:40Z"),
            None,
            Packet::DataUnset {
                transaction_ids: vec![data1.id().clone()],
            },
        );
        dotty.push_tx(&id_lookup(&[&dotty]), &[&rm1]).unwrap();
        let data3 = dotty.tx_data(ts("2012-03-04T09:58:23Z"), AppData::new("nice knowing you, data1..."), None, None);
        dotty.push_tx(&id_lookup(&[&dotty]), &[&data3]).unwrap();
        dotty.snapshot(data3.id()).unwrap();
        dotty.push_tx(&id_lookup(&[&butch]), &[&data2_snapshotted]).unwrap();

        // if the bug exists, we'll see "get a job" in the list (which should be removed)
        assert_eq!(
            topicdata!(dotty).unwrap(),
            vec![
                AppData::new("pweased to make your acquaintance"),
                AppData::new("nice knowing you, data1...")
            ],
        );
    }

    // tests a case with two peers that have tx A. peer1 removes tx A and snapshots that removal
    // (so the removing tx and tx A are both erased). peer1 then syncs with peer2, who still has tx
    // A and has no removal transaction (but has a snapshot removing that tx). peer2 should, when
    // getting ordered transactions and grabbing data, NOT SEE tx A.
    #[test]
    fn topic_transaction_integrity_removed_snapshotted_node() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dogphone");
        let mut dotty = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dupephone");
        let genesis = {
            let packet = butch
                .topic()
                .rekey(&mut rng, vec![rkmember!(&butch, admin_perms(), 0), rkmember!(&dotty, admin_perms(), 0)])
                .unwrap();
            butch.tx(ts("2024-12-08T01:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&genesis]).unwrap();
        dotty.push_tx(&id_lookup(&[&butch]), &[&genesis]).unwrap();
        // butch and dotty both get data1
        let data1 = butch.tx_data(ts("2012-03-04T09:56:23Z"), AppData::new("get a job"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data1]).unwrap();
        dotty.push_tx(&id_lookup(&[&butch]), &[&data1]).unwrap();

        // dotty removes data1
        let rm1 = dotty.tx(
            ts("2012-03-04T09:57:00Z"),
            None,
            Packet::DataUnset {
                transaction_ids: vec![data1.id().clone()],
            },
        );
        dotty.push_tx(&id_lookup(&[&dotty]), &[&rm1]).unwrap();

        // dotty creates data2, a post-rm1 tx.
        let data2 = dotty.tx_data(ts("2012-03-04T09:58:23Z"), AppData::new("nice knowing you, data1..."), None, None);
        dotty.push_tx(&id_lookup(&[&dotty]), &[&data2]).unwrap();

        // this should remove data1 and rm1 from dotty
        let rm = dotty.snapshot(data2.id()).unwrap();
        assert_eq!(rm, BTreeSet::from([data1.id().clone(), rm1.id().clone()]));

        // grab the data2 transaction *with* the snapshot
        let data2_snapshotted = dotty.topic().transactions().iter().find(|t| t.id() == data2.id()).unwrap().clone();

        // push it onto Butch.
        butch.push_tx(&id_lookup(&[&dotty]), &[&data2_snapshotted]).unwrap();

        // if the bug exists, we'll see "get a job" in the list (which should be removed)
        assert_eq!(topicdata!(butch).unwrap(), vec![AppData::new("nice knowing you, data1...")],);
    }

    // Depending on snapshot ordering and branching, it was possible for a later unset to be
    // overridden by an earlier snapshot. we want to eliminate this possibility by creating the
    // conditions under which this can happen and test to make sure it doesn't.
    #[test]
    fn topic_snapshot_rm_override() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "butch");
        let mut dotty = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dotty");
        let genesis = {
            let packet = butch
                .topic()
                .rekey(&mut rng, vec![rkmember!(&butch, admin_perms(), 0), rkmember!(&dotty, admin_perms(), 0)])
                .unwrap();
            butch.tx(ts("2024-12-08T01:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&genesis]).unwrap();
        dotty.push_tx(&id_lookup(&[&butch]), &[&genesis]).unwrap();

        let data1 = butch.tx_data(ts("2024-12-08T02:00:00Z"), AppData::new("thsi is not a typo"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data1]).unwrap();
        dotty.push_tx(&id_lookup(&[&butch]), &[&data1]).unwrap();

        // now branch...
        //
        // dotty snapshots data1, butch removes the data packet both he and dotty both have access
        // to...
        let data2 = dotty.tx_data(ts("2024-12-08T03:00:00Z"), AppData::new("hi dupe dupe here"), None, None);
        dotty.push_tx(&id_lookup(&[&dotty]), &[&data2]).unwrap();
        dotty.snapshot(data2.id()).unwrap();
        let data2_snapshotted = dotty
            .topic()
            .transactions()
            .iter()
            .find(|tx| tx.id() == data2.id())
            .cloned()
            .unwrap();
        let rm1 = butch.tx(
            ts("2024-12-08T04:00:00Z"),
            None,
            Packet::DataUnset {
                transaction_ids: vec![data1.id().clone()],
            },
        );
        butch.push_tx(&id_lookup(&[&butch]), &[&rm1]).unwrap();

        // now, push dotty's snapshotted tx into butch
        butch.push_tx(&id_lookup(&[&dotty]), &[&data2_snapshotted]).unwrap();

        // merge the two branches
        //
        // we should now have:
        //
        //            ---->RM1**
        //           /          \
        // GEN-->DAT1            -->DAT3
        //           \          /
        //            ->DAT2*---
        //
        // *  [SNAP(DAT2, DAT1, GEN)]
        // ** [RM(DAT1)]
        //
        // So our DAT2 snapshot contains DAT1, and even though RM1 removes DAT1, DAT2's snapshot
        // has the potential to restore DAT1 to its former glory (which we DO NOT WANT).
        let data3 = butch.tx_data(ts("2024-12-08T05:00:00Z"), AppData::new("one tx to bring them in"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&data3]).unwrap();

        // make sure our assumptions are correct without our final snapshot
        assert_eq!(
            topicdata!(butch).unwrap(),
            vec![AppData::new("hi dupe dupe here"), AppData::new("one tx to bring them in")]
        );

        // now snapshot data3 on butch. this is where the bug happens.
        //
        // if the bug is present here, data1 should be present in the final data.
        // if the bug is fixed, data1 should be absent
        {
            let butch = butch.clone();
            butch.snapshot(data3.id()).unwrap();
            assert_eq!(
                topicdata!(butch).unwrap(),
                vec![AppData::new("hi dupe dupe here"), AppData::new("one tx to bring them in")]
            );
        }
    }

    // Tests a weird scenario where the state for a topic can get into a scenario where a tx would
    // have created its own state in the topic but we skip processing it because it's a removed
    // transaction, yet that tx branches off meaning the Dag.apply() fn will try to create that
    // tx's state into its upcoming branches, however the state doesn't exist.
    //
    // kind of a tongue twister, tbh. it took a shitload of time to reduce this down, so enjoy it.
    // savor it. there's some odd combination of branches, removes, and snapshots that make this
    // possible.
    //
    // the fix to this is to NOT skip recreated nodes, but instead skip validation and state
    // application for recreated nodes instead. this allows the state to be created when applying
    // the DAG but doesn't try to actually read the empty packet data.
    #[test]
    fn topic_branch_merge_branch_rm() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "butch");
        let mut dotty = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "dotty");
        // jerry gets nothing until the end
        let jerry = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "jerry! jerry!");

        // Scenario: (this is in D2 because I'm sick of making and remaking ASCII charts)
        //
        // E: E (snap)
        // F: F (rm C)
        // G: G (snap)
        // A -> B
        // A -> C
        // A -> D
        // B -> E
        // C -> E
        // C -> F
        // D -> F
        // F -> G
        // G -> H
        // E -> H

        let tx_a = {
            let packet = butch
                .topic()
                .rekey(
                    &mut rng,
                    vec![
                        rkmember!(&butch, admin_perms(), 0),
                        rkmember!(&dotty, admin_perms(), 0),
                        rkmember!(&jerry, vec![], 0),
                    ],
                )
                .unwrap();
            butch.tx(ts("2024-12-08T00:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_a]).unwrap();
        dotty.push_tx(&id_lookup(&[&butch]), &[&tx_a]).unwrap();

        let tx_b = dotty.tx_data(ts("2024-12-08T01:00:00Z"), AppData::new("B"), None, None);
        let tx_c = butch.tx_data(ts("2024-12-08T01:30:00Z"), AppData::new("C"), None, None);
        let tx_d = butch.tx_data(ts("2024-12-08T01:00:00Z"), AppData::new("D"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_c, &tx_d]).unwrap();
        dotty.push_tx(&id_lookup(&[&butch, &dotty]), &[&tx_b, &tx_c]).unwrap();

        let tx_e = dotty.tx_data(ts("2024-12-08T02:00:00Z"), AppData::new("E"), None, None);
        dotty.push_tx(&id_lookup(&[&dotty]), &[&tx_b, &tx_e]).unwrap();
        dotty.snapshot(tx_e.id()).unwrap();
        let tx_e_snapshotted = dotty
            .topic()
            .transactions()
            .iter()
            .find(|tx| tx.id() == tx_e.id())
            .cloned()
            .unwrap();

        let tx_f = butch.tx(
            ts("2024-12-08T02:00:00Z"),
            None,
            Packet::DataUnset {
                transaction_ids: vec![tx_c.id().clone()],
            },
        );
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_f]).unwrap();

        let tx_g = butch.tx_data(ts("2024-12-08T04:00:00Z"), AppData::new("G"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_g]).unwrap();
        butch.snapshot(tx_g.id()).unwrap();
        let tx_g_snapshotted = butch
            .topic()
            .transactions()
            .iter()
            .find(|tx| tx.id() == tx_g.id())
            .cloned()
            .unwrap();

        butch.push_tx(&id_lookup(&[&dotty]), &[&tx_b]).unwrap();
        butch.push_tx(&id_lookup(&[&dotty]), &[&tx_e_snapshotted]).unwrap();

        let tx_h = butch.tx_data(ts("2024-12-08T06:00:00Z"), AppData::new("H"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_h]).unwrap();
        jerry
            .push_tx(
                &id_lookup(&[&butch, &dotty]),
                &[
                    &tx_a.clone().into(),
                    &tx_b.clone().into(),
                    &tx_d.clone().into(),
                    &tx_e_snapshotted,
                    &tx_f.clone().into(),
                    &tx_g_snapshotted,
                    &tx_h.clone().into(),
                ],
            )
            .unwrap();
        let butch_nodes = {
            let topic = butch.topic();
            Topic::with_expanded_snapshots(&[topic.transactions()], |tx_mod, _, _| {
                let nodes_old = topic.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
                let nodes_mod = tx_mod.iter().map(|x| x.into()).collect::<Vec<_>>();
                let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_old, &nodes_mod]);
                Ok(dag.visited().iter().cloned().cloned().collect::<Vec<_>>())
            })
            .unwrap()
        };
        let jerry_nodes = {
            let topic = butch.topic();
            Topic::with_expanded_snapshots(&[topic.transactions()], |tx_mod, _, _| {
                let nodes_old = topic.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
                let nodes_mod = tx_mod.iter().map(|x| x.into()).collect::<Vec<_>>();
                let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_old, &nodes_mod]);
                Ok(dag.visited().iter().cloned().cloned().collect::<Vec<_>>())
            })
            .unwrap()
        };
        assert_eq!(
            butch_nodes.iter().collect::<Vec<_>>(),
            vec![
                tx_a.id(),
                tx_d.id(),
                tx_b.id(),
                tx_c.id(),
                tx_f.id(),
                tx_e.id(),
                tx_g.id(),
                tx_h.id()
            ]
        );
        assert_eq!(butch_nodes, jerry_nodes);
        let butch_data = topicdata!(butch).unwrap();
        let jerry_data = topicdata!(jerry).unwrap();
        assert_eq!(butch_data, ["D", "B", "E", "G", "H"].into_iter().map(|x| AppData::new(x)).collect::<Vec<_>>());
        assert_eq!(butch_data, jerry_data);
    }

    // Create two branches, snapshot both, merge them, snapshot the merge. This test is not built
    // off of any known failure cases, but should just pass because it's the right thing to do.
    #[test]
    fn topic_snapshot_snapshotted_branches() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "butch");

        // Scenario: (this is in D2 because I'm sick of making and remaking ASCII charts)
        //
        // B: B (snap)
        // C: C (snap)
        // D: D (snap)
        // A -> B
        // A -> C
        // C -> D
        // B -> D

        let tx_a = {
            let packet = butch.topic().rekey(&mut rng, vec![rkmember!(&butch, admin_perms(), 0)]).unwrap();
            butch.tx(ts("2024-12-08T00:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_a]).unwrap();

        let tx_b = butch.tx_data(ts("2024-12-08T01:00:00Z"), AppData::new("B"), None, None);
        let tx_c = butch.tx_data(ts("2024-12-08T01:30:00Z"), AppData::new("C"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_b, &tx_c]).unwrap();

        butch.snapshot(tx_b.id()).unwrap();
        butch.snapshot(tx_c.id()).unwrap();

        let tx_d = butch.tx_data(ts("2024-12-08T01:00:00Z"), AppData::new("D"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_d]).unwrap();

        butch.snapshot(tx_d.id()).unwrap();

        assert_eq!(topicdata!(butch).unwrap(), vec![AppData::new("B"), AppData::new("C"), AppData::new("D")]);
        {
            let topic = butch.topic();
            Topic::with_expanded_snapshots(&[topic.transactions()], |tx_mod, _, _| {
                let nodes_old = topic.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
                let nodes_mod = tx_mod.iter().map(|x| x.into()).collect::<Vec<_>>();
                let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_old, &nodes_mod]);
                assert_eq!(dag.visited(), &vec![tx_a.id(), tx_b.id(), tx_c.id(), tx_d.id()]);
                Ok(())
            })
            .unwrap();
        }
    }

    // What happens when we rm a snapshot? let's see if we can get it to break.
    #[test]
    fn topic_rm_snapshot() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "butch");

        let tx_a = {
            let packet = butch.topic().rekey(&mut rng, vec![rkmember!(&butch, admin_perms(), 0)]).unwrap();
            butch.tx(ts("2024-12-08T00:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_a]).unwrap();

        let tx_b = butch.tx_data(ts("2024-12-08T01:00:00Z"), AppData::new("B"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_b]).unwrap();
        let tx_c = butch.tx_data(ts("2024-12-08T01:30:00Z"), AppData::new("C"), None, None);
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_c]).unwrap();

        let tx_d = butch.tx(
            ts("2024-12-08T02:00:00Z"),
            None,
            Packet::DataUnset {
                transaction_ids: vec![tx_b.id().clone()],
            },
        );
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_d]).unwrap();

        // snapshot C after D has(the removal) has been pushed
        butch.snapshot(tx_c.id()).unwrap();

        {
            let topic = butch.topic();
            Topic::with_expanded_snapshots(&[topic.transactions()], |tx_mod, _, _| {
                let nodes_old = topic.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
                let nodes_mod = tx_mod.iter().map(|x| x.into()).collect::<Vec<_>>();
                let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_old, &nodes_mod]);
                assert_eq!(dag.visited(), &vec![tx_a.id(), tx_b.id(), tx_c.id(), tx_d.id()]);
                Ok(())
            })
            .unwrap();
        }

        assert_eq!(topicdata!(butch).unwrap(), vec![AppData::new("C")]);
    }

    // Create two branches. One has a data tx, the other an rm of that data, however the data is
    // NOT in the causal chain for the rm. This should not be allowed as a tx shuold only be
    // allowed to remove data within its causal chain.
    #[test]
    fn topic_rm_causal_chain() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"GOATS").unwrap().as_bytes().try_into().unwrap());
        let topic_id = TopicID::new(&mut rng);
        let mut butch = Peer::new_identity(&mut rng, &topic_id, "dupedupe123", "butch");

        let tx_a = {
            let packet = butch.topic().rekey(&mut rng, vec![rkmember!(&butch, admin_perms(), 0)]).unwrap();
            butch.tx(ts("2024-12-08T00:00:00Z"), None, packet)
        };
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_a]).unwrap();

        let tx_b = butch.tx_data(ts("2024-12-08T01:00:00Z"), AppData::new("B"), None, None);
        let tx_c = butch.tx(
            ts("2024-12-08T02:00:00Z"),
            None,
            Packet::DataUnset {
                transaction_ids: vec![tx_b.id().clone()],
            },
        );
        butch.push_tx(&id_lookup(&[&butch]), &[&tx_b]).unwrap();
        match butch.push_tx(&id_lookup(&[&butch]), &[&tx_c]) {
            Ok(_) => panic!("expecting causal unset error"),
            Err(Error::TransactionUnsetNotCausal(ref id1, ref id2)) => {
                assert_eq!(id1, tx_c.id());
                assert_eq!(id2, tx_b.id());
            }
            Err(e) => panic!("unexpected error: {:?}", e),
        }

        {
            let topic = butch.topic();
            Topic::with_expanded_snapshots(&[topic.transactions()], |tx_mod, _, _| {
                let nodes_old = topic.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
                let nodes_mod = tx_mod.iter().map(|x| x.into()).collect::<Vec<_>>();
                let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_old, &nodes_mod]);
                assert_eq!(dag.visited(), &vec![tx_a.id(), tx_b.id()]);
                Ok(())
            })
            .unwrap();
        }

        assert_eq!(topicdata!(butch).unwrap(), vec![AppData::new("B")]);
    }
}

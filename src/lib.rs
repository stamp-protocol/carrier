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
    identity::{keychain::AdminKey, IdentityID},
    util::{Binary, BinarySecret, BinaryVec, HashMapAsn1, SerdeBinary, Timestamp},
};
use std::collections::{HashMap, HashSet, VecDeque};
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
#[derive(Debug, Clone, AsnType, Encode, Decode, PartialEq, Eq, Hash)]
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
#[derive(Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
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
#[derive(Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
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
#[derive(Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
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
        recipient_crypto_pubkeys: &HashMap<&DeviceID, &CryptoKeypairPublic>,
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
            .collect::<Result<HashMap<_, _>>>()?
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
            .ok_or_else(|| Error::MemberMissingDevice(our_device_id.clone()))?;
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
}

impl SerdeBinary for TopicID {}

/// A data topic. This is a structure built from running a DAG of transactions in order. It tracks
/// the keys used to decrypt data contained in the topic, information on members of the topic and
/// their permissions within the topic, as well as the data contained within the topic itself.
#[derive(Debug, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Topic {
    /// A collection of secret seeds, in order of the DAG control packets, that allow deriving the
    /// topic's current (or past) secret key(s).
    secrets: Vec<SecretEntry>,
    /// This topic's keychain. This starts off empty and is populated as control packets come in
    /// that give access to various identities via their sync keys. A new entry is created whenever
    /// a member is added to or removed from the topic.
    keychain: HashMap<TransactionID, SecretKey>,
    /// Tracks who is a member of this topic and what their permissions are.
    members: HashMap<IdentityID, Member>,
    /// The actual transactions (control or data) in this topic.
    transactions: Vec<TopicTransaction>,
}

impl Topic {
    /// Create a new empty `Topic` object.
    pub fn new() -> Self {
        Self {
            secrets: Vec::new(),
            keychain: HashMap::new(),
            members: HashMap::new(),
            transactions: Vec::new(),
        }
    }

    /// Create a new `Topic` with the given transaction list.
    ///
    /// This takes a list of the full identities of the participants in the topic and a list of our
    /// crypto keypairs and a) verifies each transaction against the identity it came from and b)
    /// uses our crypto keypairs to decrypt any topic secrets in the control packets. This allows
    /// us to full build our topic state.
    pub fn new_from_transactions(
        transactions: &[TopicTransaction],
        identities: &HashMap<IdentityID, &Transactions>,
        our_master_key: &SecretKey,
        our_crypto_keypairs: &[&CryptoKeypair],
        our_identity_id: &IdentityID,
        our_device_id: &DeviceID,
    ) -> Result<Self> {
        let mut topic = Self::new();
        topic.push_transactions(transactions, identities, our_master_key, our_crypto_keypairs, our_identity_id, our_device_id)?;
        Ok(topic)
    }

    /// Check if the permissions on a transaction are valid.
    pub fn check_permissions(&self, permission: Permission, identity_id: &IdentityID, transaction_id: &TransactionID) -> Result<()> {
        let member = self
            .members()
            .get(identity_id)
            .ok_or_else(|| Error::PermissionCheckFailed(transaction_id.clone(), permission.clone()))?;
        if !member.permissions().contains(&permission) {
            Err(Error::PermissionCheckFailed(transaction_id.clone(), permission))?;
        }
        Ok(())
    }

    /// Allows staging a transaction (adding it to a clone of our current accepted transaction list
    /// and aplying its changes to see if they're valid). If everything checks out, we return a new
    /// topic with all transactions (including the pushed one) run in-order and the state
    /// reflecting these transactions.
    pub fn push_transactions(
        &mut self,
        transactions: &[TopicTransaction],
        identities: &HashMap<IdentityID, &Transactions>,
        our_master_key: &SecretKey,
        our_crypto_keypairs: &[&CryptoKeypair],
        our_identity_id: &IdentityID,
        our_device_id: &DeviceID,
    ) -> Result<bool> {
        let nodes_old = self.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
        let nodes_new = transactions.iter().map(|x| x.into()).collect::<Vec<_>>();

        // verify our transactions against their respective identities
        for trans in transactions {
            let trans_identity_id = trans.identity_id()?;
            let prev = trans.transaction().entry().previous_transactions();
            let identity_tx = identities
                .get(trans_identity_id)
                .ok_or_else(|| Error::IdentityMissing(trans_identity_id.clone()))?;
            let identity = identity_tx.build_identity_at_point_in_history(&prev)?;
            trans.transaction().verify(Some(&identity))?;
        }

        let visited: Vec<&TopicTransaction> = {
            let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes_old, &nodes_new]);
            if dag.missing().len() > 0 {
                Err(Error::TopicMissingTransactions(dag.missing().iter().cloned().cloned().collect::<Vec<_>>()))?;
            }
            dag.visited()
                .iter()
                .map(|tid| {
                    #[allow(suspicious_double_ref_op)]
                    dag.index()
                        .get(tid)
                        .map(|t| *t.node())
                        .ok_or_else(|| Error::TopicMissingTransactions(vec![tid.clone().clone()]))
                })
                .collect::<Result<Vec<_>>>()?
        };
        let mut found_control = false;
        let transactions_since_last_control = self
            .transactions()
            .iter()
            .rev()
            .filter(|trans| {
                let last_found_control = found_control;
                if let Ok(packet) = trans.get_packet() {
                    match packet {
                        Packet::MemberDevicesUpdate { .. } | Packet::MemberPermissionsChange { .. } | Packet::TopicRekey { .. } => {
                            found_control = true;
                        }
                        Packet::DataSet { .. } | Packet::DataUnset { .. } => {}
                    }
                }
                !last_found_control
            })
            .map(|t| t.id())
            .collect::<HashSet<_>>();
        let new_nodes_id_set = nodes_new.iter().map(|t| t.id()).collect::<HashSet<_>>();
        let new_nodes_prev_list = nodes_new
            .iter()
            .map(|t| t.node().previous_transactions().unwrap_or_else(|_| Vec::new()))
            .fold(Vec::new(), |mut acc, mut x| {
                acc.append(&mut x);
                acc
            });
        let mut new_nodes_only_reference_nodes_since_latest_control = true;
        for prev in new_nodes_prev_list {
            if !transactions_since_last_control.contains(prev) {
                new_nodes_only_reference_nodes_since_latest_control = false;
                break;
            }
        }
        // if our new nodes only reference nodes since the last control, we can happily just run
        // them on top of our current topic state.
        //
        // if our new nodes reference transactions BEFORE the latest control packet, we've got to
        // rebuild our entire state from the beginning.
        let apply = if new_nodes_only_reference_nodes_since_latest_control {
            let mut apply = Vec::with_capacity(nodes_new.len());
            for trans in visited {
                if new_nodes_id_set.contains(&trans.id()) {
                    apply.push(trans.clone());
                }
            }
            apply
        } else {
            visited.iter().cloned().cloned().collect::<Vec<_>>()
        };
        for trans in apply {
            self.apply_transaction(trans, our_master_key, our_crypto_keypairs, our_identity_id, our_device_id)?;
        }
        Ok(new_nodes_only_reference_nodes_since_latest_control)
    }

    /// Push a new [`TopicTransaction`] into this topic.
    fn apply_transaction<'a>(
        &'a mut self,
        transaction: TopicTransaction,
        our_master_key: &SecretKey,
        our_crypto_keypairs: &[&CryptoKeypair],
        our_identity_id: &IdentityID,
        our_device_id: &DeviceID,
    ) -> Result<&TopicTransaction> {
        let is_initial_packet = self.transactions().len() == 0;

        let packet = transaction.get_packet()?;
        let identity_id = transaction.identity_id()?;
        match packet {
            Packet::DataSet { .. } => {
                self.check_permissions(Permission::DataSet, &identity_id, transaction.id())?;
            }
            Packet::DataUnset { .. } => {
                self.check_permissions(Permission::DataUnset, &identity_id, transaction.id())?;
                // TODO:
                // - don't allow Unset on non-data packets
            }
            Packet::MemberDevicesUpdate { devices } => {
                self.check_permissions(Permission::MemberDevicesUpdate, &identity_id, transaction.id())?;
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
                self.check_permissions(Permission::MemberPermissionsChange, &identity_id, transaction.id())?;
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
                if !is_initial_packet {
                    self.check_permissions(Permission::TopicRekey, &identity_id, transaction.id())?;
                }
                // every rekey necessarily rebuilds the entire member set
                self.members_mut().clear();
                for member_rekey in members {
                    let member = if member_rekey.member().identity_id() == our_identity_id {
                        let (member, secrets) = member_rekey.open(our_master_key, our_crypto_keypairs, our_device_id, transaction.id())?;
                        for secret in secrets {
                            self.keychain_mut()
                                .insert(transaction.id().clone(), secret.secret().derive_secret_key()?);
                            self.secrets_mut().push(secret);
                        }
                        member
                    } else {
                        member_rekey.consume()
                    };
                    self.members.insert(member.identity_id().clone(), member);
                }
            }
        }
        self.transactions_mut().push(transaction);
        Ok(self.transactions().last().unwrap())
    }

    /// Find operations that are not referenced in any other operation's `previous` list.
    fn find_leaves<'a>(&'a self) -> Vec<&'a TransactionID> {
        let mut seen: HashSet<&TransactionID> = HashSet::new();
        for tx in self.transactions() {
            match tx.transaction().entry().body() {
                TransactionBody::ExtV1 { previous_transactions, .. } => {
                    for prev in previous_transactions {
                        seen.insert(prev);
                    }
                }
                _ => {}
            }
        }
        self.transactions()
            .iter()
            .filter_map(|t| if seen.get(t.id()).is_some() { None } else { Some(t.id()) })
            .collect::<Vec<_>>()
    }

    /// Create and push a transaction into this topic
    pub fn create_and_apply_transaction<T: Into<Timestamp> + Clone>(
        &mut self,
        master_key: &SecretKey,
        admin_key: &AdminKey,
        our_crypto_keypairs: &[&CryptoKeypair],
        our_identity_id: &IdentityID,
        our_device_id: &DeviceID,
        transactions: &Transactions,
        hash_with: &HashAlgo,
        now: T,
        topic_id: TopicID,
        packet: &Packet,
    ) -> Result<&TopicTransaction> {
        let packet_ser = packet.serialize_binary()?;
        let prev = self.find_leaves().into_iter().cloned().collect::<Vec<_>>();
        let ty = Vec::from(b"/stamp/sync/v1/packet");
        let topic_id_ser = topic_id.serialize_binary()?;
        let trans = transactions
            .ext(
                hash_with,
                now,
                prev,
                Some(ty.into()),
                Some([(b"topic_id".as_slice(), &topic_id_ser[..])]),
                packet_ser.into(),
            )?
            .sign(master_key, admin_key)?;
        let transaction = TopicTransaction::new(trans);
        self.apply_transaction(transaction, master_key, our_crypto_keypairs, our_identity_id, our_device_id)
    }

    /*
    /// Create and push a new operation into this topic.
    pub fn push_data<T: Into<Timestamp>>(
        &mut self,
        master_key: &SecretKey,
        sign_key: &AdminKeypair,
        now: T,
        op: OperationAction,
    ) -> Result<&TopicTransaction> {
        let prev = self.find_leaves().into_iter().cloned().collect();
        let op = TopicTransaction::new(master_key, sign_key, now, prev, op)?;
        self.operations.push(op);
        Ok(())
    }
    */

    /// Return this operation set as a [`Dag`], which provides information on the structure of the
    /// DAG itself (missing nodes, unvisited/unreachable nodes) and also allows
    /// [walking][Dag::walk].
    pub fn as_dag<'a>(transactions: &'a [TopicTransaction]) -> Dag<'a, TransactionID, TopicTransaction> {
        let nodes = transactions.iter().map(|x| x.into()).collect::<Vec<_>>();
        let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes]);
        dag
    }

    /// Return all operations in this set, ordered causally. This will return an error if we have
    /// any breaks in our causal chain (ie, missing transactions).
    pub fn order<'a>(&'a self) -> Result<Vec<&'a TopicTransaction>> {
        if self.transactions().len() == 0 {
            return Ok(Vec::new());
        }

        let mut tx_index: HashMap<&'a TransactionID, &'a TopicTransaction> = HashMap::new();
        let mut unsets: HashSet<TransactionID> = HashSet::new();
        let mut snapshots: HashMap<&'a TransactionID, Vec<&'a TransactionID>> = HashMap::new();

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

        let mut transactions_clone = self.transactions().clone();
        // a store for saving mods to operations that we can't do inline because of borrow checker
        // stuff
        let mut tx_set_prev: HashMap<TransactionID, Vec<TransactionID>> = HashMap::new();
        // any ops that we need to recreate. see comment below for deets.
        let mut recreate_unset_tx: Vec<(TransactionID, Timestamp)> = Vec::new();
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
        for tx in transactions_clone.iter_mut() {
            if let Some(mut snapshot) = tx.snapshot_mut().take() {
                let mut last_snap_transaction_id = None;
                for snap_op in snapshot.entry_mut().ordered_transactions_mut().drain(..) {
                    match &snap_op {
                        SnapshotOrderedOp::Remove { id, timestamp } => {
                            if !tx_index.contains_key(id) {
                                recreate_unset_tx.push((id.clone(), timestamp.clone()));
                            }
                        }
                        _ => {}
                    }
                    tx_set_prev.insert(snap_op.transaction_id().clone(), last_snap_transaction_id.unwrap_or_else(|| Vec::new()));
                    last_snap_transaction_id = Some(vec![snap_op.transaction_id().clone()]);
                }
            }
        }

        for (id, timestamp) in recreate_unset_tx {
            let trans = Transaction::create_raw_with_id(
                id,
                timestamp,
                vec![],
                TransactionBody::ExtV1 {
                    creator: TransactionID::from(Hash::new_blake3_from_bytes([0u8; 32])).into(),
                    ty: None,
                    previous_transactions: vec![],
                    context: None,
                    payload: Vec::new().into(),
                },
            );

            let recreated_op = TopicTransaction {
                transaction: trans,
                snapshot: None,
            };
            transactions_clone.push(recreated_op);
        }

        for tx in transactions_clone.iter_mut() {
            if let Some(prev) = tx_set_prev.remove(tx.id()) {
                let _ = tx.transaction_mut().try_mod_ext_previous_transaction(prev)?;
            }
        }

        let nodes = transactions_clone.iter().map(|x| x.into()).collect::<Vec<_>>();
        let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes]);
        if dag.missing().len() > 0 {
            Err(Error::TopicMissingTransactions(dag.missing().iter().cloned().cloned().collect::<Vec<_>>()))?;
        }
        let mut output: Vec<&'a TopicTransaction> = Vec::with_capacity(self.transactions().len() - unsets.len());
        for node_id in dag.visited() {
            #[allow(suspicious_double_ref_op)]
            let node = dag
                .index()
                .get(node_id)
                .ok_or_else(|| Error::TopicMissingTransactions(vec![node_id.clone().clone()]))?;
            if !node.node().is_unset()? && !unsets.contains(node.node().id()) {
                // NOTE: we can't push `node.node()` directly here because it's a clone of our
                // original list, so instead we pull from our dumb tx index.
                if let Some(tx) = tx_index.remove(node.node().id()) {
                    output.push(tx);
                }
            }
        }
        Ok(output)
    }

    /// Create a snapshot at a specific point in the operation chain.
    ///
    /// It's important to note that this operation doesn't snapshot all previous temporal
    /// operations, but rather just the ones that causally happened before the `replaces`
    /// operation. In other words, given:
    ///
    /// ```ignore
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
    pub fn snapshot(&mut self, master_key: &SecretKey, sign_key: &SignKeypair, replaces: &TransactionID) -> Result<Vec<TransactionID>> {
        let mut tx_index: HashMap<&TransactionID, &TopicTransaction> = HashMap::new();
        let mut unsets_in_causal_chain: HashSet<TransactionID> = HashSet::new();
        let mut in_existing_snapshot: HashSet<&TransactionID> = HashSet::new();
        let mut include_in_current_snapshot: HashSet<&TransactionID> = HashSet::new();
        let mut removed = Vec::new();

        // index our ops
        for tx in self.transactions() {
            tx_index.insert(tx.id(), tx);
        }

        // find and index all nodes causally preceding (and including) `replaces`.
        // this gives is a big fat list we can compare against when creating the final snapshot
        // list.
        let mut walk_queue = VecDeque::new();
        walk_queue.push_back(replaces);
        while let Some(id) = walk_queue.pop_front() {
            include_in_current_snapshot.insert(id);
            let tx = match tx_index.get(id) {
                Some(x) => x,
                None => continue,
            };
            for prev in tx.previous_transactions()? {
                walk_queue.push_back(prev);
            }
        }

        // sorry for all the loops
        for tx in self.transactions() {
            if let Some(snapshot) = tx.snapshot.as_ref() {
                for transaction_id in snapshot.all_transactions() {
                    in_existing_snapshot.insert(transaction_id);
                }
            }
            // only track unsets *if the unsetting node is in the snapshot's causal chain*
            if include_in_current_snapshot.contains(tx.id()) {
                for txid in tx.unset_ids()? {
                    unsets_in_causal_chain.insert(txid);
                }
            }
        }

        let nodes = self.transactions().iter().map(|x| x.into()).collect::<Vec<_>>();
        let dag: Dag<TransactionID, TopicTransaction> = Dag::from_nodes(&[&nodes]);

        // this list will replace `self.operations`
        let mut final_nodes: Vec<TopicTransaction> = Vec::with_capacity(self.transactions().len());
        // this is our final snapshot list
        let mut snapshot_ordered_operations: Vec<SnapshotOrderedOp> = Vec::new();
        let mut found_replacement_node = false;
        for node_id in dag.visited() {
            #[allow(suspicious_double_ref_op)]
            let node = dag
                .index()
                .get(node_id)
                .ok_or_else(|| Error::TopicMissingTransactions(vec![node_id.clone().clone()]))?;
            #[allow(suspicious_double_ref_op)]
            let mut tx: TopicTransaction = node.node().clone().clone();
            if !found_replacement_node {
                if include_in_current_snapshot.contains(tx.id()) {
                    // null out any previous snapshots in this causal chain.. at this point, their ordered
                    // operation list has been folded into our final list.
                    //
                    // one snapshot to rule them all.
                    if let Some(mut snapshot) = tx.snapshot_mut().take() {
                        // if this tx IS a snapshot, push its items, in order, onto the
                        // snapshot_ordered_operations list.
                        for save_op in snapshot.entry_mut().ordered_transactions_mut().drain(..) {
                            if save_op.is_keep() {
                                if let Some(tx) = tx_index.get(save_op.transaction_id()) {
                                    #[allow(suspicious_double_ref_op)]
                                    final_nodes.push(tx.clone().clone());
                                }
                            }
                            snapshot_ordered_operations.push(save_op);
                        }
                    } else if tx.id() != replaces && !in_existing_snapshot.contains(tx.id()) {
                        if tx.is_unset()? || unsets_in_causal_chain.contains(tx.id()) {
                            // if we still haven't found our replacement node and the current tx is
                            // eligible, push it onto the ordered tx list
                            let save = SnapshotOrderedOp::Remove {
                                id: tx.id().clone(),
                                timestamp: tx.timestamp().clone(),
                            };
                            snapshot_ordered_operations.push(save);
                            // notify the caller this tx can be removed.
                            removed.push(tx.id().clone());
                        } else {
                            // if we still haven't found our replacement node and the current tx is
                            // eligible, push it onto the ordered tx list
                            let save = SnapshotOrderedOp::Keep { id: tx.id().clone() };
                            snapshot_ordered_operations.push(save);
                            final_nodes.push(tx.clone());
                        }
                    }
                } else {
                    final_nodes.push(tx.clone());
                }
            } else {
                final_nodes.push(tx.clone());
            }

            if tx.id() == replaces {
                // this is our replacement node! create our snapshot.
                // NOTE: we specifically do NOT push the replacement node id onto the ordered_ops
                // list above because it's not a given it will run and its easier to do the
                // final push here instead.
                let save = SnapshotOrderedOp::Keep { id: tx.id().clone() };
                snapshot_ordered_operations.push(save);
                tx.snapshot = Some(Snapshot::new(master_key, sign_key, snapshot_ordered_operations.clone())?);
                found_replacement_node = true;
                final_nodes.push(tx.clone());
            }
        }
        if !found_replacement_node {
            Err(Error::SnapshotFailed)?;
        }
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
            HashAlgo, SecretKey,
        },
        dag::tx_chain,
        identity::keychain::ExtendKeypair,
    };
    use std::str::FromStr;

    fn create_fake_identity<R: RngCore + CryptoRng>(rng: &mut R, now: Timestamp) -> (SecretKey, Transactions, AdminKey) {
        let transactions = stamp_core::dag::Transactions::new();
        let master_key = stamp_core::crypto::base::SecretKey::new_xchacha20poly1305(rng).unwrap();
        let admin = stamp_core::identity::keychain::AdminKeypair::new_ed25519(rng, &master_key).unwrap();
        let admin_key = stamp_core::identity::keychain::AdminKey::new(admin, "Alpha", None);
        let policy = stamp_core::policy::Policy::new(
            vec![stamp_core::policy::Capability::Permissive],
            stamp_core::policy::MultisigPolicy::MOfN {
                must_have: 1,
                participants: vec![admin_key.key().clone().into()],
            },
        );
        let trans = transactions
            .create_identity(&HashAlgo::Blake3, now, vec![admin_key.clone()], vec![policy])
            .unwrap()
            .sign(&master_key, &admin_key)
            .unwrap();
        let transactions2 = transactions.push_transaction(trans).unwrap();
        (master_key, transactions2, admin_key)
    }

    #[allow(dead_code)]
    fn dump_tx(id_to_name: &HashMap<TransactionID, &'static str>, transactions: &[Transaction]) {
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
    fn ids_to_names(map: &HashMap<TransactionID, &'static str>, ops: &[&TransactionID]) -> Vec<&'static str> {
        ops.iter().map(|x| map.get(x).cloned().unwrap_or("??")).collect::<Vec<_>>()
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
        let identity_id = transactions.identity_id().unwrap();
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

    fn create_1p_topic(
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
        Topic::new_from_transactions(&transactions[..], &identity_map, master_key, &[&crypto_key], &identity_id, device_id).unwrap()
    }

    /*
    #[test]
    fn tx_chain_lol() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"get a job").unwrap().as_bytes().try_into().unwrap());
        let (master_key, transactions, admin_key) = create_fake_identity(&mut rng, Timestamp::from_str("2024-01-01T00:00:06Z").unwrap());
        let node_a_sync_sig = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let node_a_sync_crypto = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();

        let topic_id = TopicID::new(&mut rng);
        let topic_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
        let topic_secret = TopicSecret::new(&mut rng);
        let topic_seckey = topic_secret.derive_secret_key().unwrap();

        let members = vec![MemberRekey::seal(
            &mut rng,
            &node_a_sync_crypto.clone().into(),
            transactions.identity_id().unwrap(),
            &vec![SecretEntry::new_current_transaction(topic_secret.clone())],
        )];

        let packet_tx = |now, prev, packet| packet_body(&transactions, now, prev, &topic_id, &packet);
        let mut packet_tx_data = |id: &TransactionID, payload_plaintext: &[u8]| Packet::DataSet {
            key_ref: id.clone(),
            payload: topic_seckey.seal(&mut rng, payload_plaintext).unwrap(),
        };

        let (transactions, _name_to_op, id_to_name) = tx_chain! {
            [
                A = ("2024-01-03T00:01:01Z", |now, prev| packet_tx(now, prev, Packet::TopicRekey { members: vec![] }));
                B = ("2024-01-02T00:01:01Z", |now, prev| packet_tx(now, prev, packet_tx_data(A.id(), b"pardon me")));
                C = ("2024-01-02T00:01:01Z", |now, prev| packet_tx(now, prev, packet_tx_data(A.id(), b"may i use your bathroom??!")));
                D = ("2024-01-04T00:01:01Z", |now, prev| packet_tx(now, prev, Packet::DataUnset { transaction_ids: vec![C.id().clone()] }));
                E = ("2024-01-02T00:01:01Z", |now, prev| packet_tx(now, prev, packet_tx_data(A.id(), b"thank you!!")));
                F = ("2024-01-02T00:01:01Z", |now, prev| packet_tx(now, prev, packet_tx_data(A.id(), b"aughh!")));
                G = ("2024-01-04T00:01:01Z", |now, prev| packet_tx(now, prev, Packet::DataUnset { transaction_ids: vec![E.id().clone()] }));
            ],
            [
                [A] <- [B],
                [A, B] <- [C],
                [C] <- [D, E],
                [E] <- [F],
                [D, F] <- [G],
            ],
        };
        dump_tx(&id_to_name, &transactions[..]);
    }
    */

    #[test]
    fn order_topic() {
        let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"get a job").unwrap().as_bytes().try_into().unwrap());
        let (master_key, transactions, admin_key) = create_fake_identity(&mut rng, Timestamp::from_str("2024-01-01T00:00:06Z").unwrap());
        let node_a_sync_sig = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();
        let node_a_sync_crypto = CryptoKeypair::new_curve25519xchacha20poly1305(&mut rng, &master_key).unwrap();
        let node_a_device_id = DeviceID::new(&mut rng);

        let topic_id = TopicID::new(&mut rng);
        let topic_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
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
            &HashMap::from([(member.devices[0].id(), &node_a_sync_crypto.clone().into())]),
            vec![SecretEntry::new_current_transaction(topic_secret.clone())],
        )
        .unwrap();

        let (topic_tx, _name_to_op, id_to_name) = tx_chain! {
            [
                A = ("2024-01-03T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::TopicRekey { members: vec![node_a_member.clone()] }));
                B = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"pardon me"));
                C = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"may i use your bathroom??!"));
                D = ("2024-01-04T00:01:01Z", |now, prev| pkt.tx(now, prev, Packet::DataUnset { transaction_ids: vec![C.id().clone()] }));
                E = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"thank you!!"));
                F = ("2024-01-02T00:01:01Z", |now, prev| pkt.tx_data(now, prev, A.id(), b"aughh!"));
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
        let topic = create_1p_topic(&master_key, &admin_key, &transactions, &node_a_sync_crypto, member.devices()[0].id(), topic_tx);
        let ordered = topic
            .order()
            .unwrap()
            .into_iter()
            .map(|x| id_to_name.get(x.id()).unwrap())
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(ordered, vec!["A", "B", "F"]);
    }

    /*
    #[test]
    fn order_missing_tx() {
        todo!("check missing transactions during order() returns an error");
    }

        #[test]
        fn empty_dag() {
            let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"get a job").unwrap().as_bytes().try_into().unwrap());
            let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
            let sign_key = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();

            let (operations, _name_to_op, id_to_name) = op_chain! {
                &master_key, &sign_key,
                [
                    A = ("2024-01-03T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"get").unwrap()));
                    B = ("2024-01-02T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"a").unwrap()));
                    C = ("2024-01-03T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"job").unwrap()));
                    D = ("2024-01-04T00:01:01Z", OperationAction::Unset(C.id.clone()));
                    E = ("2024-01-08T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"lol").unwrap()));
                    F = ("2024-01-05T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"gfffft").unwrap()));
                    G = ("2024-01-06T00:01:01Z", OperationAction::Unset(E.id.clone()));
                ],
                [ ],
            };
            let ordered = operations
                .order(&sign_key.clone().into())
                .unwrap()
                .into_iter()
                .map(|x| id_to_name.get(x.id()).unwrap())
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(ordered, vec!["B", "A", "F"]);
        }

        #[test]
        fn snapshot_and_order() {
            let mut rng = rng::chacha20_seeded(
                Hash::new_blake3(b"i am sleeping under the stars with my dog. he is happy. so am i.")
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            );
            let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
            let sign_key = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();

            let (operations, name_to_op, id_to_name) = op_chain! {
                &master_key, &sign_key,
                [
                    A = ("2024-01-03T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"00").unwrap()));
                    B = ("2024-01-02T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"01").unwrap()));
                    C = ("2024-01-03T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"02").unwrap()));
                    D = ("2024-01-03T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"02.5").unwrap()));
                    E = ("2024-01-04T08:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"03").unwrap()));
                    F = ("2024-01-05T00:01:01Z", OperationAction::Unset(B.id.clone()));
                    G = ("2024-01-06T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"94").unwrap()));
                    H = ("2024-01-05T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"05").unwrap()));
                    I = ("2024-01-07T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"06").unwrap()));
                    J = ("2024-01-05T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"96").unwrap()));
                    K = ("2024-01-05T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"08").unwrap()));
                    L = ("2024-01-08T00:01:01Z", OperationAction::Unset(J.id.clone()));
                    M = ("2024-01-09T00:01:01Z", OperationAction::Set(master_key.seal(&mut rng, b"10").unwrap()));
                ],
                [
                    // branch1
                    [A, B] <- [C],
                    [C] <- [D, E],
                    [E] <- [F],

                    // branch2
                    [G] <- [H, I],
                    [H, I] <- [J],
                    [J] <- [K],

                    // merge the branches. let's get weird
                    [K, F] <- [L],
                    [L, D] <- [M],
                ],
            };
            macro_rules! assert_op {
                ($operations:expr, $id_to_name:expr, $idx:expr, $name:expr, $is_snapshot:expr) => {
                    assert_eq!($id_to_name.get($operations.operations()[$idx].id()), Some(&$name));
                    assert_eq!($operations.operations()[$idx].snapshot().is_some(), $is_snapshot);
                };
            }
            dump_tx(&id_to_name, &operations);
            assert_eq!(
                operations
                    .operations()
                    .iter()
                    .map(|x| id_to_name.get(x.id()).unwrap())
                    .cloned()
                    .collect::<Vec<_>>(),
                vec!["B", "A", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"],
            );
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
                let mut operations = operations.clone();
                let e_id = name_to_op.get("E").unwrap().id();
                operations.snapshot(&master_key, &sign_key, e_id).unwrap();
                assert_eq!(
                    operations
                        .operations()
                        .iter()
                        .map(|x| id_to_name.get(x.id()).unwrap())
                        .cloned()
                        .collect::<Vec<_>>(),
                    vec!["B", "A", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"],
                );
                assert_op!(operations, id_to_name, 0, "B", false);
                assert_op!(operations, id_to_name, 1, "A", false);
                assert_op!(operations, id_to_name, 2, "C", false);
                assert_op!(operations, id_to_name, 3, "D", false);
                assert_op!(operations, id_to_name, 4, "E", true);
                assert_eq!(
                    ids_to_names(&id_to_name, &operations.operations()[4].snapshot().as_ref().unwrap().active_transaction()),
                    vec!["B", "A", "C", "E"],
                );
                assert_op!(operations, id_to_name, 5, "F", false);
                assert_op!(operations, id_to_name, 6, "G", false);
                assert_op!(operations, id_to_name, 7, "H", false);
                assert_op!(operations, id_to_name, 8, "I", false);
                assert_op!(operations, id_to_name, 9, "J", false);
                assert_op!(operations, id_to_name, 10, "K", false);
                assert_op!(operations, id_to_name, 11, "L", false);
                assert_op!(operations, id_to_name, 12, "M", false);
                assert_eq!(operations.operations().get(13), None);
                let ordered = operations
                    .order(&sign_key.clone().into())
                    .unwrap()
                    .into_iter()
                    .map(|x| id_to_name.get(x.id()).unwrap())
                    .cloned()
                    .collect::<Vec<_>>();
                // NOTE: this is messed up now because E houses B, A, & C and injects them into
                // E's position instead of naturally sorting them into the DAG as they were previously.
                // this is because the snapshots only operate on the branch level
                assert_eq!(ordered, vec!["A", "C", "D", "E", "G", "H", "I", "K", "M"]);
            }
            {
                let mut operations = operations.clone();
                let h_id = name_to_op.get("J").unwrap().id();
                operations.snapshot(&master_key, &sign_key, h_id).unwrap();
                assert_op!(operations, id_to_name, 0, "B", false);
                assert_op!(operations, id_to_name, 1, "A", false);
                assert_op!(operations, id_to_name, 2, "C", false);
                assert_op!(operations, id_to_name, 3, "D", false);
                assert_op!(operations, id_to_name, 4, "E", false);
                assert_op!(operations, id_to_name, 5, "F", false);
                assert_op!(operations, id_to_name, 6, "G", false);
                assert_op!(operations, id_to_name, 7, "H", false);
                assert_op!(operations, id_to_name, 8, "I", false);
                assert_op!(operations, id_to_name, 9, "J", true);
                assert_eq!(
                    ids_to_names(&id_to_name, &operations.operations()[9].snapshot().as_ref().unwrap().active_transaction()),
                    vec!["G", "H", "I", "J"],
                );
                assert_op!(operations, id_to_name, 10, "K", false);
                assert_op!(operations, id_to_name, 11, "L", false);
                assert_op!(operations, id_to_name, 12, "M", false);
                assert_eq!(operations.operations().get(13), None);
                let ordered = operations
                    .order(&sign_key.clone().into())
                    .unwrap()
                    .into_iter()
                    .map(|x| id_to_name.get(x.id()).unwrap())
                    .cloned()
                    .collect::<Vec<_>>();
                assert_eq!(ordered, vec!["A", "C", "D", "E", "G", "H", "I", "K", "M"]);
            }
        }

        #[test]
        fn operation_serde() {
            let mut rng = rng::chacha20_seeded(
                Hash::new_blake3(b"i definitely do NOT eat worms ahaha XD XD")
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            );
            let master_key = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
            let sign_key = SignKeypair::new_ed25519(&mut rng, &master_key).unwrap();

            let action = OperationAction::Set(master_key.seal(&mut rng, b"TOP SECRET").unwrap());
            let op_a = TopicTransaction::new(
                &master_key,
                &sign_key,
                Timestamp::from_str("2020-01-01T00:00:01Z").unwrap(),
                vec![TransactionID::from(Hash::new_blake3(b"zing").unwrap())],
                action,
            )
            .unwrap();
            let op_a_ser = op_a.serialize_binary().unwrap();
            assert_eq!(
                op_a_ser,
                vec![
                    48, 129, 228, 160, 36, 160, 34, 4, 32, 13, 233, 152, 222, 240, 83, 110, 231, 147, 180, 109, 95, 150, 199, 228, 111, 102,
                    90, 171, 207, 171, 18, 38, 201, 51, 160, 207, 182, 245, 72, 172, 197, 161, 118, 48, 116, 160, 8, 2, 6, 1, 111, 94, 102,
                    235, 232, 161, 38, 48, 36, 160, 34, 4, 32, 48, 245, 97, 247, 85, 38, 122, 249, 77, 217, 180, 151, 79, 222, 158, 225, 23,
                    115, 176, 65, 95, 126, 7, 176, 130, 213, 116, 25, 25, 156, 82, 91, 162, 64, 160, 62, 48, 60, 160, 28, 160, 26, 4, 24, 196,
                    105, 153, 92, 242, 84, 209, 71, 242, 90, 64, 229, 117, 104, 128, 199, 42, 198, 173, 213, 146, 9, 135, 123, 161, 28, 4, 26,
                    153, 159, 221, 1, 168, 119, 95, 211, 141, 174, 62, 132, 131, 169, 191, 20, 219, 97, 165, 108, 52, 226, 43, 28, 237, 229,
                    162, 68, 160, 66, 4, 64, 117, 161, 229, 148, 251, 222, 139, 161, 124, 113, 84, 139, 76, 167, 237, 11, 232, 241, 64, 239,
                    66, 146, 103, 54, 0, 194, 66, 39, 69, 182, 32, 11, 98, 169, 149, 128, 132, 219, 218, 136, 107, 205, 80, 70, 166, 207, 41,
                    175, 157, 12, 113, 98, 234, 76, 20, 29, 149, 13, 234, 189, 154, 252, 113, 10
                ]
            );

            let op_b_ser = vec![
                48, 130, 1, 10, 160, 36, 160, 34, 4, 32, 181, 194, 24, 63, 6, 132, 108, 158, 161, 111, 229, 107, 220, 29, 215, 142, 101, 231,
                18, 237, 112, 194, 48, 221, 167, 45, 100, 220, 93, 151, 12, 132, 161, 129, 155, 48, 129, 152, 160, 8, 2, 6, 1, 111, 94, 102,
                235, 232, 161, 74, 48, 72, 160, 34, 4, 32, 48, 245, 97, 247, 85, 38, 122, 249, 77, 217, 180, 151, 79, 222, 158, 225, 23, 115,
                176, 65, 95, 126, 7, 176, 130, 213, 116, 25, 25, 156, 82, 91, 160, 34, 4, 32, 98, 136, 195, 216, 27, 32, 176, 102, 70, 179, 57,
                127, 6, 100, 245, 153, 255, 60, 74, 109, 60, 238, 9, 61, 174, 50, 93, 12, 210, 152, 97, 12, 162, 64, 160, 62, 48, 60, 160, 28,
                160, 26, 4, 24, 11, 133, 79, 196, 72, 22, 8, 243, 98, 172, 78, 198, 217, 165, 177, 176, 199, 131, 254, 163, 126, 155, 149, 172,
                161, 28, 4, 26, 26, 237, 64, 124, 198, 145, 81, 173, 203, 170, 37, 103, 48, 194, 143, 128, 83, 247, 17, 115, 170, 114, 54, 119,
                49, 250, 162, 68, 160, 66, 4, 64, 123, 77, 255, 54, 177, 240, 168, 205, 235, 132, 159, 2, 222, 117, 30, 35, 218, 250, 57, 96,
                201, 248, 77, 184, 87, 152, 78, 67, 159, 230, 252, 201, 220, 127, 245, 239, 63, 254, 220, 37, 142, 175, 65, 147, 96, 166, 129,
                26, 176, 193, 161, 182, 56, 224, 228, 23, 26, 238, 70, 191, 75, 183, 196, 6,
            ];
            let op_b = TopicTransaction::deserialize_binary(&op_b_ser).unwrap();
            assert_eq!(
                op_b.id().deref().as_bytes(),
                &vec![
                    181, 194, 24, 63, 6, 132, 108, 158, 161, 111, 229, 107, 220, 29, 215, 142, 101, 231, 18, 237, 112, 194, 48, 221, 167, 45,
                    100, 220, 93, 151, 12, 132
                ]
            );
            assert_eq!(op_b.entry().previous()[0], TransactionID::from(Hash::new_blake3(b"zing").unwrap()));
            assert_eq!(op_b.entry().previous()[1], TransactionID::from(Hash::new_blake3(b"zong").unwrap()));
            match op_b.entry().tx() {
                OperationAction::Set(sealed) => {
                    let mut rng = rng::chacha20_seeded(Hash::new_blake3(b"poopy butt").unwrap().as_bytes().try_into().unwrap());
                    let master_key2 = SecretKey::new_xchacha20poly1305(&mut rng).unwrap();
                    assert_eq!(master_key2.open(&sealed).unwrap(), b"TOP SECRET");
                }
                _ => panic!("bad dates"),
            }
        }
    */
}

#![doc = include_str!("../README.md")]

pub mod error;

use crate::error::{Error, Result};
use getset;
use rand::{CryptoRng, RngCore};
use rasn::{AsnType, Decode, Encode};
use stamp_core::{
    crypto::{
        base::{
            CryptoKeypair, CryptoKeypairPublic, Hash, Hmac, HmacKey, Sealed, SecretKey,
            SignKeypair, SignKeypairPublic, SignKeypairSignature,
        },
        message::Message,
    },
    dag::{Dag, DagNode, Transaction, TransactionID},
    identity::IdentityID,
    util::{base64_encode, Binary, BinarySecret, HashMapAsn1, SerdeBinary, Timestamp},
};

/// Defines a permission a member can have within a group.
#[derive(Clone, Debug, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum Permission {
    /// Allows changing member's permissions
    #[rasn(tag(explicit(0)))]
    MemberChangePermissions,
    /// Allows marking old packets as deleted. This doesn't fully remove the packet (as this might
    /// break the DAG chain), but does wipe out its data.
    #[rasn(tag(explicit(1)))]
    PacketDelete,
    /// Allows publishing messages on the topic
    #[rasn(tag(explicit(2)))]
    TopicPublish,
    /// Allows re-keying the topic without modifying membership
    #[rasn(tag(explicit(3)))]
    TopicRekey,
}

/// Information on a member of a topic.
#[derive(
    Clone, Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters,
)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Member {
    /// The Stamp identity id of the member
    #[rasn(tag(explicit(0)))]
    identity_id: IdentityID,
    /// An additive list of permissions this member can perform on the topic
    #[rasn(tag(explicit(1)))]
    permissions: Vec<Permission>,
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
    secret: BinarySecret<32>,
}

impl SerdeBinary for SecretEntry {}

/// Holds information about a cryptographic encryption key.
#[derive(Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct KeyPacketEntry {
    /// The identity id that owns the included public key
    #[rasn(tag(explicit(0)))]
    identity_id: IdentityID,
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
        pubkey: CryptoKeypairPublic,
    ) -> Result<Self> {
        let entry = KeyPacketEntry {
            identity_id,
            pubkey,
        };
        let entry_ser = entry.serialize_binary()?;
        let id = Hash::new_blake3(&entry_ser[..])?;
        let id_ser = id.serialize_binary()?;
        let signature = sign_keypair.sign(master_key, &id_ser[..])?;
        Ok(Self {
            id,
            entry,
            signature,
        })
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

/// A member re-key entry, allowing an existing member of a topic to get a new shared secret, or
/// allowing a new member to be initiated into the topic via a collection of past shared secrets
/// (along with the latest secret).
#[derive(Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct MemberRekey {
    /// The member's Stamp id
    #[rasn(tag(explicit(0)))]
    identity_id: IdentityID,
    /// Any secret(s) this member needs to read the topic's data, encrypted with the member's
    /// public sync key.
    #[rasn(tag(explicit(1)))]
    secrets: Vec<Message>,
}

impl MemberRekey {
    /// Create a new member reykey structure, encrypting the secrets passed in with the member's
    /// syncing cryptographic public key.
    pub fn seal<R: RngCore + CryptoRng>(
        rng: &mut R,
        recipient_crypto_pubkey: &CryptoKeypairPublic,
        identity_id: IdentityID,
        secrets: &Vec<SecretEntry>,
    ) -> Result<Self> {
        let secrets = secrets
            .iter()
            .map(|entry| {
                let ser = entry.serialize_binary()?;
                let enc = recipient_crypto_pubkey
                    .seal_anonymous(rng, &ser[..])
                    .map_err(|e| Error::Stamp(e))?;
                Ok(Message::Anonymous(enc.into()))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            identity_id,
            secrets,
        })
    }

    /// Open a rekey entry given the proper crypto secret key and master key.
    pub fn open(
        &self,
        recipient_master_key: &SecretKey,
        recipient_crypto_keypair: &CryptoKeypair,
    ) -> Result<Vec<SecretEntry>> {
        let entries = self
            .secrets
            .iter()
            .map(|msg| {
                let enc = match msg {
                    Message::Anonymous(enc) => enc,
                    _ => Err(Error::PacketInvalid)?,
                };
                let dec =
                    recipient_crypto_keypair.open_anonymous(recipient_master_key, &enc[..])?;
                let entry = SecretEntry::deserialize_binary(&dec[..])?;
                Ok(entry)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(entries)
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
    /// Marks a packet as no longer needed, allowing its garbage collection via a snapshot.
    DataUnset {
        /// The id of the packet we're unsetting
        #[rasn(tag(explicit(0)))]
        transaction_id: TransactionID,
    },
    /// Changes a member's permissions
    #[rasn(tag(explicit(1)))]
    MemberChangePermissions {
        /// The identity ID of the member we're editing
        #[rasn(tag(explicit(0)))]
        identity_id: IdentityID,
        /// The new permissions this member is getting.
        #[rasn(tag(explicit(1)))]
        permissions: Vec<Permission>,
    },
    /// Re-keys a topic, assigning a new topic key for future packets and potentially changing
    /// membership (adding/removing members).
    #[rasn(tag(explicit(2)))]
    TopicRekey {
        /// The new member list of this topic, complete with the secret(s) required to decrypt
        /// the data in the topic, encrypted for each member individually via their public sync
        /// key.
        #[rasn(tag(explicit(0)))]
        members: Vec<MemberRekey>,
    },
}

/// A data topic. This is a structure built from running a DAG of transactions in order. It tracks
/// the keys used to decrypt data contained in the topic, information on members of the topic and
/// their permissions within the topic, as well as the data contained within the topic itself.
#[derive(Debug, AsnType, Encode, Decode, getset::Getters, getset::MutGetters, getset::Setters)]
#[getset(get = "pub", get_mut = "pub(crate)", set = "pub(crate)")]
pub struct Topic {
    /// A collection of secret seeds, in order of the DAG control packets, that allow deriving the
    /// topic's current (or past) secret key(s).
    #[rasn(tag(explicit(0)))]
    secrets: Vec<SecretEntry>,
    /// This topic's keychain. This starts off empty and is populated as control packets come in
    /// that give access to various identities via their sync keys. A new entry is created whenever
    /// a member is added to or removed from the topic.
    #[rasn(tag(explicit(1)))]
    keychain: HashMapAsn1<TransactionID, SecretKey>,
    /// Tracks who is a member of this topic and what their permissions are.
    #[rasn(tag(explicit(2)))]
    members: HashMapAsn1<IdentityID, Member>,
    /// The actual packets (control or data) that make this topic.
    #[rasn(tag(explicit(3)))]
    packets: Vec<Transaction>,
}

impl Topic {
    /// create a new topic
    pub fn new() {}
}

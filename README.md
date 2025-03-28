# Carrier

A topic-based intra-or-inter-identity data syncing system based on Stamp identities, with the goal of building
shared datasets between multiple peers.


A [`Topic`] is an object shared via message exchange by one or more peers that describes:

- Who is a member of the topic
- What permissions each member in the topic has
- A set of messages, organized as a Merkle-DAG, with two main types:
  - Control messages, which update the topic itself, and can be read by anybody with read access to the topic.
  - Data messages, encrypted using keys synced by the Topic itself, that create a shared dataset amongst
    peers.

Topics are meant to have a number of full-access peers who can share data amongst each other, as well as any
number of read-only relay peers that can pass messages between peers but *cannot* read the data within the
topic. This allows securely syncing data between peers that are online at different times without explicitly
needing to trust an always-connected third peer.

Topics employ post-compromise security (as in, all members can be re-keyed in the event of a breach), but
*do not* implement forward secrecy as this is counterproductive to shared datasets (more on this later).

## Transactions

A topic consists of control transactions (which re-key the topic and update member devices/permissions) as well
as data transactions which allows setting data or removing data.

Control transactions are not encrypted by the protocol (although it is encouraged that they be encrypted at the
transport layer). Transactions that contain actual topic data *are* encrypted
using keys that exist within the control transactions. These data keys are encrypted individually for each
peer/device in the topic.

Transactions are effectively [`ExtV1`][stamp_core::dag::TransactionBody::ExtV1] transactions, signed by the
creating Stamp identity. These transactions form a Merkle-DAG, meaning each new transaction references the
transactions just before it, and is then hashed and signed. This forms a chain of transactions which cannot be
tampered with in any way, be it re-ordering or changing the content.

This means that given any set of transactions

- We can tell if past transactions are missing
- We can tell if transactions have been tampered with
- We can consistently order all transactions

The main downside to this particular setup is that our transaction list grows indefinitely. This is why we have
[snapshots](#snapshots).

### Transaction types

- `TopicRekey` - This is used when initiating the topic, whenever membership in the topic changes (members added,
  removed), or whenever one of the members' devices is compromised and the topic needs to be re-keyed going
  forward (post-compromise security). This transaction contains the members allowed to read the topic's data
  going forward, and also the topic's *new* secret value (randomly generated) which is encrypted individually
  for each member using either a one-use asymmetric keypair or their long-lived syncing asymmetric key. This
  secret value is used as a seed to generate the topic's symmetric encryption key used to unlock the data.
- `MemberPermissionsChange` - Allows assigning new permissions to a member in the topic (assuming the initiating
  identity has the permissions to change permissions lol). This happens without a rekey.
- `MemberDevicesUpdate` - Allows a member of a topic to update *their own devices* associated with their identity
  within the topic. This replaces all existing devices within the topic for that member.
- `DataSet` - "Sets" data within the topic, or in other words marks the data for inclusion. This includes a
  reference to the transaction ID in which the secret used to generate the key for the data was introduced (this
  would be a `TopicRekey` transaction) as well as the *sealed* (encrypted) data itself.
- `DataUnset` - Marks one or more `DataSet` transactions for unsetting (aka, removal). This does not actually
  remove the transactions marked for removal as that would break the DAG chain. The unset transactions, along
  with the transaction that did the unsetting, can be removed via snapshotting.

## Snapshots

Snapshots allow peers to delete any data transactions that have been marked for removal. For instance, let's say
a set of data transactions creates a user, then modifies that user's name, then updates the user's bio. Then that
user removes their account and so we create a remove transaction that deletes all the transactions that created
that user.

With our Merkle-DAG setup, all those transactions (create user, update name, update bio, remove user) are still
sitting there taking up space. A snapshot allows us to gather all the transactions that are still active but
remove any that have been marked for removal, and preserve their order. Because this modifies the actual DAG
itself, any peer that creates a snapshot must hash and sign the snapshot to prevent tampering.

This allows data compression of the DAG over time, allowing us to lean on the benefits of a Merkle-DAG but also
mitigate with one of its biggest problems: infinite growth.

## Read-only relay peers

Carrier offers two layers in its messaging system: data transactions which are encrypted using keys synced within
the topic, and plaintext control transactions which modify the topic itself. While the data transactions can only
be read by topic peers, the control transactions can be accessed by anyone on the transport layer the topic
is being communicated on. This allows a peer who is *not* a part of the topic to validate, store, and relay topic
transactions to other peers. This allows a secure sync without needing an always-on peer.

## Security

Non-control data in a topic is encrypted using a key generated from a shared secret. Whenever membership is changed
for a topic, a new secret is generated and securely shared with each current member. Sharing of the secret is done
using one of two methods:

1. Peers have a long-lived asymmetric keypair allowing secure sharing of secret data. This will generally live
under the Stamp identity within the keychain under the name `/stamp/sync/v1/crypto`.
1. Peers can (and should!) pre-generate and publish a set of "key packets" for each of their devices to a well-known
location. Key packets contain a public asymmetric encryption key while the secret key is retained by the peer (and
stored privately). Key packets are signed with the peer's signing key, which lives in their Stamp identity in the
keychain under the name `/stamp/sync/v1/sign`. Key packets are meant to be single-use: once the sharing peer
downloads a key packet, it should be removed from the location serving it. When a receiving peer receives a secret
via a key in a key packet it should delete the private key associated with that packet.

Key packets should be the preferred method of sharing secrets between peers. They reduce the damage done by a
compromised long-lived encryption key. Long-lived encryption keys can be used in the absence of key packets.
Long-lived keys are still secure, but have a somewhat higher risk of compromise.

### Post-compromise security

Carrier topics allow for post-compromise security. This means that in the event that a peer's device is compromised
and the communications are monitored thereafter, the topic can be completely re-keyed such that all *future* data
is secure from compromise. This does not protect the previous data from compromise but does protect future data.

Re-keying is done by issuing a `TopicRekey` transaction with the existing members retained (or the compromised
member removed to shame them).

### Forward secrecy

Carrier topics *do not* implement forward secrecy. Because topics are meant for creating shared datasets, it makes
sense that if a new member is added, all previous transactions are accessible to them. Because forward secrecy is
meant to protect past data from compromise, including it in the protocol would only add extra process around how
transactions are shared without adding any value.


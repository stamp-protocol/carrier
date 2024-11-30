# Carrier

A topic-based intra-or-inter-identity messaging system based on Stamp identities.

## Architecture

### Full and relay members

Full can encrypt/decrypt messages to other members

Relay 

### Topics

A topic is a UUID


## Dumping ground

- sync identity based on sync keypair within stamp identity.
- HMAC signatures? with shared secret, protects identity.
- different HMAC secret per identity?

---

# Topics

Every topic is a DAG, with previous tail packets getting signed by new packets.

Message classes:

- Control packets
  - Contains seed secret, and the secret is encrypted for each intended recipient
    via their public sync key. Any data created after the control packet must have its subkey
    encrypted via a key generated from the new seed. This allows any new data to be protected
    from participants removed from the topic even if they manage to intercept packets.
- Data packets
  - Each packet is encrypted by a randomly-generated key.
  - The key is stored with the packet, but encrypted by the *current* key of the topic it exists under
    - The packet thus can exist under multiple topics without needing to share a master key
  - The encrypted key references the transaction ID of the control packet it derived its key from

## Structure

Topic
  - packets: `Transaction::ExtV1[]`
    - payload: `Packet`

## Snapshots

Snapshots come in via another transaction type and are NOT part of the DAG


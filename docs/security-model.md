# Security model: vault items and organization keys

This document covers two protections against a malicious or compromised
server: binding vault items to their identity, and verifying the keys that
organization keys are shared with. The server stores ciphertext and public
keys; it never sees vault keys or plaintext.

## Vault item envelope (v2)

Every item written by a current client is encrypted with AES-256-GCM. The
additional authenticated data (AAD) is a canonical encoding of:

- format version (2)
- owner scope: `personal`, or the organization id for org items
- item id (chosen by the client before encrypting)
- item type
- item revision

The blob is `0x02 || revision (u64, big-endian) || ciphertext`, and `blobMac`
is empty. Decryption fails if the server moves a blob to another item, changes
its type, or edits the revision. The v1 HMAC is gone because GCM already
authenticates both ciphertext and AAD.

Personal items bind `personal`, not the user id. The personal vault key is
unique per account, so a blob moved to another account already fails to
decrypt. Vault ids are not bound, because items move between vaults without
being re-encrypted.

### Rollback protection

Each client stores the highest revision it has seen for each item and rejects
anything older. It also rejects a v1 blob for an item it has already seen as v2.
An edit first decrypts the blob it replaces and writes one past the higher of
that revision and the local record, so a device with no history never writes
a revision other devices would refuse. Revisions above 2^53 - 1 are refused.

The store is named by `trustStateId`, an HMAC under the account's vault MAC
key. The server cannot change that name (unlike user or vault ids it serves),
so it cannot point a device at an empty store.

Limits:

- A device with no history accepts whatever it is served first.
- The server can withhold newer revisions (freeze) or resurrect a deleted
  item; neither is detected.
- The record lives in local storage (browser localStorage, extension
  `storage.local`, `~/.nopwd` for the CLI). Clearing it resets protection on
  that device.

### Migration

v1 items still decrypt until the account is v2-only. Any write produces v2,
and the web app re-encrypts the remaining v1 items once per unlock. When no v1
item is left, it stores a v2-only marker on the server: an HMAC under the
vault MAC key, which the server cannot forge. Every client fetches it at
unlock, verifies it, and from then on refuses v1 blobs, including on fresh
devices. The server can withhold the marker (a fresh device then accepts v1
again) but cannot fake it, and a device that has seen it keeps the setting
locally. Account recovery re-encrypts every item into v2.

## Identity keys and key verification

Every user has an Ed25519 identity key. It signs the user's key bundle:

```
"nopwd-key-bundle-v1" || 0x00 || user id (16 bytes) || RSA-OAEP public key (SPKI)
```

The identity seed is derived with HKDF-SHA256 from the user's RSA private key,
so it needs no separate stored secret and survives password changes and
recovery. The server stores the identity public key and the bundle signature,
and accepts them only once per account.

On every unlock the client derives its RSA public key from its own private
key. If the server publishes a different RSA key or identity key for the
account, the client refuses to sign and shows an error. Accounts created
before identity keys existed publish one on their next unlock.

### Safety numbers and pinning

A safety number is six groups of five digits computed from the user id and
identity key (5,200 rounds of SHA-512). Members compare it out of band.

Clients never pin a key silently. A key is pinned only when the user says the
safety numbers match: when sending an invite, when accepting one, when first
opening an organization, or from the member list. Until then the key is not
used to share or accept organization keys. If a pinned key later changes, the
client refuses it and shows a "key changed" error. Pins are stored per device
under the same account-derived name as the revision store.

Invites to users who have not published an identity key yet are blocked
until that user signs in once.

### Signed organization-key wraps

When someone shares an organization key, they sign the wrap with their
identity key:

```
"nopwd-org-key-wrap-v2" || 0x00 || org id || key epoch (u32) || recipient id
  || signer id || len(role) || role || RSA-OAEP ciphertext of the org key
```

The server returns a chain of wraps for each member: the member's own wrap,
then the wrap of whoever signed it, and so on, ending with the owner's
self-signed wrap. Before an invite is accepted, and every time an
organization is opened, the client checks that:

- every wrap in the chain is signed by the recipient of the next one;
- every signer holds the owner or admin role in their own signed wrap;
- the chain ends with a self-signed wrap whose role is owner;
- every signer's identity key is pinned (the user confirmed the safety
  number; if not, the client lists the numbers to compare and uses nothing
  until the user confirms them);
- the key epoch is not below the highest epoch this device has accepted for
  the organization, so old wraps can't be replayed after a key change.

A server that wraps a key of its own choosing to a member cannot produce such
a chain without the identity key of someone the member confirmed.

Unsigned wraps (from before signing existed) are never used. The owner of
such an organization sees a re-sign action: after an explicit decision, the
client signs the owner's own wrap and re-wraps the key, signed, for every
member whose safety number the owner has confirmed. Other members of an
unsigned organization see an error asking them to have the owner re-sign.

### Org key rotation and member removal

Members are removed only as part of a key rotation, which the owner can also
start on its own. The owner's client:

1. generates a new org key at the current epoch + 1;
2. re-encrypts every org item, tombstones included, under the new key (v2
   envelope, org scope, next revision);
3. wraps the new key for every remaining member and signs each wrap; every
   remaining member's safety number must be confirmed first, so no member is
   silently left out;
4. uploads all of it in one request.

The server applies a rotation in one transaction. It locks the organization,
its members and its items, and checks three things: the new epoch is exactly
current + 1, the wraps cover exactly the remaining members, and the items
cover exactly the org's items (both compared by distinct id). If any check
fails, nothing changes. Wraps or re-signs for any epoch other than the
current one are refused, and a member cannot be removed any other way.

After a rotation, clients verify the new chain and record the new epoch,
after which wraps from the old epoch are refused. A client may keep the
retired key only to finish reads that were in flight; it never writes with
it. The removed member gets no new wrap, so items written after the rotation
are unreadable to them.

## Known limits and future work

- **RSA key rotation rotates the identity key.** The identity seed comes from
  the RSA private key, so rotating the RSA key changes the identity key, which
  every pin then reports as a changed key. Before RSA rotation ships, it needs
  a re-pin flow: the old identity key signs the new one, and clients accept a
  change that carries a valid signature from the pinned key.
- Pins, revision records and accepted org epochs are per device and are not
  synced.
- A removed member cannot read anything written after the rotation, but may
  still hold copies of items (and the old key) from before it.
- Item shares, the recovery blob and vault names do not use AAD binding. Each
  share has its own random key and each account has exactly one recovery
  blob, so swapping them gains nothing. Vault names were left out as low
  value.

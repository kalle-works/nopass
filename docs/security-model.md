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

Limits:

- A device with no history accepts whatever it is served first.
- The server can withhold newer revisions (freeze) or resurrect a deleted
  item; neither is detected.
- The record lives in local storage (browser localStorage, extension
  `storage.local`, `~/.nopwd` for the CLI). Clearing it resets protection on
  that device.

### Migration

v1 items still decrypt. Any write produces v2, and the web app re-encrypts
the remaining v1 items once per unlock. Account recovery re-encrypts every
item into v2.

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

Clients pin each user's identity key the first time they see it (trust on
first use). If a pinned key later changes, the client refuses to use it and
shows a "key changed" error. Pins are stored per device.

Invites to users who have not published an identity key yet are blocked
until that user signs in once.

### Signed organization-key wraps

When someone shares an organization key, they sign the wrap with their
identity key:

```
"nopwd-org-key-wrap-v1" || 0x00 || org id || recipient id || signer id
  || len(role) || role || RSA-OAEP ciphertext of the org key
```

Before accepting an invite, the invitee checks the inviter's signed bundle
against their pin, sees the inviter's safety number, and checks the wrap
signature. The same check runs every time an organization is opened. A server
that wraps a key of its own choosing to a member cannot forge the signature.
Organization creators sign their own wrap; the client picks the organization
id so it can be included in that signature.

Wraps made before signing existed have no signature. They are still accepted,
with a warning, so existing organizations keep working. An admin can replace
one by removing the member and inviting them again.

## Known limits and future work

- **RSA key rotation rotates the identity key.** The identity seed comes from
  the RSA private key, so rotating the RSA key changes the identity key, which
  every pin then reports as a changed key. Before RSA rotation ships, it needs
  a re-pin flow: the old identity key signs the new one, and clients accept a
  change that carries a valid signature from the pinned key.
- Pins and revision records are per device and are not synced.
- Item shares, the recovery blob and vault names do not use AAD binding. Each
  share has its own random key and each account has exactly one recovery
  blob, so swapping them gains nothing. Vault names were left out as low
  value.

# Cryptography specification v1.0.0-draft.3

- Status: Draft — independent cryptographic review and human approval required
- Decision set: DEC-001, 2026-08-19
- Cryptographic profile: `mesh-messenger-crypto/1`

This document selects standard constructions; it does not define a new primitive. Independent technical reviews of draft.1, draft.2, and draft.3 failed; the reports are preserved in `../adr/reviews/`. Later corrective work has not passed independent review. Implementation remains blocked until a human independent cryptographic reviewer accepts the composition and `vectors/v1/vectors.json`. The words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are normative.

## 1. Primitive registry

| Purpose | Exact primitive/profile | Authority |
|---|---|---|
| Hash and HMAC | SHA-256 and HMAC-SHA-256 | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final), [FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final) |
| Derivation | HKDF-SHA-256 | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) |
| Identity signatures | Ed25519, pure mode | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) |
| Structured signatures | COSE_Sign1, EdDSA algorithm `-8`, Ed25519 key | [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html), [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html) |
| Canonical structure | RFC 8949 deterministic CBOR | [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) |
| Group messaging | MLS 1.0 cipher suite `0x0001` | [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) |
| Bootstrap encryption | HPKE Base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM | [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) |
| Outer encryption | AES-128-GCM with 96-bit random IV | [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) |
| Recovery words | BIP-39 entropy/checksum and English list; mnemonic-to-seed step forbidden | [BIP-39](https://github.com/bitcoin/bips/blob/857a7debc6625a3dadbaecee1ee7b2ed5e8ada75/bip-0039.mediawiki), [pinned English list](https://github.com/bitcoin/bips/blob/857a7debc6625a3dadbaecee1ee7b2ed5e8ada75/bip-0039/english.txt) |
| Linux passphrase fallback | scrypt | [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html) |
| Opportunistic link channel | `Noise_NN_25519_ChaChaPoly_SHA256`, revision 34 | [Noise specification](https://noiseprotocol.org/noise.html) |

Do not substitute algorithms, truncate values beyond the rules below, enable MLS draft extensions, reuse MLS/HPKE key pairs, or introduce password stretching, signatures, or encryption outside this registry. Provider-specific serialization is forbidden on wire and in fixtures.

## 2. Exact domain-separation strings

Every string below is its exact UTF-8 byte sequence, without a trailing NUL, BOM, newline, Unicode normalization step, or implicit length prefix. Algorithms concatenate only fixed-length values or explicitly specified `I2OSP` integers, so no delimiter is omitted.

| Symbol | Exact text |
|---|---|
| `L_ROOT_SEED` | `mesh-messenger/v1/root-ed25519-seed` |
| `L_IDENTITY_ID` | `mesh-messenger/v1/identity-id` |
| `L_SAFETY_NUMBER` | `mesh-messenger/v1/safety-number` |
| `L_DEVICE_CERT_AAD` | `mesh-messenger/v1/device-certificate` |
| `L_CONTACT_BUNDLE_AAD` | `mesh-messenger/v1/contact-bundle` |
| `L_BOOTSTRAP_RECORD_AAD` | `mesh-messenger/v1/bootstrap-record` |
| `L_ROUTING_EXPORTER` | `mesh-messenger/v1/routing-secret` |
| `L_OUTER_EXPORTER` | `mesh-messenger/v1/outer-aead-key` |
| `L_ROUTING_TAG` | `mesh-messenger/v1/routing-tag` |
| `L_BOOTSTRAP_ROUTING_TAG` | `mesh-messenger/v1/bootstrap-routing-tag` |
| `L_HPKE_INFO` | `mesh-messenger/v1/bootstrap-hpke` |
| `L_POW` | `mesh-messenger/v1/pow` |
| `L_NOISE_PROLOGUE` | `mesh-messenger/v1/noise-sync` |
| `L_DATABASE_WRAP_AAD` | `mesh-messenger/v1/database-key-wrap` |
| `L_STORAGE_WRAP_AAD` | `mesh-messenger/v1/linux-storage-wrap` |

`I2OSP(x, n)` means the RFC 8017 unsigned, fixed-width, big-endian encoding and fails if `x` does not fit.

## 3. Entropy and randomness

All production randomness MUST come directly from the operating-system CSPRNG through a vetted Rust crate backed by `getrandom`; partial reads and RNG errors fail closed. The deterministic fixture RNG MUST be impossible to construct in a production build.

| Value | Size | Additional rule |
|---|---:|---|
| Recovery entropy | 32 bytes | independently generated; all-zero rejected |
| Device Ed25519 seed | 32 bytes | independently generated; never derived from root; all-zero rejected |
| Device instance ID | 16 bytes | independently generated; all-zero rejected |
| MLS group ID | 32 bytes | independently generated; all-zero rejected |
| Event/envelope/bundle/invitation/session ID | 16 bytes | independently generated; all-zero rejected |
| HPKE recipient private key | 32 bytes | independently generated and clamped by X25519 implementation; all-zero input rejected |
| HPKE ephemeral private key | 32 bytes | fresh per encryption and clamped by implementation; all-zero input rejected |
| Rendezvous secret | 32 bytes | independently generated; all-zero rejected |
| SQLCipher database key | 32 bytes | independently generated; all-zero rejected |
| AES-GCM nonce | 12 bytes | fresh random, all-zero rejected, uniqueness enforced as below |
| CBOR/envelope/frame padding | required remainder | fresh random bytes; not reused as key material |

Every fixed-length security-critical random input in the table except padding MUST be checked before use. An all-zero result or a generated-ID collision is discarded; generation permits at most eight draws in total and then fails closed without creating partial state. A library-generated X25519 key MUST satisfy the same eight-draw bound and its public key MUST also be nonzero. Random IDs provide 128-bit targeted-guess/preimage cost; their generic birthday-collision strength is approximately 64 bits, with accidental collision probability approximately `n^2 / 2^129` after `n` draws. Random bytes MUST never be logged, exported in diagnostics, or silently replaced with timestamps/counters. The all-zero recovery value is retained only as a negative fixture; positive vectors use nonzero entropy.

## 4. Recovery root and identity

### 4.1 Mnemonic encoding

Encode the 32 recovery bytes using BIP-39's 256-bit entropy plus eight checksum bits and the pinned 2,048-word English list, yielding exactly 24 lowercase words separated by one ASCII space. The BIP-39 PBKDF2 mnemonic-to-seed procedure MUST NOT be called. On input, apply BIP-39 NFKD word handling, require exactly 24 full list entries and a valid checksum, and recover exactly the original 32 bytes.

The setup UI MUST show the phrase once, clear it, and require re-entry of all 24 words in order. Only after a byte-exact round trip and successful first contact-bundle creation may setup complete. Then recovery entropy, phrase strings, root seed, and root private-key objects MUST be zeroized and removed from all persistent storage. Screenshots, clipboard copy, keyboard learning, analytics, and OS backup MUST be disabled where platform APIs permit; platform limits must be documented to the user.

### 4.2 Root derivation

```text
prk          = HKDF-Extract-SHA256(salt = empty, IKM = recovery_entropy[32])
root_seed    = HKDF-Expand-SHA256(prk, info = UTF8(L_ROOT_SEED), L = 32)
root_public  = Ed25519.PublicKey(root_seed)
identity_id  = first16(SHA-256(UTF8(L_IDENTITY_ID) || root_public[32]))
```

`root_seed` is the RFC 8032 32-byte Ed25519 private seed, not a scalar supplied directly. The root key signs device certificates only. It MUST NOT sign application messages, act as an MLS leaf key, derive device/MLS/database keys, or remain after confirmation/recovery.

## 5. Device certificates and canonical signatures

### 5.1 COSE profile

Every application COSE_Sign1 object uses protected header `{1: -8}` (canonical bytes `a10127`), an empty unprotected map, an attached payload, and a 64-byte Ed25519 signature. No other protected/unprotected header is accepted. The standard COSE `Sig_structure` is:

```text
["Signature1", protected_header_bstr, external_aad_bstr, payload_bstr]
```

encoded with deterministic CBOR. The external AAD is the exact label named for the object. Verification MUST re-encode the payload canonically and require byte equality before signature verification.

### 5.2 Device certificate

The root-signed payload is this integer-key CBOR map:

```text
{
  0: 1,                       / certificate version /
  1: identity_id,             / bstr .size 16 /
  2: device_instance_id,      / bstr .size 16 /
  3: device_signing_public,   / bstr .size 32, Ed25519 /
  4: issued_minute,           / uint32, informational /
  5: predecessor_hash,        / null or bstr .size 32 /
  6: 1                        / capabilities: bit 0 = v1 MLS /
}
```

Sign with the root key and external AAD `L_DEVICE_CERT_AAD`. `predecessor_hash`, when the prior public certificate is available during planned replacement, is SHA-256 of its complete COSE bytes; otherwise it is null. It is an audit hint, not an ordering authority. A certificate has no clock-based expiry because offline peers cannot reliably validate one; its issue time is display/audit data.

There is deliberately no numeric global generation counter: recovery from the 24 words has no trustworthy knowledge of counters stored only on a lost device. “One active device” therefore means one explicitly accepted `device_instance_id` per identity in each contact record and one leaf per identity in each MLS group. A root signature proves common identity authority but never activates or orders a replacement by itself.

### 5.3 MLS credential bytes

OpenMLS MUST use a BasicCredential whose identity byte string is the deterministic CBOR encoding of:

```text
{0: 1, 1: root_public, 2: device_certificate_cose}
```

The MLS CredentialWithKey signature key MUST byte-equal the certificate's Ed25519 public key. Validation recomputes `identity_id` from `root_public`, verifies the root COSE signature, checks all exact sizes/capabilities, and checks the locally accepted device instance. Self-signed or unknown-root credentials are not implicitly trusted.

## 6. Contact bundle and bootstrap

### 6.1 Contact bundle

A contact bundle payload is:

```text
{
  0: 1,                     / bundle version /
  1: bundle_id,             / bstr .size 16 /
  2: issued_minute,         / uint32 /
  3: expires_minute,        / issued + 10080 exactly /
  4: root_public,           / bstr .size 32 /
  5: device_certificate,    / bstr, complete root COSE_Sign1 /
  6: mls_key_package,       / bstr, complete TLS serialization /
  7: bootstrap_hpke_public, / bstr .size 32, X25519 /
  8: rendezvous_secret      / bstr .size 32 /
}
```

The active device signs it with COSE_Sign1 and external AAD `L_CONTACT_BUNDLE_AAD`. The complete COSE object is capped at 2,048 bytes. Its KeyPackage MUST use suite `0x0001`, the exact MLS credential above, a one-time init key independent of the bootstrap HPKE key, `not_before = issued_minute * 60`, and `not_after = expires_minute * 60`, rejecting arithmetic overflow. The private KeyPackage/init/HPKE material and bundle ID are committed atomically in the private database before displaying the QR.

At scan time let `W` be local wall-clock Unix minutes and `M` a monotonic instant. Validation order is sizes/canonical CBOR and TTL arithmetic, `issued_minute <= W + 10`, `expires_minute = issued_minute + 10,080`, `expires_minute + 10 > W`, identity-ID recomputation, root certificate signature, device-key match, outer device signature, KeyPackage suite/credential/exact lifetime/signature, then explicit full safety-number confirmation. Set the immutable local bundle deadline to `M + min(10,080, max(0, expires_minute + 10 - W))` minutes. Later wall changes cannot extend it. Expiry deletes its private init/HPKE material; wall time never makes an unknown root trusted.

First contact is deliberately bilateral. Both people display independently generated bundles, scan the other's card, compare the same full safety number out of band, and durably accept the other's active device before any network bootstrap is valid. For a direct chat, the side with the lexicographically smaller unsigned `identity_id` is the sole inviter; the other side waits. This deterministic role prevents two simultaneous direct groups. A one-sided scan may store a pending card for display but is not an accepted contact and cannot authorize a bootstrap. Group owners likewise establish bilateral contact with an invitee before adding that invitee.

### 6.2 Bootstrap HPKE and signed record

Use HPKE Base mode (`mode=0`) with KEM ID `0x0020`, KDF ID `0x0001`, AEAD ID `0x0001`, `info = UTF8(L_HPKE_INFO)`, and the normalized 80-byte envelope header as AAD. HPKE creates one message at sequence number zero. The 32-byte encapsulated key is serialized before the ciphertext as specified in `PROTOCOL_V1.md`. Do not use HPKE authenticated/PSK modes and do not reuse its X25519 keys for MLS.

The HPKE plaintext body is a COSE_Sign1 object signed by the inviter device with external AAD `L_BOOTSTRAP_RECORD_AAD`. Its payload is:

```text
{
  0: 1,                    / record version /
  1: recipient_bundle_id, / bstr .size 16 /
  2: welcome,             / bstr, TLS-serialized MLS Welcome /
  3: inviter_credential,  / bstr, deterministic MLS credential CBOR /
  4: conversation_kind,   / 1 direct, 2 private group /
  5: owner_identity_id,   / null for direct; bstr .size 16 for group /
  6: invitation_id        / bstr .size 16 /
}
```

After HPKE authentication, validate that the signed inviter credential is an already accepted bilateral contact, the COSE key equals its active device key, the Welcome's signed GroupInfo/Commit is consistent with that credential, the Welcome is encrypted to the exact one-time KeyPackage committed by `recipient_bundle_id`, and group ownership/count rules hold. For a direct chat, require the inviter's `identity_id` to be lexicographically smaller than the recipient's. Only then atomically mark the recipient bundle consumed and join the group. Invalid unauthenticated traffic cannot consume a bundle. A concurrent second valid use loses the transaction race and is rejected. Bundle private keys are deleted on consumption or expiry.

The pinned conformance harness in `vectors/v1/openmls_harness/` generated a positive 16-member application-bound group at the pinned OpenMLS revision using a fresh nonzero provider-random 32-byte group ID. Four conforming runs produced stable semantic results and lengths while their random IDs, ciphertexts, keys, signatures, and hashes differed. The frozen run measured a 474-byte recipient KeyPackage, a 6,625-byte complete TLS `MlsMessage` Welcome with the required ratchet tree, a 6,965-byte signed bootstrap COSE object, and a 7,097-byte minimum complete HPKE envelope before padding. The smallest fitting class remains 8,192 bytes and has 1,095 bytes of padding headroom. These figures are derived from the frozen generated bytes, not estimated. The checked fixture, harness, dependency graph, repeated-run assertion, and exact commands are retained beside the vectors. Bootstrap envelopes above the 1,536-byte LoRa ceiling are BLE/WLAN-only.

For bootstrap routing:

```text
bootstrap_tag = first16(HMAC-SHA256(
  rendezvous_secret,
  UTF8(L_BOOTSTRAP_ROUTING_TAG) || I2OSP(slot, 8)
))
```

The slot/overlap rules are those in `PROTOCOL_V1.md`. Possession of a photographed contact card permits targeting and denial attempts until expiry; it does not authenticate an inviter or decrypt replies.

## 7. MLS profile

Use OpenMLS tag `openmls-v0.8.1` at immutable revision `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6` with the `openmls_libcrux_crypto` provider from the same workspace revision. Do not substitute the RustCrypto provider or implement a custom crypto provider. Only cipher suite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`) is accepted. Draft-extension features, external commits, custom proposals, custom credentials, and custom MLS extensions are disabled.

The exact group configuration is:

| Setting | v1 value |
|---|---|
| Wire-format policy | encrypted PrivateMessage for application and post-join handshake traffic |
| Ratchet-tree extension | enabled and included with Welcome |
| `max_past_epochs` | 3 |
| Sender-ratchet out-of-order tolerance | 100 |
| Sender-ratchet maximum forward distance | 1,000 |
| MLS padding | zero bytes; outer envelope supplies padding |
| KeyPackage lifetime | 10,080 minutes |
| Group ID | fresh random 32 bytes |
| Direct member count | exactly 2 |
| Private-group member count | 2–16 |

At each epoch transition, retain OpenMLS state plus the application exporter outputs in section 8 for the new current epoch and exactly three past epochs. Delete the oldest state and exporter outputs transactionally when a fourth prior epoch would be retained. No seven-day exception exists. Reaching forward-distance/tolerance limits rejects the message and moves that conversation to `REPAIR_REQUIRED` under section 11.5; limits are never raised from peer input.

For a private group, the immutable group owner is an `identity_id` recorded from the group bootstrap. A membership-changing Commit is accepted only if its authenticated committer credential has that identity and accepted device instance. The owner MUST remain represented by exactly one leaf after the Commit; planned owner replacement is permitted only as one remove/add Commit whose resulting owner credential has the same `identity_id` and the newly accepted device instance. A v1 private group MUST contain 2–16 members and at most one leaf for each identity after a Commit.

A direct chat has a null owner and exactly two fixed member identities. After bootstrap, every Add, Remove, PreSharedKey, ReInit, external, or other membership-changing Proposal or Commit is rejected as `POLICY_REJECT`, regardless of sender. A direct member may send only a valid leaf Update for its own leaf. Direct repair or device replacement always creates a fresh two-member group through the bilateral bootstrap procedure; it never changes membership in the active direct group.

## 8. MLS-derived outer protection

For every retained epoch, derive one group routing secret with empty context and one outer key for every member leaf in that epoch's authenticated roster:

```text
routing_secret[32]          = MLS-Exporter(L_ROUTING_EXPORTER, context = empty, length = 32)
sender_context[4]           = I2OSP(sender_leaf_index, 4)
sender_outer_key[16]        = MLS-Exporter(L_OUTER_EXPORTER, context = sender_context, length = 16)
```

The label arguments are the UTF-8 strings in section 2. `sender_leaf_index` is the authenticated MLS leaf index in the roster snapshot for that epoch. The sender uses only its own context. These outputs and the exact roster snapshot are stored encrypted with their epoch and deleted with that epoch. They MUST NOT be used as MLS input secrets or exposed through FFI.

For an envelope slot:

```text
routing_tag = first16(HMAC-SHA256(
  routing_secret,
  UTF8(L_ROUTING_TAG) || I2OSP(slot, 8)
))
```

Define `MAX_SEALS = 2^24` for each `(group_id, epoch, sender_leaf_index)`. Its durable `seal_count` is the number of committed outer ciphertexts created under that sender key. Before any encryption the implementation MUST atomically reserve a unique `(group_id, epoch, sender_leaf_index, nonce)` and increment that same counter; a collision is retried within the section 3 eight-draw total. Decryption never writes a nonce reservation.

Ordinary application, receipt, replacement-notice, and non-rollover handshake envelopes are permitted only while `seal_count < MAX_SEALS - 1`. The ordinary seal that changes the count from `MAX_SEALS - 2` to `MAX_SEALS - 1` is permitted; after its commit the sender enters `ROLLOVER_REQUIRED` and MUST reject every new ordinary seal. The one remaining old-key seal is reserved exclusively for one MLS self-Update Commit envelope. It MUST NOT be spent by application traffic, padding retries, replacement envelopes, or a second Update attempt.

From `ROLLOVER_REQUIRED`, creation of that Update is one private-database transaction with no externally visible bytes before commit. Using the current old-epoch MLS state and old sender key, the transaction MUST:

1. generate and reserve the final fresh envelope ID and nonce, and stage `seal_count = MAX_SEALS`;
2. create exactly one MLS self-Update Commit, retain its serialized old-epoch PrivateMessage, and stage the OpenMLS pending state;
3. seal that serialized Commit once under the old epoch/sender key as a traffic-class-2 envelope and store its complete immutable bytes in a durable outbound-retry record;
4. merge the same pending Commit locally, stage the resulting new current epoch while retaining the old epoch under the three-past-epoch rule, derive the new epoch roster/routing secret/per-sender outer keys, and initialize the local new-epoch sender `seal_count` to zero; and
5. commit the nonce reservation, final old counter, immutable envelope, pending/merged MLS state, exporters, and new counter atomically.

Any error or crash before that transaction commits consumes no ID, nonce, seal, or MLS transition and recovers `ROLLOVER_REQUIRED` at `MAX_SEALS - 1`. A crash after commit recovers the merged new epoch and the exact stored old-epoch Update envelope. Every retry transmits those bytes byte-for-byte and performs no encryption or counter change. At `seal_count = MAX_SEALS`, every attempt to create another old-key ciphertext, including recreating the Update, fails closed; transmitting the already stored ciphertext is not a new seal.

Recipients first authenticate the outer envelope under the old epoch/sender context, then authenticate and process the enclosed old-epoch MLS self-Update Commit, and only then transition to the new epoch and derive its exporters. A sender may create ordinary new-epoch envelopes after the rollover transaction commits; the transport scheduler MUST offer the stored Update first, but correctness MUST tolerate reordering. After any valid epoch transition, the private post-commit processor rescans still-unexpired opaque relay rows without changing their relay metadata so an already stored new-epoch envelope can be processed. A valid incoming MLS epoch transition received while local state is `ROLLOVER_REQUIRED` may supersede the local rollover: atomically apply the incoming transition, leave the unused old counter at `MAX_SEALS - 1`, permanently disable old-epoch encryption, initialize the new-epoch counter to zero, and clear the requirement. Peer input never raises, lowers, or resets a counter within an epoch.

After a routing-tag match, a receiver enumerates the authenticated member leaf indices for that exact retained epoch in ascending order and performs at most one AES-GCM trial per leaf. A routing-tag collision may yield multiple local epoch candidates, but the receiver MUST perform at most 64 total sender-key trials across all candidates; more candidates fail closed before any trial. Zero or more than one successful outer authentication is `AUTH_FAILED`. For exactly one successful key context, the receiver processes the complete MLS message and MUST require its authenticated MLS epoch and sender leaf index to equal the selected epoch and `sender_leaf_index`. A mismatch is `POLICY_REJECT` with no replay, counter, membership, or application state change.

The complete TLS-serialized MLS message is the outer plaintext content; therefore a successful outer authentication is not sufficient. The receiver MUST also validate the credential, replay, owner, membership, and application schema rules. All of this is local post-relay-commit processing: custody status is already queued, and neither route lookup nor authentication may change the opaque relay row, inventory, forwarding, retention, session response, or peer-visible error. Unknown outer keys/tags and authentication failures are therefore indistinguishable to the peer.

## 9. Safety number

For two distinct root public keys `A` and `B`, set `lo` and `hi` by unsigned lexicographic byte order and compute:

```text
d = SHA-256(UTF8(L_SAFETY_NUMBER) || lo || hi)
n = OS2IP(d) mod 10^60
```

Render `n` as exactly 60 zero-padded decimal digits in twelve groups of five separated by single spaces. Both sides obtain the same value. Users MUST compare the whole value out of band; the UI MUST NOT claim that partial comparison is secure. Equal root keys are a self-contact error.

## 10. Linux passphrase fallback

When Secret Service is unavailable, require a user passphrase of 12–128 Unicode scalar values and at most 512 UTF-8 bytes after NFKC normalization. Derive:

```text
wrap_key = scrypt(UTF8(NFKC(passphrase)), salt[16], N=131072, r=8, p=1, dkLen=32)
```

Use a fresh random salt and 12-byte random nonzero nonce. Wrap the random SQLCipher key with AES-256-GCM and `UTF8(L_STORAGE_WRAP_AAD) || header[44]` as AAD, where `header` is the first 44 bytes below:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | ASCII `MSK1` |
| 4 | 1 | version 1 |
| 5 | 1 | `log2_N = 17` |
| 6 | 4 | `r = 8` |
| 10 | 4 | `p = 1` |
| 14 | 16 | salt |
| 30 | 12 | nonce |
| 42 | 2 | wrapped length, exactly 48 |
| 44 | 48 | 32-byte ciphertext plus 16-byte GCM tag |

The file is exactly 92 bytes with no trailing data and mode `0600` in a user-private directory. Resource parameters are constants, not file-selected policy; a mismatch is rejected before scrypt. After `n` consecutive failures, delay the next attempt by `min(2^(n-1), 60)` monotonic seconds; success resets the counter. There is no destructive retry limit or password reset. The 128 MiB scrypt memory requirement is a deliberate security/usability gate and must pass the Ubuntu benchmarks before approval.

## 11. One-active-device recovery and revocation

### 11.1 Initial acceptance

A contact becomes active only after QR validation, full safety-number confirmation, and a durable mapping from `identity_id` to exactly one `device_instance_id` and root public key. Relayed certificates and device-replacement notices can only create a pending prompt.

### 11.2 Recovery or replacement

1. The recovering user enters and validates all 24 words locally.
2. The device derives the same root, creates a fresh random device key/instance, root-signs a new certificate, creates fresh one-time bundles, and erases the root again after confirmation.
3. The recovering user and each contact exchange fresh QR bundles in person, scan each other's bundle, verify the unchanged full safety number, and explicitly accept the recovering certificate as “replace”. Declining changes nothing; the unchanged contact device is re-confirmed, not replaced.
4. After bilateral acceptance, the lexicographically smaller `identity_id` is the sole inviter and creates exactly one fresh two-member MLS group plus one mode-2 bootstrap using the other party's fresh one-time bundle. On a successful join, each side atomically activates the replacement direct group, destroys any locally held old direct-group/exporter/routing state, and consumes the applicable bundle/invitation. Old plaintext may remain only under ordinary history retention; no history or old session key is imported into the new group.
5. For each private group, after the recovering user and owner have completed the bilateral acceptance in step 3, that same owner remains the sole inviter: it performs one membership Commit that removes the old leaf and adds the recovering user's fresh bundle KeyPackage, then sends one mode-2 Welcome bootstrap to that bundle. Until the recovering device validates and joins it, the new device is not a member and the old leaf may retain access to messages it legitimately received.

A planned owner replacement can use one owner-authenticated Commit that swaps its old leaf for the new same-identity leaf. If the sole owner device and its MLS state are lost, that group cannot be recovered in v1; members must form a new group. No relay, timestamp, certificate issue time, predecessor hint, or root signature automatically selects a winner. A stolen recovery phrase can impersonate the identity to contacts who accept it; phrase compromise has no cryptographic revocation path in v1.

During a planned rotation, the old device MAY send the new root-signed certificate as an MLS device-replacement notice. Recipients store it as pending only. This is the complete v1 meaning of a signed revocation announcement: the old contact instance is revoked only by explicit local replacement, and an old group leaf only by the authenticated owner Commit. No unauthenticated relay beacon changes trust state.

### 11.3 Deletion

Conversation deletion removes plaintext, message/event mappings, MLS group state, exporter outputs, contact-specific routing state, and queued outbound mappings in one private transaction, then checkpoints SQLCipher. Account deletion additionally deletes all contact records, active device key, database wrapping records, and the private database. Filesystem/flash remanence and copies already held by peers are outside the deletion guarantee.

### 11.4 Removal and rejoin

When an authenticated valid owner Commit removes this client from a private group, the client atomically enters `REMOVED` and deletes every current and retained-past MLS secret/state object, MLS group ID/epoch/roster, routing secret, sender outer key, nonce reservation/count, queued outbound mapping, pending membership/repair object, and private routing index for that group. The only remaining private tombstone fields are the local conversation-row ID, user-visible group label, immutable owner contact identity, state `REMOVED`, local removal minute, history-row references, and a boolean rejoin-prompt flag. Opaque copies already in the relay database remain unassociated and expire under ordinary relay policy. No exporter or decrypt operation may run after the removal transaction.

The UI retains already-decrypted history only until each row's ordinary history deadline, marks the conversation read-only as “Removed”, and shows a permanent boundary before any later rejoin. It MUST NOT display post-removal opaque traffic, send texts or receipts, offer repair, or imply that retained history proves current membership. Immediate user deletion still removes the retained history.

Rejoin requires a fresh bilateral contact bundle delivered to the immutable owner. The owner adds the fresh KeyPackage in a new owner Commit and sends one fresh Welcome bootstrap. `REMOVED` moves to `REINVITE_PENDING` only after the user accepts that exact owner invitation; a valid transactional join moves it to `ACTIVE`, while expiry/cancel returns it to `REMOVED`. Rejoin restores only new current group state. It never restores deleted epoch/exporter keys, imports history, or removes the UI boundary.

### 11.5 Conversation repair

V1 defines no automatic MLS state transfer, resynchronization request, or state snapshot. An unauthorized non-owner membership Commit is rejected while the last valid state remains `ACTIVE`; it does not itself trigger repair. A conversation moves from `ACTIVE` to `REPAIR_REQUIRED` only when a validly authenticated owner Commit cannot be processed under RFC 9420, a fork cannot be reconciled by RFC processing, the sender-ratchet bounds are exceeded, or required current state is corrupt/missing. In `REPAIR_REQUIRED`, history remains readable while its retention permits, but new application sends, membership changes, receipts, and exporter use are disabled.

One explicit user action may create exactly one pending repair attempt per conversation and target identity:

| From | Trigger/action | To | Exact result |
|---|---|---|---|
| `REPAIR_REQUIRED` direct chat | both unchanged active devices exchange fresh bilateral QR bundles and reconfirm the full safety number | `REINVITE_PENDING` | lexicographically smaller identity creates exactly one fresh two-member group and one mode-2 bootstrap using the other's one-time bundle |
| `REPAIR_REQUIRED` non-owner group member | member gives the owner a fresh QR bundle in person; owner validates the already accepted identity/device | `REINVITE_PENDING` | active owner creates one Commit that removes the stale leaf and adds the bundle KeyPackage, then one mode-2 Welcome bootstrap |
| `REINVITE_PENDING` | recipient validates and durably joins the exact invitation | `ACTIVE` | atomically delete old MLS/exporter/routing state, bind the new group/leaf, consume bundle/invitation, and preserve old plaintext only until its ordinary history deadline |
| `REINVITE_PENDING` | bundle deadline expires, user cancels, or an authenticated inviter produces a policy-invalid Welcome | `REPAIR_REQUIRED` | delete pending private material and the offered bootstrap; a later attempt requires a new bundle and invitation ID |
| `REPAIR_REQUIRED` owner group with missing/corrupt owner state | user acknowledges loss | `ABANDONED` | no successor or state import is accepted; members must form a new group |
| any state except `ABANDONED` | user deletes/abandons conversation | `ABANDONED` | delete cryptographic state under section 11.3; terminal for that conversation ID |

One attempt is one `bundle_id`, one `invitation_id`, and one byte-identical bootstrap envelope. Ordinary transport retries reuse those exact envelope bytes; there is no re-encryption, automatic request, snapshot response, background retry loop, or peer-selected limit. A valid join is attempted once transactionally. Invalid unauthenticated traffic does not change state or consume the bundle. A group owner whose own state is `REPAIR_REQUIRED` cannot repair that group. Physical QR exchange is the only repair-bundle transport in v1, avoiding a new unaudited recovery channel.

## 12. Conformance and review gate

Application-specific known-answer coverage MUST include nonzero positive and all-zero negative recovery entropy; root HKDF/Ed25519/identity ID; COSE device/contact/bootstrap signatures; MLS credential CBOR; positive and negative application-bound KeyPackage/Welcome cases; safety number; routing exporter with empty context and per-sender outer exporters with the exact four-byte contexts; routing tags; AES-GCM envelope and sender-context match; proof of work; HPKE bootstrap; QR text; empty-payload Noise NN handshake/transport with the required prologue and exact handshake lengths; every sync and application record variant; BLE chunks; every LoRa size mapping; Android/Apple/Windows/Ubuntu wrapping profiles and binary records; and Linux fallback wrapping. Both independent generators must produce byte-identical canonical JSON.

Standard internals are not reimplemented as production project primitives. The vector generators independently implement only published known-answer formulas and cross-check the pinned OpenMLS/snow fixtures. Implementations MUST additionally run the upstream RFC/OpenMLS conformance material for Ed25519, HPKE, MLS, AES-GCM, HKDF, CBOR/COSE, scrypt, and Noise. Passing local vectors cannot replace library/provider validation. The pinned OpenMLS suite-`0x0001` upstream fixture remains a negative application-binding control. The retained Rust harness compiles against exact commit `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6`, generates the positive application-bound 16-member KeyPackage/Welcome/application message, checks joining and authenticated sender identity, and checks wrong-recipient rejection. Its source, `Cargo.lock`, output fixture, source/toolchain checks, and reproduction command are normative test evidence.

The following remain approval blockers, not implementation discretion:

- human independent review and acceptance of MLS exporter use, HPKE/COSE bootstrap binding, recovery authority, outer AEAD, nonce accounting, and metadata consequences;
- physical secure-store extraction/lock tests on minimum/current devices;
- measured scrypt performance and memory behavior on the Ubuntu reference host;
- a new independent reproduction and human security acceptance after the failed draft.1, draft.2, and draft.3 reviews and later corrections;
- human approval of ADR-0002 and ADR-0003 after findings are resolved.

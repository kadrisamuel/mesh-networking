# ADR-0002: Identity, cryptography, recovery, and storage

- Status: Draft — independent security review and human approval required
- Decision date: 2026-08-19
- Scope: DEC-001 only

## Context

Recovery, MLS state, outer-envelope privacy, and storage locking must compose standard primitives without creating a new cipher or key exchange.

## Proposed decision

Use RFC 9420 MLS with cipher suite `0x0001` (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`) through pinned OpenMLS 0.8.1. Direct chats are fixed two-member groups and reject every post-bootstrap membership-changing Proposal or Commit because they have no owner. Private groups contain 2–16 members, and only the immutable group owner may commit additions and removals; owner succession is outside v1. Store the current MLS epoch plus exactly three past epochs using OpenMLS `max_past_epochs(3)`. Do not implement the plan's seven-day delayed-key alternative because the pinned release has no approved time-based retention mechanism.

Create 256 random nonzero recovery bits with at most eight draws and encode them as 24 BIP-39 English words. All-zero is a mandatory negative fixture and a production failure, not an identity. BIP-39 is encoding only: its passphrase/PBKDF2 seed is not used. Derive one Ed25519 root seed with the HKDF-SHA-256 rule and fixed label in `CRYPTOGRAPHY_V1.md`. Device signing keys, MLS keys, and one-time bootstrap HPKE keys are independently random. Root-sign device certificates using deterministic CBOR and COSE_Sign1 EdDSA. Remove recovery entropy and the root private key after the user proves recovery-code possession.

Initial contact establishment is bilateral. Each person displays one independently generated QR bundle, scans the other person's bundle, and confirms the same full safety number before either contact becomes accepted. The identity with the lexicographically smaller identity ID is the sole direct-chat inviter, eliminating crossed invitations without treating ordering as authentication. Direct repair and recovery use an in-person bilateral exchange of one fresh bundle per person; group re-invitation uses one fresh invitee bundle. Each attempt has one byte-identical bootstrap envelope, and v1 has no automatic state-transfer or resynchronization protocol.

There is exactly one explicitly accepted device instance per identity in each contact record and one leaf per identity in each MLS group. Recovery creates a fresh root-signed instance and restores identity authority only; it restores neither history nor MLS state. There is no numeric “newest” counter because a recovery phrase cannot know state held only by a lost device. Each contact must explicitly compare/accept the replacement certificate and start fresh direct MLS state. Group owners must explicitly swap the old leaf for the replacement. Relayed certificates never auto-replace a contact. There is no global revocation service.

Conversation state is exactly `ACTIVE`, `REPAIR_REQUIRED`, `REMOVED`, `REINVITE_PENDING`, or `ABANDONED`. An unrecoverable authenticated MLS failure disables sends and exporter use. A valid owner Commit that removes the local member enters `REMOVED`, atomically deletes every group/exporter/routing/nonce state object, and leaves only a read-only UI tombstone plus ordinary time-bounded plaintext history. Rejoin requires a fresh owner invitation and adds a visible boundary without recovering old keys. Direct contacts may explicitly re-establish a new two-member group; a group owner may explicitly replace a failed member. An owner that cannot operate its own group state leaves that group `ABANDONED` in v1. History and failed state are never copied into replacement cryptographic state.

The plan's “signed revocation” is narrowed to a root-signed replacement certificate optionally announced inside an existing authenticated MLS session during planned rotation. It creates a pending prompt only. Local acceptance revokes the old contact instance; a group removal/swap Commit revokes the old group leaf. V1 has no broadcast revocation beacon or automatic global effect.

Keep private state in a SQLCipher database and opaque relay envelopes in a separate ordinary SQLite database. The private database key is a random 32-byte key protected by the exact Android Keystore, Apple Data Protection Keychain, Windows user-scope DPAPI, or Ubuntu Secret Service profile and record encoding in `ARCHITECTURE.md`. Locking closes the private database and zeroizes process-held key/plaintext buffers while leaving the relay database usable. The relay database is forbidden from containing display names, contacts, group identifiers, routing-secret mappings, keys, plaintext, or decrypted metadata. Linux Secret Service is primary; the exact RFC 7914 scrypt passphrase fallback is defined in `CRYPTOGRAPHY_V1.md`.

Use only the standards and library constructions named in the cryptography specification. Derive the routing secret once per epoch and the outer AES-GCM key separately for each authenticated sender leaf by using the RFC 9420 exporter with the exact four-byte leaf-index context. Receivers make at most 64 key trials and require the decrypted MLS sender/epoch to match the successful context. Nonce uniqueness and `MAX_SEALS = 2^24` are enforced per sender and epoch: ordinary traffic stops one seal early, and the reserved final old-key seal transactionally stores one byte-stable self-Update envelope while merging and persisting the new epoch before emission. This MLS-exporter outer wrap, recovery hierarchy, HPKE bootstrap container, and COSE schemas are a protocol composition that requires independent cryptographic review before implementation even though each primitive is standardized.

## Consequences

- Lost history is an intentional recovery property.
- An old device cannot be silently displaced; availability depends on contact-by-contact action.
- Messages delayed beyond three previous MLS epochs become undecryptable regardless of wall-clock age.
- Relay operation while locked exposes opaque traffic timing and volume but not private database contents.

## Approval blockers

- The preserved draft.1, draft.2, and draft.3 independent reviews failed. Later corrections have no new independent result, and no human cryptographic approval of the corrected composition has been recorded.
- Secure-store behavior, key zeroization, and locked extraction have not been tested on physical minimum/current devices.
- The Android hardware-backed-key result, Apple Keychain protection class, Windows DPAPI scope, and Ubuntu Secret Service backend must be captured as device evidence; the specified profiles do not by themselves prove hardware-backed storage.
- Linux fallback usability and memory cost have not been measured on reference hardware.

## Sources

- [RFC 9420: Messaging Layer Security](https://www.rfc-editor.org/rfc/rfc9420.html)
- [OpenMLS 0.8.1 release](https://github.com/openmls/openmls/releases/tag/openmls-v0.8.1)
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)
- [RFC 8032: Ed25519](https://www.rfc-editor.org/rfc/rfc8032.html)
- [RFC 9180: HPKE](https://www.rfc-editor.org/rfc/rfc9180.html)
- [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [RFC 9052 and RFC 9053: COSE](https://www.rfc-editor.org/rfc/rfc9052.html)
- [BIP-39 at pinned source commit](https://github.com/bitcoin/bips/blob/857a7debc6625a3dadbaecee1ee7b2ed5e8ada75/bip-0039.mediawiki)
- [RFC 7914: scrypt](https://www.rfc-editor.org/rfc/rfc7914.html)

## Human decision required

Approve or reject, as one decision, the nonzero recovery and permanent history-loss model; bilateral contact bootstrap; one-active-device/contact-acceptance rule; fixed two-member direct-chat policy; private-group owner-only changes; complete `REMOVED`/re-invitation state and key deletion; three-past-epoch limit; per-sender exporter-derived outer keys, bounded receiver trials, sender-context match, per-sender/epoch nonce limits, and reserved-seal crash-atomic rollover; exact platform key-wrapping profiles; database split; and cryptographic-review gate.

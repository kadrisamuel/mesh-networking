# Phase 10 — Security, Identity, and Storage

All tasks are blocked by approved `DEC-001` specifications. Implement no cryptographic behavior directly from `MVP_PLAN.md` prose.

## SEC-001 — Implement secret-safe cryptographic utilities

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `DEC-001`, `TST-001`  
**Allowed paths:** `rust/crates/mesh-identity/`, shared secret-safe test support

**Objective:** Centralize the approved primitive implementations and make accidental secret disclosure difficult.

**Implementation:** Wrap zeroizing secret bytes, production CSPRNG, test-only deterministic RNG, HKDF/HMAC/AEAD/signature helpers, constant-time comparison, domain-label constants, and sanitized errors. Algorithms are compile-time choices from `CRYPTOGRAPHY_V1.md`, not caller parameters.

**Verification:** Run approved known-answer vectors, RNG failure cases, compile tests proving secret types do not implement `Debug` or general serialization, and zeroization tests where observable.

**Done when:** Production code cannot request an unapproved algorithm, deterministic RNG, raw secret log, or ad hoc domain label.

## ID-001 — Implement recovery-code and root-identity derivation

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `SEC-001`  
**Allowed paths:** `rust/crates/mesh-identity/`, `tests/fixtures/v1/identity/`

**Objective:** Create and import the stable root identity exactly as specified.

**Implementation:** Generate 32 CSPRNG bytes, encode the approved versioned 24-word format, normalize and validate imports, derive the Ed25519 root seed with the frozen domain-separated construction, compute the root fingerprint, and expose a transient root-authority session. Wipe phrase/entropy/root seed after use.

**Verification:** Cross-platform fixed vectors, round trips, checksum/word-count/case/whitespace failures, RNG failure, and canary scans of errors/logs/storage.

**Done when:** Identical words produce the identical root public key on every target and no API persists the root private seed.

**Do not:** Add an optional passphrase, cloud recovery, clipboard default, or custom word list unless the approved specification says so.

## ID-002 — Implement device certificates and safety numbers

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human review required before merge  
**Depends on:** `ID-001`  
**Allowed paths:** `rust/crates/mesh-identity/`, identity fixtures

**Objective:** Bind a device key to a stable root and provide verifiable contact pinning.

**Implementation:** Add canonical root-signed device certificates, independent device IDs/keys, strict verification, certificate status, pinned contact records, and symmetric safety-number derivation. Root-authority operations require transient recovery-code entry.

**Verification:** Golden encodings plus forged root/device signatures, changed fields, noncanonical forms, wrong root, duplicate device ID, superseded certificate, and safety-number symmetry tests.

**Done when:** An invalid, revoked, superseded, or differently rooted certificate cannot become a verified device or MLS credential.

## ID-003 — Implement one-use contact invitation bundles

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `ID-002`, approved opaque KeyPackage size/interface fixture from `DEC-001`  
**Allowed paths:** identity invitation module and fixtures

**Objective:** Define the QR/import container without making it reusable or discoverable publicly.

**Implementation:** Encode protocol version, root public key, device certificate, random invitation nonce, expiry, and opaque one-time KeyPackage bytes; add strict size/version/canonical validation and reserved/consumed transaction states.

**Verification:** Reuse, simultaneous double use, expiry, certificate/KeyPackage substitution, unknown version, invalid encoding, and oversized payload tests.

**Done when:** Exactly one successful consumption is possible and failure leaves contact/conversation state unchanged.

## STO-001 — Specify and migrate separate private and relay databases

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human approval required before implementation  
**Depends on:** `DEC-001`, `ID-002`  
**Allowed paths:** `docs/spec/`, `rust/crates/mesh-storage/`, migration fixtures

**Objective:** Permit ciphertext relaying while the app is locked without exposing conversation secrets.

**Implementation:** Freeze schemas and migration ownership for `private.db` and `relay.db`. Private storage contains keys, contacts, MLS state, plaintext history, outer-key/tag indexes, and message state. Relay storage contains opaque complete envelopes, bounded incomplete fragments, dedupe and transport-forwarding metadata only. Use random database-local identifiers; forbid cross-database foreign keys and stable contact identifiers in relay storage.

**Verification:** Schema/migration fixtures, table/column allowlist tests, and a test that relay operations run with private storage absent.

**Done when:** The schema review finds no secret or contact relationship in `relay.db`.

## STO-002 — Integrate SQLCipher and transactional migrations

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `STO-001`, `FND-002`  
**Allowed paths:** `rust/crates/mesh-storage/`, storage fixtures

**Objective:** Encrypt both storage domains using independent random keys and fail safely on corruption or missing keys.

**Implementation:** Add SQLCipher opening, raw 32-byte keys, encrypted WAL/journal settings, versioned migrations, integrity checks, transaction boundaries, backup exclusions, explicit corrupt/wrong-key states, and crash-safe initialization.

**Verification:** Wrong/crossed-key rejection, corruption, crash/reopen at every migration boundary, rollback, concurrent readers, and binary scans for known plaintext.

**Done when:** A copied closed database reveals no fixture plaintext and unlock failure never silently creates a new identity/database.

## STO-003 — Implement Apple key protection

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `STO-002`, `PLAT-001` capability contract  
**Allowed paths:** Apple native plugin, Apple project entitlements, storage integration tests

**Objective:** Protect private and relay database keys according to their different availability needs.

**Implementation:** Store the private wrapping key with device-only/user-presence policy; store the relay wrapping key as device-only and available after first unlock; configure file protection and backup exclusion; surface typed unavailable/cancelled/invalidated states.

**Verification:** Physical iOS/macOS lock, reboot-before-first-unlock, biometric cancellation, enrollment change, key deletion, and attempted restore on another device.

**Done when:** Private storage requires explicit user presence while permitted relay-only operation works after first unlock.

**Do not:** Use synchronizable/iCloud Keychain entries.

## STO-004 — Implement Android key protection

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `STO-002`, `PLAT-001`  
**Allowed paths:** Android native plugin, manifest, storage integration tests

**Objective:** Provide equivalent Android 10+ database-key wrapping and invalidation behavior.

**Implementation:** Use Android Keystore authentication-required private wrapping, unlocked-device relay wrapping, backup exclusion, capability reporting, and explicit invalidated/unrecoverable-local-data state.

**Verification:** API 29 and current physical/emulator tests for cancellation, reboot, lock, enrollment change, key invalidation, and copied database/credential material.

**Done when:** Invalidated wrapping keys never trigger a silent new identity and hardware-backed status is claimed only when runtime evidence supports it.

## STO-005 — Implement Windows and Linux private-storage protection

**Model:** `gpt-5.6-terra`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `STO-002`, `PLAT-001`  
**Allowed paths:** Windows/Linux platform adapters, desktop tests

**Objective:** Keep desktop private storage explicitly locked even where login keyrings do not prove user presence.

**Implementation:** On Windows, use approved Windows Hello protection when available and an Argon2id high-entropy passphrase fallback; use a current-user relay key. On Linux, use Secret Service for the relay key and versioned Argon2id passphrase wrapping for private storage. Do not pass secrets via arguments, environment, or plaintext files.

**Verification:** Physical/VM tests for correct/wrong passphrase, cancellation, copied databases, changed user account, unavailable/locked keyring, and parameter migration.

**Done when:** Desktop login alone does not silently open `private.db`; capability/limitations are reported accurately.

## STO-006 — Implement lock lifecycle and local history deletion

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human review required before merge  
**Depends on:** `STO-002` through `STO-005`  
**Allowed paths:** storage/core lifecycle state machine, lifecycle tests

**Objective:** Close and zeroize private state safely while retaining bounded ciphertext relaying.

**Implementation:** Add an explicit locked/unlocking/unlocked/locking state machine, cancel private operations, close `private.db`, wipe its in-memory key, mask UI snapshots before backgrounding, keep only approved relay operations, purge seven-day history, and implement conversation deletion as application-level best effort.

**Verification:** Lock during send/decrypt/migration, rapid cycles, OS background/lock, relay arrival while locked, process death, restart, purge, deletion, and deadlock/race tests.

**Done when:** No decrypt/send/contact call succeeds outside the unlocked state and logs/errors contain no secret state.

**Do not:** Claim guaranteed forensic erasure from flash media.

## ID-004 — Implement manual device replacement and revocation objects

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human approval required before implementation  
**Depends on:** `ID-002`, `STO-006`, approved recovery semantics from `DEC-001`  
**Allowed paths:** identity/recovery core, recovery fixtures, specification amendments

**Objective:** Restore root identity without falsely promising contact discovery, message recovery, or immediate global revocation.

**Implementation:** Recovery creates a new device certificate and no history/contacts. Define root-signed replacement/revocation objects identifying the old certificate hash without timestamps as authority. Require contact-by-contact re-pair; affected conversations perform remove/add transitions after receiving the object. Lost group owners remain unsupported unless `DEC-001` explicitly chooses a different reviewed design.

**Verification:** Wrong phrase/root, replay, wrong predecessor, old-device traffic before and after conversation removal, missing contact list, restart mid-flow, and stable-root safety number tests.

**Done when:** The old device loses future conversation access only after each conversation processes its authenticated removal; UI/API wording matches this limitation exactly.

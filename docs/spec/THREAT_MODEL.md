# Threat model v1.0.0-draft.3

- Status: Draft — independent security review and human approval required
- Decision set: DEC-001, 2026-08-19
- Applies to: architecture/protocol/cryptography profile v1 drafts

This is a laboratory-prototype threat model, not a security certification. A passing test suite does not authorize emergency or high-risk use.

## 1. Assets and priorities

| Priority | Asset | Required property |
|---:|---|---|
| 1 | Message plaintext and private history | Confidentiality and integrity outside accepted endpoints |
| 1 | Recovery entropy, root/device/MLS/database keys | Confidentiality, correct use, prompt deletion |
| 1 | Contact and group identity bindings | Authenticity; no silent replacement |
| 2 | Membership and sender attribution | MLS integrity and owner-only changes |
| 2 | Locked private database | Confidentiality against file extraction |
| 2 | Delivery-state truth | “Delivered” only from authenticated direct peer |
| 3 | Relay availability and bounded resources | Best effort under explicit storage/session/TTL limits |
| 3 | Discovery privacy | No application-level stable identity/name in advertisements |

When availability conflicts with key/identity integrity, the implementation MUST fail closed and report a redacted local error.

## 2. Trust boundaries

Trusted only after their specified checks:

- the shared Rust core and pinned cryptographic providers;
- an unlocked endpoint OS/process, excluding other privileged/malicious software;
- a root/device/MLS credential after canonical parsing, signature verification, and local acceptance checks;
- private state read from an authenticated SQLCipher database after successful key unwrap.

Always untrusted:

- BLE/WLAN peers, mDNS, GATT metadata, TCP, Meshtastic radios/firmware/channels, gateways, couriers, relay databases, sender clocks, mutable hop fields, custody/radio ACKs, and all external bytes;
- contact/group members outside the authority MLS grants them;
- Flutter/native layers with respect to cryptographic decisions;
- logs, crash reporters, clipboard, screenshots, backups, package registries, build workers, and distribution stores.

Noise NN makes one link confidential against passive observers after its handshake but does not authenticate the peer. It is not promoted into the trusted set.

## 3. Adversaries

| Adversary | Capabilities | Explicit limit of guarantee |
|---|---|---|
| Passive nearby observer | Capture BLE/WLAN/LoRa traffic, timing, sizes, RF fingerprints, IP/MAC/OS metadata | Cannot read authenticated payloads; can infer presence, volume, padded-size class, and movement/encounters |
| Active network attacker | Replay, reorder, duplicate, mutate, fragment, inject, race, downgrade, MITM Noise NN, reset mutable hops, disconnect | Cannot forge MLS/COSE/AEAD without keys; can deny/delay and correlate sessions |
| Malicious relay/gateway | Store, drop, selectively forward, inspect relay DB, lie in custody ACK, reset hop count | Cannot cause `delivered`; can cause `accepted_by_mesh`, denial, delay, traffic analysis, and storage pressure within quotas |
| Malicious/captured radio | Observe PhoneAPI and ciphertext, acknowledge without RF delivery, alter/drop packets, expose channel key | End-to-end confidentiality/integrity remains at MLS/outer layer; availability and accepted state are not guaranteed |
| Malicious contact/member | Send valid abusive content, retain plaintext, screenshot/export, replay allowed credentials, traffic-analyze group | MLS cannot prevent an authorized recipient from retaining/sharing plaintext |
| Malicious group owner | Add/remove members, withhold commits, partition or abandon group | Owner governance is intentional; no fairness, succession, or availability guarantee |
| Stolen locked device/file copy | Copy app files and relay DB, attempt offline database/key attack | SQLCipher/private key should remain protected if OS secure store/passphrase and OS are uncompromised; relay metadata remains visible |
| Stolen unlocked device or compromised OS | Read process memory/UI/private DB, send as active device, alter binaries | Outside cryptographic protection; user must perform contact-by-contact replacement |
| Recovery-phrase thief | Derive root and create valid device certificates | Can impersonate the identity to contacts who explicitly accept replacement; no global phrase revocation exists |
| Supply-chain attacker | Compromise dependency, generator, CI, package, compiler, signing key | Mitigated by immutable pins, checksums, audits, reproducible evidence, human signing custody; not eliminated |
| RF jammer or disaster | Jam/interfere, exhaust duty cycle, damage devices, isolate partitions | Availability is not guaranteed; no anti-jamming claim |

## 4. Security claims

Subject to correct implementation, reviewed composition, uncompromised accepted endpoints, and pinned providers, v1 intends to provide:

1. MLS confidentiality, integrity, sender authentication, forward secrecy, and post-compromise behavior as defined by RFC 9420 for accepted group state.
2. Root-authenticated device credentials and explicit contact replacement; a relay cannot silently change an accepted device.
3. Confidentiality of MLS group IDs/epochs from ordinary relays through the outer AES-GCM/HPKE layer.
4. Opaque rotating routing tags rather than stable contact/group identifiers on the relay layer.
5. Locked private-history/key confidentiality against application-file extraction, assuming the platform wrapping facility or Linux passphrase remains secure.
6. Bounded parsing, sessions, fragments, proof-of-work admission, cache space, retention, and retry work.
7. Authenticated direct-message delivery only through an MLS receipt from the currently accepted peer device.
8. Membership changes only from the immutable group-owner identity, with at most one accepted leaf per identity after each Commit.

These are draft design goals until review and tests complete; they are not present-tense audited guarantees.

## 5. Explicit non-goals and residual leakage

V1 does not hide or guarantee:

- that a device runs the app, transmits radio/BLE/WLAN traffic, or encounters another device;
- IP/MAC/BLE address behavior supplied by the OS, radio hardware fingerprints, packet timing, count, direction, padded-size class, selected transport, or RF location inference;
- unlinkability against an observer that follows routing-tag changes through timing/continuity;
- availability against jamming, deletion, withholding, routing eclipse, malicious owner, device loss, battery loss, OS scheduling, or duty-cycle enforcement;
- plaintext on an unlocked/compromised endpoint or after an authorized recipient records it;
- retroactive protection for messages/keys already captured from a compromised current endpoint;
- secure deletion from flash snapshots, backups outside app control, peer devices, notifications already shown, screenshots, or human copies;
- anonymity, deniability, censorship resistance, Sybil resistance, or proof that a custody ACK represents an honest independent person;
- automatic group recovery when the only owner device/state is lost;
- continuous iOS background relay, desktop phone-mesh BLE, or lawful RF operation in every EU location.

## 6. Required invariants

An implementation is security-invalid if any invariant fails:

1. Cryptographic keys and plaintext are created/processed only in the Rust core and private database; FFI receives neither keys nor security decisions.
2. Every external length/count is capped before allocation; canonical parsing and enum/reserved checks precede cryptography.
3. Unsupported version/suite/algorithm/extension fails closed without downgrade.
4. AEAD/HPKE associated data is exactly the normalized header; only hop remainder and proof-of-work nonce are mutable.
5. Same-ID offers are compared over normalized header plus sealed body; valid hop/PoW-only variants merge deterministically and immutable differences are collisions.
6. The outer AES-GCM key is exporter-derived separately for every authenticated sender leaf and epoch. `(group, epoch, sender leaf, nonce)` is unique and durably reserved. Ordinary seals stop at `MAX_SEALS - 1`; the final seal is used once only by a crash-atomic old-epoch self-Update transaction, after which old-key creation is impossible and retries reuse stored bytes. Receivers try at most 64 retained sender contexts and require the decrypted MLS sender/epoch to match the successful context.
7. Structural/time/proof-of-work/collision/quota admission durably stores every admissible envelope in the single opaque relay pool and queues its custody ACK before route lookup. An envelope is not parsed beyond its outer container, displayed, or persisted privately until all applicable outer and MLS/COSE checks pass. Unknown route, known route with invalid ciphertext, and known route with valid ciphertext have the same relay/ACK/session/forwarding/inventory/expiry behavior; only the valid case may additionally create private state after ACK queueing.
8. Custody/radio acknowledgements never produce `delivered`; group delivery/read receipts do not exist.
9. Sender timestamps never select eviction order or extend local retention beyond the class cap.
10. Current plus three past MLS epochs is the complete delayed-key window; deleted epoch/exporter secrets do not return from backups.
11. A root-signed replacement remains pending until each contact explicitly confirms the full safety number and replacement action.
12. Private-group membership Commits authenticate to the stored owner identity; direct-chat membership changes are always rejected; groups contain at most 16 leaves and one leaf per identity. A locally removed member atomically deletes every group secret and enters read-only `REMOVED` state.
13. Lock closes SQLCipher, clears UI plaintext, and zeroizes process-held secrets while relay SQLite remains keyless and opaque.
14. Route knowledge and authentication results never enter the relay database or change relay quota, eviction, retention, inventory, forwarding, ACK, or peer-visible error behavior. All opaque objects use one uniform bounded relay pool.
15. Production logs/diagnostics contain none of the sensitive values prohibited in `ARCHITECTURE.md`.
16. Meshtastic channel encryption, Noise NN, proof of work, and mutable hop count are never described as end-to-end authentication.
17. Plaintext history expires against the private database's wall-clock high-water mark; an observed backward clock step latches rollback and deletes existing history before display, while overdue rows are deleted on unlock.

## 7. Abuse and failure analysis

| Attack/failure | Required response | Residual risk |
|---|---|---|
| Malformed/oversized envelope or CBOR | Reject before large allocation; generic close/counter | CPU used for bounded parse |
| Opaque-envelope flood | Require 18-bit work; per-session/single-global-pool quota and deterministic uniform eviction | Distributed attackers can consume bandwidth/battery and evict user or control traffic; no private classification protects relay rows |
| Proof-of-work precomputation/reuse | Work binds complete header/sealed bytes; duplicates count against session quota | A captured valid envelope can still be replayed until ID/TTL suppression |
| Same ID on multiple honest paths | Compare canonical content; merge valid mutable-only variants using max hops/min valid PoW | Mutable hops remain attacker-resettable and provide no security boundary |
| ID collision with different canonical content | Keep first canonical object, discard second, close session, aggregate alert | Deliberate targeted collision is impractical; compromised sender can cause denial for an ID it chose |
| Clock far future/past | Apply ten-minute admission tolerance and monotonic local deadline | Wrong local OS clock can reject valid traffic or shorten availability |
| Crash/key exhaustion during outer rollover | Reserve the final old-key seal; atomically persist the exact old-epoch Update envelope, merged new state/exporters, and counters before emission; retry stored bytes | Loss of the only stored Update envelope or prolonged withholding can partition availability and require ordinary MLS repair |
| Mutable-hop reset | Continue TTL/dedup/quota enforcement | Malicious relay can circulate until expiry and across fresh caches |
| Noise MITM | MLS/COSE rejects impersonation; expose no detailed error | MITM can correlate, drop, reorder, and issue false custody ACK after storing bytes |
| Fragment collision/memory flood | Compare only meaningful final-fragment prefix, drop conflicting meaningful bytes, cap 128/2 MiB/10 min | RF airtime/battery denial remains; random tail is unauthenticated and ignored |
| Claimed control-class flood | Charge every object to the same opaque pool; claimed class affects only structurally checked TTL, never priority | Valid-work objects can occupy the bounded pool and claim seven-day retention; accepting this prevents an authentication oracle |
| Observed routing-tag probe | Commit and ACK admissible bytes before lookup; retain unknown and failed-authentication objects identically; keep results private | An attacker still observes ordinary encounter/session timing but cannot distinguish route possession from custody behavior |
| Forged/old device certificate | Verify root; require currently accepted instance | Phrase thief can produce a valid new certificate and socially engineer acceptance |
| Lost member device | Owner swaps/removes leaf, contact starts fresh direct group | Messages already delivered and old retained epochs remain readable on compromised endpoint |
| Lost group owner | Do not accept non-owner succession | Group becomes administratively unrecoverable |
| Relay database disclosure | Reveal only opaque bytes/local timing/class/size metadata | Traffic graph and storage timing remain sensitive |
| SQLCipher file extraction | Depend on wrapping key/passphrase; test locked extraction | Weak passphrase, compromised OS, memory capture, or rollback may defeat protection |
| Malicious update/dependency | Immutable source/checksum pins, audits, fixture drift, SBOM, signed release gate | Build-system/compiler compromise and maintainer-key compromise remain |
| Radio misconfiguration | Read-back exact EU profile; disable app TX on mismatch | Firmware bugs, antenna gain, hardware defects, and local law require human qualification |

## 8. Recovery-specific limitations

The root phrase is ultimate identity authority but contains no contact list, device counter, MLS state, history, or revocation registry. Consequently:

- there is no trustworthy automatic “newest certificate” after total device loss;
- one-active-device enforcement is local to each accepting contact/group, not globally atomic;
- contacts who have not performed replacement may continue to accept the old device/session;
- a non-owner replacement rejoins each group only after the owner swaps its leaf;
- an unplanned owner loss cannot recover the group;
- phrase theft cannot be revoked while preserving the same identity in v1.

UI copy and operational documents MUST state these limits before recovery confirmation.

## 9. Platform and physical assumptions

- Android Keystore, Apple Keychain, Windows DPAPI, Secret Service, OS CSPRNG, memory isolation, secure lock, and code-signing verification behave as documented and are not compromised.
- “Zeroize” means best effort within Rust/native memory; Flutter strings, OS keyboards, screenshots, swap, crash dumps, managed-runtime copies, and flash wear leveling can prevent complete erasure.
- BLE advertisement privacy depends partly on OS address randomization, which the application does not control.
- mDNS necessarily reveals a service and host/network metadata even though the app instance is random.
- SQLCipher protects database pages, not plaintext visible to an unlocked process or external notification content.
- Android hardware-backed Keystore availability, Apple Keychain/DPAPI extraction resistance, and Secret Service behavior are platform assumptions until the exact profiles pass physical extraction/lock tests.
- SQLCipher does not provide trusted anti-rollback; a compromised OS that restores an older private database, or restores both clock and database to mutually plausible values while the app is stopped, can restore its history high-water mark and retained ciphertext.
- Meshtastic firmware is beta and outside the project's security boundary.

Each assumption requires the physical tests in `TEST_MATRIX.md`; hardware-free simulation cannot satisfy them.

## 10. Privacy and logging

Notification text MUST default to “New message” with no sender/body while locked. Clipboard export is explicit and receives an expiry request where supported. Screenshots are blocked on recovery/private screens where supported. Crash reporting, analytics, advertising IDs, remote diagnostics, and automatic log upload are prohibited.

Redacted diagnostics may contain only exact software versions, coarse platform model/OS, boolean capability states, aggregate error/count buckets, storage-size buckets, and monotonic duration percentiles. Export scans for fixture canaries and patterns matching recovery words, keys, QR prefixes, routing/envelope IDs, IP/MAC/BLE addresses, and message samples; a match aborts export.

## 11. Review and operational blockers

The following are explicit blockers:

- **Security:** the preserved draft.1 independent review failed with eight findings, the draft.2 review failed with four findings, and the draft.3 review failed with a high-severity authentication-dependent session-quota oracle. Later corrective work has not received a new independent result, and no human reviewer has approved recovery/credential semantics, MLS ownership enforcement, exporter-derived per-sender outer encryption and crash-safe rollover, route-custody indistinguishability, HPKE bootstrap binding, nonce limits, padding/metadata, lock boundary, or parser state machines.
- **Hardware:** no actual phone, desktop, radio, antenna, battery, or secure-store extraction evidence is recorded.
- **RF/legal:** no qualified person has approved Sweden/EU transmit conditions for an actual configuration; the engineering profile is not legal advice.
- **Licensing/distribution:** AGPL/store terms, linked SQLCipher/OpenMLS dependencies, Meshtastic GPL/generated protobuf treatment, cryptography controls, notices/source obligations, and distribution territories lack qualified review.
- **Signing:** no approved credential custodian, notarization, rotation, compromise response, or reproducible signed-release procedure exists.
- **Platform:** Flutter does not list Ubuntu 26.04 LTS for the pinned release; Flutter/bridge/platform toolchain interoperability is not yet built on five targets.
- **Firmware:** the pinned Meshtastic release is beta and has not been qualified on the three radio families.

Until resolved, the project may produce draft documents, deterministic vectors, simulations, and receive-only/non-RF development after ADR approval; it may not claim audited security, lawful RF operation, or public-release readiness.

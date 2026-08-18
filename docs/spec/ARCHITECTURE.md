# Architecture specification v1.0.0-draft.2

- Status: Draft — human approval required; implementation is blocked
- Decision set: DEC-001, 2026-08-18
- Compatibility identifier: `mesh-messenger-architecture/1`

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** express normative requirements. This draft becomes authoritative only after all ADR approvals are signed in `docs/adr/DECISION_RECORD.md`.

## 1. Product boundary

The MVP is a laboratory offline messenger. It is not safety-certified and MUST NOT be represented as suitable for emergency, life-safety, or high-risk operational reliance.

Included:

- Android and iOS foreground BLE and WLAN messaging;
- Windows, macOS, and Ubuntu WLAN messaging;
- optional Meshtastic PhoneAPI over mobile BLE and desktop serial/TCP;
- direct chats, private groups, opaque store-carry-forward, local history, recovery, and revocation;
- EU_868 laboratory radio configuration after the RF gate is signed.

Excluded:

- browser, server, internet transport, accounts, cloud backup, usernames, attachments, voice, public channels, location, analytics, telemetry, and custom firmware;
- guaranteed iOS background routing;
- desktop phone-to-phone BLE;
- group-owner succession and multi-device synchronization;
- public or signed distribution before the gates in section 12.

## 2. Ownership and trust boundaries

| Component | Required owner | Allowed data | Forbidden behavior |
|---|---|---|---|
| Flutter app | Presentation and OS integration | Render-ready state, opaque byte buffers, user commands | Keys, crypto, envelope parsing, relay policy, plaintext persistence |
| Native platform plugin | OS permission/lifecycle byte pumps | Opaque bytes and typed capability/status values | Decryption, message interpretation, persistent identity logic |
| Shared Rust core | All security and protocol behavior | Plaintext while unlocked, keys, MLS, databases, transports | UI rendering, secret export through FFI |
| Private database | SQLCipher | Identity, contacts, MLS state, plaintext history, message state | Opening while locked |
| Relay database | ordinary SQLite | Complete opaque envelopes, local monotonic metadata, counters | Names, contacts, group IDs, routing-secret mappings, keys, plaintext |
| BLE/WLAN peer or radio | Untrusted transport | Opaque frames | Authority over identity, delivery, expiry, or plaintext |

The Rust core MUST expose the following conceptual interfaces through generated `flutter_rust_bridge` bindings:

- `IdentityService`: create, confirm, recover, certify one active device instance, create/consume contact bundles;
- `ConversationService`: direct/group lifecycle, owner-governed membership, send, receive, delete;
- `RelayService`: ingest, deduplicate, quota, expire, synchronize, clear opaque cache;
- `Transport`: idempotent `start`, `stop`, `capabilities`, bounded `send_frames`, cancellable event stream;
- `RadioService`: discover, connect, read configuration, configure only after explicit confirmation;
- `CoreEvent`: redacted state changes only.

All calls MUST use bounded buffers. Cancellation and restart MUST be idempotent. Rust panics MUST become a generic fatal-core event without secret-bearing text. Flutter and native code MUST never receive recovery entropy, private keys, SQLCipher keys, MLS secrets, decrypted relay entries, or unredacted protocol errors.

## 3. Process and lock lifecycle

States are `COLD`, `LOCKED_RELAY`, `UNLOCKED`, and `SHUTTING_DOWN`.

1. Process start enters `COLD`, generates a fresh nonzero random 16-byte `node_run_id`, opens only the relay database, initializes bounded transports, then enters `LOCKED_RELAY`. The ID lives only for that process run, appears only inside Noise and as the lowercase-hex WLAN mDNS instance name, and is erased on shutdown.
2. Successful platform-store or passphrase unlock unwraps the private database key, opens SQLCipher, loads MLS state, and enters `UNLOCKED`.
3. OS screen lock, explicit lock, 30 seconds continuously backgrounded, or five minutes without user input while foregrounded MUST atomically stop plaintext work, close SQLCipher, clear UI plaintext, zeroize secret buffers, and return to `LOCKED_RELAY`.
4. `LOCKED_RELAY` MAY ingest and forward complete opaque envelopes. It MUST NOT derive routing tags; it can forward only stored objects or objects offered by peers under unknown-route policy.
5. Shutdown cancels transports, checkpoints each database separately, zeroizes secrets, and enters `SHUTTING_DOWN`; a repeated shutdown request has no additional effect.

A setting MAY shorten but MUST NOT lengthen the five-minute foreground timeout or 30-second background timeout in v1.

## 4. Storage domains

### 4.1 Private database

Use SQLCipher 4.17.0 in v4 compatibility mode with its release defaults. Supply a random 32-byte raw database key; do not derive it with SQLCipher's passphrase interface. The application MUST enable foreign keys, secure deletion, encrypted WAL, and an integrity check after unclean shutdown. Backups are disabled. A schema migration MUST be transactional, versioned, and retain the previous encrypted file until the first successful open, then securely remove it where the OS permits.

Each private database has a fresh random nonzero 16-byte `database_id`, which is not an identity and is stored outside the encrypted database only to locate its key item. The random database key is protected as follows; no platform may silently substitute another facility:

| Platform | Exact primary profile |
|---|---|
| Android | Generate a non-exportable 256-bit AES key under alias `mesh-messenger-v1-db-` plus lowercase `database_id` hex with purposes encrypt/decrypt, GCM, no padding, `randomizedEncryptionRequired=true`, `unlockedDeviceRequired=true`, and no per-use authentication. Use neither StrongBox as a requirement nor a software key chosen by application code. Record `KeyInfo.isInsideSecureHardware` in the private hardware evidence. |
| iOS | Store the raw 32-byte database key as a generic-password item with service `mesh-messenger/v1/database-key`, account equal to lowercase `database_id` hex, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `kSecAttrSynchronizable=false`, the app's default access group, and no `SecAccessControl` flags. |
| macOS | Use the same service/account/data and accessibility values as iOS, additionally set `kSecUseDataProtectionKeychain=true`; use the app's default access group, `kSecAttrSynchronizable=false`, and no `SecAccessControl` flags. |
| Windows | Protect the raw 32-byte key with user-scope DPAPI `CryptProtectData`, description `mesh-messenger-v1`, optional entropy defined below, and `CRYPTPROTECT_UI_FORBIDDEN`; `CRYPTPROTECT_LOCAL_MACHINE` is forbidden. |
| Ubuntu | Store the raw 32-byte key in the unlocked default Secret Service collection as `application/octet-stream` with attributes `application=mesh-messenger-v1` and `database-id=` plus lowercase ID hex. It MUST NOT fall back to a different collection or plaintext file. |

Android stores one 86-byte wrapping record in the no-backup app-data directory:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | ASCII `MDA1` |
| 4 | 1 | version 1 |
| 5 | 1 | platform 1 |
| 6 | 2 | zero |
| 8 | 16 | `database_id` |
| 24 | 12 | fresh nonzero AES-GCM nonce |
| 36 | 2 | wrapped length, exactly 48 |
| 38 | 48 | 32-byte ciphertext and 16-byte tag |

AES-256-GCM associated data is `UTF8(L_DATABASE_WRAP_AAD) || record[0..38]`. Every rewrap uses a fresh nonce and atomically replaces the record. The nonce is reserved before encryption; eight collisions exhaust the operation. A missing alias, changed key properties, authentication failure, or key invalidation is a recovery event.

Windows stores `MDW1 || 0x01 || 0x02 || 0x0000 || database_id[16] || blob_length[4] || dpapi_blob`, with integers big-endian, `blob_length` in 1–16,384, and no trailing bytes. DPAPI optional entropy is `SHA-256(UTF8(L_DATABASE_WRAP_AAD) || database_id)`. Unprotect must return exactly 32 bytes and the stored ID must match; any UI request, scope mismatch, parse error, or unprotect error is a recovery event. DPAPI output remains opaque and is never reserialized by the application.

Linux systems without a working Secret Service MUST require the passphrase fallback in `CRYPTOGRAPHY_V1.md`; they MUST NOT store the raw key in a file or environment variable. A missing/invalidated wrapping key is a recovery event, not a request to open or reset the database silently.

Plaintext message history is retained for at most 10,080 minutes after its local durable commit under the accepted OS-clock model. The private database stores a `wall_highwater_minute`, initialized from local Unix time on creation. On each unlock and at least once per foreground minute, compare the current wall minute with that value. If current time is lower, set a durable `clock_rollback_detected` latch and delete every plaintext history row before display; otherwise replace the high-water value with current time. A sent or received history row records `history_expires_minute = wall_highwater_minute + 10,080`, rejecting overflow. When the high-water value reaches that deadline, the next unlocked transaction MUST delete the plaintext, UI row, event-to-envelope mapping, and delivery receipt state. A forward wall jump may delete early. If the app remains locked or stopped past a deadline, deletion occurs in the first unlock transaction before history is displayed. The rollback latch may be cleared only by explicit local reset after all pre-latch history is gone. Immediate conversation/account deletion remains authoritative. Undetectable OS/database rollback is outside the guarantee and is stated in `THREAT_MODEL.md`.

### 4.2 Relay database

The relay database is unencrypted because it must remain available while locked and contains only already sealed envelopes. Its complete allowed schema is: envelope bytes, envelope ID, total length, traffic class, locally observed first/last monotonic times, local expiry deadline, source transport class, forwarding bitset, and non-sensitive quota counters. Values copied from authenticated headers are untrusted until the unlocked core authenticates them; locked relay admission uses the structural/PoW rules only.

Clearing relay cache MUST NOT delete private chat history. Deleting a conversation MUST remove its private plaintext, MLS state, routing secrets, and local outbound mapping immediately; unrelated opaque relay copies remain until ordinary expiry or explicit cache clear.

## 5. Conversation and device rules

- A direct chat is exactly two fixed MLS members after bootstrap. Because it has no owner, every post-bootstrap membership-changing Proposal or Commit is rejected; only a member's own leaf Update is allowed.
- A private group has 2–16 members, including its immutable owner.
- Only the private-group owner credential may create a membership-changing Commit. Non-owner membership Commits MUST be rejected while retaining the last valid `ACTIVE` state. Members MAY make leaf updates; non-owner add/remove proposals are requests that only the owner may commit.
- There is at most one locally pending owner Commit. A later proposal is queued against the resulting epoch. Conflicting incoming owner Commits are resolved by RFC 9420 processing; an unreconciled valid-owner fork moves the conversation to `REPAIR_REQUIRED`, never an application-selected fork.
- Current epoch plus exactly three past epochs are retained. On merging the fourth newer epoch, the oldest past-epoch secrets are deleted. Time does not extend or shorten this limit.
- One root identity has exactly one explicitly accepted active device instance per contact and one leaf per group. No certificate is automatically “newest”; replacement occurs only through the contact-by-contact procedure in `CRYPTOGRAPHY_V1.md`.
- A root-signed device-replacement notice is only a pending signal, optionally carried through an old authenticated MLS session during planned rotation. Revocation becomes effective separately when a contact accepts replacement or a group owner removes/swaps the old leaf. There is no global broadcast revocation in v1.
- Recovery restores identity authority, not private storage, message history, contacts, group membership, or MLS state.
- Conversation states are `ACTIVE`, `REPAIR_REQUIRED`, `REMOVED`, `REINVITE_PENDING`, and `ABANDONED`. A valid owner removal atomically enters `REMOVED`, deletes all group cryptographic/routing state, and leaves only read-only locally retained history plus a non-secret tombstone. Rejoin uses a fresh owner invitation and preserves a visible history boundary; no deleted key or state returns. V1 has no automatic state-transfer or resynchronization message. The exact transitions and one-attempt bound are in `CRYPTOGRAPHY_V1.md`; transport sync moves opaque envelopes only.

## 6. Transport topology

All transports move the same complete v1 envelope or its specified fragments. Gateways use the envelope ID only as the lookup key, then apply the canonical-content comparison, mutable-field merge, and collision handling in `PROTOCOL_V1.md`; an ID alone never proves equality. They forward an admitted canonical envelope no more than once per destination transport instance. Transport-internal acknowledgements never authenticate a conversation peer.

| Platform | Phone-mesh BLE | WLAN/hotspot | Meshtastic |
|---|---|---|---|
| Android | foreground acceptance; optional later user-visible foreground service | foreground acceptance | BLE |
| iOS | foreground acceptance; background best-effort only | foreground acceptance | BLE |
| Windows | excluded | supported | serial/TCP |
| macOS | excluded | supported | serial/TCP |
| Ubuntu | excluded | supported | serial/TCP |

## 7. Frozen toolchain and dependency pins

The date-qualified baseline below is exact for DEC-001. Package manifests and lockfiles created by FND-002 MUST use equality pins or immutable revisions and MUST preserve upstream checksums.

| Item | Frozen revision | Decision/source |
|---|---|---|
| Flutter | 3.44.8 stable, Dart 3.12.2, framework commit `058e0af2c2b57e369d905a03ac9748b0ebf543c6` | [official archive](https://docs.flutter.dev/install/archive) |
| Dart | 3.12.2 bundled with Flutter 3.44.8, source commit `d684a576a6aa954ae107a03b2b4e1d61c3bebe93` | [official archive](https://docs.flutter.dev/install/archive), [official SDK source](https://github.com/dart-lang/sdk/tree/d684a576a6aa954ae107a03b2b4e1d61c3bebe93) |
| Rust/Cargo | 1.97.1 stable, source commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452` | [Rust 1.97.1 announcement](https://blog.rust-lang.org/2026/07/16/Rust-1.97.1/) |
| Rust edition | 2024 | toolchain decision; MSRV equals 1.97.1 for v1 |
| `flutter_rust_bridge` | 2.12.0 stable, commit `62b9330ed2f900535e34d8443ff82dc54070579a`; generator and runtimes match | [pub.dev versions](https://pub.dev/packages/flutter_rust_bridge/versions) |
| OpenMLS | `openmls-v0.8.1`, commit `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6`; `openmls_libcrux_crypto` from that workspace; draft extensions disabled | [official release](https://github.com/openmls/openmls/releases/tag/openmls-v0.8.1) |
| SQLCipher | 4.17.0, commit `810db22f575ee7cf94ea96a3e91622b5fcece3dc`, SQLite baseline 3.53.3 | [official release](https://www.zetetic.net/blog/2026/07/08/sqlcipher-4-17-0-release/) |
| Meshtastic schemas | `v2.7.26`, commit `da60cee584c6dc1efbb4a3809b98666505179b85` | [official release](https://github.com/meshtastic/protobufs/releases/tag/v2.7.26) |
| Meshtastic firmware | beta `v2.7.26.54e0d8d`, commit `54e0d8d0ab2ff56b3a9ce967e53f79e49af560fb` | [official release](https://github.com/meshtastic/firmware/releases/tag/v2.7.26.54e0d8d) |
| Noise | revision 34, `Noise_NN_25519_ChaChaPoly_SHA256`; `snow` 0.10.0 commit `4bb43f50370bdb3e8b1b57814ac662864db2704f` | [Noise specification](https://noiseprotocol.org/noise.html), [`snow` 0.10.0 docs](https://docs.rs/snow/0.10.0/snow/) |

Use `snow` with `default-features=false` and exactly `std`, `default-resolver`, `use-curve25519`, `use-chacha20poly1305`, `use-sha2`, and `use-getrandom`; do not enable alternative patterns, P-256, XChaChaPoly, AES-GCM, BLAKE, PSK, or ring-accelerated selection. `use-getrandom` is REQUIRED so production ephemeral keys come from the OS; fixed ephemeral keys are test-only. Upstream states that `snow` has not received a formal audit. Because Noise protects routing inventory even though MLS remains the end-to-end boundary, independent review must explicitly accept or reject this dependency before implementation.

### 7.1 Release-tag provenance

The following was resolved directly from each official Git remote on 2026-08-18. The direct target is the object ID stored at `refs/tags/<tag>`. An annotated tag has a separate tag object and a `refs/tags/<tag>^{}` dereferenced commit; a lightweight tag has no tag object, points straight to its commit, and cannot itself contain a tag signature. For lightweight tags the dereferenced commit below is therefore the direct ref target even when the remote does not advertise a separate peeled ref.

| Release | Tag | Type | Direct tag-ref target | Tag object ID | `refs/tags/<tag>^{}` commit | Tag-signature result |
|---|---|---|---|---|---|---|
| Flutter 3.44.8 | `3.44.8` | Lightweight | `058e0af2c2b57e369d905a03ac9748b0ebf543c6` | None | `058e0af2c2b57e369d905a03ac9748b0ebf543c6` | Not applicable; no tag object |
| Dart 3.12.2 | `3.12.2` | Annotated | `704629bcd35e8bc1dd6b4808b618cccbbbd8fb6a` | `704629bcd35e8bc1dd6b4808b618cccbbbd8fb6a` | `d684a576a6aa954ae107a03b2b4e1d61c3bebe93` | Unsigned annotated tag; local `git verify-tag` reports no signature |
| flutter_rust_bridge 2.12.0 | `v2.12.0` | Lightweight | `62b9330ed2f900535e34d8443ff82dc54070579a` | None | `62b9330ed2f900535e34d8443ff82dc54070579a` | Not applicable; no tag object |
| OpenMLS 0.8.1 | `openmls-v0.8.1` | Lightweight | `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6` | None | `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6` | Not applicable; no tag object |
| SQLCipher 4.17.0 | `v4.17.0` | Annotated | `f9788efa8ac4dfed75c03e4756b1666a1d0845da` | `f9788efa8ac4dfed75c03e4756b1666a1d0845da` | `810db22f575ee7cf94ea96a3e91622b5fcece3dc` | PGP signature present; local `git verify-tag` could not establish validity because public key fingerprint `2646E8ECC00DAF4C2F67DBCD19A0457D05EA8350` was unavailable from an authoritative Zetetic source; provenance gate remains open |
| Meshtastic protobufs 2.7.26 | `v2.7.26` | Lightweight | `da60cee584c6dc1efbb4a3809b98666505179b85` | None | `da60cee584c6dc1efbb4a3809b98666505179b85` | Not applicable; no tag object |
| Meshtastic firmware 2.7.26 | `v2.7.26.54e0d8d` | Lightweight | `54e0d8d0ab2ff56b3a9ce967e53f79e49af560fb` | None | `54e0d8d0ab2ff56b3a9ce967e53f79e49af560fb` | Not applicable; no tag object |
| Rust 1.97.1 | `1.97.1` | Annotated | `bd3cd8fdf9945e13d317642df03363bfa1b4c30e` | `bd3cd8fdf9945e13d317642df03363bfa1b4c30e` | `8bab26f4f68e0e26f0bb7960be334d5b520ea452` | Valid PGP signature from fingerprint `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`, verified with the [official Rust signing key](https://static.rust-lang.org/rust-key.gpg.ascii); local ownertrust was undefined |
| snow 0.10.0 | `v0.10.0` | Lightweight | `4bb43f50370bdb3e8b1b57814ac662864db2704f` | None | `4bb43f50370bdb3e8b1b57814ac662864db2704f` | Not applicable; no tag object |

The immutable source pin is always the dereferenced full commit, never the tag name. FND-002 MUST also record registry/archive checksums and official provenance attestations in lock/build manifests. A missing/moved ref, checksum disagreement, invalid signature, or unresolved SQLCipher signer key fails closed and requires an ADR amendment or signed provenance exception.

The bridge's Flutter 3.44/Android Gradle Plugin 9/Swift Package Manager compatibility remains unqualified. FND-002 MUST use CocoaPods for the bridge, Android Gradle Plugin 8.13.2, Gradle 8.13, JDK 17, Android Build Tools 36.0.0, and NDK `29.0.14206865`; it MUST NOT silently move to AGP 9 or bridge beta releases. Sources: [AGP 8.13 notes](https://developer.android.com/build/releases/agp-8-13-0-release-notes), [NDK downloads](https://developer.android.com/ndk/downloads), and the [bridge compatibility issue](https://github.com/fzyzcjy/flutter_rust_bridge/issues/3202).

## 8. Platform baseline

“Minimum” is the oldest promised runtime. “Current” is the upper acceptance target frozen on 2026-08-18, not a promise to track a moving label.

| Target | Minimum acceptance | Current acceptance | Build target |
|---|---|---|---|
| Android arm64 | Android 10 / API 29 | Android 17 / API 37, Pixel 8 build `CP2A.260805.005`, 2026-08-05 security level | minSdk 29, compileSdk/targetSdk 36; install the pinned API 37 image |
| iOS arm64 | iOS 16.7.16 | iOS 26.6 | Xcode 26.6 and its bundled iOS SDK; deployment target 16.0 |
| Windows x64 | Windows 11 24H2 | Windows 11 25H2 build 26200.9168 | Windows SDK 10.0.26100.0, Visual Studio 2022 17.14 toolset |
| macOS arm64 | macOS 12 Monterey | macOS 26.6 Tahoe | Xcode 26.6; deployment target 12.0 |
| Ubuntu x64 | Ubuntu 24.04.4 LTS | Ubuntu 24.04.4 LTS | Ubuntu 24.04.4 image, Clang 18, CMake 3.28, Ninja 1.11, GTK 3.24 |

Flutter itself lists Android API 24–37, iOS 15–26, Windows 10/11, macOS 12–26, and Ubuntu 20.04–24.04 LTS for the pinned generation. This product deliberately uses the narrower table above. Android 17 is a runtime compatibility target; the lab build remains target/compile API 36 because the pinned AGP/bridge combination is not qualified for an API-37 toolchain. Moving target/compile to 37 requires an ADR amendment after bridge qualification. The exact Pixel 8 (`shiba`) factory archive for `CP2A.260805.005` has Google-published SHA-256 `26ca3017652d5df8d5002a449ef079637061165de02396634514387602aad177`; HW-001 MUST verify the downloaded archive against it before flashing. Sources: [Flutter platform matrix](https://docs.flutter.dev/reference/supported-platforms), [Android 17/API 37](https://developer.android.com/about/versions/17), [Google Pixel factory images](https://developers.google.com/android/images), [August 2026 Android bulletin](https://source.android.com/docs/security/bulletin/2026/2026-08-01), [Xcode requirements](https://developer.apple.com/xcode/system-requirements), [Windows KB5121003](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/08/kb5121003-windows-11-24h2-25h2-security-update), [Ubuntu release list](https://wiki.ubuntu.com/Releases), and [Ubuntu 26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/).

## 9. Reference devices

Hardware acceptance MUST use actual inventory records; the models below are required targets, not a claim that the project owns them.

| Role | Frozen reference | Required software |
|---|---|---|
| Android floor phone | Google Pixel 4 (`flame`) | Android 10 build `QD1A.190821.014` |
| Android current phone | Google Pixel 8 (`shiba`) | Android 17 build `CP2A.260805.005`, 2026-08-05 security level |
| iOS floor phone | Apple iPhone 8 | iOS 16.7.16 |
| iOS current phone | Apple iPhone 15 | iOS 26.6 |
| Primary nRF52 radio A | LILYGO T-Echo EU868, SX1262, stock antenna | pinned Meshtastic beta firmware |
| Primary nRF52 radio B | RAK4631 EU868 module on RAK19007 base, matched EU868 antenna | pinned Meshtastic beta firmware |
| ESP32 compatibility radio | Heltec Wireless Stick V3 EU868, SX1262, matched EU868 antenna | pinned Meshtastic beta firmware |

Phone source references: [Google factory images](https://developers.google.com/android/images), [Android security bulletins](https://source.android.com/docs/security/bulletin/asb-overview), [iOS 16.7.16 security content](https://support.apple.com/en-us/127113), and [iOS 26.6 security content](https://support.apple.com/en-us/128066). Radio references: [T-Echo](https://github.com/Xinyuan-LilyGO/T-Echo), [RAK4631](https://docs.rakwireless.com/product-categories/wisblock/rak4631/overview/), and [Wireless Stick V3](https://heltec.org/project/wireless-stick-v3/).

Serial numbers, battery health, antenna gain, calibration, and measured performance are intentionally absent because no inventory inspection has occurred. HW-001 MUST record them; hardware acceptance stays `blocked` until then.

## 10. Meshtastic configuration

The only proposed radio profile is:

| Setting | Exact value |
|---|---|
| Region | `EU_868` |
| Modem preset | `LONG_FAST`, `use_preset=true` |
| Center/slot | frequency slot 1; nominal 869.525 MHz |
| Meshtastic hop limit | 3 |
| Transmit power | firmware regional default (`tx_power=0`), never override upward |
| Duty cycle | firmware regional default; override disabled |
| Frequency override | disabled (`0`) |
| MQTT uplink/downlink | disabled; packets marked not MQTT-originated |
| App port | `PRIVATE_APP` = 256 |
| Channel key | fresh random non-default channel key; never treated as end-to-end security |

EU_868/LONG_FAST documentation currently describes SF11, coding rate 4/5, 250 kHz bandwidth, nominal +27 dBm ERP, and a 10% duty-cycle profile. The software MUST read back and display the actual radio configuration before enabling send. Any mismatch disables app transmission. Firmware duty-cycle refusal supersedes application retry schedules. Sources: [LoRa configuration](https://meshtastic.org/docs/configuration/radio/lora/), [radio settings](https://meshtastic.org/docs/overview/radio-settings/), and [EU Decision 2025/105](https://eur-lex.europa.eu/eli/dec_impl/2025/105/oj/eng).

These settings are a technical proposal, not legal advice. Physical transmission is blocked until the signed RF record covers the actual country, venue, antenna, effective radiated power, and device conformity.

## 11. Logging and diagnostics

Release builds MUST emit no plaintext, recovery words, QR/contact payloads, keys, database paths containing user identifiers, stable identities, peer addresses, service-instance names, routing tags, envelope IDs, or radio payloads. Allowed diagnostics are version, coarse component state, aggregate count buckets, bounded error codes, and monotonic durations. Diagnostic export requires explicit user action, scans for seeded canaries, and excludes database files.

## 12. Gates

Implementation remains blocked until all ADRs and specifications are human-approved. Independently:

- security-sensitive implementation remains blocked until a new independent review resolves and accepts the preserved failed draft.1 findings and a human reviewer approves the corrected composition and reproduced v1 vectors;
- RF transmission remains blocked until hardware inventory and jurisdiction-specific compliance are signed;
- public/signed distribution remains blocked until qualified legal review resolves AGPL/store, linked dependencies, generated protobufs, notices/source obligations, cryptography distribution, privacy, and territorial requirements;
- release signing remains blocked until a human-owned key-custody, notarization, rotation, and incident process is approved;
- Ubuntu 26.04 support remains blocked until Flutter lists it or an amendment approves an independently qualified exception;
- target/compile SDK 37 remains blocked until the pinned Flutter/bridge/AGP combination is qualified or amended; Android 17 runtime compatibility is still required;
- Meshtastic beta firmware use remains blocked until the product owner accepts beta risk and all three physical radio families pass the matrix.

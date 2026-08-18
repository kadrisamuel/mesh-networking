# Phase 40 — WLAN and Bluetooth Connectivity

Mobile hardware-free acceptance is foreground operation. Android foreground relay is opt-in; iOS background behavior is observed and reported but is not a reliability gate.

## WLAN-001 — Validate cross-platform local discovery

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `FND-001`, `PLAT-001`, physical target devices  
**Allowed paths:** isolated probe under `tooling/probes/`, evidence under `tests/hardware/`

**Objective:** Select the implementation boundary for mDNS/DNS-SD from physical evidence rather than assumption.

**Implementation:** Build a minimal Rust discovery probe and run advertise/browse/resolve/reconnect in both directions on Android, iOS, Windows, macOS, and Ubuntu. If Rust discovery fails on a mobile platform, record the approved native fallback (`NsdManager` or Network.framework) in an ADR.

**Verification:** Signed device/OS result matrix and packet capture showing discovery behavior. Loopback or simulator-only results do not pass.

**Done when:** Every target has one chosen implementation path and known permission/firewall behavior.

## WLAN-002 — Implement the DNS-SD service contract

**Model:** `gpt-5.6-sol`  
**Effort:** medium  
**Human checkpoint:** Human review required before merge  
**Depends on:** `WLAN-001`, `DEC-001`  
**Allowed paths:** WLAN discovery module, discovery fixtures

**Objective:** Advertise compatibility without identity or relationship metadata.

**Implementation:** Use the approved stable service type, random per-launch instance name, minimal version TXT field, ephemeral port, strict TXT bounds, cancellation, and republish behavior.

**Verification:** Capture and parser tests for incompatible/extra/oversized fields, interface changes, restart, and simultaneous peers.

**Done when:** Captures contain no display name, identity key, boot history, routing tag, contact ID, or persistent instance value.

## WLAN-003 — Implement bounded TCP listener/client sessions

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `WLAN-002`, `RLY-006`  
**Allowed paths:** Rust WLAN transport, tests

**Objective:** Carry Noise records over IPv4/IPv6 with bounded hostile-client behavior.

**Implementation:** Add listeners/connectors, length-prefixed record pump, connection/session limits, timeouts, backpressure, graceful shutdown, and sync handoff. Support local IPv6 as well as IPv4.

**Verification:** Partial/coalesced writes, oversized lengths, slow client, eight concurrent peers, duplicate close, cancellation, interface loss, packet mutation, and 1 MiB session cap.

**Done when:** Memory/connections stay bounded and a packet capture reveals no inventory or envelope bytes.

## WLAN-004 — Resolve simultaneous connections and peer restarts

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `WLAN-003`  
**Allowed paths:** WLAN session arbitration, fixtures

**Objective:** Converge two peers to one session without exposing a stable discovery identifier.

**Implementation:** Exchange random per-launch `boot_id` only inside Noise, apply deterministic connection direction/tie-break, jitter reconnects, and clear stale sessions after peer/interface restart.

**Verification:** Simultaneous dial, two network interfaces, service republish, boot-ID collision fixture, peer restart, and livelock bounds.

**Done when:** Exactly one live session remains and `boot_id` is neither advertised nor persisted.

## WLAN-005 — Integrate Apple local-network permissions

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `WLAN-001`, `WLAN-004`  
**Allowed paths:** iOS/macOS plugin/project settings, Apple integration tests

**Objective:** Make declared Bonjour/local-network access work and fail transparently.

**Implementation:** Add approved usage text/service declaration, permission/capability mapper, Network.framework fallback if mandated by `WLAN-001`, and denial/revocation behavior. Do not request broader entitlements without recorded need.

**Verification:** Physical iOS allow/deny/revoke/reinstall, app restart, hotspot/AP, and signed-development macOS firewall/local-network tests.

**Done when:** Denial produces a typed degraded state without retry loops and WLAN can be re-enabled after permission recovery.

## WLAN-006 — Integrate Android local-network discovery

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `WLAN-001`, `WLAN-004`  
**Allowed paths:** Android plugin/manifest, integration tests

**Objective:** Support the approved Android API range and evolving local-network permission states.

**Implementation:** Add native `NsdManager` fallback if required, multicast-lock lifecycle if proven necessary, versioned permission mapper, and explicit allow/deny/revoke handling for the pinned target SDK.

**Verification:** API 29, representative middle version, current target, allow/deny, app standby, interface change, Android/iPhone hotspot, and ordinary AP.

**Done when:** WLAN succeeds where supported and permission denial never blocks non-WLAN app use.

## WLAN-007 — Run WLAN interoperability and latency acceptance

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `WLAN-005`, `WLAN-006`, `RLY-005`  
**Allowed paths:** performance/hardware scenarios and evidence only

**Objective:** Validate the frozen 100-message WLAN profile on real devices.

**Verification:** Run Android↔iOS, mobile↔each desktop OS, ordinary AP, Android hotspot, and iPhone hotspot as defined by `TEST_MATRIX.md`; include failures as infinite latency in p95 and report delivery separately.

**Done when:** Required shared-WLAN pairs meet p95 under five seconds; hotspot support is reported per host OS and never generalized.

## BLE-001 — Freeze GATT and link-record fixtures

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human approval required before implementation  
**Depends on:** `DEC-001`, `BR-004`  
**Allowed paths:** `docs/spec/`, BLE fixtures

**Objective:** Define one interoperable phone-to-phone BLE service without identity-bearing advertisements.

**Implementation:** Specify fixed service UUID, RX write and TX notify characteristics, record lengths, MTU segmentation, sequencing, backpressure, peer limits, errors, reconnect boundary, and golden fixtures. A per-launch ID is exchanged only after Noise starts.

**Verification:** Independent fixture parser review and malformed-sequence corpus.

**Done when:** Android and iOS can implement solely from the spec and fixtures; no rotating manufacturer/local-name data is required.

## BLE-002 — Create the federated BLE plugin and fake backend

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review required before merge  
**Depends on:** `BLE-001`, `PLAT-001`  
**Allowed paths:** `packages/mesh_platform/` BLE interface/fakes and platform package shells

**Objective:** Expose typed central/peripheral events and opaque record bytes to Flutter/Rust.

**Implementation:** Add platform interface, Android/iOS packages, fake backend, capability/errors, cancellation, and session generation. Desktop returns `unsupported` for phone mesh.

**Verification:** Plugin contract/lifecycle tests and fake end-to-end `BR-004` session.

**Done when:** No native/Dart API carries a key, message plaintext, routing tag, or decoded envelope.

## BLE-003 — Implement Android permissions and capability mapping

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `BLE-002`  
**Allowed paths:** Android plugin/manifest/tests

**Objective:** Request only required permissions and distinguish all unavailable states.

**Verification:** API 29, 31, 33, and current permission matrices for denied, permanently denied, Bluetooth off, unsupported advertise, and background restriction.

**Done when:** Location is not requested on versions/configurations where approved `neverForLocation` behavior applies.

## BLE-004 — Implement Android advertiser and GATT server

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `BLE-003`  
**Allowed paths:** Android BLE server implementation/tests

**Objective:** Accept bounded peer writes and deliver notification records reliably.

**Implementation:** Add fixed-service advertisement, GATT server, RX assembly, TX subscriptions, MTU-aware segmentation, per-peer queues, limits, backpressure, and idempotent cleanup.

**Verification:** Unit tests plus physical Android transfer at MTU 23 and a larger negotiated MTU, queue-full, malformed sequence, disconnect, and Bluetooth toggle.

**Done when:** No truncation, unbounded queue, stale callback, or identity-bearing advertisement occurs.

## BLE-005 — Implement Android scanner and GATT client

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `BLE-003`, `BLE-004`  
**Allowed paths:** Android BLE client/tests

**Objective:** Find only the exact service and reconnect at record boundaries.

**Implementation:** Add filtered scanning, connection queue, service/characteristic validation, GATT operation serialization, write/notify path, timeouts, and reconnect.

**Verification:** Missing characteristic, wrong service, disconnect mid-record, dual role, rapid restart, Bluetooth toggle, and physical Android↔Android tests.

**Done when:** Reconnect never duplicates a logical envelope and GATT operations never overlap incorrectly.

## BLE-006 — Add the opt-in Android foreground relay service

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `BLE-005`, `APP-009`  
**Allowed paths:** Android service/notification/lifecycle tests

**Objective:** Relay only while the user-visible service is explicitly active.

**Verification:** Screen off, app swipe, process recreation, battery saver, user stop, permission revocation, and reboot policy on physical devices.

**Done when:** There is no hidden auto-start or attempt to bypass background-service restrictions.

## BLE-007 — Implement iOS permissions and project configuration

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `BLE-002`  
**Allowed paths:** iOS plugin/project settings/tests

**Objective:** Configure central/peripheral roles and accurately expose foreground/background limitations.

**Verification:** Physical allow/deny/revoke, Bluetooth off, app restart, and WLAN fallback tests.

**Done when:** The app remains usable without BLE and makes no uninterrupted-background claim.

## BLE-008 — Implement iOS peripheral mode

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human execution required and review required before merge  
**Depends on:** `BLE-007`, `BLE-001`  
**Allowed paths:** iOS peripheral implementation/tests

**Objective:** Publish the fixed service and deliver bounded notifications under Core Bluetooth lifecycle rules.

**Verification:** Physical foreground iPhone transfer, subscription changes, queue-full recovery, app background/foreground observation, and process restoration where supported.

**Done when:** Foreground transfer is reliable and degraded background behavior is surfaced, not hidden.

## BLE-009 — Implement iOS central mode and restoration

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human execution required and review required before merge  
**Depends on:** `BLE-007`, `BLE-008`  
**Allowed paths:** iOS central implementation/tests

**Objective:** Scan by service UUID, connect, validate, subscribe, and survive permitted lifecycle changes.

**Verification:** Foreground/background scan observation, connection loss, stale peripheral, service mismatch, notification split, state restoration, and physical iOS↔iOS tests.

**Done when:** Delayed discovery/restoration cannot corrupt record/session state and background scanning always uses the service UUID.

## BLE-010 — Integrate dual roles and encrypted session arbitration

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human review required before merge  
**Depends on:** `BLE-005`, `BLE-009`, `BR-004`, `RLY-006`  
**Allowed paths:** cross-platform BLE session coordinator/tests

**Objective:** Resolve simultaneous Android/iOS connections and feed exactly one Noise record stream to Rust.

**Implementation:** Start both roles, exchange encrypted per-launch IDs, choose canonical direction, close duplicates, handle split records, and resynchronize after restart.

**Verification:** Android↔iOS simultaneous dial, iOS↔iOS, dual connections, boot-ID collision fixture, app restart, and message dedupe.

**Done when:** Peers converge to one live session and one received logical message.

## BLE-011 — Run physical BLE and battery acceptance

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `BLE-006`, `BLE-010`, `PERF-001`  
**Allowed paths:** hardware/performance evidence only

**Objective:** Execute the approved foreground latency, compatibility, and active-relay battery profiles.

**Verification:** Android↔Android, Android↔iOS, iOS↔iOS within ten metres; 100-message profile; eight-hour Android foreground-service and iOS active-app observations on pinned phones.

**Done when:** Foreground p95 is under fifteen seconds and battery results are reported separately with device, OS, health, screen state, load, and variation. Background results remain observational.

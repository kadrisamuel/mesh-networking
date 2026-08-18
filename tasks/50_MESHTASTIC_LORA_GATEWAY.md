# Phase 50 — Meshtastic, LoRa, and Gateway Routing

Read the pinned Meshtastic schemas and official PhoneAPI reference chosen by `DEC-001`. Never copy firmware/client implementation code. Physical RF work requires a completed `HW-001` manifest and `EU-003` checklist.

## MT-001 — Prove PRIVATE_APP compatibility on reference radios

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `HW-001`; disposable configured radios available  
**Allowed paths:** isolated probe and `tests/hardware/meshtastic/` evidence

**Objective:** Confirm that pinned firmware transports opaque private application payloads before building the adapter.

**Implementation:** Send and receive bounded `PRIVATE_APP` payloads through T-Echo, RAK4631, and the selected ESP32/SX1262 radio; capture BLE/serial/TCP PhoneAPI traces; record firmware/config/channel/hop behavior and payload limits.

**Verification:** Each hardware pair broadcasts and receives a unique opaque fixture; a multi-hop forward is observed; incompatibilities remain explicit blockers.

**Done when:** The selected firmware/device matrix has reproducible traces and no task relies on an assumed maximum.

## MT-002 — Pin Meshtastic schemas and generated bindings

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review required before merge  
**Depends on:** `FND-002`, schema revision from `DEC-001`  
**Allowed paths:** `rust/crates/mesh-meshtastic/`, protobuf generation tooling, notices

**Objective:** Generate reproducible Rust types from one reviewed Meshtastic protobuf revision.

**Implementation:** Pin commit/hash, generate with the approved tool, include schema/license notices, expose schema hash, and add an update script that produces a reviewable diff.

**Verification:** Two regenerations are identical; changed schema hash fails CI; license scanner passes.

**Done when:** No generated type is hand-edited and upstream drift cannot enter silently.

## MT-003 — Implement serial/TCP StreamAPI framing

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `MT-002`  
**Allowed paths:** Meshtastic stream codec/tests/fuzz target

**Objective:** Parse and write the pinned StreamAPI framing safely over arbitrary byte streams.

**Implementation:** Implement magic/length framing, approved protobuf limit, partial/coalesced input, corruption resynchronization, bounded scanning/allocation, and typed errors.

**Verification:** Golden traces, every truncation point, garbage prefixes, oversized length, repeated magic, slow stream, and fuzz corpus.

**Done when:** Parser recovers after bounded garbage and never allocates before validating length.

## MT-004 — Implement BLE PhoneAPI framing

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `MT-002`, `BLE-002`, `MT-001` traces  
**Allowed paths:** Meshtastic BLE profile and tests

**Objective:** Expose the same logical `ToRadio`/`FromRadio` events as StreamAPI without applying stream framing to BLE.

**Implementation:** Implement pinned service/characteristics, writes, notification/drain policy, queue-empty state, disconnect/reconnect, operation serialization, and recorded-trace playback.

**Verification:** Physical traces, empty queue, repeated notification, split characteristic value, wrong service, and disconnect tests.

**Done when:** BLE and serial/TCP feed byte-equivalent protobuf events into one PhoneAPI state machine.

## MT-005 — Implement the PhoneAPI configuration handshake

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human review required before merge  
**Depends on:** `MT-003`, `MT-004`  
**Allowed paths:** Meshtastic PhoneAPI state machine/tests

**Objective:** Reach ready state only after a matching, complete, bounded radio configuration exchange.

**Implementation:** Add request ID/nonce, config and node drain, completion matching, timeout, reconnect, bounded NodeDB, unexpected-message handling, and read-only initial behavior.

**Verification:** Golden BLE/stream traces, missing/stale/mismatched completion, out-of-order records, huge NodeDB, duplicate completion, reboot, and reconnect.

**Done when:** Commands cannot transmit until the exact handshake reaches ready state.

## MT-006 — Map hybrid envelopes to PRIVATE_APP packets

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `MT-001`, `MT-005`, `LR-001`  
**Allowed paths:** Meshtastic packet adapter/tests

**Objective:** Send and receive only versioned hybrid LoRa frames through the private application port.

**Implementation:** Map approved private port, broadcast address, hop limit three, generated nonzero packet IDs, payload bound, application magic/version filter, and duplicate MeshPacket handling.

**Verification:** Wrong port, magic/version, over-limit payload, zero ID, duplicate ID, decoded/encrypted firmware variants, and physical packet trace.

**Done when:** Unrelated private-port traffic never reaches hybrid reassembly and Meshtastic channel crypto is never treated as E2E security.

## MT-007 — Implement radio queue and send lifecycle

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `MT-005`, `MT-006`  
**Allowed paths:** radio send queue/state/tests

**Objective:** Distinguish queued, radio accepted, radio rejected, and recipient-delivered state.

**Implementation:** Add bounded local queue, queue-status handling, routing errors, timeout, reboot recovery, duplicate callback handling, and metrics. Broadcast packets use the approved no-ACK setting.

**Verification:** Full queue, stale status, timeout, disconnect, reboot, callback duplication, and fake delivered callback injection.

**Done when:** No local/radio event can produce recipient `delivered`.

## MT-008 — Implement mobile Meshtastic BLE connection

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `MT-004`, `BLE-005`, `BLE-009`  
**Allowed paths:** mobile radio connector/native BLE tests

**Objective:** Connect a selected radio without disabling phone-to-phone BLE roles.

**Implementation:** Add exact radio profile discovery, explicit user selection, per-peripheral GATT operation queue, simultaneous app-mesh/radio operation, reconnect, and capability errors.

**Verification:** Physical Android/iOS radio pairing, wrong device, both BLE roles active, disconnect/reconnect, and app restart.

**Done when:** A radio connection does not silently stop phone advertising/scanning or leak raw payloads to Dart.

## MT-009 — Expose the typed RadioService facade

**Model:** `gpt-5.6-sol`  
**Effort:** medium  
**Human checkpoint:** Human review required before merge  
**Depends on:** `MT-005`, `MT-007`, `MT-008`  
**Allowed paths:** `mesh-api/`, `mesh-meshtastic/`, FFI schemas

**Objective:** Present discover/connect/disconnect/configuration/send state without protobufs in Flutter.

**Implementation:** Add typed commands/events, connector selection, concurrent-command rejection, config snapshot, firmware/schema compatibility, and set-unset-region command guarded by `EU-001`.

**Verification:** Fake connector switching, restart, command collision, unsupported firmware, and FFI round-trip tests.

**Done when:** Flutter handles no protobuf, raw PhoneAPI record, radio key, or opaque payload.

## MT-010 — Implement desktop serial and TCP connectors

**Model:** `gpt-5.6-sol`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `MT-003`, `MT-005`, `DSK-002`  
**Allowed paths:** desktop connector implementation/tests

**Objective:** Feed serial and explicit LAN-radio endpoints into the identical PhoneAPI state machine.

**Implementation:** Add safe port enumeration, stable descriptors, open/close/unplug/replug, explicit TCP endpoint, timeouts, and no arbitrary LAN scanning.

**Verification:** Fake serial, loopback TCP, physical radio on each desktop OS, unplug/replug, stale path, denied permission, and connection loss.

**Done when:** Both connectors expose identical typed radio events and never change OS permissions automatically.

## LR-001 — Freeze the LoRa application-frame format

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human approval required before implementation  
**Depends on:** `DEC-001`, `MT-001`, `RLY-001`  
**Allowed paths:** `docs/spec/PROTOCOL_V1.md`, LoRa golden fixtures

**Objective:** Define a fixed private payload that safely fragments an opaque envelope.

**Implementation:** Freeze magic/version, transfer ID, index/count, fragment length, flags, complete-envelope length/hash binding or corruption check, data and random padding. Recommended approved baseline: exactly 180 bytes, at most 160 data bytes, 1–10 fragments, envelope at most 1,536 bytes.

**Verification:** Independent encoders produce identical vectors and exact-size assertions for every count/boundary.

**Done when:** Reserved values, validation order, authentication limitations, and collision behavior are fully specified. A CRC, if present, is explicitly non-authenticating.

## LR-002 — Implement LoRa fragmentation and reassembly

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `LR-001`  
**Allowed paths:** LoRa frame codec/tests/fuzz target

**Objective:** Transform eligible envelopes into exact frames and reassemble only complete consistent envelopes.

**Verification:** Property tests for every length 1 through the approved maximum, reorder/drop/duplicate/mutation/conflicting metadata, every truncation, reserved fields, and fuzzing.

**Done when:** Reassembly yields exactly one original envelope or a typed failure and never partially emits data.

## LR-003 — Implement the bounded incomplete-transfer cache

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `LR-002`, `RLY-004`  
**Allowed paths:** LoRa reassembly cache/migrations/tests

**Objective:** Bound fragment floods by source, transfer, memory, disk, and time.

**Implementation:** Key by approved source/transfer identity, validate before allocation, apply per-source/global counts and bytes, TTL, conflict rejection, deterministic eviction, and restart cleanup.

**Verification:** Fragment flood, collision, conflicting count/length, sparse fragments, expiry, restart, source churn, and memory/disk assertions.

**Done when:** Incomplete data cannot grow beyond approved caps or persist indefinitely.

## LR-004 — Implement the LoRa send scheduler and retry policy

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human approval required before implementation  
**Depends on:** `LR-002`, `MT-007`, `RLY-008`, `EU-002`  
**Allowed paths:** LoRa scheduler/tests

**Objective:** Schedule fragments without ACK storms, starvation, or regulatory bypass.

**Implementation:** Apply frozen priorities, queue/utilization backoff, expiry cancellation, direct-message whole-envelope retry rule, group no-retry rule, and control-traffic reservation. Never add fragment ACK broadcasts.

**Verification:** Saturation, expiry mid-send, delayed authenticated receipt, queue error, group/direct profiles, near-duty limit, and exact attempt-count tests.

**Done when:** Attempt counts and timing match the spec, firmware duty enforcement stays enabled, and larger envelopes remain for faster transports.

## LR-005 — Integrate the LoRa envelope adapter

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `LR-003`, `LR-004`, `MT-006`  
**Allowed paths:** LoRa adapter/relay integration/tests

**Objective:** Carry eligible complete outer envelopes through Meshtastic without truncation or re-encryption.

**Verification:** Maximum and maximum+1 boundaries, corrupt fragment, duplicate complete envelope, wrong magic, adapter restart, and waiting-for-faster-link state.

**Done when:** Ineligible 1,537–4,096-byte envelopes remain available to BLE/WLAN and the UI receives a typed limitation.

## GW-001 — Implement the transport supervisor

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `RLY-007`, `WLAN-004`, `BLE-010`, `LR-005`  
**Allowed paths:** core transport supervisor/tests

**Objective:** Manage independent adapter lifecycles and report partial capability accurately.

**Implementation:** Add registration, start/stop, source metadata, health, restart/backoff, cancellation, and event isolation.

**Verification:** Adapter crash/restart, partial availability, app lock/shutdown, duplicate registration, and event flood.

**Done when:** One failed transport cannot stop or falsely degrade the others.

## GW-002 — Enforce gateway bridge and loop policy

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human review required before merge  
**Depends on:** `GW-001`, `RLY-007`  
**Allowed paths:** gateway policy and simulator scenarios

**Objective:** Validate complete envelopes and forward each at most once per transport/retention window.

**Implementation:** Reassemble transport records first, apply envelope admission, dedupe by common ID, exclude immediate source, track per-transport forwarding, enforce quotas, and discard raw fragments after their transport layer.

**Verification:** BLE↔WLAN, WLAN↔LoRa, three-gateway cycle, replay, corrupt frame, adapter restart, and bounded-event trace.

**Done when:** Gateway loops terminate and gateway code never opens private storage or decrypts relay payloads.

## GW-003 — Add user-visible gateway modes

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review recommended  
**Depends on:** `GW-002`, `APP-009`  
**Allowed paths:** gateway state/API/UI integration/tests

**Objective:** Offer foreground mobile, Android foreground-service, and desktop always-on modes honestly.

**Verification:** Toggle, restart, permission loss, app lock, radio disconnect, and unsupported iOS background state.

**Done when:** No hidden background service exists and current operating mode is visible.

## EU-001 — Implement EU_868 region readback policy

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `MT-009`, approved radio policy  
**Allowed paths:** radio policy/core/UI fixtures

**Objective:** Block transmit unless the radio reports the pilot region and duty override remains disabled.

**Implementation:** Read config; allow an explicit human-confirmed change only from UNSET to EU_868; never overwrite an existing region, channel, modem preset, power, or duty setting; verify readback.

**Verification:** Physical and fake UNSET/EU/other region, failed write/readback, duty override true, reconnect, and stale config.

**Done when:** Transmit enables only after approved readback and configuration changes are audit-visible without sensitive values.

## EU-002 — Implement airtime and congestion backoff

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `EU-001`, `MT-007`  
**Allowed paths:** radio metrics/backoff policy/tests

**Objective:** Stay below the human-approved application-originated budget and never bypass firmware controls.

**Verification:** Near-limit utilization, stale/missing metrics, clock shift, queue saturation, priority reservation, reconnect, and conservative fallback.

**Done when:** The app backs off or blocks rather than disabling firmware duty-cycle enforcement.

## EU-003 — Complete the radio-compliance checklist

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `HW-001`, `EU-002`  
**Allowed paths:** `docs/operations/RADIO_COMPLIANCE.md`, signed hardware evidence

**Objective:** Record the actual country/venue, hardware, firmware, antenna, region, preset, power, duty setting, and RF method before transmission tests.

**Verification:** A human completes and signs one checklist per hardware family and confirms a lawful/shielded test setup.

**Done when:** Incomplete legal or equipment facts block RF tests; the document makes no certification or EU-wide legal claim.

## DSK-001 — Freeze and build desktop target baselines

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `CI-002`, `BR-005`  
**Allowed paths:** desktop project/build configuration and smoke tests

**Objective:** Produce buildable baselines for the exact Windows, macOS, and Ubuntu versions selected by `DEC-001`.

**Verification:** Clean release build and launch on each physical/VM target; report the capability matrix. Unverified architectures are not claimed.

**Done when:** Each desktop app starts, locks, displays/imports QR data, uses WLAN, and can host a radio connector.

## DSK-002 — Implement desktop serial discovery and permission guidance

**Model:** `gpt-5.6-sol`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `DSK-001`  
**Allowed paths:** desktop platform adapter and documentation/tests

**Objective:** Enumerate stable radio choices and explain permission failures without changing OS configuration.

**Verification:** Fake port and physical Windows/macOS/Ubuntu tests for unplug, stale path, denied access, and replug.

**Done when:** Users can reconnect where enumeration supports it and the app never modifies groups, udev, or firewall settings automatically.

## GW-004 — Execute the mixed-route hardware demonstration

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `GW-003`, `EU-003`, `PERF-001`, all reference transports/radios  
**Allowed paths:** hardware scenarios and evidence only

**Objective:** Demonstrate A→BLE courier→WLAN gateway→controlled three-hop LoRa→recipient with reproducible evidence.

**Verification:** Run the frozen sample size, 10% loss-injection layer, timeout, topology, payload, and retry profile; include gateway restart, duplicate, and reorder cases.

**Done when:** At least the approved delivery target is met within five minutes, traces contain only opaque IDs/hashes, and every radio/compliance manifest is attached.

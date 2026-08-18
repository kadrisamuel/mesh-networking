# Phase 30 — Application and Rust/Dart Bridge

Flutter contains presentation and platform integration only. Security, message, relay, and delivery rules remain in Rust.

## PLAT-001 — Define the platform capability contract

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review required before merge  
**Depends on:** `FND-001`, `DEC-001`  
**Allowed paths:** `mesh-api/`, Flutter platform DTOs, capability fixtures

**Objective:** Represent support honestly across every OS and lifecycle state.

**Implementation:** Define typed capabilities for BLE central/peripheral, WLAN discovery/listening, radio BLE/serial/TCP, foreground/background relay, notifications, camera, biometrics, and secure storage. States must include `supported`, `foregroundOnly`, `degraded`, `permissionDenied`, `temporarilyUnavailable`, and `unsupported` with typed reason/action.

**Verification:** Exhaustive enum/serialization tests and an approved platform matrix fixture.

**Done when:** UI cannot enable an unsupported capability or infer support from platform name alone.

## BR-001 — Establish the Flutter/Rust bridge smoke path

**Model:** `gpt-5.6-terra`  
**Effort:** low  
**Human checkpoint:** AI-verifiable  
**Depends on:** `FND-001`, `FND-002`  
**Allowed paths:** `rust/crates/mesh-ffi/`, bridge configuration, generated binding subtree, Flutter core adapter

**Objective:** Prove reproducible generated calls on the host platform.

**Implementation:** Configure pinned `flutter_rust_bridge`; export `coreVersion()` and `healthCheck()` only; add one regeneration command and generated banner.

**Verification:** Rust unit test, Dart binding test, two clean regenerations, and debug host build.

**Done when:** Flutter receives the pinned protocol/core version and no generated file is hand-edited.

## BR-002 — Define typed bridge DTOs and commands

**Model:** `gpt-5.6-sol`  
**Effort:** medium  
**Human checkpoint:** Human review required before merge  
**Depends on:** `BR-001`, `PLAT-001`, stable `mesh-api`  
**Allowed paths:** public API/FFI schemas, generated bindings

**Objective:** Expose the minimum typed product surface without exporting secrets or internal persistence types.

**Implementation:** Add versioned IDs, timestamps, snapshots, commands, events, capabilities, message states, and structured errors. Binary values must be bounded wrappers. Secret-bearing Rust types must be impossible to export.

**Verification:** Boundary/unknown enum, error, optional value, maximum byte field, and cross-language round-trip tests.

**Done when:** No dynamic maps, raw JSON commands, stringly errors, pointers, keys, MLS objects, or database handles cross the boundary.

## BR-003 — Implement bounded event streaming and resynchronization

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `BR-002`  
**Allowed paths:** `mesh-api/`, `mesh-ffi/`, Flutter event adapter tests

**Objective:** Deliver state changes without unbounded memory or silent loss.

**Implementation:** Add bounded event sequence, cancellation, subscriber generation, overflow policy, `ResyncRequired`, snapshot refresh, and idempotent reconnect.

**Verification:** Slow consumer, 10,000-event burst, cancellation, duplicate subscription, core restart, stale sequence, and terminal security-event tests.

**Done when:** A lagging UI can recover persisted truth and critical terminal events are never silently discarded.

## BR-004 — Implement the external-transport byte pump

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `BR-003`, `RLY-006`  
**Allowed paths:** FFI transport API, platform-plugin interface, fake transport

**Objective:** Let native BLE carry opaque Noise/session records while Rust owns parsing and synchronization.

**Implementation:** Add typed open/bytes/writable/closed inputs and Rust `TransportAction` outputs; enforce peer handles, session generations, record bounds, backpressure, cancellation, and idempotent close.

**Verification:** Fake Dart transport completes a Noise sync; split/coalesced/oversized records, stale handle, slow write, duplicate close, and restart tests pass.

**Done when:** Native/Dart layers cannot parse envelope or session plaintext and allocations are bounded before accepting lengths.

## BR-005 — Enforce binding reproducibility and compatibility

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** AI-verifiable  
**Depends on:** `BR-004`  
**Allowed paths:** binding tooling, ABI manifest, CI

**Objective:** Detect stale code generation and incompatible app/core combinations.

**Implementation:** Add one regeneration command, clean-tree check, ABI/protocol version handshake, and compatibility fixture.

**Verification:** Regenerate twice, modify one generated file and confirm CI failure, then run old/new version rejection tests.

**Done when:** Startup fails with a typed explanation rather than using incompatible bindings.

## APP-001 — Build the Flutter application shell

**Model:** `gpt-5.6-terra`  
**Effort:** low  
**Human checkpoint:** Human review recommended  
**Depends on:** `BR-002`  
**Allowed paths:** `app/mesh_app/` shell, routes, theme, localization foundation

**Objective:** Provide stable navigation and state boundaries without product logic in widgets.

**Implementation:** Use the framework frozen by `DEC-001`; add routes, dependency scopes, theme, localization, lifecycle observer, error boundary, and placeholder screens.

**Verification:** Startup, route, unknown-route, restoration, light/dark, and basic accessibility widget tests.

**Done when:** Every MVP screen has a reachable placeholder and no widget talks directly to FFI or native plugins.

## APP-002 — Add repositories, reducers, and a deterministic fake core

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review required before merge  
**Depends on:** `APP-001`, `BR-003`  
**Allowed paths:** Flutter data/state layer, fake core fixtures

**Objective:** Make every UI state testable without a second device or radio.

**Implementation:** Add UI-facing repositories, event-to-state reducers, snapshot resync, typed retries, and a scriptable fake implementation using v1 fixtures.

**Verification:** Loading/error/retry, stale event, event burst, resync, app restart, and deterministic golden-state tests.

**Done when:** UI feature tasks can use the fake without duplicating Rust business rules.

## APP-003 — Implement identity onboarding

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `APP-002`, `ID-001`  
**Allowed paths:** onboarding UI/tests only

**Objective:** Create or restore an identity and require proof that the recovery code was recorded.

**Implementation:** Add create/restore choice, protected 24-word display, randomized confirmation challenge, interruption recovery, explicit limitations, and completion state.

**Verification:** Incorrect/missing words, background/screenshot masking, cancellation, restore errors, localization layout, and screen-reader tests. A human reviews wording and physical-device behavior.

**Done when:** Setup cannot finish without correct confirmation and recovery words are not copied or logged by default.

## APP-004 — Implement app lock and privacy lifecycle

**Model:** `gpt-5.6-sol`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `APP-003`, `STO-006`  
**Allowed paths:** lock UI, lifecycle/native snapshot protection, tests

**Objective:** Hide private UI before OS snapshots and accurately represent unlock methods.

**Implementation:** Add lock/unlock, approved timeout, biometric/passphrase fallback states, pre-background privacy screen, cancellation, and unrecoverable-local-data path. Key derivation remains native/Rust.

**Verification:** Physical mobile/desktop background snapshots, timeout, OS lock, failed/cancelled unlock, unsupported biometrics, process restart.

**Done when:** Conversation content never appears in an OS task-switcher snapshot after locking begins.

## APP-005 — Implement contacts, QR, and safety-number UI

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `APP-002`, `ID-003`, `MLS-002`  
**Allowed paths:** contact UI, camera/import adapter, tests

**Objective:** Pair and verify contacts without exposing invitation data.

**Implementation:** Add expiring QR display/scan, desktop encoded-file import, camera denial path, safety-number comparison, duplicate/root-change warnings, and consumed-invite feedback.

**Verification:** Physical scan/display, malformed/version/oversized QR, replay, duplicate contact, changed root, denied camera, and no-camera desktop behavior.

**Done when:** Camera frames/QR strings never enter logs or persistent UI state and pairing results come only from verified core responses.

## APP-006 — Implement direct-conversation UI

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review recommended  
**Depends on:** `APP-002`, `MLS-003`, `RLY-008`  
**Allowed paths:** conversation list/direct chat UI/tests

**Objective:** Compose and render direct text messages with truthful delivery states.

**Implementation:** Add list, transcript, 512-byte UTF-8 counter, composer, queued/relayed/delivered/expired/waiting-for-faster-link display, resend policy from core, and empty/error states.

**Verification:** Multibyte limit, duplicate events, out-of-order arrival, expiry, restart, long text layout, lock transition, and accessibility tests.

**Done when:** One logical message renders once and radio acceptance never appears as recipient delivery.

## APP-007 — Implement private-group UI

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review required before merge  
**Depends on:** `APP-006`, `MLS-004`  
**Allowed paths:** group UI/tests

**Objective:** Create and use owner-controlled invitation-only groups up to 16 members.

**Implementation:** Add creation, invitation, member list, owner-only removal, offline/pending state, limit feedback, and accepted-by-mesh state. Hide owner succession, read receipts, and per-member delivery.

**Verification:** Non-owner action, seventeenth member, removed member, delayed epoch, duplicate event, owner loss warning, and accessibility tests.

**Done when:** UI cannot initiate a forbidden policy action and does not promise unsupported owner recovery.

## APP-008 — Implement the connectivity dashboard

**Model:** `gpt-5.6-terra`  
**Effort:** low  
**Human checkpoint:** Human review recommended  
**Depends on:** `PLAT-001`, `APP-002`  
**Allowed paths:** connectivity UI/tests

**Objective:** Explain BLE, WLAN, relay, radio, permissions, and lifecycle limitations accurately.

**Verification:** Every capability and error fixture renders with an action or clear limitation; unsupported features cannot be toggled.

**Done when:** iOS foreground-only/best-effort background behavior and desktop BLE exclusion are plainly visible.

## APP-009 — Implement relay and storage controls

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review recommended  
**Depends on:** `APP-008`, `RLY-004`  
**Allowed paths:** settings UI/tests

**Objective:** Let users opt into relaying, inspect bounded cache usage, and clear relay ciphertext independently of conversations.

**Verification:** Empty/full cache, concurrent clear, relay disabled, locked mode, quota warning, and restart tests.

**Done when:** Controls cannot delete conversation history accidentally or imply that relayed content was readable.

## APP-010 — Implement radio setup UI

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `APP-008`, `MT-009`, `EU-001`  
**Allowed paths:** radio UI/tests

**Objective:** Discover/connect a supported radio and prevent transmission until safe readback succeeds.

**Verification:** Physical radio discovery, unsupported firmware, wrong/unset region, explicit confirmation, failed readback, disconnect, and denied permission.

**Done when:** UI never silently changes an existing region/channel/preset/power and transmit remains disabled until the approved configuration is confirmed.

## APP-011 — Implement device replacement UI

**Model:** `gpt-5.6-sol`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `APP-002`, `ID-004`  
**Allowed paths:** recovery/replacement UI/tests

**Objective:** Guide root restoration and contact-by-contact replacement without claiming history or global revocation.

**Verification:** Wrong phrase, no contacts, stale/replayed object, old-device warning, group-owner limitation, interrupted recovery, and physical UX review.

**Done when:** Every promise exactly matches signed core state and the user understands when the old device actually loses access.

## APP-012 — Implement notifications and redacted diagnostics

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `APP-006`, `PLAT-001`  
**Allowed paths:** notification/diagnostic platform code and tests

**Objective:** Notify locally and export actionable support data without sensitive fields.

**Implementation:** Add lock-aware notification content, permission/capability states, diagnostic versions/counters/error codes, and automated forbidden-field scan.

**Verification:** Locked/unlocked physical notifications on supported OSes; seeded secrets/IDs/messages in memory must not appear in exports; unavailable Linux notifications degrade honestly.

**Done when:** Diagnostic exports pass the sensitive-value scanner and contain enough version/state metadata to reproduce failures.

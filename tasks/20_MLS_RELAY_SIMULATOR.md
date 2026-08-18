# Phase 20 — MLS, Relay Protocol, and Simulator

The approved v1 specifications and Phase 10 identity/storage APIs are authoritative. No task in this phase may revise cryptographic or wire decisions.

## MLS-001 — Pin OpenMLS and implement the storage provider

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human review required before merge  
**Depends on:** `ID-002`, `STO-002`, `FND-002`  
**Allowed paths:** `rust/crates/mesh-mls/`, MLS fixtures, dependency lockfiles

**Objective:** Establish one reviewed OpenMLS integration that persists transactionally on every target.

**Implementation:** Pin the approved version/provider, enable only the approved cipher suite, implement SQLCipher-backed OpenMLS storage, bind device certificates into the application authentication layer, expose opaque KeyPackages, and add deterministic fixture helpers.

**Verification:** Create/join/send/reload round trips, approved RFC/library vectors, transaction rollback, wrong credential, and compile/test matrix for all native targets.

**Done when:** Every target consumes identical fixtures and no code manipulates serialized MLS internals or enables experimental extensions.

## MLS-002 — Integrate one-use KeyPackages and pairing transactions

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `MLS-001`, `ID-003`  
**Allowed paths:** MLS pairing module, identity invitation integration, fixtures

**Objective:** Establish a contact/conversation without a server and without reusable invitation state.

**Implementation:** Generate fresh ordinary KeyPackages, embed them opaquely in invitation bundles, reserve/consume atomically, create Welcome data, and define typed retry/failure states.

**Verification:** Concurrent double scan, reuse, expiry, dropped Welcome, substituted certificate or KeyPackage, rollback, and restart tests.

**Done when:** Exactly one conversation is created and every failed/replayed path leaves KeyPackage and conversation state consistent.

## MLS-003 — Implement direct-conversation state

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `MLS-002`, `STO-006`  
**Allowed paths:** `rust/crates/mesh-mls/`, `mesh-api/`, conversation fixtures

**Objective:** Support a direct conversation as exactly two active device leaves.

**Implementation:** Add create/join, application-message schema, transactional outbox/state commit, sender plaintext persistence, duplicate suppression, and typed queued/relayed/delivered/expired states. Enforce one active device per root for MVP.

**Verification:** Offline join, duplicate/reordered messages, app restart at every transaction boundary, own-message rendering, forged sender, and removed/replaced device tests.

**Done when:** Two clients recover consistent state after every injected crash and one logical message produces one UI record.

## MLS-004 — Implement owner-controlled private groups

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human review required before merge  
**Depends on:** `MLS-003`  
**Allowed paths:** group state/policy module, group fixtures

**Objective:** Support groups of 2–16 members with owner-only membership changes.

**Implementation:** Bind an authenticated owner root to group application state, inspect staged commits before merge, permit only owner add/remove and member self-updates, enforce member/device limits, and expose accepted-by-mesh status without read/per-member delivery receipts.

**Verification:** Non-owner commits, mixed proposal sets, forged owner, seventeenth member, concurrent membership commits, removed-member future decrypt, and restart tests.

**Done when:** Unauthorized membership state is rejected before any MLS state is merged. Owner loss/succession remains explicitly unsupported.

## MLS-005 — Implement delayed-message and epoch bounds

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human review required before merge  
**Depends on:** `MLS-003`, `MLS-004`  
**Allowed paths:** MLS state machine, persistence, simulator fixtures

**Objective:** Handle store-carry-forward reordering without unbounded queues or unsupported key retention.

**Implementation:** Apply approved sender-ratchet limits, missing-commit/future-message queues, three-past-epoch policy, atomic commit/outbox changes, old-key cleanup, and `ResyncRequired` events. Do not emulate unreleased OpenMLS time-retention APIs.

**Verification:** Missing/reordered commits, four-old-epoch message, forward-distance overflow, conflicts, crash before/after merge, and resync event idempotence.

**Done when:** In-bound messages recover, out-of-bound messages fail closed, and group state never becomes partially advanced.

## RLY-001 — Implement the canonical outer-envelope codec

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review required before merge  
**Depends on:** `DEC-001`, `TST-001`  
**Allowed paths:** `rust/crates/mesh-protocol/`, v1 fixtures

**Objective:** Encode and strictly parse the approved transport-independent envelope.

**Implementation:** Implement canonical fields, immutable authenticated header, separate mutable forwarding metadata, opaque padded ciphertext, exact length/version checks, typed errors, and allocation-before-bound checks. Fragment fields do not belong to this envelope.

**Verification:** Golden bytes, all truncation points, unknown version/flags, trailing bytes, oversized values, noncanonical encodings, and parser fuzz smoke.

**Done when:** Every vector round-trips byte-for-byte and malformed input is rejected before large allocation.

## RLY-002 — Implement MLS-derived outer protection and routing tags

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human approval required before implementation and review required before merge  
**Depends on:** `RLY-001`, `MLS-003`, approved `CRYPTOGRAPHY_V1.md`  
**Allowed paths:** MLS outer-protection module, crypto vectors

**Objective:** Hide MLS group identifiers/epochs while enabling recipient lookup exactly as specified.

**Implementation:** Implement frozen exporter labels, AEAD key/nonce construction, authenticated-header binding, six-hour tag derivation, bounded old-tag/key index, commit-transition rule, padding, and removal cleanup.

**Verification:** Independent vectors; wrong conversation/epoch/key; nonce reuse check; altered header/ciphertext; time-window/skew boundaries; commit transition; removed member; delayed prior-epoch data; artifact scan.

**Done when:** Captures and relay databases expose no MLS group ID, root key, contact ID, or tag outside the documented six-hour correlation window.

## RLY-003 — Implement proof-of-work admission

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `RLY-001`, approved work parameters  
**Allowed paths:** `mesh-protocol/` work module, benchmark fixture

**Objective:** Add the fixed defense-in-depth work check without treating it as identity or Sybil protection.

**Implementation:** Implement the approved SHA-256 input, cancellable asynchronous miner, constant-cost verifier after cheap bounds parsing, and metrics that reveal duration but no input data.

**Verification:** Known nonces, bit mutation, cancellation, counter overflow, cross-platform equality, and lowest-reference-device benchmark.

**Done when:** Work is portable and within the approved human-reviewed time/battery budget. Stop rather than silently reducing difficulty.

## RLY-004 — Implement the bounded relay database

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `STO-002`, `RLY-001`, `RLY-003`  
**Allowed paths:** `rust/crates/mesh-relay/`, relay migrations/tests

**Objective:** Admit, expire, deduplicate, and evict opaque envelopes within hard resource limits.

**Implementation:** Add the approved admission pipeline, local arrival deadlines, global/session caps, ID collision handling, deterministic eviction, per-transport forward markers, and restart-safe counters. Treat sender timestamps and mutable hops as untrusted.

**Verification:** Future/past timestamps, cache full, ID collision with different bytes, reconnect churn, expiry, crash/restart, concurrent clear, and eight-hour simulated flood.

**Done when:** Logical cache bytes/count and memory remain bounded and relay code has no dependency on private storage or decryption.

## RLY-005 — Implement peer inventory synchronization

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `RLY-004`, approved sync specification  
**Allowed paths:** `mesh-relay/` synchronization module, protocol fixtures

**Objective:** Exchange missing envelopes efficiently without exposing conversations or allowing unbounded manifests.

**Implementation:** Add version/capability negotiation, time-bucketed paged inventories of truncated envelope IDs, missing-ID requests, session byte/count limits, restart cursors, and explicit completion/cancellation. Resolve truncated-ID collisions safely.

**Verification:** Empty/full stores, simultaneous sync, pagination, collision, disconnect/resume, stale cursor, malformed counts, and 1 MiB cap tests.

**Done when:** Two arbitrary relay stores converge within quotas and no inventory contains a routing tag, identity, or contact field.

## RLY-006 — Implement Noise NN session framing

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `RLY-005`, approved Noise profile  
**Allowed paths:** relay session module, handshake fixtures

**Objective:** Protect local synchronization metadata from passive interception while making no false relay-authentication claim.

**Implementation:** Add versioned prologue, ephemeral handshake, maximum record size, timeouts, counter/rekey limits, split/coalesced record parsing, backpressure, and sanitized errors.

**Verification:** Known handshake fixture, passive capture, active mutation/MITM documentation, replay, timeout, record overflow, slow consumer, and cancellation.

**Done when:** Packet capture reveals no inventory/envelope data and the threat model states that arbitrary relays are unauthenticated.

## RLY-007 — Implement forwarding and loop-prevention policy

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `RLY-004`, `RLY-005`  
**Allowed paths:** relay scheduler, transport-supervisor interfaces, simulator tests

**Objective:** Forward each complete accepted envelope at most once per transport and retention window.

**Implementation:** Add source-transport exclusion, per-transport forward state, bounded queues, expiry cancellation, degraded transport recovery, and policy for mutable hop metadata. Never bridge raw/incomplete transport fragments.

**Verification:** BLE↔WLAN, WLAN↔LoRa, three-gateway cycles, replay, adapter restart, full queue, expiry during send, and bounded-event-count tests.

**Done when:** Loops terminate deterministically and one failed transport does not stop others.

## RLY-008 — Implement authenticated delivery state

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human approval required before implementation  
**Depends on:** `MLS-003`, `RLY-007`, delivery semantics from `DEC-001`  
**Allowed paths:** message-state core, receipt fixtures

**Objective:** Distinguish local queue, transport acceptance, relay observation, recipient delivery, and expiry without false claims.

**Implementation:** Add the frozen state machine and authenticated direct-message delivery receipt. Receipts are idempotent and do not imply reading. Groups expose only accepted-by-mesh. Local Meshtastic queue acceptance is never recipient delivery.

**Verification:** Forged/replayed/late receipts, duplicate transport callbacks, expiry race, app restart, black-hole relay, and alternate-route tests.

**Done when:** No untrusted relay/radio event can produce `delivered` and transitions cannot move backward except to an explicit terminal failure defined by the spec.

## SIM-001 — Implement the deterministic event engine

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `TST-001`  
**Allowed paths:** `rust/crates/mesh-simulator/`, scenario schema

**Objective:** Run reproducible virtual nodes and events without sleeps or host timing.

**Implementation:** Add ordered event queue, virtual time, seeded decisions, node lifecycle, trace/evidence output, state digest, and one-command seed reproduction.

**Verification:** Same scenario/seed has identical trace digest across two hosts; cancellation and maximum-event guards prevent runaway simulations.

**Done when:** A failed seed can be replayed exactly from one command.

## SIM-002 — Model transports, stores, and mobile lifecycle

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review recommended  
**Depends on:** `SIM-001`, stable relay interfaces  
**Allowed paths:** simulator models and fixtures

**Objective:** Represent BLE, WLAN, LoRa, storage quotas, MTUs, bandwidth, battery state, process restart, lock, and transport switching.

**Verification:** Unit scenarios exercise every model boundary and reject impossible/negative capacities.

**Done when:** Production relay/core code runs unchanged against simulated transport/storage adapters.

## SIM-003 — Add deterministic network and process faults

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** AI-verifiable  
**Depends on:** `SIM-002`  
**Allowed paths:** simulator fault modules and fixtures

**Objective:** Inject partition/heal, drop, delay, reorder, duplicate, corrupt, clock skew, restart, lock, full disk, and adapter failure.

**Verification:** Each fault has a minimal fixture demonstrating its expected oracle and stable trace.

**Done when:** Faults compose deterministically and never rely on probability without a recorded seed.

## SIM-004 — Add malicious-relay behaviors

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human review required before merge  
**Depends on:** `SIM-003`, `RLY-004` through `RLY-008`  
**Allowed paths:** simulator adversary modules, security scenarios

**Objective:** Exercise replay, mutation, forgery, flooding, selective dropping, stale forwarding, tag observation, inventory lies, and gateway loops.

**Verification:** Every behavior has a bounded expected oracle: typed rejection, no false delivery, quota enforcement, alternate-path success, or documented residual risk.

**Done when:** No adversary scenario can expose plaintext/keys, exceed resource caps, impersonate a verified member, or create unbounded events.

## SIM-005 — Encode the MVP end-to-end scenarios

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review recommended  
**Depends on:** `SIM-004`, `MLS-005`  
**Allowed paths:** `tests/scenarios/`, scenario runner configuration

**Objective:** Turn product acceptance into deterministic executable scenarios.

**Implementation:** Add direct exchange, A→courier→C, mixed bearer, 16-member offline group, removal/replacement, missing commit, epoch expiry, locked relay, malformed input, and cache flood scenarios.

**Verification:** Run all seeds defined by `TEST_MATRIX.md`; compare expected events and state digests.

**Done when:** Every non-hardware acceptance claim maps to a named passing scenario or documented residual limitation.

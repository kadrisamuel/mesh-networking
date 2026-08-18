# Phase 60 — Verification, Packaging, and Lab Demonstration

This phase does not add product scope. It verifies the integrated system, produces artifacts, and blocks release when evidence is missing.

## QA-001 — Add normative protocol and cross-platform fixture tests

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** all v1 codecs/derivations and `TST-001`  
**Allowed paths:** `tests/fixtures/v1/`, `tests/interop/`, test-only adapters

**Objective:** Prove every target uses identical canonical identity, certificate, MLS wrapper, envelope, BLE record, sync, Meshtastic, and LoRa bytes.

**Implementation:** Add immutable golden fixtures with source/spec/version metadata and independent encode/decode consumers for Rust, Dart/native boundaries, and supported platforms.

**Verification:** `just generated-check`, fixture digest check, and cross-platform matrix. Mutation of any byte must fail the appropriate integrity/canonical check.

**Done when:** No platform-specific wire serialization remains and fixture changes require a versioned human-approved protocol update.

## QA-002 — Complete property tests for bounded protocol behavior

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `QA-001`, relay/LoRa codecs and stores  
**Allowed paths:** property-test suites/corpora

**Objective:** Verify fragmentation, reassembly, canonical parsing, dedupe, quota, expiry, inventory, and state-machine invariants across broad generated input.

**Verification:** Approved case/seed budget locally and nightly; every failure prints one reproducible seed/command.

**Done when:** Properties cover all declared lengths/bounds and CI retains minimal failing cases.

## QA-003 — Add and operate parser fuzz targets

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** stable parsers for QR, envelope, Noise records, BLE, Meshtastic, and LoRa  
**Allowed paths:** fuzz targets/corpora, nightly CI

**Objective:** Find crashes, panics, hangs, excessive allocation, and parser disagreement in every external-byte boundary.

**Verification:** Seed corpus smoke in PR; sanitizer where supported; approved timed runs nightly; corpus/artifact retention; reproduce one injected crash.

**Done when:** Every parser has a bounded target and there are no unresolved crashes, leaks, or timeouts in the release corpus.

## QA-004 — Run the integrated malicious-relay suite

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human review required before merge  
**Depends on:** `SIM-004`, integrated core and gateways  
**Allowed paths:** `tests/security/`, simulator scenarios/evidence

**Objective:** Validate interception, impersonation, replay, mutation, flooding, selective drop, stale forwarding, inventory lies, and loops end to end.

**Verification:** Each threat maps to a typed rejection, bounded resource oracle, no-false-delivery oracle, alternate-route result, or explicit residual risk in `THREAT_MODEL.md`.

**Done when:** A reviewed threat-to-test matrix has no unowned or silently untested claim.

## QA-005 — Inspect packet captures, relay databases, logs, and diagnostics

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** integrated WLAN/BLE/LoRa, storage, logging, diagnostics  
**Allowed paths:** security evidence/scanners and fixes to violating component only

**Objective:** Confirm the stated metadata boundary using seeded canary values.

**Verification:** Capture all transports and exported databases/logs/diagnostics; automated scan must find no plaintext, recovery words, root/device private keys, contact IDs, display names, MLS group IDs, stable app discovery IDs, or radio payload dumps. Human reviews unavoidable OS/link metadata.

**Done when:** Evidence states exactly what timing, size, radio/link identifiers, and six-hour tag correlation remain observable.

## QA-006 — Test locked/captured storage and revocation boundaries

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human execution required and review required before merge  
**Depends on:** `STO-006`, `ID-004`, `MLS-005`, integrated apps  
**Allowed paths:** storage/security tests and evidence

**Objective:** Verify realistic locked-device guarantees without claiming protection for an unlocked/rooted attacker.

**Verification:** Copy closed databases, locked app snapshot, reboot-before-unlock, wrong keys, non-owner device replacement, old device before/after removal commit, past-epoch boundary, and key invalidation on physical platforms.

**Done when:** Closed storage and supported lock states meet the spec; unlocked, rooted/jailbroken, flash-forensics, jamming, radio location, and timing attacks remain documented residual risks.

## PERF-001 — Build the common performance evidence runner

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `TST-001`, metric definitions from `DEC-001`  
**Allowed paths:** `tests/performance/`, evidence tooling

**Objective:** Produce comparable latency, delivery, resource, and battery reports.

**Implementation:** Add manifest schema, monotonic event capture, nearest-rank p95, timeout-as-infinite treatment, delivery rate, warm-up handling, environment/device metadata, JSON report and digest.

**Verification:** Synthetic known distributions, failures/timeouts, clock discontinuity, duplicate events, and report reproducibility.

**Done when:** A result cannot hide loss inside latency and every measurement names exact start/end events.

## PERF-002 — Aggregate WLAN, BLE, and store-carry performance

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `PERF-001`, `WLAN-007`, `BLE-011`  
**Allowed paths:** performance evidence only

**Objective:** Run and compare the approved 100-message profiles and A→courier→C encounter profile on pinned devices.

**Verification:** Three runs per required pairing/environment; attach raw events, reports, and hashes.

**Done when:** WLAN p95 <5 seconds, foreground BLE p95 <15 seconds, store-carry p95 <30 seconds after session-ready, and delivery target is met—or the MVP remains blocked with evidence.

## PERF-003 — Build and run controlled LoRa loss injection

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `PERF-001`, `EU-003`, `LR-005`, reference radios  
**Allowed paths:** LoRa harness/evidence

**Objective:** Apply the frozen 10% loss at the specified layer in a lawful/shielded controlled topology.

**Verification:** Record topology, attenuators or venue, RF config, firmware, frame/envelope counts, retries, timeouts, delivery and p95. Use the approved number of radios; a physical three-hop route normally requires four radio nodes.

**Done when:** The approved 160-byte profile meets at least 95% delivery within five minutes or produces a blocking report.

## PERF-004 — Run the eight-hour relay soak

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `PERF-001`, integrated transports  
**Allowed paths:** soak scenario/evidence and bug fixes

**Objective:** Detect crashes, duplicate UI records, unbounded cache/database/RSS growth, deadlocks, and stuck adapters.

**Verification:** Approved mixed-load profile with restarts, lock cycles, cache pressure, and transport toggles; record crash count, logical cache, DB size, RSS slope, duplicate count, queue depth, and final integrity.

**Done when:** Zero crashes/duplicates, all logical quotas hold, and resource slopes stay within frozen limits.

## PERF-005 — Run repeatable mobile battery profiles

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `PERF-001`, `BLE-011`, pinned phones  
**Allowed paths:** battery evidence only

**Objective:** Measure percentage-point battery loss under fixed approved Android/iOS relay states.

**Verification:** Record model, OS, battery health, temperature, radios, signal environment, screen/lifecycle, message load, baseline, and three-run variation.

**Done when:** Each OS result is independently reported against the approved <20 percentage-point target; iOS background observations are not generalized.

## DSK-003 — Validate desktop network/firewall/privacy behavior

**Model:** `gpt-5.6-sol`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `DSK-001`, `WLAN-004`  
**Allowed paths:** desktop integration/docs/tests

**Objective:** Provide actionable local-network diagnostics without weakening OS security.

**Verification:** Fresh user/VM on each OS, firewall allow/deny, multicast unavailable, interface change, and recovery.

**Done when:** The app never disables a firewall or installs broad rules automatically and denial produces clear guidance.

## REL-001 — Package installable lab artifacts on all targets

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** integrated tests, `DSK-001`, mobile build matrix  
**Allowed paths:** packaging/release workflows and smoke evidence

**Objective:** Produce installable development/lab packages without pretending absent signing credentials exist.

**Verification:** Clean install, upgrade, uninstall, first launch, minimum OS, and artifact hash on Android, iOS development provisioning, Windows, macOS, and Ubuntu.

**Done when:** Unsigned/development artifacts are labelled accurately and release jobs block clearly when credentials are absent.

## REL-002 — Produce SBOM, notices, checksums, and signing hooks

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution required  
**Depends on:** `REL-001`, `CI-003`, human licensing decision  
**Allowed paths:** release workflows, SBOM/notices/checksum artifacts

**Objective:** Attach complete provenance without exposing credentials.

**Verification:** Validate SBOMs, licenses/notices, source revision, deterministic manifests, checksums, and signatures where credentials are available. Secret scan workflow/logs.

**Done when:** A human licensing reviewer approves the distribution set and missing credentials produce `blocked`, not success.

## DOC-001 — Finalize threat model and operational warnings

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human approval required before release  
**Depends on:** `QA-004` through `QA-006`  
**Allowed paths:** security/threat documentation

**Objective:** Align every security statement with verified evidence and residual risks.

**Done when:** Assets, adversaries, guarantees, assumptions, capture states, metadata leakage, recovery timing, radio detection/location, traffic analysis, jamming, unlocked devices, and forensic limits are explicit; no marketing claim exceeds a test.

## DOC-002 — Write reproducible build, test, and hardware setup guides

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review recommended  
**Depends on:** `REL-001`, hardware/performance tasks  
**Allowed paths:** `docs/operations/`, compatibility matrix

**Objective:** Let a new developer reproduce software and controlled hardware evidence from a clean system.

**Verification:** A second machine follows the guide without undocumented steps and records resulting hashes.

**Done when:** Tool versions, permissions, radio configuration, legal/RF prerequisites, test commands, expected duration, and troubleshooting are complete.

## DOC-003 — Write the deterministic lab demo runbook

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** all acceptance tasks  
**Allowed paths:** `docs/operations/DEMO_RUNBOOK.md`, demo evidence template

**Objective:** Demonstrate the MVP without improvisation or hidden internet connectivity.

**Implementation:** Specify inventory, preflight, internet-off proof, BLE direct, WLAN, A→B→C carry, mixed route, restart/dedupe, 16-member fixture, replacement/removal, expected observations, evidence paths, teardown, and cache/key cleanup.

**Verification:** A person unfamiliar with implementation rehearses the runbook and records ambiguities.

**Done when:** Every step has a pass oracle and the lab-prototype warning appears at start and end.

## DEMO-001 — Rehearse and gate the lab MVP

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human execution and final human approval required  
**Depends on:** all required tasks, `DOC-001` through `DOC-003`, `REL-002`  
**Allowed paths:** versioned evidence bundle and release notes only

**Objective:** Execute the complete runbook and decide release from recorded evidence.

**Verification:** Run on the exact tagged source/artifacts; archive manifests, hashes, test reports, selected redacted traces, hardware/compliance records, known limitations, and reviewer sign-offs.

**Done when:** Every required gate is pass or the release is explicitly blocked. The artifact is labelled a lab demonstration, not operationally reviewed software.

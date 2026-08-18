# Phase 00 — Foundation and Decision Gates

Do not start security, wire-protocol, storage, transport, or UI implementation until `DEC-001` is approved.

## DEC-001 — Freeze the normative MVP decisions

**Model:** `gpt-5.6-sol`  
**Effort:** xhigh  
**Human checkpoint:** Human approval required before implementation  
**Depends on:** `MVP_PLAN.md`, `ENGINEERING_TASKS.md`  
**Allowed paths:** `docs/adr/`, `docs/spec/`

**Objective:** Convert all ambiguous plan prose into decision-complete, versioned specifications.

**Implementation:**

1. Write `ARCHITECTURE.md`, `PROTOCOL_V1.md`, `CRYPTOGRAPHY_V1.md`, `THREAT_MODEL.md`, and `TEST_MATRIX.md`.
2. Pin algorithms, domain labels, canonical encodings, nonce rules, authenticated and mutable fields, padding, routing-tag overlap, TTL/clock-skew handling, quotas, delivery states, ACK rules, and error behavior.
3. Resolve the one-active-device rule, contact-by-contact recovery, separate private/relay databases, owner-only group changes, three-past-epoch limit, fixed BLE service UUID, foreground mobile acceptance, desktop BLE exclusion, and LoRa admission ceiling.
4. Pin minimum/current OS versions, reference phones, Flutter/Rust/OpenMLS/SQLCipher/Meshtastic revisions, firmware versions, radios, EU radio preset, and benchmark definitions.
5. Record AGPL/App Store, Meshtastic GPL/protobuf, signing, and distribution decisions as explicit legal-review gates.
6. Generate normative golden vectors for every derivation and binary format using two independent scripts or implementations.

**Verification:** A second `gpt-5.6-sol` xhigh review must reproduce all vectors and list no unresolved security choices. A human must approve every ADR and sign the decision record.

**Done when:** Specifications contain no TODO/TBD language; constants and fixtures are versioned; every acceptance criterion has exact start/end events, sample size, timeout, environment, and pass rule.

**Stop if:** A choice requires legal advice, unavailable hardware measurements, or an unreviewed cryptographic construction. Record the blocker rather than inventing a default.

## FND-001 — Scaffold the monorepo and ownership boundaries

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human review recommended  
**Depends on:** `DEC-001`  
**Allowed paths:** repository root, `app/`, `packages/`, `rust/`, `tests/`, `tooling/`, `.github/`

**Objective:** Create the planned directory structure and minimal buildable Rust, Flutter, and native-plugin projects.

**Implementation:** Create the Rust workspace and empty focused crates, Flutter desktop/mobile app, federated `mesh_platform` plugin, test/evidence directories, root README, `.gitignore`, editor settings, and ownership notes. Each crate/package must contain a one-sentence responsibility and forbidden dependencies. Do not add product behavior.

**Verification:** `cargo metadata`, `cargo test --workspace`, `flutter pub get`, `flutter analyze`, and `flutter test` succeed. A dependency-boundary test rejects reverse dependencies from protocol/storage into FFI or Flutter.

**Done when:** A clean clone can build the host-supported targets and each planned component has an unambiguous owner.

## FND-002 — Pin toolchains, dependencies, and generated-code commands

**Model:** `gpt-5.6-sol`  
**Effort:** medium  
**Human checkpoint:** Human review required before merge  
**Depends on:** `FND-001`, approved dependency versions from `DEC-001`  
**Allowed paths:** toolchain manifests, lockfiles, `tooling/`, generated-code configuration

**Objective:** Make local and CI builds reproducible.

**Implementation:** Pin Rust and Flutter versions, platform build SDKs, `flutter_rust_bridge`, protobuf compiler/plugins, SQLCipher, OpenMLS, and analysis tools. Add a `justfile` whose commands are check-only by default. Add one command per generated subtree and a clean-tree drift check.

**Verification:** Run every generation command twice and require identical tree hashes; run `just verify-fast` from a clean checkout.

**Done when:** No unbounded version ranges remain in production dependencies and generated output is reproducible.

**Stop if:** A pinned dependency conflicts with AGPL/GPL policy or lacks a supported target from the approved matrix.

## FND-003 — Add licensing, contribution, and security policies

**Model:** `gpt-5.6-terra`  
**Effort:** low  
**Human checkpoint:** Human execution required  
**Depends on:** `DEC-001`, `FND-001`  
**Allowed paths:** root policy files, `docs/operations/`, notice files

**Objective:** Establish project rules before third-party code or security reports arrive.

**Implementation:** Add AGPL-3.0 project license, third-party notice template, contribution/DCO policy, code of conduct, vulnerability-reporting instructions, supported-version policy, and an explicit lab-prototype warning. Record that legal counsel or a qualified human must approve App Store and GPL compatibility before public distribution.

**Verification:** License scanner recognizes the intended project and dependency licenses; all root links resolve.

**Done when:** A contributor knows how to submit code or a private vulnerability report and users cannot mistake the project for operationally reviewed software.

## TST-001 — Create the deterministic test foundation

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `FND-001`, `FND-002`, `DEC-001`  
**Allowed paths:** test-support crates/packages, `tests/fixtures/v1/`, `tooling/`

**Objective:** Give all subsequent tasks injected time, randomness, storage, transport, and reproducible evidence.

**Implementation:** Add virtual clock, seeded test RNG, in-memory storage/transport interfaces, fixture loader, stable JSON evidence schema, sensitive-value scanner, and result digest. Production constructors must reject test RNGs and virtual clocks.

**Verification:** The same seed produces byte-identical ordered traces and digest on two supported hosts; a different seed changes the trace; the scanner detects seeded canary secrets.

**Done when:** Tests can run without real sleeps, wall-clock dependencies, network, radios, or production secrets.

## CI-001 — Add required pull-request checks

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** AI-verifiable  
**Depends on:** `FND-002`, `TST-001`  
**Allowed paths:** `.github/workflows/`, `tooling/`, root check configuration

**Objective:** Reject formatting drift, warnings, failing tests, stale generated files, and accidental secrets on every change.

**Implementation:** Add format-check, Clippy with warnings denied, Rust unit tests, Flutter analysis/tests, property-test smoke, generated-tree drift, fixture drift, secret scan, and changed-path reporting. Workflows must be least-privilege and use pinned action revisions.

**Verification:** Intentionally introduce one failure of each class on a temporary branch/worktree and confirm the relevant job fails with an actionable message.

**Done when:** `just verify-fast` matches the required PR gate locally.

## CI-002 — Add the five-platform build matrix

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `FND-002`, `CI-001`  
**Allowed paths:** platform build configuration and CI workflows

**Objective:** Compile Android, unsigned iOS, Windows, macOS, and Ubuntu artifacts continuously.

**Implementation:** Add pinned build jobs and caches, minimum-OS checks, architecture declarations, and artifact manifests. Signing must be disabled for PRs. Unsupported target/tool combinations must fail clearly rather than disappear from the matrix.

**Verification:** All five jobs build a minimal app and upload a manifest containing source revision, tool versions, target, and artifact hash.

**Done when:** A change breaking any supported target cannot merge unnoticed.

## CI-003 — Add supply-chain and nightly security jobs

**Model:** `gpt-5.6-sol`  
**Effort:** high  
**Human checkpoint:** Human review required before merge  
**Depends on:** `CI-001`, `CI-002`  
**Allowed paths:** CI, audit policy, SBOM tooling

**Objective:** Detect vulnerable, unlicensed, stale, or nondeterministic dependencies and retain long-running test evidence.

**Implementation:** Add Rust/Flutter dependency audits, license allowlist, SBOM generation, binary secret scan, scheduled generated-code drift check, sanitizer jobs where supported, and nightly fuzz/simulation placeholders that cannot report success before their task suites exist.

**Verification:** Use controlled denied-license and vulnerable-package fixtures to confirm failure. Generate and validate an SBOM for every platform artifact.

**Done when:** Audit exceptions require a dated human-approved policy record.

## HW-001 — Establish the reference hardware and test manifest

**Model:** `gpt-5.6-terra`  
**Effort:** medium  
**Human checkpoint:** Human execution required  
**Depends on:** `DEC-001`  
**Allowed paths:** `tests/hardware/`, `docs/operations/`

**Objective:** Record the exact physical equipment needed by later acceptance tasks.

**Implementation:** Create inventory/manifest templates for reference Android and iPhone models, desktop systems, T-Echo, RAK4631, ESP32/SX1262 radio, firmware, antennas, cables, attenuators or lawful test venue, battery health, and EU configuration. Record acquisition status without fabricating unavailable serials or measurements.

**Verification:** A human checks each available device and signs the manifest; missing equipment remains explicitly blocked.

**Done when:** Every hardware task names an actual device or a documented blocker and no RF test can run without a completed compliance checklist.

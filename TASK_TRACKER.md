# Engineering Task Tracker

Updated: 2026-08-18  
Coordinator: Kadri Samuel, with Codex providing operational coordination

This file records coordination state only. Task requirements and dependencies remain authoritative in `ENGINEERING_TASKS.md` and the phase files under `tasks/`.

## Status rules

- **Blocked:** at least one prerequisite is incomplete.
- **Ready:** prerequisites are verified and the task can be assigned.
- **In progress:** one implementation owner is actively working on it.
- **Evidence review:** implementation finished; the coordinator is checking the diff and test evidence.
- **Human gate:** automated checks passed; required human action or approval remains.
- **Done:** evidence is verified, required human gates are recorded, and the accepted commit is identified.

Only the coordinator changes status after verifying evidence. Implementation models must not edit this tracker.

## Current queue

| Priority | Task | State | Next coordinator action |
|---|---|---|---|
| 1 | `DEC-001` | In progress | Receive draft specifications and verification evidence |
| 2 | Independent `DEC-001` review | Waiting | Assign a separate `gpt-5.6-sol`, xhigh review |
| 3 | Human approval | Waiting | Review and sign every ADR; record reviewer, date, commit, and outcome |
| 4 | `FND-001` | Blocked | Mark Ready only after `DEC-001` is approved and committed |

## Evidence record format

For each accepted task, record the implementation owner and model, branch and commit, changed files, verification results, evidence location, human review when required, and remaining risks or deviations.

## Phase 00 — Foundation and decisions

| Task | Description | Status | Owner | Branch/PR | Human gate | Evidence/commit |
|---|---|---|---|---|---|---|
| `DEC-001` | Freeze the normative MVP decisions | In progress | Implementation model | `DEC-001` | Approve first | — |
| `FND-001` | Scaffold the monorepo and ownership boundaries | Blocked | Unassigned | — | Review recommended | — |
| `FND-002` | Pin toolchains, dependencies, and generated-code commands | Blocked | Unassigned | — | Review before merge | — |
| `FND-003` | Add licensing, contribution, and security policies | Blocked | Unassigned | — | Human execution | — |
| `TST-001` | Create the deterministic test foundation | Blocked | Unassigned | — | Review before merge | — |
| `CI-001` | Add required pull-request checks | Blocked | Unassigned | — | AI-verifiable | — |
| `CI-002` | Add the five-platform build matrix | Blocked | Unassigned | — | Review before merge | — |
| `CI-003` | Add supply-chain and nightly security jobs | Blocked | Unassigned | — | Review before merge | — |
| `HW-001` | Establish the reference hardware and test manifest | Blocked | Unassigned | — | Human execution | — |
## Phase 10 — Security, identity, and storage

| Task | Description | Status | Owner | Branch/PR | Human gate | Evidence/commit |
|---|---|---|---|---|---|---|
| `SEC-001` | Implement secret-safe cryptographic utilities | Blocked | Unassigned | — | Review before merge | — |
| `ID-001` | Implement recovery-code and root-identity derivation | Blocked | Unassigned | — | Review before merge | — |
| `ID-002` | Implement device certificates and safety numbers | Blocked | Unassigned | — | Review before merge | — |
| `ID-003` | Implement one-use contact invitation bundles | Blocked | Unassigned | — | Review before merge | — |
| `STO-001` | Specify and migrate separate private and relay databases | Blocked | Unassigned | — | Approve first | — |
| `STO-002` | Integrate SQLCipher and transactional migrations | Blocked | Unassigned | — | Review before merge | — |
| `STO-003` | Implement Apple key protection | Blocked | Unassigned | — | Human execution | — |
| `STO-004` | Implement Android key protection | Blocked | Unassigned | — | Human execution | — |
| `STO-005` | Implement Windows and Linux private-storage protection | Blocked | Unassigned | — | Human execution | — |
| `STO-006` | Implement lock lifecycle and local history deletion | Blocked | Unassigned | — | Review before merge | — |
| `ID-004` | Implement manual device replacement and revocation objects | Blocked | Unassigned | — | Approve first | — |
## Phase 20 — MLS, relay, and simulator

| Task | Description | Status | Owner | Branch/PR | Human gate | Evidence/commit |
|---|---|---|---|---|---|---|
| `MLS-001` | Pin OpenMLS and implement the storage provider | Blocked | Unassigned | — | Review before merge | — |
| `MLS-002` | Integrate one-use KeyPackages and pairing transactions | Blocked | Unassigned | — | Review before merge | — |
| `MLS-003` | Implement direct-conversation state | Blocked | Unassigned | — | Review before merge | — |
| `MLS-004` | Implement owner-controlled private groups | Blocked | Unassigned | — | Review before merge | — |
| `MLS-005` | Implement delayed-message and epoch bounds | Blocked | Unassigned | — | Review before merge | — |
| `RLY-001` | Implement the canonical outer-envelope codec | Blocked | Unassigned | — | Review before merge | — |
| `RLY-002` | Implement MLS-derived outer protection and routing tags | Blocked | Unassigned | — | Approve + review | — |
| `RLY-003` | Implement proof-of-work admission | Blocked | Unassigned | — | Review before merge | — |
| `RLY-004` | Implement the bounded relay database | Blocked | Unassigned | — | Review before merge | — |
| `RLY-005` | Implement peer inventory synchronization | Blocked | Unassigned | — | Review before merge | — |
| `RLY-006` | Implement Noise NN session framing | Blocked | Unassigned | — | Review before merge | — |
| `RLY-007` | Implement forwarding and loop-prevention policy | Blocked | Unassigned | — | Review before merge | — |
| `RLY-008` | Implement authenticated delivery state | Blocked | Unassigned | — | Approve first | — |
| `SIM-001` | Implement the deterministic event engine | Blocked | Unassigned | — | Review before merge | — |
| `SIM-002` | Model transports, stores, and mobile lifecycle | Blocked | Unassigned | — | Review recommended | — |
| `SIM-003` | Add deterministic network and process faults | Blocked | Unassigned | — | AI-verifiable | — |
| `SIM-004` | Add malicious-relay behaviors | Blocked | Unassigned | — | Review before merge | — |
| `SIM-005` | Encode the MVP end-to-end scenarios | Blocked | Unassigned | — | Review recommended | — |
## Phase 30 — Application and bridge

| Task | Description | Status | Owner | Branch/PR | Human gate | Evidence/commit |
|---|---|---|---|---|---|---|
| `PLAT-001` | Define the platform capability contract | Blocked | Unassigned | — | Review before merge | — |
| `BR-001` | Establish the Flutter/Rust bridge smoke path | Blocked | Unassigned | — | AI-verifiable | — |
| `BR-002` | Define typed bridge DTOs and commands | Blocked | Unassigned | — | Review before merge | — |
| `BR-003` | Implement bounded event streaming and resynchronization | Blocked | Unassigned | — | Review before merge | — |
| `BR-004` | Implement the external-transport byte pump | Blocked | Unassigned | — | Review before merge | — |
| `BR-005` | Enforce binding reproducibility and compatibility | Blocked | Unassigned | — | AI-verifiable | — |
| `APP-001` | Build the Flutter application shell | Blocked | Unassigned | — | Review recommended | — |
| `APP-002` | Add repositories, reducers, and a deterministic fake core | Blocked | Unassigned | — | Review before merge | — |
| `APP-003` | Implement identity onboarding | Blocked | Unassigned | — | Human execution | — |
| `APP-004` | Implement app lock and privacy lifecycle | Blocked | Unassigned | — | Human execution | — |
| `APP-005` | Implement contacts, QR, and safety-number UI | Blocked | Unassigned | — | Human execution | — |
| `APP-006` | Implement direct-conversation UI | Blocked | Unassigned | — | Review recommended | — |
| `APP-007` | Implement private-group UI | Blocked | Unassigned | — | Review before merge | — |
| `APP-008` | Implement the connectivity dashboard | Blocked | Unassigned | — | Review recommended | — |
| `APP-009` | Implement relay and storage controls | Blocked | Unassigned | — | Review recommended | — |
| `APP-010` | Implement radio setup UI | Blocked | Unassigned | — | Human execution | — |
| `APP-011` | Implement device replacement UI | Blocked | Unassigned | — | Human execution | — |
| `APP-012` | Implement notifications and redacted diagnostics | Blocked | Unassigned | — | Human execution | — |
## Phase 40 — WLAN and Bluetooth

| Task | Description | Status | Owner | Branch/PR | Human gate | Evidence/commit |
|---|---|---|---|---|---|---|
| `WLAN-001` | Validate cross-platform local discovery | Blocked | Unassigned | — | Human execution | — |
| `WLAN-002` | Implement the DNS-SD service contract | Blocked | Unassigned | — | Review before merge | — |
| `WLAN-003` | Implement bounded TCP listener/client sessions | Blocked | Unassigned | — | Review before merge | — |
| `WLAN-004` | Resolve simultaneous connections and peer restarts | Blocked | Unassigned | — | Review before merge | — |
| `WLAN-005` | Integrate Apple local-network permissions | Blocked | Unassigned | — | Human execution | — |
| `WLAN-006` | Integrate Android local-network discovery | Blocked | Unassigned | — | Human execution | — |
| `WLAN-007` | Run WLAN interoperability and latency acceptance | Blocked | Unassigned | — | Human execution | — |
| `BLE-001` | Freeze GATT and link-record fixtures | Blocked | Unassigned | — | Approve first | — |
| `BLE-002` | Create the federated BLE plugin and fake backend | Blocked | Unassigned | — | Review before merge | — |
| `BLE-003` | Implement Android permissions and capability mapping | Blocked | Unassigned | — | Human execution | — |
| `BLE-004` | Implement Android advertiser and GATT server | Blocked | Unassigned | — | Human execution | — |
| `BLE-005` | Implement Android scanner and GATT client | Blocked | Unassigned | — | Human execution | — |
| `BLE-006` | Add the opt-in Android foreground relay service | Blocked | Unassigned | — | Human execution | — |
| `BLE-007` | Implement iOS permissions and project configuration | Blocked | Unassigned | — | Human execution | — |
| `BLE-008` | Implement iOS peripheral mode | Blocked | Unassigned | — | Execute + review | — |
| `BLE-009` | Implement iOS central mode and restoration | Blocked | Unassigned | — | Execute + review | — |
| `BLE-010` | Integrate dual roles and encrypted session arbitration | Blocked | Unassigned | — | Review before merge | — |
| `BLE-011` | Run physical BLE and battery acceptance | Blocked | Unassigned | — | Human execution | — |
## Phase 50 — Meshtastic, LoRa, and gateway

| Task | Description | Status | Owner | Branch/PR | Human gate | Evidence/commit |
|---|---|---|---|---|---|---|
| `MT-001` | Prove PRIVATE_APP compatibility on reference radios | Blocked | Unassigned | — | Human execution | — |
| `MT-002` | Pin Meshtastic schemas and generated bindings | Blocked | Unassigned | — | Review before merge | — |
| `MT-003` | Implement serial/TCP StreamAPI framing | Blocked | Unassigned | — | Review before merge | — |
| `MT-004` | Implement BLE PhoneAPI framing | Blocked | Unassigned | — | Human execution | — |
| `MT-005` | Implement the PhoneAPI configuration handshake | Blocked | Unassigned | — | Review before merge | — |
| `MT-006` | Map hybrid envelopes to PRIVATE_APP packets | Blocked | Unassigned | — | Review before merge | — |
| `MT-007` | Implement radio queue and send lifecycle | Blocked | Unassigned | — | Review before merge | — |
| `MT-008` | Implement mobile Meshtastic BLE connection | Blocked | Unassigned | — | Human execution | — |
| `MT-009` | Expose the typed RadioService facade | Blocked | Unassigned | — | Review before merge | — |
| `MT-010` | Implement desktop serial and TCP connectors | Blocked | Unassigned | — | Human execution | — |
| `LR-001` | Freeze the LoRa application-frame format | Blocked | Unassigned | — | Approve first | — |
| `LR-002` | Implement LoRa fragmentation and reassembly | Blocked | Unassigned | — | Review before merge | — |
| `LR-003` | Implement the bounded incomplete-transfer cache | Blocked | Unassigned | — | Review before merge | — |
| `LR-004` | Implement the LoRa send scheduler and retry policy | Blocked | Unassigned | — | Approve first | — |
| `LR-005` | Integrate the LoRa envelope adapter | Blocked | Unassigned | — | Review before merge | — |
| `GW-001` | Implement the transport supervisor | Blocked | Unassigned | — | Review before merge | — |
| `GW-002` | Enforce gateway bridge and loop policy | Blocked | Unassigned | — | Review before merge | — |
| `GW-003` | Add user-visible gateway modes | Blocked | Unassigned | — | Review recommended | — |
| `EU-001` | Implement EU_868 region readback policy | Blocked | Unassigned | — | Human execution | — |
| `EU-002` | Implement airtime and congestion backoff | Blocked | Unassigned | — | Review before merge | — |
| `EU-003` | Complete the radio-compliance checklist | Blocked | Unassigned | — | Human execution | — |
| `DSK-001` | Freeze and build desktop target baselines | Blocked | Unassigned | — | Human execution | — |
| `DSK-002` | Implement desktop serial discovery and permission guidance | Blocked | Unassigned | — | Human execution | — |
| `GW-004` | Execute the mixed-route hardware demonstration | Blocked | Unassigned | — | Human execution | — |
## Phase 60 — Verification and release

| Task | Description | Status | Owner | Branch/PR | Human gate | Evidence/commit |
|---|---|---|---|---|---|---|
| `QA-001` | Add normative protocol and cross-platform fixture tests | Blocked | Unassigned | — | Review before merge | — |
| `QA-002` | Complete property tests for bounded protocol behavior | Blocked | Unassigned | — | Review before merge | — |
| `QA-003` | Add and operate parser fuzz targets | Blocked | Unassigned | — | Review before merge | — |
| `QA-004` | Run the integrated malicious-relay suite | Blocked | Unassigned | — | Review before merge | — |
| `QA-005` | Inspect packet captures, relay databases, logs, and diagnostics | Blocked | Unassigned | — | Human execution | — |
| `QA-006` | Test locked/captured storage and revocation boundaries | Blocked | Unassigned | — | Execute + review | — |
| `PERF-001` | Build the common performance evidence runner | Blocked | Unassigned | — | Review before merge | — |
| `PERF-002` | Aggregate WLAN, BLE, and store-carry performance | Blocked | Unassigned | — | Human execution | — |
| `PERF-003` | Build and run controlled LoRa loss injection | Blocked | Unassigned | — | Human execution | — |
| `PERF-004` | Run the eight-hour relay soak | Blocked | Unassigned | — | Human execution | — |
| `PERF-005` | Run repeatable mobile battery profiles | Blocked | Unassigned | — | Human execution | — |
| `DSK-003` | Validate desktop network/firewall/privacy behavior | Blocked | Unassigned | — | Human execution | — |
| `REL-001` | Package installable lab artifacts on all targets | Blocked | Unassigned | — | Human execution | — |
| `REL-002` | Produce SBOM, notices, checksums, and signing hooks | Blocked | Unassigned | — | Human execution | — |
| `DOC-001` | Finalize threat model and operational warnings | Blocked | Unassigned | — | Approve release | — |
| `DOC-002` | Write reproducible build, test, and hardware setup guides | Blocked | Unassigned | — | Review recommended | — |
| `DOC-003` | Write the deterministic lab demo runbook | Blocked | Unassigned | — | Human execution | — |
| `DEMO-001` | Rehearse and gate the lab MVP | Blocked | Unassigned | — | Execute + approve | — |

## Coordination log

| Date | Task | Event | Recorded by |
|---|---|---|---|
| 2026-08-18 | `DEC-001` | Branch created; specification drafting started | Coordinator |


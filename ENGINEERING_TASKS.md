# Engineering Task Pack

This task pack decomposes `MVP_PLAN.md` into bounded implementation packets. It is designed so that one task can be given to a lower-effort coding model without asking that model to make architecture or security decisions.

## How to use this pack

1. Complete tasks in dependency order. Do not start a task whose prerequisites are incomplete.
2. Give an implementation model only:
   - `MVP_PLAN.md`
   - this file
   - the phase file containing the selected task
   - the current repository state and any specification named by the task
3. Assign one task per run or pull request. Do not combine adjacent tasks unless the task packet explicitly permits it.
4. Use the recommended model and reasoning effort. A cheaper model may be used only when the task recommends it.
5. If a required specification, fixture, tool, credential, device, or decision is missing, stop and report the blocker. Never improvise a wire format, cryptographic rule, radio policy, migration, or security guarantee.
6. After implementation, require the evidence listed in the task packet. A passing test claim without command output or an artifact is not completion evidence.
7. Require implementation models to follow the commit policy below. Implementation commits are checkpoints, not coordinator acceptance.

### Copyable executor prompt

```text
Implement exactly task <TASK-ID> from <PHASE-FILE> on branch <TASK-BRANCH>.

Read first:
1. MVP_PLAN.md
2. ENGINEERING_TASKS.md
3. The complete <TASK-ID> packet and every specification it names
4. Repository AGENTS.md files that apply to paths you may edit

Rules:
- Before editing, record the starting HEAD commit and confirm that <TASK-BRANCH> is checked out. Stop if the worktree is on main, master, a coordinator-designated protected branch, or detached HEAD.
- Inspect the initial worktree state. Stop and report any pre-existing change outside this task's allowed paths.
- Work only within the task's allowed paths and stated objective.
- Preserve existing user changes and do not perform opportunistic refactors or upgrades.
- Do not change frozen protocol constants, schemas, migrations, generated files, or public interfaces unless this task explicitly owns them.
- Add or update the required tests and run every verification command in the task.
- If a prerequisite is missing or a security choice is ambiguous, stop and return a blocker instead of guessing.
- Do not weaken, skip, delete, or rewrite a test merely to make it pass.
- Stage explicit allowed paths only. Never use git add . or git add -A.
- Create local commits according to the commit policy. Do not merge, push, rebase, or update task status.

Return:
- outcome
- files changed
- starting HEAD, ordered commits with hash and purpose, and final HEAD
- commands run and exact results
- acceptance checklist
- assumptions or deviations
- remaining risks or blockers
```

## Commit policy

Implementation models create local commits on the assigned task branch unless the coordinator explicitly supplies a `NO-COMMIT` instruction.

- Before editing, record the starting HEAD and confirm that the assigned task branch is checked out. Stop on `main`, `master`, a coordinator-designated protected branch, or detached HEAD.
- Inspect the initial worktree state. Stop and report any pre-existing change outside the task's allowed paths.
- Use one implementation commit for a small atomic task.
- For a long task, commit each coherent, independently reviewable milestone.
- Before each commit, run the verification applicable to that milestone and scan the staged diff for secrets and out-of-scope files.
- Stage explicit allowed paths only; never use `git add .` or `git add -A`.
- Commit only paths allowed by the task. Never commit real credentials, production private keys, real recovery material, temporary files, unrelated changes, or knowingly broken output. Deterministic secret inputs are allowed only when the task explicitly requires public test vectors and the files clearly identify them as public, test-only fixtures that must never be used in production.
- Use messages in the form `<TASK-ID>: <imperative summary>`.
- Do not merge, push, rebase, reset, amend, force-update, otherwise rewrite history, edit `TASK_TRACKER.md`, or mark the task complete unless the coordinator explicitly authorizes that exact action.
- On a successful implementation handoff, commit all task-owned changes and leave no uncommitted task changes. If blocked, preserve earlier safe checkpoint commits but do not commit incomplete or unsafe output merely to clean the worktree; report every remaining change.
- Return the starting HEAD, every ordered task commit with its purpose, the final HEAD, and final `git status --short` output.

The coordinator reviews the complete `<starting-HEAD>..<final-HEAD>` range, final worktree state, verification evidence, and required human gates. The coordinator may request additional fix commits, then chooses merge or squash-merge and records the accepted commit in `TASK_TRACKER.md`.

## Model recommendations

| Recommendation | Use for |
|---|---|
| `gpt-5.6-sol`, xhigh | Cryptographic specifications, MLS state transitions, hostile-input protocols, cross-transport routing, iOS BLE, recovery, and final security gates |
| `gpt-5.6-sol`, high | Rust core behavior, storage security, synchronization, Meshtastic state machines, concurrency, fuzzing, and performance harnesses |
| `gpt-5.6-sol`, medium | Typed interfaces, platform integration with known specifications, desktop connectors, and bounded refactors |
| `gpt-5.6-terra`, high | Well-specified integration work whose failure modes still require careful reasoning |
| `gpt-5.6-terra`, medium | Flutter features, CI, deterministic fixtures, packaging, documentation, and routine tests |
| `gpt-5.6-terra`, low | Mechanical scaffolding, simple UI shells, notices, and check-only automation |

The recommendation is a minimum for the task. Do not downgrade `sol/xhigh` security-design tasks.

## Human-review recommendations

Every task packet contains one of these labels:

| Label | Meaning |
|---|---|
| **Human approval required before implementation** | A human must approve the specification or product decision before dependent code begins. |
| **Human review required before merge** | AI may implement and test the task, but a human must inspect the diff, evidence, and security or platform behavior before it is accepted. |
| **Human execution required** | Physical hardware, OS permissions, legal review, credentials, RF operation, store submission, or subjective UX judgment requires a person to perform part of the task. |
| **Human review recommended** | Automated evidence is strong, but a brief human UX, documentation, or maintainability review is worthwhile. |
| **AI-verifiable** | A human need not inspect the task individually if the coordinator verifies the bounded diff and required automated tests. |

Human-required gates cannot be approved by another AI agent. The coordinator must record the reviewer, date, reviewed artifact or commit, and outcome in the task evidence.

## Global definition of done

Every implementation task is complete only when:

- The objective is met without unrelated changes.
- Public behavior and failure behavior are both tested.
- Hostile or malformed input is tested where the task accepts external bytes.
- Tests use injected clocks, randomness, transports, and storage where applicable; tests do not depend on sleeps.
- All new asynchronous resources are bounded, cancellable, and idempotently restartable.
- Logs and errors contain no plaintext messages, QR payloads, recovery words, keys, stable identities, peer addresses, service-instance names, or radio payloads.
- Generated files are regenerated by the pinned command and never hand-edited.
- The required verification commands exit successfully.
- The implementation model returns changed paths, command results, test evidence, and remaining risks.

Hardware-only acceptance can never be replaced by mocks. Signing tasks can never be marked complete when required credentials are missing.

## Frozen engineering boundaries

These rules apply until `DEC-001` produces approved normative specifications:

- Flutter owns presentation and OS integration; Rust owns identities, keys, MLS, plaintext message processing, storage rules, envelopes, relay decisions, Noise sessions, Meshtastic protocol handling, and LoRa framing.
- Dart and native plugins exchange typed state and opaque bytes only. They must never receive cryptographic keys or implement security rules.
- The browser remains outside the MVP. Desktop targets are Windows, macOS, and Ubuntu.
- Desktop phone-mesh BLE is outside the MVP; desktop uses WLAN and Meshtastic serial/TCP.
- Phone-to-phone BLE and WLAN acceptance is foreground operation. Android may add an explicit foreground relay service; iOS background routing is best-effort and is not an acceptance promise.
- No custom cryptographic primitive, custom MLS extension, custom Meshtastic firmware, internet service, analytics, or remote telemetry may be added.
- Radio firmware and channel encryption are transport aids, not end-to-end security.
- Never copy implementation code from Meshtastic firmware or clients. Pin schemas, generate bindings, and preserve licenses.

## Decisions that must be frozen before implementation

`DEC-001` is a blocking task. Its human-approved outputs become authoritative when they conflict with prose in `MVP_PLAN.md`. It must resolve at least:

- Exact toolchain, dependency, OS, Meshtastic firmware, hardware, and test-device versions
- Canonical envelope/frame layouts, authenticated versus mutable fields, domain-separation labels, nonce rules, padding classes, expiry and clock-skew rules
- One-active-device policy and recovery limitations
- Separate private and relay storage domains so locked devices can relay ciphertext
- Three-past-MLS-epoch retention supported by the pinned OpenMLS version; no unreleased time-based retention behavior
- Fixed BLE service UUID with ephemeral identity exchanged only inside an encrypted connection; no rotating iOS advertisement identifier requirement
- LoRa frame size and admission ceiling; recommended baseline is 180-byte frames, 160 fragment bytes, at most 10 fragments, and a 1,536-byte LoRa envelope ceiling
- Delivery-state and authenticated acknowledgement semantics
- Local quota/expiry semantics that never trust sender clocks
- AGPL, App Store, generated-protobuf, signing, and distribution constraints

## Planned repository layout

```text
MVP_PLAN.md
ENGINEERING_TASKS.md
tasks/
docs/
  adr/
  spec/
    ARCHITECTURE.md
    PROTOCOL_V1.md
    CRYPTOGRAPHY_V1.md
    THREAT_MODEL.md
    TEST_MATRIX.md
  operations/
    BUILD.md
    RADIO_COMPLIANCE.md
    RELEASE_CHECKLIST.md
    DEMO_RUNBOOK.md
app/mesh_app/                 Flutter application
packages/mesh_platform/       Federated native platform plugin
rust/
  Cargo.toml                  Workspace
  crates/
    mesh-api/
    mesh-identity/
    mesh-mls/
    mesh-protocol/
    mesh-storage/
    mesh-relay/
    mesh-simulator/
    mesh-meshtastic/
    mesh-ffi/
tests/
  fixtures/v1/
  interop/
  scenarios/
  security/
  performance/
  hardware/
tooling/
```

Generated Rust, Dart, and protobuf bindings must live in clearly marked generated subtrees with drift checks.

## Standard verification commands

Foundation tasks may introduce a `justfile`, but it must map to these check-only operations:

```text
just format-check
just rust-check
just rust-test
just flutter-check
just flutter-test
just generated-check
just verify-fast
just verify-all
```

Underlying commands must include:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
flutter analyze
flutter test
```

Do not run rewriting formatters as part of CI. Hardware and signing checks are explicit manual jobs and must report `blocked`, never silently `skipped` or `passed`.

## Phase and dependency map

Phase files are thematic context bundles, not permission to run every task in numerical file order. Cross-file dependencies are intentional; the `Depends on` field in each task is authoritative.

| Phase file | Purpose | Entry gate | Exit gate |
|---|---|---|---|
| `tasks/00_FOUNDATION_AND_DECISIONS.md` | Freeze decisions and create the repository/test foundation | `MVP_PLAN.md` exists | Approved v1 specifications, scaffold, CI, deterministic harness |
| `tasks/10_SECURITY_IDENTITY_STORAGE.md` | Identity, recovery primitives, certificates, databases, key protection | `DEC-001` | Locked/private boundary and identity fixtures pass on all targets |
| `tasks/20_MLS_RELAY_SIMULATOR.md` | MLS conversations, outer protocol, relay behavior, network simulation | Security/storage foundation | Direct/group/relay behavior passes deterministic adversarial scenarios |
| `tasks/30_APP_AND_BRIDGE.md` | Rust/Dart bridge and Flutter product surfaces | Stable core API fixtures | Complete UI works against fake and real core |
| `tasks/40_WLAN_AND_BLE.md` | Hardware-free discovery and synchronization | Transport byte-pump API | Physical Android/iOS foreground BLE and WLAN acceptance |
| `tasks/50_MESHTASTIC_LORA_GATEWAY.md` | Meshtastic, LoRa, EU policy, and bridge routing | Stable relay protocol and reference radios | Controlled mixed-route hardware demonstration |
| `tasks/60_VERIFICATION_RELEASE.md` | Security, performance, packaging, documentation, demo | Integrated feature set | Reproducible lab MVP evidence bundle |

Critical path:

```text
DEC-001 → FND-001 → FND-002 → TST-001
TST-001 → identity/storage → MLS → envelope/relay → bridge/app
bridge + relay → WLAN → BLE
relay + Meshtastic compatibility spike → LoRa → gateway
integrated transports → adversarial/performance gates → lab release
```

Parallel work is permitted only when task write sets do not overlap. Never parallelize tasks that modify the protocol specification, FFI schema, database migrations, generated bindings, or the same platform project files.

## Task evidence format

Every executor must return:

```text
Task: <ID>
Outcome: complete | blocked
Changed paths:
- ...
Commands and results:
- <command> — PASS/FAIL, <summary>
Acceptance:
- [x] ...
Evidence artifacts:
- <path, seed, digest, report, or hardware manifest>
Assumptions/deviations:
- none | ...
Remaining risks/blockers:
- none | ...
```

The coordinator, not the implementation model, updates task status after verifying this evidence.

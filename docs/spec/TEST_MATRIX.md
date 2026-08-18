# Verification and acceptance matrix v1.0.0-draft.1

- Status: Draft — human approval required; hardware, RF, legal, signing, and security-review rows are blocked pending named evidence
- Decision set: DEC-001, 2026-08-18
- Matrix version: `mesh-messenger-tests/1`

Every row defines an exact start event, end event, sample, timeout, environment, and pass rule. A row may report only `PASS`, `FAIL`, or `BLOCKED` with evidence. Mocks cannot pass a row marked physical, legal, signing, or human review.

## 1. Measurement rules

- All automated tests record source revision, clean/dirty state, tool/dependency versions, target, seed, start/end monotonic timestamps, ordered observations, failures, and SHA-256 evidence digest in canonical JSON.
- Unit/simulation tests use injected clocks, RNG, storage, and transports; they contain no real sleeps. Physical performance tests use a monotonic platform clock.
- Unless a row states otherwise, per-message time starts immediately after the sender's private transaction enters `queued` and ends immediately after the recipient's private transaction commits the authenticated plaintext/event.
- For 100 timed samples, p95 is nearest-rank observation 95 after ascending sort. Warm-up samples are excluded and identified. A timeout is retained as its timeout value and a failure; it is not discarded.
- “No internet” means cellular disabled, test WLAN WAN physically disconnected, DNS default route absent, and a simultaneous packet capture showing no packet to a non-link-local address.
- Packet/text scans use unique 32-byte canaries for message, display name, root/device keys, SQLCipher key, MLS group ID, routing secret, recovery phrase prefix, contact QR, and peer address. A test passes only when expected private-memory/private-database controls find every canary and prohibited artifacts find none.
- A physical row starts only after HW-001 records actual model/serial, OS/firmware, antenna, battery health, cables, and calibration. RF rows additionally require the signed jurisdiction/venue/power/duty-cycle checklist.

## 2. Frozen environments

| ID | Exact environment |
|---|---|
| `SIM` | Ubuntu 24.04.4 x64, Rust 1.97.1, release build, one process, injected monotonic/wall clocks and ChaCha20 test RNG seeded by the row, in-memory transports/storage |
| `INT` | Same host/toolchain as `SIM`, real SQLite/SQLCipher temporary databases on ext4, loopback sockets, release build |
| `BLE-FLOOR` | Pixel 4 Android 10 `QD1A.190821.014` and iPhone 8 iOS 16.7.16, clean installs, foreground/unlocked, 10.0 m line of sight in recorded low-interference venue, WLAN/cellular off, no Meshtastic device |
| `BLE-CURRENT` | Pixel 8 Android 16 security level 2026-07-05 and iPhone 15 iOS 26.6 under the same conditions as `BLE-FLOOR` |
| `WLAN-5` | The four phones above plus Windows 11 25H2, macOS 26.6, and Ubuntu 24.04.4 clients as named by each row, dedicated WPA2/WPA3 AP with WAN unplugged, RSSI -50 ±5 dBm at each client, foreground/unlocked |
| `LORA-EU` | RF-approved EU venue or shielded/cabled setup; T-Echo EU868, RAK4631/RAK19007 EU868, Heltec Wireless Stick V3 EU868 plus enough pinned-firmware relays for a forced three-hop route; exact `ARCHITECTURE.md` profile; MQTT/internet absent |
| `BUILD-5` | CI images pinned by FND-002: Android API 29/36, Xcode 26.6 iOS/macOS, Windows SDK 10.0.26100.0, Ubuntu 24.04.4; source and dependency caches empty at first run |

The physical inventory and RF approvals do not yet exist, so every physical row is presently blocked without implying a test result.

## 3. Normative documents and vectors

| ID | Start event | End event | Sample / timeout | Environment | Pass rule |
|---|---|---|---|---|---|
| `DOC-001` | checker opens all DEC-001 markdown | checker emits report | every file; 60 s | `SIM` | required five specs and ADR index/record exist; no unresolved-work placeholder marker; all relative links resolve; every normative constant has one value |
| `DOC-002` | dependency provenance check starts | all refs classified | every tagged pin; 120 s plus network | clean host with Git | tag object ID and peeled commit ID are recorded; lightweight/annotated classification matches `ls-remote`; annotated signature verification result is recorded, never inferred from tag name |
| `VEC-001` | Python generator starts | canonical JSON closes | one full vector set; 120 s | Python 3.14.4 + cryptography 46.0.7 | exit 0 and output SHA-256 equals checked-in digest |
| `VEC-002` | Node generator starts | canonical JSON closes | one full vector set; 120 s | Node 25.9.0, built-in crypto only | exit 0 and bytes equal Python output and checked-in file |
| `VEC-003` | independent reviewer receives frozen specs and both generators | reviewer signs report | all vector fields; four hours | second `gpt-5.6-sol` xhigh run plus human security reviewer | both implementations reproduce identical bytes/digest; reviewer independently checks formulas and representative bytes; report lists every construction and says no unresolved security choice; human accepts findings |
| `SPEC-001` | review begins at source revision | decision record is signed | all ADRs/specs; ten business days | product, engineering, security, legal/RF roles named in record | every required reviewer records name/date/revision/outcome; any rejection or condition leaves row blocked |

## 4. Functional acceptance

| ID | Start event | End event | Sample / timeout | Environment | Pass rule |
|---|---|---|---|---|---|
| `FUN-BLE-001` | sender commits first queued text after BLE-only setup | last recipient commit or timeout | 10 warm-up + 100 measured, alternating direction; 30 s/message, 45 min suite | `BLE-FLOOR`, repeat `BLE-CURRENT` | 100/100 authenticated texts byte-equal, no duplicates, no WLAN/internet/radio traffic; p95 evaluated separately by PERF-BLE-001 |
| `FUN-WLAN-001` | first ring sender commits after all clients discover | final ring recipient commits or timeout | 5 clients (Android floor, iOS floor, Windows, macOS, Ubuntu), 20 texts/client = 100; 15 s/message, 45 min | `WLAN-5` | 100/100 messages reach next client in ring exactly once and packet capture confirms link-local WLAN only |
| `FUN-COURIER-001` | A commits while C absent | C commits after its later encounter with B | 100 seeds; virtual 24 h/message, 30 min suite | `SIM`, topology A↔B then partition then B↔C; A/C never connected | 100/100 arrive exactly once, ciphertext on B cannot route to plaintext, and trace contains no A↔C edge |
| `FUN-MIXED-001` | Pixel 4 commits queued text | iPhone 15 commits text at final WLAN | 20 texts; 10 min/message, four-hour suite | RF-approved: Pixel 4 BLE→Pixel 8 gateway→Ubuntu WLAN gateway/T-Echo→forced 3-hop LoRa→Windows gateway→iPhone 15 WLAN | at least 19/20 arrive exactly once; every trace contains BLE, WLAN, exactly three Meshtastic radio hops, and final WLAN; no alternate path exists |
| `FUN-RESTART-001` | sender commits 100 texts then fault schedule starts | both apps restart and recipient settles | 100 texts; 60 virtual min, 10 min wall | `SIM`, seed `0xdec00105`: 20% loss, 30% duplicate, 0–120 s delay, reordering, restart after item 50 | all 100 displayed exactly once/in original authenticated sender-counter order after convergence; no lost private commit or duplicate UI row |
| `FUN-GROUP-001` | owner creates group | final member processes epoch E+4 message | 16 members, 25 texts/epoch across 5 epochs = 125; 48 virtual h, 20 min wall | `SIM`, four members offline each epoch, deterministic dropped/delayed commits | authorized online/current members receive exactly expected messages once; removed member decrypts none after removal Commit; owner rules hold; current+3 past epoch behavior matches crypto spec |
| `FUN-RECOVERY-001` | replacement enters known 24 words | contact and group finish explicit swaps | 20 contacts, 4 groups including planned notice and owner-loss cases; 72 virtual h, 30 min wall | `SIM` | root-signed planned notice remains pending; no contact changes before explicit acceptance; accepted contacts create fresh direct groups/no history; non-owner rejoins only by owner swap; old leaf gets nothing after swap; owner-loss group reports unrecoverable and accepts no successor |
| `FUN-STORAGE-001` | app enters locked relay with private DB closed | app unlocks after relay exchange | 1,000 opaque envelopes; 15 virtual min, 10 min wall | `INT` | locked process forwards/stores within quota, no private DB open/key read occurs, unlock authenticates eligible envelopes, relay schema has no forbidden field/canary |
| `FUN-HISTORY-001` | 10,000 sent/received rows commit at the injected time high-water mark | first unlock transaction after every boundary completes | boundaries at 10,080 minutes -1/0/+1, observed wall jumps ±30 days, and stopped/locked overdue cases; 60 s | `SIM`, seed `0xdec00106`, persistent private-store model and injected clocks | no row deletes before its deadline under nondecreasing time; every due row and associated UI/mapping/receipt state deletes before display; an observed rollback latches and deletes all pre-latch history before display; forward jump may delete early; immediate deletion removes selected rows regardless of time |
| `FUN-BUILD-001` | clean build job checks out revision | artifact manifest uploaded | one clean build plus three cold launches/target; 45 min Android/Linux, 90 min Apple/Windows | `BUILD-5` and actual minimum/current devices for launch | installable lab artifact builds for all five targets, manifest contains tool/source/artifact hashes, and each launch reaches locked screen without crash; missing signing/device reports blocked |

## 5. Protocol, identity, and MLS correctness

| ID | Start event | End event | Sample / timeout | Environment | Pass rule |
|---|---|---|---|---|---|
| `PRO-ENC-001` | codec receives fixture/property input | decode/re-encode completes | all padding classes plus 100,000 generated cases, seed `0xdec00110`; 120 s | `SIM` | canonical valid inputs round-trip byte-identically; invalid length/reserved/enum/trailing inputs reject without allocation over 4,096 bytes |
| `PRO-FRAG-001` | fragmenter receives admitted LoRa envelope | reassembler resolves | each LoRa size × all loss/duplicate/order patterns up to 10 fragments plus 100,000 properties; 180 s | `SIM` | exact reassembly or bounded expiry; no mixed-ID/count/conflicting fragment succeeds; cache limits never exceed specification |
| `PRO-TIME-001` | envelope offered at injected wall/monotonic pair | admission/deletion decision occurs | every boundary at -1/0/+1 minute around skew, TTL, slot, wall jumps ±30 days; 30 s | `SIM` | decisions equal formulas; wall rollback/advance after admission never extends monotonic deadline |
| `PRO-QUOTA-001` | empty cache receives deterministic stream | last admission/eviction completes | 20,000 envelopes of every class/size; 120 s | `SIM` | byte/row/general/reserved limits never exceed exact constants; eviction order is local sequence then ID and independent of sender time |
| `ID-001` | identity creation starts with injected entropy | confirmed identity locks | 10,000 seeds; 120 s | `SIM` | each phrase round-trips/checksums, root/ID/cert equals independent implementation, no root/recovery bytes remain after confirmation |
| `ID-002` | parser receives certificate/contact corpus | decision returns | every canonical fixture, one mutation at each byte, 100,000 structural cases; 180 s | `SIM` | only valid canonical/root/device/TTL/KeyPackage bindings accept; no malformed input panics or emits sensitive error |
| `MLS-001` | two valid KeyPackages are supplied | both persist same group state | 1,000 direct groups; 120 s | `SIM`, OpenMLS pinned revision | exactly two members, private wire format/suite 0x0001, bidirectional texts/receipts authenticate and match |
| `MLS-OWNER-001` | 16-member group at epoch E receives proposals/commits | all honest members settle | every member attempts add/remove/update; 5,000 operations, 300 s | `SIM` | only owner membership Commits apply, leaf self-updates apply, >16/duplicate-identity/external/draft-extension changes reject |
| `MLS-EPOCH-001` | group starts epoch E | compromise/decrypt probes finish at E+5 | 100 messages each at E..E+5; 180 s | `SIM` | current plus exactly three prior epochs decrypt when otherwise valid; E is impossible at E+4; exporter records are transactionally deleted with epoch |
| `MLS-INTEROP-001` | fixture is loaded on host A | host B re-encodes/processes | all MLS fixtures on Ubuntu x64 and macOS arm64; 10 min/host | pinned release builds | byte/canonical application fixtures and state-transition digest match; OpenMLS upstream RFC interop suite passes |

## 6. Hostile-input and security acceptance

| ID | Start event | End event | Sample / timeout | Environment | Pass rule |
|---|---|---|---|---|---|
| `SEC-CAPTURE-001` | canary contacts/messages are created | capture/artifact scan ends | 30 min BLE + 30 min WLAN + 30 min LoRa; 60 min analysis | approved physical environments | packet captures, advertisements, radio payload captures, logs, crash output, and relay DB contain none of plaintext/name/stable app identity/MLS group ID/key canaries; expected fixed UUID/mDNS service and padded metadata are documented |
| `SEC-MUTATE-001` | valid corpus is mutated | all decisions recorded | every byte set to 0x00/0xff and every single bit flipped for envelope/header/frame/QR/sync; 10,000 forged cert/signature/tag/replay cases; 300 s | `SIM` | no mutation violating canonical/auth rules yields plaintext/state change; exact duplicates deduplicate; no panic/over-limit allocation/detail oracle |
| `SEC-RELAY-001` | malicious relay controls all scheduling/ACKs | 10,000 traces end | seed `0xdec00120`; replay/drop/mutate/fake custody; 300 s | `SIM` | relay never creates authenticated text/member/receipt or `delivered`; false custody can cause only `accepted_by_mesh`; availability failures are recorded |
| `SEC-FLOOD-001` | attacker opens maximum sessions and streams corpus | quiescent cleanup finishes | 1,000,000 structural objects across 100 virtual peers, 24 virtual h; 600 s | `SIM` | session/concurrency/fragment/cache/TTL/row/byte limits never exceed constants; control reserve works; memory returns within 5% of pre-test RSS after cleanup |
| `SEC-LOCK-001` | seeded app locks and process settles | extraction attempts and unlock finish | each minimum/current OS device; 20 lock cycles, 30 min/device | physical devices, release build, platform backup/debug disabled as production | SQLCipher file/plain file scan exposes no private canary, private DB cannot open without wrapped key, relay continues, valid unlock restores data; unlocked capture limitation recorded |
| `SEC-EPOCH-001` | attacker receives complete epoch-E state | E+4/E+5 ciphertext probes finish | 1,000 messages after four owner updates; 180 s | `SIM` | attacker decrypts allowed E test control but zero E+4/E+5 application/outer payloads; deleted exporter/epoch values absent from DB dump |
| `SEC-LOG-001` | all local error paths execute with canaries | diagnostic export scanner returns | every typed error plus 10,000 fuzz failures; 120 s | `INT`, release logging | export contains allowed aggregate schema only; zero canary/address/ID/QR/key/message matches; injected canary in logger causes export failure |
| `SEC-FUZZ-001` | four parser fuzz targets start | execution budget ends | envelope, QR/CBOR, BLE/sync, Meshtastic; 10 million cases or 60 min each, whichever occurs first | sanitizer-enabled Ubuntu build | zero crash, hang over 1 s/case, sanitizer finding, allocation beyond cap, or accepted invalid corpus; corpus/digest retained |
| `SEC-SUPPLY-001` | clean dependency audit begins | SBOM/scan report closes | every production/transitive dependency and five artifacts; 15 min/platform | `BUILD-5` | immutable pins/checksums match, no denied license/known unapproved vulnerability, SBOM validates, binary scan finds no fixture/release secret; exceptions require dated human record |

## 7. Reliability and performance

| ID | Start event | End event | Sample / timeout | Environment | Pass rule |
|---|---|---|---|---|---|
| `PERF-WLAN-001` | sender queued commit | recipient private commit | 10 warm-up + 100 measured 160-byte ASCII texts, alternating clients; 15 s/message | `WLAN-5`, Android-current↔iOS-current and Windows↔Ubuntu results separate | 100/100 delivered exactly once and p95 < 5.000 s for each pair |
| `PERF-BLE-001` | sender queued commit | recipient private commit | 10 warm-up + 100 measured 160-byte texts, alternating direction; 30 s/message | `BLE-FLOOR`, repeat `BLE-CURRENT` | 100/100 delivered exactly once and p95 < 15.000 s in each environment |
| `PERF-COURIER-001` | recipient first reports courier service discovery | recipient private commit | 100 independent 160-byte texts, fresh sessions; 60 s/message | physical current Android/iOS pairs at 10 m, message already durable on courier | 100/100 exactly once and p95 < 30.000 s; setup time before discovery excluded and separately reported |
| `PERF-LORA-001` | origin gateway queues first LoRa fragment | destination gateway commits complete authenticated envelope | 10 warm-up + 100 measured 160-byte ASCII texts; deterministic loss drops every 10th first-attempt application frame; 300 s/message | `LORA-EU`, forced exactly three radio hops, all three hardware families represented in 34/33/33 measured messages | at least 95/100 arrive exactly once within 300.000 s; retries obey schedule/duty cycle; failures remain in denominator |
| `SOAK-001` | steady-state relay workload and measurement start | eight monotonic hours elapse | 20 msg/min, 30% duplicates, 10% loss, hourly process restart, 8 h | physical Android-current, iOS-current, Ubuntu gateway; foreground conditions recorded separately | no crash/deadlock/corruption; zero duplicate UI events; cache stays within limits; RSS after each hour ≤ baseline +10%; all eligible messages converge by final 10 min |
| `BATT-001` | device is 100% charged, unplugged, workload begins | eight monotonic hours elapse | one run per current phone, repeat once = 2/device; 8 h/run | battery health ≥90%, 20–22°C, screen on at minimum fixed brightness, foreground app, radios/WLAN as SOAK-001, cellular off, low-power mode off | each run loses <20 percentage points; Android/iOS values reported separately; thermal shutdown/background suspension is failure |
| `SCRYPT-001` | passphrase derivation begins | key and peak RSS recorded | 30 runs after 3 warm-ups; 10 s/run | Ubuntu 24.04.4 minimum reference host | every output matches vector; p95 <2.000 s, peak process RSS <192 MiB, no swap/OOM; otherwise fallback profile requires ADR amendment |

## 8. Radio and platform behavior

| ID | Start event | End event | Sample / timeout | Environment | Pass rule |
|---|---|---|---|---|---|
| `BLE-ADV-001` | app begins foreground advertising/scanning | capture ends | 30 min/platform/OS version; 2 h total | `BLE-FLOOR` and `BLE-CURRENT`, external BLE sniffer | only fixed service UUID and OS-controlled fields appear; no local name/service data/manufacturer data/app identifier; 100 foreground discoveries succeed within 30 s each |
| `BLE-BG-001` | user backgrounds/locks app | 30 min observation ends | 10 cycles/device; 30 min/cycle | minimum/current phones | behavior is recorded as best effort; no result is used for foreground acceptance and UI makes no continuous-routing promise |
| `RADIO-CONFIG-001` | app connects read-only to flashed radio | read-back report is signed | each physical radio, 5 cold boots; 10 min/boot | `LORA-EU` | tag/hash match pin and every EU setting matches architecture; mismatch disables app TX and reports exact local setting name without secret |
| `RADIO-COMPAT-001` | first 160-byte test text queues | final cross-family receipt or timeout | every ordered source/destination family pair, 20 each = 120; 5 min/message | `LORA-EU`, one-hop controlled link | at least 19/20 per ordered pair arrive within 5 min, no duplicate/plaintext radio payload, exact frame format and port 256 |
| `RF-GATE-001` | qualified reviewer receives inventory/profile/venue | reviewer signs scope | every radio/antenna/venue, one review valid for named revision | Sweden/EU qualified human | written determination covers frequency, ERP, antenna, duty cycle, conformity, operator, venue, and allowed test procedure; absence is `BLOCKED`, never pass-by-assumption |
| `IOS-LIFECYCLE-001` | foreground BLE/WLAN suite begins | lifecycle cycles finish | 25 foreground connect/send/disconnect and 25 background/return cycles per iPhone; 60 min/device | floor/current iPhones | foreground cycles deliver exactly once and release resources; background cycles never corrupt state/leak secrets; delivery while background is not required |

## 9. Human, legal, signing, and distribution gates

| ID | Start event | End event | Sample / timeout | Environment | Pass rule |
|---|---|---|---|---|---|
| `REV-CRYPTO-001` | independent reviewer receives frozen specs/vectors/source pins | signed findings/disposition closes | entire crypto/protocol composition; no automatic timeout | reviewer independent of author | no unresolved high/critical finding or unresolved security choice; vector reproduction passes; named human accepts all dispositions |
| `REV-LEGAL-001` | qualified reviewer receives distribution/dependency matrix | scoped written determination closes | AGPL, each linked dependency, generated Meshtastic protobufs, stores/direct distribution, notices/source, crypto controls, privacy, territories; no automatic timeout | qualified human; not AI | every listed subject has an explicit allowed/prohibited/conditional outcome and owner; public distribution remains blocked for any absent/conditional unmet item |
| `REV-SIGN-001` | release owner receives signing design | custody drill and approval close | Apple/Android/Windows/macOS channels and incident scenario; one drill/channel | human-controlled credentials/HSM where selected | owner, access, short-lived CI auth, notarization, rotation/revocation, backup, compromise response, and audit evidence are signed; no secret appears in repo/logs |
| `REV-HW-001` | HW-001 inventory inspection begins | manifest signatures complete | every phone, desktop, radio, antenna, cable, attenuator/venue | human physical inspection | actual identifiers/health/software are recorded; missing item remains blocked and no measurement is fabricated |
| `REV-RELEASE-001` | lab release evidence bundle is frozen | product owner signs decision | all matrix rows required for lab scope; no automatic timeout | product/security/platform/RF/legal owners | every required row passes and evidence digests resolve; all blockers scoped out in writing; artifact labelled laboratory/non-operational; public release requires separate approval |

## 10. Required evidence bundle

Each execution stores, under a later task-owned evidence path, the canonical result JSON, raw measurement data, environment manifest, seed/loss schedule, capture or trace digest, command line, and artifact hashes. Hardware and human evidence additionally contains reviewer/operator name, date, scope, source revision, actual device IDs, and signed outcome. Sensitive captures remain access-controlled and are represented in the bundle by digest plus retention location, never copied into public artifacts.

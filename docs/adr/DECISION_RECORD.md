# DEC-001 draft decision record

This record is not signed. DEC-001 remains blocked and all specifications remain drafts until every required outcome is recorded against an immutable source revision or artifact digest. An AI review cannot satisfy a human gate.

| Artifact | Required reviewer | Required evidence | Current outcome |
|---|---|---|---|
| ADR-0001 | Product owner and platform lead | Name, date, source revision, approve/reject, rationale | Not reviewed |
| ADR-0002 | Product owner and independent security reviewer | Name, date, source revision, vector digest, approve/reject, findings disposition | Not reviewed |
| ADR-0003 | Product owner, independent security reviewer, and RF-qualified reviewer | Name, date, source revision, vector digest, RF scope, approve/reject | Not reviewed |
| ADR-0004 | Product owner, qualified legal reviewer, release owner, and RF-qualified reviewer | Names, dates, source revision, scoped written determinations, approve/reject | Not reviewed |
| Five normative specifications | Product owner and engineering lead | Names, date, source revision, specification version, approve/reject | Not reviewed |
| v1 golden vectors | Independent reproducer using `gpt-5.6-sol` at xhigh plus human security reviewer | Both generator commands, byte-identical digest, security-choice checklist, human acceptance | Independent technical review **PASS** at commit `bd82d16833c2f435aef68ca0b048f1226bd72958`, after the preserved failed reviews and corrective commits. No named human security acceptance or approval exists, so this gate remains unapproved. |

## Failed independent technical review — supersedes prior PASS claim

On 2026-08-18, draft.1's Python and Node generators reproduced byte-identical SHA-256 `cc991844bf2987e2ce36216ee87c1af8ce9bc75cb5280765553ba04ee9c939c2`. A preliminary report described that state as passing. The later final independent review of commit `f00c53d3ff263602937150b4339dd79a230ec4d3` found two high-, five medium-, and one low-severity finding. Its outcome is `FAIL`, and it supersedes the preliminary PASS statement everywhere.

The complete report is preserved byte-for-byte at [`reviews/DEC-001-independent-review-fail-2026-08-18.txt`](reviews/DEC-001-independent-review-fail-2026-08-18.txt), SHA-256 `2e059d6c1cfa56206e4c984966a70691d06f7fe0ebf7080f0cb3b772314893df`. The findings cover shared outer-key nonce accounting, the unmeasured 16-member bootstrap, all-zero recovery entropy, routing-slot boundaries, direct/removal membership state, incomplete vectors, an unbounded fragmentation sample, and Noise handshake payloads/lengths.

Draft.2 corrective documents, harnesses, and vectors were not an approval result; the next final review also failed as recorded below. The later cumulative independent technical review passed, but DEC-001 remains blocked until a named human security reviewer accepts the reproduction and composition. None of this evidence is a signature, cryptographic approval, legal opinion, RF determination, hardware result, or product approval.

## Failed draft.2 independent technical review

The final independent review of commit `ee83cbb6cc833a0988ee687e0cbb338454f65c01` reproduced SHA-256 `df345ab74cf40e6508c82171a77de3b213838ed6d4a3794b93d0af085fb277ab` with both generators and returned `FAIL`: one high- and three medium-severity findings remained. This result supersedes any earlier statement that draft.2 passed or was ready for approval.

The supplied report is preserved verbatim at [`reviews/DEC-001-independent-review-fail-2026-08-19.txt`](reviews/DEC-001-independent-review-fail-2026-08-19.txt), SHA-256 `a37b17faddce3404788a4e92abc6dd2d97aad752345276a5213989936db82646`. Its four review dispositions remain unresolved until a new independent reviewer accepts the committed corrections; a local correction checkpoint is evidence of a draft change, not a review disposition.

| Finding | Draft.3 corrective checkpoint | Review disposition |
|---|---|---|
| Known-route custody ACK oracle | Commit `709e5017a3b53d488ee3b99164f9678677e5a3c0` makes durable opaque commit and ACK queueing precede route/authentication processing and adds peer-observable equivalence tests. | Resolved by cumulative independent technical review at `bd82d168`; human acceptance pending |
| Outer-key rollover deadlock | Commit `ab4501f3a415a5f0d9589d410e2aea5f0882dc85` reserves the final old-key seal in one crash-safe persisted self-Update transaction and defines boundary/crash tests. | Resolved by cumulative independent technical review at `bd82d168`; human acceptance pending |
| Nonconforming positive OpenMLS fixture | Commit `b1a986f8d6088a38ac39073d2f907d35a720e7ab` uses a fresh provider-random nonzero 32-byte group ID, retains a conforming run, and regenerates both vector implementations. | Resolved by cumulative independent technical review at `bd82d168`; human acceptance pending |
| Undefined all-fragments-lost timing | The same committed checkpoint as this record defines the four no-delivery/no-entry cases separately from the 1,164 timed incomplete cases without changing the 2,293-schedule total. | Resolved by cumulative independent technical review at `bd82d168`; human acceptance pending |

Draft.3 is therefore a correction candidate only. No local command, generated digest, or author disposition changes either preserved `FAIL` result.

## Failed draft.3 independent technical review

The final independent review of commit `fd871a38e0002ca7c878678a07d05489051d47fd` reproduced the pinned OpenMLS harness once and the byte-identical vector digest `a143cb7c2701c70f56c05dca9f3af37edb6ffe36a07d548c7e7effa0a634022e`. It returned `FAIL` with one high-severity authentication-dependent session-quota oracle. The review found all twelve earlier findings otherwise resolved, but this new contradiction blocks approval.

The supplied report is preserved verbatim at [`reviews/DEC-001-independent-review-fail-2026-08-21.txt`](reviews/DEC-001-independent-review-fail-2026-08-21.txt), SHA-256 `3d5a44cd0c194621f41ef10e9a34edc74a0d7bae8db06a443b66c24f41aefbea`. A subsequent quota correction is a draft change only and does not alter this `FAIL` or constitute review or human approval.

## Failed quota-correction focused re-review

The focused read-only re-review of commit `06e1fe4e736dbed96d2c0339935f782a839bb05b` returned `FAIL`: the normative quota was route-independent, but `PRO-CUSTODY-001` incorrectly required quota behavior for the first offer above the former 262,144-byte boundary even though it remained below the common 1,048,576-byte limit.

The supplied report is preserved verbatim at [`reviews/DEC-001-independent-review-fail-2026-08-21-2.txt`](reviews/DEC-001-independent-review-fail-2026-08-21-2.txt), SHA-256 `3024874a4c01d0bfff0033c48cf47aaf862e2e1f2a25a83f0f4d5f53f3958144`. At that checkpoint, the later schedule correction remained an unreviewed draft change; it was subsequently covered by the cumulative technical review below. Neither result approves DEC-001.

## Cumulative independent technical review pass

The focused read-only cumulative re-review at commit `bd82d16833c2f435aef68ca0b048f1226bd72958` returned `PASS` with no actionable findings. It confirmed the corrected quota schedules, route-independent behavior, and consistent review records over the final corrective range.

The supplied report is preserved verbatim at [`reviews/DEC-001-independent-review-pass-2026-08-22.txt`](reviews/DEC-001-independent-review-pass-2026-08-22.txt), SHA-256 `799adb5a0825b52f028b9181c9f4ef8c3f440858f94f6fe6714c7f7acb5046a8`. This is an independent technical result only. DEC-001 remains an unapproved draft pending every named human, physical, legal, RF, signing, and distribution gate already required by this record.

## Approval semantics

An approval is valid only when it identifies all reviewed files, their Git tree or per-file SHA-256 digests, the reviewer, date, outcome, and any conditions. Conditional or partial approval leaves dependent implementation blocked. Any normative edit after approval invalidates the affected approval and requires a new record.

## Recorded blockers at draft publication

1. The cumulative independent technical review passed at `bd82d168`, but named human findings acceptance is absent.
2. Human security acceptance of the reproduced vectors and security-choice checklist is absent.
3. Reference phones, desktops, and radios are not inventoried or physically qualified.
4. EU/Swedish RF compliance has not been determined for an actual radio/antenna/test venue.
5. AGPL, store, generated-protobuf, cryptography-distribution, signing, and public-distribution legal determinations are absent.
6. Ubuntu 26.04 LTS is newer than the Flutter-supported Ubuntu ceiling used by this draft.
7. The five-platform Flutter/Rust bridge build and Android API-37 toolchain are not qualified.
8. SQLCipher tag-signature provenance remains unresolved until the signer key is obtained from an authoritative Zetetic source or a signed exception is approved.

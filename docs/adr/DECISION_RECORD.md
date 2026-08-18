# DEC-001 draft decision record

This record is not signed. DEC-001 remains blocked and all specifications remain drafts until every required outcome is recorded against an immutable source revision or artifact digest. An AI review cannot satisfy a human gate.

| Artifact | Required reviewer | Required evidence | Current outcome |
|---|---|---|---|
| ADR-0001 | Product owner and platform lead | Name, date, source revision, approve/reject, rationale | Not reviewed |
| ADR-0002 | Product owner and independent security reviewer | Name, date, source revision, vector digest, approve/reject, findings disposition | Not reviewed |
| ADR-0003 | Product owner, independent security reviewer, and RF-qualified reviewer | Name, date, source revision, vector digest, RF scope, approve/reject | Not reviewed |
| ADR-0004 | Product owner, qualified legal reviewer, release owner, and RF-qualified reviewer | Names, dates, source revision, scoped written determinations, approve/reject | Not reviewed |
| Five normative specifications | Product owner and engineering lead | Names, date, source revision, specification version, approve/reject | Not reviewed |
| v1 golden vectors | Independent reproducer using `gpt-5.6-sol` at xhigh plus human security reviewer | Both generator commands, byte-identical digest, security-choice checklist, human acceptance | **FAIL** for draft.1 at commit `f00c53d3ff263602937150b4339dd79a230ec4d3`: byte reproduction succeeded, but final independent review found eight unresolved defects. Draft.2 regeneration/review and human acceptance are pending. |

## Failed independent technical review — supersedes prior PASS claim

On 2026-08-18, draft.1's Python and Node generators reproduced byte-identical SHA-256 `cc991844bf2987e2ce36216ee87c1af8ce9bc75cb5280765553ba04ee9c939c2`. A preliminary report described that state as passing. The later final independent review of commit `f00c53d3ff263602937150b4339dd79a230ec4d3` found two high-, five medium-, and one low-severity finding. Its outcome is `FAIL`, and it supersedes the preliminary PASS statement everywhere.

The complete report is preserved byte-for-byte at [`reviews/DEC-001-independent-review-fail-2026-08-18.txt`](reviews/DEC-001-independent-review-fail-2026-08-18.txt), SHA-256 `2e059d6c1cfa56206e4c984966a70691d06f7fe0ebf7080f0cb3b772314893df`. The findings cover shared outer-key nonce accounting, the unmeasured 16-member bootstrap, all-zero recovery entropy, routing-slot boundaries, direct/removal membership state, incomplete vectors, an unbounded fragmentation sample, and Noise handshake payloads/lengths.

Draft.2 corrective documents, harnesses, and vectors are not an independent review result. DEC-001 remains blocked until a new independent reproducer checks the complete corrected revision and a named human security reviewer accepts the reproduction and composition. None of this evidence is a signature, cryptographic approval, legal opinion, RF determination, hardware result, or product approval.

## Approval semantics

An approval is valid only when it identifies all reviewed files, their Git tree or per-file SHA-256 digests, the reviewer, date, outcome, and any conditions. Conditional or partial approval leaves dependent implementation blocked. Any normative edit after approval invalidates the affected approval and requires a new record.

## Recorded blockers at draft publication

1. A new independent cryptographic composition review and human findings acceptance are absent; the prior final technical result is FAIL.
2. Human security acceptance of the reproduced vectors and security-choice checklist is absent.
3. Reference phones, desktops, and radios are not inventoried or physically qualified.
4. EU/Swedish RF compliance has not been determined for an actual radio/antenna/test venue.
5. AGPL, store, generated-protobuf, cryptography-distribution, signing, and public-distribution legal determinations are absent.
6. Ubuntu 26.04 LTS is newer than the Flutter-supported Ubuntu ceiling used by this draft.
7. The five-platform Flutter/Rust bridge build and Android API-37 toolchain are not qualified.
8. SQLCipher tag-signature provenance remains unresolved until the signer key is obtained from an authoritative Zetetic source or a signed exception is approved.

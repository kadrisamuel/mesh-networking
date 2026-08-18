# DEC-001 draft decision record

This record is not signed. DEC-001 remains blocked and all specifications remain drafts until every required outcome is recorded against an immutable source revision or artifact digest. An AI review cannot satisfy a human gate.

| Artifact | Required reviewer | Required evidence | Current outcome |
|---|---|---|---|
| ADR-0001 | Product owner and platform lead | Name, date, source revision, approve/reject, rationale | Not reviewed |
| ADR-0002 | Product owner and independent security reviewer | Name, date, source revision, vector digest, approve/reject, findings disposition | Not reviewed |
| ADR-0003 | Product owner, independent security reviewer, and RF-qualified reviewer | Name, date, source revision, vector digest, RF scope, approve/reject | Not reviewed |
| ADR-0004 | Product owner, qualified legal reviewer, release owner, and RF-qualified reviewer | Names, dates, source revision, scoped written determinations, approve/reject | Not reviewed |
| Five normative specifications | Product owner and engineering lead | Names, date, source revision, specification version, approve/reject | Not reviewed |
| v1 golden vectors | Independent reproducer using `gpt-5.6-sol` at xhigh plus human security reviewer | Both generator commands, byte-identical digest, security-choice checklist, human acceptance | Automated reproduction PASS on 2026-08-18 at SHA-256 `cc991844bf2987e2ce36216ee87c1af8ce9bc75cb5280765553ba04ee9c939c2`; human acceptance not reviewed |

## Automated technical review evidence — not approval

On 2026-08-18, a separate `gpt-5.6-sol` xhigh reviewer ran the Python and Node.js generators, compared their complete canonical JSON byte-for-byte, checked the checked-in digest above, and independently reviewed representative derivations, source anchors, binary layouts, parse ordering, collision handling, LoRa padding, recovery/bootstrap roles, platform-key profiles, platform pins, and release-tag provenance. Its first pass found blocking collision-vector and bilateral-recovery inconsistencies. Those findings were corrected; its final report was `PASS` with no unresolved security-critical choice, blocking inconsistency, or high-severity defect.

This evidence satisfies only DEC-001's required second-model reproduction. It is not a signature, cryptographic approval, legal opinion, RF determination, hardware result, or product approval. The vector row and DEC-001 remain blocked until a named human security reviewer accepts the reproduction and composition against an immutable source revision.

## Approval semantics

An approval is valid only when it identifies all reviewed files, their Git tree or per-file SHA-256 digests, the reviewer, date, outcome, and any conditions. Conditional or partial approval leaves dependent implementation blocked. Any normative edit after approval invalidates the affected approval and requires a new record.

## Recorded blockers at draft publication

1. Human independent cryptographic composition review and findings acceptance are absent; the automated technical pass does not satisfy this gate.
2. Human security acceptance of the reproduced vectors and security-choice checklist is absent.
3. Reference phones, desktops, and radios are not inventoried or physically qualified.
4. EU/Swedish RF compliance has not been determined for an actual radio/antenna/test venue.
5. AGPL, store, generated-protobuf, cryptography-distribution, signing, and public-distribution legal determinations are absent.
6. Ubuntu 26.04 LTS is newer than the Flutter-supported Ubuntu ceiling used by this draft.
7. The five-platform Flutter/Rust bridge build and Android API-37 toolchain are not qualified.
8. SQLCipher tag-signature provenance remains unresolved until the signer key is obtained from an authoritative Zetetic source or a signed exception is approved.

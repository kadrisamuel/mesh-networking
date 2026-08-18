# DEC-001 draft decision record

This record is not signed. DEC-001 remains blocked and all specifications remain drafts until every required outcome is recorded against an immutable source revision or artifact digest. An AI review cannot satisfy a human gate.

| Artifact | Required reviewer | Required evidence | Current outcome |
|---|---|---|---|
| ADR-0001 | Product owner and platform lead | Name, date, source revision, approve/reject, rationale | Not reviewed |
| ADR-0002 | Product owner and independent security reviewer | Name, date, source revision, vector digest, approve/reject, findings disposition | Not reviewed |
| ADR-0003 | Product owner, independent security reviewer, and RF-qualified reviewer | Name, date, source revision, vector digest, RF scope, approve/reject | Not reviewed |
| ADR-0004 | Product owner, qualified legal reviewer, release owner, and RF-qualified reviewer | Names, dates, source revision, scoped written determinations, approve/reject | Not reviewed |
| Five normative specifications | Product owner and engineering lead | Names, date, source revision, specification version, approve/reject | Not reviewed |
| v1 golden vectors | Independent reproducer using `gpt-5.6-sol` at xhigh plus human security reviewer | Both generator commands, byte-identical digest, security-choice checklist, human acceptance | Not reviewed |

## Approval semantics

An approval is valid only when it identifies all reviewed files, their Git tree or per-file SHA-256 digests, the reviewer, date, outcome, and any conditions. Conditional or partial approval leaves dependent implementation blocked. Any normative edit after approval invalidates the affected approval and requires a new record.

## Recorded blockers at draft publication

1. Independent cryptographic composition review is absent.
2. Second-model vector/security reproduction is absent.
3. Reference phones, desktops, and radios are not inventoried or physically qualified.
4. EU/Swedish RF compliance has not been determined for an actual radio/antenna/test venue.
5. AGPL, store, generated-protobuf, cryptography-distribution, signing, and public-distribution legal determinations are absent.
6. Ubuntu 26.04 LTS is newer than the Flutter-supported Ubuntu ceiling used by this draft.

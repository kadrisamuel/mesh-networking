# Draft architecture decision records

These records are DEC-001 draft decisions. They are normative for review, but none is approved and no implementation may rely on them until every row in [DECISION_RECORD.md](DECISION_RECORD.md) has a human `Approved` outcome.

| ADR | Subject | Status |
|---|---|---|
| [ADR-0001](0001-platform-and-architecture-baseline.md) | Platforms, ownership, dependencies, and hardware | Draft — human approval required |
| [ADR-0002](0002-identity-cryptography-and-recovery.md) | Identity, MLS, recovery, and storage | Draft — security review and human approval required |
| [ADR-0003](0003-envelope-relay-and-transport.md) | Envelope, relay, BLE/WLAN, and LoRa | Draft — security, RF, and human approval required |
| [ADR-0004](0004-distribution-and-compliance-gates.md) | Licensing, signing, stores, and distribution | Draft — qualified legal and human approval required |

The five files in `docs/spec/` and the versioned fixtures in `docs/spec/vectors/v1/` are part of these decisions. If prose conflicts, the exact constants and byte layouts in the v1 specifications govern after approval.

The final independent reviews of draft.1, draft.2, and draft.3 failed, and the focused re-review of the first quota correction also failed. Their byte-preserved reports are [`reviews/DEC-001-independent-review-fail-2026-08-18.txt`](reviews/DEC-001-independent-review-fail-2026-08-18.txt), [`reviews/DEC-001-independent-review-fail-2026-08-19.txt`](reviews/DEC-001-independent-review-fail-2026-08-19.txt), [`reviews/DEC-001-independent-review-fail-2026-08-21.txt`](reviews/DEC-001-independent-review-fail-2026-08-21.txt), and [`reviews/DEC-001-independent-review-fail-2026-08-21-2.txt`](reviews/DEC-001-independent-review-fail-2026-08-21-2.txt). The cumulative independent technical review then passed at commit `bd82d16833c2f435aef68ca0b048f1226bd72958`; its report is [`reviews/DEC-001-independent-review-pass-2026-08-22.txt`](reviews/DEC-001-independent-review-pass-2026-08-22.txt). This technical result is not approval: DEC-001 remains a draft pending every required named human, physical, legal, RF, signing, and distribution gate.

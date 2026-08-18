# ADR-0004: Distribution and compliance gates

- Status: Draft — qualified legal review and human approval required
- Decision date: 2026-08-18
- Scope: DEC-001 only

## Context

The proposed AGPL application links or interoperates with third-party components, may be distributed through controlled stores, uses cryptography, and can transmit on regulated spectrum. An engineering specification cannot supply legal advice.

## Proposed decision

Project-authored code is intended for AGPL-3.0-or-later, subject to qualified legal confirmation. Do not make a public binary release, store submission, field deployment, or claim of license compatibility until counsel or another qualified human records conclusions for AGPL/store terms, linked-component licenses, generated Meshtastic protobuf output, copyright notices/source obligations, cryptography import/export controls, privacy disclosures, and the relevant distribution territories.

Pin Meshtastic protobuf schemas and generate bindings; never copy firmware/client implementation code. Do not bundle Meshtastic firmware in application artifacts. If firmware is later redistributed, record its exact source, corresponding source offer/availability, notices, and GPL-3.0 obligations before distribution.

Pull-request and laboratory artifacts are unsigned and clearly labeled non-operational. Production signing, Apple notarization, and store credentials remain human-controlled outside the repository and CI logs. CI may use short-lived identity federation only after a separately approved release design. No signing secret, recovery secret, radio payload, or stable user identifier may enter source control or build logs.

RF transmit tests are disabled until the signed compliance record names the country, location, radio, antenna, region preset, power, duty-cycle policy, and operator. EU_868 is the only proposed v1 region; this is not a legal determination that every listed setup is lawful.

## Consequences

- Local documentation, simulation, and receive-only development may proceed after the technical ADRs are approved.
- Public distribution, signed release, and RF transmission remain blocked independently of test success.
- Store feasibility is a release gate rather than an assumed property of AGPL licensing.

## Approval blockers

- No qualified legal review is recorded.
- No release-signing design, credential custodian, or incident/revocation process is recorded.
- No physical RF inventory or jurisdiction-specific compliance sign-off is recorded.
- No App Store, Google Play, Microsoft Store, or direct-distribution determination is recorded.

## Sources

- [GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html)
- [Meshtastic firmware license at the pinned commit](https://github.com/meshtastic/firmware/blob/54e0d8d0ab2ff56b3a9ce967e53f79e49af560fb/LICENSE)
- [Meshtastic protobufs license at the pinned commit](https://github.com/meshtastic/protobufs/blob/da60cee584c6dc1efbb4a3809b98666505179b85/LICENSE)
- [Apple upcoming submission requirements](https://developer.apple.com/news/upcoming-requirements/)
- [EU Commission Implementing Decision (EU) 2025/105](https://eur-lex.europa.eu/eli/dec_impl/2025/105/oj/eng)

## Human decision required

A qualified reviewer must record the legal determinations; a release owner must approve signing custody; an RF-qualified reviewer must approve any transmit procedure. Approval of this ADR records the gates, not the absent determinations.

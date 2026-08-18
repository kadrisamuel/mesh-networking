# ADR-0003: Envelope, relay, and transport baseline

- Status: Draft — independent security review, RF qualification, and human approval required
- Decision date: 2026-08-18
- Scope: DEC-001 only

## Context

BLE, WLAN, and LoRa must carry one bounded store-and-forward object without revealing MLS group identifiers or trusting relay clocks and acknowledgements.

## Proposed decision

Use the v1 80-byte outer header and padded sealed body in `PROTOCOL_V1.md`. All multibyte integers are unsigned big-endian. The authenticated header is normalized by zeroing only `hops_remaining` and `pow_nonce`; those two fields may be changed by relays. Every other header byte, including original hop limit, timestamps, traffic class, sizes, routing tag, envelope ID, and nonce, is authenticated. Duplicate identity is the normalized header plus sealed body, not the envelope ID alone: byte-identical immutable content merges to the highest valid remaining-hop value and lowest valid proof-of-work nonce, while the same ID on different immutable content is quarantined as a collision. Unknown-route admission requires 18 leading zero SHA-256 bits. Envelopes use fixed total-length classes of 256, 512, 1,024, 1,536, 2,048, 3,072, 4,096, or 8,192 bytes. The 8,192-byte class follows a pinned OpenMLS measurement of a 7,094-byte minimum positive 16-member bootstrap; the retained harness and fixture are normative evidence.

Routing tags rotate in six-hour UTC slots. To preserve store-and-forward at exact skew boundaries, receivers derive the inclusive candidate range from `oldest_created=max(0,W-TTL-9)` through `newest_created=min(2^32-1,W+10)`. This includes user slot `S-5` and control slot `S-29` while they remain admissible at the start of a new slot, and includes `S+1` only in the final ten minutes. User TTL is 24 hours; control, revocation, and receipt TTL is seven days. Sender timestamps are authenticated admission hints, never eviction clocks. A receiver establishes a monotonic local deadline at first admission and applies the exact skew and cap rules in the protocol specification.

BLE advertises one fixed service UUID and no local name, identity, rotating identifier, or contact data. Session-only random identifiers are exchanged after a Noise `NN` encrypted channel exists. Both handshake payloads are empty; NN messages are exactly 32 and 48 bytes. WLAN uses a fresh random per-process identifier as its mDNS instance and the same framed Noise synchronization protocol over TCP. Crossed sessions are deterministically reduced using the encrypted process and session IDs. V1 sync moves only opaque envelopes: it has no routing-tag list, MLS snapshot, repair request, or state-transfer record. Noise provides opportunistic link encryption, not peer identity; MLS/COSE authentication remains authoritative.

Meshtastic carries already sealed v1 envelopes as `PRIVATE_APP` port 256 data. Use standard firmware and generated v2.7.26 schemas only. The application frame is exactly 180 bytes: 20 header bytes plus 160 fragment bytes, at most ten fragments. An envelope admitted to LoRa is at most 1,536 bytes. Fragment counts map exactly to the supported LoRa envelope sizes, and only the declared meaningful prefix of the final fragment participates in reassembly; its random tail is transport padding. A sender caches and retransmits byte-identical fragment frames, allowing different gateways to combine retries without requiring identical independently generated padding. Meshtastic's own hop limit is three and is independent of the application hop budget. Radio/channel encryption is not end-to-end security.

Delivery states are `queued`, `accepted_by_mesh`, `delivered`, and `expired`. A durable per-hop custody ACK can advance to `accepted_by_mesh` but never to `delivered`. Only an authenticated MLS receipt from the current direct-chat peer advances a direct message to `delivered`. Groups never emit per-member delivery or read receipts.

## Consequences

- Fixed size classes reduce but do not eliminate size/timing leakage.
- Noise NN does not stop an active nearby intermediary from dropping traffic or observing timing.
- Mutable hop fields are enforceable for honest relays only; malicious relays can reset them, while TTL, quotas, deduplication, and proof of work remain the abuse bounds.
- Unauthenticated claimed traffic classes consume general capacity only; reserved control capacity is available only after cryptographic class verification.
- LoRa delivery is capacity constrained and regulatory duty-cycle enforcement overrides retry timing.

## Approval blockers

- The outer composition and bootstrap path have not received human independent cryptographic approval; the preserved draft.1 review failed and draft.2 has not been independently reviewed.
- BLE behavior, RF airtime, range, duty cycle, loss, battery, and timing claims lack physical measurements.
- EU 868 operation requires a qualified human to confirm the device, antenna, effective radiated power, firmware configuration, venue, and local Swedish rules before transmission.
- The pinned Meshtastic firmware is a beta release and needs explicit human risk acceptance.

## Sources

- [Noise Protocol Framework revision 34](https://noiseprotocol.org/noise.html)
- [Apple Core Bluetooth background processing](https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html)
- [Android BLE background guidance](https://developer.android.com/develop/connectivity/bluetooth/ble/background)
- [Meshtastic LoRa configuration](https://meshtastic.org/docs/configuration/radio/lora/)
- [Meshtastic radio settings](https://meshtastic.org/docs/overview/radio-settings/)
- [Meshtastic protobuf PortNum schema v2.7.26](https://github.com/meshtastic/protobufs/blob/v2.7.26/meshtastic/portnums.proto)
- [EU Commission Implementing Decision (EU) 2025/105](https://eur-lex.europa.eu/eli/dec_impl/2025/105/oj/eng)

## Human decision required

Approve or reject the authenticated/mutable split, routing overlap, quota and ACK semantics, fixed BLE discovery, opportunistic Noise use, foreground limitation, and exact LoRa ceiling as one decision.

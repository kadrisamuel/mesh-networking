# Protocol specification v1.0.0-draft.1

- Status: Draft — independent security review and human approval required
- Decision set: DEC-001, 2026-08-18
- Wire version: 1

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are normative. Integers are unsigned and big-endian unless explicitly stated. Byte offsets are zero-based. Parsers MUST reject non-canonical encodings, trailing data outside a fixed padding class, duplicate CBOR keys, indefinite CBOR items, unsupported values, nonzero reserved bits, and integer overflow. There is no version fallback.

Cryptographic operations, labels, and keys are defined in `CRYPTOGRAPHY_V1.md`. Golden bytes are in `vectors/v1/vectors.json`.

## 1. Limits

| Constant | v1 value |
|---|---:|
| UTF-8 text body | 512 bytes after NFC normalization |
| Complete envelope | 4,096 bytes |
| Envelope header | 80 bytes |
| Padding classes | 256, 512, 1,024, 1,536, 2,048, 3,072, 4,096 bytes |
| Application hop limit | 8 |
| User TTL | 1,440 minutes |
| Control/revocation/receipt TTL | 10,080 minutes |
| Clock-skew tolerance | 10 minutes |
| Routing-tag slot | 360 minutes |
| Proof-of-work difficulty | 18 leading zero SHA-256 bits |
| Relay cache | 52,428,800 stored envelope bytes and 10,000 envelopes |
| Per sync session | 256 newly offered envelopes and 1,048,576 envelope bytes per direction |
| Sync session duration | 60 seconds from completed Noise handshake |
| LoRa application frame | 180 bytes |
| LoRa fragment data | 160 bytes |
| LoRa fragments/envelope | 10 |
| LoRa envelope ceiling | 1,536 bytes |
| Fragment cache | 128 assemblies, 2,097,152 bytes, 600 seconds |

## 2. Complete envelope

### 2.1 Header layout

Every envelope is exactly `total_length` bytes and starts with this 80-byte header:

| Offset | Size | Field | Required value/rule |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `MSH1` (`4d534831`) |
| 4 | 1 | `version` | `1` |
| 5 | 1 | `seal_mode` | `1` MLS epoch AEAD; `2` one-time HPKE bootstrap |
| 6 | 1 | `traffic_class` | `1` user; `2` MLS control; `3` device-replacement notice; `4` delivery receipt |
| 7 | 1 | `flags` | bit 0 `RELAY_ALLOWED` MUST be 1; bits 1–7 zero |
| 8 | 2 | `total_length` | one padding-class value |
| 10 | 2 | `sealed_length` | exactly `total_length - 80` |
| 12 | 16 | `envelope_id` | fresh random 128-bit value; all-zero forbidden |
| 28 | 16 | `routing_tag` | derived for the envelope creation slot |
| 44 | 4 | `created_minute` | `floor(Unix seconds / 60)` at creation |
| 48 | 4 | `expires_minute` | exact class TTL added to `created_minute`, without overflow |
| 52 | 12 | `nonce` | random AES-GCM nonce for mode 1; all zero for mode 2 |
| 64 | 1 | `original_hop_limit` | exactly 8 for locally created v1 envelopes |
| 65 | 1 | `hops_remaining` | 0–8 and no greater than `original_hop_limit` |
| 66 | 2 | `reserved_0` | zero |
| 68 | 8 | `pow_nonce` | proof-of-work counter chosen by sender |
| 76 | 4 | `reserved_1` | zero |

`total_length`, `sealed_length`, the physical input length, and the padding class MUST agree before allocation or cryptography. A parser MUST cap the input at 4,096 bytes before reading declared sizes.

### 2.2 Authenticated and mutable fields

`normalized_header` is a copy of bytes 0–79 with byte 65 (`hops_remaining`) and bytes 68–75 (`pow_nonce`) replaced by zero. It is the AEAD/HPKE associated data. Therefore only `hops_remaining` and `pow_nonce` are mutable in transit. Every other byte is authenticated.

A relay sends `max(0, stored_hops_remaining - 1)` without changing its stored canonical copy. It MUST NOT forward an envelope whose stored value is zero. Multiple outbound transports from the same node use the same decremented value. Meshtastic's internal hop counter is separate. Because hop fields are mutable, a malicious relay can reset them; TTL, proof of work, deduplication, and quota are the security bounds.

### 2.3 Sealed body and padding

The unsealed body has this format:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | `body_version = 1` |
| 1 | 1 | `body_kind`: `1` complete TLS-serialized MLSMessage; `2` bootstrap record |
| 2 | 2 | `content_length` |
| 4 | `content_length` | content bytes |
| next | remainder | fresh CSPRNG padding bytes |

Mode 1 seals the entire unsealed body with AES-128-GCM and appends its 16-byte tag; its unsealed size is `sealed_length - 16`. Mode 2 produces `enc[32] || hpke_ciphertext`; its unsealed size is `sealed_length - 32 - 16`. The sender MUST choose the smallest padding class that fits. Receivers authenticate before parsing `body_version`, `body_kind`, `content_length`, or padding. Padding has no semantic value and is not required to match any byte pattern.

Mode/body combinations are exact: mode 1 permits body kind 1 only; mode 2 permits body kind 2 only. Mode 1 traffic class MUST agree with the enclosed MLS object/application kind. Mode 2 is permitted only for a Welcome bootstrap and uses traffic class 2. Mismatch is `POLICY_REJECT`.

### 2.4 Proof of work

All sender-created v1 envelopes MUST satisfy proof of work so validation does not reveal whether a route is known. Define `pow_header` as the transmitted header with byte 65 zeroed and bytes 68–75 left as transmitted. The condition is:

```text
SHA-256(UTF8("mesh-messenger/v1/pow") || pow_header || sealed_body)
```

The first 18 most-significant digest bits MUST be zero. Search starts at counter 0 and increments the unsigned 64-bit `pow_nonce`; exhaustion fails closed. A receiver verifies this before route lookup or expensive cryptography. Relays MAY replace `pow_nonce` only with another satisfying value.

### 2.5 Identity, duplication, and parse order

`envelope_id` is an opaque random deduplication key, not a message identifier. A sender MUST durably reserve it before emission and MUST generate a new envelope ID and nonce for every re-encryption or retransmission that changes sealed bytes. Byte-identical transport retries retain the envelope ID and entire envelope.

External bytes are processed in this exact order:

1. enforce physical size cap;
2. check magic, version, enum ranges, reserved bytes, declared lengths, and padding class;
3. check class/TTL arithmetic and coarse time admission;
4. check duplicate ID and conflicting-byte collision;
5. verify proof of work;
6. enforce source/session/global quotas;
7. if a key is available, authenticate/decrypt and validate inner canonical content;
8. commit the complete opaque envelope and local metadata atomically;
9. emit custody ACK only after durable commit.

The same envelope ID with different bytes is an attack: discard the offered bytes, retain the first admitted copy, close that peer session, and increment only an aggregate collision counter. Identical bytes are a duplicate and may be acknowledged as such.

## 3. Time, TTL, and routing slots

### 3.1 TTL validation without trusting sender clocks

Class 1 MUST have `expires_minute - created_minute = 1,440`. Classes 2–4 MUST have a difference of 10,080. Other differences are rejected.

At first admission let `W` be local wall-clock Unix minutes and `M` a monotonic instant. Reject if `created_minute > W + 10` or `expires_minute + 10 <= W`. Set the immutable local deletion deadline to:

```text
M + min(class_ttl, max(0, expires_minute + 10 - W)) minutes
```

Expiry processing uses only this monotonic deadline after admission. Wall-clock changes cannot extend it. A sender can shorten storage with an old timestamp but cannot extend a receiver beyond one class TTL. When the deadline is reached, stop forwarding and delete the relay copy. Private seven-day UI history is governed separately and never extends relay or MLS-key retention.

### 3.2 Routing-tag slots and overlap

`slot = floor(created_minute / 360)`. A sender computes exactly one tag for that slot. For a local wall time `W`, an unlocked recipient precomputes candidate tags for every unexpired slot:

- class 1: slots `floor(W/360)-4` through `floor(W/360)`;
- classes 2–4: slots `floor(W/360)-28` through `floor(W/360)`;
- add slot `floor(W/360)+1` only during the final ten minutes of the current slot.

During the first ten minutes, the prior slot is already included by the ranges above. Outside the final ten minutes, a next-slot tag is rejected. After route lookup, the receiver recomputes the exact tag from the authenticated `created_minute` slot and requires constant-time equality. Candidate tags are generated for the current plus three retained MLS epochs only. A message from an older deleted epoch is undecryptable even if its TTL remains.

This explicit catch-up window preserves 24-hour/seven-day store-and-forward while tags still change every six hours. Tag lists MUST be sent only inside Noise and MUST NOT appear in BLE or mDNS discovery.

## 4. Canonical CBOR records

All application-defined structured records use RFC 8949 deterministic encoding: definite lengths, shortest integer/length encoding, map keys in encoded-byte order, no floats, no tags, no duplicate keys, and UTF-8 text normalized to NFC. Unknown required keys or any unknown enum value fail closed. Array limits are checked before allocation.

### 4.1 MLS application plaintext

An MLS application message contains one map:

```text
{
  0: 1,                    / format version /
  1: kind,                 / 1 text, 2 delivery receipt, 3 device-replacement notice /
  2: event_id,             / bstr .size 16, random and nonzero /
  3: sender_counter,       / uint64, strictly increasing per MLS sender leaf /
  4: payload
}
```

- Text payload is an NFC UTF-8 text string of 0–512 encoded bytes. C0 controls are forbidden except LF (`U+000A`); DEL is forbidden. The UI MAY trim for display but persisted/authenticated text is unchanged.
- Delivery-receipt payload is `{0: target_event_id}` where the value is a 16-byte ID of a direct text message. A receipt is created only after authenticated MLS decryption and durable private persistence of that text.
- Device-replacement-notice payload is a byte string containing the root-signed device certificate defined in `CRYPTOGRAPHY_V1.md`. It creates a pending prompt only; it MUST NOT activate an instance without explicit contact acceptance.

Application messages and post-join MLS handshakes MUST use MLS PrivateMessage wire format. MLS draft extensions are disabled. KeyPackage and credential validation fails for any cipher suite other than `0x0001`.

### 4.2 Bootstrap record

An HPKE bootstrap body contains one COSE_Sign1 signed by the inviter device with the external AAD fixed in `CRYPTOGRAPHY_V1.md`. Its deterministic-CBOR payload is:

```text
{
  0: 1,                    / format version /
  1: bundle_id,            / bstr .size 16 /
  2: welcome,              / bstr, complete TLS-serialized MLS Welcome /
  3: inviter_credential,   / bstr, deterministic MLS BasicCredential identity CBOR /
  4: conversation_kind,    / 1 direct, 2 private group /
  5: owner_identity_id,    / null for direct; bstr .size 16 for group /
  6: invitation_id         / bstr .size 16, random and nonzero /
}
```

The complete COSE object MUST be at most 2,000 bytes. The Welcome MUST use the ratchet-tree extension, cipher suite `0x0001`, and the one-time KeyPackage identified by `bundle_id`. The inviter credential/signature MUST match an already accepted contact and the Welcome's authenticated committer. A consumed, expired, unknown, or mismatched bundle is rejected without network detail. Direct bootstrap must result in exactly two members and a null owner. Group bootstrap must result in 2–16 members, a non-null owner equal to the inviter identity, and an owner credential matching the locally accepted group invitation.

### 4.3 QR contact card

The presentation form is ASCII `meshmsg:v1:` followed by unpadded base64url of a COSE_Sign1 contact bundle from `CRYPTOGRAPHY_V1.md`. Input is capped at 4,096 ASCII bytes before decoding; decoded COSE is capped at 2,048 bytes. Whitespace, padding `=`, alternate alphabets, non-ASCII, or a non-canonical re-encoding is rejected. Contact bundles expire exactly 10,080 minutes after issuance and contain a one-time KeyPackage/bootstrap HPKE key. A scanner MUST display the safety number and require explicit confirmation before persisting the contact.

## 5. Relay quotas and eviction

The hard global limits are both 52,428,800 envelope bytes and 10,000 envelope rows; reaching either is full. Of these, 5,242,880 bytes and 1,000 rows are reserved for classes 2–4. Class 1 can use at most 47,185,920 bytes and 9,000 rows. Control traffic may use unused general capacity.

For each Noise session and direction, accept at most 256 newly offered envelope IDs and 1,048,576 total envelope bytes, whichever is reached first. Duplicates count toward offered IDs and bytes so they cannot bypass work limits. For a connection that has not completed an authenticated MLS/COSE operation, additionally accept at most 64 new envelopes and 262,144 bytes in any 60-second session. The session closes at 60 seconds regardless of progress. Maximum concurrent sessions are four on mobile and sixteen on desktop; excess peers receive only a generic busy close.

Eviction occurs before rejecting an otherwise admissible envelope:

1. delete monotonic-expired entries;
2. delete structurally invalid rows found by integrity scan;
3. for class 1 admission, evict oldest class 1 rows until both general limits fit;
4. for classes 2–4, evict oldest class 1 rows, then oldest control rows if required.

“Oldest” is ascending local first-seen monotonic sequence, then lexicographic envelope ID. No sender timestamp influences eviction order. If the incoming object alone exceeds its applicable limit, reject it. Quota accounting uses complete stored envelope bytes, not declared plaintext size or filesystem allocation.

## 6. Noise synchronization over byte streams

BLE and WLAN use Noise revision 34 protocol name `Noise_NN_25519_ChaChaPoly_SHA256` with the exact prologue in `CRYPTOGRAPHY_V1.md`. Noise NN is unauthenticated: it provides per-link confidentiality/integrity only. Conversation authentication comes only from MLS/COSE.

After the handshake, each encrypted transport message contains one four-byte length prefix followed by one canonical CBOR sync map. The CBOR length is 1–65,000 bytes. The prefix is inside the Noise transport ciphertext, so plaintext is at most 65,004 bytes and the 16-byte Noise tag keeps the ciphertext below Noise's 65,535-byte message limit. The map common keys are `0: 1` (version), `1: kind`, and `2: payload`:

| Kind | Name | Payload and limit |
|---:|---|---|
| 1 | `HELLO` | `{0: session_id bstr16, 1: max_envelope=4096, 2: max_offer=256}` |
| 2 | `INVENTORY` | array of 1–256 envelope IDs, sorted, unique |
| 3 | `REQUEST` | array of 1–256 envelope IDs, sorted, unique subset of inventory |
| 4 | `PUSH` | array of 1–15 complete envelope byte strings totaling at most 61,440 bytes |
| 5 | `CUSTODY_ACK` | array of 1–256 `[envelope_id, status]`; status 0 stored, 1 identical duplicate |
| 6 | `GOODBYE` | reason 0 complete, 1 quota, 2 timeout, 3 superseded |
| 7 | `ERROR` | generic reason 0 protocol or 1 busy; immediately close |

Each side sends exactly one HELLO first. Inventories contain only envelopes the sender is willing to forward and MUST be chunked across records. A receiver requests only absent IDs, PUSHes only requested IDs, and acknowledges only after durable relay/private commit. Receipt of an unrequested envelope, out-of-order first message, limit violation, or second HELLO is a generic protocol close. A session ends on bilateral GOODBYE, error, disconnect, quota, or 60-second timeout. Resume starts a new Noise session and inventory; no unauthenticated resume token exists.

## 7. BLE link

The fixed UUIDs are RFC 9562 UUIDv5 values under the URL namespace:

| Role | Name input | UUID |
|---|---|---|
| Service | `https://mesh-messenger.invalid/ble/service/v1` | `6c39fca5-35c7-5ff9-a135-f157bcd2a295` |
| Central-to-peripheral write | `https://mesh-messenger.invalid/ble/write/v1` | `db882ebd-6df3-5284-b196-594e34798f70` |
| Peripheral-to-central indicate | `https://mesh-messenger.invalid/ble/indicate/v1` | `a6d07640-438a-5407-880f-01d8815543de` |

Foreground advertisements include only the service UUID: no local name, manufacturer data, service data, stable/rotating app identifier, identity, or contact value. Ephemeral OS BLE addresses are outside application control. The encrypted HELLO session ID is the first application identifier. iOS background advertisements and scans are best-effort and are not acceptance paths.

GATT characteristic values carry `LinkChunk`:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | version 1 |
| 1 | 1 | flags: bit 0 START, bit 1 END; others zero |
| 2 | 2 | record ID |
| 4 | 2 | sequence number |
| 6 | 2 | payload length |
| 8 | variable | payload bytes |

Payload length MUST equal characteristic-value length minus 8 and MUST be no greater than negotiated ATT MTU minus 11. One Noise handshake message or one Noise transport ciphertext is one record. Record IDs start at a random 16-bit value after connect and increment modulo 65,536; reuse is forbidden while a record is live. Sequence starts at zero, START appears only on zero, increments without gaps, and END appears only on the final nonempty chunk. Only one record per direction may be in flight. GATT write-with-response and indications provide flow control. A missing response/confirmation or incomplete record after 15 monotonic seconds closes the connection and discards the partial record. Reassembled records are capped at 65,535 bytes before allocation.

## 8. WLAN link

Each process start creates a random 128-bit lowercase-hex mDNS instance name. It advertises service `_meshmsg._tcp.local.`, TTL 120 seconds, on a randomly selected available TCP port in 49152–65535, with the sole TXT pair `v=1`. Hostnames and OS network metadata can still leak outside the application. The app advertises no display name, identity, contact, or stable instance value.

The listener accepts at most the platform session concurrency limit. TCP connects enter Noise immediately. The first Noise handshake byte must arrive within five seconds; the complete handshake must finish within ten seconds; otherwise close. Each Noise handshake/transport ciphertext is framed outside Noise with a four-byte big-endian length capped at 65,535. The encrypted sync length prefix described in section 6 remains inside the transport ciphertext. TCP keepalive is not a liveness guarantee; all reads/writes obey the 60-second session deadline.

## 9. LoRa fragmentation and Meshtastic

Only complete envelopes of 256, 512, 1,024, or 1,536 bytes are eligible. Fragment count is `ceil(total_length / 160)` and therefore 2, 4, 7, or 10. Each `PRIVATE_APP` payload is exactly 180 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | frame version 1 |
| 1 | 1 | flags zero |
| 2 | 16 | envelope ID copied from header |
| 18 | 1 | zero-based fragment index |
| 19 | 1 | fragment count 1–10 |
| 20 | 160 | consecutive envelope bytes; final unused bytes are fresh random padding |

All fragments MUST use identical ID/count and unique indices. Reassembly concatenates indices, parses the inner envelope's authenticated `total_length`, requires the count to equal `ceil(total_length/160)`, trims only bytes after `total_length`, and requires the frame ID to equal the envelope header ID. Conflicting bytes for one ID/index discard the entire assembly and suppress that ID for the remainder of the ten-minute fragment deadline. Duplicate identical fragments are ignored.

Fragment storage is capped globally at 128 assemblies and 2,097,152 bytes. An assembly expires 600 monotonic seconds after its first fragment and is never extended. On pressure, evict earliest deadline then lexicographic ID. Fragment bytes are never forwarded or stored in the relay database until the complete envelope passes admission.

The adapter sends each fragment with Meshtastic port 256 and `want_ack=true`. Attempt 1 is immediate; if no successful Meshtastic Routing acknowledgement, attempts 2 and 3 become eligible 15 and 45 seconds after the preceding attempt, with zero application jitter in v1. The firmware may delay/refuse transmission for duty cycle. Stop on success, terminal radio error, envelope expiry, or five minutes after the first attempt. The next fragment starts only after success or exhausted attempts. The entire envelope is `accepted_by_mesh` only after every fragment has a successful Routing acknowledgement. This is hop/radio acceptance, never end-to-end delivery.

## 10. Delivery state machine

Private message state is keyed by MLS application `event_id`, not envelope ID.

| State | Exact entry event | Allowed next state |
|---|---|---|
| `queued` | text and required MLS/envelope state commit in one private transaction, before first transport attempt | `accepted_by_mesh`, `expired`, `delivered` |
| `accepted_by_mesh` | any BLE/WLAN peer durably ACKs the complete envelope, or every LoRa fragment receives a successful radio Routing ACK | `expired`, `delivered` |
| `expired` | all locally mapped envelopes reach monotonic expiry without an authenticated receipt | `delivered` only |
| `delivered` | current direct-chat peer sends a valid MLS receipt for the event and the receipt is durably stored | terminal |

For groups, `delivered` is unreachable; UI displays `queued`, `accepted_by_mesh` (labelled “relayed”), or `expired`. No read receipt exists. Custody ACKs are protected by the current Noise channel or radio link only and MUST NOT be displayed as contact delivery. A late valid direct receipt may correct `expired` to `delivered` while the seven-day private history row exists.

## 11. Errors and observability

Local typed codes are `MALFORMED`, `UNSUPPORTED_VERSION`, `DUPLICATE`, `ID_COLLISION`, `EXPIRED`, `FUTURE_TIME`, `POW_INVALID`, `AUTH_FAILED`, `POLICY_REJECT`, `QUOTA`, `BUSY`, `TIMEOUT`, `RADIO_REFUSED`, and `STORAGE_FAILED`. They MUST carry no offending bytes, IDs, addresses, cryptographic details, or plaintext.

Before Noise, errors are silent connection close. Inside Noise, only generic sync `ERROR` protocol/busy is sent; cryptographic, route, quota-detail, and parser reasons are not exposed. Meshtastic malformed frames are silently dropped. Unsupported v1 values never trigger downgrade. Logs aggregate error-code counts in coarse ten-minute buckets and MUST NOT correlate them with a peer, route, envelope, or conversation.

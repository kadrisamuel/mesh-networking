# Protocol specification v1.0.0-draft.2

- Status: Draft — independent security review and human approval required
- Decision set: DEC-001, 2026-08-18
- Wire version: 1

The words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **MAY** are normative. Integers are unsigned and big-endian unless explicitly stated. Byte offsets are zero-based. Parsers MUST reject non-canonical encodings, trailing data outside a fixed padding class, duplicate CBOR keys, indefinite CBOR items, unsupported values, nonzero reserved bits, and integer overflow. There is no version fallback.

Cryptographic operations, labels, and keys are defined in `CRYPTOGRAPHY_V1.md`. Golden bytes are in `vectors/v1/vectors.json`. Draft.2 corrects the eight findings in the preserved failed draft.1 review and has not yet passed a new independent review.

## 1. Limits

| Constant | v1 value |
|---|---:|
| UTF-8 text body | 512 bytes after NFC normalization |
| Complete envelope | 8,192 bytes |
| Envelope header | 80 bytes |
| Padding classes | 256, 512, 1,024, 1,536, 2,048, 3,072, 4,096, 8,192 bytes |
| Application hop limit | 8 |
| User TTL | 1,440 minutes |
| Control/revocation/receipt TTL | 10,080 minutes |
| Clock-skew tolerance | 10 minutes |
| Routing-tag slot | 360 minutes |
| Proof-of-work difficulty | 18 leading zero SHA-256 bits |
| Relay cache | 52,428,800 stored envelope bytes and 10,000 envelopes |
| Per sync session | 256 offered envelope entries (duplicates included) and 1,048,576 envelope bytes per direction |
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

`total_length`, `sealed_length`, the physical input length, and the padding class MUST agree before allocation or cryptography. A parser MUST cap the input at 8,192 bytes before reading declared sizes.

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

`envelope_id` is an opaque random deduplication key, not a message identifier. A sender MUST durably reserve it before emission and MUST generate a new envelope ID and nonce for every re-encryption or retransmission that changes any authenticated byte or sealed byte. Byte-identical transport retries retain the envelope ID and entire envelope.

For duplicate/collision comparison, `canonical_content = normalized_header || sealed_body`. Two offers with the same envelope ID and byte-identical canonical content are the same envelope even when their transmitted `hops_remaining` or `pow_nonce` differs. Every new mutable variant must independently pass structural, time, and proof-of-work checks, counts against session offered-ID/byte limits, and consumes no new global row. Merge an admitted variant by storing the maximum valid `hops_remaining` and the numerically smallest valid `pow_nonce`; this deterministic forwarding form is not an end-to-end authenticated value. A malicious relay can still reset hops, as section 2.2 states.

External bytes are processed in this exact order:

1. enforce physical size cap;
2. check magic, version, enum ranges, reserved bytes, declared lengths, and padding class;
3. check class/TTL arithmetic and coarse time admission;
4. verify proof of work for every offer, including duplicates and tentative collisions;
5. charge source/session offered-ID and byte counters, including duplicates and tentative collisions, and reject if their limits are exceeded;
6. locate any existing ID and compare canonical content; a canonical mismatch is an ID collision, an exact admitted byte string is a duplicate, and a mutable-only variant continues;
7. enforce global row/byte quotas for a new canonical object; an existing canonical object consumes no second global row;
8. if a key is available, authenticate/decrypt and validate inner canonical content;
9. atomically commit a new canonical object or merge the selected mutable values into its existing row;
10. emit custody ACK only after durable commit.

The same envelope ID with different canonical content is an attack: discard the offered bytes, retain the first admitted canonical object, close that peer session, and increment only an aggregate collision counter. Identical bytes and valid mutable-only variants are duplicates and may receive duplicate custody status. Invalid mutable variants are rejected and never alter the stored form.

## 3. Time, TTL, and routing slots

### 3.1 TTL validation without trusting sender clocks

Class 1 MUST have `expires_minute - created_minute = 1,440`. Classes 2–4 MUST have a difference of 10,080. Other differences are rejected.

At first admission let `W` be local wall-clock Unix minutes and `M` a monotonic instant. Reject if `created_minute > W + 10` or `expires_minute + 10 <= W`. Set the immutable local deletion deadline to:

```text
M + min(class_ttl, max(0, expires_minute + 10 - W)) minutes
```

Expiry processing uses only this monotonic deadline after admission. Wall-clock changes cannot extend it. A sender can shorten storage with an old timestamp but cannot extend a receiver beyond one class TTL. When the deadline is reached, stop forwarding and delete the relay copy. Private seven-day UI history is governed separately and never extends relay or MLS-key retention.

### 3.2 Routing-tag slots and overlap

`slot = floor(created_minute / 360)`. A sender computes exactly one tag for that slot. For local wall-clock Unix minute `W`, traffic-class TTL `T`, and uint32 timestamps, compute in a wider signed integer type:

```text
oldest_created = max(0, W - T - 9)
newest_created = min(2^32 - 1, W + 10)
oldest_slot    = floor(oldest_created / 360)
newest_slot    = floor(newest_created / 360)
```

The recipient precomputes every slot in that inclusive range. The `-9` is required by the strict admission test `created_minute + T + 10 > W`: during wall-minute offsets 0–8 of a new slot, this includes user slot `S-5` and control slot `S-29`; at offset 9 those slots are no longer admissible. `newest_slot` includes `S+1` only for offsets 350–359. These formulas replace approximate fixed ranges and cover the exact skew boundaries without accepting a slot that cannot contain an admissible timestamp. After route lookup, the receiver recomputes the exact tag from the authenticated `created_minute` slot and requires constant-time equality. Candidate tags are generated for the current plus three retained MLS epochs only. A message from an older deleted epoch is undecryptable even if its TTL remains.

This explicit catch-up window preserves 24-hour/seven-day store-and-forward while tags still change every six hours. V1 never transmits routing-tag lists, including inside Noise; a recipient performs route lookup only after receiving an offered envelope. Tags MUST NOT appear in BLE, mDNS, HELLO, INVENTORY, or REQUEST records.

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

For an active direct chat, every post-bootstrap membership-changing Proposal or Commit is a policy rejection; this includes Add, Remove, PSK, ReInit, external, and any future unsupported membership mechanism. Only an authenticated leaf Update by that same direct member may proceed. For a private group, the owner and resulting-roster rules in `CRYPTOGRAPHY_V1.md` apply. A valid owner Commit that removes the local member completes MLS authentication first, then atomically enters the `REMOVED` deletion/UI/rejoin state defined there; its post-removal application content is never processed.

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

The complete COSE object MUST be at most 8,060 bytes, the exact content capacity of an 8,192-byte mode-2 envelope after its 80-byte header, 32-byte HPKE encapsulated key, 16-byte AEAD tag, and four-byte inner header. The Welcome MUST use the ratchet-tree extension, cipher suite `0x0001`, and the one-time KeyPackage identified by `bundle_id`. The inviter credential/signature MUST match an already accepted contact and the Welcome's authenticated committer. A consumed, expired, unknown, or mismatched bundle is rejected without network detail. Direct bootstrap must result in exactly two members and a null owner. Group bootstrap must result in 2–16 members, a non-null owner equal to the inviter identity, and an owner credential matching the locally accepted group invitation.

The pinned OpenMLS harness measured the positive 16-member application-bound case: 6,622-byte Welcome, 6,962-byte signed COSE, and 7,094-byte minimum complete envelope. It therefore occupies the 8,192-byte padding class and is BLE/WLAN-only. This does not raise the LoRa ceiling. A bootstrap is eligible for LoRa only when its complete padded envelope is one of the four LoRa sizes in section 9.

### 4.3 QR contact card

The presentation form is ASCII `meshmsg:v1:` followed by unpadded base64url of a COSE_Sign1 contact bundle from `CRYPTOGRAPHY_V1.md`. Input is capped at 4,096 ASCII bytes before decoding; decoded COSE is capped at 2,048 bytes. Whitespace, padding `=`, alternate alphabets, non-ASCII, or a non-canonical re-encoding is rejected. Contact bundles expire exactly 10,080 minutes after issuance and contain a one-time KeyPackage/bootstrap HPKE key. A scanner MUST display the safety number and require explicit confirmation before persisting the contact.

## 5. Relay quotas and eviction

The hard global limits are both 52,428,800 envelope bytes and 10,000 envelope rows; reaching either is full. Of these, 5,242,880 bytes and 1,000 rows are reserved for cryptographically verified classes 2–4. Class 1 and every locked, unknown-route, or not-yet-authenticated object share the 47,185,920-byte/9,000-row general limit, regardless of claimed header class. After successful outer and MLS/COSE authentication, an unlocked endpoint atomically marks the object verified and may account it to the control reserve. Verified control traffic may use unused general capacity.

`traffic_class` is authenticated by the outer container only for a recipient with the key; it is untrusted quota input before then. An opaque courier can therefore preserve a claimed seven-day control TTL but cannot consume reserved control rows/bytes. Attackers can still spend valid proof of work to occupy general capacity for the claimed TTL; this bounded availability risk is explicit and no relay guesses whether an unknown route is legitimate.

For each Noise session and direction, accept at most 256 newly offered envelope IDs and 1,048,576 total envelope bytes, whichever is reached first. Duplicates count toward offered IDs and bytes so they cannot bypass work limits. For a connection that has not completed an authenticated MLS/COSE operation, additionally accept at most 64 new envelopes and 262,144 bytes in any 60-second session. The session closes at 60 seconds regardless of progress. Maximum concurrent sessions are four on mobile and sixteen on desktop; excess peers receive only a generic busy close.

Eviction occurs before rejecting an otherwise admissible envelope:

1. delete monotonic-expired entries;
2. delete structurally invalid rows found by integrity scan;
3. for general admission, evict oldest general rows until both general limits fit;
4. for verified-control admission, evict oldest general rows, then oldest verified-control rows if required.

“Oldest” is ascending local first-seen monotonic sequence, then lexicographic envelope ID. No sender timestamp influences eviction order. If the incoming object alone exceeds its applicable limit, reject it. Quota accounting uses complete stored envelope bytes, not declared plaintext size or filesystem allocation.

## 6. Noise synchronization over byte streams

BLE and WLAN use Noise revision 34 protocol name `Noise_NN_25519_ChaChaPoly_SHA256` with the exact prologue in `CRYPTOGRAPHY_V1.md`. Noise NN is unauthenticated: it provides per-link confidentiality/integrity only. Conversation authentication comes only from MLS/COSE.

Both NN handshake payloads MUST be the empty byte string. The initiator's `-> e` message is exactly 32 bytes. The responder's `<- e, ee` message is exactly 48 bytes: 32 bytes of ephemeral public key plus the 16-byte AEAD tag on the empty payload. The sender MUST pass a zero-length payload to the Noise API; the receiver MUST require zero recovered payload bytes and the exact encoded length before entering transport mode. Any other handshake length or nonempty recovered payload is a generic protocol close. No sync or application bytes may be carried in a handshake payload.

After the handshake, each encrypted transport message contains one four-byte length prefix followed by one canonical CBOR sync map. The CBOR length is 1–65,000 bytes. The prefix is inside the Noise transport ciphertext, so plaintext is at most 65,004 bytes and the 16-byte Noise tag keeps the ciphertext below Noise's 65,535-byte message limit. The map common keys are `0: 1` (version), `1: kind`, and `2: payload`:

| Kind | Name | Payload and limit |
|---:|---|---|
| 1 | `HELLO` | `{0: session_id bstr16, 1: node_run_id bstr16, 2: max_envelope=8192, 3: max_offer=256}`; both IDs nonzero |
| 2 | `INVENTORY` | array of 1–256 envelope IDs, sorted, unique |
| 3 | `REQUEST` | array of 1–256 envelope IDs, sorted, unique subset of inventory |
| 4 | `PUSH` | array of 1–15 complete envelope byte strings totaling at most 61,440 bytes |
| 5 | `CUSTODY_ACK` | array of 1–256 `[envelope_id, status]`; status 0 stored, 1 canonical duplicate including a valid mutable-only variant |
| 6 | `GOODBYE` | reason 0 complete, 1 quota, 2 timeout, 3 superseded |
| 7 | `ERROR` | generic reason 0 protocol or 1 busy; immediately close |

Each side sends exactly one HELLO first. `session_id` is fresh per Noise session; `node_run_id` is the process value from `ARCHITECTURE.md`. Inventories contain only unexpired envelopes with positive stored hops, ordered by local first-seen monotonic sequence then envelope ID, and MUST be chunked across records. V1 performs no route negotiation: this bounded inventory selection is identical whether or not the peer knows any route. A receiver requests only absent IDs, PUSHes only requested IDs, and acknowledges only after durable relay/private commit. Receipt of an unrequested envelope, out-of-order first message, limit violation, or second HELLO is a generic protocol close.

After both HELLOs, concurrent sessions with the same remote `node_run_id` and transport class are superseded deterministically. For each session compute `pair_id = min(local_session_id, remote_session_id) || max(local_session_id, remote_session_id)` using unsigned lexicographic order. Both endpoints keep the session with the lexicographically smallest pair ID and send GOODBYE reason 3 on every loser; equal pair IDs on distinct connections close both as protocol errors. BLE and WLAN are separate transport classes and do not supersede one another. This rule is an availability/deduplication rule, not identity authentication.

A session ends on bilateral GOODBYE, supersession, error, disconnect, quota, or 60-second timeout. Resume starts a new Noise session and full inventory; no resume token, state snapshot, MLS repair record, or routing-tag-list record exists.

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

The mDNS instance name is the lowercase hexadecimal `node_run_id` created at process start. It advertises service `_meshmsg._tcp.local.`, TTL 120 seconds, on a randomly selected available TCP port in 49152–65535, with the sole TXT pair `v=1`. Hostnames and OS network metadata can still leak outside the application. The app advertises no display name, identity, contact, or value stable across process runs.

The listener accepts at most the platform session concurrency limit. TCP connects enter Noise immediately. The first Noise handshake byte must arrive within five seconds; the complete handshake must finish within ten seconds; otherwise close. Each Noise handshake/transport ciphertext is framed outside Noise with a four-byte big-endian length capped at 65,535. For NN handshake flights those prefixes MUST encode exactly 32 and 48 respectively. The encrypted sync length prefix described in section 6 remains inside the transport ciphertext. TCP keepalive is not a liveness guarantee; all reads/writes obey the 60-second session deadline.

## 9. LoRa fragmentation and Meshtastic

Only complete envelopes of 256, 512, 1,024, or 1,536 bytes are eligible. The 2,048-, 3,072-, 4,096-, and 8,192-byte classes MUST NOT enter the LoRa fragmenter and may move only over BLE/WLAN. Fragment count is `ceil(total_length / 160)` and therefore exactly 2, 4, 7, or 10; every other count is rejected before allocation. The count uniquely fixes total length and meaningful final-fragment bytes as `{2: (256, 96), 4: (512, 32), 7: (1,024, 64), 10: (1,536, 96)}`. Each `PRIVATE_APP` payload is exactly 180 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | frame version 1 |
| 1 | 1 | flags zero |
| 2 | 16 | envelope ID copied from header |
| 18 | 1 | zero-based fragment index |
| 19 | 1 | fragment count exactly 2, 4, 7, or 10 |
| 20 | 160 | consecutive envelope bytes; final unused bytes are fresh random padding |

All fragments MUST use identical ID/count and unique indices. For a non-final index all 160 data bytes are meaningful. For the final index only the mapped prefix length above is meaningful; its remaining random tail is ignored for duplicate/conflict comparison and never enters the reassembled envelope. Thus independently fragmenting gateways may use different final padding without conflict. Reassembly concatenates meaningful prefixes, structurally parses the inner envelope `total_length`, requires it to equal the count mapping, and requires the frame ID to equal the envelope header ID before ordinary envelope admission authenticates that header. Conflicting meaningful bytes for one ID/index discard the entire assembly and suppress that ID for the remainder of the ten-minute fragment deadline. Duplicates with equal meaningful bytes are ignored even if final padding differs.

Fragment storage is capped globally at 128 assemblies and 2,097,152 bytes. An assembly expires 600 monotonic seconds after its first fragment and is never extended. On pressure, evict earliest deadline then lexicographic ID. Fragment bytes are never forwarded or stored in the relay database until the complete envelope passes admission.

The fragmenter caches the exact 180-byte frame set for one gateway/envelope before the first send; all retries by that gateway reuse those byte-identical frames. The adapter sends each fragment with Meshtastic port 256 and `want_ack=true`. Attempt 1 is immediate; if no successful Meshtastic Routing acknowledgement, attempts 2 and 3 become eligible 15 and 45 seconds after the preceding attempt, with zero application jitter in v1. The firmware may delay/refuse transmission for duty cycle. Stop on success, terminal radio error, envelope expiry, or five minutes after the first attempt. The next fragment starts only after success or exhausted attempts. The entire envelope is `accepted_by_mesh` only after every fragment has a successful Routing acknowledgement. This is hop/radio acceptance, never end-to-end delivery.

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

Local typed codes are `MALFORMED`, `UNSUPPORTED_VERSION`, `DUPLICATE`, `ID_COLLISION`, `EXPIRED`, `FUTURE_TIME`, `POW_INVALID`, `AUTH_FAILED`, `POLICY_REJECT`, `REPAIR_REQUIRED`, `QUOTA`, `BUSY`, `TIMEOUT`, `RADIO_REFUSED`, and `STORAGE_FAILED`. They MUST carry no offending bytes, IDs, addresses, cryptographic details, or plaintext.

Before Noise, errors are silent connection close. Inside Noise, only generic sync `ERROR` protocol/busy is sent; cryptographic, route, quota-detail, and parser reasons are not exposed. Meshtastic malformed frames are silently dropped. Unsupported v1 values never trigger downgrade. Logs aggregate error-code counts in coarse ten-minute buckets and MUST NOT correlate them with a peer, route, envelope, or conversation.

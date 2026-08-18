# Normative v1 draft vectors

- Status: Draft — draft.1 final review failed; draft.2 awaits independent reproduction and human security approval
- Vector schema: `mesh-messenger-vectors/1`
- Specification: `1.0.0-draft.2`
- Checked-in `vectors.json` SHA-256: `df345ab74cf40e6508c82171a77de3b213838ed6d4a3794b93d0af085fb277ab`
- OpenMLS application fixture SHA-256: `1015e46e7423a57bc00e12c0c7008c648cb468a3df0b41cea77c3ad585395b7f`

`vectors.json` is generated, never hand-edited. Every private value is deterministic public test material and MUST NOT be used in production.

## Reproduction

The two vector generators share no implementation source and use different language/runtime cryptographic bindings:

```text
python3 docs/spec/vectors/v1/generate_vectors.py --output /tmp/vectors-python.json
node docs/spec/vectors/v1/generate_vectors.mjs --output /tmp/vectors-node.json
cmp /tmp/vectors-python.json /tmp/vectors-node.json
cmp /tmp/vectors-python.json docs/spec/vectors/v1/vectors.json
shasum -a 256 /tmp/vectors-python.json /tmp/vectors-node.json docs/spec/vectors/v1/vectors.json
```

The frozen vector environment is Python 3.14.4 with `cryptography` 46.0.7 and Node.js 25.9.0 using built-in `node:crypto`. Both commands must exit zero, both `cmp` commands must produce no output, and all three digests must equal the vector digest above.

The positive application-bound MLS evidence is reproducible from a clean checkout of the exact pinned OpenMLS revision with the retained Rust harness, exact top-level equality pins, full `Cargo.lock`, source/toolchain checks, and generated fixture:

```text
docs/spec/vectors/v1/openmls_harness/reproduce.sh /tmp/dec001-openmls-review /tmp/dec001-openmls-measurement.reproduced.json /Users/kadri.samuel/.cargo/bin/cargo /Users/kadri.samuel/.cargo/bin/rustc
```

The harness command must satisfy every assertion in `openmls_harness/README.md`. Provider randomness makes regenerated MLS bytes different, but the pinned encoded lengths, 16-member join, application sender, exporter contexts, and wrong-recipient result are stable. The checked fixture is the exact generated input consumed by both vector generators.

## Coverage

| Vector section | Normative coverage |
|---|---|
| `identity` | nonzero positive BIP-39 entropy/checksum/phrase; all-zero retry/failure control; root HKDF, Ed25519 public keys, identity IDs, safety number |
| `canonical_objects` | deterministic CBOR/COSE device and contact objects; positive application-bound KeyPackage, 16-member Welcome, and 8,192-byte bootstrap; independently computed credential mismatch; wrong-recipient Welcome rejected by OpenMLS; upstream application-mismatch control |
| `openmls_upstream` | pinned official suite-`0x0001` fixtures and exporter KAT; application harness digest; routing exporter and all 16 four-byte sender contexts/outer keys |
| `routing_and_user_envelope` | actual harness-produced MLS application message, matching leaf-0 outer key, routing tag, exact header normalization, AES-128-GCM, proof of work, complete 512-byte envelope |
| `duplicate_merge` | valid mutable variants and a complete same-ID/different-content collision fixture |
| `bootstrap_envelope` | measured positive 16-member signed record, RFC 9180 HPKE Base values, 7,094-byte minimum, exact 8,192-byte padded envelope, proof of work |
| `application_cbor` | text, delivery receipt, and device-replacement notice variants |
| `noise_nn` | empty 32/48-byte NN handshakes, handshake hash, split keys, both transport directions, and pinned `snow` cross-check |
| `ble_and_wlan` | handshake and transport frames/chunks plus HELLO, INVENTORY, REQUEST, PUSH, both custody statuses, all GOODBYE reasons, and both ERROR reasons |
| `lora` | all four size/count/final-prefix mappings, complete 180-byte frames, two ignored final-tail values, and frame/envelope digests |
| `platform_storage_wrap` | `L_DATABASE_WRAP_AAD`; exact Android 86-byte AES-GCM record; iOS/macOS Keychain profiles; Windows DPAPI entropy and deterministic opaque-record encoding; Ubuntu Secret Service profile |
| `linux_storage_wrap` | RFC 7914 scrypt parameters/output and exact 92-byte fallback record |
| `uuids` | RFC 9562 UUIDv5 inputs and fixed BLE UUIDs |

Padding uses explicit ascending byte patterns and LoRa final padding uses `a5`/`5a` solely for reproducibility. Production uses fresh OS CSPRNG bytes.

The checked application fixture was generated at OpenMLS commit `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6`. It contains 199-byte application credentials, a 474-byte KeyPackage, a 6,622-byte complete TLS `MlsMessage` Welcome, a successful 16-member join with no external tree, 16 distinct per-sender outer keys, and a recipient-processed application message whose authenticated sender is leaf 0. The negative Welcome uses an outsider's valid application-bound KeyPackage and produces `NoMatchingKeyPackage`. The upstream OpenMLS case remains valid upstream but deliberately fails the separate application binding.

Both generators first reproduce case zero's official exporter result, derive all application-defined upstream exporter contexts independently, then verify and consume the retained positive fixture. They reproduce the pinned `snow.txt` case before producing the application-prologue empty handshakes. Any source digest, KAT, application credential, size, sender context, or negative-result mismatch terminates generation.

## Standards conformance incorporated by reference

Local vectors cover application-defined derivations and layouts. Production libraries must also pass their authoritative suites:

- HKDF: [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A)
- Ed25519: [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html#section-7)
- HPKE: [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A)
- MLS: [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html#name-test-vectors) and [pinned OpenMLS vectors](https://github.com/openmls/openmls/tree/47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6/openmls/test_vectors); `welcome.json` SHA-256 `06be9d5c99817ef2545e4b15b8e73fd9b604685a8e55b59ca168eda98e236502`, `key-schedule.json` SHA-256 `05aa9a68bd2538ace72d8c53375984cc728ef62220ebf314df675708546d97a7`
- AES-GCM: [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- CBOR/COSE: [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) and [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
- scrypt: [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html#section-12)
- Noise: [revision 34](https://noiseprotocol.org/noise.html) and pinned [`snow` commit `4bb43f5`](https://github.com/mcginty/snow/tree/4bb43f50370bdb3e8b1b57814ac662864db2704f); `snow.txt` SHA-256 `69da433305fd045f6c9f01b656662a389d022688986fd39fbe7af009cd402fd3`

`snow` has not received a formal audit. Its use remains blocked until a human independent security reviewer accepts that risk; MLS/COSE remains the authentication boundary.

## Review gate

The preserved final review of draft.1 is `FAIL` and supersedes its preliminary PASS claim. Draft.2's generators currently reproduce locally, but no new independent review has occurred. A new independent reproducer must verify this entire corrective revision and explicitly dispose all eight findings; a named human security reviewer must then accept the result against an immutable source revision. Until then these vectors and every dependent decision remain drafts.

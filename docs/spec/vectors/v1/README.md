# Normative v1 draft vectors

- Status: Draft — automated reproduction passed; human security approval required
- Vector schema: `mesh-messenger-vectors/1`
- Specification: `1.0.0-draft.1`
- Checked-in `vectors.json` SHA-256: `cc991844bf2987e2ce36216ee87c1af8ce9bc75cb5280765553ba04ee9c939c2`

`vectors.json` is generated, never hand-edited. All private values are deterministic test material and MUST NOT be used in production.

## Reproduction

The two generators share no source code and use different language/runtime bindings:

```text
python3 docs/spec/vectors/v1/generate_vectors.py --output /tmp/vectors-python.json
node docs/spec/vectors/v1/generate_vectors.mjs --output /tmp/vectors-node.json
cmp /tmp/vectors-python.json /tmp/vectors-node.json
shasum -a 256 /tmp/vectors-python.json
```

The frozen DEC-001 reproduction environment is Python 3.14.4 with `cryptography` 46.0.7 and Node.js 25.9.0 using built-in `node:crypto`. Both commands MUST exit zero, `cmp` MUST produce no output, and the digest MUST equal the value above. A later build task may package these exact environments without changing the vector bytes.

## Coverage

| Vector section | Normative coverage |
|---|---|
| `identity` | BIP-39 256-bit checksum indices/phrase, HKDF root derivation, Ed25519 public keys, identity IDs, safety number |
| `canonical_objects` | deterministic CBOR, root-signed device certificate, MLS BasicCredential identity bytes, device-signed contact bundle/QR and bootstrap record, plus the required credential-mismatch rejection |
| `openmls_upstream` | valid suite-`0x0001` KeyPackage and Welcome bytes, pinned file/commit digests, an upstream exporter KAT, and the exact application exporter labels with empty context |
| `routing_and_user_envelope` | exporter-derived routing/outer secrets, six-hour routing tag, exact header normalization, AES-128-GCM body, deterministic padding fixture, 18-bit proof of work, complete 256-byte envelope |
| `duplicate_merge` | one immutable envelope with two valid mutable header variants, deterministic merge result, and a complete valid-PoW same-ID/different-content envelope that reaches the quarantine rule |
| `bootstrap_envelope` | bootstrap routing tag, RFC 9180 HPKE Base key schedule/X25519/AES-128-GCM, signed record, exact 1,024-byte envelope, proof of work |
| `application_cbor` | canonical text application record |
| `noise_nn` | complete deterministic Noise NN handshake, handshake hash, split keys, bidirectional transport ciphertexts, and exact pinned-`snow` KAT cross-check |
| `ble_and_wlan` | both canonical HELLOs including process IDs, encrypted-plaintext length frames, a Noise transport ciphertext, BLE `LinkChunk`, and WLAN ciphertext-length frame |
| `lora` | complete 180-byte fragments, meaningful final prefix, two different ignored final-padding tails, and fragment digests |
| `linux_storage_wrap` | scrypt parameters/output and exact 92-byte AES-256-GCM wrapping record |
| `uuids` | RFC 9562 UUIDv5 inputs and fixed BLE UUIDs |

Padding uses an explicit ascending byte pattern, and final LoRa padding uses `a5`, solely to make fixtures reproducible. Production MUST use fresh OS CSPRNG bytes.

The KeyPackage and Welcome are copied byte-for-byte from case zero of the pinned OpenMLS `welcome.json` and are valid upstream suite-`0x0001` objects. Their embedded credential, lifetime, group, and invitation do not match the application fixture's independently generated identity and invitation; `canonical_objects.application_binding_expected` therefore requires `POLICY_REJECT_UPSTREAM_OBJECT_NOT_APPLICATION_BOUND`. This negative binding result is deliberate and does not make the upstream objects invalid. A production contact or invitation MUST contain freshly generated OpenMLS objects bound to the enclosing credential and invitation.

Both generators first reproduce case zero's exporter result from `key-schedule.json`, then derive the application routing secret and outer key using the two exact labels and empty context. They also reproduce all four ciphertexts of the pinned `Noise_NN_25519_ChaChaPoly_SHA256` `snow.txt` case before producing the application-prologue handshake. Any upstream KAT mismatch terminates generation.

## Standards conformance incorporated by reference

Local vectors cover every application-defined derivation and binary layout. Standard-library internals MUST also pass their authoritative known-answer/conformance suites; copying those large suites into this repository would create a divergent duplicate.

- HKDF: [RFC 5869 test cases](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A)
- Ed25519: [RFC 8032 test vectors](https://www.rfc-editor.org/rfc/rfc8032.html#section-7)
- HPKE: [RFC 9180 test vectors](https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A)
- MLS: [RFC 9420 test vectors](https://www.rfc-editor.org/rfc/rfc9420.html#name-test-vectors) and the [OpenMLS vectors at the pinned commit](https://github.com/openmls/openmls/tree/47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6/openmls/test_vectors); `welcome.json` SHA-256 is `06be9d5c99817ef2545e4b15b8e73fd9b604685a8e55b59ca168eda98e236502` and `key-schedule.json` SHA-256 is `05aa9a68bd2538ace72d8c53375984cc728ef62220ebf314df675708546d97a7`
- AES-GCM: [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) and provider validation suite
- deterministic CBOR/COSE: [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) and [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
- scrypt: [RFC 7914 test vectors](https://www.rfc-editor.org/rfc/rfc7914.html#section-12)
- Noise: [Noise revision 34](https://noiseprotocol.org/noise.html) and pinned [`snow` 0.10.0](https://github.com/mcginty/snow/tree/4bb43f50370bdb3e8b1b57814ac662864db2704f); `tests/vectors/snow.txt` SHA-256 is `69da433305fd045f6c9f01b656662a389d022688986fd39fbe7af009cd402fd3`

The `snow` dependency is pinned, but upstream states it has not received a formal audit. Its use remains blocked until the independent security reviewer explicitly accepts that risk for opportunistic link protection; MLS/COSE remains the authentication boundary.

## Review gate

On 2026-08-18, a separate `gpt-5.6-sol` xhigh reviewer executed both independent generators, reproduced the byte-identical digest `cc991844bf2987e2ce36216ee87c1af8ce9bc75cb5280765553ba04ee9c939c2`, independently checked the specified formulas and representative bytes, and reported no unresolved security-critical choice. This satisfies the automated reproduction portion of DEC-001 only. A named human security reviewer must still accept the reproduction and composition against an immutable source revision; until then the vectors and all dependent decisions remain drafts.

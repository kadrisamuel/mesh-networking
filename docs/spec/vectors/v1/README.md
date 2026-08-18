# Normative v1 draft vectors

- Status: Draft — independent reproduction and human security approval required
- Vector schema: `mesh-messenger-vectors/1`
- Specification: `1.0.0-draft.1`
- Checked-in `vectors.json` SHA-256: `37b6091e10cbc8a4ec5588f417be4b47083d57a29dfb8950eae1c2ea9f513c70`

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
| `canonical_objects` | deterministic CBOR, root-signed device certificate, MLS BasicCredential identity bytes, device-signed contact bundle/QR, device-signed bootstrap record |
| `routing_and_user_envelope` | six-hour routing tag, exact header normalization, AES-128-GCM body, deterministic padding fixture, 18-bit proof of work, complete 256-byte envelope |
| `bootstrap_envelope` | bootstrap routing tag, RFC 9180 HPKE Base key schedule/X25519/AES-128-GCM, signed record, exact 512-byte envelope, proof of work |
| `application_cbor` | canonical text application record |
| `ble_and_wlan` | canonical HELLO, encrypted-plaintext length frame, BLE `LinkChunk`, WLAN ciphertext-length frame |
| `lora` | complete 180-byte fragments, last-fragment padding, fragment digests |
| `linux_storage_wrap` | scrypt parameters/output and exact 92-byte AES-256-GCM wrapping record |
| `uuids` | RFC 9562 UUIDv5 inputs and fixed BLE UUIDs |

Padding uses an explicit ascending byte pattern, and final LoRa padding uses `a5`, solely to make fixtures reproducible. Production MUST use fresh OS CSPRNG bytes.

The `opaque_key_package_tls_hex` and `opaque_welcome_tls_hex` values are framing sentinels and are deliberately not valid MLS objects. An implementation MUST reject them semantically. The project does not redefine RFC 9420 TLS serialization; complete MLS/KeyPackage/Welcome semantics and byte encodings are validated by the pinned OpenMLS/RFC conformance material below.

## Standards conformance incorporated by reference

Local vectors cover every application-defined derivation and binary layout. Standard-library internals MUST also pass their authoritative known-answer/conformance suites; copying those large suites into this repository would create a divergent duplicate.

- HKDF: [RFC 5869 test cases](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A)
- Ed25519: [RFC 8032 test vectors](https://www.rfc-editor.org/rfc/rfc8032.html#section-7)
- HPKE: [RFC 9180 test vectors](https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A)
- MLS: [RFC 9420 test vectors](https://www.rfc-editor.org/rfc/rfc9420.html#name-test-vectors) and the [OpenMLS source at the pinned commit](https://github.com/openmls/openmls/tree/47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6/openmls/src/test_utils/test_vectors)
- AES-GCM: [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) and provider validation suite
- deterministic CBOR/COSE: [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html) and [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
- scrypt: [RFC 7914 test vectors](https://www.rfc-editor.org/rfc/rfc7914.html#section-12)
- Noise: [Noise revision 34](https://noiseprotocol.org/noise.html) and the pinned [`snow` 0.10.0](https://docs.rs/snow/0.10.0/snow/) official test suite at commit `4bb43f50370bdb3e8b1b57814ac662864db2704f`

The `snow` dependency is pinned, but upstream states it has not received a formal audit. Its use remains blocked until the independent security reviewer explicitly accepts that risk for opportunistic link protection; MLS/COSE remains the authentication boundary.

## Review gate

DEC-001 verification requires a separate `gpt-5.6-sol` xhigh run to execute both independent generators, reproduce every output/digest, independently check the specified formulas and representative bytes, and list no unresolved security choices. A human security reviewer must then accept the reproduction and composition. Neither requirement has been satisfied by generating this draft.

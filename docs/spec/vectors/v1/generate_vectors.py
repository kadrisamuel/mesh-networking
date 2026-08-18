#!/usr/bin/env python3
"""Independent Python generator for mesh-messenger v1 draft vectors."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import struct
import unicodedata
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


LABELS = {
    "bootstrap_record_aad": "mesh-messenger/v1/bootstrap-record",
    "bootstrap_routing_tag": "mesh-messenger/v1/bootstrap-routing-tag",
    "contact_bundle_aad": "mesh-messenger/v1/contact-bundle",
    "device_certificate_aad": "mesh-messenger/v1/device-certificate",
    "hpke_info": "mesh-messenger/v1/bootstrap-hpke",
    "identity_id": "mesh-messenger/v1/identity-id",
    "noise_prologue": "mesh-messenger/v1/noise-sync",
    "outer_exporter": "mesh-messenger/v1/outer-aead-key",
    "pow": "mesh-messenger/v1/pow",
    "root_seed": "mesh-messenger/v1/root-ed25519-seed",
    "routing_exporter": "mesh-messenger/v1/routing-secret",
    "routing_tag": "mesh-messenger/v1/routing-tag",
    "safety_number": "mesh-messenger/v1/safety-number",
    "storage_wrap_aad": "mesh-messenger/v1/linux-storage-wrap",
}

OPENMLS_COMMIT = "47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6"
OPENMLS_WELCOME_FILE_SHA256 = "06be9d5c99817ef2545e4b15b8e73fd9b604685a8e55b59ca168eda98e236502"
OPENMLS_KEY_SCHEDULE_FILE_SHA256 = "05aa9a68bd2538ace72d8c53375984cc728ef62220ebf314df675708546d97a7"
OPENMLS_KEY_PACKAGE = bytes.fromhex(
    "00010005000100012028b2cd6417984dc4708c61a1cce7c0f11d181bd36d6f7a"
    "610ea21cb96f79ba6020275d9e6337b11a5e21ba755f2353053a500103efa1c5a"
    "c7c07d3a78f8817ad2d203de79c7e370156ce25a88d897a8ea7c8f90fea1f71f"
    "beb5f31855312d8750007000120b640fbb0df8e646b29c83c5ed08aea89f72ab1"
    "08922827ea76cd3b917d6d99420200010c00010002000300040005000600000400"
    "010002010000000000000000ffffffffffffffff004040fd81837a40a9ba774bb4"
    "4db665081f4d0ff2a8f680ce5c902b17acc4ae6d9a14b9d4e9b4f8e7d74af8ff"
    "42032ec9caadf267e85931b550eebbe480150d4b9b0a0040401ec696ab731d5a7"
    "b1092b0db9912fe35086e188ce2946996bdf3cec463849f1a32f653b6e246b8b8"
    "5a486ce3f604891501052c3d7bbee2155fff6a367e5a1f03"
)
OPENMLS_WELCOME = bytes.fromhex(
    "0001000300014076208e1faada70f08b91ef7f7f79ed1da917d9ce3cea5e5ce22"
    "e4a8b10f4311559dd20a87de170e9dc54bd4a8a48f38cd5c949f0cc82fce8ea7"
    "2232417975ec6bad95033f6701d639694cbb51a4b2d0191f432add5267eea7b33f"
    "3c0c7edc65a28650adb0008f08b84a420bf1070516cb079a8e5c4159a40e80bee"
    "12b78b86d125155b035f52e8a131469cf1b9645d70e270d3aa21c04945fa80b7f"
    "ea30ccfceb436e4df23558cdc1a6cd435db3199314795b7c488b4bf0855cb589a"
    "d9c7eb43ea8bc9edef6b85ad1c97451b706e5de27aabe664dca132a288b3fc091"
    "b9100e470fb506833aaa4ab279a44c92c21e34dd295b6e49978d8c93cf20537be"
    "bc1a467177500d7fe6b127d5b3d13bf038cd2e8ec00937db6fd4996b2f2e416b"
    "810d0822b77bd71b59bf1e486c1ad74da0de9872f839b63928a03ae11e4dfacb"
    "7cf27ea2c35ae233d9c63fe901ddd4e7be7e643912bb39ad8a728792753bc8314"
    "317388e"
)
OPENMLS_EXPORTER_SECRET = bytes.fromhex(
    "5a097e149f2a375d0b9e1d1f4dc3a9c6c1788df888e5441f41a8791f4dc56cea"
)
OPENMLS_GROUP_ID = bytes.fromhex(
    "a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"
)
OPENMLS_GROUP_CONTEXT = bytes.fromhex(
    "0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39"
    "cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068"
    "664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c49"
    "0708a47e29f8f73f2b318201d2f00"
)
OPENMLS_EXPORTER_KAT_LABEL = "9ba13d54ecdec7cbefcb47b4268d7b1990fabc6d6e67681e167959389d84e4e4"
OPENMLS_EXPORTER_KAT_CONTEXT = bytes.fromhex(
    "884f1af892ab002f5be4c5d5081ade9e0e6418c6ea7a9a92e90534f19dcef785"
)
OPENMLS_EXPORTER_KAT_SECRET = bytes.fromhex(
    "dbce4e25e59ab4dfa6f6200f113ed08393cf6e7286d024811141c6a4dd11c0cb"
)
NOISE_PROTOCOL_NAME = b"Noise_NN_25519_ChaChaPoly_SHA256"
NOISE_INITIATOR_PRIVATE = bytes.fromhex(
    "ba743ce40b65ad7ec0700dc2e57de4791022a8f42cd46517c6689c5c812b3b36"
)
NOISE_RESPONDER_PRIVATE = bytes.fromhex(
    "d5cb9c3d9df2b6263f292f59099680ab2b523cf02b43a4c534b1fa94f9a80ed8"
)
SNOW_COMMIT = "4bb43f50370bdb3e8b1b57814ac662864db2704f"
SNOW_VECTOR_FILE_SHA256 = "69da433305fd045f6c9f01b656662a389d022688986fd39fbe7af009cd402fd3"
SNOW_VECTOR_PROLOGUE = bytes.fromhex(
    "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572"
    "652773206f6e6c792066756e20616e6420626f72696e672e"
)
SNOW_VECTOR_PAYLOADS = [
    bytes.fromhex("d369dc8436b80ad2936b4179ef262a0d174c06e3d452de5f22a7ca0326baaac7"),
    bytes.fromhex("87f4ce9acdcfe73e88f0d2b7e8b6009f07c5a42b3412909c1b7ce407a763ebd1"),
    bytes.fromhex("bdc326451b8af9b6b82a2054643878d9eeaea4845c6b1e9ba616b2723c2ef272"),
    bytes.fromhex("a783aa12cefa403d1dff9d6ac924f860a15d1ba21c2c4976f8fa88d76e590fef"),
]
SNOW_VECTOR_CIPHERTEXTS = [
    bytes.fromhex(
        "479a148ee78e18278f7716338574086a12bf8d90cc54c6c88ae6a4275dbd1478"
        "d369dc8436b80ad2936b4179ef262a0d174c06e3d452de5f22a7ca0326baaac7"
    ),
    bytes.fromhex(
        "5f1bc611a449717c2fc7c33a0f3976beae914c336d2a761c2f6e1ee2ab721f7c"
        "166608582f25b34bf5ebe478049971b64e5982d8b546b1cfa58fae828b7c8137"
        "562fdec5808f41fadeeee43013019277"
    ),
    bytes.fromhex(
        "15f337bd32ddb96a17765a9499a4eb24b757d59c78d5366fdd56a2eab7eed11a"
        "0b6d4ed2947c0bf83d9d625ab90ee60b"
    ),
    bytes.fromhex(
        "6b676682c308c230a602d1997ff9e94b815dbc497346a4144fc4290021a2dbfc"
        "bee618798a8eb5042562a637927d4e98"
    ),
]


def hx(value: bytes) -> str:
    return value.hex()


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def mls_vl_bytes(value: bytes) -> bytes:
    length = len(value)
    if length < 64:
        return bytes([length]) + value
    if length < 16_384:
        return struct.pack(">H", 0x4000 | length) + value
    if length < 1 << 30:
        return struct.pack(">I", 0x80000000 | length) + value
    raise ValueError("MLS variable-length vector too large")


def mls_expand_with_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    kdf_label = (
        struct.pack(">H", length)
        + mls_vl_bytes(b"MLS 1.0 " + label.encode("utf-8"))
        + mls_vl_bytes(context)
    )
    return hkdf_expand(secret, kdf_label, length)


def mls_export(exporter_secret: bytes, label: str, context: bytes, length: int) -> bytes:
    derived = mls_expand_with_label(exporter_secret, label, b"", 32)
    return mls_expand_with_label(derived, "exported", sha256(context), length)


def noise_hkdf(chaining_key: bytes, input_key_material: bytes) -> tuple[bytes, bytes]:
    temp_key = hmac.new(chaining_key, input_key_material, hashlib.sha256).digest()
    output1 = hmac.new(temp_key, b"\x01", hashlib.sha256).digest()
    output2 = hmac.new(temp_key, output1 + b"\x02", hashlib.sha256).digest()
    return output1, output2


def noise_nonce(counter: int) -> bytes:
    return b"\x00" * 4 + struct.pack("<Q", counter)


def noise_encrypt(key: bytes, counter: int, aad: bytes, plaintext: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(noise_nonce(counter), plaintext, aad)


def noise_nn(
    initiator_plaintext: bytes,
    responder_plaintext: bytes,
    *,
    prologue: bytes | None = None,
    initiator_handshake_payload: bytes = b"",
    responder_handshake_payload: bytes = b"",
) -> dict[str, bytes]:
    if len(NOISE_PROTOCOL_NAME) != 32:
        raise AssertionError("unexpected Noise protocol-name length")
    initiator_public = x_public(NOISE_INITIATOR_PRIVATE)
    responder_public = x_public(NOISE_RESPONDER_PRIVATE)
    chaining_key = NOISE_PROTOCOL_NAME
    handshake_hash = NOISE_PROTOCOL_NAME
    actual_prologue = LABELS["noise_prologue"].encode() if prologue is None else prologue
    handshake_hash = sha256(handshake_hash + actual_prologue)

    handshake_hash = sha256(handshake_hash + initiator_public)
    handshake_hash = sha256(handshake_hash + initiator_handshake_payload)
    message1 = initiator_public + initiator_handshake_payload

    handshake_hash = sha256(handshake_hash + responder_public)
    shared = X25519PrivateKey.from_private_bytes(NOISE_RESPONDER_PRIVATE).exchange(
        X25519PublicKey.from_public_bytes(initiator_public)
    )
    chaining_key, handshake_key = noise_hkdf(chaining_key, shared)
    encrypted_payload = noise_encrypt(
        handshake_key, 0, handshake_hash, responder_handshake_payload
    )
    handshake_hash = sha256(handshake_hash + encrypted_payload)
    message2 = responder_public + encrypted_payload

    initiator_send_key, initiator_receive_key = noise_hkdf(chaining_key, b"")
    initiator_ciphertext = noise_encrypt(
        initiator_send_key, 0, b"", initiator_plaintext
    )
    responder_ciphertext = noise_encrypt(
        initiator_receive_key, 0, b"", responder_plaintext
    )
    return {
        "initiator_public": initiator_public,
        "responder_public": responder_public,
        "ee_shared_secret": shared,
        "message1": message1,
        "message2": message2,
        "handshake_hash": handshake_hash,
        "initiator_send_key": initiator_send_key,
        "initiator_receive_key": initiator_receive_key,
        "initiator_ciphertext": initiator_ciphertext,
        "responder_ciphertext": responder_ciphertext,
    }


def cbor_head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xFF:
        return bytes([(major << 5) | 24, value])
    if value <= 0xFFFF:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + struct.pack(">I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([(major << 5) | 27]) + struct.pack(">Q", value)
    raise ValueError("CBOR integer out of range")


def cbor(value: Any) -> bytes:
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        if value >= 0:
            return cbor_head(0, value)
        return cbor_head(1, -1 - value)
    if isinstance(value, bytes):
        return cbor_head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return cbor_head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return cbor_head(4, len(value)) + b"".join(cbor(item) for item in value)
    if isinstance(value, dict):
        items = [(cbor(key), cbor(item)) for key, item in value.items()]
        items.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return cbor_head(5, len(items)) + b"".join(key + item for key, item in items)
    raise TypeError(f"unsupported CBOR value: {type(value)!r}")


def ed_public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )


def cose_sign1(payload: bytes, seed: bytes, external_aad: bytes) -> bytes:
    protected = cbor({1: -8})
    sig_structure = cbor(["Signature1", protected, external_aad, payload])
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(sig_structure)
    return cbor([protected, {}, payload, signature])


def x_public(seed: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )


def labeled_extract(salt: bytes, suite_id: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def labeled_expand(prk: bytes, suite_id: bytes, label: bytes, info: bytes, length: int) -> bytes:
    labeled_info = struct.pack(">H", length) + b"HPKE-v1" + suite_id + label + info
    return hkdf_expand(prk, labeled_info, length)


def hpke_context(recipient_public: bytes, ephemeral_seed: bytes, info: bytes) -> dict[str, bytes]:
    kem_id = 0x0020
    kdf_id = 0x0001
    aead_id = 0x0001
    ephemeral = X25519PrivateKey.from_private_bytes(ephemeral_seed)
    enc = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    dh = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))
    kem_suite = b"KEM" + struct.pack(">H", kem_id)
    eae_prk = labeled_extract(b"", kem_suite, b"eae_prk", dh)
    shared = labeled_expand(eae_prk, kem_suite, b"shared_secret", enc + recipient_public, 32)
    suite = b"HPKE" + struct.pack(">HHH", kem_id, kdf_id, aead_id)
    psk_id_hash = labeled_extract(b"", suite, b"psk_id_hash", b"")
    info_hash = labeled_extract(b"", suite, b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = labeled_extract(shared, suite, b"secret", b"")
    key = labeled_expand(secret, suite, b"key", context, 16)
    base_nonce = labeled_expand(secret, suite, b"base_nonce", context, 12)
    exporter_secret = labeled_expand(secret, suite, b"exp", context, 32)
    return {
        "enc": enc,
        "shared_secret": shared,
        "key": key,
        "base_nonce": base_nonce,
        "exporter_secret": exporter_secret,
    }


def header(
    *,
    mode: int,
    traffic_class: int,
    total_length: int,
    envelope_id: bytes,
    routing_tag: bytes,
    created: int,
    expires: int,
    nonce: bytes,
    hops: int = 8,
    pow_nonce: int = 0,
) -> bytes:
    return b"".join(
        [
            b"MSH1",
            bytes([1, mode, traffic_class, 1]),
            struct.pack(">HH", total_length, total_length - 80),
            envelope_id,
            routing_tag,
            struct.pack(">II", created, expires),
            nonce,
            bytes([8, hops]),
            b"\x00\x00",
            struct.pack(">Q", pow_nonce),
            b"\x00\x00\x00\x00",
        ]
    )


def normalized_header(value: bytes) -> bytes:
    out = bytearray(value)
    out[65] = 0
    out[68:76] = b"\x00" * 8
    return bytes(out)


def pow_header(value: bytes) -> bytes:
    out = bytearray(value)
    out[65] = 0
    return bytes(out)


def find_pow(base_header: bytes, sealed: bytes, start: int = 0) -> tuple[int, bytes, bytes]:
    prefix = LABELS["pow"].encode()
    for counter in range(start, 0x10000000000000000):
        candidate = bytearray(base_header)
        candidate[68:76] = struct.pack(">Q", counter)
        digest = sha256(prefix + pow_header(bytes(candidate)) + sealed)
        if digest[0] == 0 and digest[1] == 0 and digest[2] & 0xC0 == 0:
            return counter, bytes(candidate), digest
    raise RuntimeError("proof-of-work counter exhausted")


def pattern(length: int, start: int) -> bytes:
    return bytes((start + index) & 0xFF for index in range(length))


def make_inner(kind: int, content: bytes, total_plaintext: int, pad_start: int) -> bytes:
    prefix = bytes([1, kind]) + struct.pack(">H", len(content)) + content
    if len(prefix) > total_plaintext:
        raise ValueError("content does not fit")
    return prefix + pattern(total_plaintext - len(prefix), pad_start)


def smallest_class(required: int) -> int:
    for size in [256, 512, 1024, 1536, 2048, 3072, 4096]:
        if required <= size:
            return size
    raise ValueError("envelope too large")


def build_vectors() -> dict[str, Any]:
    entropy_a = bytes(32)
    entropy_b = bytes([0xFF]) * 32
    checksum = sha256(entropy_a)[0]
    indices = [0] * 23 + [checksum]
    phrase = " ".join(["abandon"] * 23 + ["art"])

    root_prk_a = hkdf_extract(b"", entropy_a)
    root_seed_a = hkdf_expand(root_prk_a, LABELS["root_seed"].encode(), 32)
    root_pub_a = ed_public(root_seed_a)
    identity_a = sha256(LABELS["identity_id"].encode() + root_pub_a)[:16]

    root_seed_b = hkdf_expand(
        hkdf_extract(b"", entropy_b), LABELS["root_seed"].encode(), 32
    )
    root_pub_b = ed_public(root_seed_b)
    identity_b = sha256(LABELS["identity_id"].encode() + root_pub_b)[:16]

    ordered = sorted([root_pub_a, root_pub_b])
    safety_digest = sha256(LABELS["safety_number"].encode() + ordered[0] + ordered[1])
    safety_digits = str(int.from_bytes(safety_digest, "big") % (10**60)).zfill(60)
    safety_display = " ".join(safety_digits[i : i + 5] for i in range(0, 60, 5))

    issued = 30_000_000
    device_seed = bytes(range(0x20, 0x40))
    device_pub = ed_public(device_seed)
    device_id = bytes(range(0x40, 0x50))
    cert_payload = cbor(
        {0: 1, 1: identity_a, 2: device_id, 3: device_pub, 4: issued, 5: None, 6: 1}
    )
    cert_cose = cose_sign1(cert_payload, root_seed_a, LABELS["device_certificate_aad"].encode())
    mls_credential = cbor({0: 1, 1: root_pub_a, 2: cert_cose})

    bundle_id = bytes(range(0xB0, 0xC0))
    hpke_recipient_seed = bytes(range(0xA0, 0xC0))
    hpke_recipient_pub = x_public(hpke_recipient_seed)
    rendezvous = bytes(range(0x70, 0x90))
    upstream_key_package = OPENMLS_KEY_PACKAGE
    contact_payload = cbor(
        {
            0: 1,
            1: bundle_id,
            2: issued,
            3: issued + 10_080,
            4: root_pub_a,
            5: cert_cose,
            6: upstream_key_package,
            7: hpke_recipient_pub,
            8: rendezvous,
        }
    )
    contact_cose = cose_sign1(contact_payload, device_seed, LABELS["contact_bundle_aad"].encode())
    qr = "meshmsg:v1:" + base64.urlsafe_b64encode(contact_cose).decode().rstrip("=")

    invitation_id = bytes(range(0xE0, 0xF0))
    upstream_welcome = OPENMLS_WELCOME
    bootstrap_payload = cbor(
        {
            0: 1,
            1: bundle_id,
            2: upstream_welcome,
            3: mls_credential,
            4: 1,
            5: None,
            6: invitation_id,
        }
    )
    bootstrap_cose = cose_sign1(
        bootstrap_payload, device_seed, LABELS["bootstrap_record_aad"].encode()
    )

    app_event_id = bytes(range(0x10, 0x20))
    app_cbor = cbor({0: 1, 1: 1, 2: app_event_id, 3: 1, 4: "mesh test"})
    initiator_session_id = bytes(range(0xD0, 0xE0))
    initiator_node_run_id = bytes(range(0xE0, 0xF0))
    responder_session_id = bytes(range(0xC0, 0xD0))
    responder_node_run_id = bytes(range(0xF0, 0x100))
    sync_cbor = cbor(
        {
            0: 1,
            1: 1,
            2: {
                0: initiator_session_id,
                1: initiator_node_run_id,
                2: 4096,
                3: 256,
            },
        }
    )
    responder_sync_cbor = cbor(
        {
            0: 1,
            1: 1,
            2: {
                0: responder_session_id,
                1: responder_node_run_id,
                2: 4096,
                3: 256,
            },
        }
    )
    sync_plaintext = struct.pack(">I", len(sync_cbor)) + sync_cbor
    responder_sync_plaintext = (
        struct.pack(">I", len(responder_sync_cbor)) + responder_sync_cbor
    )
    noise = noise_nn(sync_plaintext, responder_sync_plaintext)
    snow_kat = noise_nn(
        SNOW_VECTOR_PAYLOADS[2],
        SNOW_VECTOR_PAYLOADS[3],
        prologue=SNOW_VECTOR_PROLOGUE,
        initiator_handshake_payload=SNOW_VECTOR_PAYLOADS[0],
        responder_handshake_payload=SNOW_VECTOR_PAYLOADS[1],
    )
    snow_actual = [
        snow_kat["message1"],
        snow_kat["message2"],
        snow_kat["initiator_ciphertext"],
        snow_kat["responder_ciphertext"],
    ]
    if snow_actual != SNOW_VECTOR_CIPHERTEXTS:
        raise AssertionError("snow Noise NN vector mismatch")
    ble_chunk = (
        bytes([1, 3])
        + struct.pack(">HHH", 0x1234, 0, len(noise["initiator_ciphertext"]))
        + noise["initiator_ciphertext"]
    )
    wlan_frame = (
        struct.pack(">I", len(noise["initiator_ciphertext"]))
        + noise["initiator_ciphertext"]
    )

    kat_exported_secret = mls_export(
        OPENMLS_EXPORTER_SECRET,
        OPENMLS_EXPORTER_KAT_LABEL,
        OPENMLS_EXPORTER_KAT_CONTEXT,
        32,
    )
    if kat_exported_secret != OPENMLS_EXPORTER_KAT_SECRET:
        raise AssertionError("OpenMLS exporter KAT mismatch")
    routing_secret = mls_export(
        OPENMLS_EXPORTER_SECRET, LABELS["routing_exporter"], b"", 32
    )
    outer_key = mls_export(
        OPENMLS_EXPORTER_SECRET, LABELS["outer_exporter"], b"", 16
    )
    created_user = 30_000_120
    slot_user = created_user // 360
    route_tag = hmac.new(
        routing_secret,
        LABELS["routing_tag"].encode() + struct.pack(">Q", slot_user),
        hashlib.sha256,
    ).digest()[:16]
    user_id = bytes.fromhex("00112233445566778899aabbccddeeff")
    user_nonce = bytes.fromhex("0102030405060708090a0b0c")
    user_total = 256
    user_base_header = header(
        mode=1,
        traffic_class=1,
        total_length=user_total,
        envelope_id=user_id,
        routing_tag=route_tag,
        created=created_user,
        expires=created_user + 1_440,
        nonce=user_nonce,
    )
    fake_mls = bytes.fromhex("0001deadbeef")
    user_plain = make_inner(1, fake_mls, user_total - 80 - 16, 0x40)
    user_sealed = AESGCM(outer_key).encrypt(
        user_nonce, user_plain, normalized_header(user_base_header)
    )
    user_pow, user_header, user_pow_digest = find_pow(user_base_header, user_sealed)
    user_envelope = user_header + user_sealed
    alternate_pow, alternate_header, alternate_pow_digest = find_pow(
        user_base_header, user_sealed, user_pow + 1
    )
    alternate_header_mutable = bytearray(alternate_header)
    alternate_header_mutable[65] = 7
    alternate_header = bytes(alternate_header_mutable)
    alternate_envelope = alternate_header + user_sealed
    duplicate_content_digest = sha256(normalized_header(user_header) + user_sealed)
    conflict_sealed = user_sealed[:-1] + bytes([user_sealed[-1] ^ 1])
    conflict_pow, conflict_header, conflict_pow_digest = find_pow(
        user_base_header, conflict_sealed
    )
    conflict_envelope = conflict_header + conflict_sealed
    conflict_content_digest = sha256(
        normalized_header(conflict_header) + conflict_sealed
    )

    lora_frames: list[bytes] = []
    fragment_count = (len(user_envelope) + 159) // 160
    for index in range(fragment_count):
        fragment = user_envelope[index * 160 : (index + 1) * 160]
        fragment += bytes([0xA5]) * (160 - len(fragment))
        lora_frames.append(bytes([1, 0]) + user_id + bytes([index, fragment_count]) + fragment)
    alternate_final = bytearray(lora_frames[-1])
    final_meaningful = {2: 96, 4: 32, 7: 64, 10: 96}[fragment_count]
    alternate_final[20 + final_meaningful :] = bytes([0x5A]) * (
        160 - final_meaningful
    )
    alternate_final_frame = bytes(alternate_final)

    created_bootstrap = 30_000_240
    slot_bootstrap = created_bootstrap // 360
    bootstrap_tag = hmac.new(
        rendezvous,
        LABELS["bootstrap_routing_tag"].encode() + struct.pack(">Q", slot_bootstrap),
        hashlib.sha256,
    ).digest()[:16]
    required_bootstrap = 80 + 32 + 16 + 4 + len(bootstrap_cose)
    bootstrap_total = smallest_class(required_bootstrap)
    bootstrap_id = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    bootstrap_base_header = header(
        mode=2,
        traffic_class=2,
        total_length=bootstrap_total,
        envelope_id=bootstrap_id,
        routing_tag=bootstrap_tag,
        created=created_bootstrap,
        expires=created_bootstrap + 10_080,
        nonce=bytes(12),
    )
    bootstrap_plain = make_inner(
        2, bootstrap_cose, bootstrap_total - 80 - 32 - 16, 0x90
    )
    ephemeral_seed = bytes(range(0xC0, 0xE0))
    hpke = hpke_context(
        hpke_recipient_pub, ephemeral_seed, LABELS["hpke_info"].encode()
    )
    hpke_ciphertext = AESGCM(hpke["key"]).encrypt(
        hpke["base_nonce"], bootstrap_plain, normalized_header(bootstrap_base_header)
    )
    bootstrap_sealed = hpke["enc"] + hpke_ciphertext
    bootstrap_pow, bootstrap_header, bootstrap_pow_digest = find_pow(
        bootstrap_base_header, bootstrap_sealed
    )
    bootstrap_envelope = bootstrap_header + bootstrap_sealed

    storage_passphrase = unicodedata.normalize("NFKC", "correct horse battery staple")
    storage_salt = bytes(range(0x00, 0x10))
    storage_nonce = bytes(range(0xF0, 0xFC))
    database_key = bytes(range(0xD0, 0xF0))
    wrap_key = hashlib.scrypt(
        storage_passphrase.encode(),
        salt=storage_salt,
        n=131_072,
        r=8,
        p=1,
        dklen=32,
        maxmem=256 * 1024 * 1024,
    )
    storage_header = (
        b"MSK1"
        + bytes([1, 17])
        + struct.pack(">II", 8, 1)
        + storage_salt
        + storage_nonce
        + struct.pack(">H", 48)
    )
    storage_wrapped = AESGCM(wrap_key).encrypt(
        storage_nonce,
        database_key,
        LABELS["storage_wrap_aad"].encode() + storage_header,
    )
    storage_record = storage_header + storage_wrapped

    uuid_inputs = {
        "service": "https://mesh-messenger.invalid/ble/service/v1",
        "write": "https://mesh-messenger.invalid/ble/write/v1",
        "indicate": "https://mesh-messenger.invalid/ble/indicate/v1",
    }
    uuid_values = {name: str(uuid.uuid5(uuid.NAMESPACE_URL, value)) for name, value in uuid_inputs.items()}

    return {
        "application_cbor": {
            "event_id_hex": hx(app_event_id),
            "text": "mesh test",
            "text_record_hex": hx(app_cbor),
        },
        "ble_and_wlan": {
            "ble_link_chunk_hex": hx(ble_chunk),
            "initiator_noise_transport_ciphertext_hex": hx(
                noise["initiator_ciphertext"]
            ),
            "responder_sync_hello_cbor_hex": hx(responder_sync_cbor),
            "responder_sync_plaintext_frame_hex": hx(responder_sync_plaintext),
            "sync_hello_cbor_hex": hx(sync_cbor),
            "sync_plaintext_frame_hex": hx(sync_plaintext),
            "wlan_noise_frame_hex": hx(wlan_frame),
        },
        "bootstrap_envelope": {
            "aad_normalized_header_hex": hx(normalized_header(bootstrap_header)),
            "base_nonce_hex": hx(hpke["base_nonce"]),
            "enc_hex": hx(hpke["enc"]),
            "envelope_hex": hx(bootstrap_envelope),
            "envelope_sha256": hx(sha256(bootstrap_envelope)),
            "exporter_secret_hex": hx(hpke["exporter_secret"]),
            "hpke_ciphertext_hex": hx(hpke_ciphertext),
            "hpke_key_hex": hx(hpke["key"]),
            "plaintext_hex": hx(bootstrap_plain),
            "pow_digest_hex": hx(bootstrap_pow_digest),
            "pow_nonce": bootstrap_pow,
            "recipient_private_hex": hx(hpke_recipient_seed),
            "recipient_public_hex": hx(hpke_recipient_pub),
            "routing_tag_hex": hx(bootstrap_tag),
            "shared_secret_hex": hx(hpke["shared_secret"]),
            "slot": slot_bootstrap,
            "total_length": bootstrap_total,
        },
        "canonical_objects": {
            "bootstrap_cose_hex": hx(bootstrap_cose),
            "bootstrap_payload_hex": hx(bootstrap_payload),
            "contact_cose_hex": hx(contact_cose),
            "contact_payload_hex": hx(contact_payload),
            "device_certificate_cose_hex": hx(cert_cose),
            "device_certificate_payload_hex": hx(cert_payload),
            "mls_credential_cbor_hex": hx(mls_credential),
            "application_binding_expected": "POLICY_REJECT_UPSTREAM_OBJECT_NOT_APPLICATION_BOUND",
            "upstream_key_package_tls_hex": hx(upstream_key_package),
            "upstream_welcome_tls_hex": hx(upstream_welcome),
            "qr_text": qr,
        },
        "duplicate_merge": {
            "alternate_envelope_hex": hx(alternate_envelope),
            "alternate_hops_remaining": alternate_header[65],
            "alternate_pow_digest_hex": hx(alternate_pow_digest),
            "alternate_pow_nonce": alternate_pow,
            "conflict_content_sha256": hx(conflict_content_digest),
            "conflict_envelope_hex": hx(conflict_envelope),
            "conflict_expected": "QUARANTINE_ID_COLLISION",
            "conflict_pow_digest_hex": hx(conflict_pow_digest),
            "conflict_pow_nonce": conflict_pow,
            "duplicate_content_sha256": hx(duplicate_content_digest),
            "merge_expected_hops_remaining": 8,
            "merge_expected_pow_nonce": min(user_pow, alternate_pow),
            "original_envelope_hex": hx(user_envelope),
        },
        "identity": {
            "bip39_checksum_byte_hex": f"{checksum:02x}",
            "bip39_indices": indices,
            "bip39_phrase": phrase,
            "device_instance_id_hex": hx(device_id),
            "device_public_hex": hx(device_pub),
            "device_seed_hex": hx(device_seed),
            "entropy_a_hex": hx(entropy_a),
            "entropy_b_hex": hx(entropy_b),
            "identity_a_hex": hx(identity_a),
            "identity_b_hex": hx(identity_b),
            "root_prk_a_hex": hx(root_prk_a),
            "root_public_a_hex": hx(root_pub_a),
            "root_public_b_hex": hx(root_pub_b),
            "root_seed_a_hex": hx(root_seed_a),
            "root_seed_b_hex": hx(root_seed_b),
            "safety_digest_hex": hx(safety_digest),
            "safety_display": safety_display,
        },
        "labels": LABELS,
        "linux_storage_wrap": {
            "database_key_hex": hx(database_key),
            "passphrase_nfkc_utf8_hex": hx(storage_passphrase.encode()),
            "record_hex": hx(storage_record),
            "salt_hex": hx(storage_salt),
            "scrypt_N": 131_072,
            "scrypt_p": 1,
            "scrypt_r": 8,
            "wrap_key_hex": hx(wrap_key),
        },
        "lora": {
            "alternate_final_frame_hex": hx(alternate_final_frame),
            "alternate_final_frame_sha256": hx(sha256(alternate_final_frame)),
            "final_meaningful_bytes": final_meaningful,
            "fragment_count": fragment_count,
            "frames_hex": [hx(frame) for frame in lora_frames],
            "frames_sha256": [hx(sha256(frame)) for frame in lora_frames],
        },
        "meta": {
            "cbor_profile": "RFC8949-deterministic",
            "note": "Test-only private values; valid pinned OpenMLS objects and exporter input remain subject to the recorded application-binding rejection.",
            "schema": "mesh-messenger-vectors/1",
            "spec_version": "1.0.0-draft.1",
        },
        "noise_nn": {
            "ee_shared_secret_hex": hx(noise["ee_shared_secret"]),
            "handshake_hash_hex": hx(noise["handshake_hash"]),
            "initiator_private_hex": hx(NOISE_INITIATOR_PRIVATE),
            "initiator_public_hex": hx(noise["initiator_public"]),
            "initiator_receive_key_hex": hx(noise["initiator_receive_key"]),
            "initiator_send_key_hex": hx(noise["initiator_send_key"]),
            "initiator_transport_ciphertext_hex": hx(
                noise["initiator_ciphertext"]
            ),
            "message1_hex": hx(noise["message1"]),
            "message2_hex": hx(noise["message2"]),
            "prologue_utf8_hex": hx(LABELS["noise_prologue"].encode()),
            "protocol_name": NOISE_PROTOCOL_NAME.decode(),
            "responder_private_hex": hx(NOISE_RESPONDER_PRIVATE),
            "responder_public_hex": hx(noise["responder_public"]),
            "responder_transport_ciphertext_hex": hx(
                noise["responder_ciphertext"]
            ),
            "snow_source_commit": SNOW_COMMIT,
            "snow_source_file": "tests/vectors/snow.txt",
            "snow_source_file_sha256": SNOW_VECTOR_FILE_SHA256,
            "snow_source_vector_ciphertexts_sha256": hx(
                sha256(b"".join(SNOW_VECTOR_CIPHERTEXTS))
            ),
        },
        "openmls_upstream": {
            "application_outer_key_hex": hx(outer_key),
            "application_routing_secret_hex": hx(routing_secret),
            "cipher_suite": 1,
            "exporter_kat_context_hex": hx(OPENMLS_EXPORTER_KAT_CONTEXT),
            "exporter_kat_expected_secret_hex": hx(OPENMLS_EXPORTER_KAT_SECRET),
            "exporter_kat_label_utf8": OPENMLS_EXPORTER_KAT_LABEL,
            "exporter_secret_hex": hx(OPENMLS_EXPORTER_SECRET),
            "group_context_hex": hx(OPENMLS_GROUP_CONTEXT),
            "group_id_hex": hx(OPENMLS_GROUP_ID),
            "key_package_sha256": hx(sha256(OPENMLS_KEY_PACKAGE)),
            "key_schedule_file_sha256": OPENMLS_KEY_SCHEDULE_FILE_SHA256,
            "source_commit": OPENMLS_COMMIT,
            "source_key_schedule_case": 0,
            "source_welcome_case": 0,
            "valid_key_package_tls_hex": hx(OPENMLS_KEY_PACKAGE),
            "valid_welcome_tls_hex": hx(OPENMLS_WELCOME),
            "welcome_file_sha256": OPENMLS_WELCOME_FILE_SHA256,
            "welcome_sha256": hx(sha256(OPENMLS_WELCOME)),
        },
        "routing_and_user_envelope": {
            "aad_normalized_header_hex": hx(normalized_header(user_header)),
            "envelope_hex": hx(user_envelope),
            "envelope_sha256": hx(sha256(user_envelope)),
            "nonce_hex": hx(user_nonce),
            "outer_key_hex": hx(outer_key),
            "plaintext_hex": hx(user_plain),
            "pow_digest_hex": hx(user_pow_digest),
            "pow_nonce": user_pow,
            "routing_secret_fixture_hex": hx(routing_secret),
            "routing_tag_hex": hx(route_tag),
            "sealed_body_hex": hx(user_sealed),
            "slot": slot_user,
            "total_length": user_total,
        },
        "uuids": {"inputs": uuid_inputs, "values": uuid_values},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = json.dumps(build_vectors(), sort_keys=True, indent=2, separators=(",", ": ")) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()

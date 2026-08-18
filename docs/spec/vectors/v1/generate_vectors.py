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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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


def find_pow(base_header: bytes, sealed: bytes) -> tuple[int, bytes, bytes]:
    prefix = LABELS["pow"].encode()
    for counter in range(0x10000000000000000):
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
    opaque_key_package = bytes.fromhex("000100080001000102030405")
    contact_payload = cbor(
        {
            0: 1,
            1: bundle_id,
            2: issued,
            3: issued + 10_080,
            4: root_pub_a,
            5: cert_cose,
            6: opaque_key_package,
            7: hpke_recipient_pub,
            8: rendezvous,
        }
    )
    contact_cose = cose_sign1(contact_payload, device_seed, LABELS["contact_bundle_aad"].encode())
    qr = "meshmsg:v1:" + base64.urlsafe_b64encode(contact_cose).decode().rstrip("=")

    invitation_id = bytes(range(0xE0, 0xF0))
    opaque_welcome = bytes.fromhex("0001000c101112131415161718191a1b")
    bootstrap_payload = cbor(
        {
            0: 1,
            1: bundle_id,
            2: opaque_welcome,
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
    session_id = bytes(range(0xD0, 0xE0))
    sync_cbor = cbor({0: 1, 1: 1, 2: {0: session_id, 1: 4096, 2: 256}})
    sync_plaintext = struct.pack(">I", len(sync_cbor)) + sync_cbor
    ble_chunk = (
        bytes([1, 3])
        + struct.pack(">HHH", 0x1234, 0, len(sync_plaintext))
        + sync_plaintext
    )
    dummy_noise_ciphertext = bytes.fromhex("dec001000102030405060708090a0b0c")
    wlan_frame = struct.pack(">I", len(dummy_noise_ciphertext)) + dummy_noise_ciphertext

    routing_secret = bytes(range(0x00, 0x20))
    outer_key = bytes(range(0x90, 0xA0))
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

    lora_frames: list[bytes] = []
    fragment_count = (len(user_envelope) + 159) // 160
    for index in range(fragment_count):
        fragment = user_envelope[index * 160 : (index + 1) * 160]
        fragment += bytes([0xA5]) * (160 - len(fragment))
        lora_frames.append(bytes([1, 0]) + user_id + bytes([index, fragment_count]) + fragment)

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
            "opaque_key_package_tls_hex": hx(opaque_key_package),
            "opaque_welcome_tls_hex": hx(opaque_welcome),
            "qr_text": qr,
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
            "fragment_count": fragment_count,
            "frames_hex": [hx(frame) for frame in lora_frames],
            "frames_sha256": [hx(sha256(frame)) for frame in lora_frames],
        },
        "meta": {
            "cbor_profile": "RFC8949-deterministic",
            "note": "Opaque MLS bytes exercise application framing only; RFC/OpenMLS KATs validate MLS internals.",
            "schema": "mesh-messenger-vectors/1",
            "spec_version": "1.0.0-draft.1",
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

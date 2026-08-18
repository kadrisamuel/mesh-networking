#!/usr/bin/env node
// Independent Node.js generator for mesh-messenger v1 draft vectors.

import {
  createCipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  sign,
  scryptSync,
} from "node:crypto";
import { writeFileSync } from "node:fs";

const LABELS = {
  bootstrap_record_aad: "mesh-messenger/v1/bootstrap-record",
  bootstrap_routing_tag: "mesh-messenger/v1/bootstrap-routing-tag",
  contact_bundle_aad: "mesh-messenger/v1/contact-bundle",
  device_certificate_aad: "mesh-messenger/v1/device-certificate",
  hpke_info: "mesh-messenger/v1/bootstrap-hpke",
  identity_id: "mesh-messenger/v1/identity-id",
  noise_prologue: "mesh-messenger/v1/noise-sync",
  outer_exporter: "mesh-messenger/v1/outer-aead-key",
  pow: "mesh-messenger/v1/pow",
  root_seed: "mesh-messenger/v1/root-ed25519-seed",
  routing_exporter: "mesh-messenger/v1/routing-secret",
  routing_tag: "mesh-messenger/v1/routing-tag",
  safety_number: "mesh-messenger/v1/safety-number",
  storage_wrap_aad: "mesh-messenger/v1/linux-storage-wrap",
};

const utf8 = (value) => Buffer.from(value, "utf8");
const hx = (value) => Buffer.from(value).toString("hex");
const sha256 = (value) => createHash("sha256").update(value).digest();
const hmacSha256 = (key, value) => createHmac("sha256", key).update(value).digest();

function hkdfExtract(salt, ikm) {
  return hmacSha256(salt, ikm);
}

function hkdfExpand(prk, info, length) {
  let output = Buffer.alloc(0);
  let block = Buffer.alloc(0);
  let counter = 1;
  while (output.length < length) {
    block = hmacSha256(prk, Buffer.concat([block, info, Buffer.from([counter])]));
    output = Buffer.concat([output, block]);
    counter += 1;
  }
  return output.subarray(0, length);
}

function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value);
  return out;
}

function u32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function u64(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value));
  return out;
}

function cborHead(major, value) {
  if (value < 24) return Buffer.from([(major << 5) | value]);
  if (value <= 0xff) return Buffer.from([(major << 5) | 24, value]);
  if (value <= 0xffff) return Buffer.concat([Buffer.from([(major << 5) | 25]), u16(value)]);
  if (value <= 0xffffffff) return Buffer.concat([Buffer.from([(major << 5) | 26]), u32(value)]);
  const out = Buffer.alloc(9);
  out[0] = (major << 5) | 27;
  out.writeBigUInt64BE(BigInt(value), 1);
  return out;
}

function cbor(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (typeof value === "boolean") return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("CBOR number is not a safe integer");
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const raw = Buffer.from(value);
    return Buffer.concat([cborHead(2, raw.length), raw]);
  }
  if (typeof value === "string") {
    const raw = utf8(value);
    return Buffer.concat([cborHead(3, raw.length), raw]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([cborHead(4, value.length), ...value.map(cbor)]);
  }
  if (value instanceof Map) {
    const items = [...value.entries()].map(([key, item]) => [cbor(key), cbor(item)]);
    items.sort((a, b) => a[0].length - b[0].length || Buffer.compare(a[0], b[0]));
    return Buffer.concat([cborHead(5, items.length), ...items.flatMap(([key, item]) => [key, item])]);
  }
  throw new TypeError(`unsupported CBOR value: ${typeof value}`);
}

function edPrivate(seed) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({ key: Buffer.concat([prefix, seed]), format: "der", type: "pkcs8" });
}

function edPublic(seed) {
  const der = createPublicKey(edPrivate(seed)).export({ format: "der", type: "spki" });
  return Buffer.from(der).subarray(-32);
}

function xPrivate(seed) {
  const prefix = Buffer.from("302e020100300506032b656e04220420", "hex");
  return createPrivateKey({ key: Buffer.concat([prefix, seed]), format: "der", type: "pkcs8" });
}

function xPublic(seed) {
  const der = createPublicKey(xPrivate(seed)).export({ format: "der", type: "spki" });
  return Buffer.from(der).subarray(-32);
}

function xPublicKey(raw) {
  const prefix = Buffer.from("302a300506032b656e032100", "hex");
  return createPublicKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "spki" });
}

function coseSign1(payload, seed, externalAad) {
  const protectedHeader = cbor(new Map([[1, -8]]));
  const structure = cbor(["Signature1", protectedHeader, externalAad, payload]);
  const signature = sign(null, structure, edPrivate(seed));
  return cbor([protectedHeader, new Map(), payload, signature]);
}

function aesGcm(key, nonce, plaintext, aad) {
  const cipher = createCipheriv(key.length === 16 ? "aes-128-gcm" : "aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ciphertext, cipher.getAuthTag()]);
}

function labeledExtract(salt, suiteId, label, ikm) {
  return hkdfExtract(salt, Buffer.concat([utf8("HPKE-v1"), suiteId, label, ikm]));
}

function labeledExpand(prk, suiteId, label, info, length) {
  return hkdfExpand(prk, Buffer.concat([u16(length), utf8("HPKE-v1"), suiteId, label, info]), length);
}

function hpkeContext(recipientPublic, ephemeralSeed, info) {
  const kemId = 0x0020;
  const kdfId = 0x0001;
  const aeadId = 0x0001;
  const enc = xPublic(ephemeralSeed);
  const dh = diffieHellman({ privateKey: xPrivate(ephemeralSeed), publicKey: xPublicKey(recipientPublic) });
  const kemSuite = Buffer.concat([utf8("KEM"), u16(kemId)]);
  const eaePrk = labeledExtract(Buffer.alloc(0), kemSuite, utf8("eae_prk"), dh);
  const sharedSecret = labeledExpand(
    eaePrk,
    kemSuite,
    utf8("shared_secret"),
    Buffer.concat([enc, recipientPublic]),
    32,
  );
  const suite = Buffer.concat([utf8("HPKE"), u16(kemId), u16(kdfId), u16(aeadId)]);
  const pskIdHash = labeledExtract(Buffer.alloc(0), suite, utf8("psk_id_hash"), Buffer.alloc(0));
  const infoHash = labeledExtract(Buffer.alloc(0), suite, utf8("info_hash"), info);
  const context = Buffer.concat([Buffer.from([0]), pskIdHash, infoHash]);
  const secret = labeledExtract(sharedSecret, suite, utf8("secret"), Buffer.alloc(0));
  return {
    enc,
    shared_secret: sharedSecret,
    key: labeledExpand(secret, suite, utf8("key"), context, 16),
    base_nonce: labeledExpand(secret, suite, utf8("base_nonce"), context, 12),
    exporter_secret: labeledExpand(secret, suite, utf8("exp"), context, 32),
  };
}

function makeHeader({ mode, trafficClass, totalLength, envelopeId, routingTag, created, expires, nonce, hops = 8, powNonce = 0 }) {
  return Buffer.concat([
    utf8("MSH1"),
    Buffer.from([1, mode, trafficClass, 1]),
    u16(totalLength),
    u16(totalLength - 80),
    envelopeId,
    routingTag,
    u32(created),
    u32(expires),
    nonce,
    Buffer.from([8, hops]),
    Buffer.alloc(2),
    u64(powNonce),
    Buffer.alloc(4),
  ]);
}

function normalizedHeader(value) {
  const out = Buffer.from(value);
  out[65] = 0;
  out.fill(0, 68, 76);
  return out;
}

function powHeader(value) {
  const out = Buffer.from(value);
  out[65] = 0;
  return out;
}

function findPow(baseHeader, sealed) {
  const prefix = utf8(LABELS.pow);
  for (let counter = 0; counter < Number.MAX_SAFE_INTEGER; counter += 1) {
    const candidate = Buffer.from(baseHeader);
    u64(counter).copy(candidate, 68);
    const digest = sha256(Buffer.concat([prefix, powHeader(candidate), sealed]));
    if (digest[0] === 0 && digest[1] === 0 && (digest[2] & 0xc0) === 0) {
      return { counter, header: candidate, digest };
    }
  }
  throw new Error("proof-of-work counter exhausted");
}

function pattern(length, start) {
  return Buffer.from(Array.from({ length }, (_, index) => (start + index) & 0xff));
}

function makeInner(kind, content, totalPlaintext, padStart) {
  const prefix = Buffer.concat([Buffer.from([1, kind]), u16(content.length), content]);
  if (prefix.length > totalPlaintext) throw new Error("content does not fit");
  return Buffer.concat([prefix, pattern(totalPlaintext - prefix.length, padStart)]);
}

function smallestClass(required) {
  for (const size of [256, 512, 1024, 1536, 2048, 3072, 4096]) {
    if (required <= size) return size;
  }
  throw new Error("envelope too large");
}

function uuidV5(name) {
  const namespace = Buffer.from("6ba7b8119dad11d180b400c04fd430c8", "hex");
  const raw = createHash("sha1").update(namespace).update(utf8(name)).digest().subarray(0, 16);
  raw[6] = (raw[6] & 0x0f) | 0x50;
  raw[8] = (raw[8] & 0x3f) | 0x80;
  const text = raw.toString("hex");
  return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}-${text.slice(16, 20)}-${text.slice(20)}`;
}

function buildVectors() {
  const entropyA = Buffer.alloc(32);
  const entropyB = Buffer.alloc(32, 0xff);
  const checksum = sha256(entropyA)[0];
  const indices = [...Array(23).fill(0), checksum];
  const phrase = [...Array(23).fill("abandon"), "art"].join(" ");

  const rootPrkA = hkdfExtract(Buffer.alloc(0), entropyA);
  const rootSeedA = hkdfExpand(rootPrkA, utf8(LABELS.root_seed), 32);
  const rootPubA = edPublic(rootSeedA);
  const identityA = sha256(Buffer.concat([utf8(LABELS.identity_id), rootPubA])).subarray(0, 16);
  const rootSeedB = hkdfExpand(hkdfExtract(Buffer.alloc(0), entropyB), utf8(LABELS.root_seed), 32);
  const rootPubB = edPublic(rootSeedB);
  const identityB = sha256(Buffer.concat([utf8(LABELS.identity_id), rootPubB])).subarray(0, 16);

  const ordered = [rootPubA, rootPubB].sort(Buffer.compare);
  const safetyDigest = sha256(Buffer.concat([utf8(LABELS.safety_number), ordered[0], ordered[1]]));
  const safetyDigits = (BigInt(`0x${safetyDigest.toString("hex")}`) % (10n ** 60n)).toString().padStart(60, "0");
  const safetyDisplay = Array.from({ length: 12 }, (_, index) => safetyDigits.slice(index * 5, index * 5 + 5)).join(" ");

  const issued = 30_000_000;
  const deviceSeed = Buffer.from(Array.from({ length: 32 }, (_, index) => 0x20 + index));
  const devicePub = edPublic(deviceSeed);
  const deviceId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0x40 + index));
  const certPayload = cbor(new Map([
    [0, 1], [1, identityA], [2, deviceId], [3, devicePub], [4, issued], [5, null], [6, 1],
  ]));
  const certCose = coseSign1(certPayload, rootSeedA, utf8(LABELS.device_certificate_aad));
  const mlsCredential = cbor(new Map([[0, 1], [1, rootPubA], [2, certCose]]));

  const bundleId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0xb0 + index));
  const hpkeRecipientSeed = Buffer.from(Array.from({ length: 32 }, (_, index) => 0xa0 + index));
  const hpkeRecipientPub = xPublic(hpkeRecipientSeed);
  const rendezvous = Buffer.from(Array.from({ length: 32 }, (_, index) => 0x70 + index));
  const opaqueKeyPackage = Buffer.from("000100080001000102030405", "hex");
  const contactPayload = cbor(new Map([
    [0, 1], [1, bundleId], [2, issued], [3, issued + 10_080], [4, rootPubA],
    [5, certCose], [6, opaqueKeyPackage], [7, hpkeRecipientPub], [8, rendezvous],
  ]));
  const contactCose = coseSign1(contactPayload, deviceSeed, utf8(LABELS.contact_bundle_aad));
  const qr = `meshmsg:v1:${contactCose.toString("base64url")}`;

  const invitationId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0xe0 + index));
  const opaqueWelcome = Buffer.from("0001000c101112131415161718191a1b", "hex");
  const bootstrapPayload = cbor(new Map([
    [0, 1], [1, bundleId], [2, opaqueWelcome], [3, mlsCredential], [4, 1], [5, null], [6, invitationId],
  ]));
  const bootstrapCose = coseSign1(bootstrapPayload, deviceSeed, utf8(LABELS.bootstrap_record_aad));

  const appEventId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0x10 + index));
  const appCbor = cbor(new Map([[0, 1], [1, 1], [2, appEventId], [3, 1], [4, "mesh test"]]));
  const sessionId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0xd0 + index));
  const syncCbor = cbor(new Map([[0, 1], [1, 1], [2, new Map([[0, sessionId], [1, 4096], [2, 256]])]]));
  const syncPlaintext = Buffer.concat([u32(syncCbor.length), syncCbor]);
  const bleChunk = Buffer.concat([Buffer.from([1, 3]), u16(0x1234), u16(0), u16(syncPlaintext.length), syncPlaintext]);
  const dummyNoiseCiphertext = Buffer.from("dec001000102030405060708090a0b0c", "hex");
  const wlanFrame = Buffer.concat([u32(dummyNoiseCiphertext.length), dummyNoiseCiphertext]);

  const routingSecret = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
  const outerKey = Buffer.from(Array.from({ length: 16 }, (_, index) => 0x90 + index));
  const createdUser = 30_000_120;
  const slotUser = Math.floor(createdUser / 360);
  const routeTag = hmacSha256(routingSecret, Buffer.concat([utf8(LABELS.routing_tag), u64(slotUser)])).subarray(0, 16);
  const userId = Buffer.from("00112233445566778899aabbccddeeff", "hex");
  const userNonce = Buffer.from("0102030405060708090a0b0c", "hex");
  const userTotal = 256;
  const userBaseHeader = makeHeader({
    mode: 1, trafficClass: 1, totalLength: userTotal, envelopeId: userId, routingTag: routeTag,
    created: createdUser, expires: createdUser + 1_440, nonce: userNonce,
  });
  const fakeMls = Buffer.from("0001deadbeef", "hex");
  const userPlain = makeInner(1, fakeMls, userTotal - 80 - 16, 0x40);
  const userSealed = aesGcm(outerKey, userNonce, userPlain, normalizedHeader(userBaseHeader));
  const userProof = findPow(userBaseHeader, userSealed);
  const userEnvelope = Buffer.concat([userProof.header, userSealed]);

  const fragmentCount = Math.ceil(userEnvelope.length / 160);
  const loraFrames = [];
  for (let index = 0; index < fragmentCount; index += 1) {
    let fragment = userEnvelope.subarray(index * 160, (index + 1) * 160);
    fragment = Buffer.concat([fragment, Buffer.alloc(160 - fragment.length, 0xa5)]);
    loraFrames.push(Buffer.concat([Buffer.from([1, 0]), userId, Buffer.from([index, fragmentCount]), fragment]));
  }

  const createdBootstrap = 30_000_240;
  const slotBootstrap = Math.floor(createdBootstrap / 360);
  const bootstrapTag = hmacSha256(
    rendezvous,
    Buffer.concat([utf8(LABELS.bootstrap_routing_tag), u64(slotBootstrap)]),
  ).subarray(0, 16);
  const requiredBootstrap = 80 + 32 + 16 + 4 + bootstrapCose.length;
  const bootstrapTotal = smallestClass(requiredBootstrap);
  const bootstrapId = Buffer.from("ffeeddccbbaa99887766554433221100", "hex");
  const bootstrapBaseHeader = makeHeader({
    mode: 2, trafficClass: 2, totalLength: bootstrapTotal, envelopeId: bootstrapId, routingTag: bootstrapTag,
    created: createdBootstrap, expires: createdBootstrap + 10_080, nonce: Buffer.alloc(12),
  });
  const bootstrapPlain = makeInner(2, bootstrapCose, bootstrapTotal - 80 - 32 - 16, 0x90);
  const ephemeralSeed = Buffer.from(Array.from({ length: 32 }, (_, index) => 0xc0 + index));
  const hpke = hpkeContext(hpkeRecipientPub, ephemeralSeed, utf8(LABELS.hpke_info));
  const hpkeCiphertext = aesGcm(hpke.key, hpke.base_nonce, bootstrapPlain, normalizedHeader(bootstrapBaseHeader));
  const bootstrapSealed = Buffer.concat([hpke.enc, hpkeCiphertext]);
  const bootstrapProof = findPow(bootstrapBaseHeader, bootstrapSealed);
  const bootstrapEnvelope = Buffer.concat([bootstrapProof.header, bootstrapSealed]);

  const storagePassphrase = "correct horse battery staple".normalize("NFKC");
  const storageSalt = Buffer.from(Array.from({ length: 16 }, (_, index) => index));
  const storageNonce = Buffer.from(Array.from({ length: 12 }, (_, index) => 0xf0 + index));
  const databaseKey = Buffer.from(Array.from({ length: 32 }, (_, index) => 0xd0 + index));
  const wrapKey = scryptSync(utf8(storagePassphrase), storageSalt, 32, {
    N: 131_072, r: 8, p: 1, maxmem: 256 * 1024 * 1024,
  });
  const storageHeader = Buffer.concat([
    utf8("MSK1"), Buffer.from([1, 17]), u32(8), u32(1), storageSalt, storageNonce, u16(48),
  ]);
  const storageWrapped = aesGcm(
    wrapKey,
    storageNonce,
    databaseKey,
    Buffer.concat([utf8(LABELS.storage_wrap_aad), storageHeader]),
  );
  const storageRecord = Buffer.concat([storageHeader, storageWrapped]);

  const uuidInputs = {
    service: "https://mesh-messenger.invalid/ble/service/v1",
    write: "https://mesh-messenger.invalid/ble/write/v1",
    indicate: "https://mesh-messenger.invalid/ble/indicate/v1",
  };
  const uuidValues = Object.fromEntries(Object.entries(uuidInputs).map(([name, value]) => [name, uuidV5(value)]));

  return {
    application_cbor: {
      event_id_hex: hx(appEventId), text: "mesh test", text_record_hex: hx(appCbor),
    },
    ble_and_wlan: {
      ble_link_chunk_hex: hx(bleChunk), sync_hello_cbor_hex: hx(syncCbor),
      sync_plaintext_frame_hex: hx(syncPlaintext), wlan_noise_frame_hex: hx(wlanFrame),
    },
    bootstrap_envelope: {
      aad_normalized_header_hex: hx(normalizedHeader(bootstrapProof.header)),
      base_nonce_hex: hx(hpke.base_nonce), enc_hex: hx(hpke.enc), envelope_hex: hx(bootstrapEnvelope),
      envelope_sha256: hx(sha256(bootstrapEnvelope)), exporter_secret_hex: hx(hpke.exporter_secret),
      hpke_ciphertext_hex: hx(hpkeCiphertext), hpke_key_hex: hx(hpke.key), plaintext_hex: hx(bootstrapPlain),
      pow_digest_hex: hx(bootstrapProof.digest), pow_nonce: bootstrapProof.counter,
      recipient_private_hex: hx(hpkeRecipientSeed), recipient_public_hex: hx(hpkeRecipientPub),
      routing_tag_hex: hx(bootstrapTag), shared_secret_hex: hx(hpke.shared_secret),
      slot: slotBootstrap, total_length: bootstrapTotal,
    },
    canonical_objects: {
      bootstrap_cose_hex: hx(bootstrapCose), bootstrap_payload_hex: hx(bootstrapPayload),
      contact_cose_hex: hx(contactCose), contact_payload_hex: hx(contactPayload),
      device_certificate_cose_hex: hx(certCose), device_certificate_payload_hex: hx(certPayload),
      mls_credential_cbor_hex: hx(mlsCredential), opaque_key_package_tls_hex: hx(opaqueKeyPackage),
      opaque_welcome_tls_hex: hx(opaqueWelcome), qr_text: qr,
    },
    identity: {
      bip39_checksum_byte_hex: checksum.toString(16).padStart(2, "0"), bip39_indices: indices,
      bip39_phrase: phrase, device_instance_id_hex: hx(deviceId), device_public_hex: hx(devicePub),
      device_seed_hex: hx(deviceSeed), entropy_a_hex: hx(entropyA), entropy_b_hex: hx(entropyB),
      identity_a_hex: hx(identityA), identity_b_hex: hx(identityB), root_prk_a_hex: hx(rootPrkA),
      root_public_a_hex: hx(rootPubA), root_public_b_hex: hx(rootPubB), root_seed_a_hex: hx(rootSeedA),
      root_seed_b_hex: hx(rootSeedB), safety_digest_hex: hx(safetyDigest), safety_display: safetyDisplay,
    },
    labels: LABELS,
    linux_storage_wrap: {
      database_key_hex: hx(databaseKey), passphrase_nfkc_utf8_hex: hx(utf8(storagePassphrase)),
      record_hex: hx(storageRecord), salt_hex: hx(storageSalt), scrypt_N: 131_072,
      scrypt_p: 1, scrypt_r: 8, wrap_key_hex: hx(wrapKey),
    },
    lora: {
      fragment_count: fragmentCount, frames_hex: loraFrames.map(hx), frames_sha256: loraFrames.map((frame) => hx(sha256(frame))),
    },
    meta: {
      cbor_profile: "RFC8949-deterministic",
      note: "Opaque MLS bytes exercise application framing only; RFC/OpenMLS KATs validate MLS internals.",
      schema: "mesh-messenger-vectors/1", spec_version: "1.0.0-draft.1",
    },
    routing_and_user_envelope: {
      aad_normalized_header_hex: hx(normalizedHeader(userProof.header)), envelope_hex: hx(userEnvelope),
      envelope_sha256: hx(sha256(userEnvelope)), nonce_hex: hx(userNonce), outer_key_hex: hx(outerKey),
      plaintext_hex: hx(userPlain), pow_digest_hex: hx(userProof.digest), pow_nonce: userProof.counter,
      routing_secret_fixture_hex: hx(routingSecret), routing_tag_hex: hx(routeTag),
      sealed_body_hex: hx(userSealed), slot: slotUser, total_length: userTotal,
    },
    uuids: { inputs: uuidInputs, values: uuidValues },
  };
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortJson(value[key])]));
  }
  return value;
}

const outputIndex = process.argv.indexOf("--output");
if (outputIndex !== -1 && outputIndex + 1 >= process.argv.length) throw new Error("--output requires a path");
const rendered = `${JSON.stringify(sortJson(buildVectors()), null, 2)}\n`;
if (outputIndex === -1) process.stdout.write(rendered);
else writeFileSync(process.argv[outputIndex + 1], rendered, "utf8");

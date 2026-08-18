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
import { readFileSync, writeFileSync } from "node:fs";

const LABELS = {
  bootstrap_record_aad: "mesh-messenger/v1/bootstrap-record",
  bootstrap_routing_tag: "mesh-messenger/v1/bootstrap-routing-tag",
  contact_bundle_aad: "mesh-messenger/v1/contact-bundle",
  database_wrap_aad: "mesh-messenger/v1/database-key-wrap",
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

const APPLICATION_FIXTURE_URL = new URL("./openmls_16_member_measurement.json", import.meta.url);
const APPLICATION_FIXTURE_SHA256 = "1015e46e7423a57bc00e12c0c7008c648cb468a3df0b41cea77c3ad585395b7f";

const OPENMLS_COMMIT = "47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6";
const OPENMLS_WELCOME_FILE_SHA256 = "06be9d5c99817ef2545e4b15b8e73fd9b604685a8e55b59ca168eda98e236502";
const OPENMLS_KEY_SCHEDULE_FILE_SHA256 = "05aa9a68bd2538ace72d8c53375984cc728ef62220ebf314df675708546d97a7";
const OPENMLS_KEY_PACKAGE = Buffer.from(
  "00010005000100012028b2cd6417984dc4708c61a1cce7c0f11d181bd36d6f7a" +
  "610ea21cb96f79ba6020275d9e6337b11a5e21ba755f2353053a500103efa1c5a" +
  "c7c07d3a78f8817ad2d203de79c7e370156ce25a88d897a8ea7c8f90fea1f71f" +
  "beb5f31855312d8750007000120b640fbb0df8e646b29c83c5ed08aea89f72ab1" +
  "08922827ea76cd3b917d6d99420200010c00010002000300040005000600000400" +
  "010002010000000000000000ffffffffffffffff004040fd81837a40a9ba774bb4" +
  "4db665081f4d0ff2a8f680ce5c902b17acc4ae6d9a14b9d4e9b4f8e7d74af8ff" +
  "42032ec9caadf267e85931b550eebbe480150d4b9b0a0040401ec696ab731d5a7" +
  "b1092b0db9912fe35086e188ce2946996bdf3cec463849f1a32f653b6e246b8b8" +
  "5a486ce3f604891501052c3d7bbee2155fff6a367e5a1f03",
  "hex",
);
const OPENMLS_WELCOME = Buffer.from(
  "0001000300014076208e1faada70f08b91ef7f7f79ed1da917d9ce3cea5e5ce22" +
  "e4a8b10f4311559dd20a87de170e9dc54bd4a8a48f38cd5c949f0cc82fce8ea7" +
  "2232417975ec6bad95033f6701d639694cbb51a4b2d0191f432add5267eea7b33f" +
  "3c0c7edc65a28650adb0008f08b84a420bf1070516cb079a8e5c4159a40e80bee" +
  "12b78b86d125155b035f52e8a131469cf1b9645d70e270d3aa21c04945fa80b7f" +
  "ea30ccfceb436e4df23558cdc1a6cd435db3199314795b7c488b4bf0855cb589a" +
  "d9c7eb43ea8bc9edef6b85ad1c97451b706e5de27aabe664dca132a288b3fc091" +
  "b9100e470fb506833aaa4ab279a44c92c21e34dd295b6e49978d8c93cf20537be" +
  "bc1a467177500d7fe6b127d5b3d13bf038cd2e8ec00937db6fd4996b2f2e416b" +
  "810d0822b77bd71b59bf1e486c1ad74da0de9872f839b63928a03ae11e4dfacb" +
  "7cf27ea2c35ae233d9c63fe901ddd4e7be7e643912bb39ad8a728792753bc8314" +
  "317388e",
  "hex",
);
const OPENMLS_EXPORTER_SECRET = Buffer.from("5a097e149f2a375d0b9e1d1f4dc3a9c6c1788df888e5441f41a8791f4dc56cea", "hex");
const OPENMLS_GROUP_ID = Buffer.from("a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e", "hex");
const OPENMLS_GROUP_CONTEXT = Buffer.from(
  "0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39" +
  "cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068" +
  "664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c49" +
  "0708a47e29f8f73f2b318201d2f00",
  "hex",
);
const OPENMLS_EXPORTER_KAT_LABEL = "9ba13d54ecdec7cbefcb47b4268d7b1990fabc6d6e67681e167959389d84e4e4";
const OPENMLS_EXPORTER_KAT_CONTEXT = Buffer.from("884f1af892ab002f5be4c5d5081ade9e0e6418c6ea7a9a92e90534f19dcef785", "hex");
const OPENMLS_EXPORTER_KAT_SECRET = Buffer.from("dbce4e25e59ab4dfa6f6200f113ed08393cf6e7286d024811141c6a4dd11c0cb", "hex");
const NOISE_PROTOCOL_NAME = Buffer.from("Noise_NN_25519_ChaChaPoly_SHA256", "ascii");
const NOISE_INITIATOR_PRIVATE = Buffer.from("ba743ce40b65ad7ec0700dc2e57de4791022a8f42cd46517c6689c5c812b3b36", "hex");
const NOISE_RESPONDER_PRIVATE = Buffer.from("d5cb9c3d9df2b6263f292f59099680ab2b523cf02b43a4c534b1fa94f9a80ed8", "hex");
const SNOW_COMMIT = "4bb43f50370bdb3e8b1b57814ac662864db2704f";
const SNOW_VECTOR_FILE_SHA256 = "69da433305fd045f6c9f01b656662a389d022688986fd39fbe7af009cd402fd3";
const SNOW_VECTOR_PROLOGUE = Buffer.from(
  "5468657265206973206e6f20726967687420616e642077726f6e672e2054686572" +
  "652773206f6e6c792066756e20616e6420626f72696e672e",
  "hex",
);
const SNOW_VECTOR_PAYLOADS = [
  "d369dc8436b80ad2936b4179ef262a0d174c06e3d452de5f22a7ca0326baaac7",
  "87f4ce9acdcfe73e88f0d2b7e8b6009f07c5a42b3412909c1b7ce407a763ebd1",
  "bdc326451b8af9b6b82a2054643878d9eeaea4845c6b1e9ba616b2723c2ef272",
  "a783aa12cefa403d1dff9d6ac924f860a15d1ba21c2c4976f8fa88d76e590fef",
].map((value) => Buffer.from(value, "hex"));
const SNOW_VECTOR_CIPHERTEXTS = [
  "479a148ee78e18278f7716338574086a12bf8d90cc54c6c88ae6a4275dbd1478" +
    "d369dc8436b80ad2936b4179ef262a0d174c06e3d452de5f22a7ca0326baaac7",
  "5f1bc611a449717c2fc7c33a0f3976beae914c336d2a761c2f6e1ee2ab721f7c" +
    "166608582f25b34bf5ebe478049971b64e5982d8b546b1cfa58fae828b7c8137" +
    "562fdec5808f41fadeeee43013019277",
  "15f337bd32ddb96a17765a9499a4eb24b757d59c78d5366fdd56a2eab7eed11a" +
    "0b6d4ed2947c0bf83d9d625ab90ee60b",
  "6b676682c308c230a602d1997ff9e94b815dbc497346a4144fc4290021a2dbfc" +
    "bee618798a8eb5042562a637927d4e98",
].map((value) => Buffer.from(value, "hex"));

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

function mlsVlBytes(value) {
  if (value.length < 64) return Buffer.concat([Buffer.from([value.length]), value]);
  if (value.length < 16_384) return Buffer.concat([u16(0x4000 | value.length), value]);
  if (value.length < 2 ** 30) return Buffer.concat([u32(0x80000000 + value.length), value]);
  throw new Error("MLS variable-length vector too large");
}

function mlsExpandWithLabel(secret, label, context, length) {
  const kdfLabel = Buffer.concat([
    u16(length),
    mlsVlBytes(Buffer.concat([utf8("MLS 1.0 "), utf8(label)])),
    mlsVlBytes(context),
  ]);
  return hkdfExpand(secret, kdfLabel, length);
}

function mlsExport(exporterSecret, label, context, length) {
  const derived = mlsExpandWithLabel(exporterSecret, label, Buffer.alloc(0), 32);
  return mlsExpandWithLabel(derived, "exported", sha256(context), length);
}

function noiseHkdf(chainingKey, inputKeyMaterial) {
  const tempKey = hmacSha256(chainingKey, inputKeyMaterial);
  const output1 = hmacSha256(tempKey, Buffer.from([1]));
  const output2 = hmacSha256(tempKey, Buffer.concat([output1, Buffer.from([2])]));
  return [output1, output2];
}

function noiseNonce(counter) {
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64LE(BigInt(counter), 4);
  return nonce;
}

function noiseEncrypt(key, counter, aad, plaintext) {
  const cipher = createCipheriv("chacha20-poly1305", key, noiseNonce(counter), { authTagLength: 16 });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ciphertext, cipher.getAuthTag()]);
}

function noiseNn(
  initiatorPlaintext,
  responderPlaintext,
  {
    prologue = utf8(LABELS.noise_prologue),
    initiatorHandshakePayload = Buffer.alloc(0),
    responderHandshakePayload = Buffer.alloc(0),
  } = {},
) {
  if (NOISE_PROTOCOL_NAME.length !== 32) throw new Error("unexpected Noise protocol-name length");
  const initiatorPublic = xPublic(NOISE_INITIATOR_PRIVATE);
  const responderPublic = xPublic(NOISE_RESPONDER_PRIVATE);
  let chainingKey = NOISE_PROTOCOL_NAME;
  let handshakeHash = NOISE_PROTOCOL_NAME;
  handshakeHash = sha256(Buffer.concat([handshakeHash, prologue]));

  handshakeHash = sha256(Buffer.concat([handshakeHash, initiatorPublic]));
  handshakeHash = sha256(Buffer.concat([handshakeHash, initiatorHandshakePayload]));
  const message1 = Buffer.concat([initiatorPublic, initiatorHandshakePayload]);

  handshakeHash = sha256(Buffer.concat([handshakeHash, responderPublic]));
  const shared = diffieHellman({
    privateKey: xPrivate(NOISE_RESPONDER_PRIVATE),
    publicKey: xPublicKey(initiatorPublic),
  });
  let handshakeKey;
  [chainingKey, handshakeKey] = noiseHkdf(chainingKey, shared);
  const encryptedPayload = noiseEncrypt(handshakeKey, 0, handshakeHash, responderHandshakePayload);
  handshakeHash = sha256(Buffer.concat([handshakeHash, encryptedPayload]));
  const message2 = Buffer.concat([responderPublic, encryptedPayload]);

  const [initiatorSendKey, initiatorReceiveKey] = noiseHkdf(chainingKey, Buffer.alloc(0));
  return {
    initiator_public: initiatorPublic,
    responder_public: responderPublic,
    ee_shared_secret: shared,
    message1,
    message2,
    handshake_hash: handshakeHash,
    initiator_send_key: initiatorSendKey,
    initiator_receive_key: initiatorReceiveKey,
    initiator_ciphertext: noiseEncrypt(initiatorSendKey, 0, Buffer.alloc(0), initiatorPlaintext),
    responder_ciphertext: noiseEncrypt(initiatorReceiveKey, 0, Buffer.alloc(0), responderPlaintext),
  };
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

function findPow(baseHeader, sealed, start = 0) {
  const prefix = utf8(LABELS.pow);
  for (let counter = start; counter < Number.MAX_SAFE_INTEGER; counter += 1) {
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
  for (const size of [256, 512, 1024, 1536, 2048, 3072, 4096, 8192]) {
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
  const fixtureBytes = readFileSync(APPLICATION_FIXTURE_URL);
  if (hx(sha256(fixtureBytes)) !== APPLICATION_FIXTURE_SHA256) {
    throw new Error("application-bound OpenMLS fixture digest mismatch");
  }
  const applicationFixture = JSON.parse(fixtureBytes.toString("utf8"));
  if (applicationFixture.openmls_revision !== OPENMLS_COMMIT) {
    throw new Error("application-bound OpenMLS revision mismatch");
  }

  const zeroEntropy = Buffer.alloc(32);
  const entropyA = Buffer.alloc(32, 0xff);
  const entropyB = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
  const checksum = sha256(entropyA)[0];
  const indices = [...Array(23).fill(2047), (7 << 8) | checksum];
  const phrase = [...Array(23).fill("zoo"), "vote"].join(" ");

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

  const issued = applicationFixture.issued_minute;

  function fixtureIdentity(role) {
    const record = applicationFixture.application_binding[role];
    const rootSeed = Buffer.from(record.root_seed_public_test_only_hex, "hex");
    const deviceSeed = Buffer.from(record.device_seed_public_test_only_hex, "hex");
    const rootPublic = edPublic(rootSeed);
    const devicePublic = edPublic(deviceSeed);
    const identityId = sha256(Buffer.concat([utf8(LABELS.identity_id), rootPublic])).subarray(0, 16);
    if (hx(rootPublic) !== record.root_public_hex || hx(devicePublic) !== record.device_public_hex) {
      throw new Error(`${role} fixture public-key mismatch`);
    }
    if (hx(identityId) !== record.identity_id_hex) throw new Error(`${role} fixture identity mismatch`);
    const certificatePayload = cbor(new Map([
      [0, 1],
      [1, identityId],
      [2, Buffer.from(record.device_instance_id_hex, "hex")],
      [3, devicePublic],
      [4, issued],
      [5, null],
      [6, 1],
    ]));
    const certificate = coseSign1(certificatePayload, rootSeed, utf8(LABELS.device_certificate_aad));
    const credential = cbor(new Map([[0, 1], [1, rootPublic], [2, certificate]]));
    if (hx(credential) !== record.credential_cbor_hex) {
      throw new Error(`${role} fixture credential mismatch`);
    }
    return {
      rootSeed,
      rootPublic,
      identityId,
      deviceSeed,
      devicePublic,
      deviceId: Buffer.from(record.device_instance_id_hex, "hex"),
      certificatePayload,
      certificate,
      credential,
    };
  }

  const owner = fixtureIdentity("owner");
  const recipient = fixtureIdentity("recipient");
  const outsider = fixtureIdentity("outsider");
  const deviceSeed = owner.deviceSeed;
  const devicePub = owner.devicePublic;
  const deviceId = owner.deviceId;
  const certPayload = owner.certificatePayload;
  const certCose = owner.certificate;
  const mlsCredential = owner.credential;

  const bundleId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0xb0 + index));
  const hpkeRecipientSeed = Buffer.from(Array.from({ length: 32 }, (_, index) => 0xa0 + index));
  const hpkeRecipientPub = xPublic(hpkeRecipientSeed);
  const rendezvous = Buffer.from(Array.from({ length: 32 }, (_, index) => 0x70 + index));
  const applicationKeyPackage = Buffer.from(applicationFixture.recipient_key_package_tls.hex, "hex");
  if (applicationKeyPackage.length !== 474) throw new Error("application KeyPackage length mismatch");
  const contactPayload = cbor(new Map([
    [0, 1], [1, bundleId], [2, issued], [3, issued + 10_080], [4, recipient.rootPublic],
    [5, recipient.certificate], [6, applicationKeyPackage], [7, hpkeRecipientPub], [8, rendezvous],
  ]));
  const contactCose = coseSign1(contactPayload, recipient.deviceSeed, utf8(LABELS.contact_bundle_aad));
  const qr = `meshmsg:v1:${contactCose.toString("base64url")}`;

  const invitationId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0xe0 + index));
  const applicationWelcome = Buffer.from(applicationFixture.welcome_mls_message_tls.hex, "hex");
  if (applicationWelcome.length !== 6622) throw new Error("application Welcome length mismatch");
  const bootstrapPayload = cbor(new Map([
    [0, 1], [1, bundleId], [2, applicationWelcome], [3, mlsCredential], [4, 2], [5, owner.identityId], [6, invitationId],
  ]));
  const bootstrapCose = coseSign1(bootstrapPayload, deviceSeed, utf8(LABELS.bootstrap_record_aad));
  if (bootstrapCose.length !== 6962) throw new Error("measured bootstrap COSE length mismatch");

  const wrongKeyPackagePayload = cbor(new Map([
    [0, 1],
    [1, Buffer.from(Array.from({ length: 16 }, (_, index) => 0x90 + index))],
    [2, issued],
    [3, issued + 10_080],
    [4, owner.rootPublic],
    [5, owner.certificate],
    [6, applicationKeyPackage],
    [7, hpkeRecipientPub],
    [8, rendezvous],
  ]));
  const wrongKeyPackageCose = coseSign1(
    wrongKeyPackagePayload,
    owner.deviceSeed,
    utf8(LABELS.contact_bundle_aad),
  );
  if (owner.credential.equals(recipient.credential)) {
    throw new Error("negative KeyPackage credential unexpectedly matched");
  }

  const outsiderBundleId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0x80 + index));
  const outsiderKeyPackage = Buffer.from(
    applicationFixture.negative_application_binding.wrong_welcome_recipient_key_package_tls.hex,
    "hex",
  );
  const wrongWelcomePayload = cbor(new Map([
    [0, 1],
    [1, outsiderBundleId],
    [2, applicationWelcome],
    [3, owner.credential],
    [4, 2],
    [5, owner.identityId],
    [6, Buffer.from(Array.from({ length: 16 }, (_, index) => 0x60 + index))],
  ]));
  const wrongWelcomeCose = coseSign1(
    wrongWelcomePayload,
    owner.deviceSeed,
    utf8(LABELS.bootstrap_record_aad),
  );

  const appEventId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0x10 + index));
  const receiptEventId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0x20 + index));
  const replacementEventId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0x30 + index));
  const applicationRecords = {
    text: cbor(new Map([[0, 1], [1, 1], [2, appEventId], [3, 1], [4, "mesh test"]])),
    delivery_receipt: cbor(new Map([
      [0, 1], [1, 2], [2, receiptEventId], [3, 2], [4, new Map([[0, appEventId]])],
    ])),
    device_replacement_notice: cbor(new Map([
      [0, 1], [1, 3], [2, replacementEventId], [3, 3], [4, owner.certificate],
    ])),
  };
  const initiatorSessionId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0xd0 + index));
  const initiatorNodeRunId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0xe0 + index));
  const responderSessionId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0xc0 + index));
  const responderNodeRunId = Buffer.from(Array.from({ length: 16 }, (_, index) => 0xf0 + index));
  const syncRecord = (kind, payload) => cbor(new Map([[0, 1], [1, kind], [2, payload]]));
  const syncCbor = syncRecord(
    1,
    new Map([
      [0, initiatorSessionId], [1, initiatorNodeRunId], [2, 8192], [3, 256],
    ]),
  );
  const responderSyncCbor = cbor(new Map([
    [0, 1], [1, 1],
    [2, new Map([[0, responderSessionId], [1, responderNodeRunId], [2, 8192], [3, 256]])],
  ]));
  const syncPlaintext = Buffer.concat([u32(syncCbor.length), syncCbor]);
  const responderSyncPlaintext = Buffer.concat([u32(responderSyncCbor.length), responderSyncCbor]);
  const noise = noiseNn(syncPlaintext, responderSyncPlaintext);
  if (noise.message1.length !== 32 || noise.message2.length !== 48) {
    throw new Error("Noise NN empty-payload handshake length mismatch");
  }
  const snowKat = noiseNn(SNOW_VECTOR_PAYLOADS[2], SNOW_VECTOR_PAYLOADS[3], {
    prologue: SNOW_VECTOR_PROLOGUE,
    initiatorHandshakePayload: SNOW_VECTOR_PAYLOADS[0],
    responderHandshakePayload: SNOW_VECTOR_PAYLOADS[1],
  });
  const snowActual = [snowKat.message1, snowKat.message2, snowKat.initiator_ciphertext, snowKat.responder_ciphertext];
  if (!snowActual.every((value, index) => value.equals(SNOW_VECTOR_CIPHERTEXTS[index]))) {
    throw new Error("snow Noise NN vector mismatch");
  }
  const bleChunk = Buffer.concat([
    Buffer.from([1, 3]), u16(0x1234), u16(0), u16(noise.initiator_ciphertext.length),
    noise.initiator_ciphertext,
  ]);
  const wlanFrame = Buffer.concat([u32(noise.initiator_ciphertext.length), noise.initiator_ciphertext]);
  const bleHandshakeMessage1 = Buffer.concat([
    Buffer.from([1, 3]), u16(0x1200), u16(0), u16(32), noise.message1,
  ]);
  const bleHandshakeMessage2 = Buffer.concat([
    Buffer.from([1, 3]), u16(0x1201), u16(0), u16(48), noise.message2,
  ]);
  const wlanHandshakeMessage1 = Buffer.concat([u32(32), noise.message1]);
  const wlanHandshakeMessage2 = Buffer.concat([u32(48), noise.message2]);

  const katExportedSecret = mlsExport(
    OPENMLS_EXPORTER_SECRET,
    OPENMLS_EXPORTER_KAT_LABEL,
    OPENMLS_EXPORTER_KAT_CONTEXT,
    32,
  );
  if (!katExportedSecret.equals(OPENMLS_EXPORTER_KAT_SECRET)) {
    throw new Error("OpenMLS exporter KAT mismatch");
  }
  const upstreamRoutingSecret = mlsExport(
    OPENMLS_EXPORTER_SECRET,
    LABELS.routing_exporter,
    Buffer.alloc(0),
    32,
  );
  const upstreamSenderOuterKeys = Array.from({ length: 16 }, (_, leaf) => ({
    sender_leaf_index: leaf,
    context_hex: hx(u32(leaf)),
    outer_key_hex: hx(mlsExport(OPENMLS_EXPORTER_SECRET, LABELS.outer_exporter, u32(leaf), 16)),
  }));
  const applicationExporters = applicationFixture.application_exporters;
  const routingSecret = Buffer.from(applicationExporters.routing_secret_hex, "hex");
  const senderOuterKeys = applicationExporters.sender_outer_keys;
  if (senderOuterKeys.length !== 16 || new Set(senderOuterKeys.map((entry) => entry.outer_key_hex)).size !== 16) {
    throw new Error("application sender outer-key coverage mismatch");
  }
  senderOuterKeys.forEach((entry, leaf) => {
    if (entry.sender_leaf_index !== leaf || entry.context_hex !== hx(u32(leaf))) {
      throw new Error("application sender outer-key context mismatch");
    }
  });
  const outerKey = Buffer.from(senderOuterKeys[0].outer_key_hex, "hex");
  const createdUser = issued + 120;
  const slotUser = Math.floor(createdUser / 360);
  const routeTag = hmacSha256(routingSecret, Buffer.concat([utf8(LABELS.routing_tag), u64(slotUser)])).subarray(0, 16);
  const userId = Buffer.from("00112233445566778899aabbccddeeff", "hex");
  const userNonce = Buffer.from("0102030405060708090a0b0c", "hex");
  const applicationMls = Buffer.from(applicationFixture.application_message.mls_message_tls.hex, "hex");
  if (applicationFixture.application_message.authenticated_sender_leaf_index !== 0) {
    throw new Error("application MLS sender fixture mismatch");
  }
  const userTotal = smallestClass(80 + 16 + 4 + applicationMls.length);
  const userBaseHeader = makeHeader({
    mode: 1, trafficClass: 1, totalLength: userTotal, envelopeId: userId, routingTag: routeTag,
    created: createdUser, expires: createdUser + 1_440, nonce: userNonce,
  });
  const userPlain = makeInner(1, applicationMls, userTotal - 80 - 16, 0x40);
  const userSealed = aesGcm(outerKey, userNonce, userPlain, normalizedHeader(userBaseHeader));
  const userProof = findPow(userBaseHeader, userSealed);
  const userEnvelope = Buffer.concat([userProof.header, userSealed]);
  const alternateProof = findPow(userBaseHeader, userSealed, userProof.counter + 1);
  const alternateHeader = Buffer.from(alternateProof.header);
  alternateHeader[65] = 7;
  const alternateEnvelope = Buffer.concat([alternateHeader, userSealed]);
  const duplicateContentDigest = sha256(Buffer.concat([normalizedHeader(userProof.header), userSealed]));
  const conflictSealed = Buffer.from(userSealed);
  conflictSealed[conflictSealed.length - 1] ^= 1;
  const conflictProof = findPow(userBaseHeader, conflictSealed);
  const conflictEnvelope = Buffer.concat([conflictProof.header, conflictSealed]);
  const conflictContentDigest = sha256(Buffer.concat([normalizedHeader(conflictProof.header), conflictSealed]));

  function fragmentVector(envelope) {
    const envelopeId = envelope.subarray(12, 28);
    const fragmentCount = Math.ceil(envelope.length / 160);
    const finalMeaningful = new Map([[2, 96], [4, 32], [7, 64], [10, 96]]).get(fragmentCount);
    const frames = [];
    for (let index = 0; index < fragmentCount; index += 1) {
      let fragment = envelope.subarray(index * 160, (index + 1) * 160);
      fragment = Buffer.concat([fragment, Buffer.alloc(160 - fragment.length, 0xa5)]);
      frames.push(Buffer.concat([
        Buffer.from([1, 0]), envelopeId, Buffer.from([index, fragmentCount]), fragment,
      ]));
    }
    const alternateFinal = Buffer.from(frames.at(-1));
    alternateFinal.fill(0x5a, 20 + finalMeaningful);
    return {
      alternate_final_frame_hex: hx(alternateFinal),
      alternate_final_frame_sha256: hx(sha256(alternateFinal)),
      envelope_hex: hx(envelope),
      envelope_sha256: hx(sha256(envelope)),
      final_meaningful_bytes: finalMeaningful,
      fragment_count: fragmentCount,
      frames_hex: frames.map(hx),
      frames_sha256: frames.map((frame) => hx(sha256(frame))),
    };
  }

  const loraEnvelopes = new Map([[userTotal, userEnvelope]]);
  [256, 512, 1024, 1536].forEach((mappingSize, mappingIndex) => {
    if (loraEnvelopes.has(mappingSize)) return;
    const mappingId = Buffer.alloc(16, 0x50 + mappingIndex);
    const mappingNonce = Buffer.alloc(12, 0x60 + mappingIndex);
    const mappingHeader = makeHeader({
      mode: 1,
      trafficClass: 1,
      totalLength: mappingSize,
      envelopeId: mappingId,
      routingTag: routeTag,
      created: createdUser,
      expires: createdUser + 1_440,
      nonce: mappingNonce,
    });
    const mappingMls = mappingSize >= 512 ? applicationMls : Buffer.from("0001deadbeef", "hex");
    const mappingPlain = makeInner(1, mappingMls, mappingSize - 80 - 16, 0x50 + mappingIndex);
    const mappingSealed = aesGcm(outerKey, mappingNonce, mappingPlain, normalizedHeader(mappingHeader));
    const mappingProof = findPow(mappingHeader, mappingSealed);
    loraEnvelopes.set(mappingSize, Buffer.concat([mappingProof.header, mappingSealed]));
  });
  const loraMappings = Object.fromEntries(
    [256, 512, 1024, 1536].map((size) => [`size_${size}`, fragmentVector(loraEnvelopes.get(size))]),
  );
  loraMappings.size_256.transport_only_inner_mls_stub = true;

  const createdBootstrap = issued + 240;
  const slotBootstrap = Math.floor(createdBootstrap / 360);
  const bootstrapTag = hmacSha256(
    rendezvous,
    Buffer.concat([utf8(LABELS.bootstrap_routing_tag), u64(slotBootstrap)]),
  ).subarray(0, 16);
  const requiredBootstrap = 80 + 32 + 16 + 4 + bootstrapCose.length;
  const bootstrapTotal = smallestClass(requiredBootstrap);
  if (requiredBootstrap !== 7094 || bootstrapTotal !== 8192) {
    throw new Error("measured bootstrap envelope limit mismatch");
  }
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

  const inventoryIds = [userId, bootstrapId].sort(Buffer.compare);
  const syncVariantBytes = {
    hello_initiator: syncCbor,
    hello_responder: responderSyncCbor,
    inventory: syncRecord(2, inventoryIds),
    request: syncRecord(3, [userId]),
    push: syncRecord(4, [userEnvelope, bootstrapEnvelope]),
    custody_ack_both_statuses: syncRecord(5, [[userId, 0], [bootstrapId, 1]]),
    ...Object.fromEntries(Array.from({ length: 4 }, (_, reason) => [
      `goodbye_reason_${reason}`, syncRecord(6, reason),
    ])),
    ...Object.fromEntries(Array.from({ length: 2 }, (_, reason) => [
      `error_reason_${reason}`, syncRecord(7, reason),
    ])),
  };
  const syncVariants = Object.fromEntries(Object.entries(syncVariantBytes).map(([name, record]) => [
    name,
    {
      cbor_hex: hx(record),
      plaintext_frame_hex: hx(Buffer.concat([u32(record.length), record])),
    },
  ]));

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

  const platformDatabaseId = Buffer.from(Array.from({ length: 16 }, (_, index) => index + 1));
  const androidWrappingKey = Buffer.from(Array.from({ length: 32 }, (_, index) => 0x40 + index));
  const androidNonce = Buffer.from(Array.from({ length: 12 }, (_, index) => 0xe0 + index));
  const androidHeader = Buffer.concat([
    utf8("MDA1"), Buffer.from([1, 1]), Buffer.alloc(2), platformDatabaseId, androidNonce, u16(48),
  ]);
  const androidAad = Buffer.concat([utf8(LABELS.database_wrap_aad), androidHeader]);
  const androidWrapped = aesGcm(androidWrappingKey, androidNonce, databaseKey, androidAad);
  const androidRecord = Buffer.concat([androidHeader, androidWrapped]);
  if (androidRecord.length !== 86) throw new Error("Android wrapping record length mismatch");

  const windowsEntropy = sha256(Buffer.concat([utf8(LABELS.database_wrap_aad), platformDatabaseId]));
  const syntheticDpapiBlob = pattern(64, 0x33);
  const windowsRecord = Buffer.concat([
    utf8("MDW1"), Buffer.from([1, 2]), Buffer.alloc(2), platformDatabaseId,
    u32(syntheticDpapiBlob.length), syntheticDpapiBlob,
  ]);

  const uuidInputs = {
    service: "https://mesh-messenger.invalid/ble/service/v1",
    write: "https://mesh-messenger.invalid/ble/write/v1",
    indicate: "https://mesh-messenger.invalid/ble/indicate/v1",
  };
  const uuidValues = Object.fromEntries(Object.entries(uuidInputs).map(([name, value]) => [name, uuidV5(value)]));

  return {
    application_cbor: {
      device_replacement_notice_event_id_hex: hx(replacementEventId),
      delivery_receipt_event_id_hex: hx(receiptEventId),
      records_hex: Object.fromEntries(
        Object.entries(applicationRecords).map(([name, record]) => [name, hx(record)]),
      ),
      text_event_id_hex: hx(appEventId),
    },
    ble_and_wlan: {
      ble_handshake_message1_chunk_hex: hx(bleHandshakeMessage1),
      ble_handshake_message2_chunk_hex: hx(bleHandshakeMessage2),
      ble_link_chunk_hex: hx(bleChunk), initiator_noise_transport_ciphertext_hex: hx(noise.initiator_ciphertext),
      responder_sync_hello_cbor_hex: hx(responderSyncCbor),
      responder_sync_plaintext_frame_hex: hx(responderSyncPlaintext), sync_hello_cbor_hex: hx(syncCbor),
      sync_plaintext_frame_hex: hx(syncPlaintext), sync_variants: syncVariants,
      wlan_handshake_message1_frame_hex: hx(wlanHandshakeMessage1),
      wlan_handshake_message2_frame_hex: hx(wlanHandshakeMessage2),
      wlan_noise_frame_hex: hx(wlanFrame),
    },
    bootstrap_envelope: {
      aad_normalized_header_hex: hx(normalizedHeader(bootstrapProof.header)),
      base_nonce_hex: hx(hpke.base_nonce), enc_hex: hx(hpke.enc), envelope_hex: hx(bootstrapEnvelope),
      envelope_sha256: hx(sha256(bootstrapEnvelope)), exporter_secret_hex: hx(hpke.exporter_secret),
      hpke_ciphertext_hex: hx(hpkeCiphertext), hpke_key_hex: hx(hpke.key), plaintext_hex: hx(bootstrapPlain),
      pow_digest_hex: hx(bootstrapProof.digest), pow_nonce: bootstrapProof.counter,
      recipient_private_hex: hx(hpkeRecipientSeed), recipient_public_hex: hx(hpkeRecipientPub),
      routing_tag_hex: hx(bootstrapTag), shared_secret_hex: hx(hpke.shared_secret),
      slot: slotBootstrap, bootstrap_cose_length: bootstrapCose.length,
      minimum_unpadded_length: requiredBootstrap, total_length: bootstrapTotal,
    },
    canonical_objects: {
      bootstrap_cose_hex: hx(bootstrapCose), bootstrap_payload_hex: hx(bootstrapPayload),
      contact_cose_hex: hx(contactCose), contact_payload_hex: hx(contactPayload),
      device_certificate_cose_hex: hx(certCose), device_certificate_payload_hex: hx(certPayload),
      mls_credential_cbor_hex: hx(mlsCredential),
      positive_application_binding_expected: "ACCEPT",
      positive_key_package_tls_hex: hx(applicationKeyPackage),
      positive_welcome_tls_hex: hx(applicationWelcome),
      positive_member_count: applicationFixture.member_count,
      positive_join_validation: applicationFixture.join_validation,
      negative_key_package_contact_cose_hex: hx(wrongKeyPackageCose),
      negative_key_package_contact_payload_hex: hx(wrongKeyPackagePayload),
      negative_key_package_expected: applicationFixture.negative_application_binding.expected_key_package_result,
      negative_key_package_expected_credential_hex: hx(owner.credential),
      negative_key_package_actual_credential_hex: hx(recipient.credential),
      negative_welcome_bootstrap_cose_hex: hx(wrongWelcomeCose),
      negative_welcome_bootstrap_payload_hex: hx(wrongWelcomePayload),
      negative_welcome_outsider_credential_hex: hx(outsider.credential),
      negative_welcome_outsider_key_package_tls_hex: hx(outsiderKeyPackage),
      negative_welcome_expected: applicationFixture.negative_application_binding.expected_welcome_result,
      negative_welcome_openmls_error: applicationFixture.negative_application_binding.wrong_welcome_recipient_openmls_error,
      upstream_application_binding_expected: "POLICY_REJECT_UPSTREAM_OBJECT_NOT_APPLICATION_BOUND",
      upstream_key_package_tls_hex: hx(OPENMLS_KEY_PACKAGE),
      upstream_welcome_tls_hex: hx(OPENMLS_WELCOME), qr_text: qr,
    },
    duplicate_merge: {
      alternate_envelope_hex: hx(alternateEnvelope), alternate_hops_remaining: alternateHeader[65],
      alternate_pow_digest_hex: hx(alternateProof.digest), alternate_pow_nonce: alternateProof.counter,
      conflict_content_sha256: hx(conflictContentDigest), conflict_envelope_hex: hx(conflictEnvelope),
      conflict_expected: "QUARANTINE_ID_COLLISION", conflict_pow_digest_hex: hx(conflictProof.digest),
      conflict_pow_nonce: conflictProof.counter,
      duplicate_content_sha256: hx(duplicateContentDigest), merge_expected_hops_remaining: 8,
      merge_expected_pow_nonce: Math.min(userProof.counter, alternateProof.counter),
      original_envelope_hex: hx(userEnvelope),
    },
    identity: {
      bip39_checksum_byte_hex: checksum.toString(16).padStart(2, "0"), bip39_indices: indices,
      bip39_phrase: phrase, device_instance_id_hex: hx(deviceId), device_public_hex: hx(devicePub),
      device_seed_hex: hx(deviceSeed), entropy_a_hex: hx(entropyA), entropy_b_hex: hx(entropyB),
      positive_entropy_nonzero: true, zero_entropy_hex: hx(zeroEntropy),
      zero_entropy_expected: "RETRY_THEN_FAIL_AFTER_EIGHT_ALL_ZERO_DRAWS",
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
    platform_storage_wrap: {
      database_id_hex: hx(platformDatabaseId),
      android: {
        aad_hex: hx(androidAad),
        alias: `mesh-messenger-v1-db-${hx(platformDatabaseId)}`,
        nonce_hex: hx(androidNonce),
        record_hex: hx(androidRecord),
        record_length: androidRecord.length,
        wrapping_key_public_test_only_hex: hx(androidWrappingKey),
      },
      ios: {
        access_control_flags: [],
        access_group: "application-default",
        accessibility: "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
        account: hx(platformDatabaseId),
        data_hex: hx(databaseKey),
        service: "mesh-messenger/v1/database-key",
        synchronizable: false,
        use_data_protection_keychain: false,
      },
      macos: {
        access_control_flags: [],
        access_group: "application-default",
        accessibility: "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
        account: hx(platformDatabaseId),
        data_hex: hx(databaseKey),
        service: "mesh-messenger/v1/database-key",
        synchronizable: false,
        use_data_protection_keychain: true,
      },
      ubuntu_secret_service: {
        attributes: { application: "mesh-messenger-v1", "database-id": hx(platformDatabaseId) },
        collection: "default",
        content_type: "application/octet-stream",
        secret_hex: hx(databaseKey),
      },
      windows: {
        description: "mesh-messenger-v1",
        dpapi_blob_hex: hx(syntheticDpapiBlob),
        dpapi_blob_is_synthetic_opaque_test_data: true,
        flags: ["CRYPTPROTECT_UI_FORBIDDEN"],
        optional_entropy_hex: hx(windowsEntropy),
        record_hex: hx(windowsRecord),
      },
    },
    lora: {
      mappings: loraMappings,
    },
    meta: {
      cbor_profile: "RFC8949-deterministic",
      note: "All private values are public test-only fixtures and must never be used in production; draft.2 awaits independent and human review.",
      schema: "mesh-messenger-vectors/1", spec_version: "1.0.0-draft.2",
    },
    noise_nn: {
      ee_shared_secret_hex: hx(noise.ee_shared_secret), handshake_hash_hex: hx(noise.handshake_hash),
      initiator_private_hex: hx(NOISE_INITIATOR_PRIVATE), initiator_public_hex: hx(noise.initiator_public),
      initiator_receive_key_hex: hx(noise.initiator_receive_key), initiator_send_key_hex: hx(noise.initiator_send_key),
      initiator_transport_ciphertext_hex: hx(noise.initiator_ciphertext), message1_hex: hx(noise.message1),
      message1_length: noise.message1.length, message1_payload_hex: "",
      message2_hex: hx(noise.message2), message2_length: noise.message2.length,
      message2_payload_hex: "", prologue_utf8_hex: hx(utf8(LABELS.noise_prologue)),
      protocol_name: NOISE_PROTOCOL_NAME.toString("ascii"), responder_private_hex: hx(NOISE_RESPONDER_PRIVATE),
      responder_public_hex: hx(noise.responder_public), responder_transport_ciphertext_hex: hx(noise.responder_ciphertext),
      snow_source_commit: SNOW_COMMIT, snow_source_file: "tests/vectors/snow.txt",
      snow_source_file_sha256: SNOW_VECTOR_FILE_SHA256,
      snow_source_vector_ciphertexts_sha256: hx(sha256(Buffer.concat(SNOW_VECTOR_CIPHERTEXTS))),
    },
    openmls_upstream: {
      application_fixture_sha256: APPLICATION_FIXTURE_SHA256,
      application_fixture_source: "openmls_16_member_measurement.json",
      application_routing_secret_hex: hx(routingSecret),
      application_sender_outer_keys: senderOuterKeys,
      cipher_suite: 1, exporter_kat_context_hex: hx(OPENMLS_EXPORTER_KAT_CONTEXT),
      exporter_kat_expected_secret_hex: hx(OPENMLS_EXPORTER_KAT_SECRET),
      exporter_kat_label_utf8: OPENMLS_EXPORTER_KAT_LABEL, exporter_secret_hex: hx(OPENMLS_EXPORTER_SECRET),
      group_context_hex: hx(OPENMLS_GROUP_CONTEXT), group_id_hex: hx(OPENMLS_GROUP_ID),
      key_package_sha256: hx(sha256(OPENMLS_KEY_PACKAGE)), key_schedule_file_sha256: OPENMLS_KEY_SCHEDULE_FILE_SHA256,
      source_commit: OPENMLS_COMMIT, source_key_schedule_case: 0, source_welcome_case: 0,
      valid_key_package_tls_hex: hx(OPENMLS_KEY_PACKAGE), valid_welcome_tls_hex: hx(OPENMLS_WELCOME),
      welcome_file_sha256: OPENMLS_WELCOME_FILE_SHA256, welcome_sha256: hx(sha256(OPENMLS_WELCOME)),
      upstream_application_routing_secret_hex: hx(upstreamRoutingSecret),
      upstream_application_sender_outer_keys: upstreamSenderOuterKeys,
    },
    routing_and_user_envelope: {
      aad_normalized_header_hex: hx(normalizedHeader(userProof.header)), envelope_hex: hx(userEnvelope),
      envelope_sha256: hx(sha256(userEnvelope)), nonce_hex: hx(userNonce), outer_key_hex: hx(outerKey),
      plaintext_hex: hx(userPlain), pow_digest_hex: hx(userProof.digest), pow_nonce: userProof.counter,
      routing_secret_fixture_hex: hx(routingSecret), routing_tag_hex: hx(routeTag),
      sealed_body_hex: hx(userSealed), slot: slotUser,
      selected_sender_context_hex: "00000000", selected_sender_leaf_index: 0,
      authenticated_mls_sender_leaf_index: applicationFixture.application_message.authenticated_sender_leaf_index,
      sender_context_match_expected: true, total_length: userTotal,
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

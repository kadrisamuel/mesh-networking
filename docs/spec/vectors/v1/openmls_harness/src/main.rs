// Deterministic inputs are PUBLIC TEST-ONLY MATERIAL. Never use them in production.

use std::{
    env, fs,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{Signer as _, SigningKey};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider;
use serde_json::json;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as _, Serialize as _};

const OPENMLS_REVISION: &str = "47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6";
const RUSTC_VERSION: &str = "rustc 1.97.1 (8bab26f4f 2026-07-14)";
const CARGO_VERSION: &str = "cargo 1.97.1 (c980f4866 2026-06-30)";
const L_IDENTITY_ID: &[u8] = b"mesh-messenger/v1/identity-id";
const L_DEVICE_CERT_AAD: &[u8] = b"mesh-messenger/v1/device-certificate";
const MEMBER_COUNT: usize = 16;
const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn deterministic_seed(label: &[u8], member: usize) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"DEC-001 public test-only seed v1");
    hash.update(label);
    hash.update((member as u32).to_be_bytes());
    hash.finalize().into()
}

fn cbor_head(major: u8, value: u64) -> Vec<u8> {
    match value {
        0..=23 => vec![(major << 5) | value as u8],
        24..=0xff => vec![(major << 5) | 24, value as u8],
        0x100..=0xffff => {
            let mut out = vec![(major << 5) | 25];
            out.extend_from_slice(&(value as u16).to_be_bytes());
            out
        }
        0x1_0000..=0xffff_ffff => {
            let mut out = vec![(major << 5) | 26];
            out.extend_from_slice(&(value as u32).to_be_bytes());
            out
        }
        _ => {
            let mut out = vec![(major << 5) | 27];
            out.extend_from_slice(&value.to_be_bytes());
            out
        }
    }
}

fn cbor_uint(value: u64) -> Vec<u8> {
    cbor_head(0, value)
}

fn cbor_bstr(value: &[u8]) -> Vec<u8> {
    let mut out = cbor_head(2, value.len() as u64);
    out.extend_from_slice(value);
    out
}

fn cbor_tstr(value: &str) -> Vec<u8> {
    let mut out = cbor_head(3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
    out
}

fn cbor_array(values: &[Vec<u8>]) -> Vec<u8> {
    let mut out = cbor_head(4, values.len() as u64);
    for value in values {
        out.extend_from_slice(value);
    }
    out
}

fn cbor_map(entries: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = cbor_head(5, entries.len() as u64);
    for (key, value) in entries {
        out.extend_from_slice(&cbor_uint(*key));
        out.extend_from_slice(value);
    }
    out
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

struct TestIdentity {
    credential_with_key: CredentialWithKey,
    signer: SignatureKeyPair,
    credential_bytes: Vec<u8>,
    identity_id: [u8; 16],
    root_public: [u8; 32],
    device_instance_id: [u8; 16],
    device_public: [u8; 32],
}

fn application_bound_identity(member: usize, issued_minute: u64) -> TestIdentity {
    let root_key = SigningKey::from_bytes(&deterministic_seed(b"root", member));
    let root_public = root_key.verifying_key().to_bytes();
    let device_key = SigningKey::from_bytes(&deterministic_seed(b"device", member));
    let device_public = device_key.verifying_key().to_bytes();

    let mut id_hash = Sha256::new();
    id_hash.update(L_IDENTITY_ID);
    id_hash.update(root_public);
    let identity_id: [u8; 16] = id_hash.finalize()[..16].try_into().unwrap();
    let device_instance_seed = deterministic_seed(b"device-instance", member);
    let device_instance_id: [u8; 16] = device_instance_seed[..16].try_into().unwrap();

    let certificate_payload = cbor_map(&[
        (0, cbor_uint(1)),
        (1, cbor_bstr(&identity_id)),
        (2, cbor_bstr(&device_instance_id)),
        (3, cbor_bstr(&device_public)),
        (4, cbor_uint(issued_minute)),
        (5, vec![0xf6]),
        (6, cbor_uint(1)),
    ]);
    let protected = vec![0xa1, 0x01, 0x27];
    let sig_structure = cbor_array(&[
        cbor_tstr("Signature1"),
        cbor_bstr(&protected),
        cbor_bstr(L_DEVICE_CERT_AAD),
        cbor_bstr(&certificate_payload),
    ]);
    let signature = root_key.sign(&sig_structure).to_bytes();
    root_key
        .verifying_key()
        .verify_strict(
            &sig_structure,
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .unwrap();
    let certificate = cbor_array(&[
        cbor_bstr(&protected),
        cbor_map(&[]),
        cbor_bstr(&certificate_payload),
        cbor_bstr(&signature),
    ]);
    let credential_bytes = cbor_map(&[
        (0, cbor_uint(1)),
        (1, cbor_bstr(&root_public)),
        (2, cbor_bstr(&certificate)),
    ]);

    let signer = SignatureKeyPair::from_raw(
        SignatureScheme::ED25519,
        device_key.to_bytes().to_vec(),
        device_public.to_vec(),
    );
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(credential_bytes.clone()).into(),
        signature_key: device_public.to_vec().into(),
    };

    TestIdentity {
        credential_with_key,
        signer,
        credential_bytes,
        identity_id,
        root_public,
        device_instance_id,
        device_public,
    }
}

fn build_key_package(
    provider: &Provider,
    identity: &TestIdentity,
    not_before: u64,
    not_after: u64,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .key_package_lifetime(Lifetime::init(not_before, not_after))
        .build(
            SUITE,
            provider,
            &identity.signer,
            identity.credential_with_key.clone(),
        )
        .unwrap()
}

fn main() {
    let output_path = env::args().nth(1).expect("usage: harness OUTPUT.json");
    let now_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let issued_minute = (now_seconds / 60).saturating_sub(1);
    let not_before = issued_minute * 60;
    let not_after = (issued_minute + 10_080) * 60;

    let config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(SUITE)
        .use_ratchet_tree_extension(true)
        .max_past_epochs(3)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(100, 1_000))
        .build();

    let owner_provider = Provider::default();
    let owner = application_bound_identity(0, issued_minute);
    let mut group = MlsGroup::new_with_group_id(
        &owner_provider,
        &owner.signer,
        &config,
        GroupId::from_slice(b"DEC-001-16-member-measurement"),
        owner.credential_with_key.clone(),
    )
    .unwrap();

    let mut credential_evidence = vec![json!({
        "member": 0,
        "credential_length": owner.credential_bytes.len(),
        "credential_sha256": sha256_hex(&owner.credential_bytes),
    })];

    for member in 1..(MEMBER_COUNT - 1) {
        let provider = Provider::default();
        let identity = application_bound_identity(member, issued_minute);
        let key_package = build_key_package(&provider, &identity, not_before, not_after);
        group
            .add_members(
                &owner_provider,
                &owner.signer,
                &[key_package.key_package().clone()],
            )
            .unwrap();
        group.merge_pending_commit(&owner_provider).unwrap();
        credential_evidence.push(json!({
            "member": member,
            "credential_length": identity.credential_bytes.len(),
            "credential_sha256": sha256_hex(&identity.credential_bytes),
        }));
    }

    let recipient_member = MEMBER_COUNT - 1;
    let recipient_provider = Provider::default();
    let recipient = application_bound_identity(recipient_member, issued_minute);
    let recipient_key_package =
        build_key_package(&recipient_provider, &recipient, not_before, not_after);
    assert_eq!(
        recipient_key_package
            .key_package()
            .leaf_node()
            .credential()
            .serialized_content(),
        recipient.credential_bytes
    );
    let key_package_tls = recipient_key_package
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    let (_commit, welcome_message, _group_info) = group
        .add_members(
            &owner_provider,
            &owner.signer,
            &[recipient_key_package.key_package().clone()],
        )
        .unwrap();
    let welcome_tls = welcome_message.tls_serialize_detached().unwrap();
    group.merge_pending_commit(&owner_provider).unwrap();
    credential_evidence.push(json!({
        "member": recipient_member,
        "credential_length": recipient.credential_bytes.len(),
        "credential_sha256": sha256_hex(&recipient.credential_bytes),
    }));

    let outsider_provider = Provider::default();
    let outsider = application_bound_identity(MEMBER_COUNT, issued_minute);
    let outsider_key_package =
        build_key_package(&outsider_provider, &outsider, not_before, not_after);
    let outsider_key_package_tls = outsider_key_package
        .key_package()
        .tls_serialize_detached()
        .unwrap();

    let welcome_in: MlsMessageIn = welcome_message.into();
    let welcome = welcome_in.into_welcome().expect("expected Welcome");
    let wrong_recipient_error = StagedWelcome::new_from_welcome(
        &outsider_provider,
        config.join_config(),
        welcome.clone(),
        None,
    )
    .expect_err("a Welcome must not join with a non-recipient KeyPackage");
    let wrong_recipient_error = format!("{wrong_recipient_error:?}");
    assert!(wrong_recipient_error.contains("NoMatchingKeyPackage"));
    let staged =
        StagedWelcome::new_from_welcome(&recipient_provider, config.join_config(), welcome, None)
            .expect("ratchet-tree extension must make external tree unnecessary");
    assert_eq!(
        staged
            .welcome_sender()
            .expect("Welcome sender must be in the ratchet tree")
            .credential()
            .serialized_content(),
        owner.credential_bytes
    );
    let mut joined_group = staged.into_group(&recipient_provider).unwrap();
    assert_eq!(group.members().count(), MEMBER_COUNT);
    assert_eq!(joined_group.members().count(), MEMBER_COUNT);
    for expected in &credential_evidence {
        let expected_hash = expected["credential_sha256"].as_str().unwrap();
        assert!(
            joined_group.members().any(|member| {
                sha256_hex(member.credential.serialized_content()) == expected_hash
            })
        );
    }

    let routing_secret = group
        .export_secret(
            owner_provider.crypto(),
            "mesh-messenger/v1/routing-secret",
            &[],
            32,
        )
        .unwrap();
    assert_eq!(
        routing_secret,
        joined_group
            .export_secret(
                recipient_provider.crypto(),
                "mesh-messenger/v1/routing-secret",
                &[],
                32,
            )
            .unwrap()
    );
    let mut sender_outer_keys = Vec::new();
    for sender_leaf_index in 0..MEMBER_COUNT {
        let context = (sender_leaf_index as u32).to_be_bytes();
        let outer_key = group
            .export_secret(
                owner_provider.crypto(),
                "mesh-messenger/v1/outer-aead-key",
                &context,
                16,
            )
            .unwrap();
        assert_eq!(
            outer_key,
            joined_group
                .export_secret(
                    recipient_provider.crypto(),
                    "mesh-messenger/v1/outer-aead-key",
                    &context,
                    16,
                )
                .unwrap()
        );
        sender_outer_keys.push(json!({
            "sender_leaf_index": sender_leaf_index,
            "context_hex": hex::encode(context),
            "outer_key_hex": hex::encode(outer_key),
        }));
    }

    let application_plaintext = cbor_map(&[
        (0, cbor_uint(1)),
        (1, cbor_uint(1)),
        (2, cbor_bstr(&[0x31; 16])),
        (3, cbor_uint(1)),
        (4, cbor_tstr("16-member application-bound fixture")),
    ]);
    let application_message = group
        .create_message(&owner_provider, &owner.signer, &application_plaintext)
        .unwrap();
    let application_message_tls = application_message.tls_serialize_detached().unwrap();
    let inbound_application =
        MlsMessageIn::tls_deserialize_exact(application_message_tls.clone()).unwrap();
    let processed_application = joined_group
        .process_message(
            &recipient_provider,
            inbound_application
                .try_into_protocol_message()
                .expect("expected an MLS protocol message"),
        )
        .unwrap();
    assert_eq!(
        processed_application.sender(),
        &Sender::Member(group.own_leaf_index())
    );
    match processed_application.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => {
            assert_eq!(message.into_bytes(), application_plaintext)
        }
        _ => panic!("expected an application message"),
    }

    let evidence = json!({
        "schema": "DEC-001-OpenMLS-measurement-v1",
        "public_test_fixture": true,
        "openmls_revision": OPENMLS_REVISION,
        "rustc": RUSTC_VERSION,
        "cargo": CARGO_VERSION,
        "ciphersuite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        "ciphersuite_id": 1,
        "wire_format_policy": "PURE_CIPHERTEXT_WIRE_FORMAT_POLICY",
        "ratchet_tree_extension": true,
        "member_count": MEMBER_COUNT,
        "issued_minute": issued_minute,
        "not_before_seconds": not_before,
        "not_after_seconds": not_after,
        "credential_evidence": credential_evidence,
        "application_binding": {
            "owner": {
                "member": 0,
                "identity_id_hex": hex::encode(owner.identity_id),
                "root_seed_public_test_only_hex": hex::encode(deterministic_seed(b"root", 0)),
                "root_public_hex": hex::encode(owner.root_public),
                "device_instance_id_hex": hex::encode(owner.device_instance_id),
                "device_seed_public_test_only_hex": hex::encode(deterministic_seed(b"device", 0)),
                "device_public_hex": hex::encode(owner.device_public),
                "credential_cbor_hex": hex::encode(&owner.credential_bytes),
                "credential_sha256": sha256_hex(&owner.credential_bytes),
            },
            "recipient": {
                "member": recipient_member,
                "identity_id_hex": hex::encode(recipient.identity_id),
                "root_seed_public_test_only_hex": hex::encode(deterministic_seed(b"root", recipient_member)),
                "root_public_hex": hex::encode(recipient.root_public),
                "device_instance_id_hex": hex::encode(recipient.device_instance_id),
                "device_seed_public_test_only_hex": hex::encode(deterministic_seed(b"device", recipient_member)),
                "device_public_hex": hex::encode(recipient.device_public),
                "credential_cbor_hex": hex::encode(&recipient.credential_bytes),
                "credential_sha256": sha256_hex(&recipient.credential_bytes),
            },
            "outsider": {
                "member": MEMBER_COUNT,
                "identity_id_hex": hex::encode(outsider.identity_id),
                "root_seed_public_test_only_hex": hex::encode(deterministic_seed(b"root", MEMBER_COUNT)),
                "root_public_hex": hex::encode(outsider.root_public),
                "device_instance_id_hex": hex::encode(outsider.device_instance_id),
                "device_seed_public_test_only_hex": hex::encode(deterministic_seed(b"device", MEMBER_COUNT)),
                "device_public_hex": hex::encode(outsider.device_public),
                "credential_cbor_hex": hex::encode(&outsider.credential_bytes),
                "credential_sha256": sha256_hex(&outsider.credential_bytes),
            },
            "key_package_embedded_credential_matches_recipient": true,
            "welcome_authenticated_committer_matches_owner": true,
        },
        "recipient_key_package_tls": {
            "length": key_package_tls.len(),
            "sha256": sha256_hex(&key_package_tls),
            "hex": hex::encode(&key_package_tls),
        },
        "welcome_mls_message_tls": {
            "length": welcome_tls.len(),
            "sha256": sha256_hex(&welcome_tls),
            "hex": hex::encode(&welcome_tls),
        },
        "negative_application_binding": {
            "wrong_key_package_expected_credential_cbor_hex": hex::encode(&owner.credential_bytes),
            "wrong_key_package_actual_credential_cbor_hex": hex::encode(&recipient.credential_bytes),
            "key_package_credential_match": false,
            "expected_key_package_result": "POLICY_REJECT_KEY_PACKAGE_CREDENTIAL_MISMATCH",
            "wrong_welcome_recipient_key_package_tls": {
                "length": outsider_key_package_tls.len(),
                "sha256": sha256_hex(&outsider_key_package_tls),
                "hex": hex::encode(&outsider_key_package_tls),
            },
            "wrong_welcome_recipient_openmls_error": wrong_recipient_error,
            "expected_welcome_result": "POLICY_REJECT_WELCOME_NOT_FOR_BUNDLE_KEY_PACKAGE",
        },
        "join_validation": {
            "external_ratchet_tree_supplied": false,
            "joined_member_count": joined_group.members().count(),
            "all_application_credentials_present": true,
        },
        "application_message": {
            "authenticated_sender_leaf_index": group.own_leaf_index().u32(),
            "plaintext_cbor_hex": hex::encode(&application_plaintext),
            "mls_message_tls": {
                "length": application_message_tls.len(),
                "sha256": sha256_hex(&application_message_tls),
                "hex": hex::encode(&application_message_tls),
            },
            "recipient_processed_and_matched_plaintext": true,
        },
        "application_exporters": {
            "routing_label": "mesh-messenger/v1/routing-secret",
            "routing_context_hex": "",
            "routing_secret_hex": hex::encode(routing_secret),
            "outer_label": "mesh-messenger/v1/outer-aead-key",
            "sender_outer_keys": sender_outer_keys,
            "owner_and_recipient_outputs_match": true,
        }
    });
    fs::write(output_path, serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
}

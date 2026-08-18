# Pinned OpenMLS 16-member measurement harness

- Status: DEC-001 draft test evidence; not human approval
- OpenMLS source: lightweight tag `openmls-v0.8.1`, direct and dereferenced commit `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6`
- Rust: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, full source commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`
- Cargo: `cargo 1.97.1 (c980f4866 2026-06-30)`
- Dependency graph: `Cargo.lock`; registry package checksums and exact selected versions are authoritative inputs to `--locked`

This harness compiles against an existing clean checkout of the pinned OpenMLS source. It draws a fresh nonzero 32-byte group ID from `openmls_libcrux_crypto::Provider`, records and asserts its exact length, creates 16 valid application-bound BasicCredentials and KeyPackages, creates a private-wire-format suite-`0x0001` group with the ratchet-tree extension, generates the Welcome for member 16, and proves that member can join with no external ratchet tree. It also exports all 16 leaf-context outer keys, creates and processes an authenticated application message from leaf 0, and rejects the Welcome with an outsider KeyPackage.

The checked-in `../openmls_16_member_measurement.json`, SHA-256 `b48add24c5f0046c72849dcfbdd3c30e5b124e3dc729cbb5b6fa58ea9f1101d9`, is one conforming generated public test fixture used by the independent vector generators. Its deterministic private inputs are labeled public test-only material and must never be used in production; its group ID and OpenMLS cryptographic bytes came from provider randomness.

From the repository root, the exact reproduction command for the verified local environment is:

```text
docs/spec/vectors/v1/openmls_harness/reproduce.sh /tmp/dec001-openmls-review /tmp/dec001-openmls-measurement.reproduced.json /Users/kadri.samuel/.cargo/bin/cargo /Users/kadri.samuel/.cargo/bin/rustc
```

The command must exit zero. The output must report schema `DEC-001-OpenMLS-measurement-v2`, a fresh nonzero 32-byte group ID sourced from the configured provider, `member_count = 16`, 199-byte application credentials, a 474-byte recipient KeyPackage, a 6,625-byte complete `MlsMessage` Welcome, a 224-byte application message, `external_ratchet_tree_supplied = false`, `joined_member_count = 16`, and `all_application_credentials_present = true`. It must produce 16 distinct sender-context keys, process the leaf-0 application message at the recipient, and reject the same Welcome with an uninvited KeyPackage as `NoMatchingKeyPackage`. A source revision, source worktree, toolchain, lockfile, compile, join, exporter, sender, negative check, or assertion mismatch fails closed.

Semantic harness reproducibility is deliberately different from byte-identical vector reproduction. Run the command three times with output names ending `-1.json`, `-2.json`, and `-3.json`; each must satisfy the assertions above, while group IDs, ciphertexts, keys, signatures, and hashes are expected to differ. The frozen fixture is not expected to reappear byte-for-byte. In contrast, both independent vector generators consume that exact frozen fixture and MUST produce byte-identical `vectors.json`.

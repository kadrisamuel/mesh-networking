# Pinned OpenMLS 16-member measurement harness

- Status: DEC-001 draft test evidence; not human approval
- OpenMLS source: lightweight tag `openmls-v0.8.1`, direct and dereferenced commit `47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6`
- Rust: `rustc 1.97.1 (8bab26f4f 2026-07-14)`, full source commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`
- Cargo: `cargo 1.97.1 (c980f4866 2026-06-30)`
- Dependency graph: `Cargo.lock`; registry package checksums and exact selected versions are authoritative inputs to `--locked`

This harness compiles against an existing clean checkout of the pinned OpenMLS source. It creates 16 valid application-bound BasicCredentials and KeyPackages, creates a private-wire-format suite-`0x0001` group with the ratchet-tree extension, generates the Welcome for member 16, and proves that member can join with no external ratchet tree. It also exports all 16 leaf-context outer keys, creates and processes an authenticated application message from leaf 0, and rejects the Welcome with an outsider KeyPackage. The generated MLS objects use provider randomness, so bytes and hashes are intentionally not repeatable; their encoded lengths and conformance results are deterministic for the pinned graph and inputs.

The checked-in `../openmls_16_member_measurement.json`, SHA-256 `1015e46e7423a57bc00e12c0c7008c648cb468a3df0b41cea77c3ad585395b7f`, is the generated public test fixture used by the independent vector generators. Its deterministic private inputs are labeled public test-only material and must never be used in production.

From the repository root, the exact reproduction command for the verified local environment is:

```text
docs/spec/vectors/v1/openmls_harness/reproduce.sh /tmp/dec001-openmls-review /tmp/dec001-openmls-measurement.reproduced.json /Users/kadri.samuel/.cargo/bin/cargo /Users/kadri.samuel/.cargo/bin/rustc
```

The command must exit zero. The output must report `member_count = 16`, 199-byte application credentials, a 474-byte recipient KeyPackage, a 6,622-byte complete `MlsMessage` Welcome, `external_ratchet_tree_supplied = false`, `joined_member_count = 16`, and `all_application_credentials_present = true`. It must produce 16 distinct sender-context keys, process the leaf-0 application message at the recipient, and reject the same Welcome with an uninvited KeyPackage as `NoMatchingKeyPackage`. A source revision, source worktree, toolchain, lockfile, compile, join, exporter, sender, negative check, or assertion mismatch fails closed.

# ADR-0001: Platform and architecture baseline

- Status: Draft — human approval required
- Decision date: 2026-08-18
- Scope: DEC-001 only

## Context

The MVP needs one security implementation across five operating-system families while respecting mobile lifecycle limits and reproducible builds.

## Proposed decision

Flutter owns presentation, accessibility, notifications, and OS integration. The shared Rust core exclusively owns plaintext processing, identity and keys, MLS, both databases, envelope and frame codecs, relay policy, Noise sessions, and Meshtastic protocol handling. FFI conveys typed commands/state and opaque byte buffers; it never exports key material.

Supported clients are Android 10 (API 29) through Android 16 (API 36), iOS 16.7.16 through iOS 26.6, Windows 11 24H2 through 25H2, macOS Monterey 12 through Tahoe 26.6, and Ubuntu 24.04.4 LTS. Android 10 and iOS 16 are product floors. Windows 10 is deliberately excluded because its normal support has ended. Ubuntu 26.04 LTS is not an acceptance target because the pinned Flutter release currently lists support only through Ubuntu 24.04 LTS.

Mobile phone-to-phone BLE and WLAN acceptance is foreground-only. Android may later provide a conspicuous user-started foreground relay service; iOS background relay remains best-effort and cannot satisfy acceptance. Desktop phone-mesh BLE is excluded. Desktop clients use WLAN and Meshtastic serial/TCP only. The browser, internet service, cloud account, custom radio firmware, analytics, and remote telemetry are excluded.

The exact toolchain, dependency, device, and radio pins are in `docs/spec/ARCHITECTURE.md`. Any version change requires a new ADR or an approved amendment, regenerated fixtures where relevant, and the full test matrix.

## Consequences

- Security-sensitive behavior has one Rust implementation and one fixture set.
- A locked client can relay opaque ciphertext because relay storage is separate from private storage.
- Compatibility promises are narrower than Flutter's theoretical support matrix.
- Foreground-only mobile tests do not imply continuous background routing.

## Approval blockers

- Physical reference devices and radios have not been inventoried or measured.
- Flutter does not yet list Ubuntu 26.04 LTS as supported; adding it requires an upstream support statement or a separately approved qualification result.
- The pinned Flutter/Rust bridge combination needs a five-platform build qualification.

## Sources

- [Flutter SDK archive](https://docs.flutter.dev/install/archive)
- [Flutter supported deployment platforms](https://docs.flutter.dev/reference/supported-platforms)
- [Android SDK platform releases](https://developer.android.com/tools/releases/platforms)
- [Apple Xcode system requirements](https://developer.apple.com/xcode/system-requirements)
- [Microsoft Windows 11 release information](https://learn.microsoft.com/windows/release-health/windows11-release-information)
- [Ubuntu 26.04 release notes](https://documentation.ubuntu.com/release-notes/26.04/)

## Human decision required

Approve or reject the proposed platform floors, current-version targets, Ubuntu 24.04.4 limitation, foreground-only mobile acceptance, desktop BLE exclusion, and architectural ownership boundary as one decision.

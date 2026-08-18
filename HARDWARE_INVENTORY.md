# Hardware Inventory and Acquisition Plan

**Last updated:** 2026-08-18

**Status:** Planning input only; not an approved `DEC-001` decision or completed `HW-001` manifest.

This file intentionally excludes serial numbers, device identifiers, and other unnecessary personal data. Prices are estimates and should be rechecked before purchase.

## Available equipment

| Category  | Device                                | Software       | Availability          | Intended use                                                                       | Notes                                                                                                        |
| --------- | ------------------------------------- | -------------- | --------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Computer  | MacBook Air, Apple M4, 16 GB, ARM64   | macOS 26.5.2   | Available             | Primary development machine; macOS and iOS builds; host for local virtual machines | No other physical computer currently owned                                                                   |
| Computer access | School Windows computers       | Unknown Windows versions | Available in principle | Windows build, installation, firewall, serial/TCP, packaging, and clean-build tests | Confirm access schedule, installation rights, administrator/firewall permissions, USB access, and data-handling rules |
| Phone     | iPhone 13                             | iOS 26.6       | Available for testing | Primary physical iOS endpoint                                                      | Record battery health during performance testing                                                             |
| Phone loan | Android phones from friends          | Unknown        | Likely borrowable; unconfirmed | Android-to-Android and Android-to-iOS physical testing                         | Confirm at least two models, Android versions, availability dates, and permission to install development builds |
| Tablet    | iPad Air, generation not yet recorded | iPadOS 26.2.1  | Available             | Possible second Apple BLE/WLAN endpoint                                            | `DEC-001` must decide whether an iPad satisfies iOS-to-iOS acceptance or whether a second iPhone is required |
| Network   | Ordinary Wi-Fi router/access point    | Not recorded   | Available             | Shared-WLAN discovery, connection, and latency tests                               | Record make/model and configuration when `HW-001` begins                                                     |
| Radio     | Possible radio borrowed from friend   | Unknown        | Unconfirmed           | Possible third mesh node                                                           | Model, frequency band, firmware, and borrowing availability are unknown                                      |

## Recommended minimum Meshtastic purchase

Do not order until `DEC-001` approves the reference-radio matrix.

Purchase **two Heltec WiFi LoRa 32 V3 boards in the EU868 / 863–870 MHz variant** as the budget bench baseline.

- Two owned units allow repeatable point-to-point LoRa tests without depending on borrowed equipment.
- The boards provide SX1262 LoRa, Bluetooth LE, 2.4 GHz Wi-Fi, USB-C, and a display.
- Heltec V3 is supported by the official Meshtastic web flasher.
- An 868 MHz antenna is included in the cited EU listing; batteries and USB data cables are not.
- Current board price observed: approximately **EUR 22.95 each**, including VAT but excluding shipping.
- Estimated bench-ready total for two boards: **EUR 60–90**, including suitable USB data cables, simple protective cases, and shipping. Batteries are optional for initial USB-powered bench work.
- Do not buy a 915 MHz variant for Swedish/EU testing.
- Treat these as budget bench devices, not substitutes for the frozen T-Echo, RAK4631, and Heltec Wireless Stick V3 reference matrix.
- Heltec states that onboard Wi-Fi and Bluetooth cannot be used simultaneously on this model, so it is not the sole reference device for simultaneous BLE/WLAN gateway acceptance.

Sources checked 2026-08-18:

- Meshtastic supported-device flasher: <https://flasher.meshtastic.org/>
- Heltec product information: <https://heltec.org/project/wifi-lora-32-v3/>
- EU Heltec V3 listing used for price estimate: <https://hexaspot.com/products/heltec-wifi-lora-32-v3>

## Acquisition stages

| Stage | Equipment needed | Acquisition guidance |
|---|---|---|
| `DEC-001` and software foundation | Existing MacBook Air | No purchase required. Freeze the reference-device matrix first. |
| Core protocol, cryptography, storage, and simulator | Existing MacBook Air; CI runners | No physical radio required. Simulators and deterministic fixtures should be used. |
| WLAN and Apple BLE development | iPhone 13, iPad Air, ordinary Wi-Fi router | Available, subject to approval of the iPad as the second Apple endpoint. |
| Android WLAN/BLE development | Physical Android devices | Plan to borrow from friends before Android transport tasks. Confirm two suitable devices because Android-to-Android physical acceptance requires both simultaneously. |
| `MT-001` Meshtastic compatibility | At least two owned EU868 radios plus a third compatible node | Buy two approved baseline radios. Borrowing the third is acceptable if its exact model and EU868 compatibility are confirmed. |
| LoRa relay and integration acceptance | At least three EU868 radios | Three nodes are the practical minimum for source-relay-destination testing. |
| Final controlled three-hop profile (`PERF-003`) | Normally four EU868 radios; controlled RF setup | The current task pack says a physical three-hop route normally requires four nodes. Freeze topology before acquiring the fourth. |
| Cross-hardware Meshtastic acceptance | T-Echo, RAK4631, and selected ESP32/SX1262 radio unless `DEC-001` changes the matrix | The current `MT-001` wording requires all three families. Decide whether to retain this broad matrix before buying them. |
| Desktop acceptance and reproducible-build review | School Windows computers, Ubuntu environment, and a second independent computer | Use the school computers where permissions allow. Use VMs or CI where the test permits them; confirm a suitable machine for final clean-build reproduction. |

## Missing and critical later

### Mobile devices

- **Two physical Android phones:** critical for Android-to-Android BLE acceptance and Android-to-iOS interoperability. Friends are a likely borrowing source, but the devices remain unconfirmed until their models, Android API levels, availability, and development-build permissions are recorded.
- **Decision on the second Apple endpoint:** approve the iPad Air for iOS-to-iOS tests or arrange access to a second iPhone.
- Exact iPad Air generation and battery health remain unrecorded.

### Meshtastic and RF equipment

- **Two owned EU868 radios:** critical when `MT-001` starts.
- **Third EU868 radio:** critical for a physical relay mesh. The friend's radio may satisfy this after its model and band are verified.
- **Fourth EU868 radio:** likely critical for the final physical three-hop profile if that topology remains in `TEST_MATRIX.md`.
- **T-Echo and RAK4631 access:** critical under the current `MT-001` cross-hardware requirement unless `DEC-001` narrows it.
- USB data cables, correct 868 MHz antennas, protective cases, and safe power sources must be inventoried with the radios.
- A controlled and lawful RF test arrangement is required later: suitable attenuators/shielding or an approved venue, plus a completed Swedish/EU compliance checklist.

### Computers and test environments

- **Windows test environment:** school computers are available in principle. They satisfy this need only if their Windows versions are supported and development builds, USB devices, local-network/firewall tests, and required tooling are permitted.
- **Ubuntu test environment:** critical for corresponding Linux acceptance.
- **Second independent computer:** critical for the documented clean-build reproduction. It can be borrowed when that release task approaches.
- CI can compile unsupported local targets but cannot replace physical mobile, radio, permission, battery, or RF tests.

### Non-hardware prerequisites

- Apple development provisioning/signing access for physical iOS installation; distribution credentials are only needed if public distribution remains in scope.
- Human legal review for AGPL/App Store and Meshtastic GPL/protobuf distribution decisions.
- Human RF/compliance review before transmission tests.

## Provisional cost scenarios

| Scenario | Contents | Estimated cost |
|---|---|---:|
| Minimum repeatable LoRa bench | Two Heltec V3 EU868 boards, cables/cases, USB-powered | **EUR 60–90** |
| Three-node relay bench | Minimum bench plus one borrowed compatible EU868 radio | **EUR 60–90** out of pocket |
| Current broad hardware matrix | Two Heltec V3 units, one RAK4631 kit, one T-Echo, basic accessories and shipping | **Approximately EUR 180–250** |

Price references:

- RAK WisBlock Meshtastic Starter Kit: starts at USD 24.99 before shipping/tax: <https://store.rakwireless.com/products/wisblock-meshtastic-starter-kit>
- LILYGO T-Echo: USD 48.49 direct before shipping/tax; EU reseller examples are roughly EUR 75–100: <https://lilygo.cc/en-ca/products/t-echo-meshtastic>

## Information still to collect

- iPad Air generation and battery health.
- Friend's radio manufacturer, exact model, frequency band, firmware version, and dates it can be borrowed.
- Wi-Fi router make/model and whether its administration settings can be changed for testing.
- Confirm two borrowable Android phones: models, Android versions/API levels, availability dates, and permission to install development builds.
- School Windows computer versions, access schedule, installation/admin rights, USB access, local-network/firewall permissions, and data-handling restrictions.
- Availability of an Ubuntu environment and a second computer suitable for independent clean-build reproduction.
- Final approved reference-radio matrix and physical test topology from `DEC-001`.

## Compliance note

Use only the approved EU868 configuration and antennas, and do not assume that hardware maximum transmit power is lawful. Swedish frequency, power, spectrum-access, and duty-cycle conditions must be checked against the current Post and Telecom Authority rules before RF testing: <https://pts.se/contentassets/b05c8a7d01a64783aafc6a19e1b78590/ptsfs-2025-1-foreskrifter-om-undantag-fran-tillstandsplikt-for-anvandning-av-vissa-radiosandare.pdf>

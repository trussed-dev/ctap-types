# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

[Unreleased]: https://github.com/trussed-dev/ctap-types/compare/0.6.0-rc.3...HEAD

-

## [0.6.0-rc.3] 2026-05-28

[0.6.0-rc.3]: https://github.com/trussed-dev/ctap-types/compare/0.6.0-rc.2...0.6.0-rc.3

- Add fields 0x19 to 0x1F to `ctap2::get_info::Response`.
- Map `cbor_smol::Error::DeserializeBadBool` to `Error::CborUnexpectedType` instead of `Error::InvalidCbor`.

## [0.6.0-rc.2] 2026-05-27

[0.6.0-rc.2]: https://github.com/trussed-dev/ctap-types/compare/0.6.0-rc.1...0.6.0-rc.2

- Rename `authenticator_config` to `config`.
- Add `platform-serde` feature for additional `Serialize` and `Deserialize` implementations not required by authenticators.
- Add `ctap2::client_pin::MAX_PIN_LENGTH` and `ctap2::config::{DEFAULT_MIN_PIN_LENGTH, MAX_RP_ID_LENGTH, MAX_SUBCOMMAND_PARAMS_CBOR_LEN}` constants.
- Add `min_pin_length` to `make_credential::{ExtensionsInput, ExtensionsOutput}`.

## [0.6.0-rc.1] 2026-05-21

[0.6.0-rc.1]: https://github.com/trussed-dev/ctap-types/compare/0.5.0...0.6.0-rc.1

- `ctap2::get_info`: Fix field order of the `CtapOptions` and `Certifications` structs to produce canonical CBOR
- Add support for missing CTAP 2.1 features:
  - Add `AuthenticatorConfig` command.
  - Add `credBlob` extension and split `make_credential::Extensions` into `ExtensionsInput` and `ExtensionsOutput`.
  - Add `minPinLength` extension.
- Add support for missing CTAP 2.2 features:
  - Add `hmac-secret-mc` extension.
- Add support for CTAP 2.3:
  - Add `Version::Fido2_3` variant.
  - Add `Transport::SmartCard` variant.
  - `ctap2::authenticator_config`: Add `Subcommand::EnableLongTouchForReset`.
- Add `EXTENSION_COUNT`, `TRANSPORT_COUNT` and `VERSION_COUNT` constants for the size of the corresponding enums.

## [0.5.0] 2026-03-23

[0.5.0]: https://github.com/trussed-dev/ctap-types/compare/0.4.0...0.5.0

- Update dependencies:
  - `cosey` v0.4
  - `heapless` v0.9
  - `heapless-bytes` v0.5
  - `iso7816` v0.2

## [0.4.0] 2025-05-09

[0.4.0]: https://github.com/trussed-dev/ctap-types/compare/0.3.2...0.4.0

- Make `pin_protocol` optional in `ctap2::client_pin::Request` for compliance with CTAP 2.1.

## [0.3.2] 2024-10-24

[0.3.2]: https://github.com/trussed-dev/ctap-types/compare/0.3.1...0.3.2

### Changed

- Update `cbor-smol` dependency to v0.5.0

## [0.3.1] 2024-10-18

[0.3.1]: https://github.com/trussed-dev/ctap-types/compare/0.3.0...0.3.1

### Added

- Implement `TryFrom<iso7816::command::CommandView<'a>>` for `Request<'a>`

## [0.3.0] 2024-08-01

[0.3.0]: https://github.com/trussed-dev/ctap-types/compare/0.2.0...0.3.0

### Breaking Changes

- Use enums instead of string constants
  - Introduce `Version`, `Extension` and `Transport` enums and use them in `ctap2::get_info`
  - Fix serialization of the `AttestationStatementFormat` enum and use it in `ctap2::make_credential`
- Remove `Deserialize` implementation for `ctap2::get_assertion::Response`
- Remove `Serialize` implementation for `ctap2::{get_assertion, make_credential}::Request`
- Move `AttestationStatement`, `AttestationStatementFormat`, `NoneAttestationStatement`, `PackedAttestationStatement` from `ctap2::make_credential` into the `ctap2` module

### Added

- Add a `std` feature (disabled by default)
- Add `arbitrary::Arbitrary` implementations for all requests behind an `arbitrary` feature (disabled by default)
- Add support for CTAP 2.2 ([#38](https://github.com/trussed-dev/ctap-types/issues/38))
  - Add support for the `thirdPartyPayment` extension behind a `third-party-payment` feature (disabled by default)
  - Add new fields to `get_info`
  - Add unsigned extension outputs to `make_credential` and `get_assertion`
  - Add enterprise attestation support to `get_assertion`
  - Add support for attestation statements in `get_assertion`
  - Add support for attestation format preferences
- Derive `Copy` for `ctap2::AttestationStatementFormat`

## [0.2.0] - 2024-06-21

[0.2.0]: https://github.com/trussed-dev/ctap-types/compare/0.1.2...0.2.0

- Rename `url` to `icon` in `PublicKeyCredentialRpEntity` and ignore its
  content ([#9][])
- Truncate overlong `name` and `displayName` values for `PublicKeyCredentialEntity` instances ([#30][])
- Send empty response to clientPin instead of empty map ([#13][])
- Use references rather owned byte vectors to reduce the size of structs ([#16][])
- Accept more than 12 algorithms ([#17][])
- Add support for the `largeBlobKey` extension ([#18][])
- Remove `AuthenticatorDataFlags::EMPTY` (use `AuthenticatorDataFlags::empty()` instead)
- Allow missing algorithms in COSE keys ([#8][])
- Remove unused `REALISTIC_MAX_MESSAGE_SIZE` constant
- Handle overlong `icon` values in `PublicKeyCredentialUserEntity` ([#27][])
- Update for compatibility with PIN protocol 2
- Add support for permissions in `ctap2::client_pin`
- Replace `cose` module with `cosey` dependency ([#36][])
- Mark `get_assertion::{ExtensionsInput, ExtensionsOutput}` and `make_credential::Extensions` as non-exhaustive and implement `Default`
- Mark CTAP2 request and response types as non-exhaustive where possible
- Use references where possible
- Put uncommon fields in `get_info` behind `get-info-full` feature flag and add fields for CTAP 2.1
- Use byte arrays instead of slices or Bytes<_> where possible
- Make `att_stmt` optional in `make_credential::Response`, preparing for CTAP 2.2

[#8]: https://github.com/trussed-dev/ctap-types/pull/8
[#9]: https://github.com/solokeys/ctap-types/issues/9
[#30]: https://github.com/solokeys/fido-authenticator/issues/30
[#13]: https://github.com/solokeys/ctap-types/issues/13
[#16]: https://github.com/trussed-dev/ctap-types/pull/16
[#17]: https://github.com/trussed-dev/ctap-types/pull/17
[#18]: https://github.com/trussed-dev/ctap-types/pull/18
[#27]: https://github.com/trussed-dev/ctap-types/pull/27
[#36]: https://github.com/trussed-dev/ctap-types/issues/36

## [0.1.2] - 2022-03-07

[0.1.2]: https://github.com/trussed-dev/ctap-types/compare/0.1.1...0.1.2

Yanked 0.1.1 instead of 0.1.0 by mistake, re-releasing.

## [0.1.1] - 2022-03-07

[0.1.1]: https://github.com/trussed-dev/ctap-types/compare/0.1.0...0.1.1

- add CTAP2.1 Selection command
- add CTAP2.1 options

We will release this and yank 0.1.0, to avoid a minor version bump.

## [0.1.0] - 2022-03-05

[0.1.0]: https://github.com/trussed-dev/ctap-types/releases/tag/0.1.0

- use 2021 edition
- make CTAP1 and CTAP2 more homogeneous
- add Authenticator traits
- lower `MAX_CREDENTIAL_ID_LENGTH` to 255 bytes, which seems to be the
  limit used in practice (coming from U2F's size bytes)
- replace `MESSAGE_SIZE` with a theoretical and a realistic constant
- use iso7816 0.1.0 release


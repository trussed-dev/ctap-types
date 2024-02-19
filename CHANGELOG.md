# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[#8]: https://github.com/trussed-dev/ctap-types/pull/8
[#9]: https://github.com/solokeys/ctap-types/issues/9
[#30]: https://github.com/solokeys/fido-authenticator/issues/30
[#13]: https://github.com/solokeys/ctap-types/issues/13
[#16]: https://github.com/trussed-dev/ctap-types/pull/16
[#17]: https://github.com/trussed-dev/ctap-types/pull/17
[#18]: https://github.com/trussed-dev/ctap-types/pull/18
[#27]: https://github.com/trussed-dev/ctap-types/pull/27

## [0.1.2] - 2022-03-07

Yanked 0.1.1 instead of 0.1.0 by mistake, re-releasing.

## [0.1.1] - 2022-03-07

- add CTAP2.1 Selection command
- add CTAP2.1 options

We will release this and yank 0.1.0, to avoid a minor version bump.

## [0.1.0] - 2022-03-05

- use 2021 edition
- make CTAP1 and CTAP2 more homogeneous
- add Authenticator traits
- lower `MAX_CREDENTIAL_ID_LENGTH` to 255 bytes, which seems to be the
  limit used in practice (coming from U2F's size bytes)
- replace `MESSAGE_SIZE` with a theoretical and a realistic constant
- use iso7816 0.1.0 release


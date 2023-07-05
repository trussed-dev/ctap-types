# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Rename `url` to `icon` in `PublicKeyCredentialRpEntity` and ignore its
  content ([#9][])

[#9]: https://github.com/solokeys/ctap-types/issues/9

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


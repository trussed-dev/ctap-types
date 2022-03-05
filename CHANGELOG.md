# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2022-03-05

- use 2021 edition
- make CTAP1 and CTAP2 more homogeneous
- add Authenticator traits
- lower `MAX_CREDENTIAL_ID_LENGTH` to 255 bytes, which seems to be the
  limit used in practice (coming from U2F's size bytes)
- replace `MESSAGE_SIZE` with a theoretical and a realistic constant
- use iso7816 0.1.0 release


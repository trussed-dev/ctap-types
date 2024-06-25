use crate::Bytes;
use bitflags::bitflags;
use cosey::EcdhEsHkdf256PublicKey;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Clone, Debug, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
#[repr(u8)]
pub enum PinV1Subcommand {
    GetRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUVRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}

bitflags! {
    #[derive(Default)]
    pub struct Permissions: u8 {
        const MAKE_CREDENTIAL = 0x01;
        const GET_ASSERTION = 0x02;
        const CREDENTIAL_MANAGEMENT = 0x04;
        const BIO_ENROLLMENT = 0x08;
        const LARGE_BLOB_WRITE = 0x10;
        const AUTHENTICATOR_CONFIGURATION = 0x20;
    }
}

// minimum PIN length: 4 unicode
// maximum PIN length: UTF-8 represented by <= 63 bytes
// maximum consecutive incorrect PIN attempts: 8

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Request<'a> {
    // 0x01
    // PIN protocol version chosen by the client.
    // For this version of the spec, this SHALL be the number 1.
    pub pin_protocol: u8,

    // 0x02
    // The authenticator Client PIN sub command currently being requested
    pub sub_command: PinV1Subcommand,

    // 0x03
    // Public key of platformKeyAgreementKey.
    // Must contain "alg" parameter, must not contain any other optional parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<EcdhEsHkdf256PublicKey>,

    // 0x04
    // First 16 bytes of HMAC-SHA-256 of encrypted contents
    // using `sharedSecret`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth: Option<&'a serde_bytes::Bytes>,

    // 0x05
    // Encrypted new PIN using `sharedSecret`.
    // (Encryption over UTF-8 representation of new PIN).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_pin_enc: Option<&'a serde_bytes::Bytes>,

    // 0x06
    // Encrypted first 16 bytes of SHA-256 of PIN using `sharedSecret`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_hash_enc: Option<&'a serde_bytes::Bytes>,

    // 0x07
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) _placeholder07: Option<()>,

    // 0x08
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) _placeholder08: Option<()>,

    // 0x09
    // Bitfield of permissions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<u8>,

    // 0x0A
    // The RP ID to assign as the permissions RP ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<&'a str>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Response {
    // 0x01, like ClientPinParameters::key_agreement
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<EcdhEsHkdf256PublicKey>,

    // 0x02, encrypted `pinToken` using `sharedSecret`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_token: Option<Bytes<48>>,

    // 0x03, number of PIN attempts remaining before lockout
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u8>,

    // 0x04, whether a power cycle is required before any future PIN operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub power_cycle_state: Option<bool>,

    // 0x05, number of uv attempts remaining before lockout
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_retries: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use serde_test::{assert_de_tokens, assert_ser_tokens, assert_tokens, Token};

    const KEY_AGREEMENT: &[u8] = &hex!("b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9");
    const NEW_PIN_ENC: &[u8] = &[0xde; 64];
    const PIN_AUTH: &[u8] = &[0xad; 32];
    const PIN_HASH_ENC: &[u8] = &[0xda; 16];
    const PIN_TOKEN: &[u8] = &[0xed; 32];

    #[test]
    fn test_de_request_get_retries() {
        let request = Request {
            pin_protocol: 1,
            sub_command: PinV1Subcommand::GetRetries,
            key_agreement: None,
            pin_auth: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            _placeholder07: None,
            _placeholder08: None,
            permissions: None,
            rp_id: None,
        };
        assert_tokens(
            &request,
            &[
                Token::Map { len: Some(2) },
                // 0x01: pinProtocol
                Token::U64(0x01),
                Token::U8(1),
                // 0x02: subCommand
                Token::U64(0x02),
                Token::U8(0x01),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_de_request_get_key_agreement() {
        let request = Request {
            pin_protocol: 1,
            sub_command: PinV1Subcommand::GetKeyAgreement,
            key_agreement: None,
            pin_auth: None,
            new_pin_enc: None,
            pin_hash_enc: None,
            _placeholder07: None,
            _placeholder08: None,
            permissions: None,
            rp_id: None,
        };
        assert_tokens(
            &request,
            &[
                Token::Map { len: Some(2) },
                // 0x01: pinProtocol
                Token::U64(0x01),
                Token::U8(1),
                // 0x02: subCommand
                Token::U64(0x02),
                Token::U8(0x02),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_de_request_set_pin() {
        let key_agreement = EcdhEsHkdf256PublicKey {
            x: Bytes::from_slice(&KEY_AGREEMENT[..32]).unwrap(),
            y: Bytes::from_slice(&KEY_AGREEMENT[32..]).unwrap(),
        };
        let request = Request {
            pin_protocol: 1,
            sub_command: PinV1Subcommand::SetPin,
            key_agreement: Some(key_agreement),
            pin_auth: Some(serde_bytes::Bytes::new(PIN_AUTH)),
            new_pin_enc: Some(serde_bytes::Bytes::new(NEW_PIN_ENC)),
            pin_hash_enc: None,
            _placeholder07: None,
            _placeholder08: None,
            permissions: None,
            rp_id: None,
        };
        assert_de_tokens(
            &request,
            &[
                Token::Map { len: Some(5) },
                // 0x01: pinProtocol
                Token::U64(0x01),
                Token::U8(1),
                // 0x02: subCommand
                Token::U64(0x02),
                Token::U8(0x03),
                // 0x03: keyAgreement
                Token::U64(0x03),
                Token::Map { len: Some(5) },
                //       1: kty
                Token::I8(1),
                Token::I8(2),
                //       3: alg
                Token::I8(3),
                Token::I8(-25),
                //       -1: crv
                Token::I8(-1),
                Token::I8(1),
                //       -2: x
                Token::I8(-2),
                Token::BorrowedBytes(&KEY_AGREEMENT[..32]),
                //       -3: y
                Token::I8(-3),
                Token::BorrowedBytes(&KEY_AGREEMENT[32..]),
                Token::MapEnd,
                // 0x04: pinUvAuthParam
                Token::U64(0x04),
                Token::BorrowedBytes(PIN_AUTH),
                // 0x05: newPinEnc
                Token::U64(0x05),
                Token::BorrowedBytes(NEW_PIN_ENC),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_de_request_change_pin() {
        let key_agreement = EcdhEsHkdf256PublicKey {
            x: Bytes::from_slice(&KEY_AGREEMENT[..32]).unwrap(),
            y: Bytes::from_slice(&KEY_AGREEMENT[32..]).unwrap(),
        };
        let request = Request {
            pin_protocol: 1,
            sub_command: PinV1Subcommand::ChangePin,
            key_agreement: Some(key_agreement),
            pin_auth: Some(serde_bytes::Bytes::new(PIN_AUTH)),
            new_pin_enc: Some(serde_bytes::Bytes::new(NEW_PIN_ENC)),
            pin_hash_enc: Some(serde_bytes::Bytes::new(PIN_HASH_ENC)),
            _placeholder07: None,
            _placeholder08: None,
            permissions: None,
            rp_id: None,
        };
        assert_de_tokens(
            &request,
            &[
                Token::Map { len: Some(6) },
                // 0x01: pinProtocol
                Token::U64(0x01),
                Token::U8(1),
                // 0x02: subCommand
                Token::U64(0x02),
                Token::U8(0x04),
                // 0x03: keyAgreement
                Token::U64(0x03),
                Token::Map { len: Some(5) },
                //       1: kty
                Token::I8(1),
                Token::I8(2),
                //       3: alg
                Token::I8(3),
                Token::I8(-25),
                //       -1: crv
                Token::I8(-1),
                Token::I8(1),
                //       -2: x
                Token::I8(-2),
                Token::BorrowedBytes(&KEY_AGREEMENT[..32]),
                //       -3: y
                Token::I8(-3),
                Token::BorrowedBytes(&KEY_AGREEMENT[32..]),
                Token::MapEnd,
                // 0x04: pinUvAuthParam
                Token::U64(0x04),
                Token::BorrowedBytes(PIN_AUTH),
                // 0x05: newPinEnc
                Token::U64(0x05),
                Token::BorrowedBytes(NEW_PIN_ENC),
                // 0x06: pinHashEnc
                Token::U64(0x06),
                Token::BorrowedBytes(PIN_HASH_ENC),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_de_get_pin_token() {
        let key_agreement = EcdhEsHkdf256PublicKey {
            x: Bytes::from_slice(&KEY_AGREEMENT[..32]).unwrap(),
            y: Bytes::from_slice(&KEY_AGREEMENT[32..]).unwrap(),
        };
        let request = Request {
            pin_protocol: 1,
            sub_command: PinV1Subcommand::GetPinToken,
            key_agreement: Some(key_agreement),
            pin_auth: None,
            new_pin_enc: None,
            pin_hash_enc: Some(serde_bytes::Bytes::new(PIN_HASH_ENC)),
            _placeholder07: None,
            _placeholder08: None,
            permissions: None,
            rp_id: None,
        };
        assert_de_tokens(
            &request,
            &[
                Token::Map { len: Some(4) },
                // 0x01: pinProtocol
                Token::U64(0x01),
                Token::U8(1),
                // 0x02: subCommand
                Token::U64(0x02),
                Token::U8(0x05),
                // 0x03: keyAgreement
                Token::U64(0x03),
                Token::Map { len: Some(5) },
                //       1: kty
                Token::I8(1),
                Token::I8(2),
                //       3: alg
                Token::I8(3),
                Token::I8(-25),
                //       -1: crv
                Token::I8(-1),
                Token::I8(1),
                //       -2: x
                Token::I8(-2),
                Token::BorrowedBytes(&KEY_AGREEMENT[..32]),
                //       -3: y
                Token::I8(-3),
                Token::BorrowedBytes(&KEY_AGREEMENT[32..]),
                Token::MapEnd,
                // 0x06: pinHashEnc
                Token::U64(0x06),
                Token::BorrowedBytes(PIN_HASH_ENC),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_de_get_pin_token_with_permissions() {
        let key_agreement = EcdhEsHkdf256PublicKey {
            x: Bytes::from_slice(&KEY_AGREEMENT[..32]).unwrap(),
            y: Bytes::from_slice(&KEY_AGREEMENT[32..]).unwrap(),
        };
        let request = Request {
            pin_protocol: 1,
            sub_command: PinV1Subcommand::GetPinUvAuthTokenUsingPinWithPermissions,
            key_agreement: Some(key_agreement),
            pin_auth: None,
            new_pin_enc: None,
            pin_hash_enc: Some(serde_bytes::Bytes::new(PIN_HASH_ENC)),
            _placeholder07: None,
            _placeholder08: None,
            permissions: Some(0x04),
            rp_id: Some("example.com"),
        };
        assert_de_tokens(
            &request,
            &[
                Token::Map { len: Some(6) },
                // 0x01: pinProtocol
                Token::U64(0x01),
                Token::U8(1),
                // 0x02: subCommand
                Token::U64(0x02),
                Token::U8(0x09),
                // 0x03: keyAgreement
                Token::U64(0x03),
                Token::Map { len: Some(5) },
                //       1: kty
                Token::I8(1),
                Token::I8(2),
                //       3: alg
                Token::I8(3),
                Token::I8(-25),
                //       -1: crv
                Token::I8(-1),
                Token::I8(1),
                //       -2: x
                Token::I8(-2),
                Token::BorrowedBytes(&KEY_AGREEMENT[..32]),
                //       -3: y
                Token::I8(-3),
                Token::BorrowedBytes(&KEY_AGREEMENT[32..]),
                Token::MapEnd,
                // 0x06: pinHashEnc
                Token::U64(0x06),
                Token::BorrowedBytes(PIN_HASH_ENC),
                // 0x09: permissions
                Token::U64(0x09),
                Token::U8(0x04),
                // 0x0A: rpId
                Token::U64(0x0A),
                Token::BorrowedStr("example.com"),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_ser_response_get_retries() {
        let response = Response {
            retries: Some(3),
            ..Default::default()
        };
        assert_ser_tokens(
            &response,
            &[
                Token::Map { len: Some(1) },
                // 0x03: pinRetries
                Token::U64(0x03),
                Token::Some,
                Token::U8(3),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_ser_response_get_key_agreement() {
        let key_agreement = EcdhEsHkdf256PublicKey {
            x: Bytes::from_slice(&KEY_AGREEMENT[..32]).unwrap(),
            y: Bytes::from_slice(&KEY_AGREEMENT[32..]).unwrap(),
        };
        let response = Response {
            key_agreement: Some(key_agreement),
            ..Default::default()
        };
        assert_ser_tokens(
            &response,
            &[
                Token::Map { len: Some(1) },
                // 0x01: keyAgreement
                Token::U64(0x01),
                Token::Some,
                Token::Map { len: Some(5) },
                //       1: kty
                Token::I8(1),
                Token::I8(2),
                //       3: alg
                Token::I8(3),
                Token::I8(-25),
                //       -1: crv
                Token::I8(-1),
                Token::I8(1),
                //       -2: x
                Token::I8(-2),
                Token::BorrowedBytes(&KEY_AGREEMENT[..32]),
                //       -3: y
                Token::I8(-3),
                Token::BorrowedBytes(&KEY_AGREEMENT[32..]),
                Token::MapEnd,
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_ser_response_get_pin_token() {
        let response = Response {
            pin_token: Some(Bytes::from_slice(PIN_TOKEN).unwrap()),
            ..Default::default()
        };
        assert_ser_tokens(
            &response,
            &[
                Token::Map { len: Some(1) },
                // 0x02: pinAuvAuthToken
                Token::U64(0x02),
                Token::Some,
                Token::BorrowedBytes(PIN_TOKEN),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn pin_v1_subcommand() {
        // NB: This does *not* work without serde_repr, as the
        // discriminant of a numerical enum does not have to coincide
        // with its assigned value.
        // E.g., for PinV1Subcommand, the first entry is set to
        // value 1, but its discriminant (which our normal serialization
        // to CBOR would output) is 0.
        // The following test would then fail, as [1] != [2]
        let mut buf = [0u8; 64];
        let example = PinV1Subcommand::GetKeyAgreement;
        let ser = crate::serde::cbor_serialize(&example, &mut buf).unwrap();
        assert_eq!(ser, &[0x02]);
    }
}

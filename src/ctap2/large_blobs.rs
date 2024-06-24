use crate::sizes::LARGE_BLOB_MAX_FRAGMENT_LENGTH;
use crate::Bytes;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

// See: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW
#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Request<'a> {
    // 0x01
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get: Option<u32>,
    // 0x02
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set: Option<&'a serde_bytes::Bytes>,
    // 0x03
    pub offset: u32,
    // 0x04
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    // 0x05
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_param: Option<&'a serde_bytes::Bytes>,
    // 0x06
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_protocol: Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Response {
    // 0x01
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<Bytes<LARGE_BLOB_MAX_FRAGMENT_LENGTH>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_test::{assert_de_tokens, assert_ser_tokens, Token};

    const FRAGMENT: &[u8] = &[0xaf; 255];
    const PIN_AUTH: &[u8] = &[0xad; 32];

    #[test]
    fn test_de_request_get() {
        let request = Request {
            get: Some(255),
            set: None,
            offset: 0,
            length: None,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        assert_de_tokens(
            &request,
            &[
                Token::Map { len: Some(2) },
                // 0x01: get
                Token::U64(0x01),
                Token::U32(255),
                // 0x03: offset
                Token::U64(0x03),
                Token::U32(0),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_de_request_set() {
        let request = Request {
            get: None,
            set: Some(serde_bytes::Bytes::new(FRAGMENT)),
            offset: 0,
            length: Some(255),
            pin_uv_auth_param: Some(serde_bytes::Bytes::new(PIN_AUTH)),
            pin_uv_auth_protocol: Some(1),
        };
        assert_de_tokens(
            &request,
            &[
                Token::Map { len: Some(5) },
                // 0x02: set
                Token::U64(0x02),
                Token::BorrowedBytes(FRAGMENT),
                // 0x03: offset
                Token::U64(0x03),
                Token::U32(0),
                // 0x04: length
                Token::U64(0x04),
                Token::U32(255),
                // 0x05: pinUvAuthParam
                Token::U64(0x05),
                Token::BorrowedBytes(PIN_AUTH),
                // 0x06: pinUvAuthProtocol
                Token::U64(0x06),
                Token::U32(1),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_ser_response() {
        let response = Response {
            config: Some(Bytes::from_slice(&[]).unwrap()),
            ..Default::default()
        };
        assert_ser_tokens(
            &response,
            &[
                Token::Map { len: Some(1) },
                // 0x01: config
                Token::U64(0x01),
                Token::Some,
                Token::BorrowedBytes(&[]),
                Token::MapEnd,
            ],
        );
    }
}

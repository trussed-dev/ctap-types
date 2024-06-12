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

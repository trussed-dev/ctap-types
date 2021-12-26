use crate::sizes::LARGE_BLOB_MAX_FRAGMENT_LENGTH;
use crate::Bytes;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

use super::PinAuth;

// See: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW
#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Request {
    // 0x01
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get: Option<u32>,
    // 0x02
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set: Option<Bytes<LARGE_BLOB_MAX_FRAGMENT_LENGTH>>,
    // 0x03
    pub offset: u32,
    // 0x04
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    // 0x05
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_param: Option<PinAuth>,
    // 0x06
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_protocol: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Response {
    // 0x01
    pub config: Bytes<LARGE_BLOB_MAX_FRAGMENT_LENGTH>,
}

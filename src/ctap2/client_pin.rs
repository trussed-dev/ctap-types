use crate::Bytes;
use bitflags::bitflags;
use cosey::EcdhEsHkdf256PublicKey;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Clone, Debug, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
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
    _placeholder07: Option<()>,

    // 0x08
    #[serde(skip_serializing_if = "Option::is_none")]
    _placeholder08: Option<()>,

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
        let example = super::PinV1Subcommand::GetKeyAgreement;
        let ser = crate::serde::cbor_serialize(&example, &mut buf).unwrap();
        assert_eq!(ser, &[0x02]);
    }
}

//! `authenticatorConfig` (CTAP 2.1 §6.11), command `0x0D`.
//!
//! Carries `setMinPINLength`, `toggleAlwaysUv`, and (CTAP 2.3) `enableLongTouchForReset`
//! sub-commands, plus the spec-required `enableEnterpriseAttestation` and
//! `vendorPrototype` placeholders.

use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
#[repr(u8)]
pub enum Subcommand {
    EnableEnterpriseAttestation = 0x01,
    ToggleAlwaysUv = 0x02,
    SetMinPINLength = 0x03,
    VendorPrototype = 0xff,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct SubcommandParameters<'a> {
    // 0x01
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_min_pin_length: Option<u8>,
    // 0x02
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length_rp_ids: Option<Vec<&'a str, 4>>,
    // 0x03
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_change_pin: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Request<'a> {
    // 0x01
    pub sub_command: Subcommand,
    // 0x02
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_command_params: Option<SubcommandParameters<'a>>,
    // 0x03
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_protocol: Option<u8>,
    // 0x04
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth: Option<&'a serde_bytes::Bytes>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_test::{assert_de_tokens, assert_ser_tokens, assert_tokens, Token};

    #[test]
    fn test_serde_subcommand() {
        for (sub, byte) in [
            (Subcommand::EnableEnterpriseAttestation, 0x01),
            (Subcommand::ToggleAlwaysUv, 0x02),
            (Subcommand::SetMinPINLength, 0x03),
            (Subcommand::VendorPrototype, 0xff),
        ] {
            assert_tokens(&sub, &[Token::U8(byte)]);
        }
    }

    #[test]
    fn test_de_request_toggle_always_uv() {
        // A bare ToggleAlwaysUv request has no params and (typically) no pinAuth.
        let req = Request {
            sub_command: Subcommand::ToggleAlwaysUv,
            sub_command_params: None,
            pin_protocol: None,
            pin_auth: None,
        };
        assert_de_tokens(
            &req,
            &[
                Token::Map { len: Some(1) },
                Token::U64(1),
                Token::U8(0x02),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_de_request_set_min_pin_length() {
        let mut rp_ids = Vec::new();
        rp_ids.push("login.example.com").unwrap();
        let req = Request {
            sub_command: Subcommand::SetMinPINLength,
            sub_command_params: Some(SubcommandParameters {
                new_min_pin_length: Some(6),
                min_pin_length_rp_ids: Some(rp_ids),
                force_change_pin: Some(true),
            }),
            pin_protocol: Some(2),
            pin_auth: None,
        };
        // Deserialization side: serde_indexed reads each present key directly,
        // without `Token::Some` wrappers (presence of the key encodes Some).
        assert_de_tokens(
            &req,
            &[
                Token::Map { len: Some(3) },
                Token::U64(1),
                Token::U8(0x03),
                Token::U64(2),
                Token::Map { len: Some(3) },
                Token::U64(1),
                Token::U8(6),
                Token::U64(2),
                Token::Seq { len: Some(1) },
                Token::BorrowedStr("login.example.com"),
                Token::SeqEnd,
                Token::U64(3),
                Token::Bool(true),
                Token::MapEnd,
                Token::U64(3),
                Token::U8(2),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_ser_request_set_min_pin_length() {
        let mut rp_ids = Vec::new();
        rp_ids.push("login.example.com").unwrap();
        let req = Request {
            sub_command: Subcommand::SetMinPINLength,
            sub_command_params: Some(SubcommandParameters {
                new_min_pin_length: Some(6),
                min_pin_length_rp_ids: Some(rp_ids),
                force_change_pin: Some(true),
            }),
            pin_protocol: Some(2),
            pin_auth: None,
        };
        // Serialization side: `Some` is emitted for each present optional.
        assert_ser_tokens(
            &req,
            &[
                Token::Map { len: Some(3) },
                Token::U64(1),
                Token::U8(0x03),
                Token::U64(2),
                Token::Some,
                Token::Map { len: Some(3) },
                Token::U64(1),
                Token::Some,
                Token::U8(6),
                Token::U64(2),
                Token::Some,
                Token::Seq { len: Some(1) },
                Token::BorrowedStr("login.example.com"),
                Token::SeqEnd,
                Token::U64(3),
                Token::Some,
                Token::Bool(true),
                Token::MapEnd,
                Token::U64(3),
                Token::Some,
                Token::U8(2),
                Token::MapEnd,
            ],
        );
    }
}

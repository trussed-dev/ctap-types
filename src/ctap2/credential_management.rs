use serde_indexed::{DeserializeIndexed, SerializeIndexed};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    cose::PublicKey,
    webauthn::{
        PublicKeyCredentialDescriptor, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    },
    Bytes,
};

type Bytes16 = Bytes<16>;
type Bytes32 = Bytes<32>;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
// #[derive(Clone,Debug,Eq,PartialEq,Serialize, Deserialize)]
// #[serde(tag = "credProtect")]
#[repr(u8)]
pub enum CredentialProtectionPolicy {
    // #[serde(rename = "userVerificationOptional")]
    #[default]
    Optional = 1,
    // #[serde(rename = "userVerificationOptionalWithCredentialIDList")] // <-- len = 44
    OptionalWithCredentialIdList = 2,
    // #[serde(rename = "userVerificationRequired")]
    Required = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Subcommand {
    GetCredsMetadata = 0x01,                      // 1, 2
    EnumerateRpsBegin = 0x02,                     // 3, 4, 5
    EnumerateRpsGetNextRp = 0x03,                 //  3, 4
    EnumerateCredentialsBegin = 0x04,             // 6, 7, 8 ,9, A
    EnumerateCredentialsGetNextCredential = 0x05, // 6, 7, 8, A
    DeleteCredential = 0x06,                      // -
    UpdateUserInformation = 0x07,
}

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct SubcommandParameters {
    // 0x01
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id_hash: Option<Bytes32>,
    // 0x02
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<PublicKeyCredentialDescriptor>,
    // 0x03
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<PublicKeyCredentialUserEntity>,
}

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Request {
    // 0x01
    pub sub_command: Subcommand,
    // 0x02
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_command_params: Option<SubcommandParameters>,
    // 0x03
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_protocol: Option<u8>,
    // 0x04
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth: Option<Bytes16>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, SerializeIndexed)]
#[serde_indexed(offset = 1)]
// #[derive(Clone,Debug, Default,Eq,PartialEq,Serialize,Deserialize)]
pub struct Response {
    // Metadata

    // 0x01
    #[serde(skip_serializing_if = "Option::is_none")]
    pub existing_resident_credentials_count: Option<u32>,
    // 0x02
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_possible_remaining_residential_credentials_count: Option<u32>,

    // EnumerateRps

    // 0x03
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp: Option<PublicKeyCredentialRpEntity>,
    // 0x04
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id_hash: Option<Bytes32>,
    // 0x05
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_rps: Option<u32>,

    // EnumerateCredentials given RP

    // 0x06
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<PublicKeyCredentialUserEntity>,
    // 0x07
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<PublicKeyCredentialDescriptor>,
    // 0x08
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
    // pub public_key: Option<Bytes<COSE_KEY_LENGTH>>,  // <-- AAAAHH. no Bytes, just COSE_Key
    // 0x09
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_credentials: Option<u32>,
    // 0x0A
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<CredentialProtectionPolicy>,
    // 0x0B
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<Bytes<32>>,
}

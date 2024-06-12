use crate::{Bytes, String, Vec};

use serde::{Deserialize, Serialize};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

use super::AuthenticatorOptions;
use crate::ctap2::credential_management::CredentialProtectionPolicy;
use crate::sizes::*;
use crate::webauthn::*;

impl TryFrom<u8> for CredentialProtectionPolicy {
    type Error = super::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => CredentialProtectionPolicy::Optional,
            2 => CredentialProtectionPolicy::OptionalWithCredentialIdList,
            3 => CredentialProtectionPolicy::Required,
            _ => return Err(Self::Error::InvalidParameter),
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Extensions {
    #[serde(rename = "credProtect")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<u8>,
    #[serde(rename = "hmac-secret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<bool>,
    // See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-largeBlobKey-extension
    #[serde(rename = "largeBlobKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Request<'a> {
    pub client_data_hash: &'a serde_bytes::Bytes,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub pub_key_cred_params: FilteredPublicKeyCredentialParameters,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_list: Option<Vec<PublicKeyCredentialDescriptorRef<'a>, 16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<AuthenticatorOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth: Option<&'a serde_bytes::Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_protocol: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_attestation: Option<u32>,
}

pub type AttestationObject = Response;

pub type AuthenticatorData = super::AuthenticatorData<AttestedCredentialData, Extensions>;

// NOTE: This is not CBOR, it has a custom encoding...
// https://www.w3.org/TR/webauthn/#sec-attested-credential-data
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestedCredentialData {
    pub aaguid: Bytes<16>,
    // this is where "unlimited non-resident keys" get stored
    // TODO: Model as actual credential ID, with ser/de to bytes (format is up to authenticator)
    pub credential_id: Bytes<MAX_CREDENTIAL_ID_LENGTH>,
    pub credential_public_key: Bytes<COSE_KEY_LENGTH>,
}

impl super::SerializeAttestedCredentialData for AttestedCredentialData {
    fn serialize(&self) -> Bytes<ATTESTED_CREDENTIAL_DATA_LENGTH> {
        let mut bytes = Vec::<u8, ATTESTED_CREDENTIAL_DATA_LENGTH>::new();
        // 16 bytes, the aaguid
        bytes.extend_from_slice(&self.aaguid).unwrap();

        // byte length of credential ID as 16-bit unsigned big-endian integer.
        bytes
            .extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes())
            .unwrap();
        // raw bytes of credential ID
        bytes
            .extend_from_slice(&self.credential_id[..self.credential_id.len()])
            .unwrap();

        // use existing `bytes` buffer
        // let mut cbor_key = [0u8; 128];

        // CHANGE this back if credential_public_key is not serialized again
        // let l = crate::serde::cbor_serialize(&self.credential_public_key, &mut cbor_key).unwrap();
        // bytes.extend_from_slice(&cbor_key[..l]).unwrap();
        bytes
            .extend_from_slice(&self.credential_public_key)
            .unwrap();

        Bytes::from(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Response {
    pub fmt: String<32>,
    pub auth_data: super::SerializedAuthenticatorData,
    pub att_stmt: AttestationStatement,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ep_att: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<Bytes<32>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum AttestationStatement {
    None(NoneAttestationStatement),
    Packed(PackedAttestationStatement),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum AttestationStatementFormat {
    None,
    Packed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NoneAttestationStatement {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PackedAttestationStatement {
    pub alg: i32,
    pub sig: Bytes<ASN1_SIGNATURE_LENGTH>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<Bytes<1024>, 1>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rp_entity_icon() {
        // icon has been removed but must still be parsed
        let cbor = b"\xa4\x01X \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\x02\xa2bidx0make_credential_relying_party_entity.example.comdiconohttp://icon.png\x03\xa2bidX \x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1ddnamedAdam\x04\x81\xa2calg&dtypejpublic-key";
        let _request: Request = cbor_smol::cbor_deserialize(cbor.as_slice()).unwrap();

        // previously, we called it `url` and should still be able to deserialize it
        let cbor = b"\xa4\x01X \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\x02\xa2bidx0make_credential_relying_party_entity.example.comcurlohttp://icon.png\x03\xa2bidX \x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1ddnamedAdam\x04\x81\xa2calg&dtypejpublic-key";
        let _request: Request = cbor_smol::cbor_deserialize(cbor.as_slice()).unwrap();
    }
}

use crate::{Bytes, String, Vec};

use serde::{Deserialize, Serialize};
use serde_bytes::ByteArray;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

use super::{AuthenticatorOptions, Error};
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
#[non_exhaustive]
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

pub type AuthenticatorData<'a> =
    super::AuthenticatorData<'a, AttestedCredentialData<'a>, Extensions>;

// NOTE: This is not CBOR, it has a custom encoding...
// https://www.w3.org/TR/webauthn/#sec-attested-credential-data
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestedCredentialData<'a> {
    pub aaguid: &'a [u8],
    // this is where "unlimited non-resident keys" get stored
    // TODO: Model as actual credential ID, with ser/de to bytes (format is up to authenticator)
    pub credential_id: &'a [u8],
    pub credential_public_key: &'a [u8],
}

impl<'a> super::SerializeAttestedCredentialData for AttestedCredentialData<'a> {
    fn serialize(&self, buffer: &mut super::SerializedAuthenticatorData) -> Result<(), Error> {
        // TODO: validate lengths of credential ID and credential public key
        // 16 bytes, the aaguid
        buffer
            .extend_from_slice(self.aaguid)
            .map_err(|_| Error::Other)?;
        // byte length of credential ID as 16-bit unsigned big-endian integer.
        let credential_id_len =
            u16::try_from(self.credential_id.len()).map_err(|_| Error::Other)?;
        buffer
            .extend_from_slice(&credential_id_len.to_be_bytes())
            .map_err(|_| Error::Other)?;
        // raw bytes of credential ID
        buffer
            .extend_from_slice(self.credential_id)
            .map_err(|_| Error::Other)?;
        buffer
            .extend_from_slice(self.credential_public_key)
            .map_err(|_| Error::Other)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Response {
    pub fmt: String<32>,
    pub auth_data: super::SerializedAuthenticatorData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub att_stmt: Option<AttestationStatement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ep_att: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<ByteArray<32>>,
}

#[derive(Debug)]
pub struct ResponseBuilder {
    pub fmt: String<32>,
    pub auth_data: super::SerializedAuthenticatorData,
}

impl ResponseBuilder {
    #[inline(always)]
    pub fn build(self) -> Response {
        Response {
            fmt: self.fmt,
            auth_data: self.auth_data,
            att_stmt: None,
            ep_att: None,
            large_blob_key: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum AttestationStatement {
    None(NoneAttestationStatement),
    Packed(PackedAttestationStatement),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
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

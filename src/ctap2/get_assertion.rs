use crate::{Bytes, Vec};
use cosey::EcdhEsHkdf256PublicKey;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteArray;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

use super::{AuthenticatorOptions, Result};
use crate::sizes::*;
use crate::webauthn::*;

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct HmacSecretInput {
    pub key_agreement: EcdhEsHkdf256PublicKey,
    // *either* enc(salt1) *or* enc(salt1 || salt2)
    pub salt_enc: Bytes<80>,
    pub salt_auth: Bytes<32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_protocol: Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExtensionsInput {
    #[serde(rename = "hmac-secret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<HmacSecretInput>,
    /// Whether a large blob key is requested.
    #[serde(rename = "largeBlobKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<bool>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExtensionsOutput {
    #[serde(rename = "hmac-secret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    // *either* enc(output1) *or* enc(output1 || output2)
    pub hmac_secret: Option<Bytes<80>>,
}

pub struct NoAttestedCredentialData;

impl super::SerializeAttestedCredentialData for NoAttestedCredentialData {
    fn serialize(&self, _buffer: &mut super::SerializedAuthenticatorData) -> Result<()> {
        Ok(())
    }
}

pub type AuthenticatorData<'a> =
    super::AuthenticatorData<'a, NoAttestedCredentialData, ExtensionsOutput>;

pub type AllowList<'a> = Vec<PublicKeyCredentialDescriptorRef<'a>, MAX_CREDENTIAL_COUNT_IN_LIST>;

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Request<'a> {
    pub rp_id: &'a str,
    pub client_data_hash: &'a serde_bytes::Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_list: Option<AllowList<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ExtensionsInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<AuthenticatorOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_auth: Option<&'a serde_bytes::Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_protocol: Option<u32>,
}

// NB: attn object definition / order at end of
// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
// does not coincide with what python-fido2 expects in AttestationObject.__init__ *at all* :'-)
#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Response {
    pub credential: PublicKeyCredentialDescriptor,
    pub auth_data: Bytes<AUTHENTICATOR_DATA_LENGTH>,
    pub signature: Bytes<ASN1_SIGNATURE_LENGTH>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<PublicKeyCredentialUserEntity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_credentials: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_selected: Option<bool>,
    /// A key that can be used to encrypt and decrypt large blob data.
    /// See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-getAssert-authnr-alg
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<ByteArray<32>>,
}

#[derive(Debug)]
pub struct ResponseBuilder {
    pub credential: PublicKeyCredentialDescriptor,
    pub auth_data: Bytes<AUTHENTICATOR_DATA_LENGTH>,
    pub signature: Bytes<ASN1_SIGNATURE_LENGTH>,
}

impl ResponseBuilder {
    #[inline(always)]
    pub fn build(self) -> Response {
        Response {
            credential: self.credential,
            auth_data: self.auth_data,
            signature: self.signature,
            user: None,
            number_of_credentials: None,
            user_selected: None,
            large_blob_key: None,
        }
    }
}

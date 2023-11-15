use crate::{Bytes, String, Vec};
use serde::{Deserialize, Serialize};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

use super::AuthenticatorOptions;
use crate::cose::EcdhEsHkdf256PublicKey;
use crate::sizes::*;
use crate::webauthn::*;

// #[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
// pub struct AuthenticatorExtensions {
//     #[serde(rename = "hmac-secret")]
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub hmac_secret: Option<bool>,
// }

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct HmacSecretInput {
    pub key_agreement: EcdhEsHkdf256PublicKey,
    // *either* enc(salt1) *or* enc(salt1 || salt2)
    pub salt_enc: Bytes<64>,
    pub salt_auth: Bytes<16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_protocol: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtensionsInput {
    #[serde(rename = "hmac-secret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<HmacSecretInput>,
    /// Whether a large blob key is requested.
    #[serde(rename = "largeBlobKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ExtensionsOutput {
    #[serde(rename = "hmac-secret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    // *either* enc(output1) *or* enc(output1 || output2)
    pub hmac_secret: Option<Bytes<64>>,
}

pub struct NoAttestedCredentialData(core::marker::PhantomData<()>);

impl super::SerializeAttestedCredentialData for NoAttestedCredentialData {
    fn serialize(&self) -> Bytes<ATTESTED_CREDENTIAL_DATA_LENGTH> {
        Bytes::new()
    }
}

pub type AuthenticatorData = super::AuthenticatorData<NoAttestedCredentialData, ExtensionsOutput>;

pub type AllowList<'a> = Vec<PublicKeyCredentialDescriptorRef<'a>, MAX_CREDENTIAL_COUNT_IN_LIST>;

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
// #[serde(rename_all = "camelCase")]
#[serde_indexed(offset = 1)]
pub struct Request<'a> {
    pub rp_id: String<64>,
    pub client_data_hash: Bytes<32>,
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
#[serde_indexed(offset = 1)]
pub struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<PublicKeyCredentialDescriptor>,
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
    pub large_blob_key: Option<Bytes<32>>,
}

pub type Responses = Vec<Response, 8>;

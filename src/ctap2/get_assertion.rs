use crate::{Bytes, String, Vec};
use cosey::EcdhEsHkdf256PublicKey;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteArray;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

use super::{AttestationFormatsPreference, AttestationStatement, AuthenticatorOptions, Result};
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
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
pub struct ExtensionsInput {
    /// `credBlob` (CTAP 2.1 §11.1) retrieval flag. `Some(true)` asks the
    /// authenticator to return the blob stored at MakeCredential time.
    #[serde(rename = "credBlob")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<bool>,

    #[serde(rename = "hmac-secret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<HmacSecretInput>,

    /// Whether a large blob key is requested.
    #[serde(rename = "largeBlobKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<bool>,

    #[cfg(feature = "third-party-payment")]
    #[serde(rename = "thirdPartyPayment")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_payment: Option<bool>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExtensionsOutput {
    /// `credBlob` retrieval result: the bytes stored at MakeCredential time, up
    /// to `maxCredBlobLength` (≥ 32). Absent if the platform did not request
    /// `credBlob` or if no blob is associated with the credential.
    #[serde(rename = "credBlob")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<Bytes<MAX_CRED_BLOB_LENGTH>>,

    #[serde(rename = "hmac-secret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    // *either* enc(output1) *or* enc(output1 || output2)
    pub hmac_secret: Option<Bytes<80>>,

    #[cfg(feature = "third-party-payment")]
    #[serde(rename = "thirdPartyPayment")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_payment: Option<bool>,
}

impl ExtensionsOutput {
    #[inline]
    pub fn is_set(&self) -> bool {
        let Self {
            cred_blob,
            hmac_secret,
            #[cfg(feature = "third-party-payment")]
            third_party_payment,
        } = self;
        if hmac_secret.is_some() {
            return true;
        }
        if cred_blob.is_some() {
            return true;
        }
        #[cfg(feature = "third-party-payment")]
        if third_party_payment.is_some() {
            return true;
        }
        false
    }
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

#[derive(Clone, Debug, Eq, PartialEq, DeserializeIndexed)]
#[cfg_attr(feature = "test-client", derive(SerializeIndexed))]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise_attestation: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_formats_preference: Option<AttestationFormatsPreference>,
}

// NB: attn object definition / order at end of
// https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential
// does not coincide with what python-fido2 expects in AttestationObject.__init__ *at all* :'-)
#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed)]
#[cfg_attr(feature = "test-client", derive(DeserializeIndexed))]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Response {
    pub credential: PublicKeyCredentialDescriptor,
    pub auth_data: Bytes<AUTHENTICATOR_DATA_LENGTH>,
    pub signature: Bytes<MAX_PACKED_SIG_LENGTH>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_extension_outputs: Option<UnsignedExtensionOutputs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ep_att: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub att_stmt: Option<AttestationStatement>,
}

#[derive(Debug)]
pub struct ResponseBuilder {
    pub credential: PublicKeyCredentialDescriptor,
    pub auth_data: Bytes<AUTHENTICATOR_DATA_LENGTH>,
    pub signature: Bytes<MAX_PACKED_SIG_LENGTH>,
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
            unsigned_extension_outputs: None,
            ep_att: None,
            att_stmt: None,
        }
    }
}

impl Response {
    /// Empty `Response` with default fields. Used by `Authenticator::call_ctap2`
    /// to preallocate the `Response::GetAssertion` variant slot so the inner
    /// `get_assertion` impl can write via `&mut` — same shape as
    /// `make_credential::Response::empty()`.
    pub fn empty() -> Self {
        ResponseBuilder {
            credential: PublicKeyCredentialDescriptor {
                id: Bytes::new(),
                key_type: String::new(),
            },
            auth_data: Bytes::new(),
            signature: Bytes::new(),
        }
        .build()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct UnsignedExtensionOutputs {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extensions_input_canonical() {
        let input = ExtensionsInput {
            hmac_secret: Some(HmacSecretInput {
                key_agreement: EcdhEsHkdf256PublicKey {
                    x: [0xff; 32].try_into().unwrap(),
                    y: [0xff; 32].try_into().unwrap(),
                },
                salt_enc: [0xff; 80].try_into().unwrap(),
                salt_auth: [0xff; 32].try_into().unwrap(),
                pin_protocol: Some(1),
            }),
            large_blob_key: Some(true),
            cred_blob: Some(true),
            #[cfg(feature = "third-party-payment")]
            third_party_payment: Some(true),
        };
        crate::test::assert_canonical_cbor(&input);
    }

    #[test]
    fn test_extensions_output_canonical() {
        let output = ExtensionsOutput {
            hmac_secret: Some([0xff; 80].try_into().unwrap()),
            cred_blob: Some([0xff; 32].try_into().unwrap()),
            #[cfg(feature = "third-party-payment")]
            third_party_payment: Some(true),
        };
        crate::test::assert_canonical_cbor(&output);
    }

    #[test]
    fn test_unsigned_extension_outputs_canonical() {
        let outputs = UnsignedExtensionOutputs {};
        crate::test::assert_canonical_cbor(&outputs);
    }
}

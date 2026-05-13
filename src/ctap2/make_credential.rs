use crate::Vec;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteArray;
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

use super::{
    AttestationFormatsPreference, AttestationStatement, AttestationStatementFormat,
    AuthenticatorOptions, Error,
};
use crate::ctap2::credential_management::CredentialProtectionPolicy;
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

/// Extensions input to `authenticatorMakeCredential`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
// `Arbitrary` impl lives in `crate::arbitrary` because `&'a serde_bytes::Bytes`
// (cred_blob) doesn't satisfy `Arbitrary<'_>` and the derive macro can't
// special-case it. Same pattern as `make_credential::Request<'a>`.
pub struct ExtensionsInput<'a> {
    /// `credBlob` (CTAP 2.1 §11.1): platform-supplied bytes to associate with
    /// the credential. Up to `maxCredBlobLength` (≥ 32) bytes per credential.
    #[serde(rename = "credBlob")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    pub cred_blob: Option<&'a serde_bytes::Bytes>,

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

    /// `hmac-secret-mc` (CTAP 2.2 §11.4.5 / WebAuthn L3): platform-supplied
    /// hmac-secret request evaluated at MakeCredential time, returning
    /// hmac-secret outputs alongside the freshly-minted credential.
    #[serde(rename = "hmac-secret-mc")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret_mc: Option<super::get_assertion::HmacSecretInput>,

    #[cfg(feature = "third-party-payment")]
    #[serde(rename = "thirdPartyPayment")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_payment: Option<bool>,
}

/// Extensions output emitted in `authenticatorData.extensions` after
/// `authenticatorMakeCredential`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExtensionsOutput {
    /// `credBlob` storage acknowledgement: `Some(true)` if the platform-supplied
    /// blob was stored, `Some(false)` if not stored, absent if the platform did
    /// not request the extension.
    #[serde(rename = "credBlob")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_blob: Option<bool>,

    #[serde(rename = "credProtect")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_protect: Option<u8>,

    #[serde(rename = "hmac-secret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret: Option<bool>,

    /// `hmac-secret-mc` (CTAP 2.2): encrypted hmac-secret outputs produced at
    /// MakeCredential time. Wire format mirrors GetAssertion's `hmac-secret`
    /// output — `enc(output1)` or `enc(output1 || output2)`, up to 80 bytes.
    #[serde(rename = "hmac-secret-mc")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac_secret_mc: Option<crate::Bytes<80>>,

    #[cfg(feature = "third-party-payment")]
    #[serde(rename = "thirdPartyPayment")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_payment: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, DeserializeIndexed)]
#[cfg_attr(feature = "platform-serde", derive(SerializeIndexed))]
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
    pub extensions: Option<ExtensionsInput<'a>>,
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

pub type AttestationObject = Response;

pub type AuthenticatorData<'a> =
    super::AuthenticatorData<'a, AttestedCredentialData<'a>, ExtensionsOutput>;

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

impl super::SerializeAttestedCredentialData for AttestedCredentialData<'_> {
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
#[cfg_attr(feature = "platform-serde", derive(DeserializeIndexed))]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Response {
    pub fmt: AttestationStatementFormat,
    pub auth_data: super::SerializedAuthenticatorData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub att_stmt: Option<AttestationStatement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ep_att: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blob_key: Option<ByteArray<32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_extension_outputs: Option<UnsignedExtensionOutputs>,
}

#[derive(Debug)]
pub struct ResponseBuilder {
    pub fmt: AttestationStatementFormat,
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
            unsigned_extension_outputs: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "platform-serde", derive(Deserialize))]
#[non_exhaustive]
pub struct UnsignedExtensionOutputs {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap2::get_assertion::HmacSecretInput;
    use cosey::EcdhEsHkdf256PublicKey;
    use serde_test::{assert_ser_tokens, Token};

    #[test]
    fn rp_entity_icon() {
        // icon has been removed but must still be parsed
        let cbor = b"\xa4\x01X \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\x02\xa2bidx0make_credential_relying_party_entity.example.comdiconohttp://icon.png\x03\xa2bidX \x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1ddnamedAdam\x04\x81\xa2calg&dtypejpublic-key";
        let _request: Request = cbor_smol::cbor_deserialize(cbor.as_slice()).unwrap();

        // previously, we called it `url` and should still be able to deserialize it
        let cbor = b"\xa4\x01X \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\x02\xa2bidx0make_credential_relying_party_entity.example.comcurlohttp://icon.png\x03\xa2bidX \x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1d\x1ddnamedAdam\x04\x81\xa2calg&dtypejpublic-key";
        let _request: Request = cbor_smol::cbor_deserialize(cbor.as_slice()).unwrap();
    }

    #[test]
    fn test_serde_attestation_statement_format() {
        let formats = [
            (AttestationStatementFormat::None, "none"),
            (AttestationStatementFormat::Packed, "packed"),
        ];
        for (format, s) in formats {
            assert_ser_tokens(&format, &[Token::BorrowedStr(s)]);
        }
    }

    #[test]
    fn test_extensions_input_canonical() {
        let extensions = ExtensionsInput {
            cred_protect: Some(1),
            hmac_secret: Some(true),
            large_blob_key: Some(true),
            #[cfg(feature = "third-party-payment")]
            third_party_payment: Some(true),
            cred_blob: Some(serde_bytes::Bytes::new(b"1234")),
            hmac_secret_mc: Some(HmacSecretInput {
                key_agreement: EcdhEsHkdf256PublicKey {
                    x: [0xff; 32].try_into().unwrap(),
                    y: [0xff; 32].try_into().unwrap(),
                },
                salt_enc: [0xff; 80].try_into().unwrap(),
                salt_auth: [0xff; 32].try_into().unwrap(),
                pin_protocol: Some(1),
            }),
        };
        crate::test::assert_canonical_cbor(&extensions);
    }

    #[test]
    fn test_extensions_output_canonical() {
        let extensions = ExtensionsOutput {
            cred_protect: Some(1),
            hmac_secret: Some(true),
            #[cfg(feature = "third-party-payment")]
            third_party_payment: Some(true),
            cred_blob: Some(true),
            hmac_secret_mc: Some([0xff; 80].try_into().unwrap()),
        };
        crate::test::assert_canonical_cbor(&extensions);
    }

    #[test]
    fn test_unsigned_extension_outputs_canonical() {
        let outputs = UnsignedExtensionOutputs {};
        crate::test::assert_canonical_cbor(&outputs);
    }
}

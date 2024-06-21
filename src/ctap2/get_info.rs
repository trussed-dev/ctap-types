use crate::webauthn::FilteredPublicKeyCredentialParameters;
use crate::{Bytes, TryFromStrError, Vec};
use serde::{Deserialize, Serialize};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

pub type AuthenticatorInfo = Response;

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Response {
    // 0x01
    pub versions: Vec<Version, 4>,

    // 0x02
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<Extension, 4>>,

    // 0x03
    pub aaguid: Bytes<16>,

    // 0x04
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<CtapOptions>,

    // 0x05
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_msg_size: Option<usize>,

    // 0x06
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_protocols: Option<Vec<u8, 2>>,

    // 0x07
    // FIDO_2_1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_creds_in_list: Option<usize>,

    // 0x08
    // FIDO_2_1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cred_id_length: Option<usize>,

    // 0x09
    // FIDO_2_1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<Transport, 4>>,

    // 0x0A
    // FIDO_2_1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<FilteredPublicKeyCredentialParameters>,

    // 0x0B
    // FIDO_2_1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_serialized_large_blob_array: Option<usize>,

    // 0x0C
    // FIDO_2_1
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_pin_change: Option<bool>,

    // 0x0D
    // FIDO_2_1
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_pin_length: Option<usize>,

    // 0x0E
    // FIDO_2_1
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware_version: Option<usize>,

    // 0x0F
    // FIDO_2_1
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cred_blob_length: Option<usize>,

    // 0x10
    // FIDO_2_1
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_rpids_for_set_min_pin_length: Option<usize>,

    // 0x11
    // FIDO_2_1
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_platform_uv_attempts: Option<usize>,

    // 0x12
    // FIDO_2_1
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_modality: Option<usize>,

    // 0x13
    // FIDO_2_1
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certifications: Option<Certifications>,

    // 0x14
    // FIDO_2_1
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_discoverable_credentials: Option<usize>,

    // 0x15
    // FIDO_2_1
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_prototype_config_commands: Option<usize>,

    // 0x16
    // FIDO_2_2
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_formats: Option<Vec<super::make_credential::AttestationStatementFormat, 2>>,

    // 0x17
    // FIDO_2_2
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_count_since_last_pin_entry: Option<usize>,

    // 0x18
    // FIDO_2_2
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long_touch_for_reset: Option<bool>,
}

impl Default for Response {
    fn default() -> Self {
        let mut zero_aaguid = Vec::<u8, 16>::new();
        zero_aaguid.resize_default(16).unwrap();
        let aaguid = Bytes::<16>::from(zero_aaguid);

        let mut response = ResponseBuilder {
            aaguid,
            versions: Vec::new(),
        }
        .build();
        response.options = Some(CtapOptions::default());
        response
    }
}

#[derive(Debug)]
pub struct ResponseBuilder {
    pub versions: Vec<Version, 4>,
    pub aaguid: Bytes<16>,
}

impl ResponseBuilder {
    #[inline(always)]
    pub fn build(self) -> Response {
        Response {
            versions: self.versions,
            aaguid: self.aaguid,
            extensions: None,
            options: None,
            max_msg_size: None,
            pin_protocols: None,
            max_creds_in_list: None,
            max_cred_id_length: None,
            transports: None,
            algorithms: None,
            max_serialized_large_blob_array: None,
            #[cfg(feature = "get-info-full")]
            force_pin_change: None,
            #[cfg(feature = "get-info-full")]
            min_pin_length: None,
            #[cfg(feature = "get-info-full")]
            firmware_version: None,
            #[cfg(feature = "get-info-full")]
            max_cred_blob_length: None,
            #[cfg(feature = "get-info-full")]
            max_rpids_for_set_min_pin_length: None,
            #[cfg(feature = "get-info-full")]
            preferred_platform_uv_attempts: None,
            #[cfg(feature = "get-info-full")]
            uv_modality: None,
            #[cfg(feature = "get-info-full")]
            certifications: None,
            #[cfg(feature = "get-info-full")]
            remaining_discoverable_credentials: None,
            #[cfg(feature = "get-info-full")]
            vendor_prototype_config_commands: None,
            #[cfg(feature = "get-info-full")]
            attestation_formats: None,
            #[cfg(feature = "get-info-full")]
            uv_count_since_last_pin_entry: None,
            #[cfg(feature = "get-info-full")]
            long_touch_for_reset: None,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(into = "&str", try_from = "&str")]
pub enum Version {
    Fido2_0,
    Fido2_1,
    Fido2_1Pre,
    U2fV2,
}

impl Version {
    const FIDO_2_0: &'static str = "FIDO_2_0";
    const FIDO_2_1: &'static str = "FIDO_2_1";
    const FIDO_2_1_PRE: &'static str = "FIDO_2_1_PRE";
    const U2F_V2: &'static str = "U2F_V2";
}

impl From<Version> for &str {
    fn from(version: Version) -> Self {
        match version {
            Version::Fido2_0 => Version::FIDO_2_0,
            Version::Fido2_1 => Version::FIDO_2_1,
            Version::Fido2_1Pre => Version::FIDO_2_1_PRE,
            Version::U2fV2 => Version::U2F_V2,
        }
    }
}

impl TryFrom<&str> for Version {
    type Error = TryFromStrError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            Self::FIDO_2_0 => Ok(Self::Fido2_0),
            Self::FIDO_2_1 => Ok(Self::Fido2_1),
            Self::FIDO_2_1_PRE => Ok(Self::Fido2_1Pre),
            Self::U2F_V2 => Ok(Self::U2fV2),
            _ => Err(TryFromStrError),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(into = "&str", try_from = "&str")]
pub enum Extension {
    CredProtect,
    HmacSecret,
    LargeBlobKey,
    ThirdPartyPayment,
}

impl Extension {
    const CRED_PROTECT: &'static str = "credProtect";
    const HMAC_SECRET: &'static str = "hmac-secret";
    const LARGE_BLOB_KEY: &'static str = "largeBlobKey";
    const THIRD_PARTY_PAYMENT: &'static str = "thirdPartyPayment";
}

impl From<Extension> for &str {
    fn from(extension: Extension) -> Self {
        match extension {
            Extension::CredProtect => Extension::CRED_PROTECT,
            Extension::HmacSecret => Extension::HMAC_SECRET,
            Extension::LargeBlobKey => Extension::LARGE_BLOB_KEY,
            Extension::ThirdPartyPayment => Extension::THIRD_PARTY_PAYMENT,
        }
    }
}

impl TryFrom<&str> for Extension {
    type Error = TryFromStrError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            Self::CRED_PROTECT => Ok(Self::CredProtect),
            Self::HMAC_SECRET => Ok(Self::HmacSecret),
            Self::LARGE_BLOB_KEY => Ok(Self::LargeBlobKey),
            Self::THIRD_PARTY_PAYMENT => Ok(Self::ThirdPartyPayment),
            _ => Err(TryFromStrError),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(into = "&str", try_from = "&str")]
pub enum Transport {
    Nfc,
    Usb,
}

impl Transport {
    const NFC: &'static str = "nfc";
    const USB: &'static str = "usb";
}

impl From<Transport> for &str {
    fn from(transport: Transport) -> Self {
        match transport {
            Transport::Nfc => Transport::NFC,
            Transport::Usb => Transport::USB,
        }
    }
}

impl TryFrom<&str> for Transport {
    type Error = TryFromStrError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            Self::NFC => Ok(Self::Nfc),
            Self::USB => Ok(Self::Usb),
            _ => Err(TryFromStrError),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct CtapOptions {
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ep: Option<bool>, // default false
    pub rk: bool,
    pub up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Note: This capability means capability to perform UV
    /// *within the authenticator*, for instance with biometrics
    /// or on-device PIN entry.
    pub uv: Option<bool>, // default not capable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plat: Option<bool>, // default false
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_acfg: Option<bool>, // default false
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub always_uv: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_mgmt: Option<bool>,
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authnr_cfg: Option<bool>,
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio_enroll: Option<bool>, // default false
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_pin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blobs: Option<bool>,
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_bio_enroll: Option<bool>,
    #[cfg(feature = "get-info-full")]
    #[serde(rename = "setMinPINLength", skip_serializing_if = "Option::is_none")]
    pub set_min_pin_length: Option<bool>, // default false
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_token: Option<bool>,
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub make_cred_uv_not_rqd: Option<bool>,
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_mgmt_preview: Option<bool>,
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification_mgmt_preview: Option<bool>,
    #[cfg(feature = "get-info-full")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_mc_ga_permissions_with_client_pin: Option<bool>,
}

impl Default for CtapOptions {
    fn default() -> Self {
        Self {
            #[cfg(feature = "get-info-full")]
            ep: None,
            rk: false,
            up: true,
            uv: None,
            plat: None,
            #[cfg(feature = "get-info-full")]
            uv_acfg: None,
            #[cfg(feature = "get-info-full")]
            always_uv: None,
            cred_mgmt: None,
            #[cfg(feature = "get-info-full")]
            authnr_cfg: None,
            #[cfg(feature = "get-info-full")]
            bio_enroll: None,
            client_pin: None,
            large_blobs: None,
            #[cfg(feature = "get-info-full")]
            uv_bio_enroll: None,
            pin_uv_auth_token: None,
            #[cfg(feature = "get-info-full")]
            set_min_pin_length: None,
            #[cfg(feature = "get-info-full")]
            make_cred_uv_not_rqd: None,
            #[cfg(feature = "get-info-full")]
            credential_mgmt_preview: None,
            #[cfg(feature = "get-info-full")]
            user_verification_mgmt_preview: None,
            #[cfg(feature = "get-info-full")]
            no_mc_ga_permissions_with_client_pin: None,
        }
    }
}

#[cfg(feature = "get-info-full")]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Certifications {
    #[serde(rename = "FIPS-CMVP-2")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fips_cmpv2: Option<u8>,

    #[serde(rename = "FIPS-CMVP-3")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fips_cmpv3: Option<u8>,

    #[serde(rename = "FIPS-CMVP-2-PHY")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fips_cmpv2_phy: Option<u8>,

    #[serde(rename = "FIPS-CMVP-3-PHY")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fips_cmpv3_phy: Option<u8>,

    #[serde(rename = "CC-EAL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc_eal: Option<u8>,

    #[serde(rename = "FIDO")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fido: Option<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_test::{assert_ser_tokens, assert_tokens, Token};

    #[test]
    fn test_serde_version() {
        let versions = [
            (Version::Fido2_0, "FIDO_2_0"),
            (Version::Fido2_1, "FIDO_2_1"),
            (Version::Fido2_1Pre, "FIDO_2_1_PRE"),
            (Version::U2fV2, "U2F_V2"),
        ];
        for (version, s) in versions {
            assert_tokens(&version, &[Token::BorrowedStr(s)]);
        }
    }

    #[test]
    fn test_serde_extension() {
        let extensions = [
            (Extension::CredProtect, "credProtect"),
            (Extension::HmacSecret, "hmac-secret"),
            (Extension::LargeBlobKey, "largeBlobKey"),
        ];
        for (extension, s) in extensions {
            assert_tokens(&extension, &[Token::BorrowedStr(s)]);
        }
    }

    #[test]
    fn test_serde_transport() {
        let transports = [(Transport::Nfc, "nfc"), (Transport::Usb, "usb")];
        for (transport, s) in transports {
            assert_tokens(&transport, &[Token::BorrowedStr(s)]);
        }
    }

    #[test]
    fn test_serde_get_info_minimal() {
        let versions = Vec::from_slice(&[Version::Fido2_0, Version::Fido2_1]).unwrap();
        let aaguid = Bytes::from_slice(&[0xff; 16]).unwrap();
        let response = ResponseBuilder { versions, aaguid }.build();
        assert_tokens(
            &response,
            &[
                Token::Map { len: Some(2) },
                Token::U64(1),
                Token::Seq { len: Some(2) },
                Token::BorrowedStr("FIDO_2_0"),
                Token::BorrowedStr("FIDO_2_1"),
                Token::SeqEnd,
                Token::U64(3),
                Token::BorrowedBytes(&[0xff; 16]),
                Token::MapEnd,
            ],
        );
    }

    #[test]
    fn test_serde_get_info_default() {
        // This corresponds to the response sent by the Nitrokey 3, see for example:
        // https://github.com/Nitrokey/nitrokey-3-firmware/blob/0d7209f1f75354878c0cf3454055defe8372ed14/utils/fido2-mds/metadata/v4/metadata-nk3xn-v4.json
        const AAGUID: &[u8] = &[
            236, 153, 219, 25, 205, 31, 76, 6, 162, 169, 148, 15, 23, 166, 163, 11,
        ];
        let versions =
            Vec::from_slice(&[Version::U2fV2, Version::Fido2_0, Version::Fido2_1]).unwrap();
        let aaguid = Bytes::from_slice(AAGUID).unwrap();
        let mut options = CtapOptions::default();
        options.rk = true;
        options.plat = Some(false);
        options.client_pin = Some(false);
        options.cred_mgmt = Some(true);
        options.large_blobs = Some(false);
        options.pin_uv_auth_token = Some(true);
        let mut response = ResponseBuilder { versions, aaguid }.build();
        response.extensions =
            Some(Vec::from_slice(&[Extension::CredProtect, Extension::HmacSecret]).unwrap());
        response.options = Some(options);
        response.max_msg_size = Some(3072);
        response.pin_protocols = Some(Vec::from_slice(&[1, 0]).unwrap());
        response.max_creds_in_list = Some(10);
        response.max_cred_id_length = Some(255);
        response.transports = Some(Vec::from_slice(&[Transport::Nfc, Transport::Usb]).unwrap());
        assert_ser_tokens(
            &response,
            &[
                Token::Map { len: Some(9) },
                // 0x01: versions
                Token::U64(0x01),
                Token::Seq { len: Some(3) },
                Token::BorrowedStr("U2F_V2"),
                Token::BorrowedStr("FIDO_2_0"),
                Token::BorrowedStr("FIDO_2_1"),
                Token::SeqEnd,
                // 0x02: extensions
                Token::U64(0x02),
                Token::Some,
                Token::Seq { len: Some(2) },
                Token::BorrowedStr("credProtect"),
                Token::BorrowedStr("hmac-secret"),
                Token::SeqEnd,
                // 0x03: aaguid
                Token::U64(0x03),
                Token::BorrowedBytes(AAGUID),
                // 0x04: options
                Token::U64(0x04),
                Token::Some,
                Token::Struct {
                    name: "CtapOptions",
                    len: 7,
                },
                Token::BorrowedStr("rk"),
                Token::Bool(true),
                Token::BorrowedStr("up"),
                Token::Bool(true),
                Token::BorrowedStr("plat"),
                Token::Some,
                Token::Bool(false),
                Token::BorrowedStr("credMgmt"),
                Token::Some,
                Token::Bool(true),
                Token::BorrowedStr("clientPin"),
                Token::Some,
                Token::Bool(false),
                Token::BorrowedStr("largeBlobs"),
                Token::Some,
                Token::Bool(false),
                Token::BorrowedStr("pinUvAuthToken"),
                Token::Some,
                Token::Bool(true),
                Token::StructEnd,
                // 0x05: maxMsgSize
                Token::U64(0x05),
                Token::Some,
                Token::U64(3072),
                // 0x06: pinUvAuthProtocols
                Token::U64(0x06),
                Token::Some,
                Token::Seq { len: Some(2) },
                Token::U8(1),
                Token::U8(0),
                Token::SeqEnd,
                // 0x07: maxCredentialCountInList
                Token::U64(0x07),
                Token::Some,
                Token::U64(10),
                // 0x08: maxCredentialIdLength
                Token::U64(0x08),
                Token::Some,
                Token::U64(255),
                // 0x09: transports
                Token::U64(0x09),
                Token::Some,
                Token::Seq { len: Some(2) },
                Token::BorrowedStr("nfc"),
                Token::BorrowedStr("usb"),
                Token::SeqEnd,
                Token::MapEnd,
            ],
        );
    }
}

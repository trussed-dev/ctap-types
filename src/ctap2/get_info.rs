use crate::webauthn::FilteredPublicKeyCredentialParameters;
use crate::{Bytes, String, Vec};
use serde::{Deserialize, Serialize};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

pub type AuthenticatorInfo = Response;

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[non_exhaustive]
#[serde_indexed(offset = 1)]
pub struct Response {
    // 0x01
    pub versions: Vec<String<12>, 4>,

    // 0x02
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String<13>, 4>>,

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
    pub transports: Option<Vec<String<8>, 4>>,

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
    pub versions: Vec<String<12>, 4>,
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

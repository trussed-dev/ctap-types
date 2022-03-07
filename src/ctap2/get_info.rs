use crate::webauthn::PublicKeyCredentialParameters;
use crate::{Bytes, String, Vec};
use serde::{Deserialize, Serialize};
use serde_indexed::{DeserializeIndexed, SerializeIndexed};

pub type AuthenticatorInfo = Response;

#[derive(Clone, Debug, Eq, PartialEq, SerializeIndexed, DeserializeIndexed)]
#[serde_indexed(offset = 1)]
pub struct Response {
    // 0x01
    pub versions: Vec<String<12>, 4>,

    // 0x02
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String<11>, 4>>,

    // 0x03
    // #[serde(with = "serde_bytes")]
    // #[serde(serialize_with = "serde_bytes::serialize", deserialize_with = "serde_bytes::deserialize")]
    // #[serde(serialize_with = "serde_bytes::serialize")]
    // pub(crate) aaguid: Vec<u8, 16>,
    pub aaguid: Bytes<16>,

    // 0x04
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<CtapOptions>,

    // 0x05
    // TODO: this is actually the constant MESSAGE_SIZE
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_msg_size: Option<usize>,

    // 0x06
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_protocols: Option<Vec<u8, 1>>,

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

    // 0xA0
    // FIDO_2_1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<PublicKeyCredentialParameters, 4>>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub(crate) algorithms: Option<&'l[u8]>,
}

impl Default for Response {
    fn default() -> Self {
        let mut zero_aaguid = Vec::<u8, 16>::new();
        zero_aaguid.resize_default(16).unwrap();
        let aaguid = Bytes::<16>::from(zero_aaguid);

        Self {
            versions: Vec::new(),
            extensions: None,
            aaguid,
            options: Some(CtapOptions::default()),
            max_msg_size: None, //Some(MESSAGE_SIZE),
            pin_protocols: None,
            max_creds_in_list: None,
            max_cred_id_length: None,
            transports: None,
            algorithms: None,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CtapOptions {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_acfg: Option<bool>, // default false
    #[serde(skip_serializing_if = "Option::is_none")]
    pub always_uv: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cred_mgmt: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authnr_cfg: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio_enroll: Option<bool>, // default false
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_pin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub large_blobs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv_bio_enroll: Option<bool>,
    #[serde(rename = "setMinPINLength", skip_serializing_if = "Option::is_none")]
    pub set_min_pin_length: Option<bool>, // default false
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_uv_auth_token: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub make_cred_uv_not_rqd: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_mgmt_preview: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification_mgmt_preview: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_mc_ga_permissions_with_client_pin: Option<bool>,
}

impl Default for CtapOptions {
    fn default() -> Self {
        Self {
            ep: None,
            rk: false,
            up: true,
            uv: None,
            plat: None,
            uv_acfg: None,
            always_uv: None,
            cred_mgmt: None,
            authnr_cfg: None,
            bio_enroll: None,
            client_pin: None,
            large_blobs: None,
            uv_bio_enroll: None,
            pin_uv_auth_token: None,
            set_min_pin_length: None,
            make_cred_uv_not_rqd: None,
            credential_mgmt_preview: None,
            user_verification_mgmt_preview: None,
            no_mc_ga_permissions_with_client_pin: None,
        }
    }
}

//! Types for CTAP2.
//!
//! Note that all ctap2::Authenticators automatically implement RPC with [`Request`] and
//! [`Response`].
use bitflags::bitflags;
use cbor_smol::cbor_deserialize;
use serde::{Deserialize, Serialize};

use crate::{sizes::*, Bytes, Vec};

pub use crate::operation::{Operation, VendorOperation};

pub mod client_pin;
pub mod credential_management;
pub mod get_assertion;
pub mod get_info;
pub mod large_blobs;
pub mod make_credential;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
// clippy says...large size difference
/// Enum of all CTAP2 requests.
pub enum Request {
    // 0x1
    MakeCredential(make_credential::Request),
    // 0x2
    GetAssertion(get_assertion::Request),
    // 0x8
    GetNextAssertion,
    // 0x4
    GetInfo,
    // 0x6
    ClientPin(client_pin::Request),
    // 0x7
    Reset,
    // 0xA
    CredentialManagement(credential_management::Request),
    // 0xC
    LargeBlobs(large_blobs::Request),
    // vendor, to be embellished
    // Q: how to handle the associated CBOR structures
    Vendor(crate::operation::VendorOperation),
}

pub enum CtapMappingError {
    InvalidCommand(u8),
    ParsingError(cbor_smol::Error),
}

impl From<CtapMappingError> for Error {
    fn from(mapping_error: CtapMappingError) -> Error {
        match mapping_error {
            CtapMappingError::InvalidCommand(_cmd) => Error::InvalidCommand,
            CtapMappingError::ParsingError(cbor_error) => match cbor_error {
                cbor_smol::Error::SerdeMissingField => Error::MissingParameter,
                _ => Error::InvalidCbor,
            },
        }
    }
}

impl Request {
    /// Deserialize from CBOR where the first byte denotes the operation.
    #[inline(never)]
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(
                CtapMappingError::ParsingError(cbor_smol::Error::DeserializeUnexpectedEnd).into(),
            );
        }

        let (&op, data) = data.split_first().ok_or(CtapMappingError::ParsingError(
            cbor_smol::Error::DeserializeUnexpectedEnd,
        ))?;

        let operation = Operation::try_from(op).map_err(|_| {
            debug_now!("invalid operation {}", op);
            CtapMappingError::InvalidCommand(op)
        })?;

        info!("deser {:?}", operation);
        Ok(match operation {
            Operation::MakeCredential => Request::MakeCredential(
                cbor_deserialize(data).map_err(CtapMappingError::ParsingError)?,
            ),

            Operation::GetAssertion => Request::GetAssertion(
                cbor_deserialize(data).map_err(CtapMappingError::ParsingError)?,
            ),

            Operation::GetNextAssertion => Request::GetNextAssertion,

            Operation::CredentialManagement | Operation::PreviewCredentialManagement => {
                Request::CredentialManagement(
                    cbor_deserialize(data).map_err(CtapMappingError::ParsingError)?,
                )
            }

            Operation::Reset => Request::Reset,

            Operation::GetInfo => Request::GetInfo,

            Operation::ClientPin => {
                Request::ClientPin(cbor_deserialize(data).map_err(CtapMappingError::ParsingError)?)
            }

            // NB: FIDO Alliance "stole" 0x40 and 0x41, so these are not available
            Operation::Vendor(vendor_operation) => Request::Vendor(vendor_operation),

            Operation::BioEnrollment
            | Operation::PreviewBioEnrollment
            | Operation::Config
            | Operation::LargeBlobs
            | Operation::Selection => {
                debug_now!("unhandled CBOR operation {:?}", operation);
                return Err(CtapMappingError::InvalidCommand(op).into());
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
/// Enum of all CTAP2 responses.
#[allow(clippy::large_enum_variant)]
pub enum Response {
    MakeCredential(make_credential::Response),
    GetAssertion(get_assertion::Response),
    GetNextAssertion(get_assertion::Response),
    GetInfo(get_info::Response),
    ClientPin(client_pin::Response),
    Reset,
    CredentialManagement(credential_management::Response),
    LargeBlobs(large_blobs::Response),
    // Q: how to handle the associated CBOR structures
    Vendor,
}

impl Response {
    #[inline(never)]
    pub fn serialize<const N: usize>(&self, buffer: &mut Vec<u8, N>) {
        buffer.resize_default(buffer.capacity()).ok();
        let (status, data) = buffer.split_first_mut().unwrap();
        use cbor_smol::cbor_serialize;
        use Response::*;
        let outcome = match self {
            GetInfo(response) => cbor_serialize(response, data),
            MakeCredential(response) => cbor_serialize(response, data),
            ClientPin(response) => cbor_serialize(response, data),
            GetAssertion(response) | GetNextAssertion(response) => cbor_serialize(response, data),
            CredentialManagement(response) => cbor_serialize(response, data),
            LargeBlobs(response) => cbor_serialize(response, data),
            Reset | Vendor => Ok([].as_slice()),
        };
        if let Ok(slice) = outcome {
            *status = 0;
            let l = slice.len();
            buffer.resize_default(l + 1).ok();
        } else {
            *status = Error::Other as u8;
            buffer.resize_default(1).ok();
        }
    }
}

// TODO: this is a bit weird to model...
// Need to be able to "skip unknown keys" in deserialization
//
// I think we want to model this is a "set of enums",
// and allow skipping unknown enum entries during deserialization
//
// NB: This depends on the command
//
// We need two things:
// - skip unknown fields
// #[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
// pub struct AuthenticatorExtensions {
//     // #[serde(skip_serializing_if = "Option::is_none")]
//     // pub cred_protect:
// }

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthenticatorOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rk: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Note: This flag asks to perform UV *within the authenticator*,
    /// for instance with biometrics or on-device PIN entry,
    /// use of pinAuth is implicit where required.
    pub uv: Option<bool>,
}

// #[derive(Clone,Debug,Eq,PartialEq,SerializeIndexed,DeserializeIndexed)]
// // #[serde(rename_all = "camelCase")]
// #[serde_indexed(offset = 1)]
// pub struct GetAssertionParameters {
//     pub rp_id: String<64>,
//     pub client_data_hash: Bytes<32>,
//     pub allow_list: Vec<PublicKeyCredentialDescriptor, 8>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub extensions: Option<AuthenticatorExtensions>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub options: Option<AuthenticatorOptions>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub pin_auth: Option<Bytes<16>>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub pin_protocol: Option<u32>,
// }

//// This is some pretty weird stuff ^^
//// Example serialization:
//// { 1: 2,  // kty (key type): tstr / int  [ 2 = EC2 = elliptic curve with x and y coordinate pair
////                                           1 = OKP = Octet Key Pair = for EdDSA
////          // kid, bstr
////   3: -7, // alg: tstr / int
//// [ 4:     // key_ops: tstr / int           1 = sign, 2 = verify, 3 = encrypt, 4 = decrypt, ...many more
////
////  // the curve: 1  = P-256
////  -1: 1,
////  // x-coordinate
////  -2: b'\xa0\xc3\x14\x06!\xefM\xcc\x06u\xf0\xf5v\x0bXa\xe6\xacm\x8d\xd9O`\xbd\x81\xf1\xe0_\x1a*\xdd\x9e',
////  // y-coordinate
////  -3: b'\xb4\xd4L\x94-\xbeVr\xe9C\x13u V\xf4t^\xe4.\xa2\x87I\xfe \xa4\xb0KY\x03\x00\x8c\x01'}
////
////  EdDSA
////   1: 1
////   3: -8,
////  -1: 6,
////  -2: public key bytes
//#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
//#[serde(rename_all = "camelCase")]
//pub struct CredentialPublicKey {
//}

pub type PinAuth = Bytes<16>;

// #[derive(Clone,Debug,Eq,PartialEq)]
// // #[serde(rename_all = "camelCase")]
// pub struct AuthenticatorData {
//     pub rp_id_hash: Bytes<32>,
//     pub flags: u8,
//     pub sign_count: u32,
//     // this can get pretty long
//     pub attested_credential_data: Option<Bytes<ATTESTED_CREDENTIAL_DATA_LENGTH>>,
//     // pub extensions: ?
// }

// impl AuthenticatorData {
//     pub fn serialize(&self) -> Bytes<AUTHENTICATOR_DATA_LENGTH> {
//         let mut bytes = Vec::<u8, AUTHENTICATOR_DATA_LENGTH>::new();

//         // 32 bytes, the RP id's hash
//         bytes.extend_from_slice(&self.rp_id_hash).unwrap();
//         // flags
//         bytes.push(self.flags).unwrap();
//         // signature counts as 32-bit unsigned big-endian integer.
//         bytes.extend_from_slice(&self.sign_count.to_be_bytes()).unwrap();
//         match &self.attested_credential_data {
//             Some(ref attested_credential_data) => {
//                 // finally the attested credential data
//                 bytes.extend_from_slice(&attested_credential_data).unwrap();
//             },
//             None => {},
//         }

//         Bytes::from(bytes)
//     }
// }

bitflags! {
    pub struct AuthenticatorDataFlags: u8 {
        const EMPTY = 0;
        const USER_PRESENCE = 1 << 0;
        const USER_VERIFIED = 1 << 2;
        const ATTESTED_CREDENTIAL_DATA = 1 << 6;
        const EXTENSION_DATA = 1 << 7;
    }
}

pub trait SerializeAttestedCredentialData {
    fn serialize(&self) -> Bytes<ATTESTED_CREDENTIAL_DATA_LENGTH>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
// #[serde(rename_all = "camelCase")]
pub struct AuthenticatorData<A, E> {
    pub rp_id_hash: Bytes<32>,
    pub flags: AuthenticatorDataFlags,
    pub sign_count: u32,
    // this can get pretty long
    // pub attested_credential_data: Option<Bytes<ATTESTED_CREDENTIAL_DATA_LENGTH>>,
    pub attested_credential_data: Option<A>,
    pub extensions: Option<E>,
}

pub type SerializedAuthenticatorData = Bytes<AUTHENTICATOR_DATA_LENGTH>;

// The reason for this non-use of CBOR is for compatibility with
// FIDO U2F authentication signatures.
impl<A: SerializeAttestedCredentialData, E: serde::Serialize> AuthenticatorData<A, E> {
    #[inline(never)]
    pub fn serialize(&self) -> SerializedAuthenticatorData {
        // let mut bytes = Vec::<u8, AUTHENTICATOR_DATA_LENGTH>::new();
        let mut bytes = SerializedAuthenticatorData::new();

        // 32 bytes, the RP id's hash
        bytes.extend_from_slice(&self.rp_id_hash).unwrap();
        // flags
        bytes.push(self.flags.bits()).unwrap();
        // signature counts as 32-bit unsigned big-endian integer.
        bytes
            .extend_from_slice(&self.sign_count.to_be_bytes())
            .unwrap();

        // the attested credential data
        if let Some(ref attested_credential_data) = &self.attested_credential_data {
            bytes
                .extend_from_slice(&attested_credential_data.serialize())
                .unwrap();
        }

        // the extensions data
        if let Some(extensions) = self.extensions.as_ref() {
            let mut extensions_buf = [0u8; 128];
            let ser = crate::serde::cbor_serialize(extensions, &mut extensions_buf).unwrap();
            bytes.extend_from_slice(ser).unwrap();
        }

        bytes
    }
}

// // TODO: add Default and builder
// #[derive(Clone,Debug,Eq,PartialEq,Serialize)]
// pub struct AuthenticatorInfo<'l> {
//     pub(crate) versions: &'l[&'l str],
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) extensions: Option<&'l[&'l str]>,
//     // #[serde(serialize_with = "serde_bytes::serialize")]
//     pub(crate) aaguid: &'l [u8],//; 16],
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) options: Option<CtapOptions>,
//     // TODO: this is actually the constant MESSAGE_SIZE
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) max_msg_size: Option<usize>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) pin_protocols: Option<&'l[u8]>,

//     // not in the CTAP spec, but see https://git.io/JeNxG
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) max_creds_in_list: Option<usize>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) max_cred_id_length: Option<usize>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) transports: Option<&'l[u8]>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) algorithms: Option<&'l[u8]>,
// }

// pub enum Algorithm {
//     ES256,
//     EdDSA,
// }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Success = 0x00,
    InvalidCommand = 0x01,
    InvalidParameter = 0x02,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    LockRequired = 0x0A,
    InvalidChannel = 0x0B,
    CborUnexpectedType = 0x11,
    InvalidCbor = 0x12,
    MissingParameter = 0x14,
    LimitExceeded = 0x15,
    UnsupportedExtension = 0x16,
    FingerprintDatabaseFull = 0x17,
    LargeBlobStorageFull = 0x18,
    CredentialExcluded = 0x19,
    Processing = 0x21,
    InvalidCredential = 0x22,
    UserActionPending = 0x23,
    OperationPending = 0x24,
    NoOperations = 0x25,
    UnsupportedAlgorithm = 0x26,
    OperationDenied = 0x27,
    KeyStoreFull = 0x28,
    NotBusy = 0x29,
    NoOperationPending = 0x2A,
    UnsupportedOption = 0x2B,
    InvalidOption = 0x2C,
    KeepaliveCancel = 0x2D,
    NoCredentials = 0x2E,
    UserActionTimeout = 0x2F,
    NotAllowed = 0x30,
    PinInvalid = 0x31,
    PinBlocked = 0x32,
    PinAuthInvalid = 0x33,
    PinAuthBlocked = 0x34,
    PinNotSet = 0x35,
    PinRequired = 0x36,
    PinPolicyViolation = 0x37,
    PinTokenExpired = 0x38,
    RequestTooLarge = 0x39,
    ActionTimeout = 0x3A,
    UpRequired = 0x3B,
    UvBlocked = 0x3C,
    IntegrityFailure = 0x3D,
    InvalidSubcommand = 0x3E,
    UvInvalid = 0x3F,
    UnauthorizedPermission = 0x40,
    Other = 0x7F,
    SpecLast = 0xDF,
    ExtensionFirst = 0xE0,
    ExtensionLast = 0xEF,
    VendorFirst = 0xF0,
    VendorLast = 0xFF,
}

/// CTAP2 authenticator API
///
/// Note that all Authenticators automatically implement [`crate::Rpc`] with [`Request`] and
/// [`Response`].
pub trait Authenticator {
    fn get_info(&mut self) -> get_info::Response;
    fn make_credential(
        &mut self,
        request: &make_credential::Request,
    ) -> Result<make_credential::Response>;
    fn get_assertion(
        &mut self,
        request: &get_assertion::Request,
    ) -> Result<get_assertion::Response>;
    fn get_next_assertion(&mut self) -> Result<get_assertion::Response>;
    fn reset(&mut self) -> Result<()>;
    fn client_pin(&mut self, request: &client_pin::Request) -> Result<client_pin::Response>;
    fn credential_management(
        &mut self,
        request: &credential_management::Request,
    ) -> Result<credential_management::Response>;
    fn large_blobs(
        &mut self,
        request: &large_blobs::Request,
    ) -> Result<large_blobs::Response>;
    fn vendor(&mut self, op: VendorOperation) -> Result<()>;

    /// Dispatches the enum of possible requests into the appropriate trait method.
    #[inline(never)]
    fn call_ctap2(&mut self, request: &Request) -> Result<Response> {
        match request {
            // 0x4
            Request::GetInfo => {
                debug_now!("CTAP2.GI");
                Ok(Response::GetInfo(self.get_info()))
            }

            // 0x2
            Request::MakeCredential(request) => {
                debug_now!("CTAP2.MC");
                Ok(Response::MakeCredential(
                    self.make_credential(request).map_err(|e| {
                        debug!("error: {:?}", e);
                        e
                    })?,
                ))
            }

            // 0x1
            Request::GetAssertion(request) => {
                debug_now!("CTAP2.GA");
                Ok(Response::GetAssertion(
                    self.get_assertion(request).map_err(|e| {
                        debug!("error: {:?}", e);
                        e
                    })?,
                ))
            }

            // 0x8
            Request::GetNextAssertion => {
                debug_now!("CTAP2.GNA");
                Ok(Response::GetNextAssertion(
                    self.get_next_assertion().map_err(|e| {
                        debug!("error: {:?}", e);
                        e
                    })?,
                ))
            }

            // 0x7
            Request::Reset => {
                debug_now!("CTAP2.RST");
                self.reset().map_err(|e| {
                    debug!("error: {:?}", e);
                    e
                })?;
                Ok(Response::Reset)
            }

            // 0x6
            Request::ClientPin(request) => {
                debug_now!("CTAP2.PIN");
                Ok(Response::ClientPin(self.client_pin(request).map_err(
                    |e| {
                        debug!("error: {:?}", e);
                        e
                    },
                )?))
            }

            // 0xA
            Request::CredentialManagement(request) => {
                debug_now!("CTAP2.CM");
                Ok(Response::CredentialManagement(
                    self.credential_management(request).map_err(|e| {
                        debug!("error: {:?}", e);
                        e
                    })?,
                ))
            }

            // 0xC
            Request::LargeBlobs(request) => {
                debug_now!("CTAP2.LB");
                Ok(Response::LargeBlobs(
                    self.large_blobs(request).map_err(|e| {
                        debug!("error: {:?}", e);
                        e
                    })?,
                ))
            }

            // Not stable
            Request::Vendor(op) => {
                debug_now!("CTAP2.V");
                self.vendor(*op).map_err(|e| {
                    debug!("error: {:?}", e);
                    e
                })?;
                Ok(Response::Vendor)
            }
        }
    }
}

impl<A: Authenticator> crate::Rpc<Error, Request, Response> for A {
    /// Dispatches the enum of possible requests into the appropriate trait method.
    #[inline(never)]
    fn call(&mut self, request: &Request) -> Result<Response> {
        self.call_ctap2(request)
    }
}

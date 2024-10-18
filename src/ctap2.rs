//! Types for CTAP2.
//!
//! Note that all ctap2::Authenticators automatically implement RPC with [`Request`] and
//! [`Response`].
use bitflags::bitflags;
use cbor_smol::cbor_deserialize;
use serde::{Deserialize, Serialize};

use crate::{sizes::*, Bytes, TryFromStrError, Vec};

pub use crate::operation::{Operation, VendorOperation};

pub mod client_pin;
pub mod credential_management;
pub mod get_assertion;
pub mod get_info;
pub mod large_blobs;
pub mod make_credential;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
// clippy says...large size difference
/// Enum of all CTAP2 requests.
pub enum Request<'a> {
    // 0x1
    MakeCredential(make_credential::Request<'a>),
    // 0x2
    GetAssertion(get_assertion::Request<'a>),
    // 0x8
    GetNextAssertion,
    // 0x4
    GetInfo,
    // 0x6
    ClientPin(client_pin::Request<'a>),
    // 0x7
    Reset,
    // 0xA
    CredentialManagement(credential_management::Request<'a>),
    // 0xB
    Selection,
    // 0xC
    LargeBlobs(large_blobs::Request<'a>),
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

impl<'a> Request<'a> {
    /// Deserialize from CBOR where the first byte denotes the operation.
    #[inline(never)]
    pub fn deserialize(data: &'a [u8]) -> Result<Self> {
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

            Operation::Selection => Request::Selection,

            Operation::GetInfo => Request::GetInfo,

            Operation::ClientPin => {
                Request::ClientPin(cbor_deserialize(data).map_err(CtapMappingError::ParsingError)?)
            }

            Operation::LargeBlobs => {
                Request::LargeBlobs(cbor_deserialize(data).map_err(CtapMappingError::ParsingError)?)
            }

            // NB: FIDO Alliance "stole" 0x40 and 0x41, so these are not available
            Operation::Vendor(vendor_operation) => Request::Vendor(vendor_operation),

            Operation::BioEnrollment | Operation::PreviewBioEnrollment | Operation::Config => {
                debug_now!("unhandled CBOR operation {:?}", operation);
                return Err(CtapMappingError::InvalidCommand(op).into());
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
/// Enum of all CTAP2 responses.
#[allow(clippy::large_enum_variant)]
pub enum Response {
    MakeCredential(make_credential::Response),
    GetAssertion(get_assertion::Response),
    GetNextAssertion(get_assertion::Response),
    GetInfo(get_info::Response),
    ClientPin(client_pin::Response),
    Reset,
    Selection,
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
            Reset | Selection | Vendor => Ok([].as_slice()),
        };
        if let Ok(slice) = outcome {
            *status = 0;
            // Instead of an empty CBOR map (0xA0), we return an empty response
            if slice == [0xA0] {
                buffer.resize_default(1).ok();
            } else {
                let l = slice.len();
                buffer.resize_default(l + 1).ok();
            }
        } else {
            *status = Error::Other as u8;
            buffer.resize_default(1).ok();
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
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

bitflags! {
    pub struct AuthenticatorDataFlags: u8 {
        const USER_PRESENCE = 1 << 0;
        const USER_VERIFIED = 1 << 2;
        const ATTESTED_CREDENTIAL_DATA = 1 << 6;
        const EXTENSION_DATA = 1 << 7;
    }
}

pub trait SerializeAttestedCredentialData {
    fn serialize(&self, buffer: &mut SerializedAuthenticatorData) -> Result<()>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatorData<'a, A, E> {
    pub rp_id_hash: &'a [u8; 32],
    pub flags: AuthenticatorDataFlags,
    pub sign_count: u32,
    pub attested_credential_data: Option<A>,
    pub extensions: Option<E>,
}

pub type SerializedAuthenticatorData = Bytes<AUTHENTICATOR_DATA_LENGTH>;

// The reason for this non-use of CBOR is for compatibility with
// FIDO U2F authentication signatures.
impl<'a, A: SerializeAttestedCredentialData, E: serde::Serialize> AuthenticatorData<'a, A, E> {
    #[inline(never)]
    pub fn serialize(&self) -> Result<SerializedAuthenticatorData> {
        let mut bytes = SerializedAuthenticatorData::new();

        // 32 bytes, the RP id's hash
        bytes
            .extend_from_slice(self.rp_id_hash)
            .map_err(|_| Error::Other)?;
        // flags
        bytes.push(self.flags.bits()).map_err(|_| Error::Other)?;
        // signature counts as 32-bit unsigned big-endian integer.
        bytes
            .extend_from_slice(&self.sign_count.to_be_bytes())
            .map_err(|_| Error::Other)?;

        // the attested credential data
        if let Some(attested_credential_data) = &self.attested_credential_data {
            attested_credential_data.serialize(&mut bytes)?;
        }

        // the extensions data
        if let Some(extensions) = self.extensions.as_ref() {
            cbor_smol::cbor_serialize_extending_bytes(extensions, &mut bytes)
                .map_err(|_| Error::Other)?;
        }

        Ok(bytes)
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

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[non_exhaustive]
#[serde(into = "&str", try_from = "&str")]
pub enum AttestationStatementFormat {
    None,
    Packed,
}

impl AttestationStatementFormat {
    const NONE: &'static str = "none";
    const PACKED: &'static str = "packed";
}

impl From<AttestationStatementFormat> for &str {
    fn from(format: AttestationStatementFormat) -> Self {
        match format {
            AttestationStatementFormat::None => AttestationStatementFormat::NONE,
            AttestationStatementFormat::Packed => AttestationStatementFormat::PACKED,
        }
    }
}

impl TryFrom<&str> for AttestationStatementFormat {
    type Error = TryFromStrError;

    fn try_from(s: &str) -> core::result::Result<Self, Self::Error> {
        match s {
            Self::NONE => Ok(Self::None),
            Self::PACKED => Ok(Self::Packed),
            _ => Err(TryFromStrError),
        }
    }
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AttestationFormatsPreference {
    pub(crate) known_formats: Vec<AttestationStatementFormat, 2>,
    pub(crate) unknown: bool,
}

impl AttestationFormatsPreference {
    pub fn known_formats(&self) -> &[AttestationStatementFormat] {
        &self.known_formats
    }

    pub fn includes_unknown_formats(&self) -> bool {
        self.unknown
    }
}

impl<'de> Deserialize<'de> for AttestationFormatsPreference {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor;

        impl<'de> serde::de::Visitor<'de> for ValueVisitor {
            type Value = AttestationFormatsPreference;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut preference = AttestationFormatsPreference::default();
                while let Some(value) = seq.next_element::<&str>()? {
                    if let Ok(format) = AttestationStatementFormat::try_from(value) {
                        preference.known_formats.push(format).ok();
                    } else {
                        preference.unknown = true;
                    }
                }
                Ok(preference)
            }
        }

        deserializer.deserialize_seq(ValueVisitor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
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
    fn selection(&mut self) -> Result<()>;
    fn vendor(&mut self, op: VendorOperation) -> Result<()>;

    // Optional extensions
    fn large_blobs(&mut self, request: &large_blobs::Request) -> Result<large_blobs::Response> {
        let _ = request;
        Err(Error::InvalidCommand)
    }

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
                    self.make_credential(request).inspect_err(|_e| {
                        debug!("error: {:?}", _e);
                    })?,
                ))
            }

            // 0x1
            Request::GetAssertion(request) => {
                debug_now!("CTAP2.GA");
                Ok(Response::GetAssertion(
                    self.get_assertion(request).inspect_err(|_e| {
                        debug!("error: {:?}", _e);
                    })?,
                ))
            }

            // 0x8
            Request::GetNextAssertion => {
                debug_now!("CTAP2.GNA");
                Ok(Response::GetNextAssertion(
                    self.get_next_assertion().inspect_err(|_e| {
                        debug!("error: {:?}", _e);
                    })?,
                ))
            }

            // 0x7
            Request::Reset => {
                debug_now!("CTAP2.RST");
                self.reset().inspect_err(|_e| {
                    debug!("error: {:?}", _e);
                })?;
                Ok(Response::Reset)
            }

            // 0x6
            Request::ClientPin(request) => {
                debug_now!("CTAP2.PIN");
                Ok(Response::ClientPin(self.client_pin(request).inspect_err(
                    |_e| {
                        debug!("error: {:?}", _e);
                    },
                )?))
            }

            // 0xA
            Request::CredentialManagement(request) => {
                debug_now!("CTAP2.CM");
                Ok(Response::CredentialManagement(
                    self.credential_management(request).inspect_err(|_e| {
                        debug!("error: {:?}", _e);
                    })?,
                ))
            }

            // 0xB
            Request::Selection => {
                debug_now!("CTAP2.SEL");
                self.selection().inspect_err(|_e| {
                    debug!("error: {:?}", _e);
                })?;
                Ok(Response::Selection)
            }

            // 0xC
            Request::LargeBlobs(request) => {
                debug_now!("CTAP2.LB");
                Ok(Response::LargeBlobs(
                    self.large_blobs(request).inspect_err(|_e| {
                        debug!("error: {:?}", _e);
                    })?,
                ))
            }

            // Not stable
            Request::Vendor(op) => {
                debug_now!("CTAP2.V");
                self.vendor(*op).inspect_err(|_e| {
                    debug!("error: {:?}", _e);
                })?;
                Ok(Response::Vendor)
            }
        }
    }
}

impl<'a, A: Authenticator> crate::Rpc<Error, Request<'a>, Response> for A {
    /// Dispatches the enum of possible requests into the appropriate trait method.
    #[inline(never)]
    fn call(&mut self, request: &Request) -> Result<Response> {
        self.call_ctap2(request)
    }
}

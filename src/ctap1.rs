//! Types for CTAP1.
//!
//! Note that all ctap1::Authenticators automatically implement RPC with [`Request`] and
//! [`Response`].
use crate::Bytes;

pub const NO_ERROR: u16 = 0x9000;

/// Re-export of the iso7816::Status.
pub use iso7816::Status as Error;

pub mod authenticate {
    use super::{Bytes, ControlByte};

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Request<'a> {
        pub control_byte: ControlByte,
        pub challenge: &'a [u8; 32],
        pub app_id: &'a [u8; 32],
        pub key_handle: &'a [u8],
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Response {
        pub user_presence: u8,
        pub count: u32,
        pub signature: Bytes<72>,
    }
}

pub mod register {
    use super::Bytes;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Request<'a> {
        pub challenge: &'a [u8; 32],
        pub app_id: &'a [u8; 32],
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Response {
        pub header_byte: u8,
        pub public_key: Bytes<65>,
        pub key_handle: Bytes<255>,
        pub attestation_certificate: Bytes<1024>,
        pub signature: Bytes<72>,
    }

    impl Response {
        pub fn new(
            header_byte: u8,
            public_key: &cosey::EcdhEsHkdf256PublicKey,
            key_handle: Bytes<255>,
            signature: Bytes<72>,
            attestation_certificate: Bytes<1024>,
        ) -> Self {
            let mut public_key_bytes = Bytes::new();
            public_key_bytes.push(0x04).unwrap();
            public_key_bytes.extend_from_slice(&public_key.x).unwrap();
            public_key_bytes.extend_from_slice(&public_key.y).unwrap();

            Self {
                header_byte,
                public_key: public_key_bytes,
                key_handle,
                attestation_certificate,
                signature,
            }
        }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ControlByte {
    // Conor:
    // I think U2F check-only maps to FIDO2 MakeCredential with the credID in the excludeList,
    // and pinAuth="" so the request will fail before UP check.
    // I  think this is what the windows hello API does to silently check if a credential is
    // on an authenticator
    CheckOnly = 0x07,
    EnforceUserPresenceAndSign = 0x03,
    DontEnforceUserPresenceAndSign = 0x08,
}

impl TryFrom<u8> for ControlByte {
    type Error = Error;

    fn try_from(byte: u8) -> Result<ControlByte> {
        match byte {
            0x07 => Ok(ControlByte::CheckOnly),
            0x03 => Ok(ControlByte::EnforceUserPresenceAndSign),
            0x08 => Ok(ControlByte::DontEnforceUserPresenceAndSign),
            _ => Err(Error::IncorrectDataParameter),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

/// Type alias for convenience.
pub type Register<'a> = register::Request<'a>;
/// Type alias for convenience.
pub type Authenticate<'a> = authenticate::Request<'a>;

/// Type alias for convenience.
pub type RegisterResponse = register::Response;
/// Type alias for convenience.
pub type AuthenticateResponse = authenticate::Response;

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
/// Enum of all CTAP1 requests.
pub enum Request<'a> {
    Register(register::Request<'a>),
    Authenticate(authenticate::Request<'a>),
    Version,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
/// Enum of all CTAP1 responses.
pub enum Response {
    Register(register::Response),
    Authenticate(authenticate::Response),
    Version([u8; 6]),
}

impl Response {
    #[allow(clippy::result_unit_err)]
    #[inline(never)]
    pub fn serialize<const S: usize>(
        &self,
        buf: &mut iso7816::Data<S>,
    ) -> core::result::Result<(), ()> {
        match self {
            Response::Register(reg) => {
                buf.push(reg.header_byte).map_err(drop)?;
                buf.extend_from_slice(&reg.public_key)?;
                buf.push(reg.key_handle.len() as u8).map_err(drop)?;
                buf.extend_from_slice(&reg.key_handle)?;
                buf.extend_from_slice(&reg.attestation_certificate)?;
                buf.extend_from_slice(&reg.signature)
            }
            Response::Authenticate(auth) => {
                buf.push(auth.user_presence).map_err(drop)?;
                buf.extend_from_slice(&auth.count.to_be_bytes())?;
                buf.extend_from_slice(&auth.signature)
            }
            Response::Version(version) => buf.extend_from_slice(version),
        }
    }
}

impl<'a, const S: usize> TryFrom<&'a iso7816::Command<S>> for Request<'a> {
    type Error = Error;
    #[inline(never)]
    fn try_from(apdu: &'a iso7816::Command<S>) -> Result<Request> {
        let cla = apdu.class().into_inner();
        let ins = match apdu.instruction() {
            iso7816::Instruction::Unknown(ins) => ins,
            _ins => 0,
        };
        let p1 = apdu.p1;
        let _p2 = apdu.p2;

        if cla != 0 {
            return Err(Error::ClassNotSupported);
        }

        if ins == 0x3 {
            // for some weird historical reason, [0, 3, 0, 0, 0, 0, 0, 0, 0]
            // is valid to send here.
            return Ok(Request::Version);
        };

        let request = apdu.data();

        match ins {
            // register
            0x1 => {
                if request.len() != 64 {
                    return Err(Error::IncorrectDataParameter);
                }
                Ok(Request::Register(Register {
                    challenge: (&request[..32]).try_into().unwrap(),
                    app_id: (&request[32..]).try_into().unwrap(),
                }))
            }

            // authenticate
            0x2 => {
                let control_byte = ControlByte::try_from(p1)?;
                if request.len() < 65 {
                    return Err(Error::IncorrectDataParameter);
                }
                let key_handle_length = request[64] as usize;
                if request.len() != 65 + key_handle_length {
                    return Err(Error::IncorrectDataParameter);
                }
                Ok(Request::Authenticate(Authenticate {
                    control_byte,
                    challenge: (&request[..32]).try_into().unwrap(),
                    app_id: (&request[32..64]).try_into().unwrap(),
                    key_handle: &request[65..],
                }))
            }

            // version
            0x3 => Ok(Request::Version),

            _ => Err(Error::InstructionNotSupportedOrInvalid),
        }
    }
}

/// CTAP1 (U2F) authenticator API
///
/// Note that all Authenticators automatically implement RPC with [`Request`] and
/// [`Response`].
pub trait Authenticator {
    /// Register a U2F credential.
    fn register(&mut self, request: &register::Request<'_>) -> Result<register::Response>;
    /// Authenticate with a U2F credential.
    fn authenticate(
        &mut self,
        request: &authenticate::Request<'_>,
    ) -> Result<authenticate::Response>;
    /// Supported U2F version.
    fn version() -> [u8; 6] {
        *b"U2F_V2"
    }

    #[inline(never)]
    fn call_ctap1(&mut self, request: &Request<'_>) -> Result<Response> {
        match request {
            Request::Register(reg) => {
                debug_now!("CTAP1.REG");
                Ok(Response::Register(self.register(reg)?))
            }
            Request::Authenticate(auth) => {
                debug_now!("CTAP1.AUTH");
                Ok(Response::Authenticate(self.authenticate(auth)?))
            }
            Request::Version => Ok(Response::Version(Self::version())),
        }
    }
}

impl<A: Authenticator> crate::Rpc<Error, Request<'_>, Response> for A {
    /// Dispatches the enum of possible requests into the appropriate trait method.
    fn call(&mut self, request: &Request<'_>) -> Result<Response> {
        self.call_ctap1(request)
    }
}

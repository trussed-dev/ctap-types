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
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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

#[cfg(test)]
mod tests {
    use super::*;
    use heapless::Vec;
    use hex_literal::hex;
    use iso7816::command::{
        class::Class, instruction::Instruction, Command, CommandBuilder, ExpectedLen,
    };

    // examples taken from:
    // https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#examples

    fn command(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Command<1024> {
        let builder = CommandBuilder::new(
            Class::from_byte(0).unwrap(),
            Instruction::from(ins),
            p1,
            p2,
            data,
            ExpectedLen::Max,
        );
        let mut apdu = Vec::<_, 1024>::new();
        builder.serialize_into(&mut apdu).unwrap();
        Command::try_from(&apdu).unwrap()
    }

    #[test]
    fn test_register_request() {
        let mut input = [0; 64];
        // challenge
        input[..32].copy_from_slice(&hex!(
            "4142d21c00d94ffb9d504ada8f99b721f4b191ae4e37ca0140f696b6983cfacb"
        ));
        // application
        input[32..].copy_from_slice(&hex!(
            "f0e6a6a97042a4f1f1c87f5f7d44315b2d852c2df5c7991cc66241bf7072d1c4"
        ));

        let command = command(1, 0, 0, &input);
        let request = Request::try_from(&command).unwrap();
        let Request::Register(request) = request else {
            panic!("expected register request, got: {:?}", request);
        };
        assert_eq!(request.challenge, &input[..32]);
        assert_eq!(request.app_id, &input[32..]);
    }

    #[test]
    fn test_register_response() {
        let public_key = hex!("b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9");
        let public_key = cosey::EcdhEsHkdf256PublicKey {
            x: Bytes::from_slice(&public_key[..32]).unwrap(),
            y: Bytes::from_slice(&public_key[32..]).unwrap(),
        };
        let key_handle = hex!("2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c25");
        let key_handle = Bytes::from_slice(&key_handle).unwrap();
        let signature = hex!("304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871");
        let signature = Bytes::from_slice(&signature).unwrap();
        let attestation_certificate = hex!("3082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df");
        let attestation_certificate = Bytes::from_slice(&attestation_certificate).unwrap();
        let response = register::Response::new(
            0x05,
            &public_key,
            key_handle,
            signature,
            attestation_certificate,
        );
        let mut output = Vec::<_, 1024>::new();
        Response::Register(response).serialize(&mut output).unwrap();
        assert_eq!(
            output.as_slice(),
            &hex!("0504b174bc49c7ca254b70d2e5c207cee9cf174820ebd77ea3c65508c26da51b657c1cc6b952f8621697936482da0a6d3d3826a59095daf6cd7c03e2e60385d2f6d9402a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c253082013c3081e4a003020102020a47901280001155957352300a06082a8648ce3d0403023017311530130603550403130c476e756262792050696c6f74301e170d3132303831343138323933325a170d3133303831343138323933325a3031312f302d0603550403132650696c6f74476e756262792d302e342e312d34373930313238303030313135353935373335323059301306072a8648ce3d020106082a8648ce3d030107034200048d617e65c9508e64bcc5673ac82a6799da3c1446682c258c463fffdf58dfd2fa3e6c378b53d795c4a4dffb4199edd7862f23abaf0203b4b8911ba0569994e101300a06082a8648ce3d0403020347003044022060cdb6061e9c22262d1aac1d96d8c70829b2366531dda268832cb836bcd30dfa0220631b1459f09e6330055722c8d89b7f48883b9089b88d60d1d9795902b30410df304502201471899bcc3987e62e8202c9b39c33c19033f7340352dba80fcab017db9230e402210082677d673d891933ade6f617e5dbde2e247e70423fd5ad7804a6d3d3961ef871"),
        );
    }

    #[test]
    fn test_authenticate_request() {
        let challenge = &hex!("ccd6ee2e47baef244d49a222db496bad0ef5b6f93aa7cc4d30c4821b3b9dbc57");
        let application = &hex!("4b0be934baebb5d12d26011b69227fa5e86df94e7d94aa2949a89f2d493992ca");
        let key_handle = &hex!("2a552dfdb7477ed65fd84133f86196010b2215b57da75d315b7b9e8fe2e3925a6019551bab61d16591659cbaf00b4950f7abfe6660e2e006f76868b772d70c25");
        let mut input = Vec::<_, 1024>::new();
        input.extend_from_slice(challenge).unwrap();
        input.extend_from_slice(application).unwrap();
        input.push(u8::try_from(key_handle.len()).unwrap()).unwrap();
        input.extend_from_slice(key_handle).unwrap();

        let control_bytes = [
            (0x07, ControlByte::CheckOnly),
            (0x03, ControlByte::EnforceUserPresenceAndSign),
            (0x08, ControlByte::DontEnforceUserPresenceAndSign),
        ];

        for (byte, variant) in control_bytes {
            let command = command(2, byte, 0, &input);
            let request = Request::try_from(&command).unwrap();
            let Request::Authenticate(request) = request else {
                panic!("expected authenticate request, got: {:?}", request);
            };
            assert_eq!(request.control_byte, variant);
            assert_eq!(request.challenge, challenge);
            assert_eq!(request.app_id, application);
            assert_eq!(request.key_handle, key_handle);
        }
    }

    #[test]
    fn test_authenticate_response() {
        let signature = &hex!("304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272ec10047a923f");
        let signature = Bytes::from_slice(signature).unwrap();
        let response = authenticate::Response {
            user_presence: 1,
            count: 1,
            signature,
        };
        let mut output = Vec::<_, 1024>::new();
        Response::Authenticate(response)
            .serialize(&mut output)
            .unwrap();
        assert_eq!(
            output.as_slice(),
            &hex!("0100000001304402204b5f0cd17534cedd8c34ee09570ef542a353df4436030ce43d406de870b847780220267bb998fac9b7266eb60e7cb0b5eabdfd5ba9614f53c7b22272ec10047a923f"),
        );
    }

    #[test]
    fn test_version_request() {
        let command = command(3, 0, 0, &[]);
        let request = Request::try_from(&command).unwrap();
        assert_eq!(request, Request::Version);
    }

    #[test]
    fn test_version_response() {
        let response = Response::Version(*b"U2F_V2");
        let mut output = Vec::<_, 1024>::new();
        response.serialize(&mut output).unwrap();
        assert_eq!(output.as_slice(), b"U2F_V2");
    }
}

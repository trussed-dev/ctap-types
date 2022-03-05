//! The FIDO CTAP Authenticator API in terms of RPC with our types.

use crate::ctap1;
use crate::ctap2;

pub use ctap1::Authenticator as Ctap1Authenticator;
pub use ctap2::Authenticator as Ctap2Authenticator;

// pub trait Authenticator {
//     fn process(&mut self, request: &mut Request) -> Result<Response, Error>;
// }

#[derive(Clone, Debug, PartialEq)]
// clippy says (2022-02-26): large size difference
// - first is 88 bytes
// - second is 10456 bytes
#[allow(clippy::large_enum_variant)]
pub enum Request {
    Ctap1(ctap1::Request),
    Ctap2(ctap2::Request),
}

#[derive(Clone, Debug, PartialEq)]
// clippy says...large size difference
// - first is 0 bytes
// - second is 1880 bytes
#[allow(clippy::large_enum_variant)]
pub enum Response {
    Ctap1(ctap1::Response),
    Ctap2(ctap2::Response),
}

/// Authenticator which supports both CTAP1 and CTAP2.
pub trait Authenticator: ctap1::Authenticator + ctap2::Authenticator {
    // fn call(&mut self, request: &Request) -> Result<Response> {
    //     Ok(match request {
    //         Request::Ctap1(request) => Response::Ctap1(self.call_ctap1(request)?),
    //         Request::Ctap2(request) => Response::Ctap2(self.call_ctap2(request)?),
    //     })
    // }
}

impl<A: ctap1::Authenticator + ctap2::Authenticator> Authenticator for A {}

// pub type Result<T> = core::result::Result<T, Error>;

use core::{fmt::Debug, ops::ControlFlow};

use arbitrary::{Arbitrary, Error, Result, Unstructured};
use cosey::EcdhEsHkdf256PublicKey;
use heapless::{String, Vec};
use heapless_bytes::Bytes;
use serde_bytes::ByteArray;

use crate::{ctap1, ctap2, webauthn};

// cannot be derived because of missing impl for &[T; N]
impl<'a> Arbitrary<'a> for ctap1::authenticate::Request<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let control_byte = Arbitrary::arbitrary(u)?;
        let challenge = u.bytes(32)?.try_into().unwrap();
        let app_id = u.bytes(32)?.try_into().unwrap();
        let key_handle = Arbitrary::arbitrary(u)?;
        Ok(Self {
            control_byte,
            challenge,
            app_id,
            key_handle,
        })
    }
}

// cannot be derived because of missing impl for &[T; N]
impl<'a> Arbitrary<'a> for ctap1::register::Request<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let challenge = u.bytes(32)?.try_into().unwrap();
        let app_id = u.bytes(32)?.try_into().unwrap();
        Ok(Self { challenge, app_id })
    }
}

// cannot be derived because of missing impl for serde_bytes::Bytes, EcdhEsHkdf256PublicKey
impl<'a> Arbitrary<'a> for ctap2::client_pin::Request<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let pin_protocol = u.arbitrary()?;
        let sub_command = u.arbitrary()?;
        let key_agreement = arbitrary_option(u, arbitrary_key)?;
        let pin_auth = if bool::arbitrary(u)? {
            Some(serde_bytes::Bytes::new(u.arbitrary()?))
        } else {
            None
        };
        let new_pin_enc = if bool::arbitrary(u)? {
            Some(serde_bytes::Bytes::new(u.arbitrary()?))
        } else {
            None
        };
        let pin_hash_enc = if bool::arbitrary(u)? {
            Some(serde_bytes::Bytes::new(u.arbitrary()?))
        } else {
            None
        };
        let _placeholder07 = u.arbitrary()?;
        let _placeholder08 = u.arbitrary()?;
        let permissions = u.arbitrary()?;
        let rp_id = u.arbitrary()?;
        Ok(Self {
            pin_protocol,
            sub_command,
            key_agreement,
            pin_auth,
            new_pin_enc,
            pin_hash_enc,
            _placeholder07,
            _placeholder08,
            permissions,
            rp_id,
        })
    }
}

// cannot be derived because of missing impl for serde_bytes::Bytes
impl<'a> Arbitrary<'a> for ctap2::credential_management::Request<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let sub_command = u.arbitrary()?;
        let sub_command_params = u.arbitrary()?;
        let pin_protocol = u.arbitrary()?;
        let pin_auth = if bool::arbitrary(u)? {
            Some(serde_bytes::Bytes::new(u.arbitrary()?))
        } else {
            None
        };
        Ok(Self {
            sub_command,
            sub_command_params,
            pin_protocol,
            pin_auth,
        })
    }
}

// cannot be derived because of missing impl for serde_bytes::ByteArray
impl<'a> Arbitrary<'a> for ctap2::credential_management::SubcommandParameters<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let rp_id_hash = arbitrary_option(u, arbitrary_byte_array)?;
        let credential_id = u.arbitrary()?;
        let user = u.arbitrary()?;
        Ok(Self {
            rp_id_hash,
            credential_id,
            user,
        })
    }
}

// cannot be derived because of missing impl for EcdhEsHkdf256PublicKey, Bytes<_>
impl<'a> Arbitrary<'a> for ctap2::get_assertion::HmacSecretInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let key_agreement = arbitrary_key(u)?;
        let salt_enc = arbitrary_bytes(u)?;
        let salt_auth = arbitrary_bytes(u)?;
        let pin_protocol = u.arbitrary()?;
        Ok(Self {
            key_agreement,
            salt_enc,
            salt_auth,
            pin_protocol,
        })
    }
}

// cannot be derived because of missing impl for serde_bytes::Bytes, Vec<_>
impl<'a> Arbitrary<'a> for ctap2::get_assertion::Request<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let rp_id = u.arbitrary()?;
        let client_data_hash = serde_bytes::Bytes::new(u.arbitrary()?);
        let allow_list = arbitrary_option(u, arbitrary_vec)?;
        let extensions = u.arbitrary()?;
        let options = u.arbitrary()?;
        let pin_auth = if bool::arbitrary(u)? {
            Some(serde_bytes::Bytes::new(u.arbitrary()?))
        } else {
            None
        };
        let pin_protocol = u.arbitrary()?;
        let enterprise_attestation = u.arbitrary()?;
        Ok(Self {
            rp_id,
            client_data_hash,
            allow_list,
            extensions,
            options,
            pin_auth,
            pin_protocol,
            enterprise_attestation,
        })
    }
}

// cannot be derived because of missing impl for serde_bytes::Bytes
impl<'a> Arbitrary<'a> for ctap2::large_blobs::Request<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let get = u.arbitrary()?;
        let set = if bool::arbitrary(u)? {
            Some(serde_bytes::Bytes::new(u.arbitrary()?))
        } else {
            None
        };
        let offset = u.arbitrary()?;
        let length = u.arbitrary()?;
        let pin_uv_auth_param = if bool::arbitrary(u)? {
            Some(serde_bytes::Bytes::new(u.arbitrary()?))
        } else {
            None
        };
        let pin_uv_auth_protocol = u.arbitrary()?;
        Ok(Self {
            get,
            set,
            offset,
            length,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        })
    }
}

// cannot be derived because of missing impl for serde_bytes::Bytes
impl<'a> Arbitrary<'a> for ctap2::make_credential::Request<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let client_data_hash = serde_bytes::Bytes::new(u.arbitrary()?);
        let rp = u.arbitrary()?;
        let user = u.arbitrary()?;
        let pub_key_cred_params = u.arbitrary()?;
        let exclude_list = arbitrary_option(u, arbitrary_vec)?;
        let extensions = u.arbitrary()?;
        let options = u.arbitrary()?;
        let pin_auth = if bool::arbitrary(u)? {
            Some(serde_bytes::Bytes::new(u.arbitrary()?))
        } else {
            None
        };
        let pin_protocol = u.arbitrary()?;
        let enterprise_attestation = u.arbitrary()?;
        Ok(Self {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list,
            extensions,
            options,
            pin_auth,
            pin_protocol,
            enterprise_attestation,
        })
    }
}

// cannot be derived because of missing impl for Vec<_>
impl<'a> Arbitrary<'a> for webauthn::FilteredPublicKeyCredentialParameters {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let parameters = arbitrary_vec(u)?;
        Ok(Self(parameters))
    }
}

// cannot be derived because we want to make sure that we have valid values
impl<'a> Arbitrary<'a> for webauthn::KnownPublicKeyCredentialParameters {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let alg = *u.choose(&webauthn::KNOWN_ALGS)?;
        Ok(Self { alg })
    }
}

// cannot be derived because of missing impl for serde_bytes::Bytes
impl<'a> Arbitrary<'a> for webauthn::PublicKeyCredentialDescriptorRef<'a> {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let id = serde_bytes::Bytes::new(u.arbitrary()?);
        let key_type = u.arbitrary()?;
        Ok(Self { id, key_type })
    }
}

// cannot be derived because of missing impl for String<_>
impl<'a> Arbitrary<'a> for webauthn::PublicKeyCredentialRpEntity {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let id = arbitrary_str(u)?;
        let name = if bool::arbitrary(u)? {
            Some(arbitrary_str(u)?)
        } else {
            None
        };
        let icon = Arbitrary::arbitrary(u)?;
        Ok(Self { id, name, icon })
    }
}

// cannot be derived because of missing impl for Bytes<_> and String<_>
impl<'a> Arbitrary<'a> for webauthn::PublicKeyCredentialUserEntity {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let id = arbitrary_bytes(u)?;
        let icon = if bool::arbitrary(u)? {
            Some(arbitrary_str(u)?)
        } else {
            None
        };
        let name = if bool::arbitrary(u)? {
            Some(arbitrary_str(u)?)
        } else {
            None
        };
        let display_name = if bool::arbitrary(u)? {
            Some(arbitrary_str(u)?)
        } else {
            None
        };
        Ok(Self {
            id,
            icon,
            name,
            display_name,
        })
    }
}

fn arbitrary_byte_array<'a, const N: usize>(u: &mut Unstructured<'_>) -> Result<&'a ByteArray<N>> {
    let bytes: &[u8; N] = u.bytes(N)?.try_into().unwrap();
    // TODO: conversion should be provided by serde_bytes
    Ok(unsafe { &*(bytes as *const [u8; N] as *const ByteArray<N>) })
}

fn arbitrary_bytes<const N: usize>(u: &mut Unstructured<'_>) -> Result<Bytes<N>> {
    let n = usize::arbitrary(u)?.min(N);
    Ok(Bytes::from_slice(u.bytes(n)?).unwrap())
}

fn arbitrary_vec<'a, T: Arbitrary<'a> + Debug, const N: usize>(
    u: &mut Unstructured<'a>,
) -> Result<Vec<T, N>> {
    let mut vec = Vec::new();
    u.arbitrary_loop(Some(0), Some(N.try_into().unwrap()), |u| {
        vec.push(u.arbitrary()?).unwrap();
        Ok(ControlFlow::Continue(()))
    })?;
    Ok(vec)
}

fn arbitrary_str<const N: usize>(u: &mut Unstructured<'_>) -> Result<String<N>> {
    let n = usize::arbitrary(u)?.min(N);
    match core::str::from_utf8(u.peek_bytes(n).ok_or(Error::NotEnoughData)?) {
        Ok(s) => {
            u.bytes(n)?;
            Ok(s.try_into().unwrap())
        }
        Err(e) => {
            let i = e.valid_up_to();
            let valid = u.bytes(i)?;
            let s = unsafe { core::str::from_utf8_unchecked(valid) };
            Ok(s.try_into().unwrap())
        }
    }
}

fn arbitrary_option<'a, T, F>(u: &mut Unstructured<'a>, f: F) -> Result<Option<T>>
where
    F: FnOnce(&mut Unstructured<'a>) -> Result<T>,
{
    if bool::arbitrary(u)? {
        f(u).map(Some)
    } else {
        Ok(None)
    }
}

fn arbitrary_key(u: &mut Unstructured<'_>) -> Result<EcdhEsHkdf256PublicKey> {
    let x = arbitrary_bytes(u)?;
    let y = arbitrary_bytes(u)?;
    Ok(EcdhEsHkdf256PublicKey { x, y })
}

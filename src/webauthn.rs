//! Subset of WebAuthn types that crept into CTAP.

use crate::sizes::*;
use crate::{Bytes, String};
use serde::{de::Deserializer, Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub id: String<256>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_from_str_and_truncate"
    )]
    pub name: Option<String<64>>,
    /// This field has been removed in Webauthn 2 but CTAP 2.2 requires implementors to accept it.
    ///
    /// The content of this field must not be stored.  Therefore we use the [`Icon`][] helper type.
    ///
    /// See [issue #9][] for more information.
    ///
    /// [issue #9]: https://github.com/solokeys/ctap-types/issues/9
    #[serde(skip_serializing, alias = "url")]
    pub icon: Option<Icon>,
}

/// Helper type for the `icon` field of [`PublicKeyCredentialRpEntity`][].
///
/// This field must be parsed but not used or stored.  Therefore this wrapper type can be
/// deserialized from a string but does not store any data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Icon;

impl<'de> Deserialize<'de> for Icon {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let _s: &'de str = Deserialize::deserialize(deserializer)?;
        Ok(Self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialUserEntity {
    pub id: Bytes<64>,
    #[serde(
        default,
        deserialize_with = "deserialize_from_str_and_skip_if_too_long"
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String<128>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_from_str_and_truncate"
    )]
    pub name: Option<String<64>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_from_str_and_truncate"
    )]
    pub display_name: Option<String<64>>,
}

fn deserialize_from_str_and_skip_if_too_long<'de, D, const L: usize>(
    deserializer: D,
) -> Result<Option<String<L>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let result: Result<String<L>, D::Error> = serde::Deserialize::deserialize(deserializer);
    match result {
        Ok(string) => Ok(Some(string)),
        Err(_err) => {
            info_now!("skipping field: {:?}", _err);
            Ok(None)
        }
    }
}

fn deserialize_from_str_and_truncate<'de, D, const L: usize>(
    deserializer: D,
) -> Result<Option<String<L>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<&str> = serde::Deserialize::deserialize(deserializer)?;
    Ok(s.map(truncate))
}

fn truncate<const L: usize>(s: &str) -> String<L> {
    let split = floor_char_boundary(s, L);
    let mut truncated = String::new();
    // floor_char_boundary(s, L) <= L, so this cannot fail
    truncated.push_str(&s[..split]).unwrap();
    truncated
}

// Copy of the nightly str::floor_char_boundary function
fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        s.len()
    } else {
        let lower_bound = index.saturating_sub(3);
        let new_index = s.as_bytes()[lower_bound..=index]
            .iter()
            .rposition(|b| is_utf8_char_boundary(*b));

        // SAFETY: we know that the character boundary will be within four bytes
        unsafe { lower_bound + new_index.unwrap_unchecked() }
    }
}

// Copy of the private u8::is_utf8_char_boundary function
#[inline]
const fn is_utf8_char_boundary(b: u8) -> bool {
    // This is bit magic equivalent to: b < 128 || b >= 192
    (b as i8) >= -0x40
}

impl PublicKeyCredentialUserEntity {
    pub fn from(id: Bytes<64>) -> Self {
        Self {
            id,
            icon: None,
            name: None,
            display_name: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    pub alg: i32,
    #[serde(rename = "type")]
    pub key_type: String<32>,
}

impl PublicKeyCredentialParameters {
    pub fn public_key_with_alg(alg: i32) -> Self {
        Self {
            alg,
            key_type: String::from("public-key"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialDescriptor {
    // NB: if this is too small, get a nasty error
    // See serde::error/custom for more info
    pub id: Bytes<MAX_CREDENTIAL_ID_LENGTH>,
    #[serde(rename = "type")]
    pub key_type: String<32>,
    // https://w3c.github.io/webauthn/#enumdef-authenticatortransport
    // transports: ...
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Same as PublicKeyCredentialDescriptor but which deserializes using references
pub struct PublicKeyCredentialDescriptorRef<'a> {
    // NB: if this is too small, get a nasty error
    // See serde::error/custom for more info
    pub id: &'a serde_bytes::Bytes,
    #[serde(rename = "type")]
    pub key_type: &'a str,
    // https://w3c.github.io/webauthn/#enumdef-authenticatortransport
    // transports: ...
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate() {
        // Example from § 6.4.1 String Truncation in the Webauthn spec
        let v = vec![0x61, 0x67, 0xcc, 0x88];
        let s = std::str::from_utf8(&v).unwrap();

        assert_eq!(truncate::<1>(s), "a");
        assert_eq!(truncate::<2>(s), "ag");
        assert_eq!(truncate::<3>(s), "ag");
        assert_eq!(truncate::<4>(s), s);
        assert_eq!(truncate::<5>(s), s);
        assert_eq!(truncate::<64>(s), s);
    }
}

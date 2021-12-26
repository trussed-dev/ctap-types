pub const ATTESTED_CREDENTIAL_DATA_LENGTH: usize = 612;
// // not sure why i can't use `::to_usize()` here?
// pub const ATTESTED_CREDENTIAL_DATA_LENGTH_BYTES: usize = 512;

pub const AUTHENTICATOR_DATA_LENGTH: usize = 676;
// pub const AUTHENTICATOR_DATA_LENGTH_BYTES: usize = 512;

pub const ASN1_SIGNATURE_LENGTH: usize = 77;
// pub const ASN1_SIGNATURE_LENGTH_BYTES: usize = 72;

pub const COSE_KEY_LENGTH: usize = 256;
// pub const COSE_KEY_LENGTH_BYTES: usize = 256;

pub const MAX_CREDENTIAL_ID_LENGTH: usize = 255;
pub const MAX_CREDENTIAL_ID_LENGTH_PLUS_256: usize = 767;
pub const MAX_CREDENTIAL_COUNT_IN_LIST: usize = 10;

pub const PACKET_SIZE: usize = 64;

// 7609 bytes
/// The theoretical maximal message size, which however is far
/// too large for most platforms.
pub const THEORETICAL_MAX_MESSAGE_SIZE: usize = PACKET_SIZE - 7 + 128 * (PACKET_SIZE - 5);
/// The size used by Yubico, which means that no platforms will
/// realistically expect a larger size.
pub const REALISTIC_MAX_MESSAGE_SIZE: usize = 1200;

/// Max length for a large blob fragment, according to
/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW
pub const LARGE_BLOB_MAX_FRAGMENT_LENGTH: usize = REALISTIC_MAX_MESSAGE_SIZE - 64;

pub const ATTESTED_CREDENTIAL_DATA_LENGTH: usize = 612;
// // not sure why i can't use `::to_usize()` here?
// pub const ATTESTED_CREDENTIAL_DATA_LENGTH_BYTES: usize = 512;

pub const AUTHENTICATOR_DATA_LENGTH: usize = 676;
// pub const AUTHENTICATOR_DATA_LENGTH_BYTES: usize = 512;

pub const ASN1_SIGNATURE_LENGTH: usize = 77;
// pub const ASN1_SIGNATURE_LENGTH_BYTES: usize = 72;

pub const COSE_KEY_LENGTH: usize = 256;
// pub const COSE_KEY_LENGTH_BYTES: usize = 256;

pub const MAX_CREDENTIAL_ID_LENGTH: usize = 512;
pub const MAX_CREDENTIAL_ID_LENGTH_PLUS_256: usize = 768;
pub const MAX_CREDENTIAL_COUNT_IN_LIST: usize = 10;

pub const PACKET_SIZE: usize = 64;

// 7609 bytes
pub const MESSAGE_SIZE: usize = PACKET_SIZE - 7 + 128 * (PACKET_SIZE - 5);

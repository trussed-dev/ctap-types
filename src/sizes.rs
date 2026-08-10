// Largest enabled ML-DSA parameter set: public key / signature bytes (FIPS 204).
const MLDSA: bool = cfg!(any(
    feature = "mldsa44",
    feature = "mldsa65",
    feature = "mldsa87"
));
const MLDSA_PK: usize = if cfg!(feature = "mldsa87") {
    2592
} else if cfg!(feature = "mldsa65") {
    1952
} else if cfg!(feature = "mldsa44") {
    1312
} else {
    0
};
const MLDSA_SIG: usize = if cfg!(feature = "mldsa87") {
    4627
} else if cfg!(feature = "mldsa65") {
    3309
} else if cfg!(feature = "mldsa44") {
    2420
} else {
    0
};

// authData holds the key in a COSE_Key map, plus AAGUID and credId.
pub const AUTHENTICATOR_DATA_LENGTH: usize = if MLDSA { MLDSA_PK + 736 } else { 676 };
// pub const AUTHENTICATOR_DATA_LENGTH_BYTES: usize = 512;

pub const ASN1_SIGNATURE_LENGTH: usize = 77;
// pub const ASN1_SIGNATURE_LENGTH_BYTES: usize = 72;

// P-256 fits ASN1_SIGNATURE_LENGTH; ML-DSA needs the raw signature.
pub const MAX_PACKED_SIG_LENGTH: usize = if MLDSA {
    MLDSA_SIG + 12
} else {
    ASN1_SIGNATURE_LENGTH
};

// One x5c entry, bounded by what trussed's Reply.der carries.
pub const MAX_X5C_CERT_LENGTH: usize = if MLDSA { 2048 } else { 1024 };

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

/// Max length for a large blob fragment, according to
/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#largeBlobsRW
///
/// This constant determines the buffer size in [`ctap2::large_blobs::Response`][].  Ideally, this
/// would be configurable.  Currently, this is not possible.  To keep the stack usage low if the
/// extension is not used, this constant defaults to zero. For compatibility with the max message
/// size in usbd-ctaphid (used by solo2 and nitrokey-3-firmware), it is set to 3072 - 64 =
/// 3008 if the `large-blobs` feature is enabled.
#[cfg(not(feature = "large-blobs"))]
pub const LARGE_BLOB_MAX_FRAGMENT_LENGTH: usize = 0;
#[cfg(feature = "large-blobs")]
pub const LARGE_BLOB_MAX_FRAGMENT_LENGTH: usize = 3008;

pub const MAX_CRED_BLOB_LENGTH: usize = 32;

/// the authenticator API, consisting of "operations"
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Operation {
    MakeCredential,
    GetAssertion,
    GetNextAssertion,
    GetInfo,
    ClientPin,
    Reset,
    // new in v2.1
    BioEnrollment,
    CredentialManagement,
    Selection,
    LargeBlobs,
    Config,
    PreviewBioEnrollment,
    PreviewCredentialManagement,
    /// vendors are assigned the range 0x40..=0x7f for custom operations
    Vendor(VendorOperation),
}

impl From<Operation> for u8 {
    fn from(operation: Operation) -> u8 {
        use Operation::*;
        match operation {
            MakeCredential => 0x01,
            GetAssertion => 0x02,
            GetNextAssertion => 0x08,
            GetInfo => 0x04,
            ClientPin => 0x06,
            Reset => 0x07,
            BioEnrollment => 0x09,
            CredentialManagement => 0x0A,
            Selection => 0x0B,
            LargeBlobs => 0x0C,
            Config => 0x0D,
            PreviewBioEnrollment => 0x40,
            PreviewCredentialManagement => 0x41,
            Vendor(operation) => operation.into(),
        }
    }
}

impl Operation {
    pub fn into_u8(self) -> u8 {
        self.into()
    }
}

/// Vendor CTAP2 operations, from 0x40 to 0x7f.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VendorOperation(u8);

impl VendorOperation {
    pub const FIRST: u8 = 0x40;
    pub const LAST: u8 = 0x7f;
}

impl TryFrom<u8> for VendorOperation {
    type Error = ();

    fn try_from(from: u8) -> core::result::Result<Self, ()> {
        match from {
            // code if code >= Self::FIRST && code <= Self::LAST => Ok(VendorOperation(code)),
            code @ Self::FIRST..=Self::LAST => Ok(VendorOperation(code)),
            _ => Err(()),
        }
    }
}

impl From<VendorOperation> for u8 {
    fn from(operation: VendorOperation) -> u8 {
        operation.0
    }
}

impl TryFrom<u8> for Operation {
    type Error = ();

    fn try_from(from: u8) -> core::result::Result<Operation, ()> {
        use Operation::*;
        Ok(match from {
            0x01 => MakeCredential,
            0x02 => GetAssertion,
            0x08 => GetNextAssertion,
            0x04 => GetInfo,
            0x06 => ClientPin,
            0x07 => Reset,
            0x09 => BioEnrollment,
            0x0A => CredentialManagement,
            0x0B => Selection,
            0x0C => LargeBlobs,
            0x0D => Config,
            0x40 => PreviewBioEnrollment,
            0x41 => PreviewCredentialManagement,
            code @ VendorOperation::FIRST..=VendorOperation::LAST => {
                Vendor(VendorOperation::try_from(code)?)
            }
            _ => return Err(()),
        })
    }
}

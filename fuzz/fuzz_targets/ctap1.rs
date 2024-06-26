#![no_main]

use ctap_types::ctap1::Request;
use iso7816::command::Command;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(command) = Command::<7609>::try_from(data) {
        Request::try_from(&command).ok();
    }
});

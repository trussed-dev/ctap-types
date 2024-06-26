#![no_main]

use ctap_types::ctap2::Request;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    Request::deserialize(data).ok();
});

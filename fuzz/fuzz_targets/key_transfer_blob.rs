#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO: fuzz key transfer blob parsing once implemented
    let _ = data;
});

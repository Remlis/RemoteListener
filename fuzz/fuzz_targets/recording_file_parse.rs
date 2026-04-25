#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO: fuzz recording file parsing once implemented
    let _ = data;
});

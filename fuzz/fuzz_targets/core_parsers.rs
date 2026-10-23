#![no_main]

#[path = "../../crates/core/tests/support/parsers.rs"]
mod parsers;

libfuzzer_sys::fuzz_target!(|input: &[u8]| parsers::check(input));

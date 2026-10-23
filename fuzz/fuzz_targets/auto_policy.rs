#![no_main]

#[path = "../../crates/cli/tests/support/auto_policy.rs"]
mod policy;

libfuzzer_sys::fuzz_target!(|input: &[u8]| policy::check(input));

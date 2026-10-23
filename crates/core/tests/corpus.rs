#[path = "support/parsers.rs"]
mod parsers;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions report an invalid verification corpus"
)]
fn replay_core_parser_corpus() -> std::io::Result<()> {
    let corpus =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/core_parsers");
    let mut count = 0usize;
    for entry in std::fs::read_dir(corpus)? {
        let entry = entry?;
        assert!(entry.file_type()?.is_file());
        let input = std::fs::read(entry.path())?;
        parsers::check(&input);
        if let Some(trimmed) = input.strip_suffix(b"\n") {
            parsers::check(trimmed);
        }
        count = count.saturating_add(1);
    }
    assert!(count > 0, "the parser corpus must be nonempty");
    Ok(())
}

#[path = "support/auto_policy.rs"]
mod policy;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions report an invalid verification corpus"
)]
fn replay_auto_policy_corpus() -> std::io::Result<()> {
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/auto_policy");
    let mut count = 0usize;
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        assert!(entry.file_type()?.is_file());
        policy::check(&std::fs::read(entry.path())?);
        count = count.saturating_add(1);
    }
    assert!(count > 0, "the policy corpus must be nonempty");
    Ok(())
}

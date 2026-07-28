//! Command-line interface for storage-scout 0.2.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use inquire::{InquireError, MultiSelect};
use serde::Serialize;
use storage_scout::{
    ApplyOptions, ArtifactCandidate, ArtifactKind, Bytes, CandidateId, CleanupPlan, CleanupSummary,
    DEFAULT_TOP, Measure, RiskTier, SCHEMA_VERSION, ScanOptions, apply_cleanup_plan,
    create_cleanup_plan, discover_cleanup_candidates, render_clean_human, render_json,
    render_scan_human, scan,
};

#[derive(Debug, Parser)]
#[command(
    name = "storage-scout",
    version,
    about = "Fast Windows storage scan and safety-first build-artifact cleanup"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Read-only disk usage and artifact scan.
    Scan(ScanArgs),
    /// Discover, select, validate, and optionally delete known build artifacts.
    Clean(CleanArgs),
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// One or more roots to scan.
    #[arg(value_name = "ROOT", required = true, num_args = 1..)]
    roots: Vec<PathBuf>,
    /// Number of largest directories to show.
    #[arg(long, default_value_t = DEFAULT_TOP)]
    top: usize,
    /// Minimum directory/artifact logical size.
    #[arg(long, default_value = "10MiB", value_parser = parse_size)]
    min_size: Bytes,
    /// Deepest directory level to list (root = 0); traversal remains unlimited.
    #[arg(long, value_name = "N")]
    depth: Option<usize>,
    /// Exclude a subtree. Repeatable.
    #[arg(long, value_name = "PATH")]
    exclude: Vec<PathBuf>,
    /// Rayon worker count.
    #[arg(long, value_name = "N", value_parser = parse_threads)]
    threads: Option<usize>,
    /// Size measurement mode.
    #[arg(long, default_value = "logical")]
    measure: MeasureArg,
    /// Emit stable JSON with `schema_version` 1.
    #[arg(long)]
    json: bool,
    /// Exit 1 if any filesystem read or measurement error occurs.
    #[arg(long)]
    strict: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum MeasureArg {
    Logical,
    Both,
}

impl From<MeasureArg> for Measure {
    fn from(value: MeasureArg) -> Self {
        match value {
            MeasureArg::Logical => Self::Logical,
            MeasureArg::Both => Self::Both,
        }
    }
}

#[derive(Debug, Args)]
struct CleanArgs {
    /// Explicit project roots under which artifacts may be discovered.
    #[arg(value_name = "ROOT", required = true, num_args = 1..)]
    roots: Vec<PathBuf>,
    /// Restrict artifact families. Repeatable or comma-separated.
    #[arg(long, value_name = "KIND", value_delimiter = ',', value_parser = parse_kind)]
    kind: Vec<ArtifactKind>,
    /// Minimum candidate logical size.
    #[arg(long, default_value = "10MiB", value_parser = parse_size)]
    min_size: Bytes,
    /// Keep only candidates whose newest file is at least this old, e.g. 30d.
    #[arg(long, value_name = "AGE", value_parser = parse_age)]
    older_than: Option<u64>,
    /// Protect a subtree. Repeatable.
    #[arg(long, value_name = "PATH")]
    exclude: Vec<PathBuf>,
    /// Unlock non-routine candidates. Repeatable or comma-separated.
    #[arg(long, value_name = "TIER", value_delimiter = ',', value_parser = parse_tier)]
    include_tier: Vec<RiskTier>,
    /// Emit stable JSON with `schema_version` 1.
    #[arg(long)]
    json: bool,
    /// Actually delete after revalidation. The default is a dry-run.
    #[arg(long)]
    execute: bool,
    /// Select an exact ID from a prior clean --json discovery. Repeatable.
    #[arg(long, value_name = "SHA256", value_delimiter = ',', value_parser = parse_id)]
    id: Vec<CandidateId>,
    /// Non-interactive deletion acknowledgement; requires --execute and --id.
    #[arg(long, requires_all = ["execute", "id"])]
    yes: bool,
}

#[derive(Debug, Clone)]
struct Choice {
    id: CandidateId,
    label: String,
}

impl fmt::Display for Choice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label)
    }
}

#[derive(Serialize)]
struct CleanJson<'a> {
    schema_version: u32,
    command: &'static str,
    mode: &'static str,
    candidates: &'a [ArtifactCandidate],
    #[serde(skip_serializing_if = "Option::is_none")]
    plan: Option<&'a CleanupPlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<&'a CleanupSummary>,
}

fn main() -> ExitCode {
    if std::env::args_os().len() == 1 {
        let mut command = Cli::command();
        let _ = command.print_help();
        let _ = writeln!(io::stdout().lock());
        return ExitCode::SUCCESS;
    }
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "error: {error:#}");
            ExitCode::from(1)
        },
    }
}

fn run(cli: Cli) -> Result<u8> {
    match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Clean(args) => run_clean(args),
    }
}

fn run_scan(args: ScanArgs) -> Result<u8> {
    let options = ScanOptions {
        roots: args.roots,
        top: args.top,
        min_size: args.min_size,
        max_depth: args.depth.map_or(storage_scout::DEFAULT_MAX_DEPTH, Some),
        excludes: args.exclude,
        threads: args.threads,
        measure: args.measure.into(),
    };
    let report = scan(&options);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if args.json {
        render_json(&report, &mut out)?;
    } else {
        render_scan_human(&report, use_color(), &mut out)?;
    }
    Ok(u8::from(
        report.roots.is_empty() || (args.strict && report.stats.errors > 0),
    ))
}

fn run_clean(args: CleanArgs) -> Result<u8> {
    let CleanArgs {
        roots,
        kind,
        min_size,
        older_than,
        exclude,
        include_tier,
        json,
        execute,
        id,
        yes,
    } = args;
    let options = ScanOptions {
        roots,
        top: 0,
        min_size,
        max_depth: Some(0),
        excludes: exclude.clone(),
        threads: None,
        measure: Measure::Both,
    };
    let mut report = discover_cleanup_candidates(&options).map_err(anyhow::Error::msg)?;
    if !kind.is_empty() {
        report
            .candidates
            .retain(|candidate| kind.contains(&candidate.kind));
    }
    if let Some(age) = older_than {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(age);
        report
            .candidates
            .retain(|candidate| candidate.newest_mtime != 0 && candidate.newest_mtime <= cutoff);
    }

    let unlocked = unlocked_tiers(&include_tier);
    if id.is_empty() && json {
        return write_clean_json("discovery", &report.candidates, None, None);
    }

    if !json {
        print_candidates(&report.candidates, &unlocked)?;
    }
    let selected_ids = if id.is_empty() {
        if !interactive_terminal() {
            if execute {
                bail!(
                    "non-interactive deletion requires explicit --id values with --execute --yes"
                );
            }
            writeln!(
                io::stdout().lock(),
                "No candidates selected; nothing was deleted."
            )?;
            return Ok(0);
        }
        if let Some(ids) = select_candidates(&report.candidates, &unlocked)? {
            ids
        } else {
            writeln!(
                io::stderr().lock(),
                "Selection canceled; nothing was deleted."
            )?;
            return Ok(0);
        }
    } else {
        validate_unlocked_ids(&report.candidates, &id, &unlocked)?;
        id
    };

    if selected_ids.is_empty() {
        if !json {
            writeln!(
                io::stdout().lock(),
                "No candidates selected; nothing was deleted."
            )?;
        }
        return Ok(0);
    }
    let plan = create_cleanup_plan(&report.candidates, &selected_ids, exclude)
        .map_err(anyhow::Error::msg)?;

    if !execute {
        let summary = apply_cleanup_plan(&plan, ApplyOptions { execute: false });
        output_clean(json, "dry-run", &report.candidates, &plan, &summary)?;
        return Ok(cleanup_exit_code(&summary));
    }

    if !yes {
        if !interactive_terminal() {
            bail!("non-interactive deletion requires --execute --yes with explicit --id values");
        }
        let preview = apply_cleanup_plan(&plan, ApplyOptions { execute: false });
        if preview.has_failures() {
            output_clean(
                json,
                "validation-failed",
                &report.candidates,
                &plan,
                &preview,
            )?;
            return Ok(1);
        }
        if !confirm_exact(plan.candidates().len())? {
            writeln!(
                io::stderr().lock(),
                "Confirmation did not match; nothing was deleted."
            )?;
            return Ok(0);
        }
    }

    let summary = apply_cleanup_plan(&plan, ApplyOptions { execute: true });
    output_clean(json, "executed", &report.candidates, &plan, &summary)?;
    Ok(cleanup_exit_code(&summary))
}

fn cleanup_exit_code(summary: &CleanupSummary) -> u8 {
    u8::from(summary.has_failures())
}

fn unlocked_tiers(included: &[RiskTier]) -> HashSet<RiskTier> {
    std::iter::once(RiskTier::Routine)
        .chain(included.iter().copied())
        .collect()
}

fn validate_unlocked_ids(
    candidates: &[ArtifactCandidate],
    ids: &[CandidateId],
    unlocked: &HashSet<RiskTier>,
) -> Result<()> {
    for id in ids {
        if let Some(candidate) = candidates.iter().find(|candidate| candidate.id == *id)
            && !unlocked.contains(&candidate.tier)
        {
            bail!(
                "candidate {id} is {}; add --include-tier {}",
                candidate.tier,
                candidate.tier
            );
        }
    }
    Ok(())
}

fn select_candidates(
    candidates: &[ArtifactCandidate],
    unlocked: &HashSet<RiskTier>,
) -> Result<Option<Vec<CandidateId>>> {
    let choices = candidates
        .iter()
        .filter(|candidate| unlocked.contains(&candidate.tier))
        .map(|candidate| Choice {
            id: candidate.id.clone(),
            label: format!(
                "{}  {:>11}  {:<20}  {}",
                &candidate.id.as_str()[..12],
                candidate.usage.logical,
                candidate.kind.label(),
                candidate.path.display()
            ),
        })
        .collect::<Vec<_>>();
    if choices.is_empty() {
        return Ok(Some(Vec::new()));
    }
    match MultiSelect::new("Select artifacts to clean", choices)
        .with_page_size(15)
        .with_help_message("Space: select · type: search · Enter: continue · Esc: cancel safely")
        .prompt()
    {
        Ok(selected) => Ok(Some(selected.into_iter().map(|choice| choice.id).collect())),
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => Ok(None),
        Err(error) => Err(anyhow!(error).context("interactive selection failed")),
    }
}

fn print_candidates(candidates: &[ArtifactCandidate], unlocked: &HashSet<RiskTier>) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    writeln!(
        out,
        "Authenticated cleanup candidates ({}):",
        candidates.len()
    )?;
    if candidates.is_empty() {
        writeln!(out, "  (none)")?;
        return Ok(());
    }
    for candidate in candidates {
        let lock = if unlocked.contains(&candidate.tier) {
            ""
        } else {
            " [locked: use --include-tier]"
        };
        let allocation = candidate
            .usage
            .allocated
            .map_or_else(|| "unavailable".to_owned(), |value| value.to_string());
        writeln!(
            out,
            "  {} {:>11} logical / {:>11} allocated  [{}]{}\n      id={}\n      {}",
            tier_tag(candidate.tier, use_color()),
            candidate.usage.logical,
            allocation,
            candidate.kind.label(),
            lock,
            candidate.id,
            candidate.path.display()
        )?;
    }
    Ok(())
}

fn output_clean(
    json: bool,
    mode: &'static str,
    candidates: &[ArtifactCandidate],
    plan: &CleanupPlan,
    summary: &CleanupSummary,
) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if json {
        let document = CleanJson {
            schema_version: SCHEMA_VERSION,
            command: "clean",
            mode,
            candidates,
            plan: Some(plan),
            summary: Some(summary),
        };
        render_json(&document, &mut out)?;
    } else {
        render_clean_human(plan, summary, use_color(), &mut out)?;
    }
    Ok(())
}

fn write_clean_json(
    mode: &'static str,
    candidates: &[ArtifactCandidate],
    plan: Option<&CleanupPlan>,
    summary: Option<&CleanupSummary>,
) -> Result<u8> {
    let document = CleanJson {
        schema_version: SCHEMA_VERSION,
        command: "clean",
        mode,
        candidates,
        plan,
        summary,
    };
    render_json(&document, &mut io::stdout().lock())?;
    Ok(0)
}

fn confirm_exact(count: usize) -> Result<bool> {
    let phrase = format!("delete {count} candidates");
    let stderr = io::stderr();
    let mut error_output = stderr.lock();
    write!(
        error_output,
        "Type exactly `{phrase}` to permanently delete: "
    )?;
    error_output.flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(confirmation_matches(&input, count))
}

fn confirmation_matches(input: &str, count: usize) -> bool {
    input.trim_end_matches(['\r', '\n']) == format!("delete {count} candidates")
}

fn interactive_terminal() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

fn use_color() -> bool {
    io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn tier_tag(tier: RiskTier, color: bool) -> String {
    let code = match tier {
        RiskTier::Routine => "32",
        RiskTier::Reinstallable => "33",
        RiskTier::Expensive => "31",
    };
    if color {
        format!("\u{1b}[{code}m[{tier:^13}]\u{1b}[0m")
    } else {
        format!("[{tier:^13}]")
    }
}

fn parse_kind(value: &str) -> Result<ArtifactKind, String> {
    ArtifactKind::from_str(value)
}

fn parse_threads(value: &str) -> Result<usize, String> {
    let threads = value
        .parse::<usize>()
        .map_err(|_| format!("invalid thread count: {value}"))?;
    if threads == 0 {
        Err("thread count must be at least 1".to_owned())
    } else {
        Ok(threads)
    }
}

fn parse_tier(value: &str) -> Result<RiskTier, String> {
    RiskTier::from_str(value)
}

fn parse_id(value: &str) -> Result<CandidateId, String> {
    CandidateId::from_str(value)
}

fn parse_age(value: &str) -> Result<u64, String> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(split);
    let count = number
        .parse::<u64>()
        .map_err(|_| format!("invalid age: {value}"))?;
    let multiplier = match suffix.to_ascii_lowercase().as_str() {
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        _ => return Err("age must use h, d, or w (for example 30d)".to_owned()),
    };
    count
        .checked_mul(multiplier)
        .ok_or_else(|| "age is too large".to_owned())
}

fn parse_size(input: &str) -> Result<Bytes, String> {
    let value = input.trim();
    let split = value
        .find(|character: char| !character.is_ascii_digit() && character != '.')
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(split);
    let number = number
        .parse::<f64>()
        .map_err(|_| format!("invalid size: {input}"))?;
    if !number.is_finite() || number.is_sign_negative() {
        return Err(format!("invalid non-negative size: {input}"));
    }
    let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kib" => 1024.0,
        "kb" => 1_000.0,
        "m" | "mib" => 1024.0 * 1024.0,
        "mb" => 1_000_000.0,
        "g" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "gb" => 1_000_000_000.0,
        "t" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "tb" => 1_000_000_000_000.0,
        _ => return Err(format!("unknown size suffix: {suffix}")),
    };
    let bytes = number * multiplier;
    if bytes >= 18_446_744_073_709_551_616.0 {
        return Err("size is too large".to_owned());
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "finite non-negative value was range-checked above; byte fractions are truncated"
    )]
    Ok(Bytes(bytes as u64))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use storage_scout::{
        Bytes, CandidateId, CleanupOutcome, CleanupStatus, CleanupSummary, SCHEMA_VERSION, Usage,
    };

    use super::{cleanup_exit_code, confirmation_matches};

    #[test]
    fn confirmation_requires_an_exact_case_sensitive_phrase() {
        assert!(confirmation_matches("delete 3 candidates\r\n", 3));
        assert!(!confirmation_matches("yes\n", 3));
        assert!(!confirmation_matches("Delete 3 candidates\n", 3));
        assert!(!confirmation_matches("delete 2 candidates\n", 3));
        assert!(!confirmation_matches("delete 3 candidates \n", 3));
    }

    #[test]
    fn partial_cleanup_failure_maps_to_exit_one() {
        let failed = CleanupOutcome {
            id: CandidateId::from_str(&"a".repeat(64)).unwrap(),
            path: PathBuf::from("failed"),
            usage: Usage {
                logical: Bytes(1),
                allocated: Some(Bytes(1)),
                reclaimable: Some(Bytes(1)),
            },
            status: CleanupStatus::Failed("injected".to_owned()),
        };
        let summary = CleanupSummary {
            schema_version: SCHEMA_VERSION,
            executed: true,
            predicted_freed: Some(Bytes(1)),
            observed_freed: Some(Bytes(0)),
            outcomes: vec![failed],
        };
        assert_eq!(cleanup_exit_code(&summary), 1);
    }
}

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use inquire::{InquireError, MultiSelect};
use serde::Serialize;
use storage_scout::core::artifact::{Kind, Tier};
use storage_scout::core::candidate::CandidateId;
use storage_scout::core::event::Event;
use storage_scout::core::gate::{Mandate, TierGrant};
use storage_scout::core::ownership::Admits;
use storage_scout::core::size::Bytes;
use storage_scout::trace::{self, Verbosity};
use storage_scout::{
    AutoPolicy, Color, DEFAULT_TOP, Found, Measure, Mode, Plan, SCHEMA_VERSION, ScanOptions, Scout,
    Summary, render_auto, render_clean, render_dedupe, render_doctor, render_explain, render_json,
    render_prune, render_scan, render_watch,
};

#[derive(Debug, Parser)]
#[command(
    name = "storage-scout",
    version,
    about = "Disk-usage scanner and safety-first build-artifact cleaner"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    #[arg(long, value_name = "PATH", global = true)]
    trace_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Scan(ScanArgs),
    Clean(CleanArgs),
    Auto(AutoArgs),
    Dedupe(DedupeArgs),
    Prune(DedupeArgs),
    Watch(WatchArgs),
    Doctor(Output),
    Explain(ExplainArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Human,
    Json,
}

#[derive(Debug, Args)]
struct Output {
    #[arg(long)]
    json: bool,
}

impl Output {
    const fn format(&self) -> Format {
        if self.json {
            Format::Json
        } else {
            Format::Human
        }
    }
}

#[derive(Debug, Args)]
struct ExplainArgs {
    #[arg(value_name = "PATH")]
    path: PathBuf,
    #[arg(long, value_name = "PATH")]
    exclude: Vec<PathBuf>,
    #[arg(long, value_name = "TIER", value_delimiter = ',', value_parser = parse_tier)]
    include_tier: Vec<Tier>,
    #[arg(long, value_enum, default_value = "manual")]
    phase: Phase,
    #[command(flatten)]
    output: Output,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Phase {
    Manual,
    Reap,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum MeasureArg {
    Logical,
    Both,
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[arg(value_name = "ROOT", required = true, num_args = 1..)]
    roots: Vec<PathBuf>,
    #[arg(long, default_value_t = DEFAULT_TOP)]
    top: usize,
    #[arg(long, default_value = "10MiB", value_parser = parse_size)]
    min_size: Bytes,
    #[arg(long, value_name = "N")]
    depth: Option<usize>,
    #[arg(long, value_name = "PATH")]
    exclude: Vec<PathBuf>,
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u16).range(1..))]
    threads: Option<u16>,
    #[arg(long, value_enum, default_value = "logical")]
    measure: MeasureArg,
    #[arg(long)]
    strict: bool,
    #[command(flatten)]
    output: Output,
}

#[derive(Debug, Args)]
struct CleanArgs {
    #[arg(value_name = "ROOT", required = true, num_args = 1..)]
    roots: Vec<PathBuf>,
    #[arg(long, value_name = "KIND", value_delimiter = ',', value_parser = parse_kind)]
    kind: Vec<Kind>,
    #[arg(long, default_value = "10MiB", value_parser = parse_size)]
    min_size: Bytes,
    #[arg(long, value_name = "PATH")]
    exclude: Vec<PathBuf>,
    #[arg(long, value_name = "TIER", value_delimiter = ',', value_parser = parse_tier)]
    include_tier: Vec<Tier>,
    #[arg(long, value_name = "SHA256", value_delimiter = ',', value_parser = parse_id)]
    id: Vec<CandidateId>,
    #[command(flatten)]
    execution: Execution,
    #[arg(long, requires_all = ["execute", "id"])]
    yes: bool,
    #[command(flatten)]
    output: Output,
}

#[derive(Debug, Args)]
struct DedupeArgs {
    #[arg(value_name = "ROOT", required = true, num_args = 1..)]
    roots: Vec<PathBuf>,
    #[arg(long, value_name = "PATH")]
    exclude: Vec<PathBuf>,
    #[command(flatten)]
    execution: Execution,
    #[command(flatten)]
    output: Output,
}

#[derive(Debug, Args)]
struct WatchArgs {
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confirm {
    Ask,
    Given,
}

#[derive(Debug, Args)]
struct AutoArgs {
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(flatten)]
    execution: Execution,
    #[command(flatten)]
    output: Output,
    #[arg(long, requires = "execute")]
    detach: bool,
    #[arg(long, value_enum, value_name = "HOOK")]
    event: Option<EventArg>,
    #[arg(last = true, value_name = "HOOK-ARGS")]
    hook: Vec<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EventArg {
    PostMerge,
    PostCheckout,
    ReferenceTransaction,
}

impl EventArg {
    const fn event(self) -> Event {
        match self {
            Self::PostMerge => Event::PostMerge,
            Self::PostCheckout => Event::PostCheckout,
            Self::ReferenceTransaction => Event::ReferenceTransaction,
        }
    }
}

const fn mode(output: &Execution) -> Mode {
    if output.execute {
        Mode::Execute
    } else {
        Mode::DryRun
    }
}

#[derive(Debug, Args)]
struct Execution {
    #[arg(long)]
    execute: bool,
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
struct CleanDocument<'a> {
    schema_version: u32,
    command: &'static str,
    stage: &'static str,
    candidates: &'a [Found],
    plan: Option<&'a Plan>,
    summary: Option<&'a Summary>,
}

fn main() -> ExitCode {
    if std::env::args_os().len() == 1 {
        let mut command = Cli::command();
        return match command.print_help() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_unprintable) => ExitCode::FAILURE,
        };
    }
    let cli = Cli::parse();
    if let Err(error) = trace::install(
        Verbosity::from_count(cli.verbose),
        cli.trace_file.as_deref(),
    ) {
        return complain(&anyhow!(error).context("cannot open the trace file"));
    }
    match run(cli.command) {
        Ok(code) => code,
        Err(error) => complain(&error),
    }
}

fn complain(error: &anyhow::Error) -> ExitCode {
    match writeln!(io::stderr().lock(), "error: {error:#}") {
        Ok(()) | Err(_) => ExitCode::FAILURE,
    }
}

fn run(command: Command) -> Result<ExitCode> {
    let scout = Scout::detect().context("cannot resolve this host's protected areas")?;
    match command {
        Command::Scan(args) => scan(&scout, args),
        Command::Clean(args) => clean(&scout, args),
        Command::Auto(args) => auto(&scout, args),
        Command::Dedupe(args) => dedupe(&scout, &args),
        Command::Prune(args) => prune(&scout, &args),
        Command::Watch(args) => watch(&scout, args),
        Command::Doctor(output) => doctor(&scout, &output),
        Command::Explain(args) => explain(&scout, &args),
    }
}

fn color() -> Color {
    if io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() {
        Color::Always
    } else {
        Color::Never
    }
}

fn doctor(scout: &Scout, output: &Output) -> Result<ExitCode> {
    let diagnosis = scout.diagnose(default_policy_path());
    let mut out = io::stdout().lock();
    match output.format() {
        Format::Json => render_json(&diagnosis, &mut out)?,
        Format::Human => render_doctor(&diagnosis, &mut out)?,
    }
    Ok(ExitCode::from(u8::from(!diagnosis.warnings.is_empty())))
}

fn explain(scout: &Scout, args: &ExplainArgs) -> Result<ExitCode> {
    let explanation = scout
        .explain(
            &args.path,
            &args.exclude,
            Mandate {
                tiers: TierGrant::of(args.include_tier.iter().copied()),
                settlements: match args.phase {
                    Phase::Manual => Admits::Anything,
                    Phase::Reap => Admits::Settled,
                },
            },
        )
        .map_err(|rejection| anyhow!("{rejection}"))?;
    let mut out = io::stdout().lock();
    match args.output.format() {
        Format::Json => render_json(&explanation, &mut out)?,
        Format::Human => render_explain(&explanation, &mut out)?,
    }
    Ok(ExitCode::from(u8::from(!explanation.eligible)))
}

fn scan(scout: &Scout, args: ScanArgs) -> Result<ExitCode> {
    let options = ScanOptions {
        roots: args.roots,
        top: args.top,
        min_size: args.min_size,
        max_depth: args.depth.or(Some(1)),
        excludes: args.exclude,
        threads: args.threads.map(usize::from),
        measure: match args.measure {
            MeasureArg::Logical => Measure::Logical,
            MeasureArg::Both => Measure::Allocated,
        },
    };
    let report = scout.scan(&options);
    let mut out = io::stdout().lock();
    match args.output.format() {
        Format::Json => render_json(&report, &mut out)?,
        Format::Human => render_scan(&report, color(), &mut out)?,
    }
    let failed = report.roots.is_empty() || (args.strict && report.stats.errors > 0);
    Ok(ExitCode::from(u8::from(failed)))
}

fn interactive() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

fn clean(scout: &Scout, args: CleanArgs) -> Result<ExitCode> {
    let tiers = TierGrant::of(args.include_tier.iter().copied());
    let options = ScanOptions {
        roots: args.roots,
        top: 0,
        min_size: args.min_size,
        max_depth: Some(0),
        excludes: args.exclude.clone(),
        threads: None,
        measure: Measure::Allocated,
    };
    let mut report = scout
        .discover(&options)
        .map_err(|rejection| anyhow!("{rejection}"))?;
    report
        .candidates
        .retain(|found| args.kind.is_empty() || args.kind.contains(&found.candidate().kind()));
    let format = args.output.format();
    let json = format == Format::Json;
    let mode = mode(&args.execution);
    let confirm = if args.yes {
        Confirm::Given
    } else {
        Confirm::Ask
    };
    if args.id.is_empty() && json {
        return write_clean("discovery", &report.candidates, None, None);
    }
    if !json {
        list(&report.candidates, tiers)?;
    }
    let ids = match choose(args.id, &report.candidates, tiers, mode)? {
        Some(ids) => ids,
        None => return Ok(ExitCode::SUCCESS),
    };
    if ids.is_empty() {
        writeln!(
            io::stdout().lock(),
            "No candidates selected; nothing was deleted."
        )?;
        return Ok(ExitCode::SUCCESS);
    }
    let plan = Scout::plan(
        &report.candidates,
        &ids,
        Mandate {
            tiers,
            settlements: Admits::Anything,
        },
        &args.exclude,
    )
    .map_err(|rejection| anyhow!("{rejection}"))?;
    if mode == Mode::Execute && confirm == Confirm::Ask {
        if !interactive() {
            bail!("non-interactive deletion requires --execute --yes with explicit --id values");
        }
        let preview = scout.apply(&plan, Mode::DryRun);
        if preview.failed() {
            output_clean(
                format,
                "validation-failed",
                &report.candidates,
                &plan,
                &preview,
            )?;
            return Ok(ExitCode::FAILURE);
        }
        if !confirmed(plan.candidates().len())? {
            writeln!(
                io::stderr().lock(),
                "Confirmation did not match; nothing was deleted."
            )?;
            return Ok(ExitCode::SUCCESS);
        }
    }
    let summary = scout.apply(&plan, mode);
    let stage = match mode {
        Mode::DryRun => "dry-run",
        Mode::Execute => "executed",
    };
    output_clean(format, stage, &report.candidates, &plan, &summary)?;
    Ok(ExitCode::from(u8::from(summary.failed())))
}

fn choose(
    given: Vec<CandidateId>,
    candidates: &[Found],
    tiers: TierGrant,
    mode: Mode,
) -> Result<Option<Vec<CandidateId>>> {
    if !given.is_empty() {
        return Ok(Some(given));
    }
    if !interactive() {
        if mode == Mode::Execute {
            bail!("non-interactive deletion requires explicit --id values with --execute --yes");
        }
        writeln!(
            io::stdout().lock(),
            "No candidates selected; nothing was deleted."
        )?;
        return Ok(None);
    }
    let picked = pick(candidates, tiers)?;
    if picked.is_none() {
        writeln!(
            io::stderr().lock(),
            "Selection canceled; nothing was deleted."
        )?;
    }
    Ok(picked)
}

fn dedupe(scout: &Scout, args: &DedupeArgs) -> Result<ExitCode> {
    let run = scout
        .dedupe(&args.roots, &args.exclude, mode(&args.execution))
        .map_err(|rejection| anyhow!("{rejection}"))?;
    let mut out = io::stdout().lock();
    match args.output.format() {
        Format::Json => render_json(&run, &mut out)?,
        Format::Human => render_dedupe(&run, &mut out)?,
    }
    Ok(ExitCode::from(u8::from(run.failed())))
}

fn prune(scout: &Scout, args: &DedupeArgs) -> Result<ExitCode> {
    let run = scout
        .prune(&args.roots, &args.exclude, mode(&args.execution))
        .map_err(|rejection| anyhow!("{rejection}"))?;
    let mut out = io::stdout().lock();
    match args.output.format() {
        Format::Json => render_json(&run, &mut out)?,
        Format::Human => render_prune(&run, &mut out)?,
    }
    Ok(ExitCode::from(u8::from(run.failed())))
}

fn policy_path(given: Option<PathBuf>) -> Result<PathBuf> {
    match given {
        Some(config) => Ok(config),
        None => default_policy_path().context("no --config given and no home directory is set"),
    }
}

fn load_policy(config: &std::path::Path) -> Result<AutoPolicy> {
    let text = fs::read_to_string(config)
        .with_context(|| format!("cannot read policy {}", config.display()))?;
    AutoPolicy::parse(&text)
        .map_err(|error| anyhow!("invalid policy {}: {error}", config.display()))
}

fn watch(scout: &Scout, args: WatchArgs) -> Result<ExitCode> {
    let config = policy_path(args.config)?;
    let config = fs::canonicalize(&config)
        .with_context(|| format!("cannot resolve policy {}", config.display()))?;
    let policy = load_policy(&config)?;
    let render = |record: &storage_scout::WatchRecord| {
        let mut out = io::stdout().lock();
        render_watch(record, &mut out)?;
        out.flush()
    };
    Err(anyhow!(scout.watch(&policy, &config, &render)))
}

fn auto(scout: &Scout, args: AutoArgs) -> Result<ExitCode> {
    let config = policy_path(args.config)?;
    let hook_directory = match args.event {
        Some(event) => {
            let event = event.event();
            let mut input = Vec::new();
            if event.reads_updates() {
                io::Read::read_to_end(&mut io::stdin().lock(), &mut input)?;
            }
            let directory = std::env::current_dir()?;
            if !storage_scout::hook::relevant(event, &args.hook, &input, &directory) {
                return Ok(ExitCode::SUCCESS);
            }
            Some(directory)
        },
        None => None,
    };
    let config = fs::canonicalize(&config)
        .with_context(|| format!("cannot resolve policy {}", config.display()))?;
    if args.detach {
        let forwarded = [
            OsString::from("auto"),
            OsString::from("--config"),
            config.clone().into_os_string(),
            OsString::from("--execute"),
        ];
        let detached = match hook_directory.as_deref() {
            Some(directory) => storage_scout::hook::detach_hook(&config, &forwarded, directory),
            None => storage_scout::hook::detach(&config, &forwarded),
        }
        .context("cannot start the background run")?;
        if args.output.format() == Format::Json {
            render_json(&detached, &mut io::stdout().lock())?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    let policy = load_policy(&config)?;
    let format = args.output.format();
    let show = |run: &storage_scout::AutoRun| -> Result<()> {
        let mut out = io::stdout().lock();
        match format {
            Format::Json => render_json(run, &mut out)?,
            Format::Human => render_auto(run, &mut out)?,
        }
        Ok(())
    };
    let mut failed = false;
    match mode(&args.execution) {
        Mode::DryRun => {
            let run = scout
                .auto(&policy, Mode::DryRun)
                .map_err(|rejection| anyhow!("{rejection}"))?;
            show(&run)?;
            failed = run.failed();
        },
        Mode::Execute => {
            let mut execute = || -> Result<storage_scout::AutoRun> {
                let run = scout
                    .auto(&policy, Mode::Execute)
                    .map_err(|rejection| anyhow!("{rejection}"))?;
                show(&run)?;
                if let Some(log_file) = &policy.log_file {
                    storage_scout::append_log(log_file, &run)
                        .with_context(|| format!("cannot append to log {}", log_file.display()))?;
                }
                failed |= run.failed();
                Ok(run)
            };
            let coalescing = match hook_directory.as_deref() {
                Some(directory) => {
                    storage_scout::hook::coalesced_hook(&config, directory, &mut execute)
                },
                None => storage_scout::hook::coalesced(&config, &mut execute),
            }
            .map_err(|error| match error {
                storage_scout::hook::CoalesceError::Station(error) => {
                    anyhow!(error).context("cannot coordinate with other runs")
                },
                storage_scout::hook::CoalesceError::Run(error) => error,
            })?;
            match coalescing {
                storage_scout::hook::Coalescing::Ran { .. } => {},
                storage_scout::hook::Coalescing::Handed => writeln!(
                    io::stderr().lock(),
                    "Another run for {} is in progress; it will run once more when it finishes.",
                    config.display()
                )?,
            }
        },
    }
    Ok(ExitCode::from(u8::from(failed)))
}

fn default_policy_path() -> Option<PathBuf> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })?;
    Some(PathBuf::from(home).join(".config/storage-scout/auto.toml"))
}

fn list(candidates: &[Found], tiers: TierGrant) -> Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "Cleanup candidates ({}):", candidates.len())?;
    if candidates.is_empty() {
        writeln!(out, "  (none)")?;
    }
    for found in candidates {
        let candidate = found.candidate();
        let lock = if tiers.admits(candidate.tier()) {
            ""
        } else {
            " [locked: use --include-tier]"
        };
        writeln!(
            out,
            "  [{}] {:>11}  [{}, {}, {}]{lock}\n      id={}\n      {}",
            candidate.tier(),
            candidate.usage().logical,
            candidate.kind().label(),
            candidate.provenance(),
            candidate.settlement(),
            candidate.id(),
            candidate.location()
        )?;
    }
    Ok(())
}

fn pick(candidates: &[Found], tiers: TierGrant) -> Result<Option<Vec<CandidateId>>> {
    let choices = candidates
        .iter()
        .filter(|found| tiers.admits(found.candidate().tier()))
        .map(|found| {
            let candidate = found.candidate();
            Choice {
                id: candidate.id().clone(),
                label: format!(
                    "{:>11}  {:<20}  {}",
                    candidate.usage().logical,
                    candidate.kind().label(),
                    candidate.location()
                ),
            }
        })
        .collect::<Vec<_>>();
    if choices.is_empty() {
        return Ok(Some(Vec::new()));
    }
    match MultiSelect::new("Select artifacts to clean", choices)
        .with_page_size(15)
        .with_help_message("Space: select · type: search · Enter: continue · Esc: cancel")
        .prompt()
    {
        Ok(selected) => Ok(Some(selected.into_iter().map(|choice| choice.id).collect())),
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => Ok(None),
        Err(error) => Err(anyhow!(error).context("interactive selection failed")),
    }
}

fn output_clean(
    format: Format,
    stage: &'static str,
    candidates: &[Found],
    plan: &Plan,
    summary: &Summary,
) -> Result<()> {
    match format {
        Format::Json => write_clean(stage, candidates, Some(plan), Some(summary)).map(|_| ()),
        Format::Human => {
            render_clean(plan, summary, color(), &mut io::stdout().lock())?;
            Ok(())
        },
    }
}

fn write_clean(
    stage: &'static str,
    candidates: &[Found],
    plan: Option<&Plan>,
    summary: Option<&Summary>,
) -> Result<ExitCode> {
    let document = CleanDocument {
        schema_version: SCHEMA_VERSION,
        command: "clean",
        stage,
        candidates,
        plan,
        summary,
    };
    render_json(&document, &mut io::stdout().lock())?;
    Ok(ExitCode::SUCCESS)
}

fn confirmed(count: usize) -> Result<bool> {
    let phrase = format!("delete {count} candidates");
    let mut error = io::stderr().lock();
    write!(error, "Type exactly `{phrase}` to permanently delete: ")?;
    error.flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim_end_matches(['\r', '\n']) == phrase)
}

fn parse_kind(value: &str) -> Result<Kind, String> {
    Kind::from_str(value).map_err(|error| error.to_string())
}

fn parse_tier(value: &str) -> Result<Tier, String> {
    Tier::from_str(value).map_err(|error| error.to_string())
}

fn parse_id(value: &str) -> Result<CandidateId, String> {
    CandidateId::from_str(value).map_err(|error| error.to_string())
}

fn parse_size(value: &str) -> Result<Bytes, String> {
    Bytes::from_str(value).map_err(|error| error.to_string())
}

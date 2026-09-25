use std::collections::BTreeMap;
use std::io::{self, Write};

use serde::Serialize;
use storage_scout_core::area::{Class, Reach};
use storage_scout_core::artifact::{Kind, Tier};
use storage_scout_core::candidate::{Allocation, Usage};
use storage_scout_core::gate::Outcome;
use storage_scout_core::location::Location;
use storage_scout_core::ownership::Settlement;
use storage_scout_core::select::Stop;
use storage_scout_core::size::Bytes;

use crate::apply::{Mode, Plan, Status, Summary};
use crate::auto::AutoRun;
use crate::dedupe::{Admission, DedupeRun, PairStatus, Tally};
use crate::doctor::{Diagnosis, PolicyFile, Warning};
use crate::explain::Explanation;
use crate::scan::ScanReport;

const BANNER: &str = concat!("storage-scout ", env!("CARGO_PKG_VERSION"));

pub fn render_json<T: Serialize>(value: &T, out: &mut dyn Write) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)
}

fn tier_label(tier: Tier, color: Color) -> String {
    let (name, code) = match tier {
        Tier::Routine => ("routine", "32"),
        Tier::Reinstallable => ("reinstall", "33"),
        Tier::Expensive => ("expensive", "31"),
    };
    match color {
        Color::Always => format!("\u{1b}[{code}m[{name:^9}]\u{1b}[0m"),
        Color::Never => format!("[{name:^9}]"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Always,
    Never,
}

fn write_usage(label: &str, usage: &Usage, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{label} logical size: {}", usage.logical)?;
    match usage.allocation {
        Allocation::Measured {
            allocated,
            reclaimable,
        } => {
            writeln!(out, "{label} allocated: {allocated}")?;
            writeln!(out, "{label} reclaimable: {reclaimable}")
        },
        Allocation::Unmeasured => writeln!(out, "{label} allocation: unmeasured"),
    }
}

pub fn render_scan(report: &ScanReport, color: Color, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{BANNER} — read-only scan")?;
    let roots = report
        .roots
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(out, "Roots: {roots}")?;
    write_usage("Total", &report.usage, out)?;
    writeln!(
        out,
        "Scanned {} directories and {} files ({} links, {} filesystem boundaries skipped, {} errors)",
        report.stats.directories,
        report.stats.files,
        report.stats.links_skipped,
        report.stats.mount_boundaries_skipped,
        report.stats.errors
    )?;
    writeln!(out)?;
    writeln!(out, "Largest directories:")?;
    if report.largest_directories.is_empty() {
        writeln!(out, "  (none above --min-size)")?;
    }
    for directory in &report.largest_directories {
        writeln!(
            out,
            "  {:>11}  {}",
            directory.usage.logical, directory.location
        )?;
    }
    writeln!(out)?;
    writeln!(out, "Build artifacts ({}):", report.candidates.len())?;
    for kind in Kind::ALL {
        let matching = report
            .candidates
            .iter()
            .filter(|found| found.candidate().kind() == *kind)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        let total = Bytes::total(
            matching
                .iter()
                .map(|found| found.candidate().usage().logical),
        );
        writeln!(
            out,
            "  {} {:<21} {:>4} dirs  {:>11}",
            tier_label(kind.tier(), color),
            kind.label(),
            matching.len(),
            total
        )?;
    }
    if report.candidates.is_empty() {
        writeln!(out, "  (none detected)")?;
    } else if report.listing_limit > 0 {
        writeln!(out)?;
        writeln!(out, "Largest individual artifacts:")?;
        for found in report.candidates.iter().take(report.listing_limit) {
            let candidate = found.candidate();
            writeln!(
                out,
                "  {:>11} {} {:<9} [{}] {}",
                candidate.usage().logical,
                tier_label(candidate.tier(), color),
                candidate.settlement(),
                candidate.kind().label(),
                candidate.location()
            )?;
        }
    }
    if !report.issues.is_empty() {
        writeln!(out)?;
        writeln!(out, "Errors (showing {}):", report.issues.len())?;
        for issue in &report.issues {
            writeln!(out, "  {issue}")?;
        }
    }
    Ok(())
}

fn write_outcomes(
    plan: &Plan,
    summary: &Summary,
    color: Color,
    out: &mut dyn Write,
) -> io::Result<()> {
    for outcome in &summary.outcomes {
        let status = match &outcome.status {
            Status::WouldDelete => "would delete".to_owned(),
            Status::Deleted => "deleted".to_owned(),
            Status::Rejected { rejection } => format!("REJECTED: {rejection}"),
            Status::Failed { rejection } => format!("FAILED: {rejection}"),
        };
        let tier = plan
            .candidates()
            .iter()
            .find(|found| found.candidate().id() == &outcome.id)
            .map_or(Tier::Routine, |found| found.candidate().tier());
        let logical = outcome
            .usage
            .map_or_else(|| "-".to_owned(), |usage| usage.logical.to_string());
        writeln!(
            out,
            "  {logical:>11} {} [{status}] {}",
            tier_label(tier, color),
            outcome.location
        )?;
    }
    writeln!(out)?;
    match summary.predicted_freed {
        Some(value) => writeln!(out, "Predicted reclaimable: {value}")?,
        None => writeln!(out, "Predicted reclaimable: unmeasured")?,
    }
    match (summary.mode, summary.observed_freed) {
        (Mode::Execute, Some(value)) => writeln!(out, "Observed free-space increase: {value}")?,
        (Mode::Execute, None) => writeln!(out, "Observed free-space increase: unmeasured")?,
        (Mode::DryRun, _) => {},
    }
    Ok(())
}

pub fn render_clean(
    plan: &Plan,
    summary: &Summary,
    color: Color,
    out: &mut dyn Write,
) -> io::Result<()> {
    let mode = match summary.mode {
        Mode::Execute => "executed cleanup",
        Mode::DryRun => "dry-run (nothing deleted)",
    };
    writeln!(out, "{BANNER} — {mode}")?;
    write_outcomes(plan, summary, color, out)
}

pub fn render_auto(run: &AutoRun, out: &mut dyn Write) -> io::Result<()> {
    let mode = match run.mode {
        Mode::Execute => "auto",
        Mode::DryRun => "auto: dry-run (nothing deleted)",
    };
    writeln!(out, "{BANNER} — {mode}")?;
    let settled = run
        .candidates
        .iter()
        .filter(|found| {
            matches!(
                found.candidate().settlement(),
                Settlement::Released | Settlement::Landed
            )
        })
        .count();
    writeln!(
        out,
        "Considered {} candidates under {} roots; {settled} already let go by their owners.",
        run.candidates.len(),
        run.policy.selection.roots.len()
    )?;
    match &run.reap.summary {
        Some(summary) => {
            writeln!(out)?;
            writeln!(out, "Reaped:")?;
            write_statuses(
                summary.outcomes.iter().map(|outcome| {
                    (
                        &outcome.location,
                        outcome.usage.map(|usage| usage.logical),
                        &outcome.status,
                    )
                }),
                out,
            )?;
        },
        None => writeln!(out, "Nothing to reap.")?,
    }
    if let Some(dedupe) = &run.dedupe {
        writeln!(out)?;
        writeln!(
            out,
            "Free space {} was below the trigger; sharing identical files left {}.",
            dedupe.free_before, dedupe.free_after
        )?;
        write_sharing(&dedupe.run, out)?;
    }
    let Some(evict) = &run.evict else {
        return Ok(());
    };
    writeln!(out)?;
    writeln!(
        out,
        "Free space {} against a goal of {}; eviction stopped: {}.",
        evict.free_before,
        evict.goal,
        match evict.stopped {
            Stop::NotBelowTrigger => "not below the trigger",
            Stop::GoalReached => "goal reached",
            Stop::NoProgress => "a deletion freed nothing",
            Stop::Exhausted => "nothing left to evict",
        }
    )?;
    write_statuses(
        evict
            .steps
            .iter()
            .map(|step| (&step.location, None, &step.status)),
        out,
    )?;
    Ok(())
}

fn write_statuses<'a>(
    statuses: impl Iterator<Item = (&'a Location, Option<Bytes>, &'a Status)>,
    out: &mut dyn Write,
) -> io::Result<()> {
    for (location, logical, status) in statuses {
        let status = match status {
            Status::WouldDelete => "would delete".to_owned(),
            Status::Deleted => "deleted".to_owned(),
            Status::Rejected { rejection } => format!("withheld: {rejection}"),
            Status::Failed { rejection } => format!("FAILED: {rejection}"),
        };
        let logical = logical.map_or_else(|| "-".to_owned(), |bytes| bytes.to_string());
        writeln!(out, "  {logical:>11} [{status}] {location}")?;
    }
    Ok(())
}

pub fn render_doctor(diagnosis: &Diagnosis, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{BANNER} — host report")?;
    writeln!(out)?;
    writeln!(out, "  {:<18} {}", "platform", diagnosis.platform)?;
    writeln!(
        out,
        "  {:<18} {}-{}",
        "target", diagnosis.arch, diagnosis.os
    )?;
    writeln!(out, "  {:<18} {}", "current directory", diagnosis.cwd)?;
    writeln!(out, "  {:<18} {}", "running binary", diagnosis.exe)?;
    let policy = match diagnosis.policy_file {
        PolicyFile::Present => "present",
        PolicyFile::Absent => "absent",
        PolicyFile::Unreadable => "unreadable",
        PolicyFile::Unresolved => "unresolved",
    };
    let path = diagnosis
        .default_policy
        .as_ref()
        .map_or_else(|| "-".to_owned(), |path| path.display().to_string());
    writeln!(out, "  {:<18} {path} ({policy})", "auto policy")?;
    if let Some(free) = diagnosis.free_here {
        writeln!(out, "  {:<18} {free}", "free here")?;
    }
    writeln!(out)?;
    writeln!(out, "Protected areas, in the order they are consulted:")?;
    for rule in &diagnosis.rules {
        let (trust, label) = match rule.class {
            Class::System { reason } => ("system", reason.to_string()),
            Class::AppOwned { area } => ("application-owned", area.label.to_owned()),
        };
        let reach = match rule.reach {
            Reach::Subtree => "subtree".to_owned(),
            Reach::Exact => "exact".to_owned(),
            Reach::EachChild => "each child".to_owned(),
            Reach::EachChildSubtree(name) => format!("each child's {name}"),
        };
        writeln!(out, "  {trust:<18} {reach:<22} {}  ({label})", rule.anchor)?;
    }
    writeln!(out)?;
    writeln!(out, "Deletion gates, in order:")?;
    for (index, gate) in diagnosis.gates.iter().enumerate() {
        writeln!(
            out,
            "  {}. {:<10} {}",
            index.saturating_add(1),
            gate.gate.name(),
            gate.purpose
        )?;
    }
    for warning in &diagnosis.warnings {
        let text = match warning {
            Warning::NoSystemAreas => "no system areas resolved",
            Warning::FreeSpaceUnknown => "free space here could not be measured",
        };
        writeln!(out, "warning: {text}")?;
    }
    Ok(())
}

pub fn render_explain(explanation: &Explanation, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{BANNER} — why this path is or is not a candidate")?;
    writeln!(out)?;
    writeln!(out, "{}", explanation.location)?;
    writeln!(out)?;
    for stage in &explanation.stages {
        let (mark, detail) = match &stage.outcome {
            Outcome::Pass { note } => ("ok", note.to_string()),
            Outcome::Abstain => ("--", "not asked here".to_owned()),
            Outcome::Reject { rejection } => ("REFUSED", rejection.to_string()),
            Outcome::NotReached => ("", "not reached".to_owned()),
        };
        writeln!(out, "  {mark:<8} {:<10} {detail}", stage.gate.name())?;
    }
    writeln!(out)?;
    match &explanation.rejection {
        Some(rejection) => writeln!(out, "=> not a candidate: {rejection}"),
        None => writeln!(out, "=> eligible: every gate holds"),
    }
}

fn tally(tally: Tally) -> String {
    let noun = if tally.files == 1 { "file" } else { "files" };
    format!("{} {noun} ({})", tally.files, tally.bytes)
}

fn write_sharing(run: &DedupeRun, out: &mut dyn Write) -> io::Result<()> {
    let verb = match run.mode {
        Mode::Execute => "Shared",
        Mode::DryRun => "Would share",
    };
    let admitted = run
        .subjects
        .iter()
        .filter(|subject| matches!(subject.admission, Admission::Admitted { .. }))
        .count();
    writeln!(
        out,
        "{verb} {} across {admitted} candidates.",
        tally(run.totals.shared)
    )?;
    if run.totals.already_shared.files > 0 {
        writeln!(
            out,
            "Already sharing: {}.",
            tally(run.totals.already_shared)
        )?;
    }
    if let Some(freed) = run.observed_freed {
        writeln!(out, "Observed free space gained: {freed}.")?;
    }
    let mut refused: BTreeMap<&str, u64> = BTreeMap::new();
    for pair in &run.pairs {
        if let PairStatus::Refused { refusal } = &pair.status {
            let count = refused.entry(refusal.summary()).or_default();
            *count = count.saturating_add(1);
        }
    }
    if !refused.is_empty() {
        writeln!(out, "Left alone ({}):", tally(run.totals.refused))?;
        for (reason, count) in refused {
            writeln!(out, "  {count:>7} {reason}")?;
        }
    }
    for pair in &run.pairs {
        match &pair.status {
            PairStatus::Withheld { rejection } => {
                writeln!(
                    out,
                    "  {:>11} [withheld: {rejection}] {}",
                    pair.len, pair.duplicate
                )?;
            },
            PairStatus::Failed { failure } => {
                writeln!(
                    out,
                    "  {:>11} [FAILED: {failure}] {}",
                    pair.len, pair.duplicate
                )?;
            },
            PairStatus::WouldShare
            | PairStatus::Shared
            | PairStatus::AlreadyShared
            | PairStatus::Refused { .. } => {},
        }
    }
    Ok(())
}

pub fn render_dedupe(run: &DedupeRun, out: &mut dyn Write) -> io::Result<()> {
    let mode = match run.mode {
        Mode::Execute => "dedupe",
        Mode::DryRun => "dedupe: dry-run (nothing changed)",
    };
    writeln!(out, "{BANNER} — {mode}")?;
    write_sharing(run, out)?;
    let rejected = run
        .subjects
        .iter()
        .filter_map(|subject| match &subject.admission {
            Admission::Rejected { rejection } => Some((&subject.location, rejection)),
            Admission::Admitted { .. } => None,
        })
        .collect::<Vec<_>>();
    if !rejected.is_empty() {
        writeln!(out, "Not considered:")?;
        for (location, rejection) in rejected {
            writeln!(out, "  [{rejection}] {location}")?;
        }
    }
    Ok(())
}

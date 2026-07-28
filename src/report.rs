//! Human and stable JSON rendering kept separate from filesystem logic.

use std::io::{self, Write};

use serde::Serialize;

use crate::artifact::ALL_KINDS;
use crate::{CleanupPlan, CleanupStatus, CleanupSummary, RiskTier, ScanReport, Usage};

/// Render any versioned storage-scout JSON document.
///
/// # Errors
/// Returns serialization or output I/O errors.
pub fn render_json<T: Serialize>(value: &T, out: &mut dyn Write) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)
}

/// Render a read-only scan report.
///
/// # Errors
/// Returns output I/O errors.
pub fn render_scan_human(report: &ScanReport, color: bool, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "storage-scout 0.2 — read-only scan")?;
    writeln!(
        out,
        "Roots: {}",
        report
            .roots
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    write_usage("Total", report.usage, out)?;
    writeln!(
        out,
        "Scanned {} directories and {} files in {:.2}s ({} reparse points skipped, {} errors)",
        report.stats.directories,
        report.stats.files,
        report.stats.elapsed_secs,
        report.stats.reparse_skipped,
        report.stats.errors
    )?;
    writeln!(out)?;
    writeln!(out, "Largest directories:")?;
    if report.largest_directories.is_empty() {
        writeln!(out, "  (none above --min-size)")?;
    } else {
        for directory in &report.largest_directories {
            writeln!(
                out,
                "  {:>11}  {}",
                directory.usage.logical,
                directory.path.display()
            )?;
        }
    }

    writeln!(out)?;
    writeln!(
        out,
        "Authenticated build artifacts ({}):",
        report.candidates.len()
    )?;
    for kind in ALL_KINDS {
        let matching = report
            .candidates
            .iter()
            .filter(|candidate| candidate.kind == kind)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        let total = matching.iter().fold(0u64, |sum, candidate| {
            sum.saturating_add(candidate.usage.logical.as_u64())
        });
        writeln!(
            out,
            "  {} {:<21} {:>4} dirs  {:>11}",
            tier_label(kind.tier(), color),
            kind.label(),
            matching.len(),
            crate::Bytes(total)
        )?;
    }
    if report.candidates.is_empty() {
        writeln!(out, "  (none detected)")?;
    } else if report.listing_limit > 0 {
        writeln!(out)?;
        writeln!(out, "Largest individual artifacts:")?;
        for candidate in report.candidates.iter().take(report.listing_limit) {
            writeln!(
                out,
                "  {:>11} {} [{}] {}",
                candidate.usage.logical,
                tier_label(candidate.tier, color),
                candidate.kind.label(),
                candidate.path.display()
            )?;
        }
    }
    if !report.issues.is_empty() {
        writeln!(out)?;
        writeln!(out, "Errors (showing {}):", report.issues.len())?;
        for issue in &report.issues {
            writeln!(
                out,
                "  {} [{}]: {}",
                issue.path.display(),
                issue.operation,
                issue.error
            )?;
        }
    }
    Ok(())
}

/// Render a cleanup dry-run or execution result.
///
/// # Errors
/// Returns output I/O errors.
pub fn render_clean_human(
    plan: &CleanupPlan,
    summary: &CleanupSummary,
    color: bool,
    out: &mut dyn Write,
) -> io::Result<()> {
    let mode = if summary.executed {
        "executed cleanup"
    } else {
        "dry-run (nothing deleted)"
    };
    writeln!(out, "storage-scout 0.2 — {mode}")?;
    for outcome in &summary.outcomes {
        let status = match &outcome.status {
            CleanupStatus::DryRun => "would delete".to_owned(),
            CleanupStatus::Deleted => "deleted".to_owned(),
            CleanupStatus::Rejected(reason) => format!("REJECTED: {reason}"),
            CleanupStatus::Failed(error) => format!("FAILED: {error}"),
        };
        let candidate = plan
            .candidates()
            .iter()
            .find(|candidate| candidate.id == outcome.id);
        let tier = candidate.map_or(RiskTier::Routine, |candidate| candidate.tier);
        writeln!(
            out,
            "  {:>11} {} [{status}] {}",
            outcome.usage.logical,
            tier_label(tier, color),
            outcome.path.display()
        )?;
    }
    writeln!(out)?;
    match summary.predicted_freed {
        Some(value) => writeln!(out, "Predicted reclaimable: {value}")?,
        None => writeln!(out, "Predicted reclaimable: unavailable")?,
    }
    if summary.executed {
        match summary.observed_freed {
            Some(value) => writeln!(out, "Observed volume free-space increase: {value}")?,
            None => writeln!(out, "Observed volume free-space increase: unavailable")?,
        }
    }
    Ok(())
}

fn write_usage(label: &str, usage: Usage, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "{label} logical size: {}", usage.logical)?;
    match usage.allocated {
        Some(value) => writeln!(out, "{label} allocated estimate: {value}")?,
        None => writeln!(out, "{label} allocated estimate: unavailable")?,
    }
    match usage.reclaimable {
        Some(value) => writeln!(out, "{label} reclaimable estimate: {value}"),
        None => writeln!(out, "{label} reclaimable estimate: unavailable"),
    }
}

fn tier_label(tier: RiskTier, color: bool) -> String {
    let (name, code) = match tier {
        RiskTier::Routine => ("routine", "32"),
        RiskTier::Reinstallable => ("reinstall", "33"),
        RiskTier::Expensive => ("expensive", "31"),
    };
    if color {
        format!("\u{1b}[{code}m[{name:^9}]\u{1b}[0m")
    } else {
        format!("[{name:^9}]")
    }
}

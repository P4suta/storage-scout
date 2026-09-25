mod comments;
mod syntax;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::comments::Safety;

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() && entry.file_name() != "target" && entry.file_name() != "snapshots" {
            rust_files(&path, out)?;
        } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn gates(root: &Path, out: &mut dyn Write) -> Result<usize, String> {
    let mut files = Vec::new();
    for dir in ["crates", "xtask"] {
        rust_files(&root.join(dir), &mut files).map_err(|error| format!("{dir}: {error}"))?;
    }
    files.sort();
    let mut count = 0usize;
    for path in files {
        let source =
            fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let shown = match path.strip_prefix(root) {
            Ok(inner) => inner.to_string_lossy().replace('\\', "/"),
            Err(_outside) => path.to_string_lossy().into_owned(),
        };
        for comment in comments::find(&source) {
            match comment.safety {
                Safety::Justification => {},
                Safety::Prose => {
                    writeln!(out, "{shown}:{}: comments are not written; say it in the code or the commit message", comment.line)
                        .map_err(|error| error.to_string())?;
                    count = count.saturating_add(1);
                },
            }
        }
        let findings =
            syntax::check(&source, &shown).map_err(|error| format!("{shown}: {error}"))?;
        for finding in findings {
            writeln!(out, "{shown}:{}: {}", finding.line, finding.rule)
                .map_err(|error| error.to_string())?;
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn main() -> ExitCode {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf);
    let mut out = io::stderr().lock();
    let result = match (std::env::args().nth(1).as_deref(), root) {
        (Some("gates"), Some(root)) => gates(&root, &mut out),
        (Some(_) | None, _) => Err("usage: cargo xtask gates".to_owned()),
    };
    match result {
        Ok(0) => ExitCode::SUCCESS,
        Ok(count) => match writeln!(out, "{count} finding(s)") {
            Ok(()) | Err(_) => ExitCode::FAILURE,
        },
        Err(error) => match writeln!(out, "{error}") {
            Ok(()) | Err(_) => ExitCode::FAILURE,
        },
    }
}

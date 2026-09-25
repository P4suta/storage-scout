use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use storage_scout_core::git;
use storage_scout_core::location::Location;
use storage_scout_core::ownership::{GitFailure, Landing, Worktree};

use crate::failure;

const SCRUBBED: [&str; 17] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_PREFIX",
    "GIT_NAMESPACE",
    "GIT_QUARANTINE_PATH",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
];

#[derive(Debug, Clone, Copy)]
enum Query<'a> {
    Status,
    DefaultBranches,
    IsAncestor {
        of: &'a str,
    },
    MergeBase {
        with: &'a str,
    },
    ChangedSince {
        base: &'a str,
    },
    Touching {
        base: &'a str,
        tip: &'a str,
        path: &'a str,
    },
}

impl Query<'_> {
    const fn name(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::DefaultBranches => "default-branches",
            Self::IsAncestor { .. } => "is-ancestor",
            Self::MergeBase { .. } => "merge-base",
            Self::ChangedSince { .. } => "changed-since",
            Self::Touching { .. } => "touching",
        }
    }

    fn arguments(self) -> Vec<OsString> {
        let words: Vec<String> = match self {
            Self::Status => [
                "status",
                "--porcelain=v2",
                "--branch",
                "-z",
                "--untracked-files=normal",
                "--ignore-submodules=none",
            ]
            .map(String::from)
            .to_vec(),
            Self::DefaultBranches => [
                "for-each-ref",
                "--format=%(refname)%00%(symref)",
                "refs/remotes/*/HEAD",
            ]
            .map(String::from)
            .to_vec(),
            Self::IsAncestor { of } => vec![
                "merge-base".into(),
                "--is-ancestor".into(),
                "HEAD".into(),
                of.into(),
            ],
            Self::MergeBase { with } => vec!["merge-base".into(), "HEAD".into(), with.into()],
            Self::ChangedSince { base } => vec![
                "diff".into(),
                "--name-only".into(),
                "-z".into(),
                "--no-renames".into(),
                base.into(),
                "HEAD".into(),
            ],
            Self::Touching { base, tip, path } => vec![
                "log".into(),
                "--first-parent".into(),
                "--format=%H".into(),
                format!("{base}..{tip}"),
                "--".into(),
                path.into(),
            ],
        };
        words.into_iter().map(OsString::from).collect()
    }
}

enum Answer {
    Yes(Vec<u8>),
    No,
}

#[expect(
    clippy::disallowed_methods,
    reason = "the one place git runs, with typed queries and a scrubbed environment"
)]
fn run(root: &Path, query: Query<'_>) -> Result<Answer, GitFailure> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "--no-optional-locks",
            "--literal-pathspecs",
        ])
        .args(query.arguments())
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    for name in SCRUBBED {
        command.env_remove(name);
    }
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy();
        if name.starts_with("GIT_CONFIG_KEY_") || name.starts_with("GIT_CONFIG_VALUE_") {
            command.env_remove(name.as_ref());
        }
    }
    let Output { status, stdout, .. } =
        command.output().map_err(|error| GitFailure::Unavailable {
            failure: failure::describe(&error),
        })?;
    match (query, status.code()) {
        (_, Some(0)) => Ok(Answer::Yes(stdout)),
        (Query::IsAncestor { .. } | Query::MergeBase { .. }, Some(1)) => Ok(Answer::No),
        (_, code) => Err(GitFailure::Refused {
            query: query.name(),
            code,
        }),
    }
}

fn output(root: &Path, query: Query<'_>) -> Result<Vec<u8>, GitFailure> {
    match run(root, query)? {
        Answer::Yes(output) => Ok(output),
        Answer::No => Err(GitFailure::Refused {
            query: query.name(),
            code: Some(1),
        }),
    }
}

fn parse<T>(query: Query<'_>, parsed: Result<T, git::Unparsable>) -> Result<T, GitFailure> {
    parsed.map_err(|_unparsable| GitFailure::Unparsable {
        query: query.name(),
    })
}

fn contained(root: &Path, at: &str, changed: &[Vec<u8>]) -> Result<bool, GitFailure> {
    let differing = git::names(&output(root, Query::ChangedSince { base: at })?);
    Ok(!changed.iter().any(|path| differing.contains(path)))
}

pub(crate) fn defaults(root: &Path) -> Result<Vec<String>, GitFailure> {
    parse(
        Query::DefaultBranches,
        git::default_branches(&output(root, Query::DefaultBranches)?),
    )
}

fn landing(root: &Path) -> Result<Landing, GitFailure> {
    let defaults = defaults(root)?;
    if defaults.is_empty() {
        return Ok(Landing::NoDefaultBranch);
    }
    for default in &defaults {
        if let Answer::Yes(_) = run(root, Query::IsAncestor { of: default })? {
            return Ok(Landing::NoOwnWork {
                into: default.clone(),
            });
        }
    }
    for default in &defaults {
        let Answer::Yes(base) = run(root, Query::MergeBase { with: default })? else {
            continue;
        };
        let base = String::from_utf8_lossy(&base).trim().to_owned();
        let changed = git::names(&output(root, Query::ChangedSince { base: &base })?);
        let Some(first) = changed.first() else {
            return Ok(Landing::NoOwnWork {
                into: default.clone(),
            });
        };
        if contained(root, default, &changed)? {
            return Ok(Landing::Contained {
                into: default.clone(),
            });
        }
        let Ok(first) = std::str::from_utf8(first) else {
            continue;
        };
        let touching = parse(
            Query::Touching {
                base: &base,
                tip: default,
                path: first,
            },
            git::commits(&output(
                root,
                Query::Touching {
                    base: &base,
                    tip: default,
                    path: first,
                },
            )?),
        )?;
        for commit in touching {
            if contained(root, &commit, &changed)? {
                return Ok(Landing::Contained {
                    into: default.clone(),
                });
            }
        }
    }
    Ok(Landing::NotContained)
}

pub(crate) fn linked(root: &Path, location: Location) -> Worktree {
    let evaluated = output(root, Query::Status)
        .and_then(|status| parse(Query::Status, git::status(&status)))
        .and_then(|status| Ok((status, landing(root)?)));
    match evaluated {
        Ok((status, landing)) => Worktree::Linked {
            root: location,
            changes: status.changes,
            head: status.head,
            landing,
        },
        Err(failure) => Worktree::Unreadable {
            root: location,
            failure,
        },
    }
}

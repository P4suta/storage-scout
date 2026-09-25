use alloc::string::String;
use alloc::vec::Vec;

use crate::ownership::{Changes, Head, Upstream};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub changes: Changes,
    pub head: Head,
    pub commit: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("git printed something this parser does not recognise")]
pub struct Unparsable;

fn text(bytes: &[u8]) -> Result<&str, Unparsable> {
    core::str::from_utf8(bytes).map_err(|_invalid| Unparsable)
}

pub fn status(output: &[u8]) -> Result<Status, Unparsable> {
    let mut changes = Changes::Clean;
    let mut name = None;
    let mut upstream = None;
    let mut tracked = false;
    let mut commit = None;
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let Some(header) = record.strip_prefix(b"# ") else {
            changes = Changes::Dirty;
            continue;
        };
        let header = text(header)?;
        let (key, value) = header.split_once(' ').ok_or(Unparsable)?;
        match key {
            "branch.oid" if value != "(initial)" => commit = Some(String::from(value)),
            "branch.head" => name = Some(String::from(value)),
            "branch.upstream" => upstream = Some(String::from(value)),
            "branch.ab" => tracked = true,
            _ => {},
        }
    }
    let head = match name.ok_or(Unparsable)? {
        detached if detached == "(detached)" => Head::Detached,
        name => Head::Branch {
            name,
            upstream: match (upstream, tracked) {
                (None, _) => Upstream::None,
                (Some(tracked), true) => Upstream::Tracking { name: tracked },
                (Some(gone), false) => Upstream::Gone { name: gone },
            },
        },
    };
    Ok(Status {
        changes,
        head,
        commit,
    })
}

pub fn default_branches(output: &[u8]) -> Result<Vec<String>, Unparsable> {
    output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let mut fields = line.split(|byte| *byte == 0);
            let _reference = fields.next();
            fields.next().filter(|target| !target.is_empty())
        })
        .map(|target| text(target).map(String::from))
        .collect()
}

#[must_use]
pub fn names(output: &[u8]) -> Vec<Vec<u8>> {
    output
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

pub fn commits(output: &[u8]) -> Result<Vec<String>, Unparsable> {
    output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let line = text(line)?;
            if line.len() >= 40 && line.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                Ok(String::from(line))
            } else {
                Err(Unparsable)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;
    use alloc::vec;

    use super::*;

    #[test]
    fn a_clean_tracking_branch() {
        let output = b"# branch.oid 1111111111111111111111111111111111111111\0# branch.head feat\0# branch.upstream origin/feat\0# branch.ab +1 -0\0";
        assert_eq!(
            status(output),
            Ok(Status {
                changes: Changes::Clean,
                head: Head::Branch {
                    name: "feat".to_owned(),
                    upstream: Upstream::Tracking {
                        name: "origin/feat".to_owned()
                    },
                },
                commit: Some("1111111111111111111111111111111111111111".to_owned()),
            })
        );
    }

    #[test]
    fn an_upstream_without_ahead_behind_is_gone() {
        let output = b"# branch.oid 2222222222222222222222222222222222222222\0# branch.head feat\0# branch.upstream origin/feat\0";
        let parsed = status(output).unwrap();
        assert_eq!(
            parsed.head,
            Head::Branch {
                name: "feat".to_owned(),
                upstream: Upstream::Gone {
                    name: "origin/feat".to_owned()
                }
            }
        );
    }

    #[test]
    fn any_entry_is_a_change_and_detached_is_detached() {
        let output = b"# branch.oid 3333333333333333333333333333333333333333\0# branch.head (detached)\0? untracked.txt\0";
        let parsed = status(output).unwrap();
        assert_eq!(parsed.changes, Changes::Dirty);
        assert_eq!(parsed.head, Head::Detached);
    }

    #[test]
    fn a_status_without_a_head_is_refused() {
        assert_eq!(status(b"# branch.oid 1\0"), Err(Unparsable));
        assert_eq!(status(b"#nonsense\0"), Err(Unparsable));
    }

    #[test]
    fn default_branches_are_the_symref_targets() {
        let output =
            b"refs/remotes/origin/HEAD\0refs/remotes/origin/main\nrefs/remotes/hub/HEAD\0\n";
        assert_eq!(
            default_branches(output),
            Ok(vec!["refs/remotes/origin/main".to_owned()])
        );
    }

    #[test]
    fn names_and_commits_split_exactly() {
        assert_eq!(names(b"a\0b c\0\0"), vec![b"a".to_vec(), b"b c".to_vec()]);
        let sha = "4444444444444444444444444444444444444444";
        assert_eq!(
            commits(alloc::format!("{sha}\n").as_bytes()),
            Ok(vec![sha.to_owned()])
        );
        assert_eq!(commits(b"not a sha\n"), Err(Unparsable));
    }
}

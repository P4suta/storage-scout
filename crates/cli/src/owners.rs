use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use storage_scout_core::lock::Protocol;
use storage_scout_core::ownership::{Key, Marker, OwnerLock, Ownership, Worktree};

use crate::ingress::{self, Declaration};
use crate::observe::git;
use crate::{busy, host};

pub(crate) const MARKER_NAME: &str = "owner.json";

#[derive(Debug, Default)]
pub(crate) struct Owners {
    ceilings: Vec<PathBuf>,
    worktrees: Mutex<BTreeMap<PathBuf, Worktree>>,
}

impl Clone for Owners {
    fn clone(&self) -> Self {
        Self {
            ceilings: self.ceilings.clone(),
            worktrees: Mutex::new(BTreeMap::new()),
        }
    }
}

pub(crate) fn declaration(directory: &Path) -> Option<Declaration> {
    let file = match File::open(directory.join(MARKER_NAME)) {
        Ok(file) => file,
        Err(_absent) => return None,
    };
    let mut bytes = Vec::new();
    match file.take(ingress::OWNER_LIMIT).read_to_end(&mut bytes) {
        Ok(_) => ingress::owner(&bytes),
        Err(_unreadable) => None,
    }
}

fn key(keyed_to: Option<&Path>) -> Key {
    match keyed_to {
        None => Key::Unkeyed,
        Some(path) => match fs::symlink_metadata(path) {
            Ok(_) => Key::Present,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Key::Gone,
            Err(_unreadable) => Key::Unknown,
        },
    }
}

fn marker(directory: &Path) -> Option<Marker> {
    let declaration = declaration(directory)?;
    let lock = match busy::owner_lock(&directory.join(Protocol::TEMP_OWNER_NAME)) {
        busy::LockProbe::Held => OwnerLock::Held,
        busy::LockProbe::Free => OwnerLock::Free,
        busy::LockProbe::Missing => OwnerLock::Missing,
        busy::LockProbe::Unreadable => OwnerLock::Unreadable,
    };
    Some(Marker {
        directory: match host::locate(directory) {
            Ok(location) => location,
            Err(_unnameable) => return None,
        },
        schema: declaration.schema,
        role: declaration.role,
        keep: declaration.keep,
        lock,
        key: key(declaration.keyed_to.as_deref()),
    })
}

enum Dot {
    Absent,
    Directory,
    File(PathBuf),
    Unreadable,
}

fn dot_git(directory: &Path) -> Dot {
    let path = directory.join(".git");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Dot::Absent,
        Err(_unreadable) => Dot::Unreadable,
        Ok(metadata) if metadata.file_type().is_dir() => Dot::Directory,
        Ok(metadata) if metadata.file_type().is_file() => Dot::File(path),
        Ok(_other) => Dot::Unreadable,
    }
}

fn gitdir(file: &Path) -> Option<PathBuf> {
    let mut text = String::new();
    match File::open(file).and_then(|opened| opened.take(4096).read_to_string(&mut text)) {
        Ok(_) => {},
        Err(_unreadable) => return None,
    }
    let target = text.trim().strip_prefix("gitdir:")?.trim();
    let target = PathBuf::from(target);
    Some(if target.is_absolute() {
        target
    } else {
        file.parent()?.join(target)
    })
}

impl Owners {
    pub(crate) fn forget(&self, repositories: Option<&BTreeSet<PathBuf>>) {
        let mut worktrees = match self.worktrees.lock() {
            Ok(worktrees) => worktrees,
            Err(poisoned) => poisoned.into_inner(),
        };
        match repositories {
            None => worktrees.clear(),
            Some(repositories) => worktrees.retain(|root, _| {
                !self
                    .repository(root)
                    .is_some_and(|found| repositories.contains(&found))
            }),
        }
    }

    pub(crate) fn new(ceilings: Vec<PathBuf>) -> Self {
        Self {
            ceilings: ceilings
                .into_iter()
                .map(|path| match fs::canonicalize(&path) {
                    Ok(canonical) => canonical,
                    Err(_unresolvable) => path,
                })
                .collect(),
            worktrees: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn detect() -> Self {
        Self::from_ceilings(std::env::var_os("GIT_CEILING_DIRECTORIES").as_deref())
    }

    fn from_ceilings(value: Option<&std::ffi::OsStr>) -> Self {
        Self::new(match value {
            Some(value) => std::env::split_paths(value)
                .filter(|path| path.is_absolute())
                .collect(),
            None => Vec::new(),
        })
    }

    fn ceiling(&self, directory: &Path) -> bool {
        self.ceilings.iter().any(|ceiling| ceiling == directory)
    }

    pub(crate) fn repository(&self, path: &Path) -> Option<PathBuf> {
        let path = match fs::canonicalize(path) {
            Ok(canonical) => canonical,
            Err(_unresolvable) => path.to_path_buf(),
        };
        path.ancestors()
            .take_while(|directory| !self.ceiling(directory))
            .find_map(|directory| match dot_git(directory) {
                Dot::Directory => Some(directory.join(".git")),
                Dot::File(file) => gitdir(&file)
                    .as_deref()
                    .and_then(Path::parent)
                    .and_then(Path::parent)
                    .map(Path::to_path_buf),
                Dot::Absent | Dot::Unreadable => None,
            })
            .map(|repository| match fs::canonicalize(&repository) {
                Ok(canonical) => canonical,
                Err(_unresolvable) => repository,
            })
    }

    fn worktree(&self, root: &Path, dot: Dot) -> Option<Worktree> {
        let location = match host::locate(root) {
            Ok(location) => location,
            Err(_unnameable) => return None,
        };
        let cached = match self.worktrees.lock() {
            Ok(worktrees) => worktrees.get(root).cloned(),
            Err(poisoned) => poisoned.into_inner().get(root).cloned(),
        };
        if let Some(worktree) = cached {
            return Some(worktree);
        }
        let worktree = match dot {
            Dot::Absent => return None,
            Dot::Directory => Worktree::Primary { root: location },
            Dot::Unreadable => Worktree::Unreadable {
                root: location,
                failure: storage_scout_core::ownership::GitFailure::Unparsable { query: ".git" },
            },
            Dot::File(file) => match gitdir(&file).map(fs::symlink_metadata) {
                Some(Ok(_)) => git::linked(root, location),
                Some(Err(error)) if error.kind() == io::ErrorKind::NotFound => {
                    Worktree::Orphaned { root: location }
                },
                Some(Err(_)) | None => Worktree::Unreadable {
                    root: location,
                    failure: storage_scout_core::ownership::GitFailure::Unparsable {
                        query: ".git",
                    },
                },
            },
        };
        match self.worktrees.lock() {
            Ok(mut worktrees) => worktrees.insert(root.to_path_buf(), worktree.clone()),
            Err(poisoned) => poisoned
                .into_inner()
                .insert(root.to_path_buf(), worktree.clone()),
        };
        Some(worktree)
    }

    pub(crate) fn of(&self, path: &Path, nested: &[PathBuf]) -> Ownership {
        let inside = nested
            .iter()
            .filter(|directory| directory.as_path() != path)
            .filter_map(|directory| marker(directory))
            .collect::<Vec<_>>();
        let mut markers = Vec::new();
        let mut worktree = None;
        for directory in path.ancestors() {
            if self.ceiling(directory) {
                break;
            }
            if let Some(found) = marker(directory) {
                markers.push(found);
            }
            if worktree.is_none() {
                match dot_git(directory) {
                    Dot::Absent => {},
                    dot @ (Dot::Directory | Dot::File(_) | Dot::Unreadable) => {
                        worktree = self.worktree(directory, dot);
                    },
                }
            }
        }
        Ownership::resolve(markers, inside, worktree)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    #[test]
    fn only_absolute_ceilings_are_taken_from_the_environment() {
        let temp = testkit::tempdir("owners-ceilings");
        let absolute = fs::canonicalize(temp.path()).unwrap();
        let listed = std::env::join_paths([absolute.as_path(), Path::new("relative")]).unwrap();
        let owners = Owners::from_ceilings(Some(&listed));
        assert_eq!(owners.ceilings, vec![absolute]);
        assert!(Owners::from_ceilings(None).ceilings.is_empty());
        let empty = OsString::new();
        assert!(Owners::from_ceilings(Some(&empty)).ceilings.is_empty());
        assert_eq!(owners.clone().ceilings, owners.ceilings);
    }

    #[test]
    fn forgetting_one_repository_keeps_the_other_repositories_answers() {
        let temp = testkit::tempdir("owners-forget");
        let base = fs::canonicalize(temp.path()).unwrap();
        let one = base.join("one");
        let two = base.join("two");
        testkit::make_dir(&one.join(".git"));
        testkit::make_dir(&two.join(".git"));
        let owners = Owners::default();
        let _one = owners.of(&one, &[]);
        let _two = owners.of(&two, &[]);
        assert_eq!(owners.worktrees.lock().unwrap().len(), 2);

        owners.forget(Some(&BTreeSet::from([one.join(".git")])));
        let cached = owners.worktrees.lock().unwrap();
        assert!(!cached.contains_key(&one));
        assert!(cached.contains_key(&two));
        drop(cached);

        owners.forget(None);
        assert!(owners.worktrees.lock().unwrap().is_empty());
    }

    #[test]
    fn a_git_file_has_to_name_a_git_directory() {
        let temp = testkit::tempdir("owners-git-file");
        let file = temp.path().join(".git");
        assert_eq!(gitdir(&file), None);
        testkit::write_bytes(&file, b"not a git directory\n");
        assert_eq!(gitdir(&file), None);
        testkit::write_bytes(&file, b"gitdir: ../repository/.git/worktrees/linked\n");
        assert_eq!(
            gitdir(&file),
            Some(temp.path().join("../repository/.git/worktrees/linked"))
        );
    }

    #[test]
    fn a_repository_has_one_canonical_name() {
        let temp = testkit::tempdir("owners-repository-name");
        let primary = temp.path().join("repository");
        let common = primary.join(".git");
        testkit::make_dir(&common.join("worktrees/linked"));
        let linked = temp.path().join("linked");
        testkit::write_bytes(
            &linked.join(".git"),
            b"gitdir: ../repository/.git/worktrees/linked\n",
        );
        let expected = fs::canonicalize(&common).unwrap();
        let owners = Owners::default();
        assert_eq!(
            owners.repository(&primary.join("target")),
            Some(expected.clone())
        );
        assert_eq!(owners.repository(&linked.join("target")), Some(expected));
    }

    #[test]
    fn a_repository_above_a_ceiling_is_not_an_owner_scope() {
        let temp = testkit::tempdir("owners-repository-ceiling");
        let outer = temp.path().join("outer");
        testkit::make_dir(&outer.join(".git"));
        let ceiling = outer.join("ceiling");
        let work = ceiling.join("work");
        testkit::make_dir(&work);
        assert!(Owners::default().repository(&work).is_some());
        assert_eq!(Owners::new(vec![ceiling]).repository(&work), None);
    }
}

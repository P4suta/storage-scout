use std::collections::BTreeSet;
use std::fs::{File, Metadata};
use std::io;
use std::path::{Path, PathBuf};

use storage_scout_core::candidate::Identity;
use storage_scout_core::gate::{Boundary, Shape};
use storage_scout_core::share::{Extras, Failure, Filesystem, Method, Mode, Owner, Sharing, Step};

#[cfg_attr(unix, path = "platform/unix.rs")]
#[cfg_attr(windows, path = "platform/windows.rs")]
mod imp;
#[cfg_attr(target_os = "macos", path = "platform/share_macos.rs")]
#[cfg_attr(target_os = "linux", path = "platform/share_linux.rs")]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    path = "platform/share_none.rs"
)]
mod share;
pub(crate) mod spawn;

#[derive(Debug, Clone, Copy)]
pub(crate) struct FileMeasure {
    pub identity: Identity,
    pub allocation: u64,
    pub links: u32,
}

#[derive(Debug)]
pub(crate) enum WalkError {
    Moved {
        path: PathBuf,
    },
    #[cfg_attr(
        windows,
        expect(
            dead_code,
            reason = "a Windows mount point is a reparse point and is never entered"
        )
    )]
    Boundary {
        path: PathBuf,
        from: u64,
        to: u64,
    },
    Io {
        path: PathBuf,
        error: io::Error,
    },
}

pub(crate) fn identity(path: &Path) -> io::Result<Identity> {
    imp::identity(path)
}

pub(crate) fn identity_of_file(file: &File) -> io::Result<Identity> {
    imp::identity_of_file(file)
}

#[cfg_attr(
    windows,
    expect(clippy::missing_const_for_fn, reason = "const only on Windows")
)]
pub(crate) fn identity_of_metadata(metadata: &Metadata) -> Option<Identity> {
    imp::identity_of_metadata(metadata)
}

pub(crate) fn file_measure(path: &Path) -> io::Result<FileMeasure> {
    imp::file_measure(path)
}

pub(crate) fn free_space(path: &Path) -> io::Result<u64> {
    imp::free_space(path)
}

pub(crate) fn shape(metadata: &Metadata) -> Shape {
    let kind = metadata.file_type();
    if kind.is_symlink() || imp::is_reparse_point(metadata) {
        Shape::Link
    } else if kind.is_dir() {
        Shape::Directory
    } else if kind.is_file() {
        Shape::File
    } else {
        Shape::Other
    }
}

#[cfg_attr(
    windows,
    expect(clippy::missing_const_for_fn, reason = "const only on Windows")
)]
pub(crate) fn device(metadata: &Metadata) -> Option<u64> {
    imp::device(metadata)
}

pub(crate) fn boundary(parent: &Metadata, child: &Metadata) -> Boundary {
    match (device(parent), device(child)) {
        (Some(from), Some(to)) if from == to => Boundary::Same { device: to },
        (Some(from), Some(to)) => Boundary::Crossed { from, to },
        (None, _) | (_, None) => Boundary::Unreported,
    }
}

pub(crate) fn remove_tree(
    root: &Path,
    expected: Identity,
    keep: &BTreeSet<Identity>,
    release: impl FnOnce(),
) -> Result<(), WalkError> {
    imp::remove_tree(root, expected, keep, release)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FileFacts {
    pub identity: Identity,
    pub len: u64,
    pub links: u64,
    pub owner: Owner,
    pub mode: Mode,
    pub sharing: Sharing,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    expect(dead_code, reason = "this platform shares nothing")
)]
pub(crate) struct Request<'a> {
    pub keeper: &'a Path,
    pub keeper_identity: Identity,
    pub duplicate: &'a Path,
    pub duplicate_identity: Identity,
    pub len: u64,
}

fn failed(step: Step) -> impl Fn(io::Error) -> Failure {
    move |error| Failure::Io {
        step,
        error: crate::failure::describe(&error),
    }
}

pub(crate) fn filesystem(path: &Path) -> io::Result<Filesystem> {
    share::filesystem(path)
}

pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    imp::open_regular(path)
}

pub(crate) fn file_facts(path: &Path, metadata: &Metadata) -> io::Result<FileFacts> {
    share::facts(path, metadata)
}

#[cfg_attr(
    not(target_os = "macos"),
    expect(
        clippy::missing_const_for_fn,
        reason = "only APFS replacements read extras"
    )
)]
pub(crate) fn extras(path: &Path, identity: Identity) -> Extras {
    share::extras(path, identity)
}

pub(crate) struct Tree(share::Tree);

impl Tree {
    pub(crate) fn open(root: &Path, expected: Identity) -> Result<Self, WalkError> {
        share::open(root, expected).map(Self)
    }

    pub(crate) fn share(&self, method: Method, request: &Request<'_>) -> Result<(), Failure> {
        share::share(&self.0, method, request)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use storage_scout_core::share::{Capability, Failure, Method, Step};
    use testkit::{Built, Scratch, write_patterned};

    use super::*;

    const LEN: u64 = 128 * 1024;

    struct Fixture {
        _temp: Scratch,
        root: PathBuf,
        keeper: PathBuf,
        keeper_identity: Identity,
        tree: Tree,
        method: Method,
    }

    impl Fixture {
        fn new(name: &str) -> Option<Self> {
            let temp = testkit::tempdir(name);
            let root = temp.path().join("root");
            let keeper = temp.path().join("keeper.bin");
            write_patterned(&keeper, LEN, 1);
            write_patterned(&root.join("sub/dup.bin"), LEN, 1);
            match Capability::of(filesystem(&root).unwrap()) {
                Capability::Shares { method, .. } => Some(Self {
                    keeper_identity: identity(&keeper).unwrap(),
                    tree: Tree::open(&root, identity(&root).unwrap()).unwrap(),
                    _temp: temp,
                    root,
                    keeper,
                    method,
                }),
                Capability::Unsupported { filesystem } => {
                    let _skipped = Built::Unavailable(filesystem.to_string())
                        .or_skip("a volume that shares blocks");
                    None
                },
            }
        }

        fn identity_of(&self, duplicate: &Path) -> Identity {
            identity(&self.root.join(duplicate)).unwrap()
        }

        fn share(&self, duplicate: &Path) -> Result<(), Failure> {
            self.share_as(duplicate, self.identity_of(duplicate), LEN)
        }

        fn share_as(
            &self,
            duplicate: &Path,
            identified: Identity,
            len: u64,
        ) -> Result<(), Failure> {
            self.tree.share(
                self.method,
                &Request {
                    keeper: &self.keeper,
                    keeper_identity: self.keeper_identity,
                    duplicate,
                    duplicate_identity: identified,
                    len,
                },
            )
        }
    }

    fn dup() -> &'static Path {
        Path::new("sub/dup.bin")
    }

    #[test]
    fn what_is_missing_or_not_a_file_is_an_error_not_a_guess() {
        let temp = testkit::tempdir("platform-missing");
        let missing = temp.path().join("missing");
        let _absent = open_regular(&missing).unwrap_err();
        let _directory = open_regular(temp.path()).unwrap_err();
        let _unmeasured = free_space(&missing).unwrap_err();
        let _untyped = filesystem(&missing).unwrap_err();
        assert!(matches!(
            Tree::open(&missing, identity(temp.path()).unwrap()),
            Err(WalkError::Io { .. })
        ));
    }

    #[test]
    fn a_tree_opens_only_as_the_directory_it_was_cleared_as() {
        let temp = testkit::tempdir("platform-tree");
        write_patterned(&temp.path().join("one/file"), 1, 1);
        write_patterned(&temp.path().join("two/file"), 1, 1);
        let other = identity(&temp.path().join("two")).unwrap();
        match Tree::open(&temp.path().join("one"), other) {
            Err(WalkError::Moved { .. }) => {},
            Err(WalkError::Io { error, .. }) if error.kind() == io::ErrorKind::Unsupported => {
                let _skipped = Built::Unavailable(error.to_string()).or_skip("a directory tree");
            },
            Ok(_) | Err(WalkError::Boundary { .. } | WalkError::Io { .. }) => {
                panic!("a tree opened as another directory")
            },
        }
    }

    #[test]
    fn metadata_names_the_same_file_and_volume_as_a_handle() {
        let temp = testkit::tempdir("platform-identity");
        let path = temp.path().join("file");
        write_patterned(&path, 16, 1);
        let metadata = fs::symlink_metadata(&path).unwrap();
        if testkit::reports_devices() {
            let expected = identity(&path).unwrap();
            assert_eq!(identity_of_metadata(&metadata), Some(expected));
            assert_eq!(device(&metadata), Some(expected.volume));
            assert_eq!(file_measure(&path).unwrap().identity, expected);
        }
    }

    #[test]
    fn a_keeper_or_duplicate_that_is_not_the_planned_file_is_left_alone() {
        let Some(fixture) = Fixture::new("platform-changed") else {
            return;
        };
        let wrong = identity(&fixture.keeper).unwrap();
        assert_eq!(
            fixture.share_as(dup(), wrong, LEN),
            Err(Failure::DuplicateChanged)
        );
        let right = identity(&fixture.root.join(dup())).unwrap();
        assert_eq!(
            fixture.share_as(dup(), right, LEN + 1),
            Err(Failure::KeeperChanged)
        );
        assert_eq!(
            fixture.share_as(Path::new("../keeper.bin"), right, LEN),
            Err(Failure::DuplicateChanged)
        );
        assert_eq!(
            fixture.share_as(Path::new("sub/missing.bin"), right, LEN),
            Err(Failure::DuplicateChanged)
        );
        fixture.share(dup()).unwrap();
    }

    #[test]
    fn a_method_this_platform_does_not_have_shares_nothing() {
        let Some(fixture) = Fixture::new("platform-method") else {
            return;
        };
        let other = match fixture.method {
            Method::CloneAndSwap => Method::DedupeRange,
            Method::DedupeRange => Method::CloneAndSwap,
        };
        let request = Request {
            keeper: &fixture.keeper,
            keeper_identity: fixture.keeper_identity,
            duplicate: dup(),
            duplicate_identity: fixture.identity_of(dup()),
            len: LEN,
        };
        assert!(matches!(
            fixture.tree.share(other, &request),
            Err(Failure::Io { .. })
        ));
        fixture.share(dup()).unwrap();
    }

    #[test]
    fn a_duplicate_of_another_length_is_left_alone() {
        let Some(fixture) = Fixture::new("platform-length") else {
            return;
        };
        write_patterned(&fixture.root.join(dup()), LEN * 2, 1);
        assert_eq!(fixture.share(dup()), Err(Failure::DuplicateChanged));
    }

    #[test]
    fn a_duplicate_reached_through_a_link_is_left_alone() {
        let Some(fixture) = Fixture::new("platform-link") else {
            return;
        };
        let Built::Yes(_) =
            testkit::link_dir(&fixture.root.join("linked"), &fixture.root.join("sub"))
        else {
            return;
        };
        let right = identity(&fixture.root.join(dup())).unwrap();
        assert_eq!(
            fixture.share_as(Path::new("linked/dup.bin"), right, LEN),
            Err(Failure::DuplicateChanged)
        );
    }

    #[test]
    fn a_directory_that_cannot_be_opened_is_reported_not_skipped() {
        let Some(fixture) = Fixture::new("platform-sealed") else {
            return;
        };
        let right = identity(&fixture.root.join(dup())).unwrap();
        let Some(restricted) = testkit::restrict(&fixture.root.join("sub"), 0o000) else {
            return;
        };
        let result = fixture.share_as(dup(), right, LEN);
        drop(restricted);
        assert!(
            matches!(
                result,
                Err(Failure::Io {
                    step: Step::Open,
                    ..
                })
            ),
            "{result:?}"
        );
    }

    #[test]
    fn bytes_that_differ_at_the_last_moment_are_not_shared() {
        let Some(fixture) = Fixture::new("platform-differs") else {
            return;
        };
        write_patterned(&fixture.root.join(dup()), LEN, 2);
        assert_eq!(fixture.share(dup()), Err(Failure::ContentDiffers));
        assert_ne!(
            fs::read(&fixture.keeper).unwrap(),
            fs::read(fixture.root.join(dup())).unwrap()
        );
    }

    #[test]
    fn a_duplicate_a_replacement_would_change_is_refused_only_when_replacing() {
        for (name, change) in [("linked", 0), ("executable", 1)] {
            let Some(fixture) = Fixture::new(&format!("platform-{name}")) else {
                return;
            };
            let path = fixture.root.join(dup());
            let built = if change == 0 {
                testkit::hard_link(&fixture.root.join("second.bin"), &path)
            } else {
                testkit::executable(&path)
            };
            let Built::Yes(_) = built else {
                return;
            };
            let expected = match fixture.method {
                Method::CloneAndSwap => Err(Failure::DuplicateChanged),
                Method::DedupeRange => Ok(()),
            };
            assert_eq!(fixture.share(dup()), expected, "{name}");
        }
    }

    #[test]
    fn extended_attributes_that_differ_are_never_merged() {
        let Some(fixture) = Fixture::new("platform-xattr") else {
            return;
        };
        if fixture.method != Method::CloneAndSwap {
            return;
        }
        let Built::Yes(_) = testkit::set_xattr(&fixture.keeper, "storage-scout.test", "one") else {
            return;
        };
        let Built::Yes(_) =
            testkit::set_xattr(&fixture.root.join(dup()), "storage-scout.test", "two")
        else {
            return;
        };
        assert_eq!(fixture.share(dup()), Err(Failure::DuplicateChanged));
    }

    #[test]
    fn a_leftover_of_another_size_is_never_taken_for_the_original() {
        let Some(fixture) = Fixture::new("platform-leftover") else {
            return;
        };
        if fixture.method != Method::CloneAndSwap {
            return;
        }
        let leftover = fixture.root.join(format!(
            "sub/.dup.bin{}",
            storage_scout_core::share::TEMPORARY_SUFFIX
        ));
        write_patterned(&leftover, LEN / 2, 1);
        assert_eq!(fixture.share(dup()), Err(Failure::Leftover));
        testkit::assert_present(&leftover);
    }

    #[test]
    fn a_duplicate_in_another_group_keeps_its_group() {
        let Some(fixture) = Fixture::new("platform-group") else {
            return;
        };
        let path = fixture.root.join(dup());
        let Built::Yes(_) = testkit::other_group(&path) else {
            return;
        };
        let before = testkit::group_of(&path);
        fixture.share(dup()).unwrap();
        assert_eq!(testkit::group_of(&path), before);
    }
}

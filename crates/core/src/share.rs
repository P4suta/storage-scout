use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::cmp::Reverse;
use core::{fmt, ptr};

use serde::Serialize;

use crate::candidate::Identity;
use crate::location::Location;
use crate::reject::IoFailure;

pub const MINIMUM: u64 = 64 * 1024;
pub const TEMPORARY_SUFFIX: &str = ".storage-scout-share";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Filesystem {
    Apfs,
    Btrfs,
    Xfs,
    Other,
}

impl fmt::Display for Filesystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Apfs => "APFS",
            Self::Btrfs => "btrfs",
            Self::Xfs => "XFS",
            Self::Other => "this filesystem",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Method {
    CloneAndSwap,
    DedupeRange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "capability", rename_all = "kebab-case")]
pub enum Capability {
    Shares {
        filesystem: Filesystem,
        method: Method,
    },
    Unsupported {
        filesystem: Filesystem,
    },
}

impl Capability {
    #[must_use]
    pub const fn of(filesystem: Filesystem) -> Self {
        match filesystem {
            Filesystem::Apfs => Self::Shares {
                filesystem,
                method: Method::CloneAndSwap,
            },
            Filesystem::Btrfs | Filesystem::Xfs => Self::Shares {
                filesystem,
                method: Method::DedupeRange,
            },
            Filesystem::Other => Self::Unsupported { filesystem },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Owner {
    Caller,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    Plain,
    Executable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Attributes(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Extras {
    Plain(Attributes),
    Special,
    Unobserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sharing {
    Unknown,
    Cluster(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub location: Location,
    pub len: u64,
    pub identity: Identity,
    pub method: Method,
    pub links: u64,
    pub owner: Owner,
    pub mode: Mode,
    pub extras: Extras,
    pub sharing: Sharing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Family {
    Cluster(u64),
    Alone(u128),
}

impl Record {
    const fn family(&self) -> Family {
        match self.sharing {
            Sharing::Cluster(cluster) => Family::Cluster(cluster),
            Sharing::Unknown => Family::Alone(self.identity.file),
        }
    }
}

ordered! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum PairGate {
        Distinct,
        Volume,
        Size,
        Sharing,
        Owner,
        Links,
        Mode,
        Extras,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "reason", rename_all = "kebab-case")]
pub enum Refusal {
    SameFile,
    OtherVolume,
    SizeDiffers,
    NotOwned,
    HardLinked { links: u64 },
    Executable,
    Special,
    AttributesDiffer,
    Unobserved,
}

impl Refusal {
    #[must_use]
    pub const fn summary(self) -> &'static str {
        match self {
            Self::SameFile => "both names are the same file",
            Self::OtherVolume => "the files are on different volumes",
            Self::SizeDiffers => "the files differ in size",
            Self::NotOwned => "the file belongs to another user",
            Self::HardLinked { .. } => {
                "the file has other names, and replacing one would split them"
            },
            Self::Executable => "replacing an executable would make the system verify it again",
            Self::Special => "the file has flags or an ACL a replacement would drop",
            Self::AttributesDiffer => "the files differ in extended attributes",
            Self::Unobserved => "its flags, ACL, or extended attributes could not be read",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameFile => f.write_str("both names are the same file"),
            Self::OtherVolume => f.write_str("the files are on different volumes"),
            Self::SizeDiffers => f.write_str("the files differ in size"),
            Self::NotOwned => f.write_str("the file belongs to another user"),
            Self::HardLinked { links } => {
                write!(
                    f,
                    "the file has {links} names and replacing one would split them"
                )
            },
            Self::Executable => {
                f.write_str("replacing an executable would make the system verify it again")
            },
            Self::Special => f.write_str("the file has flags or an ACL a replacement would drop"),
            Self::AttributesDiffer => f.write_str("the files differ in extended attributes"),
            Self::Unobserved => {
                f.write_str("its flags, ACL, or extended attributes could not be read")
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "pairing", rename_all = "kebab-case")]
pub enum Pairing {
    Share,
    AlreadyShared,
    Refused { refusal: Refusal },
}

enum Verdict {
    Pass,
    Shared,
    Refuse(Refusal),
}

const fn replaces(method: Method) -> bool {
    match method {
        Method::CloneAndSwap => true,
        Method::DedupeRange => false,
    }
}

fn check(gate: PairGate, keeper: &Record, duplicate: &Record) -> Verdict {
    let replaced = replaces(duplicate.method);
    match gate {
        PairGate::Distinct if keeper.identity == duplicate.identity => {
            Verdict::Refuse(Refusal::SameFile)
        },
        PairGate::Volume if keeper.identity.volume != duplicate.identity.volume => {
            Verdict::Refuse(Refusal::OtherVolume)
        },
        PairGate::Size if keeper.len != duplicate.len => Verdict::Refuse(Refusal::SizeDiffers),
        PairGate::Sharing => match (keeper.sharing, duplicate.sharing) {
            (Sharing::Cluster(left), Sharing::Cluster(right)) if left == right => Verdict::Shared,
            (Sharing::Cluster(_) | Sharing::Unknown, Sharing::Cluster(_) | Sharing::Unknown) => {
                Verdict::Pass
            },
        },
        PairGate::Owner => match duplicate.owner {
            Owner::Caller => Verdict::Pass,
            Owner::Other => Verdict::Refuse(Refusal::NotOwned),
        },
        PairGate::Links if replaced && duplicate.links > 1 => {
            Verdict::Refuse(Refusal::HardLinked {
                links: duplicate.links,
            })
        },
        PairGate::Mode => match duplicate.mode {
            Mode::Executable if replaced => Verdict::Refuse(Refusal::Executable),
            Mode::Executable | Mode::Plain => Verdict::Pass,
        },
        PairGate::Extras if replaced => match (keeper.extras, duplicate.extras) {
            (Extras::Plain(left), Extras::Plain(right)) if left == right => Verdict::Pass,
            (Extras::Plain(_), Extras::Plain(_)) => Verdict::Refuse(Refusal::AttributesDiffer),
            (Extras::Special, _) | (_, Extras::Special) => Verdict::Refuse(Refusal::Special),
            (Extras::Unobserved, _) | (_, Extras::Unobserved) => {
                Verdict::Refuse(Refusal::Unobserved)
            },
        },
        PairGate::Distinct
        | PairGate::Volume
        | PairGate::Size
        | PairGate::Links
        | PairGate::Extras => Verdict::Pass,
    }
}

#[must_use]
pub fn pair(keeper: &Record, duplicate: &Record) -> Pairing {
    for gate in PairGate::ALL {
        match check(*gate, keeper, duplicate) {
            Verdict::Pass => {},
            Verdict::Shared => return Pairing::AlreadyShared,
            Verdict::Refuse(refusal) => return Pairing::Refused { refusal },
        }
    }
    Pairing::Share
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group<'a, T> {
    pub len: u64,
    pub members: Vec<&'a T>,
}

fn record<T: Borrow<Record>>(member: &T) -> &Record {
    member.borrow()
}

fn families<T: Borrow<Record>>(members: &[&T]) -> usize {
    members
        .iter()
        .map(|member| record(*member).family())
        .collect::<BTreeSet<_>>()
        .len()
}

#[must_use]
pub fn groups<T: Borrow<Record>>(items: &[T]) -> Vec<Group<'_, T>> {
    let mut by_size: BTreeMap<(u64, u64), Vec<&T>> = BTreeMap::new();
    for item in items {
        let found = record(item);
        if found.len >= MINIMUM {
            by_size
                .entry((found.identity.volume, found.len))
                .or_default()
                .push(item);
        }
    }
    by_size
        .into_iter()
        .filter(|(_, members)| families(members) > 1)
        .map(|((_, len), members)| Group { len, members })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(pub [u8; 32]);

#[must_use]
pub fn split<'a, T: Borrow<Record>>(
    group: &Group<'a, T>,
    prints: &[Option<Fingerprint>],
) -> Vec<Group<'a, T>> {
    let mut by_print: BTreeMap<Fingerprint, Vec<&'a T>> = BTreeMap::new();
    for (member, print) in group.members.iter().zip(prints) {
        if let Some(print) = print {
            by_print.entry(*print).or_default().push(*member);
        }
    }
    by_print
        .into_values()
        .filter(|members| families(members) > 1)
        .map(|members| Group {
            len: group.len,
            members,
        })
        .collect()
}

const fn fixed(found: &Record) -> bool {
    replaces(found.method)
        && (found.links > 1
            || matches!(found.mode, Mode::Executable)
            || !matches!(found.extras, Extras::Plain(_)))
}

#[must_use]
pub fn keeper<'a, T: Borrow<Record>>(group: &Group<'a, T>) -> Option<&'a T> {
    let mut sizes: BTreeMap<Family, usize> = BTreeMap::new();
    for member in &group.members {
        let count = sizes.entry(record(*member).family()).or_default();
        *count = count.saturating_add(1);
    }
    group.members.iter().copied().max_by_key(|member| {
        let found: &'a Record = record(*member);
        (
            sizes.get(&found.family()).copied(),
            fixed(found),
            Reverse(&found.location),
        )
    })
}

#[derive(Debug)]
pub struct Pair<'a, T> {
    pub keeper: &'a T,
    pub duplicate: &'a T,
    pub len: u64,
    pub pairing: Pairing,
}

#[must_use]
pub fn plan<'a, T: Borrow<Record>>(groups: &[Group<'a, T>]) -> Vec<Pair<'a, T>> {
    groups
        .iter()
        .flat_map(|group| {
            keeper(group).into_iter().flat_map(move |kept| {
                group
                    .members
                    .iter()
                    .copied()
                    .filter(move |member| !ptr::eq(*member, kept))
                    .map(move |duplicate| Pair {
                        keeper: kept,
                        duplicate,
                        len: group.len,
                        pairing: pair(record(kept), record(duplicate)),
                    })
            })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Step {
    Open,
    Inspect,
    Read,
    Clone,
    Carry,
    Swap,
    Restore,
    Unlink,
    Dedupe,
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::Inspect => "inspect",
            Self::Read => "read",
            Self::Clone => "clone",
            Self::Carry => "carry metadata",
            Self::Swap => "swap",
            Self::Restore => "restore",
            Self::Unlink => "unlink",
            Self::Dedupe => "dedupe",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "cause", rename_all = "kebab-case")]
pub enum Failure {
    KeeperChanged,
    DuplicateChanged,
    ContentDiffers,
    MetadataNotCarried,
    Leftover,
    Stranded,
    Io { step: Step, error: IoFailure },
}

impl Failure {
    #[must_use]
    pub const fn overtaken(&self) -> bool {
        match self {
            Self::KeeperChanged | Self::DuplicateChanged | Self::ContentDiffers => true,
            Self::MetadataNotCarried | Self::Leftover | Self::Stranded | Self::Io { .. } => false,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeeperChanged => f.write_str("the kept file changed since it was read"),
            Self::DuplicateChanged => f.write_str("the duplicate changed since it was read"),
            Self::ContentDiffers => f.write_str("the bytes differ"),
            Self::MetadataNotCarried => {
                f.write_str("the replacement's metadata could not be made identical")
            },
            Self::Leftover => {
                f.write_str("an earlier run left a temporary file that differs from the original")
            },
            Self::Stranded => f.write_str(
                "the original is kept under its temporary name because it could not be restored",
            ),
            Self::Io { step, error } => write!(f, "{step} failed: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec;

    use super::*;
    use crate::location::Syntax;

    #[test]
    fn only_a_file_that_changed_under_the_run_is_overtaken_rather_than_failed() {
        for failure in [
            Failure::KeeperChanged,
            Failure::DuplicateChanged,
            Failure::ContentDiffers,
        ] {
            assert!(failure.overtaken(), "{failure}");
        }
        for failure in [
            Failure::MetadataNotCarried,
            Failure::Leftover,
            Failure::Stranded,
            Failure::Io {
                step: Step::Clone,
                error: IoFailure {
                    kind: crate::reject::IoKind::Other,
                    code: None,
                },
            },
        ] {
            assert!(!failure.overtaken(), "{failure}");
        }
    }

    fn record_of(file: u128, len: u64, sharing: Sharing) -> Record {
        Record {
            location: Location::parse_str(Syntax::Unix, &format!("/work/{file}")).unwrap(),
            len,
            identity: Identity { volume: 1, file },
            method: Method::CloneAndSwap,
            links: 1,
            owner: Owner::Caller,
            mode: Mode::Plain,
            extras: Extras::Plain(Attributes([0; 16])),
            sharing,
        }
    }

    fn deduped(mut record: Record) -> Record {
        record.method = Method::DedupeRange;
        record
    }

    fn files<T: Borrow<Record>>(members: &[&T]) -> Vec<u128> {
        members
            .iter()
            .map(|member| record(*member).identity.file)
            .collect()
    }

    #[test]
    fn groups_need_two_families_of_one_size_on_one_volume() {
        let mut elsewhere = record_of(8, MINIMUM, Sharing::Unknown);
        elsewhere.identity.volume = 2;
        let records = [
            record_of(1, MINIMUM, Sharing::Unknown),
            record_of(2, MINIMUM, Sharing::Unknown),
            record_of(3, MINIMUM + 1, Sharing::Unknown),
            record_of(4, MINIMUM - 1, Sharing::Unknown),
            record_of(5, MINIMUM - 1, Sharing::Unknown),
            record_of(6, MINIMUM * 2, Sharing::Cluster(9)),
            record_of(7, MINIMUM * 2, Sharing::Cluster(9)),
            elsewhere,
        ];
        let found = groups(&records);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].len, MINIMUM);
        assert_eq!(files(&found[0].members), vec![1, 2]);
    }

    #[test]
    fn a_group_splits_by_fingerprint_and_drops_what_has_nothing_to_share() {
        let records = [
            record_of(1, MINIMUM, Sharing::Unknown),
            record_of(2, MINIMUM, Sharing::Unknown),
            record_of(3, MINIMUM, Sharing::Unknown),
            record_of(4, MINIMUM, Sharing::Unknown),
            record_of(5, MINIMUM, Sharing::Cluster(7)),
            record_of(6, MINIMUM, Sharing::Cluster(7)),
        ];
        let group = Group {
            len: MINIMUM,
            members: records.iter().collect(),
        };
        let one = Some(Fingerprint([1; 32]));
        let two = Some(Fingerprint([2; 32]));
        let three = Some(Fingerprint([3; 32]));
        let found = split(&group, &[one, two, one, None, three, three]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].len, MINIMUM);
        assert_eq!(files(&found[0].members), vec![1, 3]);
    }

    #[test]
    fn the_keeper_is_the_largest_existing_family_then_the_first_path() {
        let records = [
            record_of(3, MINIMUM, Sharing::Unknown),
            record_of(1, MINIMUM, Sharing::Cluster(7)),
            record_of(2, MINIMUM, Sharing::Cluster(7)),
            record_of(4, MINIMUM, Sharing::Cluster(8)),
        ];
        let group = Group {
            len: MINIMUM,
            members: records.iter().collect(),
        };
        assert_eq!(keeper(&group).map(|kept| kept.identity.file), Some(1));
        let alone = Group {
            len: MINIMUM,
            members: vec![&records[0], &records[3]],
        };
        assert_eq!(keeper(&alone).map(|kept| kept.identity.file), Some(3));
    }

    #[test]
    fn a_file_that_cannot_be_replaced_is_kept_so_the_others_can_be() {
        let plain = record_of(1, MINIMUM, Sharing::Unknown);
        let mut linked = record_of(2, MINIMUM, Sharing::Unknown);
        linked.links = 3;
        let group = Group {
            len: MINIMUM,
            members: vec![&plain, &linked],
        };
        let pairs = plan(&[group]);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].keeper.identity.file, 2);
        assert_eq!(pairs[0].pairing, Pairing::Share);

        let (one, two) = (deduped(plain), deduped(linked));
        let in_place = Group {
            len: MINIMUM,
            members: vec![&one, &two],
        };
        assert_eq!(keeper(&in_place).map(|kept| kept.identity.file), Some(1));
    }

    #[test]
    fn a_plan_pairs_every_other_member_with_the_keeper() {
        let records = [
            record_of(1, MINIMUM, Sharing::Cluster(7)),
            record_of(2, MINIMUM, Sharing::Cluster(7)),
            record_of(3, MINIMUM, Sharing::Cluster(8)),
        ];
        let group = Group {
            len: MINIMUM,
            members: records.iter().collect(),
        };
        let pairs = plan(&[group]);
        assert_eq!(
            pairs
                .iter()
                .map(|each| (
                    each.keeper.identity.file,
                    each.duplicate.identity.file,
                    each.len,
                    each.pairing
                ))
                .collect::<Vec<_>>(),
            vec![
                (1, 2, MINIMUM, Pairing::AlreadyShared),
                (1, 3, MINIMUM, Pairing::Share)
            ]
        );
    }

    #[test]
    fn replacing_refuses_what_a_new_inode_would_lose_and_sharing_in_place_does_not() {
        let keeper = record_of(1, MINIMUM, Sharing::Unknown);
        let mut linked = record_of(2, MINIMUM, Sharing::Unknown);
        linked.links = 2;
        let mut binary = record_of(3, MINIMUM, Sharing::Unknown);
        binary.mode = Mode::Executable;
        let mut flagged = record_of(4, MINIMUM, Sharing::Unknown);
        flagged.extras = Extras::Special;
        let mut unobserved = record_of(5, MINIMUM, Sharing::Unknown);
        unobserved.extras = Extras::Unobserved;
        let mut labelled = record_of(6, MINIMUM, Sharing::Unknown);
        labelled.extras = Extras::Plain(Attributes([1; 16]));
        for (duplicate, refusal) in [
            (&linked, Refusal::HardLinked { links: 2 }),
            (&binary, Refusal::Executable),
            (&flagged, Refusal::Special),
            (&unobserved, Refusal::Unobserved),
            (&labelled, Refusal::AttributesDiffer),
        ] {
            assert_eq!(pair(&keeper, duplicate), Pairing::Refused { refusal });
            assert_eq!(
                pair(&deduped(keeper.clone()), &deduped(duplicate.clone())),
                Pairing::Share
            );
        }
        let mut special_keeper = keeper;
        special_keeper.extras = Extras::Special;
        assert_eq!(
            pair(&special_keeper, &record_of(7, MINIMUM, Sharing::Unknown)),
            Pairing::Refused {
                refusal: Refusal::Special
            }
        );
    }

    #[test]
    fn only_the_callers_files_are_rewritten() {
        let mut foreign = record_of(2, MINIMUM, Sharing::Unknown);
        foreign.owner = Owner::Other;
        assert_eq!(
            pair(&record_of(1, MINIMUM, Sharing::Unknown), &deduped(foreign)),
            Pairing::Refused {
                refusal: Refusal::NotOwned
            }
        );
    }

    #[test]
    fn a_pair_already_sharing_is_left_and_a_file_is_not_paired_with_itself() {
        let one = record_of(1, MINIMUM, Sharing::Cluster(5));
        let two = record_of(2, MINIMUM, Sharing::Cluster(5));
        assert_eq!(pair(&one, &two), Pairing::AlreadyShared);
        assert_eq!(
            pair(&one, &one),
            Pairing::Refused {
                refusal: Refusal::SameFile
            }
        );
        let mut far = record_of(3, MINIMUM, Sharing::Unknown);
        far.identity.volume = 2;
        assert_eq!(
            pair(&one, &far),
            Pairing::Refused {
                refusal: Refusal::OtherVolume
            }
        );
        assert_eq!(
            pair(&one, &record_of(4, MINIMUM + 1, Sharing::Unknown)),
            Pairing::Refused {
                refusal: Refusal::SizeDiffers
            }
        );
    }

    #[test]
    fn only_block_sharing_filesystems_share() {
        assert!(matches!(
            Capability::of(Filesystem::Other),
            Capability::Unsupported { .. }
        ));
        assert!(matches!(
            Capability::of(Filesystem::Apfs),
            Capability::Shares {
                method: Method::CloneAndSwap,
                ..
            }
        ));
        for filesystem in [Filesystem::Btrfs, Filesystem::Xfs] {
            assert!(matches!(
                Capability::of(filesystem),
                Capability::Shares {
                    method: Method::DedupeRange,
                    ..
                }
            ));
        }
    }
}

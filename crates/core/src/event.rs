use alloc::string::String;
use alloc::vec::Vec;

use serde::Serialize;

ordered! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum Event {
        PostMerge,
        PostCheckout,
        ReferenceTransaction,
    }
}

impl Event {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PostMerge => "post-merge",
            Self::PostCheckout => "post-checkout",
            Self::ReferenceTransaction => "reference-transaction",
        }
    }

    #[must_use]
    pub const fn reads_updates(self) -> bool {
        match self {
            Self::ReferenceTransaction => true,
            Self::PostMerge | Self::PostCheckout => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub new: String,
    pub reference: String,
}

impl Update {
    fn deletes(&self) -> bool {
        !self.new.is_empty() && self.new.bytes().all(|byte| byte == b'0')
    }
}

#[must_use]
pub fn updates(input: &[u8]) -> Vec<Update> {
    String::from_utf8_lossy(input)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _old = fields.next()?;
            let new = fields.next()?;
            let reference = fields.next()?;
            Some(Update {
                new: String::from(new),
                reference: String::from(reference),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Relevance {
    Relevant,
    Irrelevant,
    NeedsDefaults,
}

#[must_use]
pub fn relevance(
    event: Event,
    arguments: &[String],
    updates: &[Update],
    defaults: Option<&[String]>,
) -> Relevance {
    match event {
        Event::PostMerge => Relevance::Relevant,
        Event::PostCheckout => match arguments.get(2).map(String::as_str) {
            Some("1") => Relevance::Relevant,
            Some(_) | None => Relevance::Irrelevant,
        },
        Event::ReferenceTransaction => {
            if arguments.first().map(String::as_str) != Some("committed") {
                return Relevance::Irrelevant;
            }
            let remote = updates
                .iter()
                .filter(|update| update.reference.starts_with("refs/remotes/"))
                .collect::<Vec<_>>();
            if remote.is_empty() {
                return Relevance::Irrelevant;
            }
            if remote.iter().any(|update| update.deletes()) {
                return Relevance::Relevant;
            }
            match defaults {
                None => Relevance::NeedsDefaults,
                Some(defaults)
                    if remote
                        .iter()
                        .any(|update| defaults.contains(&update.reference)) =>
                {
                    Relevance::Relevant
                },
                Some(_) => Relevance::Irrelevant,
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned;
    use alloc::format;
    use alloc::vec;

    use super::*;

    const ZERO: &str = "0000000000000000000000000000000000000000";
    const SHA: &str = "1111111111111111111111111111111111111111";

    fn committed() -> Vec<String> {
        vec!["committed".to_owned()]
    }

    #[test]
    fn a_merge_is_always_relevant_and_a_file_checkout_never_is() {
        assert_eq!(
            relevance(Event::PostMerge, &[], &[], None),
            Relevance::Relevant
        );
        let branch = ["a", "b", "1"].map(String::from);
        let file = ["a", "b", "0"].map(String::from);
        assert_eq!(
            relevance(Event::PostCheckout, &branch, &[], None),
            Relevance::Relevant
        );
        assert_eq!(
            relevance(Event::PostCheckout, &file, &[], None),
            Relevance::Irrelevant
        );
    }

    #[test]
    fn only_committed_remote_transactions_matter() {
        let local = updates(format!("{ZERO} {SHA} refs/heads/feat\n").as_bytes());
        assert_eq!(
            relevance(Event::ReferenceTransaction, &committed(), &local, None),
            Relevance::Irrelevant
        );
        let prepared = vec!["prepared".to_owned()];
        let remote = updates(format!("{ZERO} {SHA} refs/remotes/origin/main\n").as_bytes());
        assert_eq!(
            relevance(Event::ReferenceTransaction, &prepared, &remote, None),
            Relevance::Irrelevant
        );
    }

    #[test]
    fn a_pruned_remote_branch_is_relevant_without_asking_git() {
        let pruned = updates(format!("{SHA} {ZERO} refs/remotes/origin/feat\n").as_bytes());
        assert_eq!(
            relevance(Event::ReferenceTransaction, &committed(), &pruned, None),
            Relevance::Relevant
        );
    }

    #[test]
    fn a_moved_remote_branch_matters_only_when_it_is_a_default_branch() {
        let moved = updates(format!("{ZERO} {SHA} refs/remotes/origin/main\n").as_bytes());
        assert_eq!(
            relevance(Event::ReferenceTransaction, &committed(), &moved, None),
            Relevance::NeedsDefaults
        );
        let defaults = vec!["refs/remotes/origin/main".to_owned()];
        assert_eq!(
            relevance(
                Event::ReferenceTransaction,
                &committed(),
                &moved,
                Some(&defaults)
            ),
            Relevance::Relevant
        );
        let other = updates(format!("{ZERO} {SHA} refs/remotes/origin/feat\n").as_bytes());
        assert_eq!(
            relevance(
                Event::ReferenceTransaction,
                &committed(),
                &other,
                Some(&defaults)
            ),
            Relevance::Irrelevant
        );
    }
}

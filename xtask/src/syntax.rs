use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Finding {
    pub line: usize,
    pub rule: &'static str,
}

struct Restriction {
    segments: &'static [&'static str],
    allowed: &'static [&'static str],
    rule: &'static str,
}

const PLATFORM: &[&str] = &["crates/cli/src/platform.rs", "crates/cli/src/platform/"];
const CAPABILITY: &[&str] = &[
    "crates/cli/src/platform.rs",
    "crates/cli/src/platform/",
    "crates/cli/src/apply/capability.rs",
];

const RESTRICTIONS: &[Restriction] = &[
    Restriction {
        segments: &["remove_tree"],
        allowed: CAPABILITY,
        rule: "only apply::capability may remove a tree, and only with an Authorized",
    },
    Restriction {
        segments: &["Authorized"],
        allowed: &[
            "crates/cli/src/apply.rs",
            "crates/cli/src/apply/capability.rs",
        ],
        rule: "only apply may hold a deletion capability",
    },
    Restriction {
        segments: &["Shareable"],
        allowed: &[
            "crates/cli/src/dedupe.rs",
            "crates/cli/src/dedupe/capability.rs",
        ],
        rule: "only dedupe may hold a sharing capability",
    },
    Restriction {
        segments: &["Tree"],
        allowed: &[
            "crates/cli/src/platform.rs",
            "crates/cli/src/platform/",
            "crates/cli/src/dedupe/capability.rs",
        ],
        rule: "only dedupe::capability may rewrite files inside a tree, and only with a Shareable",
    },
    Restriction {
        segments: &["clear_share"],
        allowed: &["crates/cli/src/dedupe.rs"],
        rule: "sharing is cleared in one place",
    },
    Restriction {
        segments: &["Prunable"],
        allowed: &[
            "crates/cli/src/prune.rs",
            "crates/cli/src/prune/capability.rs",
        ],
        rule: "only prune may hold a pruning capability",
    },
    Restriction {
        segments: &["Pruning"],
        allowed: &[
            "crates/cli/src/platform.rs",
            "crates/cli/src/platform/",
            "crates/cli/src/prune/capability.rs",
        ],
        rule: "only prune::capability may remove files inside a cache, and only with a Prunable",
    },
    Restriction {
        segments: &["clear_prune"],
        allowed: &["crates/cli/src/prune.rs"],
        rule: "pruning is cleared in one place",
    },
    Restriction {
        segments: &["unlinkat"],
        allowed: PLATFORM,
        rule: "system calls that delete live only in platform",
    },
    Restriction {
        segments: &["futimens"],
        allowed: PLATFORM,
        rule: "timestamps are only carried, and only by platform",
    },
    Restriction {
        segments: &["fchown"],
        allowed: PLATFORM,
        rule: "system calls that change ownership live only in platform",
    },
    Restriction {
        segments: &["fclonefileat"],
        allowed: PLATFORM,
        rule: "system calls that share blocks live only in platform",
    },
    Restriction {
        segments: &["renameatx_np"],
        allowed: PLATFORM,
        rule: "system calls that swap files live only in platform",
    },
    Restriction {
        segments: &["ioctl"],
        allowed: PLATFORM,
        rule: "device controls live only in platform",
    },
    Restriction {
        segments: &["fchmod"],
        allowed: PLATFORM,
        rule: "system calls that change permissions live only in platform",
    },
    Restriction {
        segments: &["remove_file"],
        allowed: &[
            "crates/cli/src/platform.rs",
            "crates/cli/src/platform/",
            "crates/cli/src/store.rs",
        ],
        rule: "deleting files lives only in platform and in the store's own files",
    },
    Restriction {
        segments: &["fs", "rename"],
        allowed: &["crates/cli/src/store.rs"],
        rule: "replacing files lives only in the store",
    },
    Restriction {
        segments: &["remove_dir"],
        allowed: PLATFORM,
        rule: "deleting directories lives only in platform",
    },
    Restriction {
        segments: &["remove_dir_all"],
        allowed: &[],
        rule: "a recursive delete that follows the path is never used; platform walks by handle",
    },
    Restriction {
        segments: &["set_permissions"],
        allowed: PLATFORM,
        rule: "changing permissions lives only in platform",
    },
    Restriction {
        segments: &["process", "Command"],
        allowed: &[
            "crates/cli/src/observe/git.rs",
            "crates/cli/src/platform/spawn.rs",
        ],
        rule: "processes start only through observe::git and platform::spawn",
    },
    Restriction {
        segments: &["toml", "from_str"],
        allowed: &["crates/cli/src/ingress.rs"],
        rule: "untrusted input is decoded only in ingress",
    },
    Restriction {
        segments: &["serde_json", "from_str"],
        allowed: &["crates/cli/src/ingress.rs"],
        rule: "untrusted input is decoded only in ingress",
    },
    Restriction {
        segments: &["serde_json", "from_slice"],
        allowed: &["crates/cli/src/ingress.rs"],
        rule: "untrusted input is decoded only in ingress",
    },
    Restriction {
        segments: &["serde_json", "from_reader"],
        allowed: &["crates/cli/src/ingress.rs"],
        rule: "untrusted input is decoded only in ingress",
    },
    Restriction {
        segments: &["OpenOptions"],
        allowed: &["crates/cli/src/store.rs"],
        rule: "files storage-scout writes are opened only in store",
    },
    Restriction {
        segments: &["create_dir_all"],
        allowed: &["crates/cli/src/store.rs"],
        rule: "directories storage-scout creates are made only in store",
    },
];

const BANNED_SERDE: &[&str] = &["untagged", "flatten", "default", "alias", "other"];

fn line(span: Span) -> usize {
    span.start().line
}

fn allowed(file: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| file.starts_with(prefix))
}

fn contains_run(haystack: &[String], needle: &[&str]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window.iter().zip(needle).all(|(have, want)| have == want))
}

struct Gate<'a> {
    file: &'a str,
    tests: usize,
    findings: Vec<Finding>,
}

impl Gate<'_> {
    fn flag(&mut self, span: Span, rule: &'static str) {
        self.findings.push(Finding {
            line: line(span),
            rule,
        });
    }

    fn check_segments(&mut self, segments: &[String], span: Span) {
        if self.tests > 0 {
            return;
        }
        for restriction in RESTRICTIONS {
            if contains_run(segments, restriction.segments)
                && !allowed(self.file, restriction.allowed)
            {
                self.flag(span, restriction.rule);
            }
        }
    }

    fn check_serde(&mut self, attrs: &[syn::Attribute]) {
        for attr in attrs.iter().filter(|attr| attr.path().is_ident("serde")) {
            let syn::Meta::List(list) = &attr.meta else {
                continue;
            };
            let text = list.tokens.to_string();
            for part in text.split(',') {
                let key = part
                    .trim()
                    .chars()
                    .take_while(|character| character.is_alphanumeric() || *character == '_')
                    .collect::<String>();
                if BANNED_SERDE.contains(&key.as_str()) {
                    self.flag(
                        attr.span(),
                        "serde attributes that guess or merge shapes are banned",
                    );
                }
            }
        }
    }
}

fn is_test_attribute(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string() == "test"))
    })
}

impl<'ast> Visit<'ast> for Gate<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let test = is_test_attribute(&item.attrs);
        self.tests = self.tests.saturating_add(usize::from(test));
        visit::visit_item_mod(self, item);
        self.tests = self.tests.saturating_sub(usize::from(test));
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if item.sig.unsafety.is_some() && !allowed(self.file, PLATFORM) {
            self.flag(item.sig.span(), "unsafe code lives only in platform");
        }
        let test = is_test_attribute(&item.attrs);
        self.tests = self.tests.saturating_add(usize::from(test));
        visit::visit_item_fn(self, item);
        self.tests = self.tests.saturating_sub(usize::from(test));
    }

    fn visit_expr_unsafe(&mut self, expr: &'ast syn::ExprUnsafe) {
        if !allowed(self.file, PLATFORM) {
            self.flag(expr.span(), "unsafe code lives only in platform");
        }
        visit::visit_expr_unsafe(self, expr);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if item.unsafety.is_some() {
            self.flag(item.span(), "unsafe impls are not written");
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        self.check_segments(&segments, path.span());
        visit::visit_path(self, path);
    }

    fn visit_use_tree(&mut self, tree: &'ast syn::UseTree) {
        let mut segments = Vec::new();
        flatten(tree, &mut segments, &mut |full: &[String]| {
            self.check_segments(full, tree.span());
        });
        visit::visit_use_tree(self, tree);
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        self.check_serde(std::slice::from_ref(attr));
        visit::visit_attribute(self, attr);
    }
}

fn flatten(tree: &syn::UseTree, prefix: &mut Vec<String>, found: &mut dyn FnMut(&[String])) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten(&path.tree, prefix, found);
            prefix.pop();
        },
        syn::UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            found(prefix);
            prefix.pop();
        },
        syn::UseTree::Rename(rename) => {
            prefix.push(rename.ident.to_string());
            found(prefix);
            prefix.pop();
        },
        syn::UseTree::Glob(_) => found(prefix),
        syn::UseTree::Group(group) => {
            for item in &group.items {
                flatten(item, prefix, found);
            }
        },
    }
}

pub(crate) fn check(source: &str, file: &str) -> Result<Vec<Finding>, syn::Error> {
    let parsed = syn::parse_file(source)?;
    let mut gate = Gate {
        file,
        tests: usize::from(file.contains("/tests/") || file.starts_with("crates/testkit/")),
        findings: Vec::new(),
    };
    gate.visit_file(&parsed);
    gate.findings.sort_by_key(|finding| finding.line);
    gate.findings.dedup();
    Ok(gate.findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(source: &str, file: &str) -> Vec<&'static str> {
        check(source, file)
            .unwrap()
            .into_iter()
            .map(|finding| finding.rule)
            .collect()
    }

    #[test]
    fn removal_outside_the_capability_is_flagged() {
        assert!(
            !rules(
                "fn f() { platform::remove_tree(); }",
                "crates/cli/src/scan.rs"
            )
            .is_empty()
        );
        assert!(
            rules(
                "fn f() { platform::remove_tree(); }",
                "crates/cli/src/apply/capability.rs"
            )
            .is_empty()
        );
        assert!(
            !rules(
                "use std::fs::remove_dir_all;",
                "crates/cli/src/platform/unix.rs"
            )
            .is_empty()
        );
    }

    #[test]
    fn unsafe_outside_platform_is_flagged() {
        assert!(!rules("fn f() { unsafe { g() } }", "crates/cli/src/scan.rs").is_empty());
        assert!(
            rules(
                "fn f() { unsafe { g() } }",
                "crates/cli/src/platform/unix.rs"
            )
            .is_empty()
        );
    }

    #[test]
    fn decoding_outside_ingress_is_flagged() {
        assert!(
            !rules(
                "fn f() { toml::from_str::<T>(s); }",
                "crates/cli/src/auto.rs"
            )
            .is_empty()
        );
        assert!(
            rules(
                "fn f() { toml::from_str::<T>(s); }",
                "crates/cli/src/ingress.rs"
            )
            .is_empty()
        );
    }

    #[test]
    fn guessing_serde_attributes_are_flagged() {
        assert!(!rules("#[serde(untagged)] enum E { A }", "crates/core/src/x.rs").is_empty());
        assert!(
            !rules(
                "struct S { #[serde(default)] a: u8 }",
                "crates/core/src/x.rs"
            )
            .is_empty()
        );
        assert!(
            rules(
                "#[serde(tag = \"kind\")] enum E { A }",
                "crates/core/src/x.rs"
            )
            .is_empty()
        );
    }

    #[test]
    fn test_modules_may_use_restricted_paths() {
        assert!(
            rules(
                "#[cfg(test)] mod tests { fn f() { toml::from_str::<T>(s); } }",
                "crates/cli/src/auto.rs"
            )
            .is_empty()
        );
    }
}

mod ingress;
pub(crate) mod runner;

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Result, ensure};
use syn::visit::{self, Visit};

#[derive(Default)]
struct Public {
    scope: Option<String>,
    symbols: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for Public {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if item.ident != "tests" && item.ident != "proofs" {
            visit::visit_item_mod(self, item);
        }
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let previous = self.scope.take();
        if let syn::Type::Path(path) = item.self_ty.as_ref() {
            self.scope = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
        }
        visit::visit_item_impl(self, item);
        self.scope = previous;
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if matches!(item.vis, syn::Visibility::Public(_)) {
            let name = match &self.scope {
                Some(scope) => format!("{scope}::{}", item.sig.ident),
                None => item.sig.ident.to_string(),
            };
            self.symbols.insert(name);
        }
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if matches!(item.vis, syn::Visibility::Public(_)) {
            self.symbols.insert(item.sig.ident.to_string());
        }
    }
}

pub(crate) fn inventory(root: &Path) -> Result<()> {
    const MODULES: [&str; 9] = [
        "crates/core/src/managed.rs",
        "crates/core/src/artifact.rs",
        "crates/core/src/gate.rs",
        "crates/core/src/ownership.rs",
        "crates/core/src/share.rs",
        "crates/core/src/prune.rs",
        "crates/core/src/select.rs",
        "crates/core/src/lock.rs",
        "crates/core/src/size.rs",
    ];
    let _miri = ingress::miri_toolchain(root)?;
    let config = ingress::inventory(root)?;
    ensure!(
        !config.harnesses.is_empty() && !config.modules.is_empty(),
        "empty assurance inventory"
    );
    let harnesses = config.harnesses.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        config
            .modules
            .iter()
            .map(|module| module.path.as_str())
            .collect::<BTreeSet<_>>()
            == BTreeSet::from(MODULES),
        "missing required decision modules"
    );
    ensure!(
        harnesses.len() == config.harnesses.len(),
        "duplicate proof inventory"
    );
    for module in config.modules {
        ensure!(
            !module.domain.is_empty() && !module.harnesses.is_empty(),
            "unassessed module {}",
            module.path
        );
        ensure!(
            module
                .harnesses
                .iter()
                .all(|harness| harnesses.contains(harness)),
            "unknown proof owner in {}",
            module.path
        );
        let source = syn::parse_file(&fs::read_to_string(root.join(&module.path))?)?;
        let mut public = Public::default();
        public.visit_file(&source);
        ensure!(
            public.symbols == module.symbols.iter().cloned().collect(),
            "public decision inventory changed in {}: {:?}",
            module.path,
            public.symbols
        );
    }
    for target in ["core_parsers", "auto_policy"] {
        ensure!(
            fs::read_dir(root.join("fuzz/corpus").join(target))?
                .next()
                .is_some(),
            "empty parser corpus {target}"
        );
        ensure!(
            fs::metadata(root.join("fuzz/fuzz_targets").join(format!("{target}.rs")))?.is_file(),
            "missing fuzz target {target}"
        );
    }
    ensure!(
        fs::metadata(root.join("specs/cleanup.qnt"))?.is_file(),
        "missing protocol model"
    );
    Ok(())
}

pub(crate) fn run(root: &Path, out: &mut dyn Write) -> Result<()> {
    inventory(root)?;
    runner::run(root, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions report a violated discovery contract"
    )]
    fn discovery_tracks_methods_and_functions_but_not_fixtures() -> Result<()> {
        let source = syn::parse_file(
            "pub fn decide() {} impl Policy { pub fn eligible() {} fn hidden() {} } #[cfg(test)] mod tests { pub fn fixture() {} }",
        )?;
        let mut public = Public::default();
        public.visit_file(&source);
        assert_eq!(
            public.symbols,
            BTreeSet::from(["decide".to_owned(), "Policy::eligible".to_owned()])
        );
        Ok(())
    }
}

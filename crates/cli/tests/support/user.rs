use std::fs;
use std::path::Path;
use std::process::{Command, Output};

pub(crate) fn run(args: &[&str], home: &Path) -> Output {
    let temporary = home.join("temporary");
    fs::create_dir_all(&temporary).unwrap();
    Command::new(env!("CARGO_BIN_EXE_storage-scout"))
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("RUSTUP_HOME", home.join(".rustup"))
        .env_remove("RUSTUP_TOOLCHAIN")
        .env("MISE_DATA_DIR", home.join("mise-data"))
        .env("MISE_STATE_DIR", home.join("mise-state"))
        .env("MISE_CACHE_DIR", home.join("mise-cache"))
        .env("MISE_CONFIG_DIR", home.join(".config/mise"))
        .env(
            "MISE_GLOBAL_CONFIG_FILE",
            home.join(".config/mise/config.toml"),
        )
        .env("MISE_GLOBAL_CONFIG_ROOT", home)
        .env("MISE_SYSTEM_CONFIG_FILE", home.join("mise-system.toml"))
        .env_remove("MISE_CONFIG_FILE")
        .env_remove("MISE_EXTRA_CONFIG_FILES")
        .env("LOCALAPPDATA", home.join("AppData/Local"))
        .env("APPDATA", home.join("AppData/Roaming"))
        .env("TMPDIR", &temporary)
        .env("TMP", &temporary)
        .env("TEMP", &temporary)
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env("GIT_CEILING_DIRECTORIES", testkit::ceiling())
        .env("STORAGE_SCOUT_STATE_DIR", home.join("coordination"))
        .output()
        .unwrap()
}

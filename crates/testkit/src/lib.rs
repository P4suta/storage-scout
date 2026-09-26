#![expect(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "fixtures build real trees; a fixture that cannot be built is a broken test"
)]

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use storage_scout_core::area::{Protection, Rule};
use storage_scout_core::location::Location;
use storage_scout_core::platform::Platform;

pub const CACHE_TAG: &[u8] = b"Signature: 8a477f597d28d172789f06886806bc55\n# storage-scout test";
const MOUNT_MARKER: &str = ".storage-scout-scratch-mount";
const RECLAIM_LIMIT: usize = 8;

#[must_use]
#[derive(Debug)]
pub struct Scratch(Option<tempfile::TempDir>);

impl Scratch {
    #[must_use]
    pub fn path(&self) -> &Path {
        self.0
            .as_ref()
            .map_or_else(|| Path::new(""), tempfile::TempDir::path)
    }
}

#[cfg(unix)]
fn writable(directory: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(metadata) = fs::symlink_metadata(directory) else {
        return;
    };
    if !metadata.is_dir() {
        return;
    }
    let _opened = fs::set_permissions(directory, fs::Permissions::from_mode(0o700));
    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            writable(&entry.path());
        }
    }
}

#[cfg(not(unix))]
const fn writable(_directory: &Path) {}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Some(temp) = self.0.take() {
            writable(temp.path());
            drop(temp);
        }
    }
}

const SCRATCH: &str = ".storage-scout-tests";
const SCRATCH_OWNER: &str = r#"{"schema": "storage-scout-temp-owner-v1", "pid": 0, "started": "tests", "kept": true, "role": "scratch"}"#;

static HELD: std::sync::OnceLock<File> = std::sync::OnceLock::new();

#[must_use]
pub fn ceiling() -> PathBuf {
    let scratch = std::env::current_dir()
        .expect("a current directory")
        .join(SCRATCH);
    let _held = HELD.get_or_init(|| {
        fs::create_dir_all(&scratch).expect("the tests' scratch directory");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(scratch.join("owner.lock"))
            .expect("the tests' owner lock");
        lock.lock_shared()
            .expect("a share of the tests' owner lock");
        let marker = scratch.join("owner.json");
        if fs::symlink_metadata(&marker).is_err() {
            let staged = scratch.join(format!("owner.json.{}", std::process::id()));
            fs::write(&staged, SCRATCH_OWNER).expect("the tests' owner marker");
            fs::rename(&staged, &marker).expect("the tests' owner marker in place");
        }
        lock
    });
    scratch
}

pub fn tempdir(prefix: &str) -> Scratch {
    Scratch(Some(
        tempfile::Builder::new()
            .prefix(&format!(".storage-scout-{prefix}-"))
            .tempdir_in(ceiling())
            .expect("a temporary directory inside the repository"),
    ))
}

fn locate(path: &Path) -> Location {
    let canonical = fs::canonicalize(path).expect("a canonical path");
    Location::parse(
        Platform::HOST.syntax(),
        canonical.as_os_str().as_encoded_bytes(),
    )
    .expect("a nameable path")
}

#[must_use]
pub fn protection(rules: Vec<Rule>) -> Protection {
    let cwd = locate(&std::env::current_dir().expect("a current directory"));
    let exe = locate(&std::env::current_exe().expect("the running test binary"));
    Protection::new(
        Platform::HOST.syntax(),
        Platform::HOST.case(),
        cwd,
        exe,
        rules,
    )
    .expect("a protection in the host syntax")
}

#[must_use]
pub fn protection_at(cwd: &Path, rules: Vec<Rule>) -> Protection {
    let exe = locate(&std::env::current_exe().expect("the running test binary"));
    Protection::new(
        Platform::HOST.syntax(),
        Platform::HOST.case(),
        locate(cwd),
        exe,
        rules,
    )
    .expect("a protection in the host syntax")
}

#[must_use]
pub fn open_protection() -> Protection {
    protection(Vec::new())
}

#[track_caller]
pub fn assert_present(path: impl AsRef<Path>) {
    fs::symlink_metadata(path.as_ref()).expect("the path must still exist");
}

#[track_caller]
pub fn assert_absent(path: impl AsRef<Path>) {
    let path = path.as_ref();
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => panic!("{} is unreadable, not absent: {error}", path.display()),
        Ok(_) => panic!("{} must be gone", path.display()),
    }
}

#[must_use]
pub fn location(path: &Path) -> Location {
    locate(path)
}

pub fn write_sized(path: &Path, size: u64) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent directories");
    }
    let size = usize::try_from(size).expect("a fixture small enough to hold in memory");
    fs::write(path, vec![b'x'; size]).expect("a sized file");
}

pub fn write_bytes(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent directories");
    }
    fs::write(path, bytes).expect("a file with the given bytes");
}

pub fn make_dir(path: &Path) {
    fs::create_dir_all(path).expect("a fixture directory");
}

pub fn remove_file(path: &Path) {
    fs::remove_file(path).expect("a removed file");
}

pub fn remove_tree(path: &Path) {
    fs::remove_dir_all(path).expect("a fixture tree that can be removed");
}

pub fn replace_file(path: &Path, bytes: &[u8]) {
    let mut staged = path.as_os_str().to_owned();
    staged.push(".replacement");
    fs::write(&staged, bytes).expect("a replacement");
    fs::rename(&staged, path).expect("the replacement takes the name");
}

pub fn write_patterned(path: &Path, size: u64, seed: u8) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent directories");
    }
    let size = usize::try_from(size).expect("a fixture small enough to hold in memory");
    let bytes = (0..size)
        .map(|index| u8::try_from(index.wrapping_rem(251)).expect("a remainder below 251") ^ seed)
        .collect::<Vec<_>>();
    fs::write(path, bytes).expect("a patterned file");
}

pub fn write_cache_tag(directory: &Path) {
    fs::create_dir_all(directory).expect("the cache directory");
    fs::write(directory.join("CACHEDIR.TAG"), CACHE_TAG).expect("a cache tag");
}

pub fn write_declared_target(directory: &Path, profile: &str) {
    fs::create_dir_all(directory.join(profile)).expect("a profile directory");
    fs::write(directory.join(".rustc_info.json"), b"{}").expect("a rustc info file");
}

#[must_use]
pub fn write_cargo_project(project: &Path, payload: u64) -> PathBuf {
    write_sized(&project.join("Cargo.toml"), 1);
    let target = project.join("target");
    write_sized(&target.join("debug/app"), payload);
    target
}

#[derive(Debug)]
pub enum Built {
    Yes(PathBuf),
    Unavailable(String),
}

impl Built {
    fn resolve(self, what: &str, notice: Option<&OsStr>) -> Option<PathBuf> {
        match self {
            Self::Yes(path) => Some(path),
            Self::Unavailable(reason) => {
                let skipped = format!("skipping: cannot create {what} here ({reason})\n");
                std::io::Write::write_all(&mut std::io::stderr(), skipped.as_bytes())
                    .expect("stderr is writable");
                report_decline(notice, what);
                None
            },
        }
    }

    #[must_use]
    pub fn or_skip(self, what: &str) -> Option<PathBuf> {
        self.resolve(what, None)
    }

    #[must_use]
    pub fn or_decline(self, why: &str) -> Option<PathBuf> {
        let notice = std::env::var_os("RUST_MUTANTS_DECLINE_NOTICE");
        self.resolve(why, notice.as_deref())
    }
}

fn report_decline(notice: Option<&OsStr>, why: &str) {
    let Some(path) = notice else {
        return;
    };
    assert!(!why.contains(['\t', '\n']), "a stable single-line reason");
    let thread = std::thread::current();
    let name = thread.name().expect("a test thread has a name");
    let line = format!("{name}\t{why}\n");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("the decline notice is writable");
    let written = std::io::Write::write(&mut file, line.as_bytes())
        .expect("the decline notice accepts one line");
    assert_eq!(written, line.len(), "the decline notice accepts one line");
}

pub fn decline(why: &str) {
    let notice = std::env::var_os("RUST_MUTANTS_DECLINE_NOTICE");
    report_decline(notice.as_deref(), why);
}

#[must_use]
pub fn link_dir(link: &Path, target: &Path) -> Built {
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent).expect("parent directories");
    }
    #[cfg(unix)]
    {
        match std::os::unix::fs::symlink(target, link) {
            Ok(()) => Built::Yes(link.to_path_buf()),
            Err(error) => Built::Unavailable(error.to_string()),
        }
    }
    #[cfg(windows)]
    {
        let quote = |path: &Path| path.display().to_string().replace('\'', "''");
        let script = format!(
            "New-Item -ItemType Junction -Path '{}' -Target '{}' | Out-Null",
            quote(link),
            quote(target)
        );
        match Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
        {
            Ok(status) if status.success() => Built::Yes(link.to_path_buf()),
            Ok(status) => Built::Unavailable(format!("New-Item exited with {status}")),
            Err(error) => Built::Unavailable(error.to_string()),
        }
    }
}

#[must_use]
pub fn symlink_file(link: &Path, target: &Path) -> Built {
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent).expect("parent directories");
    }
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(target, link);
    match made {
        Ok(()) => Built::Yes(link.to_path_buf()),
        Err(error) => Built::Unavailable(error.to_string()),
    }
}

fn command_built(path: &Path, program: &str, args: &[&str]) -> Built {
    match Command::new(program).args(args).arg(path).status() {
        Ok(status) if status.success() => Built::Yes(path.to_path_buf()),
        Ok(status) => Built::Unavailable(format!("{program} exited with {status}")),
        Err(error) => Built::Unavailable(format!("{program}: {error}")),
    }
}

#[must_use]
pub fn set_xattr(path: &Path, name: &str, value: &str) -> Built {
    if cfg!(target_os = "macos") {
        command_built(path, "xattr", &["-w", name, value])
    } else if cfg!(target_os = "linux") {
        let name = format!("user.{name}");
        command_built(path, "setfattr", &["-n", &name, "-v", value])
    } else {
        Built::Unavailable(String::from("no extended attribute tool on this platform"))
    }
}

#[cfg(unix)]
#[must_use]
#[expect(clippy::unnecessary_wraps, reason = "only Unix files have a group")]
pub fn group_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(
        fs::metadata(path)
            .expect("a file to read the group of")
            .gid(),
    )
}

#[cfg(not(unix))]
#[must_use]
pub const fn group_of(_path: &Path) -> Option<u32> {
    None
}

#[must_use]
pub fn shares_extents(path: &Path) -> Option<bool> {
    let output = Command::new("filefrag").arg("-v").arg(path).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).contains("shared"))
}

#[must_use]
pub fn other_group(path: &Path) -> Built {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current = match fs::metadata(path) {
            Ok(metadata) => metadata.gid().to_string(),
            Err(error) => return Built::Unavailable(error.to_string()),
        };
        let groups = match Command::new("id").arg("-G").output() {
            Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
            Err(error) => return Built::Unavailable(error.to_string()),
        };
        match groups.split_whitespace().find(|group| *group != current) {
            Some(group) => command_built(path, "chgrp", &[group]),
            None => Built::Unavailable(String::from("this user belongs to one group")),
        }
    }
    #[cfg(not(unix))]
    {
        Built::Unavailable(format!("{} has no group on this platform", path.display()))
    }
}

#[must_use]
pub fn hard_link(link: &Path, target: &Path) -> Built {
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent).expect("parent directories");
    }
    match fs::hard_link(target, link) {
        Ok(()) => Built::Yes(link.to_path_buf()),
        Err(error) => Built::Unavailable(error.to_string()),
    }
}

#[must_use]
pub fn watches_subtrees() -> bool {
    let whole = cfg!(any(target_os = "macos", windows));
    if !whole {
        let _skipped = Built::Unavailable(String::from("inotify watches one directory at a time"))
            .or_decline("a watcher that reports every directory below a root");
    }
    whole
}

#[must_use]
pub const fn reports_devices() -> bool {
    cfg!(unix)
}

#[must_use]
pub fn executable(path: &Path) -> Built {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = match fs::metadata(path) {
            Ok(metadata) => metadata.permissions(),
            Err(error) => return Built::Unavailable(error.to_string()),
        };
        permissions.set_mode(0o755);
        match fs::set_permissions(path, permissions) {
            Ok(()) => Built::Yes(path.to_path_buf()),
            Err(error) => Built::Unavailable(error.to_string()),
        }
    }
    #[cfg(not(unix))]
    {
        Built::Unavailable(format!(
            "{} has no executable bit on this platform",
            path.display()
        ))
    }
}

#[must_use]
#[derive(Debug)]
pub struct Restricted {
    path: PathBuf,
    #[cfg(unix)]
    mode: u32,
}

impl Drop for Restricted {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode))
                .expect("the original mode restored");
        }
    }
}

impl Restricted {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[must_use]
pub fn restrict(path: &Path, mode: u32) -> Option<Restricted> {
    let skipped = |reason: String| {
        let _skipped = Built::Unavailable(reason).or_skip("a restricted path");
        None
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let original = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata.permissions().mode() & 0o7777,
            Err(error) => return skipped(error.to_string()),
        };
        if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
            return skipped(error.to_string());
        }
        let restricted = Restricted {
            path: path.to_path_buf(),
            mode: original,
        };
        let honoured = if mode & 0o400 == 0 {
            if path.is_dir() {
                fs::read_dir(path).is_err()
            } else {
                File::open(path).is_err()
            }
        } else {
            fs::write(path.join(".storage-scout-probe"), b"").is_err()
        };
        if honoured {
            Some(restricted)
        } else {
            drop(restricted);
            skipped(String::from("this user is not bound by file modes"))
        }
    }
    #[cfg(not(unix))]
    {
        skipped(format!(
            "{} cannot take mode {mode:o} on this platform",
            path.display()
        ))
    }
}

#[must_use]
pub fn sparse_file(path: &Path, logical_len: u64) -> Built {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent directories");
    }
    let file = match File::create(path) {
        Ok(file) => file,
        Err(error) => return Built::Unavailable(error.to_string()),
    };
    #[cfg(windows)]
    {
        match Command::new("fsutil")
            .args(["sparse", "setflag", &path.display().to_string()])
            .status()
        {
            Ok(status) if status.success() => {},
            Ok(status) => return Built::Unavailable(format!("fsutil exited with {status}")),
            Err(error) => return Built::Unavailable(error.to_string()),
        }
    }
    if let Err(error) = file.set_len(logical_len) {
        return Built::Unavailable(error.to_string());
    }
    drop(file);
    match occupied_bytes(path) {
        Some(occupied) if occupied < logical_len => Built::Yes(path.to_path_buf()),
        Some(occupied) => Built::Unavailable(format!(
            "this filesystem allocated all {logical_len} bytes ({occupied} occupied)"
        )),
        None => Built::Unavailable("cannot read the occupied size".to_owned()),
    }
}

#[must_use]
pub fn occupied_bytes(path: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match fs::symlink_metadata(path) {
            Ok(metadata) => Some(metadata.blocks().saturating_mul(512)),
            Err(_unreadable) => None,
        }
    }
    #[cfg(windows)]
    {
        let output = match Command::new("fsutil")
            .args(["sparse", "queryflag", &path.display().to_string()])
            .output()
        {
            Ok(output) => output,
            Err(_unavailable) => return None,
        };
        String::from_utf8_lossy(&output.stdout)
            .contains("is set")
            .then_some(0)
    }
}

#[derive(Debug)]
pub struct Mount {
    pub path: PathBuf,
    detach: Vec<Vec<String>>,
}

impl Drop for Mount {
    fn drop(&mut self) {
        for command in &self.detach {
            if let Some((program, args)) = command.split_first() {
                match Command::new(program)
                    .args(args)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                {
                    Ok(_) | Err(_) => {},
                }
            }
        }
    }
}

fn detach_in_background(program: &str, args: &[&str]) {
    match Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => drop(child),
        Err(_unavailable) => {},
    }
}

fn alive(pid: u32) -> bool {
    match Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) => status.success(),
        Err(_unavailable) => true,
    }
}

fn output(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout).into_owned(),
        Err(_unavailable) => String::new(),
    }
}

pub fn release_abandoned_mounts() {
    let mounted = output("mount", &[]);
    let abandoned = mounted
        .lines()
        .filter_map(|line| {
            let point = line.split_once(" on ")?.1.rsplit_once(" (")?.0;
            let (_, rest) = point.rsplit_once(MOUNT_MARKER)?;
            let pid = rest
                .trim_start_matches('-')
                .split('/')
                .next()?
                .parse::<u32>()
                .ok()?;
            (!alive(pid)).then(|| point.to_owned())
        })
        .take(RECLAIM_LIMIT);
    for point in abandoned {
        detach_in_background("umount", &[&point]);
    }
    if cfg!(target_os = "macos") {
        let images = output("hdiutil", &["info"]);
        let mut ram = false;
        let mut reclaimed = 0usize;
        for line in images.lines() {
            if let Some(path) = line.strip_prefix("image-path") {
                ram = path.contains("ram://");
                continue;
            }
            let Some(device) = line.split_whitespace().next() else {
                continue;
            };
            if ram
                && device.starts_with("/dev/disk")
                && !mounted.contains(device)
                && reclaimed < RECLAIM_LIMIT
            {
                detach_in_background("hdiutil", &["detach", device, "-force"]);
                reclaimed = reclaimed.saturating_add(1);
                ram = false;
            }
        }
    }
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "{program} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

pub fn scratch_mount(parent: &Path, name: &str) -> Result<Mount, String> {
    release_abandoned_mounts();
    let point = parent.join(format!("{name}{MOUNT_MARKER}-{}", std::process::id()));
    fs::create_dir_all(&point).map_err(|error| error.to_string())?;
    let shown = point.display().to_string();
    if cfg!(target_os = "macos") {
        let device = run("hdiutil", &["attach", "-nomount", "ram://32768"])?
            .trim()
            .to_owned();
        if device.is_empty() {
            return Err("hdiutil reported no device".to_owned());
        }
        let mut mount = Mount {
            path: point,
            detach: vec![vec![
                "hdiutil".to_owned(),
                "detach".to_owned(),
                device.clone(),
            ]],
        };
        run("newfs_hfs", &["-v", "scout", &device])?;
        run("mount", &["-t", "hfs", &device, &shown])?;
        mount.detach.insert(0, vec!["umount".to_owned(), shown]);
        Ok(mount)
    } else if cfg!(target_os = "linux") {
        let image = parent.join(format!("{name}.img")).display().to_string();
        run("truncate", &["-s", "16M", &image])?;
        run("mkfs.ext4", &["-q", "-F", &image])?;
        run("mount", &["-o", "loop", &image, &shown])?;
        Ok(Mount {
            path: point,
            detach: vec![vec!["umount".to_owned(), shown]],
        })
    } else {
        Err("a mounted volume is a reparse point on this platform".to_owned())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerRole {
    Scratch,
    Cache,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerKeep {
    Kept,
    Released,
}

pub fn write_owner_marker(
    directory: &Path,
    role: MarkerRole,
    keep: MarkerKeep,
    keyed_to: Option<&Path>,
) {
    write_owner_json(directory, role, keep, keyed_to);
    write_owner_lock(directory);
}

pub fn write_owner_lock(directory: &Path) {
    fs::create_dir_all(directory).expect("the owned directory");
    fs::write(directory.join("owner.lock"), b"").expect("an owner lock");
}

pub fn write_owner_json(
    directory: &Path,
    role: MarkerRole,
    keep: MarkerKeep,
    keyed_to: Option<&Path>,
) {
    fs::create_dir_all(directory).expect("the owned directory");
    let role = match role {
        MarkerRole::Scratch => "scratch",
        MarkerRole::Cache => "cache",
    };
    let kept = match keep {
        MarkerKeep::Kept => "true",
        MarkerKeep::Released => "false",
    };
    let key = keyed_to.map_or_else(String::new, |path| {
        format!(", \"keyed_to\": {:?}", path.display().to_string())
    });
    let document = format!(
        "{{\"schema\": \"njutest-temp-owner-v1\", \"pid\": 1, \"started\": \"x\", \"kept\": {kept}, \"role\": \"{role}\"{key}}}"
    );
    fs::write(directory.join("owner.json"), document).expect("an owner marker");
}

#[must_use]
pub fn claim(directory: &Path) -> File {
    let lock = File::open(directory.join("owner.lock")).expect("an owner lock");
    lock.lock().expect("the owner lock");
    lock
}

#[derive(Debug)]
pub struct Git {
    config: PathBuf,
}

impl Git {
    #[must_use]
    pub fn isolated(scratch: &Path) -> Self {
        let config = scratch.join(".gitconfig-isolated");
        fs::write(
            &config,
            "[user]\n\tname = scout\n\temail = scout@example.invalid\n[commit]\n\tgpgsign = false\n[init]\n\tdefaultBranch = main\n[core]\n\thooksPath = /dev/null\n\tfsmonitor = false\n",
        )
        .expect("an isolated git config");
        Self { config }
    }

    #[track_caller]
    pub fn run(&self, directory: &Path, args: &[&str]) {
        drop(self.read(directory, args));
    }

    #[must_use]
    #[track_caller]
    pub fn read(&self, directory: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(args)
            .env("GIT_CONFIG_GLOBAL", &self.config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {args:?} in {} failed: {}",
            directory.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    pub fn commit_file(&self, repository: &Path, name: &str, contents: &str) {
        let path = repository.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent directories");
        }
        fs::write(&path, contents).expect("a tracked file");
        self.run(repository, &["add", name]);
        let message = format!(
            "{name} in {}",
            repository
                .file_name()
                .map_or_else(String::new, |own| own.to_string_lossy().into_owned())
        );
        self.run(repository, &["commit", "--quiet", "-m", &message]);
    }
}

const COMMAND_LEN: usize = 24;
const SYMBOLS_AT: usize = 32 + COMMAND_LEN;

fn little(value: usize) -> [u8; 4] {
    u32::try_from(value)
        .expect("a fixture field that fits in 32 bits")
        .to_le_bytes()
}

pub fn write_macho_image(path: &Path, objects: &[&str]) {
    let mut strings = vec![b' ', 0];
    let mut symbols = Vec::new();
    for object in objects.iter().copied().chain(["_main"]) {
        let kind: u8 = if object == "_main" { 0x0f } else { 0x66 };
        symbols.extend_from_slice(&little(strings.len()));
        symbols.extend_from_slice(&[kind, 0, 0, 0]);
        symbols.extend_from_slice(&0u64.to_le_bytes());
        strings.extend_from_slice(object.as_bytes());
        strings.push(0);
    }
    let strings_at = SYMBOLS_AT
        .checked_add(symbols.len())
        .expect("a small symbol table");
    let count = objects.len().checked_add(1).expect("a small symbol table");
    let mut bytes = Vec::new();
    for field in [0xfeed_facf_u32, 0x0100_000c, 0, 2, 1] {
        bytes.extend_from_slice(&field.to_le_bytes());
    }
    bytes.extend_from_slice(&little(COMMAND_LEN));
    bytes.extend_from_slice(&[0; 8]);
    for field in [2, COMMAND_LEN, SYMBOLS_AT, count, strings_at, strings.len()] {
        bytes.extend_from_slice(&little(field));
    }
    bytes.extend_from_slice(&symbols);
    bytes.extend_from_slice(&strings);
    write_bytes(path, &bytes);
    let _executable = executable(path);
}

#[derive(Debug)]
pub struct Holder(std::process::Child);

impl Drop for Holder {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        let _exited = self.0.wait();
    }
}

#[must_use]
pub fn hold_session_lock(path: &Path) -> Option<Holder> {
    if cfg!(windows) {
        let _skipped =
            Built::Unavailable(String::from("rustc locks sessions with LockFileEx here"))
                .or_skip("a process that holds a rustc session lock");
        return None;
    }
    let script = if cfg!(target_os = "linux") {
        "use Fcntl qw(:flock); open(my $f, '+<', $ARGV[0]) or die $!; flock($f, LOCK_EX | LOCK_NB) or die $!; $| = 1; print \"held\\n\"; <STDIN>;"
    } else {
        "use Fcntl; open(my $f, '+<', $ARGV[0]) or die $!; fcntl($f, F_SETLK, pack('q q l s s', 0, 0, 0, F_WRLCK, SEEK_SET)) or die $!; $| = 1; print \"held\\n\"; <STDIN>;"
    };
    let spawned = Command::new("perl")
        .args(["-e", script])
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            let _skipped =
                Built::Unavailable(error.to_string()).or_skip("a process that holds a lock");
            return None;
        },
    };
    let mut line = String::new();
    let Some(stdout) = child.stdout.take() else {
        panic!("the holder has no stdout");
    };
    if let Err(error) = std::io::BufRead::read_line(&mut std::io::BufReader::new(stdout), &mut line)
    {
        panic!("the holder did not report: {error}");
    }
    assert_eq!(
        line,
        "held\n",
        "the holder could not take {}",
        path.display()
    );
    Some(Holder(child))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decline_notice_names_the_test_and_only_the_stable_reason() {
        let temp = tempdir("decline-notice");
        let notice = temp.path().join("notice");
        let result = Built::Unavailable(String::from("dynamic /machine/path"))
            .resolve("a volume that shares blocks", Some(notice.as_os_str()));
        assert!(result.is_none());
        let thread = std::thread::current();
        let name = thread.name().unwrap();
        assert_eq!(
            fs::read_to_string(notice).unwrap(),
            format!("{name}\ta volume that shares blocks\n")
        );
    }

    #[test]
    fn an_optional_skip_and_an_absent_notice_create_no_notice() {
        let temp = tempdir("decline-optional");
        let notice = temp.path().join("notice");
        assert!(
            Built::Unavailable(String::from("optional capability"))
                .or_skip("an optional capability")
                .is_none()
        );
        report_decline(None, "an unavailable capability");
        let _absent = fs::symlink_metadata(notice).expect_err("no decline notice");
    }
}

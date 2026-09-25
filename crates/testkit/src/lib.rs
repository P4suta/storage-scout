#![expect(
    clippy::disallowed_methods,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "fixtures build real trees; a fixture that cannot be built is a broken test"
)]

use std::fs::{self, File};
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

pub fn tempdir(prefix: &str) -> Scratch {
    Scratch(Some(
        tempfile::Builder::new()
            .prefix(&format!(".storage-scout-{prefix}-"))
            .tempdir_in(std::env::current_dir().expect("a current directory"))
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
    #[must_use]
    pub fn or_skip(self, what: &str) -> Option<PathBuf> {
        match self {
            Self::Yes(path) => Some(path),
            Self::Unavailable(reason) => {
                let skipped = format!("skipping: cannot create {what} here ({reason})\n");
                std::io::Write::write_all(&mut std::io::stderr(), skipped.as_bytes())
                    .expect("stderr is writable");
                None
            },
        }
    }
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
    fs::write(directory.join("owner.lock"), b"").expect("an owner lock");
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

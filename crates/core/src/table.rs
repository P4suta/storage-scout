use alloc::vec::Vec;

use crate::area::{Reach, Rule, SystemReason};
use crate::location::{Location, LocationError, Syntax};
use crate::platform::Platform;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Host {
    pub home: Option<Location>,
    pub temp: Option<Location>,
    pub xdg_cache: Option<Location>,
    pub program_areas: Vec<(&'static str, Location)>,
}

pub fn rules(platform: Platform, host: &Host) -> Result<Vec<Rule>, LocationError> {
    match platform {
        Platform::MacOs => macos(host),
        Platform::Linux => linux(host),
        Platform::Windows => windows(host),
    }
}

fn unix(path: &str) -> Result<Location, LocationError> {
    Location::parse_str(Syntax::Unix, path)
}

fn macos(host: &Host) -> Result<Vec<Rule>, LocationError> {
    const SYSTEM: [&str; 11] = [
        "/System",
        "/Library",
        "/Applications",
        "/usr",
        "/bin",
        "/sbin",
        "/opt",
        "/private",
        "/cores",
        "/Network",
        "/nix",
    ];
    let mut rules = Vec::new();
    if let Some(temp) = &host.temp {
        rules.push(Rule::app_owned("$TMPDIR", temp.clone(), Reach::Subtree));
    }
    rules.push(Rule::app_owned(
        "/var/folders",
        unix("/private/var/folders")?,
        Reach::Subtree,
    ));
    rules.push(Rule::app_owned(
        "/tmp",
        unix("/private/tmp")?,
        Reach::Subtree,
    ));
    rules.push(Rule::app_owned(
        "/var/tmp",
        unix("/private/var/tmp")?,
        Reach::Subtree,
    ));
    if let Some(home) = &host.home {
        rules.push(Rule::app_owned(
            "~/Library",
            home.child("Library")?,
            Reach::Subtree,
        ));
    }
    rules.push(Rule::app_owned(
        "~/Library",
        unix("/Users")?,
        Reach::EachChildSubtree("Library"),
    ));
    for path in SYSTEM {
        rules.push(Rule::system(
            SystemReason::SystemArea { label: path },
            unix(path)?,
            Reach::Subtree,
        ));
    }
    rules.push(Rule::system(
        SystemReason::VolumeRoot,
        unix("/Volumes")?,
        Reach::Exact,
    ));
    rules.push(Rule::system(
        SystemReason::VolumeRoot,
        unix("/Volumes")?,
        Reach::EachChild,
    ));
    rules.push(Rule::system(
        SystemReason::UsersRoot,
        unix("/Users")?,
        Reach::Exact,
    ));
    rules.push(Rule::system(
        SystemReason::ProfileRoot,
        unix("/Users")?,
        Reach::EachChild,
    ));
    if let Some(home) = &host.home {
        rules.push(Rule::system(
            SystemReason::ProfileRoot,
            home.clone(),
            Reach::Exact,
        ));
    }
    Ok(rules)
}

fn linux(host: &Host) -> Result<Vec<Rule>, LocationError> {
    const SYSTEM: [&str; 16] = [
        "/proc", "/sys", "/dev", "/run", "/boot", "/etc", "/usr", "/bin", "/sbin", "/lib",
        "/lib64", "/opt", "/var", "/snap", "/srv", "/nix",
    ];
    let mut rules = Vec::new();
    let cache = match (&host.xdg_cache, &host.home) {
        (Some(cache), _) => Some(cache.clone()),
        (None, Some(home)) => Some(home.child(".cache")?),
        (None, None) => None,
    };
    if let Some(cache) = cache {
        rules.push(Rule::app_owned("~/.cache", cache, Reach::Subtree));
    }
    if let Some(home) = &host.home {
        rules.push(Rule::app_owned(
            "~/.local/share",
            home.child(".local")?.child("share")?,
            Reach::Subtree,
        ));
    }
    rules.push(Rule::app_owned(
        "~/.cache",
        unix("/home")?,
        Reach::EachChildSubtree(".cache"),
    ));
    rules.push(Rule::app_owned(
        "/var/tmp",
        unix("/var/tmp")?,
        Reach::Subtree,
    ));
    let temp = match &host.temp {
        Some(temp) => temp.clone(),
        None => unix("/tmp")?,
    };
    rules.push(Rule::app_owned("$TMPDIR", temp, Reach::Subtree));
    for path in SYSTEM {
        rules.push(Rule::system(
            SystemReason::SystemArea { label: path },
            unix(path)?,
            Reach::Subtree,
        ));
    }
    rules.push(Rule::system(
        SystemReason::UsersRoot,
        unix("/home")?,
        Reach::Exact,
    ));
    rules.push(Rule::system(
        SystemReason::ProfileRoot,
        unix("/home")?,
        Reach::EachChild,
    ));
    rules.push(Rule::system(
        SystemReason::ProfileRoot,
        unix("/root")?,
        Reach::Exact,
    ));
    if let Some(home) = &host.home {
        rules.push(Rule::system(
            SystemReason::ProfileRoot,
            home.clone(),
            Reach::Exact,
        ));
    }
    Ok(rules)
}

fn windows(host: &Host) -> Result<Vec<Rule>, LocationError> {
    let mut rules = Vec::new();
    let users = host.home.as_ref().and_then(Location::parent);
    if let Some(home) = &host.home {
        rules.push(Rule::app_owned(
            "AppData",
            home.child("AppData")?,
            Reach::Subtree,
        ));
    }
    if let Some(users) = &users {
        rules.push(Rule::app_owned(
            "AppData",
            users.clone(),
            Reach::EachChildSubtree("AppData"),
        ));
    }
    for (label, path) in &host.program_areas {
        rules.push(Rule::system(
            SystemReason::SystemArea { label },
            path.clone(),
            Reach::Subtree,
        ));
    }
    if let Some(home) = &host.home {
        rules.push(Rule::system(
            SystemReason::ProfileRoot,
            home.clone(),
            Reach::Exact,
        ));
    }
    if let Some(users) = users {
        rules.push(Rule::system(
            SystemReason::UsersRoot,
            users.clone(),
            Reach::Exact,
        ));
        rules.push(Rule::system(
            SystemReason::ProfileRoot,
            users,
            Reach::EachChild,
        ));
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::area::{Area, Class, Protection};

    fn at(syntax: Syntax, path: &str) -> Location {
        Location::parse_str(syntax, path).unwrap()
    }

    fn protection(platform: Platform, host: &Host) -> Protection {
        let syntax = platform.syntax();
        let (cwd, exe) = match syntax {
            Syntax::Unix => (at(syntax, "/nowhere/cwd"), at(syntax, "/nowhere/bin/scout")),
            Syntax::Windows => (at(syntax, r"Z:\cwd"), at(syntax, r"Z:\bin\scout.exe")),
        };
        Protection::new(
            syntax,
            platform.case(),
            cwd,
            exe,
            rules(platform, host).unwrap(),
        )
        .unwrap()
    }

    fn mac() -> Protection {
        protection(
            Platform::MacOs,
            &Host {
                home: Some(at(Syntax::Unix, "/Users/me")),
                temp: Some(at(Syntax::Unix, "/private/var/folders/ab/xyz/T")),
                ..Host::default()
            },
        )
    }

    fn gnu() -> Protection {
        protection(
            Platform::Linux,
            &Host {
                home: Some(at(Syntax::Unix, "/home/me")),
                temp: Some(at(Syntax::Unix, "/tmp")),
                ..Host::default()
            },
        )
    }

    fn win() -> Protection {
        protection(
            Platform::Windows,
            &Host {
                home: Some(at(Syntax::Windows, r"C:\Users\me")),
                program_areas: vec![
                    ("Windows", at(Syntax::Windows, r"C:\Windows")),
                    ("Program Files", at(Syntax::Windows, r"C:\Program Files")),
                    ("ProgramData", at(Syntax::Windows, r"C:\ProgramData")),
                ],
                ..Host::default()
            },
        )
    }

    #[track_caller]
    fn area(protection: &Protection, path: &str) -> Area {
        protection.area_of(&at(protection.syntax(), path))
    }

    #[track_caller]
    fn assert_system(protection: &Protection, path: &str) {
        assert!(
            matches!(area(protection, path), Area::System(_)),
            "{path}: {:?}",
            area(protection, path)
        );
    }

    #[track_caller]
    fn assert_app_owned(protection: &Protection, path: &str) {
        assert!(
            matches!(area(protection, path), Area::AppOwned(_)),
            "{path}: {:?}",
            area(protection, path)
        );
    }

    #[track_caller]
    fn assert_open(protection: &Protection, path: &str) {
        assert_eq!(area(protection, path), Area::Open, "{path}");
    }

    #[test]
    fn macos_refuses_the_system_the_user_root_and_mounted_volumes() {
        let mac = mac();
        for path in [
            "/System",
            "/System/Library/Frameworks",
            "/Library/Preferences",
            "/Applications/Xcode.app",
            "/usr/local/bin",
            "/opt/homebrew/Cellar",
            "/private/etc",
            "/private/var/db",
            "/Users",
            "/Users/me",
            "/Users/someone-else",
            "/Volumes",
            "/Volumes/Backup",
        ] {
            assert_system(&mac, path);
        }
        assert_open(&mac, "/Users/me/projects/app/target");
        assert_open(&mac, "/Volumes/Backup/work/target");
    }

    #[test]
    fn macos_treats_library_and_tmpdir_as_application_owned() {
        let mac = mac();
        for path in [
            "/Users/me/Library",
            "/Users/me/Library/Caches/org.rust-lang.cargo",
            "/Users/someone-else/Library/Caches/x",
            "/private/var/folders/ab/xyz/T/cargo-target",
            "/private/tmp/build-123",
            "/private/var/tmp/pip-cache",
            "/private/var/folders/zz/other-session/T/build",
        ] {
            assert_app_owned(&mac, path);
        }
    }

    #[test]
    fn linux_refuses_system_areas_and_every_home_root() {
        let gnu = gnu();
        for path in [
            "/proc",
            "/sys/kernel",
            "/dev/shm",
            "/boot",
            "/etc/apt",
            "/usr/lib",
            "/var/lib",
            "/snap/core",
            "/srv/www",
            "/home",
            "/home/me",
            "/home/other",
            "/root",
        ] {
            assert_system(&gnu, path);
        }
        assert_open(&gnu, "/home/me/src/app/target");
    }

    #[test]
    fn linux_treats_xdg_and_temporary_directories_as_application_owned() {
        let gnu = gnu();
        for path in [
            "/home/me/.cache/uv",
            "/home/other/.cache/pip",
            "/home/me/.local/share/virtualenvs",
            "/tmp/build-123",
            "/var/tmp/portage",
        ] {
            assert_app_owned(&gnu, path);
        }
        let custom = protection(
            Platform::Linux,
            &Host {
                home: Some(at(Syntax::Unix, "/home/me")),
                xdg_cache: Some(at(Syntax::Unix, "/scratch/cache")),
                ..Host::default()
            },
        );
        assert_app_owned(&custom, "/scratch/cache/cargo");
    }

    #[test]
    fn windows_rules_hold_under_every_spelling() {
        let win = win();
        for path in [
            r"C:\Windows\System32",
            r"c:\windows\system32",
            r"\\?\C:\Windows\System32",
            r"C:\Program Files\Git",
            r"C:\ProgramData\chocolatey",
            r"C:\Users",
            r"C:\Users\me",
            r"C:\Users\other",
            r"C:\",
        ] {
            assert_system(&win, path);
        }
        for path in [
            r"C:\Users\me\AppData",
            r"C:\Users\me\AppData\Local\Temp\sbt",
            r"C:\Users\other\AppData\Local\cache",
        ] {
            assert_app_owned(&win, path);
        }
        assert_open(&win, r"C:\src\app\target");
    }

    #[test]
    fn a_location_in_another_syntax_is_refused_outright() {
        let mac = mac();
        assert!(matches!(
            mac.area_of(&at(Syntax::Windows, r"C:\src\target")),
            Area::System(_)
        ));
    }

    #[test]
    fn application_owned_rules_come_before_the_system_areas_they_nest_in() {
        for platform in [Platform::MacOs, Platform::Linux, Platform::Windows] {
            let host = match platform.syntax() {
                Syntax::Unix => Host {
                    home: Some(at(Syntax::Unix, "/home/me")),
                    temp: Some(at(Syntax::Unix, "/tmp")),
                    ..Host::default()
                },
                Syntax::Windows => Host {
                    home: Some(at(Syntax::Windows, r"C:\Users\me")),
                    program_areas: vec![("Windows", at(Syntax::Windows, r"C:\Windows"))],
                    ..Host::default()
                },
            };
            let rules = rules(platform, &host).unwrap();
            let first_system = rules
                .iter()
                .position(|rule| matches!(rule.class, Class::System { .. }))
                .unwrap();
            let last_app_owned = rules
                .iter()
                .rposition(|rule| matches!(rule.class, Class::AppOwned { .. }))
                .unwrap();
            assert!(last_app_owned < first_system, "{platform}");
        }
    }

    #[test]
    fn the_current_directory_and_the_binary_are_always_protected() {
        let mac = mac();
        assert!(matches!(
            area(&mac, "/nowhere"),
            Area::System(SystemReason::CurrentDirectory)
        ));
        assert!(matches!(
            area(&mac, "/nowhere/bin"),
            Area::System(SystemReason::RunningBinary)
        ));
        assert!(matches!(
            area(&mac, "/"),
            Area::System(SystemReason::FilesystemRoot)
        ));
    }
}

use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};

#[expect(
    clippy::disallowed_methods,
    reason = "the one place storage-scout starts itself in the background"
)]
pub(crate) fn detached(program: &Path, arguments: &[OsString], directory: &Path) -> io::Result<()> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    command.spawn().map(drop)
}

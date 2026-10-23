#[cfg(unix)]
pub(super) const OWNER_DIRECTORY_MODE: u32 = 0o700;
#[cfg(unix)]
pub(super) const EXECUTABLE_MODE: u32 = 0o755;
#[cfg(unix)]
pub(super) const FILE_MODE_MASK: u32 = 0o7777;
#[cfg(unix)]
pub(super) const OWNER_READ_PERMISSION: u32 = 0o400;
#[cfg(unix)]
pub(super) const FILE_BLOCK_BYTES: u64 = 512;

pub(super) const PATTERN_PERIOD: usize = 251;
pub(super) const RAM_IMAGE_PREFIX: &str = "ram://";
pub(super) const RAM_IMAGE_SOURCE: &str = "ram://32768";
pub(super) const MACOS_DISK_PREFIX: &str = "/dev/disk";

pub(super) const MACHO_HEADER_LEN: usize = 32;
pub(super) const MACHO_FLAGS_AND_RESERVED_LEN: usize = 8;
pub(super) const MACHO_MAGIC_64: u32 = 0xfeed_facf;
pub(super) const MACHO_CPU_ARM64: u32 = 0x0100_000c;
pub(super) const MACHO_EXECUTE: u32 = 2;
pub(super) const MACHO_SYMTAB: usize = 2;
pub(super) const MACHO_EXTERNAL_SECTION: u8 = 0x0f;
pub(super) const MACHO_DEBUG_OBJECT: u8 = 0x66;

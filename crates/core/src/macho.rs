const MAGIC_64: u32 = 0xfeed_facf;
const EXECUTE: u32 = 0x2;
const DYLIB: u32 = 0x6;
const BUNDLE: u32 = 0x8;
const SYMTAB: u32 = 0x2;
const DEBUG_OBJECT: u8 = 0x66;

pub const HEADER_LEN: usize = 32;
pub const SYMBOL_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachError {
    NotAnImage,
    Truncated,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commands {
    pub count: u32,
    pub len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Symtab {
    pub symbols: u64,
    pub count: u64,
    pub strings: u64,
    pub strings_len: u64,
}

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    match bytes.get(at..end) {
        Some(&[a, b, c, d]) => Some(u32::from_le_bytes([a, b, c, d])),
        Some(_) | None => None,
    }
}

pub fn header(bytes: &[u8]) -> Result<Commands, MachError> {
    let magic = word(bytes, 0).ok_or(MachError::Truncated)?;
    if magic != MAGIC_64 {
        return Err(MachError::NotAnImage);
    }
    let filetype = word(bytes, 12).ok_or(MachError::Truncated)?;
    if !matches!(filetype, EXECUTE | DYLIB | BUNDLE) {
        return Err(MachError::NotAnImage);
    }
    Ok(Commands {
        count: word(bytes, 16).ok_or(MachError::Truncated)?,
        len: word(bytes, 20).ok_or(MachError::Truncated)?,
    })
}

pub fn symtab(commands: &[u8], count: u32) -> Result<Symtab, MachError> {
    let mut at = 0usize;
    let mut found = None;
    for _ in 0..count {
        let command = word(commands, at).ok_or(MachError::Truncated)?;
        let size = word(commands, at.checked_add(4).ok_or(MachError::Malformed)?)
            .ok_or(MachError::Truncated)?;
        let size = usize::try_from(size).map_err(|_wide| MachError::Malformed)?;
        if size < 8 {
            return Err(MachError::Malformed);
        }
        if command == SYMTAB {
            if found.is_some() {
                return Err(MachError::Malformed);
            }
            let field = |index: usize| {
                index
                    .checked_mul(4)
                    .and_then(|offset| offset.checked_add(8))
                    .and_then(|offset| at.checked_add(offset))
                    .and_then(|offset| word(commands, offset))
                    .map(u64::from)
                    .ok_or(MachError::Truncated)
            };
            found = Some(Symtab {
                symbols: field(0)?,
                count: field(1)?,
                strings: field(2)?,
                strings_len: field(3)?,
            });
        }
        at = at.checked_add(size).ok_or(MachError::Malformed)?;
    }
    found.ok_or(MachError::Malformed)
}

pub fn debug_objects(symbols: &[u8]) -> impl Iterator<Item = u32> + '_ {
    symbols
        .as_chunks::<SYMBOL_LEN>()
        .0
        .iter()
        .filter(|symbol| symbol.get(4) == Some(&DEBUG_OBJECT))
        .map(|&[a, b, c, d, ..]| u32::from_le_bytes([a, b, c, d]))
}

#[must_use]
pub fn terminated(bytes: &[u8]) -> Option<&[u8]> {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .and_then(|end| bytes.get(..end))
}

#[must_use]
pub fn base_name(path: &[u8]) -> &[u8] {
    path.rsplit(|byte| *byte == b'/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;

    fn image(filetype: u32, commands: &[Vec<u8>]) -> Vec<u8> {
        let len = commands.iter().map(Vec::len).sum::<usize>();
        let mut bytes = Vec::new();
        for field in [
            MAGIC_64,
            0x0100_000c,
            0,
            filetype,
            u32::try_from(commands.len()).unwrap(),
            u32::try_from(len).unwrap(),
            0,
            0,
        ] {
            bytes.extend_from_slice(&field.to_le_bytes());
        }
        for command in commands {
            bytes.extend_from_slice(command);
        }
        bytes
    }

    fn command(kind: u32, fields: &[u32]) -> Vec<u8> {
        let size = u32::try_from(
            fields
                .len()
                .checked_mul(4)
                .and_then(|len| len.checked_add(8))
                .unwrap(),
        )
        .unwrap();
        let mut bytes = Vec::new();
        for field in [kind, size].iter().chain(fields) {
            bytes.extend_from_slice(&field.to_le_bytes());
        }
        bytes
    }

    fn symbol(strx: u32, kind: u8) -> Vec<u8> {
        let mut bytes = strx.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[kind, 0, 0, 0]);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes
    }

    #[test]
    fn an_executable_names_its_symbol_table() {
        let bytes = image(
            EXECUTE,
            &[
                command(0x19, &[0; 16]),
                command(0x2a, &[]),
                command(SYMTAB, &[100, 3, 400, 50]),
            ],
        );
        let commands = header(&bytes).unwrap();
        assert_eq!(commands.count, 3);
        let start = HEADER_LEN;
        let end = start
            .checked_add(usize::try_from(commands.len).unwrap())
            .unwrap();
        assert_eq!(
            symtab(&bytes[start..end], commands.count),
            Ok(Symtab {
                symbols: 100,
                count: 3,
                strings: 400,
                strings_len: 50,
            })
        );
    }

    #[test]
    fn only_linked_images_are_read() {
        for filetype in [EXECUTE, DYLIB, BUNDLE] {
            header(&image(filetype, &[])).unwrap();
        }
        assert_eq!(header(&image(0x1, &[])), Err(MachError::NotAnImage));
        let mut elf = image(EXECUTE, &[]);
        elf[..4].copy_from_slice(b"\x7fELF");
        assert_eq!(header(&elf), Err(MachError::NotAnImage));
        assert_eq!(header(&[0xcf, 0xfa]), Err(MachError::Truncated));
        assert_eq!(
            header(&image(EXECUTE, &[])[..20]),
            Err(MachError::Truncated)
        );
    }

    #[test]
    fn a_table_that_is_missing_repeated_or_cut_short_is_malformed() {
        let none = [command(0x19, &[0; 4])].concat();
        assert_eq!(symtab(&none, 1), Err(MachError::Malformed));
        let twice = [command(SYMTAB, &[0; 4]), command(SYMTAB, &[0; 4])].concat();
        assert_eq!(symtab(&twice, 2), Err(MachError::Malformed));
        let tiny = [SYMTAB, 4].map(u32::to_le_bytes).concat();
        assert_eq!(symtab(&tiny, 1), Err(MachError::Malformed));
        let cut = command(SYMTAB, &[0; 4]);
        assert_eq!(symtab(&cut[..12], 1), Err(MachError::Truncated));
        assert_eq!(symtab(&cut, 2), Err(MachError::Truncated));
    }

    #[test]
    fn only_debug_object_entries_are_reported() {
        let symbols = [
            symbol(7, DEBUG_OBJECT),
            symbol(9, 0x24),
            symbol(11, DEBUG_OBJECT),
        ]
        .concat();
        assert_eq!(debug_objects(&symbols).collect::<Vec<_>>(), vec![7, 11]);
        assert_eq!(debug_objects(&symbols[..20]).count(), 1);
    }

    #[test]
    fn strings_end_at_their_terminator_and_names_at_the_last_slash() {
        assert_eq!(terminated(b"/a/b.o\0rest"), Some(&b"/a/b.o"[..]));
        assert_eq!(terminated(b"unterminated"), None);
        assert_eq!(base_name(b"/a/deps/x.o"), b"x.o");
        assert_eq!(base_name(b"x.o"), b"x.o");
        assert_eq!(base_name(b"/a/lib.rlib(x.o)"), b"lib.rlib(x.o)");
    }
}

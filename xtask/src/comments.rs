#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Comment {
    pub line: usize,
    pub safety: Safety,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Safety {
    Justification,
    Prose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Code,
    Line,
    Block(usize),
    Text,
    Raw(usize),
    Character,
}

fn raw_start(rest: &[u8]) -> Option<(usize, usize)> {
    let prefix = match rest {
        [b'b' | b'c', b'r', ..] => 2,
        [b'r', ..] => 1,
        _ => return None,
    };
    let hashes = rest
        .iter()
        .skip(prefix)
        .take_while(|byte| **byte == b'#')
        .count();
    match rest.get(prefix.saturating_add(hashes)) {
        Some(b'"') => Some((hashes, prefix.saturating_add(hashes).saturating_add(1))),
        _ => None,
    }
}

fn closes_raw(rest: &[u8], hashes: usize) -> bool {
    rest.first() == Some(&b'"')
        && rest
            .iter()
            .skip(1)
            .take(hashes)
            .filter(|byte| **byte == b'#')
            .count()
            == hashes
}

fn is_character(rest: &[u8]) -> bool {
    match rest {
        [b'\'', b'\\', ..] | [b'\'', _, b'\'', ..] => true,
        [b'\'', first, ..] => {
            let width: usize = match first {
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => return false,
            };
            rest.get(width.saturating_add(1)) == Some(&b'\'')
        },
        _ => false,
    }
}

fn safety(rest: &[u8]) -> Safety {
    if rest.starts_with(b"// SAFETY:") {
        Safety::Justification
    } else {
        Safety::Prose
    }
}

#[must_use]
pub(crate) fn find(source: &str) -> Vec<Comment> {
    let bytes = source.as_bytes();
    let mut found = Vec::new();
    let mut mode = Mode::Code;
    let mut line = 1usize;
    let mut index = 0usize;
    let mut identifier = false;
    while let Some(rest) = bytes.get(index..) {
        let Some(&byte) = rest.first() else {
            break;
        };
        let mut step = 1usize;
        mode = match mode {
            Mode::Code => {
                let next = match rest {
                    [b'/', b'/', ..] => {
                        found.push(Comment {
                            line,
                            safety: safety(rest),
                        });
                        Mode::Line
                    },
                    [b'/', b'*', ..] => {
                        found.push(Comment {
                            line,
                            safety: Safety::Prose,
                        });
                        step = 2;
                        Mode::Block(1)
                    },
                    [b'"', ..] => Mode::Text,
                    [b'\'', ..] if is_character(rest) => Mode::Character,
                    _ => match raw_start(rest) {
                        Some((hashes, width)) if !identifier => {
                            step = width;
                            Mode::Raw(hashes)
                        },
                        Some(_) | None => Mode::Code,
                    },
                };
                identifier = byte.is_ascii_alphanumeric() || byte == b'_';
                next
            },
            Mode::Line if byte == b'\n' => Mode::Code,
            Mode::Line => Mode::Line,
            Mode::Block(depth) => match rest {
                [b'*', b'/', ..] => {
                    step = 2;
                    if depth <= 1 {
                        Mode::Code
                    } else {
                        Mode::Block(depth.saturating_sub(1))
                    }
                },
                [b'/', b'*', ..] => {
                    step = 2;
                    Mode::Block(depth.saturating_add(1))
                },
                _ => Mode::Block(depth),
            },
            Mode::Text => match rest {
                [b'\\', _, ..] => {
                    step = 2;
                    Mode::Text
                },
                [b'"', ..] => Mode::Code,
                _ => Mode::Text,
            },
            Mode::Raw(hashes) if closes_raw(rest, hashes) => {
                step = hashes.saturating_add(1);
                Mode::Code
            },
            Mode::Raw(hashes) => Mode::Raw(hashes),
            Mode::Character => match rest {
                [b'\\', _, ..] => {
                    step = 2;
                    Mode::Character
                },
                [b'\'', ..] => Mode::Code,
                _ => Mode::Character,
            },
        };
        line = line.saturating_add(
            bytes
                .iter()
                .skip(index)
                .take(step)
                .filter(|skipped| **skipped == b'\n')
                .count(),
        );
        index = index.saturating_add(step);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prose(source: &str) -> Vec<usize> {
        find(source)
            .into_iter()
            .filter(|comment| comment.safety == Safety::Prose)
            .map(|comment| comment.line)
            .collect()
    }

    #[test]
    fn comments_are_found_outside_literals_only() {
        assert_eq!(prose("/// doc\nfn f() {}"), [1]);
        assert_eq!(prose("fn f() {}\n/* a /* b */ c */\n"), [2]);
        assert_eq!(prose("let s = \"// not\";"), Vec::<usize>::new());
        assert_eq!(prose("let s = r#\"/* not */\"#;"), Vec::<usize>::new());
        assert_eq!(prose("fn f<'a>(x: &'a str) -> &'a str { x } // tail"), [1]);
        assert_eq!(prose("let c = '/'; // tail"), [1]);
    }

    #[test]
    fn a_safety_justification_is_not_prose() {
        assert_eq!(
            prose("// SAFETY: fine\nunsafe { f() }"),
            Vec::<usize>::new()
        );
        assert_eq!(prose("// safety: lowercase is prose"), [1]);
    }
}

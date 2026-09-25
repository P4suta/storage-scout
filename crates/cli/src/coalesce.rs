use std::io;

use serde::Serialize;

use crate::store::{Held, Station};

pub(crate) trait Rendezvous {
    type Held;
    fn raise(&self) -> io::Result<()>;
    fn lower(&self) -> io::Result<bool>;
    fn raised(&self) -> io::Result<bool>;
    fn hold(&self) -> io::Result<Option<Self::Held>>;
}

impl Rendezvous for Station {
    type Held = Held;

    fn raise(&self) -> io::Result<()> {
        Self::raise(self)
    }

    fn lower(&self) -> io::Result<bool> {
        Self::lower(self)
    }

    fn raised(&self) -> io::Result<bool> {
        Self::raised(self)
    }

    fn hold(&self) -> io::Result<Option<Held>> {
        Self::hold(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "coalescing", rename_all = "kebab-case")]
pub enum Coalescing {
    Ran { runs: usize },
    Handed,
}

pub(crate) fn drive<R: Rendezvous, E>(
    rendezvous: &R,
    mut run: impl FnMut() -> Result<(), E>,
) -> Result<Coalescing, Driven<E>> {
    rendezvous.raise().map_err(Driven::Io)?;
    let mut runs = 0usize;
    loop {
        let Some(held) = rendezvous.hold().map_err(Driven::Io)? else {
            return Ok(if runs == 0 {
                Coalescing::Handed
            } else {
                Coalescing::Ran { runs }
            });
        };
        while rendezvous.lower().map_err(Driven::Io)? {
            run().map_err(Driven::Run)?;
            runs = runs.saturating_add(1);
        }
        drop(held);
        if !rendezvous.raised().map_err(Driven::Io)? {
            return Ok(Coalescing::Ran { runs });
        }
    }
}

#[derive(Debug)]
pub(crate) enum Driven<E> {
    Io(io::Error),
    Run(E),
}

pub(crate) fn handed_off<R: Rendezvous>(rendezvous: &R) -> io::Result<bool> {
    rendezvous.raise()?;
    Ok(rendezvous.hold()?.is_none())
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    #[derive(Default)]
    struct Memory {
        flag: Cell<bool>,
        held: Cell<bool>,
        log: RefCell<Vec<&'static str>>,
    }

    struct Token<'a>(&'a Memory);

    impl Drop for Token<'_> {
        fn drop(&mut self) {
            self.0.held.set(false);
        }
    }

    impl<'a> Rendezvous for &'a Memory {
        type Held = Token<'a>;

        fn raise(&self) -> io::Result<()> {
            self.flag.set(true);
            Ok(())
        }

        fn lower(&self) -> io::Result<bool> {
            Ok(self.flag.replace(false))
        }

        fn raised(&self) -> io::Result<bool> {
            Ok(self.flag.get())
        }

        fn hold(&self) -> io::Result<Option<Token<'a>>> {
            if self.held.replace(true) {
                Ok(None)
            } else {
                Ok(Some(Token(self)))
            }
        }
    }

    #[test]
    fn a_lone_invocation_runs_once() {
        let memory = Memory::default();
        let outcome = drive(&&memory, || -> Result<(), ()> {
            memory.log.borrow_mut().push("run");
            Ok(())
        })
        .unwrap();
        assert_eq!(outcome, Coalescing::Ran { runs: 1 });
        assert!(!memory.flag.get());
    }

    #[test]
    fn a_request_arriving_during_a_run_is_served_by_the_holder() {
        let memory = Memory::default();
        let mut first = true;
        let outcome = drive(&&memory, || -> Result<(), ()> {
            if first {
                first = false;
                let arriving = drive(&&memory, || -> Result<(), ()> { Ok(()) }).unwrap();
                assert_eq!(arriving, Coalescing::Handed);
            }
            memory.log.borrow_mut().push("run");
            Ok(())
        })
        .unwrap();
        assert_eq!(outcome, Coalescing::Ran { runs: 2 });
        assert_eq!(memory.log.borrow().len(), 2);
        assert!(!memory.flag.get());
    }

    #[test]
    fn a_detached_request_hands_off_to_a_running_holder() {
        let memory = Memory::default();
        assert!(!handed_off(&&memory).unwrap());
        let _running = (&memory).hold().unwrap();
        assert!(handed_off(&&memory).unwrap());
        assert!(memory.flag.get());
    }
}

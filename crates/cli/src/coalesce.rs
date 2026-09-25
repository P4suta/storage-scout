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
        broken: Cell<bool>,
        holds_left: Cell<Option<usize>>,
        raise_on_release: Cell<bool>,
        log: RefCell<Vec<&'static str>>,
    }

    struct Token<'a>(&'a Memory);

    impl Drop for Token<'_> {
        fn drop(&mut self) {
            self.0.held.set(false);
            if self.0.raise_on_release.replace(false) {
                self.0.flag.set(true);
            }
        }
    }

    impl<'a> Rendezvous for &'a Memory {
        type Held = Token<'a>;

        fn raise(&self) -> io::Result<()> {
            if self.broken.get() {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
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
            if let Some(left) = self.holds_left.get() {
                if left == 0 {
                    return Ok(None);
                }
                self.holds_left.set(Some(left.saturating_sub(1)));
            }
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

    #[test]
    fn a_flag_that_cannot_be_raised_stops_the_run_and_says_so() {
        let memory = Memory::default();
        memory.broken.set(true);
        let outcome = drive(&&memory, || -> Result<(), ()> {
            memory.log.borrow_mut().push("run");
            Ok(())
        });
        assert!(matches!(outcome, Err(Driven::Io(_))));
        assert!(memory.log.borrow().is_empty());
        let _refused = handed_off(&&memory).unwrap_err();
    }

    #[test]
    fn the_station_on_disk_keeps_the_same_promises() {
        let temp = testkit::tempdir("coalesce-station");
        let station = Station::for_policy(temp.path(), &temp.path().join("auto.toml"));
        assert_eq!(
            drive(&station, || -> Result<(), ()> { Ok(()) }).unwrap(),
            Coalescing::Ran { runs: 1 }
        );
        assert!(!Rendezvous::raised(&station).unwrap());
        let holder = Rendezvous::hold(&station).unwrap().unwrap();
        assert!(Rendezvous::hold(&station).unwrap().is_none());
        assert_eq!(
            drive(&station, || -> Result<(), ()> { Ok(()) }).unwrap(),
            Coalescing::Handed
        );
        assert!(Rendezvous::raised(&station).unwrap());
        drop(holder);
        assert_eq!(
            drive(&station, || -> Result<(), ()> { Ok(()) }).unwrap(),
            Coalescing::Ran { runs: 1 }
        );
        assert!(!Rendezvous::lower(&station).unwrap());
    }

    #[test]
    fn a_request_arriving_as_the_lock_is_released_is_still_served() {
        let memory = Memory::default();
        memory.raise_on_release.set(true);
        let outcome = drive(&&memory, || -> Result<(), ()> {
            memory.log.borrow_mut().push("run");
            Ok(())
        })
        .unwrap();
        assert_eq!(outcome, Coalescing::Ran { runs: 2 });
        assert!(!memory.flag.get());
    }

    #[test]
    fn a_holder_that_ran_and_then_lost_the_lock_still_says_it_ran() {
        let memory = Memory::default();
        memory.holds_left.set(Some(1));
        memory.raise_on_release.set(true);
        let outcome = drive(&&memory, || -> Result<(), ()> { Ok(()) }).unwrap();
        assert_eq!(outcome, Coalescing::Ran { runs: 1 });
        assert!(memory.flag.get());
    }
}

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

macro_rules! ordered {
    (
        $(#[$meta:meta])*
        pub enum $name:ident { $($variant:ident),+ $(,)? }
    ) => {
        $(#[$meta])*
        pub enum $name { $($variant),+ }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
        }
    };
}

pub mod area;
pub mod artifact;
pub mod candidate;
pub mod event;
pub mod gate;
pub mod git;
pub mod location;
pub mod lock;
pub mod macho;
pub mod ownership;
pub mod platform;
pub mod prune;
pub mod reject;
pub mod select;
pub mod share;
pub mod size;
pub mod table;

use std::io;
use std::path::Path;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

use crate::store;

pub const FILTER_VARIABLE: &str = "STORAGE_SCOUT_LOG";

pub fn install(verbosity: Verbosity, trace_file: Option<&Path>) -> io::Result<()> {
    let filter = match std::env::var(FILTER_VARIABLE) {
        Ok(directive) => EnvFilter::new(directive),
        Err(_unset) => EnvFilter::new(verbosity.directive()),
    };
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_writer(io::stderr)
        .with_target(true)
        .with_ansi(io::IsTerminal::is_terminal(&io::stderr()))
        .without_time()
        .with_filter(filter);
    let file_layer = match trace_file {
        None => None,
        Some(path) => {
            let file = store::append(path)?;
            Some(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(std::sync::Mutex::new(file))
                    .with_span_list(true)
                    .without_time()
                    .with_filter(EnvFilter::new("storage_scout=trace")),
            )
        },
    };
    match tracing_subscriber::registry()
        .with(stderr_layer)
        .with(file_layer)
        .try_init()
    {
        Ok(()) => Ok(()),
        Err(error) => Err(io::Error::other(error)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    Quiet,
    Info,
    Debug,
    Trace,
}

impl Verbosity {
    #[must_use]
    pub const fn from_count(count: u8) -> Self {
        match count {
            0 => Self::Quiet,
            1 => Self::Info,
            2 => Self::Debug,
            _ => Self::Trace,
        }
    }

    const fn directive(self) -> &'static str {
        match self {
            Self::Quiet => "warn",
            Self::Info => "storage_scout=info",
            Self::Debug => "storage_scout=debug",
            Self::Trace => "storage_scout=trace",
        }
    }
}

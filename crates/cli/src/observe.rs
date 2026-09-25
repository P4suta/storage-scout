use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use storage_scout_core::area::Protection;
use storage_scout_core::artifact::{
    CACHE_TAG_NAME, CACHE_TAG_SIGNATURE, CacheTag, Entries, Listing, OwnerTag, Tags,
};
use storage_scout_core::candidate::Identity;
use storage_scout_core::gate::{Boundary, Shape, Site};
use storage_scout_core::location::Location;
use storage_scout_core::ownership::Role;
use storage_scout_core::reject::{FsOp, Rejection};

use crate::{failure, host, platform};

pub(crate) mod git;

#[derive(Debug)]
pub(crate) struct Observation {
    pub path: PathBuf,
    pub location: Location,
    pub shape: Shape,
    pub boundary: Boundary,
    pub listing: Listing,
    pub identity: Identity,
}

impl Observation {
    pub(crate) const fn site<'a>(
        &'a self,
        protection: &'a Protection,
        excludes: &'a [Location],
    ) -> Site<'a> {
        Site {
            location: &self.location,
            shape: self.shape,
            boundary: self.boundary,
            listing: &self.listing,
            protection,
            excludes,
        }
    }
}

pub(crate) fn entries(directory: &Path) -> Result<Entries, Rejection> {
    let reader = fs::read_dir(directory).map_err(|e| failure::io(directory, FsOp::ReadDir, &e))?;
    let mut entries = Entries::default();
    for entry in reader {
        let entry = entry.map_err(|e| failure::io(directory, FsOp::ReadEntry, &e))?;
        let kind = entry
            .file_type()
            .map_err(|e| failure::io(&entry.path(), FsOp::FileType, &e))?;
        let name = entry.file_name();
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            entries.dir(name.as_encoded_bytes());
        } else if kind.is_file() {
            entries.file(name.as_encoded_bytes());
        }
    }
    Ok(entries)
}

pub(crate) fn cache_tag(directory: &Path, entries: &Entries) -> CacheTag {
    if !entries.has_file(CACHE_TAG_NAME) {
        return CacheTag::Absent;
    }
    let mut header = [0u8; CACHE_TAG_SIGNATURE.len()];
    match File::open(directory.join(CACHE_TAG_NAME)) {
        Ok(mut file) => match file.read_exact(&mut header) {
            Ok(()) if header.as_slice() == CACHE_TAG_SIGNATURE => CacheTag::Verified,
            Ok(()) | Err(_) => CacheTag::Invalid,
        },
        Err(_unreadable) => CacheTag::Invalid,
    }
}

pub(crate) fn owner_tag(directory: &Path, entries: &Entries) -> OwnerTag {
    if !entries.has_file(crate::owners::MARKER_NAME) {
        return OwnerTag::Absent;
    }
    match crate::owners::declaration(directory) {
        None => OwnerTag::Foreign,
        Some(declaration) => match declaration.role {
            Role::Scratch => OwnerTag::Scratch,
            Role::Cache => OwnerTag::Cache,
        },
    }
}

pub(crate) fn tags(directory: &Path, entries: &Entries) -> Tags {
    Tags {
        cache: cache_tag(directory, entries),
        owner: owner_tag(directory, entries),
    }
}

pub(crate) fn observe(path: &Path) -> Result<Observation, Rejection> {
    let metadata = fs::symlink_metadata(path).map_err(|e| failure::io(path, FsOp::Inspect, &e))?;
    let shape = platform::shape(&metadata);
    let resolved = match shape {
        Shape::Directory => {
            fs::canonicalize(path).map_err(|e| failure::io(path, FsOp::Canonicalize, &e))?
        },
        Shape::Link | Shape::File | Shape::Other => {
            std::path::absolute(path).map_err(|e| failure::io(path, FsOp::Canonicalize, &e))?
        },
    };
    let location = host::locate(&resolved)?;
    let boundary = match resolved.parent() {
        None => Boundary::NoParent,
        Some(parent) => {
            let above =
                fs::symlink_metadata(parent).map_err(|e| failure::io(parent, FsOp::Inspect, &e))?;
            platform::boundary(&above, &metadata)
        },
    };
    let parent = match resolved.parent() {
        None => Entries::default(),
        Some(parent) => entries(parent)?,
    };
    let (child, tag) = match shape {
        Shape::Directory => {
            let child = entries(&resolved)?;
            let tag = tags(&resolved, &child);
            (child, tag)
        },
        Shape::Link | Shape::File | Shape::Other => {
            (Entries::default(), Tags::cache(CacheTag::Absent))
        },
    };
    let identity =
        platform::identity(&resolved).map_err(|e| failure::io(&resolved, FsOp::FileId, &e))?;
    Ok(Observation {
        path: resolved,
        location,
        shape,
        boundary,
        listing: Listing::new(parent, child, tag),
        identity,
    })
}

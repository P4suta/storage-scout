use std::io;

use bollard::Docker;
use bollard::models::SystemDataUsageResponse;
use bollard::query_parameters::{
    DataUsageOptionsBuilder, PruneBuildOptionsBuilder, PruneImagesOptions,
};
use storage_scout_core::managed::{Clearance, Resource};
use storage_scout_core::size::Bytes;
use tokio::runtime::{Builder, Runtime};

const TRANSPORT_TIMEOUT_SECONDS: u64 = 120;

pub(crate) struct Engine {
    client: Docker,
    runtime: Runtime,
    identity: String,
}

impl Engine {
    pub(crate) fn connect() -> io::Result<Self> {
        let endpoint = super::spawn::docker_endpoint()?;
        let client = Docker::connect_with_socket(
            &endpoint,
            TRANSPORT_TIMEOUT_SECONDS,
            bollard::API_DEFAULT_VERSION,
        )
        .map_err(io::Error::other)?;
        let runtime = Builder::new_current_thread().enable_all().build()?;
        let identity = runtime
            .block_on(client.info())
            .map_err(io::Error::other)?
            .id
            .filter(|id| !id.is_empty())
            .ok_or_else(|| io::Error::other("the engine did not report its identity"))?;
        Ok(Self {
            client,
            runtime,
            identity,
        })
    }

    fn verify(&self) -> io::Result<()> {
        let identity = self
            .runtime
            .block_on(self.client.info())
            .map_err(io::Error::other)?
            .id;
        if identity.as_deref() != Some(self.identity.as_str()) {
            return Err(io::Error::other("the container engine identity changed"));
        }
        Ok(())
    }

    pub(crate) fn usage(&self) -> io::Result<(String, SystemDataUsageResponse)> {
        self.verify()?;
        let data = self
            .runtime
            .block_on(self.client.df(Some(
                DataUsageOptionsBuilder::default().verbose(true).build(),
            )))
            .map_err(io::Error::other)?;
        Ok((self.identity.clone(), data))
    }

    pub(crate) fn prune(
        &self,
        resource: Resource,
        clearance: &Clearance,
    ) -> io::Result<Option<Bytes>> {
        if resource != clearance.resource() {
            return Err(io::Error::other("wrong managed capability"));
        }
        self.verify()?;
        let (label, action) = match resource {
            Resource::Image => (
                crate::managed::PRUNE_IMAGES,
                crate::managed::Action::DanglingImages,
            ),
            Resource::BuildCache => (
                crate::managed::PRUNE_BUILD_CACHE,
                crate::managed::Action::UnusedBuildCache,
            ),
            Resource::Toolchain | Resource::Volume | Resource::Container => {
                return Err(io::Error::other("the engine preserves this resource"));
            },
        };
        let current = crate::managed::candidate(
            &self.identity,
            resource,
            label.to_owned(),
            storage_scout_core::managed::References::Unused,
            action,
        )?;
        if &current.id != clearance.id() {
            return Err(io::Error::other("the capability belongs to another engine"));
        }
        let reclaimed =
            match resource {
                Resource::Image => {
                    self.runtime
                        .block_on(self.client.prune_images(None::<PruneImagesOptions>))
                        .map_err(io::Error::other)?
                        .space_reclaimed
                },
                Resource::BuildCache => {
                    self.runtime
                        .block_on(self.client.prune_build(Some(
                            PruneBuildOptionsBuilder::default().all(true).build(),
                        )))
                        .map_err(io::Error::other)?
                        .space_reclaimed
                },
                Resource::Toolchain | Resource::Volume | Resource::Container => {
                    return Err(io::Error::other("the engine preserves this resource"));
                },
            };
        Ok(crate::ingress::reported_bytes(reclaimed))
    }
}

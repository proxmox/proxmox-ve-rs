use std::collections::{BTreeMap, BTreeSet};

use proxmox_frr::FrrConfig;

use crate::common::valid::Valid;
use crate::sdn::fabric::{section_config::node::NodeId, FabricConfig};

/// Builder that helps constructing the FrrConfig.
///
/// The goal is to have one struct collect all the rust-based configurations and then construct the
/// [`FrrConfig`] from it using the build method. In the future the controller configuration will
/// be added here as well.
#[derive(Default)]
pub struct FrrConfigBuilder {
    fabrics: Valid<FabricConfig>,
}

impl FrrConfigBuilder {
    /// Add fabric configuration to the builder
    pub fn add_fabrics(mut self, fabric: Valid<FabricConfig>) -> FrrConfigBuilder {
        self.fabrics = fabric;
        self
    }

    /// Build the complete [`FrrConfig`] from this builder configuration given the hostname of the
    /// node for which we want to build the config. We also inject the common fabric-level options
    /// into the interfaces here. (e.g. the fabric-level "hello-interval" gets added to every
    /// interface if there isn't a more specific one.)
    pub fn build(self, current_node: NodeId) -> Result<FrrConfig, anyhow::Error> {
        let mut frr_config = FrrConfig {
            router: BTreeMap::new(),
            interfaces: BTreeMap::new(),
            access_lists: Vec::new(),
            routemaps: Vec::new(),
            protocol_routemaps: BTreeSet::new(),
        };

        crate::sdn::fabric::frr::build_fabric(current_node, self.fabrics, &mut frr_config)?;

        Ok(frr_config)
    }
}

#[cfg(feature = "frr")]
pub mod frr;
pub mod section_config;

use std::collections::{BTreeMap, HashSet};
use std::marker::PhantomData;
use std::ops::Deref;

use anyhow::Error;
use serde::{Deserialize, Serialize};

use proxmox_section_config::typed::{ApiSectionDataEntry, SectionConfigData};

use crate::common::valid::{Valid, Validatable};

use crate::sdn::fabric::section_config::fabric::{
    Fabric, FabricDeletableProperties, FabricId, FabricSection, FabricSectionUpdater, FabricUpdater,
};
use crate::sdn::fabric::section_config::node::{
    api::{NodeDataUpdater, NodeDeletableProperties, NodeUpdater},
    Node, NodeId, NodeSection,
};
use crate::sdn::fabric::section_config::protocol::openfabric::{
    OpenfabricDeletableProperties, OpenfabricNodeDeletableProperties, OpenfabricNodeProperties,
    OpenfabricNodePropertiesUpdater, OpenfabricProperties, OpenfabricPropertiesUpdater,
};
use crate::sdn::fabric::section_config::protocol::ospf::{
    OspfDeletableProperties, OspfNodeDeletableProperties, OspfNodeProperties,
    OspfNodePropertiesUpdater, OspfProperties, OspfPropertiesUpdater,
};
use crate::sdn::fabric::section_config::{FabricOrNode, Section};

#[derive(thiserror::Error, Debug)]
pub enum FabricConfigError {
    #[error("fabric '{0}' does not exist in configuration")]
    FabricDoesNotExist(String),
    #[error("node '{0}' does not exist in fabric '{1}'")]
    NodeDoesNotExist(String, String),
    #[error("node IP {0} is outside the IP prefix {1} of the fabric")]
    NodeIpOutsideFabricRange(String, String),
    #[error("node has a different protocol than the referenced fabric")]
    ProtocolMismatch,
    #[error("fabric '{0}' already exists in config")]
    DuplicateFabric(String),
    #[error("node '{0}' already exists in config for fabric {1}")]
    DuplicateNode(String, String),
    #[error("fabric {0} contains nodes with duplicated IPs")]
    DuplicateNodeIp(String),
    #[error("fabric '{0}' does not have an IP prefix configured for the node IP {1}")]
    FabricNoIpPrefixForNode(String, String),
    #[error("node '{0}' does not have an IP configured for this fabric prefix {1}")]
    NodeNoIpForFabricPrefix(String, String),
    #[error("fabric '{0}' does not have an IP prefix configured")]
    FabricNoIpPrefix(String),
    #[error("node '{0}' does not have an IP configured")]
    NodeNoIp(String),
    #[error("interface is already in use by another fabric")]
    DuplicateInterface,
    #[error("IPv6 is currently not supported for protocol {0}")]
    Ipv6Unsupported(String),
    // should usually not occur, but we still check for it nonetheless
    #[error("mismatched fabric_id")]
    FabricIdMismatch,
    // this is technically possible, but we don't allow it
    #[error("duplicate OSPF area")]
    DuplicateOspfArea,
    #[error("IP prefix {0} in fabric '{1}' overlaps with IPv4 prefix {2} in fabric '{3}'")]
    OverlappingIp4Prefix(String, String, String, String),
    #[error("IPv6 prefix {0} in fabric '{1}' overlaps with IPv6 prefix {2} in fabric '{3}'")]
    OverlappingIp6Prefix(String, String, String, String),
}

/// An entry in a [`FabricConfig`].
///
/// It enforces compatible types for its containing [`FabricSection`] and [`NodeSection`] via the
/// generic parameters, so only Nodes and Fabrics with compatible types can be inserted into an
/// entry.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct Entry<F, N> {
    // we want to store the enum structs Fabric & Node here, in order to have access to the
    // properties and methods defined on the enum itself.
    // In order to still be able to type-check that an Entry contains the right combination of
    // NodeSection and FabricSection, we type hint the actual types wrapped into Fabric & Node here
    // via PhantomData and only allow insertion of the proper types via the provided methods.
    // Use `fn() -> Section<F>` so that we keep this Send + Sync regardless of F, N. This also
    // allows F and N to be dangling, which is not important for us though, because we don't store
    // it. See https://doc.rust-lang.org/nomicon/phantom-data.html.
    #[serde(skip)]
    _phantom_fabric: PhantomData<fn() -> FabricSection<F>>,
    #[serde(skip)]
    _phantom_node: PhantomData<fn() -> NodeSection<N>>,

    fabric: Fabric,
    nodes: BTreeMap<NodeId, Node>,
}

impl<F, N> Entry<F, N>
where
    Fabric: From<FabricSection<F>>,
    Node: From<NodeSection<N>>,
{
    /// Create a new [`Entry`] from the passed [`FabricSection<F>`] with no nodes.
    fn new(fabric: FabricSection<F>) -> Self {
        Self {
            fabric: fabric.into(),
            nodes: Default::default(),
            _phantom_fabric: PhantomData,
            _phantom_node: PhantomData,
        }
    }

    /// Adds a node to this entry
    ///
    /// # Errors
    ///
    /// Returns an error if the node's fabric_id doesn't match this entry's fabric_id
    /// or if a node with the same ID already exists in this entry.
    fn add_node(&mut self, node: NodeSection<N>) -> Result<(), FabricConfigError> {
        if self.nodes.contains_key(node.id().node_id()) {
            return Err(FabricConfigError::DuplicateNode(
                node.id().node_id().to_string(),
                self.fabric.id().to_string(),
            ));
        }

        if node.id().fabric_id() != self.fabric.id() {
            return Err(FabricConfigError::FabricIdMismatch);
        }

        self.nodes.insert(node.id().node_id().clone(), node.into());

        Ok(())
    }

    /// Get a reference to the node with the passed node_id. Return an error if the node doesn't exist.
    fn get_node(&self, id: &NodeId) -> Result<&Node, FabricConfigError> {
        self.nodes.get(id).ok_or_else(|| {
            FabricConfigError::NodeDoesNotExist(id.to_string(), self.fabric.id().to_string())
        })
    }

    /// Get a mutable reference to the Node with the passed node_id.
    fn get_node_mut(&mut self, id: &NodeId) -> Result<&mut Node, FabricConfigError> {
        self.nodes.get_mut(id).ok_or_else(|| {
            FabricConfigError::NodeDoesNotExist(id.to_string(), self.fabric.id().to_string())
        })
    }

    /// Removes and returns a node with the specified node_id from this entry.
    ///
    /// # Errors
    /// Returns `FabricConfigError::NodeDoesNotExist` if no node with the given node_id exists.
    fn delete_node(&mut self, id: &NodeId) -> Result<Node, FabricConfigError> {
        self.nodes.remove(id).ok_or_else(|| {
            FabricConfigError::NodeDoesNotExist(id.to_string(), self.fabric.id().to_string())
        })
    }

    /// Get entry as a (Fabric, Vec<Node>) pair. This consumes the Entry.
    fn into_pair(self) -> (Fabric, Vec<Node>) {
        (self.fabric, self.nodes.into_values().collect())
    }
}

impl Entry<OpenfabricProperties, OpenfabricNodeProperties> {
    /// Get the OpenFabric fabric config.
    ///
    /// This method is implemented for [`Entry<OpenfabricProperties, OpenfabricNodeProperties>`],
    /// so it is guaranteed that a [`FabricSection<OpenfabricProperties>`] is returned.
    pub fn fabric_section(&self) -> &FabricSection<OpenfabricProperties> {
        if let Fabric::Openfabric(section) = &self.fabric {
            return section;
        }

        unreachable!();
    }

    /// Get the OpenFabric node config for the given node_id.
    ///
    /// This method is implemented for [`Entry<OpenfabricProperties, OpenfabricNodeProperties>`],
    /// so it is guaranteed that a [`NodeSection<OpenfabricNodeProperties>`] is returned.
    /// An error is returned if the node is not found.
    pub fn node_section(
        &self,
        id: &NodeId,
    ) -> Result<&NodeSection<OpenfabricNodeProperties>, FabricConfigError> {
        if let Node::Openfabric(section) = self.get_node(id)? {
            return Ok(section);
        }

        unreachable!();
    }
}

impl Entry<OspfProperties, OspfNodeProperties> {
    /// Get the OSPF fabric config.
    ///
    /// This method is implemented for [`Entry<OspfProperties, OspfNodeProperties>`],
    /// so it is guaranteed that a [`FabricSection<OspfProperties>`] is returned.
    pub fn fabric_section(&self) -> &FabricSection<OspfProperties> {
        if let Fabric::Ospf(section) = &self.fabric {
            return section;
        }

        unreachable!();
    }

    /// Get the OSPF node config for the given node_id.
    ///
    /// This method is implemented for [`Entry<OspfProperties, OspfNodeProperties>`],
    /// so it is guaranteed that a [`NodeSection<OspfNodeProperties>`] is returned.
    /// An error is returned if the node is not found.
    pub fn node_section(
        &self,
        id: &NodeId,
    ) -> Result<&NodeSection<OspfNodeProperties>, FabricConfigError> {
        if let Node::Ospf(section) = self.get_node(id)? {
            return Ok(section);
        }

        unreachable!();
    }
}

/// All possible entries in a [`FabricConfig`].
///
/// It utilizes the [`Entry`] struct to validate proper combinations of [`FabricSection`] and
/// [`NodeSection`].
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum FabricEntry {
    Openfabric(Entry<OpenfabricProperties, OpenfabricNodeProperties>),
    Ospf(Entry<OspfProperties, OspfNodeProperties>),
}

impl FabricEntry {
    /// Adds a node to the fabric entry.
    /// The node must match the protocol type of the fabric entry.
    pub fn add_node(&mut self, node: Node) -> Result<(), FabricConfigError> {
        match (self, node) {
            (FabricEntry::Openfabric(entry), Node::Openfabric(node_section)) => {
                entry.add_node(node_section)
            }
            (FabricEntry::Ospf(entry), Node::Ospf(node_section)) => entry.add_node(node_section),
            _ => Err(FabricConfigError::ProtocolMismatch),
        }
    }

    /// Get a reference to a Node specified by the node_id. Returns an error if the node is not
    /// found.
    pub fn get_node(&self, id: &NodeId) -> Result<&Node, FabricConfigError> {
        match self {
            FabricEntry::Openfabric(entry) => entry.get_node(id),
            FabricEntry::Ospf(entry) => entry.get_node(id),
        }
    }

    /// Get a mutable reference to a Node specified by the node_id. Returns an error if the node is not
    /// found.
    pub fn get_node_mut(&mut self, id: &NodeId) -> Result<&mut Node, FabricConfigError> {
        match self {
            FabricEntry::Openfabric(entry) => entry.get_node_mut(id),
            FabricEntry::Ospf(entry) => entry.get_node_mut(id),
        }
    }

    /// Update the Node with the specified node_id using the passed [`NodeUpdater`].
    pub fn update_node(
        &mut self,
        id: &NodeId,
        updater: NodeUpdater,
    ) -> Result<(), FabricConfigError> {
        let node = self.get_node_mut(id)?;

        match (node, updater) {
            (Node::Openfabric(node_section), NodeUpdater::Openfabric(updater)) => {
                let NodeDataUpdater::<
                    OpenfabricNodePropertiesUpdater,
                    OpenfabricNodeDeletableProperties,
                > {
                    ip,
                    ip6,
                    properties: OpenfabricNodePropertiesUpdater { interfaces },
                    delete,
                } = updater;

                if let Some(ip) = ip {
                    node_section.ip = Some(ip);
                }

                if let Some(ip) = ip6 {
                    node_section.ip6 = Some(ip);
                }

                if let Some(interfaces) = interfaces {
                    node_section.properties.interfaces = interfaces;
                }

                for property in delete {
                    match property {
                        NodeDeletableProperties::Ip => node_section.ip = None,
                        NodeDeletableProperties::Ip6 => node_section.ip6 = None,
                        NodeDeletableProperties::Protocol(
                            OpenfabricNodeDeletableProperties::Interfaces,
                        ) => node_section.properties.interfaces = Vec::new(),
                    }
                }

                Ok(())
            }
            (Node::Ospf(node_section), NodeUpdater::Ospf(updater)) => {
                let NodeDataUpdater::<OspfNodePropertiesUpdater, OspfNodeDeletableProperties> {
                    ip,
                    ip6,
                    properties: OspfNodePropertiesUpdater { interfaces },
                    delete,
                } = updater;

                if let Some(ip) = ip {
                    node_section.ip = Some(ip);
                }

                if let Some(ip) = ip6 {
                    node_section.ip6 = Some(ip);
                }

                if let Some(interfaces) = interfaces {
                    node_section.properties.interfaces = interfaces;
                }

                for property in delete {
                    match property {
                        NodeDeletableProperties::Ip => node_section.ip = None,
                        NodeDeletableProperties::Ip6 => node_section.ip6 = None,
                        NodeDeletableProperties::Protocol(
                            OspfNodeDeletableProperties::Interfaces,
                        ) => node_section.properties.interfaces = Vec::new(),
                    }
                }

                Ok(())
            }
            _ => Err(FabricConfigError::ProtocolMismatch),
        }
    }

    /// Get an iterator over all the nodes in this fabric.
    pub fn nodes(&self) -> impl Iterator<Item = (&NodeId, &Node)> + '_ {
        match self {
            FabricEntry::Openfabric(entry) => entry.nodes.iter(),
            FabricEntry::Ospf(entry) => entry.nodes.iter(),
        }
    }

    /// Delete the node specified with the node_id. Returns an error if it doesn't exist.
    pub fn delete_node(&mut self, id: &NodeId) -> Result<Node, FabricConfigError> {
        match self {
            FabricEntry::Openfabric(entry) => entry.delete_node(id),
            FabricEntry::Ospf(entry) => entry.delete_node(id),
        }
    }

    /// Consume this entry and return a (Fabric, Vec<Node>) pair. This is used to write to the
    /// section-config file.
    pub fn into_section_config(self) -> (Fabric, Vec<Node>) {
        match self {
            FabricEntry::Openfabric(entry) => entry.into_pair(),
            FabricEntry::Ospf(entry) => entry.into_pair(),
        }
    }

    /// Get a reference to the Fabric.
    pub fn fabric(&self) -> &Fabric {
        match self {
            FabricEntry::Openfabric(entry) => &entry.fabric,
            FabricEntry::Ospf(entry) => &entry.fabric,
        }
    }

    /// Get a mutable reference to the Fabric.
    pub fn fabric_mut(&mut self) -> &mut Fabric {
        match self {
            FabricEntry::Openfabric(entry) => &mut entry.fabric,
            FabricEntry::Ospf(entry) => &mut entry.fabric,
        }
    }
}

impl From<Fabric> for FabricEntry {
    fn from(fabric: Fabric) -> Self {
        match fabric {
            Fabric::Openfabric(fabric_section) => {
                FabricEntry::Openfabric(Entry::new(fabric_section))
            }
            Fabric::Ospf(fabric_section) => FabricEntry::Ospf(Entry::new(fabric_section)),
        }
    }
}

impl Validatable for FabricEntry {
    type Error = FabricConfigError;

    /// Validates the [`FabricEntry`] configuration.
    ///
    /// Ensures that:
    /// - Node IP addresses are within their respective fabric IP prefix ranges
    /// - IP addresses are unique across all nodes in the fabric
    /// - Each node passes its own validation checks
    fn validate(&self) -> Result<(), FabricConfigError> {
        let fabric = self.fabric();

        let mut ips = HashSet::new();
        let mut ip6s = HashSet::new();

        for (_id, node) in self.nodes() {
            // Check IPv4 prefix and ip
            match (fabric.ip_prefix(), node.ip()) {
                (None, Some(ip)) => {
                    // Fabric needs to have a prefix if a node has an IP configured
                    return Err(FabricConfigError::FabricNoIpPrefixForNode(
                        fabric.id().to_string(),
                        ip.to_string(),
                    ));
                }
                (Some(prefix), None) => {
                    return Err(FabricConfigError::NodeNoIpForFabricPrefix(
                        node.id().to_string(),
                        prefix.to_string(),
                    ));
                }
                (Some(prefix), Some(ip)) => {
                    // Fabric prefix needs to contain the node IP
                    if !prefix.contains_address(&ip) {
                        return Err(FabricConfigError::NodeIpOutsideFabricRange(
                            ip.to_string(),
                            prefix.to_string(),
                        ));
                    }
                }
                _ => {}
            }

            // Check IPv6 prefix and ip
            match (fabric.ip6_prefix(), node.ip6()) {
                (None, Some(ip)) => {
                    // Fabric needs to have a prefix if a node has an IP configured
                    return Err(FabricConfigError::FabricNoIpPrefixForNode(
                        fabric.id().to_string(),
                        ip.to_string(),
                    ));
                }
                (Some(prefix), None) => {
                    return Err(FabricConfigError::NodeNoIpForFabricPrefix(
                        node.id().to_string(),
                        prefix.to_string(),
                    ))
                }
                (Some(prefix), Some(ip)) => {
                    // Fabric prefix needs to contain the node IP
                    if !prefix.contains_address(&ip) {
                        return Err(FabricConfigError::NodeIpOutsideFabricRange(
                            ip.to_string(),
                            prefix.to_string(),
                        ));
                    }
                }
                _ => {}
            }

            // Node IPs need to be unique inside a fabric
            if !node.ip().map(|ip| ips.insert(ip)).unwrap_or(true) {
                return Err(FabricConfigError::DuplicateNodeIp(fabric.id().to_string()));
            }

            // Node IPs need to be unique inside a fabric
            if !node.ip6().map(|ip| ip6s.insert(ip)).unwrap_or(true) {
                return Err(FabricConfigError::DuplicateNodeIp(fabric.id().to_string()));
            }

            node.validate()?;
        }

        fabric.validate()
    }
}

/// A complete SDN fabric configuration.
///
/// This struct contains the whole fabric configuration in a tree-like structure (fabrics -> nodes
/// -> interfaces).
#[derive(Default, Debug, Serialize, Deserialize, Clone, Hash)]
pub struct FabricConfig {
    fabrics: BTreeMap<FabricId, FabricEntry>,
}

impl Deref for FabricConfig {
    type Target = BTreeMap<FabricId, FabricEntry>;

    fn deref(&self) -> &Self::Target {
        &self.fabrics
    }
}

impl Validatable for FabricConfig {
    type Error = FabricConfigError;

    /// Validate the [`FabricConfig`].
    ///
    /// Ensures that:
    /// - (node, interface) combinations exist only once across all fabrics
    /// - every entry (fabric) validates
    /// - all the ospf fabrics have different areas
    /// - IP prefixes of fabrics do not overlap
    fn validate(&self) -> Result<(), FabricConfigError> {
        let mut node_interfaces = HashSet::new();
        let mut ospf_area = HashSet::new();

        // Check for overlapping IP prefixes across fabrics
        let fabrics: Vec<_> = self.fabrics.values().map(|f| f.fabric()).collect();
        let cartesian_product = fabrics
            .iter()
            .enumerate()
            .flat_map(|(i, f1)| fabrics.iter().skip(i + 1).map(move |f2| (f1, f2)));

        for (fabric1, fabric2) in cartesian_product {
            if let (Some(prefix1), Some(prefix2)) = (fabric1.ip_prefix(), fabric2.ip_prefix()) {
                if prefix1.overlaps(&prefix2) {
                    return Err(FabricConfigError::OverlappingIp4Prefix(
                        prefix2.to_string(),
                        fabric2.id().to_string(),
                        prefix1.to_string(),
                        fabric1.id().to_string(),
                    ));
                }
            }
            if let (Some(prefix1), Some(prefix2)) = (fabric1.ip6_prefix(), fabric2.ip6_prefix()) {
                if prefix1.overlaps(&prefix2) {
                    return Err(FabricConfigError::OverlappingIp6Prefix(
                        prefix2.to_string(),
                        fabric2.id().to_string(),
                        prefix1.to_string(),
                        fabric1.id().to_string(),
                    ));
                }
            }
        }

        // validate that each (node, interface) combination exists only once across all fabrics
        for entry in self.fabrics.values() {
            if let FabricEntry::Ospf(entry) = entry {
                if !ospf_area.insert(
                    entry
                        .fabric_section()
                        .properties()
                        .area()
                        .get_ipv4_representation(),
                ) {
                    return Err(FabricConfigError::DuplicateOspfArea);
                }
            }
            for (node_id, node) in entry.nodes() {
                match node {
                    Node::Ospf(node_section) => {
                        if !node_section.properties().interfaces().all(|interface| {
                            node_interfaces.insert((node_id, interface.name.as_str()))
                        }) {
                            return Err(FabricConfigError::DuplicateInterface);
                        }
                    }
                    Node::Openfabric(node_section) => {
                        if !node_section.properties().interfaces().all(|interface| {
                            node_interfaces.insert((node_id, interface.name.as_str()))
                        }) {
                            return Err(FabricConfigError::DuplicateInterface);
                        }
                    }
                }
            }

            entry.validate()?;
        }

        Ok(())
    }
}

impl FabricConfig {
    /// Add a fabric to the [`FabricConfig`].
    ///
    /// Returns an error if a fabric with the same name exists.
    pub fn add_fabric(&mut self, mut fabric: Fabric) -> Result<(), FabricConfigError> {
        if self.fabrics.contains_key(fabric.id()) {
            return Err(FabricConfigError::DuplicateFabric(fabric.id().to_string()));
        }

        if let Some(prefix) = fabric.ip_prefix() {
            fabric.set_ip_prefix(prefix.canonical());
        }
        if let Some(prefix) = fabric.ip6_prefix() {
            fabric.set_ip6_prefix(prefix.canonical());
        }

        self.fabrics.insert(fabric.id().clone(), fabric.into());

        Ok(())
    }

    /// Get a reference to the fabric with the specified fabric_id.
    pub fn get_fabric(&self, id: &FabricId) -> Result<&FabricEntry, FabricConfigError> {
        self.fabrics
            .get(id)
            .ok_or_else(|| FabricConfigError::FabricDoesNotExist(id.to_string()))
    }

    /// Get a mutable reference to the fabric with the specified fabric_id.
    pub fn get_fabric_mut(&mut self, id: &FabricId) -> Result<&mut FabricEntry, FabricConfigError> {
        self.fabrics
            .get_mut(id)
            .ok_or_else(|| FabricConfigError::FabricDoesNotExist(id.to_string()))
    }

    /// Returns an iterator over mutable references to all [`FabricEntry`] in the config
    pub fn get_fabrics_mut(&mut self) -> impl Iterator<Item = &mut FabricEntry> {
        self.fabrics.values_mut()
    }

    /// Delete a fabric with the specified fabric_id from the [`FabricConfig`].
    pub fn delete_fabric(&mut self, id: &FabricId) -> Result<FabricEntry, FabricConfigError> {
        self.fabrics
            .remove(id)
            .ok_or_else(|| FabricConfigError::FabricDoesNotExist(id.to_string()))
    }

    /// Update the fabric specified by the fabric_id using the [`FabricUpdater`].
    pub fn update_fabric(
        &mut self,
        id: &FabricId,
        updater: FabricUpdater,
    ) -> Result<(), FabricConfigError> {
        let fabric = self.get_fabric_mut(id)?.fabric_mut();

        match (fabric, updater) {
            (Fabric::Openfabric(fabric_section), FabricUpdater::Openfabric(updater)) => {
                let FabricSectionUpdater::<
                    OpenfabricPropertiesUpdater,
                    OpenfabricDeletableProperties,
                > {
                    ip_prefix,
                    ip6_prefix,
                    properties:
                        OpenfabricPropertiesUpdater {
                            hello_interval,
                            csnp_interval,
                        },
                    delete,
                } = updater;

                if let Some(prefix) = ip_prefix {
                    fabric_section.ip_prefix = Some(prefix);
                }

                if let Some(prefix) = ip6_prefix {
                    fabric_section.ip6_prefix = Some(prefix);
                }

                if let Some(hello_interval) = hello_interval {
                    fabric_section.properties.hello_interval = Some(hello_interval);
                }

                if let Some(csnp_interval) = csnp_interval {
                    fabric_section.properties.csnp_interval = Some(csnp_interval);
                }

                for property in delete {
                    match property {
                        FabricDeletableProperties::IpPrefix => {
                            fabric_section.ip_prefix = None;
                        }
                        FabricDeletableProperties::Ip6Prefix => {
                            fabric_section.ip6_prefix = None;
                        }
                        FabricDeletableProperties::Protocol(
                            OpenfabricDeletableProperties::CsnpInterval,
                        ) => fabric_section.properties.csnp_interval = None,
                        FabricDeletableProperties::Protocol(
                            OpenfabricDeletableProperties::HelloInterval,
                        ) => fabric_section.properties.hello_interval = None,
                    }
                }

                Ok(())
            }
            (Fabric::Ospf(fabric_section), FabricUpdater::Ospf(updater)) => {
                let FabricSectionUpdater::<OspfPropertiesUpdater, OspfDeletableProperties> {
                    ip_prefix,
                    ip6_prefix,
                    properties: OspfPropertiesUpdater { area },
                    delete,
                } = updater;

                if let Some(prefix) = ip_prefix {
                    fabric_section.ip_prefix = Some(prefix);
                }

                if let Some(prefix) = ip6_prefix {
                    fabric_section.ip6_prefix = Some(prefix);
                }

                if let Some(area) = area {
                    fabric_section.properties.area = area;
                }

                for property in delete {
                    match property {
                        FabricDeletableProperties::IpPrefix => {
                            fabric_section.ip_prefix = None;
                        }
                        FabricDeletableProperties::Ip6Prefix => {
                            fabric_section.ip6_prefix = None;
                        }
                    }
                }

                Ok(())
            }
            _ => Err(FabricConfigError::ProtocolMismatch),
        }
    }

    /// Constructs a valid [`FabricConfig`] from section-config data.
    ///
    /// Iterates through the [`SectionConfigData<Section>`] and matches on the [`Section`] enum. Then
    /// construct the [`FabricConfig`] and validate it.
    pub fn from_section_config(
        config: SectionConfigData<Section>,
    ) -> Result<Valid<Self>, FabricConfigError> {
        let mut fabrics = BTreeMap::new();
        let mut nodes = Vec::new();

        for (_id, section) in config {
            let fabric_or_node = FabricOrNode::from(section);

            match fabric_or_node {
                FabricOrNode::Fabric(fabric) => {
                    fabrics.insert(fabric.id().clone(), FabricEntry::from(fabric));
                }
                FabricOrNode::Node(node) => {
                    nodes.push(node);
                }
            };
        }

        for node in nodes {
            fabrics
                .get_mut(node.id().fabric_id())
                .ok_or_else(|| {
                    FabricConfigError::FabricDoesNotExist(node.id().fabric_id().to_string())
                })?
                .add_node(node)?;
        }

        let config = Self { fabrics };
        config.into_valid()
    }

    /// Constructs a valid [`FabricConfig`] from the raw section-config file content.
    ///
    /// This will call the [`Section::parse_section_config`] function to parse the raw string into a
    /// [`SectionConfigData<Section>`] struct. Then construct the valid [`FabricConfig`] with
    /// [`Self::from_section_config`].
    pub fn parse_section_config(config: &str) -> Result<Valid<Self>, Error> {
        let data = Section::parse_section_config("fabrics.cfg", config)?;
        Self::from_section_config(data).map_err(anyhow::Error::from)
    }

    /// Validate [`FabricConfig`] and write the raw config to a String.
    ///
    /// Validates the config and calls [`Valid<FabricConfig>::write_section_config`].
    pub fn write_section_config(&self) -> Result<String, Error> {
        self.clone().into_valid()?.write_section_config()
    }
}

impl Valid<FabricConfig> {
    /// Converts a valid [`FabricConfig`] into a [`SectionConfigData<Section>`].
    ///
    /// This function is implemented on [`Valid<FabricConfig>`], ensuring that only a valid
    /// [`FabricConfig`] can be written to the file.
    pub fn into_section_config(self) -> SectionConfigData<Section> {
        let config = self.into_inner();

        let mut section_config = SectionConfigData::default();

        for (fabric_id, fabric_entry) in config.fabrics {
            let (fabric, fabric_nodes) = fabric_entry.into_section_config();

            section_config.insert(fabric_id.to_string(), Section::from(fabric));

            for node in fabric_nodes {
                section_config.insert(node.id().to_string(), Section::from(node));
            }
        }

        section_config
    }

    /// Consumes the [`Valid<FabricConfig>`] and writes the raw section-config content to a String.
    ///
    /// This function is implemented on [`Valid<FabricConfig>`], ensuring that only a valid
    /// [`FabricConfig`] can be written to the file.
    pub fn write_section_config(self) -> Result<String, Error> {
        Section::write_section_config("fabrics.cfg", &self.into_section_config())
    }
}

#[cfg(feature = "frr")]
pub mod frr;
pub mod section_config;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::marker::PhantomData;
use std::ops::Deref;

use anyhow::Error;
use section_config::protocol::wireguard::WireGuardProperties;
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
use crate::sdn::fabric::section_config::protocol::bgp::{
    bgp_router_id, BgpDeletableProperties, BgpNode, BgpNodeDeletableProperties,
    BgpNodePropertiesUpdater, BgpProperties, BgpPropertiesUpdater,
};
use crate::sdn::fabric::section_config::protocol::openfabric::{
    OpenfabricDeletableProperties, OpenfabricNodeDeletableProperties, OpenfabricNodeProperties,
    OpenfabricNodePropertiesUpdater, OpenfabricProperties, OpenfabricPropertiesUpdater,
};
use crate::sdn::fabric::section_config::protocol::ospf::{
    OspfDeletableProperties, OspfNodeDeletableProperties, OspfNodeProperties,
    OspfNodePropertiesUpdater, OspfProperties, OspfPropertiesUpdater,
};
use crate::sdn::fabric::section_config::protocol::wireguard::{
    WireGuardDeletableProperties, WireGuardNode, WireGuardNodeDeletableProperties,
    WireGuardNodePeer, WireGuardNodeUpdater, WireGuardPropertiesUpdater,
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
    #[error("BGP router-id collision: nodes '{0}' and '{1}' both resolve to router-id {2}")]
    DuplicateBgpRouterId(String, String, std::net::Ipv4Addr),
    #[error("BGP router-id for node '{0}' resolved to 0.0.0.0; pick an explicit IPv4 address or a different IPv6 address")]
    InvalidBgpRouterId(String),
    #[error("IP prefix {0} in fabric '{1}' overlaps with IPv4 prefix {2} in fabric '{3}'")]
    OverlappingIp4Prefix(String, String, String, String),
    #[error("IPv6 prefix {0} in fabric '{1}' overlaps with IPv6 prefix {2} in fabric '{3}'")]
    OverlappingIp6Prefix(String, String, String, String),
    #[error("peer configuration references non-existing local interface '{0}'")]
    InvalidLocalInterfaceReference(String),
    #[error("peer configuration references non-existing interface '{0}' on node '{1}'")]
    InvalidRemoteInterfaceReference(String, String),
    #[error("peer configuration references non-existing external node '{0}'")]
    InvalidExternalNodeReference(String),
    #[error("WireGuard interface listen port duplicated in node configuration: {0}")]
    DuplicatePort(String),
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

macro_rules! impl_entry {
    ($variant:ident, $propty:ty, $nodepropty:ty) => {
        impl Entry<$propty, $nodepropty> {
            pub fn fabric_section(&self) -> &FabricSection<$propty> {
                if let Fabric::$variant(section) = &self.fabric {
                    return section;
                }

                unreachable!();
            }

            pub fn node_section(
                &self,
                id: &NodeId,
            ) -> Result<&NodeSection<$nodepropty>, FabricConfigError> {
                if let Node::$variant(section) = self.get_node(id)? {
                    return Ok(section);
                }

                unreachable!();
            }
        }
    };
}

impl_entry!(Openfabric, OpenfabricProperties, OpenfabricNodeProperties);
impl_entry!(Ospf, OspfProperties, OspfNodeProperties);
impl_entry!(WireGuard, WireGuardProperties, WireGuardNode);
impl_entry!(Bgp, BgpProperties, BgpNode);

/// All possible entries in a [`FabricConfig`].
///
/// It utilizes the [`Entry`] struct to validate proper combinations of [`FabricSection`] and
/// [`NodeSection`].
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum FabricEntry {
    Openfabric(Entry<OpenfabricProperties, OpenfabricNodeProperties>),
    Ospf(Entry<OspfProperties, OspfNodeProperties>),
    WireGuard(Entry<WireGuardProperties, WireGuardNode>),
    Bgp(Entry<BgpProperties, BgpNode>),
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
            (FabricEntry::WireGuard(entry), Node::WireGuard(node_section)) => {
                entry.add_node(node_section)
            }
            (FabricEntry::Bgp(entry), Node::Bgp(node_section)) => entry.add_node(node_section),
            _ => Err(FabricConfigError::ProtocolMismatch),
        }
    }

    /// Get a reference to a Node specified by the node_id. Returns an error if the node is not
    /// found.
    pub fn get_node(&self, id: &NodeId) -> Result<&Node, FabricConfigError> {
        match self {
            FabricEntry::Openfabric(entry) => entry.get_node(id),
            FabricEntry::Ospf(entry) => entry.get_node(id),
            FabricEntry::WireGuard(entry) => entry.get_node(id),
            FabricEntry::Bgp(entry) => entry.get_node(id),
        }
    }

    /// Get a mutable reference to a Node specified by the node_id. Returns an error if the node is not
    /// found.
    pub fn get_node_mut(&mut self, id: &NodeId) -> Result<&mut Node, FabricConfigError> {
        match self {
            FabricEntry::Openfabric(entry) => entry.get_node_mut(id),
            FabricEntry::Ospf(entry) => entry.get_node_mut(id),
            FabricEntry::WireGuard(entry) => entry.get_node_mut(id),
            FabricEntry::Bgp(entry) => entry.get_node_mut(id),
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
            (Node::WireGuard(node_section), NodeUpdater::WireGuard(updater)) => {
                let NodeDataUpdater::<WireGuardNodeUpdater, WireGuardNodeDeletableProperties> {
                    ip,
                    ip6,
                    properties,
                    delete,
                } = updater;

                if let Some(ip) = ip {
                    node_section.ip = Some(ip);
                }

                if let Some(ip) = ip6 {
                    node_section.ip6 = Some(ip);
                }

                for property in &delete {
                    match property {
                        NodeDeletableProperties::Ip => node_section.ip = None,
                        NodeDeletableProperties::Ip6 => node_section.ip6 = None,
                        // handled below, since internal / external nodes have different properties
                        NodeDeletableProperties::Protocol(_) => continue,
                    }
                }

                match (node_section.properties_mut(), properties) {
                    (
                        WireGuardNode::Internal(internal_wireguard_node),
                        WireGuardNodeUpdater::Internal(internal_wireguard_node_updater),
                    ) => {
                        if let Some(interfaces) = internal_wireguard_node_updater.interfaces {
                            internal_wireguard_node.interfaces = interfaces;
                        }

                        if let Some(endpoint) = internal_wireguard_node_updater.endpoint {
                            internal_wireguard_node.endpoint = Some(endpoint);
                        }

                        if let Some(peers) = internal_wireguard_node_updater.peers {
                            internal_wireguard_node.peers = peers;
                        }

                        if let Some(allowed_ips) = internal_wireguard_node_updater.allowed_ips {
                            internal_wireguard_node.allowed_ips = allowed_ips;
                        }

                        for property in &delete {
                            match property {
                                NodeDeletableProperties::Protocol(protocol_property) => {
                                    match protocol_property {
                                        WireGuardNodeDeletableProperties::Interfaces => {
                                            internal_wireguard_node.interfaces = Vec::new()
                                        }
                                        WireGuardNodeDeletableProperties::Endpoint => {
                                            internal_wireguard_node.endpoint = None
                                        }
                                        WireGuardNodeDeletableProperties::Peers => {
                                            internal_wireguard_node.peers = Vec::new()
                                        }
                                        WireGuardNodeDeletableProperties::AllowedIps => {
                                            internal_wireguard_node.allowed_ips = Vec::new()
                                        }
                                    }
                                }
                                _ => continue,
                            }
                        }

                        Ok(())
                    }
                    (
                        WireGuardNode::External(external_wire_guard_node),
                        WireGuardNodeUpdater::External(external_wire_guard_node_updater),
                    ) => {
                        if let Some(endpoint) = external_wire_guard_node_updater.endpoint {
                            external_wire_guard_node.endpoint = endpoint;
                        }

                        if let Some(public_key) = external_wire_guard_node_updater.public_key {
                            external_wire_guard_node.public_key = public_key;
                        }

                        if let Some(allowed_ips) = external_wire_guard_node_updater.allowed_ips {
                            external_wire_guard_node.allowed_ips = allowed_ips;
                        }

                        for property in &delete {
                            match property {
                                NodeDeletableProperties::Protocol(protocol_property) => {
                                    match protocol_property {
                                        WireGuardNodeDeletableProperties::AllowedIps => {
                                            external_wire_guard_node.allowed_ips = Vec::new()
                                        }
                                        _ => return Err(FabricConfigError::ProtocolMismatch),
                                    }
                                }
                                _ => continue,
                            }
                        }

                        Ok(())
                    }
                    _ => Err(FabricConfigError::ProtocolMismatch),
                }
            }
            (Node::Bgp(node_section), NodeUpdater::Bgp(updater)) => {
                let BgpNode::Internal(ref mut props) = node_section.properties else {
                    return Err(FabricConfigError::ProtocolMismatch);
                };

                let NodeDataUpdater::<BgpNodePropertiesUpdater, BgpNodeDeletableProperties> {
                    ip,
                    ip6,
                    properties: BgpNodePropertiesUpdater { asn, interfaces },
                    delete,
                } = updater;

                if let Some(ip) = ip {
                    node_section.ip = Some(ip);
                }

                if let Some(ip) = ip6 {
                    node_section.ip6 = Some(ip);
                }

                if let Some(asn) = asn {
                    props.asn = asn;
                }

                if let Some(interfaces) = interfaces {
                    props.interfaces = interfaces;
                }

                for property in delete {
                    match property {
                        NodeDeletableProperties::Ip => node_section.ip = None,
                        NodeDeletableProperties::Ip6 => node_section.ip6 = None,
                        NodeDeletableProperties::Protocol(
                            BgpNodeDeletableProperties::Interfaces,
                        ) => props.interfaces = Vec::new(),
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
            FabricEntry::WireGuard(entry) => entry.nodes.iter(),
            FabricEntry::Bgp(entry) => entry.nodes.iter(),
        }
    }

    /// Delete the node specified with the node_id. Returns an error if it doesn't exist.
    pub fn delete_node(&mut self, id: &NodeId) -> Result<Node, FabricConfigError> {
        match self {
            FabricEntry::Openfabric(entry) => entry.delete_node(id),
            FabricEntry::Ospf(entry) => entry.delete_node(id),
            FabricEntry::WireGuard(entry) => entry.delete_node(id),
            FabricEntry::Bgp(entry) => entry.delete_node(id),
        }
    }

    /// Consume this entry and return a (Fabric, Vec<Node>) pair. This is used to write to the
    /// section-config file.
    pub fn into_section_config(self) -> (Fabric, Vec<Node>) {
        match self {
            FabricEntry::Openfabric(entry) => entry.into_pair(),
            FabricEntry::Ospf(entry) => entry.into_pair(),
            FabricEntry::WireGuard(entry) => entry.into_pair(),
            FabricEntry::Bgp(entry) => entry.into_pair(),
        }
    }

    /// Get a reference to the Fabric.
    pub fn fabric(&self) -> &Fabric {
        match self {
            FabricEntry::Openfabric(entry) => &entry.fabric,
            FabricEntry::Ospf(entry) => &entry.fabric,
            FabricEntry::WireGuard(entry) => &entry.fabric,
            FabricEntry::Bgp(entry) => &entry.fabric,
        }
    }

    /// Get a mutable reference to the Fabric.
    pub fn fabric_mut(&mut self) -> &mut Fabric {
        match self {
            FabricEntry::Openfabric(entry) => &mut entry.fabric,
            FabricEntry::Ospf(entry) => &mut entry.fabric,
            FabricEntry::WireGuard(entry) => &mut entry.fabric,
            FabricEntry::Bgp(entry) => &mut entry.fabric,
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
            Fabric::WireGuard(fabric_section) => FabricEntry::WireGuard(Entry::new(fabric_section)),
            Fabric::Bgp(fabric_section) => FabricEntry::Bgp(Entry::new(fabric_section)),
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
    /// - For BGP fabrics, derived router-ids are unique across nodes (catches
    ///   FNV-1a hash collisions for IPv6-only nodes) and not 0.0.0.0 (FRR
    ///   rejects 0.0.0.0; a hash output of zero is astronomically unlikely
    ///   but not impossible)
    fn validate(&self) -> Result<(), FabricConfigError> {
        let fabric = self.fabric();

        let mut ips = HashSet::new();
        let mut ip6s = HashSet::new();

        if let FabricEntry::WireGuard(entry) = self {
            // check if all interfaces referenced by the peer definitions exist inside the
            // fabric
            let mut all_interfaces = HashSet::new();
            let mut all_external_nodes = HashSet::new();

            let mut internal_peers = HashSet::new();
            let mut external_peers = HashSet::new();

            let mut ipv4_addresses = HashSet::new();
            let mut ipv6_addresses = HashSet::new();

            for node_id in entry.nodes.keys() {
                let node_section = entry.node_section(node_id)?;

                match node_section.properties() {
                    WireGuardNode::Internal(node) => {
                        for interface in node.interfaces() {
                            all_interfaces.insert((&node_section.id.node_id, &interface.name));

                            // reject any duplicate IPs on interfaces
                            if !interface
                                .ip()
                                .map(|ip| ipv4_addresses.insert(ip))
                                .unwrap_or(true)
                            {
                                return Err(FabricConfigError::DuplicateNodeIp(
                                    fabric.id().to_string(),
                                ));
                            }

                            if !interface
                                .ip6()
                                .map(|ip6| ipv6_addresses.insert(ip6))
                                .unwrap_or(true)
                            {
                                return Err(FabricConfigError::DuplicateNodeIp(
                                    fabric.id().to_string(),
                                ));
                            }
                        }

                        for peer in node.peers() {
                            match peer {
                                WireGuardNodePeer::Internal(peer) => {
                                    internal_peers.insert((&peer.node, &peer.node_iface))
                                }
                                WireGuardNodePeer::External(peer) => {
                                    external_peers.insert(&peer.node)
                                }
                            };
                        }
                    }
                    WireGuardNode::External(_node) => {
                        all_external_nodes.insert(node_section.id().node_id());
                    }
                }
            }

            for (node_id, interface) in internal_peers.difference(&all_interfaces) {
                return Err(FabricConfigError::InvalidRemoteInterfaceReference(
                    interface.to_string(),
                    node_id.to_string(),
                ));
            }

            for node_id in external_peers.difference(&all_external_nodes) {
                return Err(FabricConfigError::InvalidExternalNodeReference(
                    node_id.to_string(),
                ));
            }
        }

        for (_id, node) in self.nodes() {
            node.validate()?;

            // Node IPs need to be unique inside a fabric
            if !node.ip().map(|ip| ips.insert(ip)).unwrap_or(true) {
                return Err(FabricConfigError::DuplicateNodeIp(fabric.id().to_string()));
            }

            // Node IPs need to be unique inside a fabric
            if !node.ip6().map(|ip| ip6s.insert(ip)).unwrap_or(true) {
                return Err(FabricConfigError::DuplicateNodeIp(fabric.id().to_string()));
            }

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
        }

        // Per-node IPs are unique by the checks above. Router-ids can still
        // collide when at least one node falls back to FNV-1a on its IPv6
        // address (the hash is 32 bits wide, so two distinct IPv6 addresses
        // can map to the same router-id).
        if let FabricEntry::Bgp(bgp_entry) = self {
            let mut seen_router_ids: HashMap<std::net::Ipv4Addr, &NodeId> = HashMap::new();
            for (node_id, node) in &bgp_entry.nodes {
                let Node::Bgp(node_section) = node else {
                    continue;
                };
                if !matches!(node_section.properties(), BgpNode::Internal(_)) {
                    continue;
                }
                if let Some(router_id) = bgp_router_id(node_section) {
                    if router_id.is_unspecified() {
                        return Err(FabricConfigError::InvalidBgpRouterId(
                            node_id.to_string(),
                        ));
                    }
                    if let Some(prev) = seen_router_ids.insert(router_id, node_id) {
                        return Err(FabricConfigError::DuplicateBgpRouterId(
                            prev.to_string(),
                            node_id.to_string(),
                            router_id,
                        ));
                    }
                }
            }
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
        let mut wireguard_interfaces = HashSet::new();
        let mut wireguard_listen_ports = HashSet::new();
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
        // additionally, for wireguard check the listen ports of the interfaces as well
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
                    Node::WireGuard(node_section) => {
                        if let WireGuardNode::Internal(internal_node) = node_section.properties() {
                            if !internal_node.interfaces().all(|interface| {
                                wireguard_interfaces.insert((node_id, interface.name.as_str()))
                            }) {
                                return Err(FabricConfigError::DuplicateInterface);
                            }
                            for interface in internal_node.interfaces() {
                                if !wireguard_listen_ports.insert((node_id, interface.listen_port))
                                {
                                    return Err(FabricConfigError::DuplicatePort(
                                        interface.listen_port.to_string(),
                                    ));
                                }
                            }
                        }
                    }
                    Node::Bgp(node_section) => {
                        if let BgpNode::Internal(props) = node_section.properties() {
                            if !props.interfaces().all(|interface| {
                                node_interfaces.insert((node_id, interface.name().as_str()))
                            }) {
                                return Err(FabricConfigError::DuplicateInterface);
                            }
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

    /// Get an iterator over all the nodes in all fabrics.
    pub fn all_nodes(&self) -> impl Iterator<Item = (&NodeId, &Node)> + '_ {
        self.values().flat_map(|entry| entry.nodes())
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
                            route_filter,
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

                if let Some(route_filter) = route_filter {
                    fabric_section.properties.route_filter = Some(route_filter);
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
                        FabricDeletableProperties::Protocol(
                            OpenfabricDeletableProperties::RouteFilter,
                        ) => fabric_section.properties.route_filter = None,
                    }
                }

                Ok(())
            }
            (Fabric::Ospf(fabric_section), FabricUpdater::Ospf(updater)) => {
                let FabricSectionUpdater::<OspfPropertiesUpdater, OspfDeletableProperties> {
                    ip_prefix,
                    ip6_prefix,
                    properties:
                        OspfPropertiesUpdater {
                            area,
                            route_filter,
                            redistribute,
                        },
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

                if let Some(route_filter) = route_filter {
                    fabric_section.properties.route_filter = Some(route_filter);
                }

                if let Some(redistribute) = redistribute {
                    fabric_section.properties.redistribute = redistribute;
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
                            OspfDeletableProperties::RouteFilter,
                        ) => {
                            fabric_section.properties.route_filter = None;
                        }
                        FabricDeletableProperties::Protocol(
                            OspfDeletableProperties::Redistribute,
                        ) => fabric_section.properties.redistribute = Vec::new(),
                    }
                }

                Ok(())
            }
            (Fabric::WireGuard(fabric_section), FabricUpdater::WireGuard(updater)) => {
                let FabricSectionUpdater::<
                    WireGuardPropertiesUpdater,
                    WireGuardDeletableProperties,
                > {
                    ip_prefix,
                    ip6_prefix,
                    properties:
                        WireGuardPropertiesUpdater {
                            persistent_keepalive,
                        },
                    delete,
                } = updater;

                if let Some(prefix) = ip_prefix {
                    fabric_section.ip_prefix = Some(prefix);
                }

                if let Some(prefix) = ip6_prefix {
                    fabric_section.ip6_prefix = Some(prefix);
                }

                if let Some(keepalive) = persistent_keepalive {
                    fabric_section.properties.persistent_keepalive = Some(keepalive);
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
                            WireGuardDeletableProperties::PersistentKeepalive,
                        ) => {
                            fabric_section.properties.persistent_keepalive = None;
                        }
                    }
                }

                Ok(())
            }
            (Fabric::Bgp(fabric_section), FabricUpdater::Bgp(updater)) => {
                let FabricSectionUpdater::<BgpPropertiesUpdater, BgpDeletableProperties> {
                    ip_prefix,
                    ip6_prefix,
                    properties:
                        BgpPropertiesUpdater {
                            bfd,
                            redistribute,
                            route_map_in,
                            route_map_out,
                            route_filter,
                        },
                    delete,
                } = updater;

                if let Some(prefix) = ip_prefix {
                    fabric_section.ip_prefix = Some(prefix);
                }

                if let Some(prefix) = ip6_prefix {
                    fabric_section.ip6_prefix = Some(prefix);
                }

                if let Some(bfd) = bfd {
                    fabric_section.properties.bfd = bfd;
                }

                if let Some(redistribute) = redistribute {
                    fabric_section.properties.redistribute = redistribute;
                }

                if let Some(route_map_in) = route_map_in {
                    fabric_section.properties.route_map_in = Some(route_map_in);
                }

                if let Some(route_map_out) = route_map_out {
                    fabric_section.properties.route_map_out = Some(route_map_out);
                }

                if let Some(route_filter) = route_filter {
                    fabric_section.properties.route_filter = Some(route_filter);
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
                            BgpDeletableProperties::Redistribute,
                        ) => {
                            fabric_section.properties.redistribute = Vec::new();
                        }
                        FabricDeletableProperties::Protocol(
                            BgpDeletableProperties::RouteFilter,
                        ) => {
                            fabric_section.properties.route_filter = None;
                        }
                        FabricDeletableProperties::Protocol(BgpDeletableProperties::RouteMapIn) => {
                            fabric_section.properties.route_map_in = None;
                        }
                        FabricDeletableProperties::Protocol(
                            BgpDeletableProperties::RouteMapOut,
                        ) => {
                            fabric_section.properties.route_map_out = None;
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

#[cfg(test)]
mod tests {
    use crate::sdn::fabric::FabricConfig;
    use proxmox_section_config::typed::ApiSectionDataEntry;

    use super::*;

    #[test]
    fn test_wireguard_validation_duplicate_interface() -> Result<(), anyhow::Error> {
        let section_config = r#"
wireguard_fabric: wireg

wireguard_node: wireg_internal
    role internal
    endpoint 192.0.2.1:123
    public_key Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    interfaces name=wg0,listen_port=51111,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    interfaces name=wg0,listen_port=51112,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
"#;
        let parsed_config = Section::parse_section_config("fabrics.cfg", section_config)?;
        FabricConfig::from_section_config(parsed_config)
            .expect_err("duplicate interface name on node");

        Ok(())
    }

    #[test]
    fn test_wireguard_validation_duplicate_listen_port() -> Result<(), anyhow::Error> {
        let section_config = r#"
wireguard_fabric: wireg

wireguard_node: wireg_internal
    role internal
    endpoint 192.0.2.1:123
    public_key Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    interfaces name=wg0,listen_port=51111,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    interfaces name=wg1,listen_port=51111,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
"#;
        let parsed_config = Section::parse_section_config("fabrics.cfg", section_config)?;
        FabricConfig::from_section_config(parsed_config)
            .expect_err("duplicate listen_port on node");

        Ok(())
    }

    #[test]
    fn test_wireguard_validation_duplicate_listen_port_cross_fabric() -> Result<(), anyhow::Error> {
        let section_config = r#"
wireguard_fabric: wirega

wireguard_fabric: wiregb

wireguard_node: wirega_pve1
    role internal
    endpoint 192.0.2.1:123
    public_key Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    interfaces name=wg0,listen_port=51111,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=

wireguard_node: wiregb_pve1
    role internal
    endpoint 192.0.2.1:123
    public_key Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    interfaces name=wg1,listen_port=51111,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
"#;
        let parsed_config = Section::parse_section_config("fabrics.cfg", section_config)?;
        FabricConfig::from_section_config(parsed_config)
            .expect_err("two wireguard fabrics on the same node must not share a listen port");

        Ok(())
    }

    #[test]
    fn test_wireguard_validation_node_interface_does_not_exist() -> Result<(), anyhow::Error> {
        let section_config = r#"
wireguard_fabric: wireg

wireguard_node: wireg_internal
    role internal
    endpoint 192.0.2.1:123
    public_key Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    interfaces name=wg0,listen_port=51111,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    peers type=internal,node=invalid,node_iface=invalid,iface=wg0
"#;
        let parsed_config = Section::parse_section_config("fabrics.cfg", section_config)?;
        FabricConfig::from_section_config(parsed_config)
            .expect_err("interface referenced in peer definition does not exist");

        Ok(())
    }

    #[test]
    fn test_wireguard_validation_local_interface_does_not_exist() -> Result<(), anyhow::Error> {
        let section_config = r#"
wireguard_fabric: wireg

wireguard_node: wireg_internal
    role internal
    endpoint 192.0.2.1:123
    public_key Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    interfaces name=wg0,listen_port=51111,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=

wireguard_node: wireg_internal2
    role internal
    endpoint 192.0.2.2:123
    public_key Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    interfaces name=wg0,listen_port=51111,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    peers type=internal,node=internal,node_iface=wg0,iface=wg1
"#;
        let parsed_config = Section::parse_section_config("fabrics.cfg", section_config)?;
        FabricConfig::from_section_config(parsed_config)
            .expect_err("local interface in peer definition does not exist");

        Ok(())
    }

    #[test]
    fn test_wireguard_validation_local_interface_external_peer_does_not_exist(
    ) -> Result<(), anyhow::Error> {
        let section_config = r#"
wireguard_fabric: wireg

wireguard_node: wireg_external
    role external
    endpoint 192.0.2.1:123
    public_key Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=

wireguard_node: wireg_internal
    role internal
    endpoint 192.0.2.2:123
    public_key Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    interfaces name=wg0,listen_port=51111,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    peers type=external,node=wireg_external,iface=wg1
"#;
        let parsed_config = Section::parse_section_config("fabrics.cfg", section_config)?;
        FabricConfig::from_section_config(parsed_config)
            .expect_err("local interface in external peer definition does not exist");

        Ok(())
    }
}

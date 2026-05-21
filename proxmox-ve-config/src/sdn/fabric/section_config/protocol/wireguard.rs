//! WireGuard fabric properties
//!
//! The main building blocks of the WireGuard section configuration are Fabrics, Nodes, Interfaces
//! and Peers.
//!
//! ## Nodes
//!
//! There are two types of Nodes inside a WireGuard fabric:
//! * Internal - which represents a Proxmox VE node
//! * External - which represents anything that is not a Proxmox VE node
//!
//! For internal nodes, WireGuard interfaces can be configured, which will create a respective
//! WireGuard interface on the node.
//!
//! External nodes can only contain the public key + endpoint - so even if there are multiple
//! WireGuard interfaces on the same external peer they have to be configured as separate nodes,
//! since there is no notion of interfaces for external nodes.
//!
//! The main purpose of external nodes is to provide reusable peer definitions for configuring
//! WireGuard interfaces. For instance, a remote PDM instance can be configured as an external peer
//! and then referenced in the interface defintions.
//!
//! ## Peers
//!
//! For every WireGuard interface, peers can be configured. A peer can either reference the
//! interface of an internal node or an external node. The peer definition is generated
//! automatically from the information contained in the node section. Specific fields from the node
//! definition can be overridden in the peer definition, if e.g. a different endpoint is required
//! for connecting to a node.

use std::collections::HashSet;
use std::ops::{Deref, DerefMut};

use anyhow::Result;

use const_format::concatcp;
use proxmox_network_types::endpoint::{HostnameOrIpAddr, ServiceEndpoint};
use proxmox_network_types::ip_address::{Cidr, Ipv4Cidr, Ipv6Cidr};
use proxmox_schema::api_types::CIDR_SCHEMA;
use proxmox_schema::{api, property_string::PropertyString, ApiStringFormat, Updater, UpdaterType};
use proxmox_schema::{
    api_string_type, const_regex, ApiType, ArraySchema, ObjectSchema, Schema, StringSchema,
};
use proxmox_sdn_types::wireguard::PersistentKeepalive;
use proxmox_wireguard::PublicKey;
use serde::{Deserialize, Serialize};

use crate::common::valid::Validatable;
use crate::sdn::fabric::section_config::fabric::FabricSection;
use crate::sdn::fabric::section_config::node::{NodeId, NodeSection};
use crate::sdn::fabric::FabricConfigError;

pub const WIREGUARD_INTERFACE_NAME_REGEX_STR: &str = "[a-zA-Z0-9][a-zA-Z0-9-]{0,6}[a-zA-Z0-9]?";

const_regex! {
    pub WIREGUARD_INTERFACE_NAME_REGEX = concatcp!(r"^", WIREGUARD_INTERFACE_NAME_REGEX_STR, r"$");
}

pub const WIREGUARD_INTERFACE_NAME_FORMAT: ApiStringFormat =
    ApiStringFormat::Pattern(&WIREGUARD_INTERFACE_NAME_REGEX);

api_string_type! {
    /// Name of a WireGuard network interface.
    ///
    /// The interface name can have a maximum of 8 characters. The characterset is restricted (as
    /// opposed to the other fabric types which can reference arbitrary interfaces on the host),
    /// since this name is used in filenames - among other places.
    #[api(
        min_length: 1,
        max_length: 8,
        format: &WIREGUARD_INTERFACE_NAME_FORMAT,
    )]
    #[derive(Debug, Deserialize, Serialize, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, UpdaterType)]
    pub struct WireGuardInterfaceName(String);
}

/// Global properties for a WireGuard fabric.
#[api]
#[derive(Clone, Debug, Serialize, Deserialize, Updater, Hash)]
pub struct WireGuardProperties {
    /// Persistent keepalive interval.
    #[serde(skip_serializing_if = "persistent_keepalive_is_off")]
    pub(crate) persistent_keepalive: Option<PersistentKeepalive>,
}

impl Validatable for FabricSection<WireGuardProperties> {
    type Error = FabricConfigError;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireGuardDeletableProperties {
    PersistentKeepalive,
}

/// A node in the WireGuard fabric config.
///
/// Can be either internal (= PVE node that is part of the current cluster) or external (= any
/// other peer that is running WireGuard). For more information see the respective structs or
/// module-level documentation.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case", tag = "role")]
pub enum WireGuardNode {
    Internal(InternalWireGuardNode),
    External(ExternalWireGuardNode),
}

impl WireGuardNode {
    /// An iterator over the subnets that are allowed for this WireGuard node.
    pub fn allowed_ips(&self) -> impl Iterator<Item = &Cidr> {
        match self {
            WireGuardNode::Internal(internal_wire_guard_node) => {
                internal_wire_guard_node.allowed_ips.iter()
            }
            WireGuardNode::External(external_wire_guard_node) => {
                external_wire_guard_node.allowed_ips.iter()
            }
        }
    }
}

impl ApiType for WireGuardNode {
    const API_SCHEMA: Schema = ObjectSchema::new(
        "Wireguard Node",
        &[
            (
                "allowed_ips",
                true,
                &ArraySchema::new(
                    "A list of CIDRs that are routed via this WireGuard node.",
                    &CIDR_SCHEMA,
                )
                .schema(),
            ),
            (
                "interfaces",
                true,
                &ArraySchema::new(
                    "The WireGuard interfaces that should be created on this node.",
                    &StringSchema::new("WireGuard Interface definition.")
                        .format(&ApiStringFormat::PropertyString(
                            &WireGuardInterfaceProperties::API_SCHEMA,
                        ))
                        .schema(),
                )
                .schema(),
            ),
            (
                "peers",
                true,
                &ArraySchema::new(
                    "The peers that should be created on this node.",
                    &StringSchema::new("wireguard iface")
                        .format(&ApiStringFormat::PropertyString(
                            &WireGuardNodePeer::API_SCHEMA,
                        ))
                        .schema(),
                )
                .schema(),
            ),
        ],
    )
    // TODO: not using a OneOf schema here, because it currently cannot handle properties that are
    // optional on one variant, but not on the other. To work around this we have to use
    // ObjectSchema with additional_properties until fixed in proxmox-schema.
    .additional_properties(true)
    .schema();
}

impl Validatable for NodeSection<WireGuardNode> {
    type Error = FabricConfigError;

    fn validate(&self) -> Result<(), Self::Error> {
        if let WireGuardNode::Internal(node) = self.properties() {
            return node.validate();
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case", tag = "role")]
pub enum WireGuardNodeUpdater {
    Internal(InternalWireGuardNodeUpdater),
    External(ExternalWireGuardNodeUpdater),
}

impl Updater for WireGuardNodeUpdater {
    fn is_empty(&self) -> bool {
        match self {
            WireGuardNodeUpdater::Internal(updater) => updater.is_empty(),
            WireGuardNodeUpdater::External(updater) => updater.is_empty(),
        }
    }
}

impl UpdaterType for WireGuardNode {
    type Updater = WireGuardNodeUpdater;
}

#[api(
    properties: {
        allowed_ips: {
            type: Array,
            optional: true,
            items: {
                type: Cidr,
            }
        }
    }
)]
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Updater)]
/// A node that represents an external Wireguard peer.
///
/// It can be used to store the configuration of a peer and reuse it across multiple nodes, without
/// having to re-enter the peer information for every Wireguard interface.
pub struct ExternalWireGuardNode {
    /// The public key used by this node.
    pub(crate) public_key: PublicKey,

    /// The endpoint used for connecting to this node.
    pub(crate) endpoint: ServiceEndpoint,

    /// a list of IPs that are allowed for this peer
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) allowed_ips: Vec<Cidr>,
}

/// A node that represents a member of the current cluster.
///
/// It contains information about the interfaces that should be created on the node, as well as
/// their peers.
///
/// The additional properties, like endpoint or allowed_ips, can be used to define the settings
/// when using this node as a peer inside the fabric.
#[api(
    properties: {
        interfaces: {
            type: Array,
            optional: true,
            items: {
                type: String,
                description: "WireGuard interface properties.",
                format: &ApiStringFormat::PropertyString(&WireGuardInterfaceProperties::API_SCHEMA),
            }
        },
        peers: {
            type: Array,
            optional: true,
            items: {
                type: String,
                description: "WireGuard peer properties.",
                format: &ApiStringFormat::PropertyString(&WireGuardNodePeer::API_SCHEMA),
            }
        },
        allowed_ips: {
            type: Array,
            optional: true,
            items: {
                type: Cidr,
            }
        },
    }
)]
#[derive(Clone, Debug, Serialize, Deserialize, Updater, Hash)]
#[serde(rename_all = "snake_case")]
pub struct InternalWireGuardNode {
    /// The endpoint used for connecting to this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) endpoint: Option<HostnameOrIpAddr>,

    /// The interfaces that should get created on this node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) interfaces: Vec<PropertyString<WireGuardInterfaceProperties>>,

    /// The peers that should get created for interfaces on this node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) peers: Vec<PropertyString<WireGuardNodePeer>>,

    /// A list of IPs that are routable via this node in the WireGuard fabric.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) allowed_ips: Vec<Cidr>,
}

impl InternalWireGuardNode {
    /// Returns an iterator over all wireguard interfaces on this node.
    pub fn peers(&self) -> impl Iterator<Item = &WireGuardNodePeer> {
        self.peers
            .iter()
            .map(|property_string| property_string.deref())
    }

    /// Returns an iterator over all wireguard interfaces on this node.
    pub fn interfaces(&self) -> impl Iterator<Item = &WireGuardInterfaceProperties> {
        self.interfaces
            .iter()
            .map(|property_string| property_string.deref())
    }

    /// Returns an iterator over all wireguard interfaces on this node (mutable).
    pub fn interfaces_mut(&mut self) -> impl Iterator<Item = &mut WireGuardInterfaceProperties> {
        self.interfaces
            .iter_mut()
            .map(|property_string| property_string.deref_mut())
    }
}

impl Validatable for InternalWireGuardNode {
    type Error = FabricConfigError;

    /// Validates the [FabricSection<WireGuardNodeProperties>].
    fn validate(&self) -> Result<(), Self::Error> {
        let mut local_interfaces = HashSet::new();
        let mut listen_ports = HashSet::new();

        for interface in self.interfaces() {
            // check if interface names are unique
            if !local_interfaces.insert(&interface.name) {
                return Err(FabricConfigError::DuplicateInterface);
            }

            // check if listen ports are unique
            if !listen_ports.insert(interface.listen_port) {
                return Err(FabricConfigError::DuplicatePort(
                    interface.listen_port.to_string(),
                ));
            }
        }

        for peer in self.peers() {
            // check if referenced local interface exists, both internal and
            // external peers attach to a local interface via the iface field
            if !local_interfaces.contains(peer.iface()) {
                return Err(FabricConfigError::InvalidLocalInterfaceReference(
                    peer.iface().to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[api(
    properties: {
        allowed_ips: {
            type: Array,
            optional: true,
            items: {
                type: Cidr,
            }
        },
    }
)]
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Updater)]
/// A peer definition for a internal WireGuard node.
///
/// It references the interface of an internal node. Settings are then automatically taken from the
/// respective node configuration. Additional properties can be set here to override the
/// information for the node for this specific peering instance.
pub struct InternalPeer {
    /// The name of the node
    pub(crate) node: NodeId,
    /// The name of the interface on the node
    pub(crate) node_iface: WireGuardInterfaceName,
    /// The local interface that uses this peering definition
    pub(crate) iface: WireGuardInterfaceName,
    /// Override for the endpoint settings in the node section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) endpoint: Option<HostnameOrIpAddr>,
    /// Additional allowed IPs for this peer
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) allowed_ips: Vec<Cidr>,
    /// whether to auto-generate routes for the allowed IPs
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "proxmox_serde::perl::deserialize_bool"
    )]
    #[updater(serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "proxmox_serde::perl::deserialize_bool"
    ))]
    pub(crate) skip_route_generation: Option<bool>,
}

#[api(
    properties: {
        allowed_ips: {
            type: Array,
            optional: true,
            items: {
                type: Cidr,
            }
        },
    }
)]
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Updater)]
/// A peer definition for a external WireGuard node.
///
/// They reference an external node via the name. The properties here can be used to override the
/// settings in the node definition.
pub struct ExternalPeer {
    /// The name of the external peer.
    pub(crate) node: NodeId,
    /// Override for the endpoint settings in the node section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) endpoint: Option<ServiceEndpoint>,
    /// The local interface that uses this peering definition
    pub(crate) iface: WireGuardInterfaceName,
    /// Additional allowed IPs for this peer
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) allowed_ips: Vec<Cidr>,
    /// whether to auto-generate routes for the allowed IPs
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "proxmox_serde::perl::deserialize_bool"
    )]
    #[updater(serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "proxmox_serde::perl::deserialize_bool"
    ))]
    pub(crate) skip_route_generation: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Updater)]
#[serde(rename_all = "snake_case", tag = "type")]
/// A peer entry in a node's section config.
///
/// References either an internal peer or an external peer from the node sections.
pub enum WireGuardNodePeer {
    Internal(InternalPeer),
    External(ExternalPeer),
}

impl ApiType for WireGuardNodePeer {
    const API_SCHEMA: Schema = ObjectSchema::new("wireguard node peer", &[])
        .additional_properties(true)
        .schema();
}

impl WireGuardNodePeer {
    pub fn iface(&self) -> &WireGuardInterfaceName {
        match self {
            WireGuardNodePeer::Internal(internal_peer) => &internal_peer.iface,
            WireGuardNodePeer::External(external_peer) => &external_peer.iface,
        }
    }

    pub fn node(&self) -> &NodeId {
        match self {
            WireGuardNodePeer::Internal(internal_peer) => &internal_peer.node,
            WireGuardNodePeer::External(external_peer) => &external_peer.node,
        }
    }

    pub fn skip_route_generation(&self) -> bool {
        match self {
            WireGuardNodePeer::Internal(internal_peer) => &internal_peer.skip_route_generation,
            WireGuardNodePeer::External(external_peer) => &external_peer.skip_route_generation,
        }
        .unwrap_or_default()
    }

    pub fn allowed_ips(&self) -> &[Cidr] {
        match self {
            WireGuardNodePeer::Internal(internal_peer) => &internal_peer.allowed_ips,
            WireGuardNodePeer::External(external_peer) => &external_peer.allowed_ips,
        }
    }

    pub fn node_iface(&self) -> Option<&WireGuardInterfaceName> {
        match self {
            WireGuardNodePeer::Internal(internal_peer) => Some(&internal_peer.node_iface),
            WireGuardNodePeer::External(_) => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireGuardNodeDeletableProperties {
    Interfaces,
    Endpoint,
    Peers,
    AllowedIps,
}

/// Properties of a WireGuard interface.
#[api()]
#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
pub struct WireGuardInterfaceProperties {
    /// Name for this WireGuard interface.
    pub(crate) name: WireGuardInterfaceName,

    /// Listen port of the WireGuard interface.
    pub(crate) listen_port: u16,

    /// Public Key of this interface
    pub(crate) public_key: PublicKey,

    /// If ip and ip6 are unset, then this is an point-to-point interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip: Option<Ipv4Cidr>,

    /// If ip6 and ip are unset, then this is an point-to-point interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip6: Option<Ipv6Cidr>,

    /// whether to generate an IPv6 link-local address for this interface
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip6_ll: Option<bool>,
}

impl WireGuardInterfaceProperties {
    /// Get the name of the interface.
    pub fn name(&self) -> &WireGuardInterfaceName {
        &self.name
    }

    /// Set the name of the interface.
    pub fn set_name(&mut self, name: WireGuardInterfaceName) {
        self.name = name
    }

    /// Get the ip (IPv4) of the interface.
    pub fn ip(&self) -> Option<&Ipv4Cidr> {
        self.ip.as_ref()
    }

    /// Get the ip6 (IPv6) of the interface.
    pub fn ip6(&self) -> Option<&Ipv6Cidr> {
        self.ip6.as_ref()
    }
}

/// Determines whether the given `PersistentKeepalive` value means that it is
/// turned off. Useful for usage with serde's `skip_serializing_if`.
fn persistent_keepalive_is_off(value: &Option<PersistentKeepalive>) -> bool {
    value
        .as_ref()
        .map(PersistentKeepalive::is_off)
        .unwrap_or(true)
}

/// Properties of a WireGuard interface, when creating it from the API.
///
/// This makes public_key optional, since it isn't included for new interfaces, because it gets
/// generated automatically when creating the interface.
#[api()]
#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
pub struct WireGuardInterfaceCreateProperties {
    /// Name for this WireGuard interface.
    pub(crate) name: WireGuardInterfaceName,

    /// Listen port of the WireGuard interface.
    pub(crate) listen_port: u16,

    /// Public Key of this interface
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) public_key: Option<PublicKey>,

    /// If ip and ip6 are unset, then this is an point-to-point interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip: Option<Ipv4Cidr>,

    /// If ip6 and ip are unset, then this is an point-to-point interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip6: Option<Ipv6Cidr>,

    /// whether to generate an IPv6 link-local address for this interface
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip6_ll: Option<bool>,
}

pub mod private_keys {
    use std::collections::btree_map::Entry;
    use std::collections::{BTreeMap, HashMap, HashSet};

    use anyhow::Error;
    use serde::{Deserialize, Serialize};

    use proxmox_schema::{api, ApiStringFormat, PropertyString};
    use proxmox_section_config::typed::SectionConfigData;
    use proxmox_wireguard::{PrivateKey, PublicKey};

    use crate::sdn::fabric::section_config::{
        node::{Node, NodeId, NODE_ID_FORMAT},
        protocol::wireguard::{WireGuardInterfaceName, WireGuardNode},
    };
    use crate::sdn::fabric::FabricConfig;

    #[api()]
    #[derive(Clone, Debug, Serialize, Deserialize, Hash)]
    /// A private key for a wireguard interface
    pub struct InterfacePrivateKey {
        name: WireGuardInterfaceName,
        key: PrivateKey,
    }

    impl InterfacePrivateKey {
        pub fn new(name: WireGuardInterfaceName, key: PrivateKey) -> Self {
            Self { name, key }
        }
    }

    #[api(
        properties: {
            private_keys: {
                type: Array,
                description: "A list of private keys for this node.",
                items: {
                    type: String,
                    description: "A private key for a wireguard interface.",
                    format: &ApiStringFormat::PropertyString(&InterfacePrivateKey::API_SCHEMA),
                }
            }
        }
    )]
    #[derive(Clone, Debug, Serialize, Deserialize, Hash)]
    /// The private keys for a node in a wireguard fabric.
    pub struct NodePrivateKeysSection {
        private_keys: Vec<PropertyString<InterfacePrivateKey>>,
    }

    impl FromIterator<InterfacePrivateKey> for NodePrivateKeysSection {
        fn from_iter<T: IntoIterator<Item = InterfacePrivateKey>>(iter: T) -> Self {
            Self {
                private_keys: iter.into_iter().map(PropertyString::new).collect(),
            }
        }
    }

    #[api(
        "id-property": "id",
        "id-schema": {
            type: String,
            description: "Route Map Section ID",
            format: &NODE_ID_FORMAT,
        },
        "type-key": "type",
    )]
    #[derive(Clone, Debug, Serialize, Deserialize, Hash)]
    /// The private key config for wireguard.
    #[serde(tag = "type", rename_all = "kebab-case")]
    pub enum FabricPrivateKeysSectionConfig {
        /// Private keys for a node.
        Node(NodePrivateKeysSection),
    }

    impl From<NodePrivateKeysSection> for FabricPrivateKeysSectionConfig {
        fn from(value: NodePrivateKeysSection) -> Self {
            Self::Node(value)
        }
    }

    #[derive(Clone, Debug, Serialize, Deserialize, Hash)]
    pub struct WireGuardPrivateKeys(
        pub(crate) BTreeMap<NodeId, BTreeMap<WireGuardInterfaceName, PrivateKey>>,
    );

    impl WireGuardPrivateKeys {
        /// Creates a Private key for the given (node, interface) if it doesn't exist - then
        /// returns the public key of the stored private key.
        pub fn upsert(
            &mut self,
            node: NodeId,
            interface: WireGuardInterfaceName,
        ) -> Result<PublicKey, anyhow::Error> {
            Ok(match self.0.entry(node).or_default().entry(interface) {
                Entry::Vacant(vacant_entry) => {
                    let private_key = PrivateKey::generate()?;
                    let public_key = private_key.public_key();

                    vacant_entry.insert(private_key);
                    public_key
                }
                Entry::Occupied(occupied_entry) => occupied_entry.get().public_key(),
            })
        }

        /// Removes a private key.
        pub fn remove(
            &mut self,
            node: &NodeId,
            interface: &WireGuardInterfaceName,
        ) -> Option<PrivateKey> {
            if let Some(node_config) = self.0.get_mut(node) {
                let removed_interface = node_config.remove(interface);

                if node_config.is_empty() {
                    self.0.remove(node);
                }

                return removed_interface;
            }

            None
        }

        /// Return a private key.
        pub fn get(
            &self,
            node: &NodeId,
            interface: &WireGuardInterfaceName,
        ) -> Option<&PrivateKey> {
            self.0.get(node)?.get(interface)
        }

        /// Removes all entries in the private key configuration that do not exist in the given
        /// [`FabricConfig`].
        ///
        /// Returns `true` if at least one entry was removed, allowing callers to skip an
        /// unconditional write of the cluster-replicated key file when there was nothing to clean
        /// up.
        pub fn cleanup(&mut self, fabric_config: &FabricConfig) -> Result<bool, Error> {
            let mut private_keys_nodes = HashSet::new();
            let mut private_keys_interfaces = HashSet::new();

            let mut fabric_config_nodes = HashSet::new();
            let mut fabric_config_interfaces = HashSet::new();

            for (node_id, node) in fabric_config.all_nodes() {
                let Node::WireGuard(node) = node else {
                    continue;
                };

                let WireGuardNode::Internal(node) = node.properties() else {
                    continue;
                };

                fabric_config_nodes.insert(node_id.clone());

                fabric_config_interfaces.extend(
                    node.interfaces()
                        .map(|interface| (node_id.clone(), interface.name().clone())),
                );
            }

            for (node_id, interfaces) in &self.0 {
                private_keys_nodes.insert(node_id.clone());

                private_keys_interfaces.extend(
                    interfaces
                        .keys()
                        .map(|interface_name| (node_id.clone(), interface_name.clone())),
                );
            }

            let mut changed = false;

            for node_id in private_keys_nodes.difference(&fabric_config_nodes) {
                if self.0.remove(node_id).is_some() {
                    changed = true;
                }
            }

            for (node_id, interface_id) in
                private_keys_interfaces.difference(&fabric_config_interfaces)
            {
                if self.remove(node_id, interface_id).is_some() {
                    changed = true;
                }
            }

            Ok(changed)
        }
    }

    impl From<WireGuardPrivateKeys> for SectionConfigData<FabricPrivateKeysSectionConfig> {
        fn from(value: WireGuardPrivateKeys) -> Self {
            let mut data = HashMap::new();

            for (node_id, interfaces) in value.0.into_iter() {
                data.insert(
                    node_id.to_string(),
                    NodePrivateKeysSection::from_iter(
                        interfaces
                            .into_iter()
                            .map(|(name, key)| InterfacePrivateKey::new(name, key)),
                    )
                    .into(),
                );
            }

            Self::from(data)
        }
    }

    impl TryFrom<SectionConfigData<FabricPrivateKeysSectionConfig>> for WireGuardPrivateKeys {
        type Error = anyhow::Error;

        fn try_from(
            value: SectionConfigData<FabricPrivateKeysSectionConfig>,
        ) -> Result<Self, Self::Error> {
            let mut data = BTreeMap::new();

            for (section_id, FabricPrivateKeysSectionConfig::Node(node)) in value {
                let node_id = NodeId::from_string(section_id)?;

                let interfaces: &mut BTreeMap<WireGuardInterfaceName, PrivateKey> =
                    data.entry(node_id.clone()).or_default();

                for interface in node.private_keys {
                    let interface = interface.into_inner();

                    if interfaces
                        .insert(interface.name.clone(), interface.key)
                        .is_some()
                    {
                        anyhow::bail!("duplicate interface {} for node {node_id}", interface.name);
                    }
                }
            }

            Ok(Self(data))
        }
    }
}

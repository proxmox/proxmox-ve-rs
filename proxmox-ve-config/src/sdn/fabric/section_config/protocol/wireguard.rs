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

use crate::sdn::fabric::section_config::node::NodeId;

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

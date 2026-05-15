use std::net::{Ipv4Addr as StdIpv4Addr, Ipv6Addr};
use std::ops::{Deref, DerefMut};

use proxmox_network_types::ip_address::api_types::Ipv4Addr;
use proxmox_schema::{ApiType, OneOfSchema, Schema, StringSchema, UpdaterType};
use serde::{Deserialize, Serialize};

use proxmox_schema::{api, property_string::PropertyString, ApiStringFormat, Updater};

use crate::common::valid::Validatable;
use crate::sdn::fabric::section_config::fabric::FabricSection;
use crate::sdn::fabric::section_config::interface::InterfaceName;
use crate::sdn::fabric::section_config::node::NodeSection;
use crate::sdn::fabric::FabricConfigError;

use crate::sdn::prefix_list::PrefixListId;
use crate::sdn::route_map::RouteMapId;

#[api]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
#[serde(rename_all = "lowercase")]
/// Redistribution Sources for BGP fabric
pub enum BgpRedistributionSource {
    /// redistribute connected routes
    Connected,
    /// redistribute IS-IS routes
    Isis,
    /// redistribute kernel routes
    Kernel,
    /// redistribute openfabric routes
    Openfabric,
    /// redistribute ospfv2 routes
    Ospf,
    /// redistribute ospfv3 routes
    Ospf6,
    /// redistribute static routes
    Static,
}

#[api]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
/// A BGP redistribution target
pub struct BgpRedistribution {
    /// The source used for redistribution
    pub(crate) source: BgpRedistributionSource,
    /// The metric to apply to redistributed routes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) metric: Option<u32>,
    /// Route MAP to use for filtering redistributed routes
    #[serde(rename = "route-map", skip_serializing_if = "Option::is_none")]
    pub(crate) route_map: Option<RouteMapId>,
}

#[api(
    type: Integer,
    minimum: u32::MIN as i64,
    maximum: u32::MAX as i64,
)]
#[derive(Debug, Clone, Serialize, Updater, Hash)]
/// Autonomous system number as defined by RFC 6793
pub struct ASN(u32);

impl<'de> Deserialize<'de> for ASN {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        proxmox_serde::perl::deserialize_u32(deserializer).map(ASN)
    }
}

impl UpdaterType for ASN {
    type Updater = Option<ASN>;
}

impl ASN {
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

#[api(
    properties: {
        redistribute: {
            type: Array,
            optional: true,
            items: {
                type: String,
                description: "A BGP redistribution source",
                format: &ApiStringFormat::PropertyString(&BgpRedistribution::API_SCHEMA),
            }
        }
    },
)]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
/// Properties for a BGP fabric.
pub struct BgpProperties {
    /// enable BFD for this fabric
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub(crate) bfd: bool,
    /// redistribution configuration for this fabric
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) redistribute: Vec<PropertyString<BgpRedistribution>>,

    /// Route map to apply for incoming routes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) route_map_in: Option<RouteMapId>,

    /// Route map to apply for outgoing routes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) route_map_out: Option<RouteMapId>,

    /// By default only routes from the configured IP prefix are imported
    /// into the local routing table. This setting can be used to override the
    /// allowed IPs and import additional routes besides the configured IP
    /// prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) route_filter: Option<PrefixListId>,
}

impl BgpProperties {
    pub fn bfd(&self) -> bool {
        self.bfd
    }
}

impl Validatable for FabricSection<BgpProperties> {
    type Error = FabricConfigError;

    /// Validate the [`FabricSection<BgpProperties>`].
    fn validate(&self) -> Result<(), Self::Error> {
        if self.ip_prefix().is_none() && self.ip6_prefix().is_none() {
            return Err(FabricConfigError::FabricNoIpPrefix(self.id().to_string()));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BgpDeletableProperties {
    Redistribute,
    RouteFilter,
    RouteMapIn,
    RouteMapOut,
}

#[api]
/// External BGP node.
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct ExternalBgpNode {
    peer_ip: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case", tag = "role")]
pub enum BgpNode {
    Internal(BgpNodeProperties),
    External(ExternalBgpNode),
}

impl ApiType for BgpNode {
    const API_SCHEMA: Schema = OneOfSchema::new(
        "BGP node",
        &(
            "role",
            false,
            &StringSchema::new("internal or external").schema(),
        ),
        &[
            ("external", &ExternalBgpNode::API_SCHEMA),
            ("internal", &BgpNodeProperties::API_SCHEMA),
        ],
    )
    .schema();
}

impl Validatable for NodeSection<BgpNode> {
    type Error = FabricConfigError;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[api(
    properties: {
        interfaces: {
            type: Array,
            optional: true,
            items: {
                type: String,
                description: "Properties for a BGP interface.",
                format: &ApiStringFormat::PropertyString(&BgpInterfaceProperties::API_SCHEMA),
            }
        },
    }
)]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
/// Properties for a BGP node.
pub struct BgpNodeProperties {
    /// Autonomous system number for this Node
    pub(crate) asn: ASN,
    /// Interfaces for this Node.
    #[serde(default)]
    pub(crate) interfaces: Vec<PropertyString<BgpInterfaceProperties>>,
}

impl BgpNodeProperties {
    /// Returns the ASN for this node.
    pub fn asn(&self) -> &ASN {
        &self.asn
    }

    /// Returns an iterator over all the interfaces.
    pub fn interfaces(&self) -> impl Iterator<Item = &BgpInterfaceProperties> {
        self.interfaces
            .iter()
            .map(|property_string| property_string.deref())
    }

    /// Returns an iterator over all the interfaces (mutable).
    pub fn interfaces_mut(&mut self) -> impl Iterator<Item = &mut BgpInterfaceProperties> {
        self.interfaces
            .iter_mut()
            .map(|property_string| property_string.deref_mut())
    }
}

impl Validatable for NodeSection<BgpNodeProperties> {
    type Error = FabricConfigError;

    /// Validate the [`NodeSection<BgpNodeProperties>`].
    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BgpNodeDeletableProperties {
    Interfaces,
}

#[api]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
/// Properties for a BGP interface.
pub struct BgpInterfaceProperties {
    pub(crate) name: InterfaceName,
}

impl BgpInterfaceProperties {
    /// Get the name of the BGP interface.
    pub fn name(&self) -> &InterfaceName {
        &self.name
    }

    /// Set the name of the interface.
    pub fn set_name(&mut self, name: InterfaceName) {
        self.name = name
    }
}

/// Derive a deterministic BGP router-id from an IPv6 address using FNV-1a.
///
/// BGP router-id must be a 32-bit value. For IPv6-only nodes, we hash the
/// full 16 octets down to 4 bytes. Typical loopback allocations (sequential
/// within a prefix, sparse across /48s) produce zero collisions up to 100k
/// nodes in testing -- well below the random birthday bound (~1% at 10k)
/// because structured addresses spread well under FNV-1a.
pub fn router_id_from_ipv6(addr: &Ipv6Addr) -> StdIpv4Addr {
    let mut hash: u32 = 0x811c9dc5;
    for &byte in &addr.octets() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    StdIpv4Addr::from(hash)
}

/// Resolves the BGP router-id for a node: the IPv4 address if set,
/// otherwise an FNV-1a hash of the IPv6 address.
pub fn bgp_router_id(node: &NodeSection<BgpNode>) -> Option<StdIpv4Addr> {
    node.ip()
        .or_else(|| node.ip6().map(|ipv6| router_id_from_ipv6(&ipv6)))
}

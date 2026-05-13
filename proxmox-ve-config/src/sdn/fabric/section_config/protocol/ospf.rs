use std::ops::{Deref, DerefMut};

use proxmox_network_types::ip_address::Ipv4Cidr;
use proxmox_sdn_types::ospf::Area;
use serde::{Deserialize, Serialize};

use proxmox_schema::{api, property_string::PropertyString, ApiStringFormat, Updater};

use crate::common::valid::Validatable;
use crate::sdn::fabric::section_config::fabric::FabricSection;
use crate::sdn::fabric::section_config::interface::InterfaceName;
use crate::sdn::fabric::section_config::node::NodeSection;
use crate::sdn::fabric::FabricConfigError;
use crate::sdn::prefix_list::PrefixListId;

#[api]
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Copy)]
#[serde(rename_all = "lowercase")]
/// OSPF redistribution source protocols
pub enum OspfRedistributionSource {
    /// redistribute BGP routes
    Bgp,
    /// redistribute connected routes
    Connected,
    /// redistribute IS-IS routes
    Isis,
    /// redistribute kernel routes
    Kernel,
    /// redistribute Openfabric routes
    Openfabric,
    /// redistribute OSPF routes
    Ospf,
    /// redistribute static routes
    Static,
}

#[api]
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
#[serde(rename_all = "kebab-case")]
/// An OSPF redistribution
pub struct OspfRedistribution {
    /// The source protocol for this redistribution
    pub(crate) source: OspfRedistributionSource,
    /// The metric that should be applied to redistributed routes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) metric: Option<u32>,
    /// The name of the route map used for filtering redistributed routes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) route_map: Option<String>,
}

#[api(
    properties: {
        redistribute: {
            type: Array,
            optional: true,
            items: {
                type: String,
                description: "An OSPF redistribution source.",
                format: &ApiStringFormat::PropertyString(&OspfRedistribution::API_SCHEMA),
            }
        }
    }
)]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
/// Properties for an Ospf fabric.
pub struct OspfProperties {
    /// OSPF area
    pub(crate) area: Area,

    /// By default only routes from the configured IP prefix are imported into the local routing
    /// table. This setting can be used to override the allowed IPs and import additional routes
    /// besides the configured IP prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) route_filter: Option<PrefixListId>,

    /// Redistribution configuration
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub(crate) redistribute: Vec<PropertyString<OspfRedistribution>>,
}

impl OspfProperties {
    pub fn set_area(&mut self, value: Area) {
        self.area = value;
    }

    pub fn area(&self) -> &Area {
        &self.area
    }

    pub fn redistributions(&self) -> impl IntoIterator<Item = &OspfRedistribution> {
        self.redistribute.iter().map(Deref::deref)
    }
}

impl Validatable for FabricSection<OspfProperties> {
    type Error = FabricConfigError;

    /// Validate the [`FabricSection<OspfProperties>`].
    ///
    /// Checks if the ip-prefix (IPv4) is set. If not, then return an error.
    /// If the ip6-prefix (IPv6) is set, also return an error, as OSPF doesn't support IPv6.
    fn validate(&self) -> Result<(), Self::Error> {
        if self.ip_prefix().is_none() {
            return Err(FabricConfigError::FabricNoIpPrefix(self.id().to_string()));
        }

        if self.ip6_prefix().is_some() {
            return Err(FabricConfigError::Ipv6Unsupported("ospf".to_string()));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OspfDeletableProperties {
    RouteFilter,
    Redistribute,
}

#[api(
    properties: {
        interfaces: {
            type: Array,
            optional: true,
            items: {
                type: String,
                description: "Properties for an Ospf interface.",
                format: &ApiStringFormat::PropertyString(&OspfInterfaceProperties::API_SCHEMA),
            }
        },
    }
)]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
/// Properties for an Ospf node.
pub struct OspfNodeProperties {
    /// Interfaces for this Node.
    #[serde(default)]
    pub(crate) interfaces: Vec<PropertyString<OspfInterfaceProperties>>,
}

impl OspfNodeProperties {
    /// Returns an iterator over all the interfaces.
    pub fn interfaces(&self) -> impl Iterator<Item = &OspfInterfaceProperties> {
        self.interfaces
            .iter()
            .map(|property_string| property_string.deref())
    }

    /// Returns an iterator over all the interfaces (mutable).
    pub fn interfaces_mut(&mut self) -> impl Iterator<Item = &mut OspfInterfaceProperties> {
        self.interfaces
            .iter_mut()
            .map(|property_string| property_string.deref_mut())
    }
}

impl Validatable for NodeSection<OspfNodeProperties> {
    type Error = FabricConfigError;

    /// Validate the [`NodeSection<OspfNodeProperties>`].
    ///
    /// Error if the IPv4 address is not set. Error if the IPv6 address is set (OSPF does not
    /// support IPv6).
    fn validate(&self) -> Result<(), Self::Error> {
        if self.ip().is_none() {
            return Err(FabricConfigError::NodeNoIp(self.id().to_string()));
        }
        if self.ip6().is_some() {
            return Err(FabricConfigError::Ipv6Unsupported("ospf".to_string()));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OspfNodeDeletableProperties {
    Interfaces,
}

#[api]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
/// Properties for an OSPF interface.
pub struct OspfInterfaceProperties {
    pub(crate) name: InterfaceName,

    /// If IP is unset, then this is an unnumbered interface
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip: Option<Ipv4Cidr>,

    /// Network Type of the interface. Contains all the NetworkTypes from FRR, but also includes a
    /// `None` variant which enables us to decide the network-type automatically depending on if a
    /// ip is given or not. (This also enables this change to be backwards-compatible).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network_type: Option<proxmox_sdn_types::ospf::NetworkType>,
}

impl OspfInterfaceProperties {
    /// Get the name of the OSPF interface.
    pub fn name(&self) -> &InterfaceName {
        &self.name
    }

    /// Set the name of the interface.
    pub fn set_name(&mut self, name: InterfaceName) {
        self.name = name
    }

    /// Get the ip (IPv4) of the OSPF interface.
    pub fn ip(&self) -> Option<Ipv4Cidr> {
        self.ip
    }
}

use std::ops::Deref;

use proxmox_network_types::ip_address::Ipv4Cidr;
use proxmox_sdn_types::area::Area;
use serde::{Deserialize, Serialize};

use proxmox_schema::{api, property_string::PropertyString, ApiStringFormat, Updater};

use crate::common::valid::Validatable;
use crate::sdn::fabric::section_config::fabric::FabricSection;
use crate::sdn::fabric::section_config::interface::InterfaceName;
use crate::sdn::fabric::section_config::node::NodeSection;
use crate::sdn::fabric::FabricConfigError;

#[api]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
/// Properties for an Ospf fabric.
pub struct OspfProperties {
    /// OSPF area
    pub(crate) area: Area,
}

impl OspfProperties {
    pub fn set_area(&mut self, value: Area) {
        self.area = value;
    }
    pub fn area(&self) -> &Area {
        &self.area
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
#[serde(rename_all = "snake_case", untagged)]
pub enum OspfDeletableProperties {}

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
    pub fn interfaces(&self) -> impl Iterator<Item = &OspfInterfaceProperties> {
        self.interfaces
            .iter()
            .map(|property_string| property_string.deref())
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
#[serde(rename_all = "snake_case", untagged)]
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
}

impl OspfInterfaceProperties {
    /// Get the name of the OSPF interface.
    pub fn name(&self) -> &InterfaceName {
        &self.name
    }

    /// Get the ip (IPv4) of the OSPF interface.
    pub fn ip(&self) -> Option<Ipv4Cidr> {
        self.ip
    }
}

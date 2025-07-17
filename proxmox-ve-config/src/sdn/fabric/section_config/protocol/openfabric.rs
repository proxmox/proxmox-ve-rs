use std::ops::{Deref, DerefMut};

use proxmox_network_types::ip_address::{Ipv4Cidr, Ipv6Cidr};
use serde::{Deserialize, Serialize};

use proxmox_schema::{api, property_string::PropertyString, ApiStringFormat, Updater};
use proxmox_sdn_types::openfabric::{CsnpInterval, HelloInterval, HelloMultiplier};

use crate::common::valid::Validatable;
use crate::sdn::fabric::section_config::fabric::FabricSection;
use crate::sdn::fabric::section_config::interface::InterfaceName;
use crate::sdn::fabric::section_config::node::NodeSection;
use crate::sdn::fabric::FabricConfigError;

/// Protocol-specific options for an OpenFabric Fabric.
#[api]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
pub struct OpenfabricProperties {
    /// This will be distributed to all interfaces on every node. The Hello Interval for a given
    /// interface in seconds. The range is 1 to 600. Hello packets are used to establish and
    /// maintain adjacency between OpenFabric neighbors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hello_interval: Option<HelloInterval>,

    /// This will be distributed to all interfaces on every node.The Complete Sequence Number
    /// Packets (CSNP) interval in seconds. The interval range is 1 to 600.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) csnp_interval: Option<CsnpInterval>,
}

impl Validatable for FabricSection<OpenfabricProperties> {
    type Error = FabricConfigError;

    /// Validates the [`FabricSection<OpenfabricProperties>`].
    ///
    /// Checks if we have either IPv4-prefix or IPv6-prefix. If both are not set, return an error.
    fn validate(&self) -> Result<(), Self::Error> {
        if self.ip_prefix().is_none() && self.ip6_prefix().is_none() {
            return Err(FabricConfigError::FabricNoIpPrefix(self.id().to_string()));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum OpenfabricDeletableProperties {
    HelloInterval,
    CsnpInterval,
}

/// Properties for an OpenFabric node
#[api(
    properties: {
        interfaces: {
            type: Array,
            optional: true,
            items: {
                type: String,
                description: "OpenFabric interface",
                format: &ApiStringFormat::PropertyString(&OpenfabricInterfaceProperties::API_SCHEMA),
            }
        },
    }
)]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
pub struct OpenfabricNodeProperties {
    /// Interfaces for this node
    #[serde(default)]
    pub(crate) interfaces: Vec<PropertyString<OpenfabricInterfaceProperties>>,
}

impl OpenfabricNodeProperties {
    /// Returns an iterator over all the interfaces.
    pub fn interfaces(&self) -> impl Iterator<Item = &OpenfabricInterfaceProperties> {
        self.interfaces
            .iter()
            .map(|property_string| property_string.deref())
    }

    /// Returns an iterator over all the interfaces (mutable).
    pub fn interfaces_mut(&mut self) -> impl Iterator<Item = &mut OpenfabricInterfaceProperties> {
        self.interfaces
            .iter_mut()
            .map(|property_string| property_string.deref_mut())
    }
}

impl Validatable for NodeSection<OpenfabricNodeProperties> {
    type Error = FabricConfigError;

    /// Validates the [`FabricSection<OpenfabricProperties>`].
    ///
    /// Checks if we have either an IPv4 or an IPv6 address. If neither is set, return an error.
    fn validate(&self) -> Result<(), Self::Error> {
        if self.ip().is_none() && self.ip6().is_none() {
            return Err(FabricConfigError::NodeNoIp(self.id().to_string()));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenfabricNodeDeletableProperties {
    Interfaces,
}

/// Properties for an OpenFabric interface
#[api]
#[derive(Debug, Clone, Serialize, Deserialize, Updater, Hash)]
pub struct OpenfabricInterfaceProperties {
    pub(crate) name: InterfaceName,

    /// The multiplier for the hello holding time on a given interface. The range is 2 to
    /// 100.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hello_multiplier: Option<HelloMultiplier>,

    /// If ip and ip6 are unset, then this is an point-to-point interface
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip: Option<Ipv4Cidr>,

    /// If ip6 and ip are unset, then this is an point-to-point interface
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip6: Option<Ipv6Cidr>,
}

impl OpenfabricInterfaceProperties {
    /// Get the name of the interface.
    pub fn name(&self) -> &InterfaceName {
        &self.name
    }

    /// Set the name of the interface.
    pub fn set_name(&mut self, name: InterfaceName) {
        self.name = name
    }

    /// Get the IPv4 of the interface.
    pub fn ip(&self) -> Option<Ipv4Cidr> {
        self.ip
    }

    /// Get the IPv6 of the interface.
    pub fn ip6(&self) -> Option<Ipv6Cidr> {
        self.ip6
    }
}

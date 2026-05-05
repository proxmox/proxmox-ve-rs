use std::fmt::Debug;
use std::net::Ipv4Addr;

use proxmox_sdn_types::ospf::NetworkType;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ser::{FrrWord, FrrWordError};

#[derive(Error, Debug)]
pub enum AreaParsingError {
    #[error("Invalid area idenitifier. Area must be a number or an ipv4 address.")]
    InvalidArea,
    #[error("Invalid area idenitifier. Missing 'area' prefix.")]
    MissingPrefix,
    #[error("Error parsing to FrrWord")]
    FrrWordError(#[from] FrrWordError),
}

/// The OSPF Area.
///
/// The OSPF area is a pseud-ipaddress (so it looks like an ip-address but isn't set on any
/// interface or even pingable), but can also be specified by a simple number. So you can use "5"
/// or "0" as an area, which then gets translated to "0.0.0.5" and "0.0.0.0" by FRR. We allow both
/// a number or an ip-address. Note that the area "0" (or "0.0.0.0") is a special area - it creates
/// a OSPF "backbone" area.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Area(FrrWord);

impl TryFrom<FrrWord> for Area {
    type Error = AreaParsingError;

    fn try_from(value: FrrWord) -> Result<Self, Self::Error> {
        Area::new(value)
    }
}

impl Area {
    pub fn new(name: FrrWord) -> Result<Self, AreaParsingError> {
        if name.as_ref().parse::<u32>().is_ok() || name.as_ref().parse::<Ipv4Addr>().is_ok() {
            Ok(Self(name))
        } else {
            Err(AreaParsingError::InvalidArea)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OspfRedistribution {
    pub source: OspfRedistributionSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_map: Option<String>,
}

/// The OSPF router properties.
///
/// Currently the only property of a OSPF router is the router_id. The router_id is used to
/// differentiate between nodes and every node in the same area must have a different router_id.
/// The router_id must also be the same on the different fabrics on the same node. The OSPFv2
/// daemon only supports IPv4.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OspfRouter {
    pub router_id: Ipv4Addr,
    #[serde(default)]
    pub redistribute: Vec<OspfRedistribution>,
}

impl OspfRouter {
    pub fn new(router_id: Ipv4Addr) -> Self {
        Self {
            router_id,
            redistribute: Vec::new(),
        }
    }

    pub fn router_id(&self) -> &Ipv4Addr {
        &self.router_id
    }
}

#[derive(Error, Debug)]
pub enum OspfInterfaceError {
    #[error("Error parsing area")]
    AreaParsingError(#[from] AreaParsingError),
    #[error("Error parsing frr word")]
    FrrWordParse(#[from] FrrWordError),
}

/// The OSPF interface properties.
///
/// The interface gets tied to its fabric by the area property and the FRR `ip ospf area <area>`
/// command.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OspfInterface {
    // Note: an interface can only be a part of a single area(so no vec needed here)
    pub area: Area,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub passive: Option<bool>,
    #[serde(default)]
    pub network_type: Option<NetworkType>,
}

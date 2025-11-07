use std::fmt::Debug;
use std::fmt::Display;
use std::net::Ipv4Addr;

use thiserror::Error;

use crate::ser::{FrrWord, FrrWordError};

/// The name of the ospf frr router.
///
/// We can only have a single ospf router (ignoring multiple invocations of the ospfd daemon)
/// because the router-id needs to be the same between different routers on a single node.
/// We can still have multiple fabrics by separating them using areas. Still, different areas have
/// the same frr router, so the name of the router is just "ospf" in "router ospf".
///
/// This serializes roughly to:
/// ```text
/// router ospf
/// !...
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OspfRouterName;

impl Display for OspfRouterName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ospf")
    }
}

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
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

impl Display for Area {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "area {}", self.0)
    }
}

/// The OSPF router properties.
///
/// Currently the only property of a OSPF router is the router_id. The router_id is used to
/// differentiate between nodes and every node in the same area must have a different router_id.
/// The router_id must also be the same on the different fabrics on the same node. The OSPFv2
/// daemon only supports IPv4.
/// Note that these properties also serialize with a space prefix (" ") as they are inside the OSPF
/// router block. It serializes roughly to:
///
/// ```text
/// router ospf
///  router-id <ipv4-address>
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OspfRouter {
    pub router_id: Ipv4Addr,
}

impl OspfRouter {
    pub fn new(router_id: Ipv4Addr) -> Self {
        Self { router_id }
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

/// The NetworkType of the interface.
///
/// The most important options here are Broadcast (which is the default) and PointToPoint.
/// When PointToPoint is set, then the interface has to have a /32 address and will be treated as
/// unnumbered.
///
/// This roughly serializes to:
/// ```text
/// ip ospf network point-to-point
/// ! or
/// ip ospf network broadcast
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NetworkType {
    Broadcast,
    NonBroadcast,
    /// If the interface is unnumbered (i.e. the router-id /32 ip-address is set on the interface).
    ///
    /// If OSPF is used in an unnumbered way, you don't need to configure peer-to-peer (e.g. /31)
    /// addresses at every interface, but you just need to set the router-id at the interface
    /// (/32). You also need to configure the `ip ospf network point-to-point` FRR option.
    PointToPoint,
    PointToMultipoint,
}

impl Display for NetworkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkType::Broadcast => write!(f, "broadcast"),
            NetworkType::NonBroadcast => write!(f, "non-broadcast"),
            NetworkType::PointToPoint => write!(f, "point-to-point"),
            NetworkType::PointToMultipoint => write!(f, "point-to-multicast"),
        }
    }
}

/// The OSPF interface properties.
///
/// The interface gets tied to its fabric by the area property and the FRR `ip ospf area <area>`
/// command.
///
/// This serializes to:
///
/// ```text
/// router ospf
///  ip ospf area <area>
///  ip ospf passive <value>
///  ip ospf network <value>
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OspfInterface {
    // Note: an interface can only be a part of a single area(so no vec needed here)
    pub area: Area,
    pub passive: Option<bool>,
    pub network_type: Option<NetworkType>,
}

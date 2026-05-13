pub mod bgp;
pub mod isis;
pub mod openfabric;
pub mod ospf;
pub mod route_map;
pub mod serializer;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

use crate::ser::{
    bgp::{CommunityListName, ExtCommunityList},
    route_map::{
        AccessListName, AccessListRule, PrefixListName, PrefixListRule, RouteMapEntry, RouteMapName,
    },
};

use proxmox_network_types::{
    ip_address::{Ipv4Cidr, Ipv6Cidr},
    Cidr,
};
use proxmox_serde::forward_deserialize_to_from_str;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The action for a [`AccessListRule`] or [`ExtCommunityList`].
///
/// The default is Permit. Deny can be used to create a NOT match (e.g. match all routes that are
/// NOT in 10.10.10.0/24 using `ip access-list TEST deny 10.10.10.0/24`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessAction {
    Permit,
    Deny,
}

proxmox_serde::forward_display_to_serialize!(AccessAction);

#[derive(Error, Debug)]
pub enum FrrWordError {
    #[error("word is empty")]
    IsEmpty,
    #[error("word contains invalid character")]
    InvalidCharacter,
}

/// A simple FRR Word.
///
/// Every string argument or value in FRR is an FrrWord. FrrWords must only contain ascii
/// characters and must not have a whitespace.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct FrrWord(String);

forward_deserialize_to_from_str!(FrrWord);

impl FrrWord {
    pub fn new<T: AsRef<str> + Into<String>>(name: T) -> Result<Self, FrrWordError> {
        if name.as_ref().is_empty() {
            return Err(FrrWordError::IsEmpty);
        }

        if name
            .as_ref()
            .as_bytes()
            .iter()
            .any(|c| !c.is_ascii() || c.is_ascii_whitespace())
        {
            eprintln!("invalid char in: \"{}\"", name.as_ref());
            return Err(FrrWordError::InvalidCharacter);
        }

        Ok(Self(name.into()))
    }
}

impl FromStr for FrrWord {
    type Err = FrrWordError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl AsRef<str> for FrrWord {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Error, Debug)]
pub enum InterfaceNameError {
    #[error("interface name too long")]
    TooLong,
}

/// Name of a interface, which is common between all protocols.
///
/// FRR itself doesn't enforce any limits, but the kernel does. Linux only allows interface names
/// to be a maximum of 16 bytes. This is enforced by this struct.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InterfaceName(String);

impl TryFrom<&str> for InterfaceName {
    type Error = InterfaceNameError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::validate(s).map(Self::from_str_unchecked)
    }
}

impl TryFrom<String> for InterfaceName {
    type Error = InterfaceNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if Self::validate(&value).is_ok() {
            Ok(Self::from_string_unchecked(value))
        } else {
            Err(InterfaceNameError::TooLong)
        }
    }
}

impl InterfaceName {
    fn validate(s: &str) -> Result<&str, InterfaceNameError> {
        if s.len() <= 15 {
            Ok(s)
        } else {
            Err(InterfaceNameError::TooLong)
        }
    }
    fn from_string_unchecked(s: String) -> InterfaceName {
        Self(s)
    }

    fn from_str_unchecked(s: &str) -> InterfaceName {
        Self::from_string_unchecked(s.to_string())
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Deserialize)]
pub struct Interface<T> {
    // We can't use `Cidr` because then the template doesn't know if it's IPv6
    // or IPv4, and we need to prefix the FRR command with either "ipv6 ip" or "ip"
    #[serde(default)]
    pub addresses_v4: Vec<Ipv4Cidr>,
    #[serde(default)]
    pub addresses_v6: Vec<Ipv6Cidr>,

    #[serde(flatten)]
    pub properties: T,
}
impl From<openfabric::OpenfabricInterface> for Interface<openfabric::OpenfabricInterface> {
    fn from(value: openfabric::OpenfabricInterface) -> Self {
        Interface {
            addresses_v4: Vec::new(),
            addresses_v6: Vec::new(),
            properties: value,
        }
    }
}

impl From<ospf::OspfInterface> for Interface<ospf::OspfInterface> {
    fn from(value: ospf::OspfInterface) -> Self {
        Interface {
            addresses_v4: Vec::new(),
            addresses_v6: Vec::new(),
            properties: value,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IpOrInterface {
    Ip(IpAddr),
    Interface(InterfaceName),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IpRoute {
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    is_ipv6: bool,
    prefix: Cidr,
    via: IpOrInterface,
    vrf: Option<InterfaceName>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrrProtocol {
    Ospf,
    Openfabric,
    Bgp,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct IpProtocolRouteMap {
    pub v4: Option<RouteMapName>,
    pub v6: Option<RouteMapName>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VrfName {
    #[serde(rename = "default")]
    Default,
    #[serde(untagged)]
    Custom(String),
}

/// Main FRR config.
///
/// Contains the two main frr building blocks: routers and interfaces. It also holds other
/// top-level FRR options, such as access-lists, router-maps and protocol-routemaps.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FrrConfig {
    #[serde(default)]
    pub openfabric: OpenfabricFrrConfig,
    #[serde(default)]
    pub ospf: OspfFrrConfig,
    #[serde(default)]
    pub bgp: BgpFrrConfig,
    #[serde(default)]
    pub isis: IsisFrrConfig,

    #[serde(default)]
    pub ip_routes: Vec<IpRoute>,
    #[serde(default)]
    pub protocol_routemaps: BTreeMap<FrrProtocol, IpProtocolRouteMap>,
    #[serde(default)]
    pub routemaps: BTreeMap<RouteMapName, Vec<RouteMapEntry>>,
    #[serde(default)]
    pub access_lists: BTreeMap<AccessListName, Vec<AccessListRule>>,
    #[serde(default)]
    pub prefix_lists: BTreeMap<PrefixListName, Vec<PrefixListRule>>,

    #[serde(default)]
    pub custom_frr_config: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OpenfabricFrrConfig {
    #[serde(default)]
    pub router: BTreeMap<openfabric::OpenfabricRouterName, openfabric::OpenfabricRouter>,
    #[serde(default)]
    pub interfaces: BTreeMap<InterfaceName, Interface<openfabric::OpenfabricInterface>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IsisFrrConfig {
    #[serde(default)]
    pub router: BTreeMap<isis::IsisRouterName, isis::IsisRouter>,
    #[serde(default)]
    pub interfaces: BTreeMap<InterfaceName, Interface<isis::IsisInterface>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OspfFrrConfig {
    #[serde(default)]
    pub router: Option<ospf::OspfRouter>,
    #[serde(default)]
    pub interfaces: BTreeMap<InterfaceName, Interface<ospf::OspfInterface>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BgpFrrConfig {
    #[serde(default)]
    pub vrf_router: BTreeMap<VrfName, bgp::BgpRouter>,
    #[serde(default)]
    pub view_router: BTreeMap<u32, bgp::BgpRouter>,

    #[serde(default)]
    pub vrfs: BTreeMap<InterfaceName, bgp::Vrf>,

    #[serde(default)]
    pub ext_community_lists: BTreeMap<CommunityListName, ExtCommunityList>,
}

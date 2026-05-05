use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proxmox_network_types::ip_address::Cidr;
use proxmox_sdn_types::{
    bgp::{EvpnRouteType, SetMetricValue, SetTagValue},
    ModifyNumber, Vni,
};
use serde::{Deserialize, Serialize};

/// The action for a [`AccessListRule`].
///
/// The default is Permit. Deny can be used to create a NOT match (e.g. match all routes that are
/// NOT in 10.10.10.0/24 using `ip access-list TEST deny 10.10.10.0/24`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessAction {
    Permit,
    Deny,
}

/// A single [`AccessList`] rule.
///
/// Every rule in a [`AccessList`] is its own command and gets written into a new line (with the
/// same name). These rules have an action - permit (match) or deny (don't match) - and a network
/// address (which can be a single address or a range). The seq number is used to differentiate
/// between access-lists of the same name and rules. Every [`AccessListRule`] has to have a
/// different seq number.
/// The `ip` or `ipv6` prefix gets decided based on the Cidr address passed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessListRule {
    pub action: AccessAction,
    pub network: Cidr,
    #[serde(default)]
    pub seq: Option<u32>,
    #[serde(deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub is_ipv6: bool,
}

/// The name of an [`AccessList`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccessListName(String);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PrefixListName(String);

impl PrefixListName {
    pub fn new(name: String) -> PrefixListName {
        PrefixListName(name)
    }
}

impl AccessListName {
    pub fn new(name: String) -> AccessListName {
        AccessListName(name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PrefixListRule {
    pub action: AccessAction,
    pub network: Cidr,
    pub seq: Option<u32>,
    pub le: Option<u32>,
    pub ge: Option<u32>,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub is_ipv6: bool,
}

/// A match statement inside a route-map.
///
/// A route-map has one or more match statements which decide on which routes the route-map will
/// execute its actions. If we match on an IP, there are two different syntaxes: `match ip ...` or
/// `match ipv6 ...`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "key", content = "value")]
pub enum RouteMapMatch {
    #[serde(rename = "evpn route-type")]
    RouteType(EvpnRouteType),
    #[serde(rename = "evpn vni")]
    Vni(Vni),
    #[serde(rename = "ip address")]
    IpAddressAccessList(AccessListName),
    #[serde(rename = "ipv6 address")]
    Ip6AddressAccessList(AccessListName),
    #[serde(rename = "ip address prefix-list")]
    IpAddressPrefixList(PrefixListName),
    #[serde(rename = "ipv6 address prefix-list")]
    Ip6AddressPrefixList(PrefixListName),
    #[serde(rename = "ip next-hop prefix-list")]
    IpNextHopPrefixList(PrefixListName),
    #[serde(rename = "ipv6 next-hop prefix-list")]
    Ip6NextHopPrefixList(PrefixListName),
    #[serde(rename = "ip next-hop address")]
    IpNextHopAddress(Ipv4Addr),
    #[serde(rename = "ipv6 next-hop address")]
    Ip6NextHopAddress(Ipv6Addr),
    #[serde(rename = "metric")]
    Metric(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u32")] u32),
    #[serde(rename = "local-preference")]
    LocalPreference(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u32")] u32),
    #[serde(rename = "peer")]
    Peer(String),
    #[serde(rename = "tag")]
    Tag(SetTagValue),
}

/// Defines the Action a route-map takes when it matches on a route.
///
/// If the route matches the [`RouteMapMatch`], then a [`RouteMapSet`] action will be executed.
/// We currently only use the IpSrc command which changes the source address of the route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "key", content = "value")]
pub enum RouteMapSet {
    #[serde(rename = "ip next-hop peer-address")]
    IpNextHopPeerAddress,
    #[serde(rename = "ip next-hop unchanged")]
    IpNextHopUnchanged,
    #[serde(rename = "ip next-hop")]
    IpNextHop(Ipv4Addr),
    #[serde(rename = "ipv6 next-hop peer-address")]
    Ip6NextHopPeerAddress,
    #[serde(rename = "ipv6 next-hop prefer-global")]
    Ip6NextHopPreferGlobal,
    #[serde(rename = "ipv6 next-hop global")]
    Ip6NextHop(Ipv6Addr),
    #[serde(rename = "local-preference")]
    LocalPreference(ModifyNumber),
    #[serde(rename = "tag")]
    Tag(SetTagValue),
    #[serde(rename = "weight")]
    Weight(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u32")] u32),
    #[serde(rename = "metric")]
    Metric(SetMetricValue),
    #[serde(rename = "src")]
    Src(IpAddr),
    #[serde(rename = "community")]
    Community(String),
}

/// The exit action for a route map.
///
/// This can be optionally specified to override the default behavior of FRR to terminate
/// evaluating the route map if an entry matches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "key", content = "value")]
pub enum RouteMapExitAction {
    #[serde(rename = "on-match next")]
    OnMatchNext,
    #[serde(rename = "on-match goto")]
    OnMatchGoto(u16),
    #[serde(rename = "continue")]
    Continue(u16),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RouteMapName(String);

impl RouteMapName {
    pub fn new(name: String) -> RouteMapName {
        RouteMapName(name)
    }
}

/// A FRR route-map.
///
/// In FRR route-maps are used to manipulate routes learned by protocols. We can match on specific
/// routes (from specific protocols or subnets) and then change them, by e.g. editing the source
/// address or adding a metric, bgp community, or local preference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteMapEntry {
    pub seq: u16,
    pub action: AccessAction,
    #[serde(default)]
    pub matches: Vec<RouteMapMatch>,
    #[serde(default)]
    pub sets: Vec<RouteMapSet>,
    #[serde(default)]
    pub call: Option<RouteMapName>,
    #[serde(default)]
    pub exit_action: Option<RouteMapExitAction>,
    #[serde(default)]
    pub custom_frr_config: Vec<String>,
}

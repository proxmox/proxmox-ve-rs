use std::net::IpAddr;

use proxmox_network_types::ip_address::Cidr;
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
#[serde(tag = "protocol_type")]
pub enum RouteMapMatch {
    #[serde(rename = "ip")]
    V4(RouteMapMatchInner),
    #[serde(rename = "ipv6")]
    V6(RouteMapMatchInner),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "list_type", content = "list_name", rename_all = "lowercase")]
pub enum AccessListOrPrefixList {
    PrefixList(PrefixListName),
    AccessList(AccessListName),
}

/// A route-map match statement generic on the IP-version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "match_type", content = "value", rename_all = "kebab-case")]
pub enum RouteMapMatchInner {
    Address(AccessListOrPrefixList),
    NextHop(String),
}

/// Defines the Action a route-map takes when it matches on a route.
///
/// If the route matches the [`RouteMapMatch`], then a [`RouteMapSet`] action will be executed.
/// We currently only use the IpSrc command which changes the source address of the route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "set_type", content = "value", rename_all = "kebab-case")]
pub enum RouteMapSet {
    LocalPreference(u32),
    Src(IpAddr),
    Metric(u32),
    Community(String),
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
    pub seq: u32,
    pub action: AccessAction,
    #[serde(default)]
    pub matches: Vec<RouteMapMatch>,
    #[serde(default)]
    pub sets: Vec<RouteMapSet>,
    #[serde(default)]
    pub custom_frr_config: Vec<String>,
}

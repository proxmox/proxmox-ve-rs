use std::{
    fmt::{self, Display},
    net::IpAddr,
};

use proxmox_network_types::ip_address::Cidr;

/// The action for a [`AccessListRule`].
///
/// The default is Permit. Deny can be used to create a NOT match (e.g. match all routes that are
/// NOT in 10.10.10.0/24 using `ip access-list TEST deny 10.10.10.0/24`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessAction {
    Permit,
    Deny,
}

impl fmt::Display for AccessAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessAction::Permit => write!(f, "permit"),
            AccessAction::Deny => write!(f, "deny"),
        }
    }
}

/// A single [`AccessList`] rule.
///
/// Every rule in a [`AccessList`] is its own command and gets written into a new line (with the
/// same name). These rules have an action - permit (match) or deny (don't match) - and a network
/// address (which can be a single address or a range). The seq number is used to differentiate
/// between access-lists of the same name and rules. Every [`AccessListRule`] has to have a
/// different seq number.
/// The `ip` or `ipv6` prefix gets decided based on the Cidr address passed.
///
/// This serializes to:
///
/// ```text
/// ip access-list filter permit 10.0.0.0/8
/// ! or
/// ipv6 access-list filter permit 2001:db8::/64
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessListRule {
    pub action: AccessAction,
    pub network: Cidr,
    pub seq: Option<u32>,
}

/// The name of an [`AccessList`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccessListName(String);

impl AccessListName {
    pub fn new(name: String) -> AccessListName {
        AccessListName(name)
    }
}

impl Display for AccessListName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A FRR access-list.
///
/// Holds a vec of rules. Each rule will get its own line, FRR will collect all the rules with the
/// same name and combine them.
///
/// This serializes to:
///
/// ```text
/// ip access-list pve_test permit 10.0.0.0/24
/// ip access-list pve_test permit 12.1.1.0/24
/// ip access-list pve_test deny 8.8.8.8/32
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessList {
    pub name: AccessListName,
    pub rules: Vec<AccessListRule>,
}

/// A match statement inside a route-map.
///
/// A route-map has one or more match statements which decide on which routes the route-map will
/// execute its actions. If we match on an IP, there are two different syntaxes: `match ip ...` or
/// `match ipv6 ...`.
///
/// Serializes to:
///
/// ```text
///  match ip address <access-list-name>
/// ! or
///  match ip next-hop <ip-address>
/// ! or
///  match ipv6 address <access-list-name>
/// ! or
///  match ipv6 next-hop <ip-address>
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteMapMatch {
    V4(RouteMapMatchInner),
    V6(RouteMapMatchInner),
}

impl Display for RouteMapMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteMapMatch::V4(route_map_match_v4) => match route_map_match_v4 {
                RouteMapMatchInner::IpAddress(access_list_name) => {
                    write!(f, "match ip address {access_list_name}")
                }
                RouteMapMatchInner::IpNextHop(next_hop) => {
                    write!(f, "match ip next-hop {next_hop}")
                }
            },
            RouteMapMatch::V6(route_map_match_v6) => match route_map_match_v6 {
                RouteMapMatchInner::IpAddress(access_list_name) => {
                    write!(f, "match ipv6 address {access_list_name}")
                }
                RouteMapMatchInner::IpNextHop(next_hop) => {
                    write!(f, "match ipv6 next-hop {next_hop}")
                }
            },
        }
    }
}

/// A route-map match statement generic on the IP-version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteMapMatchInner {
    IpAddress(AccessListName),
    IpNextHop(String),
}

/// Defines the Action a route-map takes when it matches on a route.
///
/// If the route matches the [`RouteMapMatch`], then a [`RouteMapSet`] action will be executed.
/// We currently only use the IpSrc command which changes the source address of the route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteMapSet {
    LocalPreference(u32),
    IpSrc(IpAddr),
    Metric(u32),
    Community(String),
}

impl Display for RouteMapSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteMapSet::LocalPreference(pref) => write!(f, "set local-preference {}", pref),
            RouteMapSet::IpSrc(addr) => write!(f, "set src {}", addr),
            RouteMapSet::Metric(metric) => write!(f, "set metric {}", metric),
            RouteMapSet::Community(community) => write!(f, "set community {}", community),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteMapName(String);

impl RouteMapName {
    pub fn new(name: String) -> RouteMapName {
        RouteMapName(name)
    }
}

impl Display for RouteMapName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A FRR route-map.
///
/// In FRR route-maps are used to manipulate routes learned by protocols. We can match on specific
/// routes (from specific protocols or subnets) and then change them, by e.g. editing the source
/// address or adding a metric, bgp community, or local preference.
///
/// This serializes to:
///
/// ```text
/// route-map <name> permit 100
///  match ip address <access-list>
///  set src <ip-address>
/// exit
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteMap {
    pub name: RouteMapName,
    pub seq: u32,
    pub action: AccessAction,
    pub matches: Vec<RouteMapMatch>,
    pub sets: Vec<RouteMapSet>,
}

/// The ProtocolType used in the [`ProtocolRouteMap`].
///
/// Specifies to which protocols we can attach route-maps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolType {
    Openfabric,
    Ospf,
}

impl Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolType::Openfabric => write!(f, "openfabric"),
            ProtocolType::Ospf => write!(f, "ospf"),
        }
    }
}

/// ProtocolRouteMap statement.
///
/// This statement attaches the route-map to the protocol, so that all the routes learned through
/// the specified protocol can be matched on and manipulated with the route-map.
///
/// This serializes to:
///
/// ```text
/// ip protocol <protocol> route-map <route-map-name>
/// ! or
/// ipv6 protocol <protocol> route-map <route-map-name>
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolRouteMap {
    pub is_ipv6: bool,
    pub protocol: ProtocolType,
    pub routemap_name: RouteMapName,
}

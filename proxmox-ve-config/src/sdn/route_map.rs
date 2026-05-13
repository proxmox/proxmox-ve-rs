//! Section config types for FRR Route Maps.
//!
//! This module contains the API types required for representing FRR Route Maps as section config.
//! Each entry in the section config maps to a Route Map entry, *not* a route map as a whole, the
//! order of the entry is encoded in the ID of the Route Map.
//!
//! Route maps in FRR consists of at least one entry, which are ordered by their given sequence
//! number / order. Each entry has a default matching policy, which is applied if the matching
//! conditions of the entry are met.
//!
//! An example for a simple FRR Route Map entry looks like this:
//!
//! ```text
//! route-map test permit 10
//!  match ip next-hop address 192.0.2.1
//!  set local-preference 200
//!  on-match goto 1234
//!
//! route-map test permit 20
//!  call some-other-routemap
//! ```
//!
//! The corresponding representation as a section config entry looks like this:
//!
//! ```text
//! route-map-entry: test_10
//!  action permit
//!  match key=ip-next-hop-address,value=192.0.2.1
//!  set key=local-preference,value=200
//!  exit-action key=on-match-goto,value=1234
//!
//! route-map-entry: test_20
//!  call some-other-routemap
//! ```
//!
//! Match / Set Actions and Exit Policies are encoded as an array with a property string that has a
//! key and an optional value parameter, because some options do not require an additional value.

use std::net::IpAddr;

use anyhow::format_err;
use const_format::concatcp;

use proxmox_network_types::ip_address::api_types::{Ipv4Addr, Ipv6Addr};
use proxmox_sdn_types::{
    bgp::{EvpnRouteType, SetMetricValue, SetTagValue},
    ModifyNumber, Vni,
};
use serde::{Deserialize, Serialize};

use proxmox_schema::{
    api, api_string_type, const_regex, property_string::PropertyString, ApiStringFormat, ApiType,
    EnumEntry, ObjectSchema, Schema, StringSchema, Updater, UpdaterType,
};

use crate::sdn::prefix_list::PrefixListId;

pub const ROUTE_MAP_ID_REGEX_STR: &str =
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]){0,30}(?:[a-zA-Z0-9]){0,1})";

pub const ROUTE_MAP_ORDER_REGEX_STR: &str = r"\d+";

const_regex! {
    pub ROUTE_MAP_ID_REGEX = concatcp!(r"^", ROUTE_MAP_ID_REGEX_STR, r"$");
    pub ROUTE_MAP_SECTION_ID_REGEX = concatcp!(r"^", ROUTE_MAP_ID_REGEX_STR, r"_", ROUTE_MAP_ORDER_REGEX_STR, r"$");
}

pub const ROUTE_MAP_SECTION_ID_FORMAT: ApiStringFormat =
    ApiStringFormat::Pattern(&ROUTE_MAP_SECTION_ID_REGEX);

pub const ROUTE_MAP_ID_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&ROUTE_MAP_ID_REGEX);

api_string_type! {
    /// ID of a Route Map.
    #[api(format: &ROUTE_MAP_ID_FORMAT)]
    #[derive(Debug, Deserialize, Serialize, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, UpdaterType)]
    pub struct RouteMapId(String);
}

/// The ID of a Route Map entry in the section config (name + order).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteMapEntryId {
    /// name of the Route Map
    route_map_id: RouteMapId,
    /// seq nr of the Route Map
    order: u16,
}

impl RouteMapEntryId {
    /// Create a new Route Map Entry ID.
    pub fn new(route_map_id: RouteMapId, order: u16) -> Self {
        Self {
            route_map_id,
            order,
        }
    }

    /// Returns the name part of the Route Map section id.
    pub fn route_map_id(&self) -> &RouteMapId {
        &self.route_map_id
    }

    /// Returns the order part of the Route Map section id.
    pub fn order(&self) -> u16 {
        self.order
    }
}

impl ApiType for RouteMapEntryId {
    const API_SCHEMA: Schema = StringSchema::new("ID of a Route Map entry in the section config")
        .format(&ROUTE_MAP_SECTION_ID_FORMAT)
        .schema();
}

impl std::fmt::Display for RouteMapEntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}_{}", self.route_map_id, self.order)
    }
}

proxmox_serde::forward_serialize_to_display!(RouteMapEntryId);

impl std::str::FromStr for RouteMapEntryId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, order) = value
            .rsplit_once("_")
            .ok_or_else(|| format_err!("invalid RouteMap section id: {}", value))?;

        Ok(Self {
            route_map_id: RouteMapId::from_string(name.to_string())?,
            order: order.parse()?,
        })
    }
}

proxmox_serde::forward_deserialize_to_from_str!(RouteMapEntryId);

#[api(
    "id-property": "id",
    "id-schema": {
        type: String,
        description: "Route Map Section ID",
        format: &ROUTE_MAP_SECTION_ID_FORMAT,
    },
    "type-key": "type",
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
/// The Route Map section config type.
pub enum RouteMap {
    RouteMapEntry(RouteMapEntry),
}

#[api()]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Matching policy of a Route Map entry.
pub enum RouteMapAction {
    /// Permit
    Permit,
    /// Deny
    Deny,
}

/// The exit action for a route map.
///
/// This can be optionally specified to override the default behavior of FRR to terminate
/// evaluating the route map if an entry matches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "key", content = "value", rename_all = "kebab-case")]
pub enum ExitAction {
    OnMatchNext,
    OnMatchGoto(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u16")] u16),
    Continue(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u16")] u16),
}

impl ApiType for ExitAction {
    const API_SCHEMA: Schema = ObjectSchema::new(
        "Exit action for a FRR route map.",
        &[
            (
                "key",
                false,
                &StringSchema::new("The key indicating which value should be set.")
                    .format(&ApiStringFormat::Enum(&[
                        EnumEntry::new(
                            "on-match-next",
                            "Proceed with the next entry in the route map.",
                        ),
                        EnumEntry::new("continue", "Continue with route map entry with order <value>."),
                        EnumEntry::new(
                            "on-match-goto",
                            "Continue processing the route map with the first entry with order >= <value>.",
                        ),
                    ]))
                    .schema(),
            ),
            (
                "value",
                true,
                &StringSchema::new("The value that should be set - depends on the given key.")
                    .schema(),
            ),
        ],
    )
    .schema();
}

impl UpdaterType for ExitAction {
    type Updater = Option<ExitAction>;
}

#[api(
    properties: {
        set: {
            type: Array,
            description: "A list of Set actions to perform in this entry.",
            optional: true,
            items: {
                type: String,
                description: "A specific Set action.",
                format: &ApiStringFormat::PropertyString(&SetAction::API_SCHEMA),
            }
        },
        "match": {
            type: Array,
            description: "A list of Match actions to perform in this entry.",
            optional: true,
            items: {
                type: String,
                description: "A specific match action.",
                format: &ApiStringFormat::PropertyString(&MatchAction::API_SCHEMA),
            }
        },
        "exit-action": {
            type: String,
            description: "Exit action for the route map.",
            optional: true,
            format: &ApiStringFormat::PropertyString(&ExitAction::API_SCHEMA),
        },
    }
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Route Map Entry
///
/// Represents one entry in a Route Map. One Route Map is made up of one or more entries, that are
/// executed in order of their ordering number.
#[serde(rename_all = "kebab-case")]
pub struct RouteMapEntry {
    id: RouteMapEntryId,
    action: RouteMapAction,
    #[serde(default, rename = "set")]
    set_actions: Vec<PropertyString<SetAction>>,
    #[serde(default, rename = "match")]
    match_actions: Vec<PropertyString<MatchAction>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    call: Option<RouteMapId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exit_action: Option<PropertyString<ExitAction>>,
}

impl RouteMapEntry {
    /// Return the ID of the Route Map.
    pub fn id(&self) -> &RouteMapEntryId {
        &self.id
    }

    /// Sets the action for this entry.
    pub fn set_action(&mut self, action: RouteMapAction) {
        self.action = action;
    }

    /// Set the set actions for this route map entry.
    pub fn set_set_actions(
        &mut self,
        set_actions: impl IntoIterator<Item = PropertyString<SetAction>>,
    ) {
        self.set_actions = set_actions.into_iter().collect();
    }

    /// Set the match actions for this route map entry.
    pub fn set_match_actions(
        &mut self,
        match_actions: impl IntoIterator<Item = PropertyString<MatchAction>>,
    ) {
        self.match_actions = match_actions.into_iter().collect();
    }

    pub fn set_call(&mut self, call: Option<RouteMapId>) {
        self.call = call;
    }

    pub fn set_exit_action(&mut self, exit_action: Option<PropertyString<ExitAction>>) {
        self.exit_action = exit_action;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "key", content = "value")]
/// A Route Map set action
pub enum SetAction {
    IpNextHopPeerAddress,
    IpNextHopUnchanged,
    IpNextHop(Ipv4Addr),
    Ip6NextHopPeerAddress,
    Ip6NextHopPreferGlobal,
    Ip6NextHop(Ipv6Addr),
    Weight(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u32")] u32),
    Tag(SetTagValue),
    Metric(SetMetricValue),
    LocalPreference(ModifyNumber),
    Src(IpAddr),
}

impl ApiType for SetAction {
    const API_SCHEMA: Schema = ObjectSchema::new(
        "FRR set action",
        &[
            (
                "key",
                false,
                &StringSchema::new("The key indicating which value should be set.")
                    .format(&ApiStringFormat::Enum(&[
                        EnumEntry::new(
                            "ip-next-hop-peer-address",
                            "Sets the BGP nexthop address to the IPv4 peer address.",
                        ),
                        EnumEntry::new("ip-next-hop-unchanged", "Leaves the nexthop unchanged."),
                        EnumEntry::new(
                            "ip-next-hop",
                            "Sets the nexthop to the given IPv4 address.",
                        ),
                        EnumEntry::new(
                            "ip6-next-hop-peer-address",
                            "Sets the BGP nexthop address to the IPv6 peer address.",
                        ),
                        EnumEntry::new(
                            "ip6-next-hop-prefer-global",
                            "If a LLA and GUA are received, prefer the GUA.",
                        ),
                        EnumEntry::new(
                            "ip6-next-hop",
                            "Sets the nexthop to the given IPv6 address.",
                        ),
                        EnumEntry::new(
                            "local-preference",
                            "Sets the local preference for this route.",
                        ),
                        EnumEntry::new("tag", "Sets a tag for the route."),
                        EnumEntry::new("weight", "Sets the weight for the route."),
                        EnumEntry::new("metric", "Sets the metric for the route."),
                        EnumEntry::new(
                            "src",
                            "The source address to insert into the kernel routing table.",
                        ),
                    ]))
                    .schema(),
            ),
            (
                "value",
                true,
                &StringSchema::new("The value that should be set - depends on the given key.")
                    .schema(),
            ),
        ],
    )
    .schema();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "key", content = "value")]
pub enum MatchAction {
    RouteType(EvpnRouteType),
    Vni(Vni),
    IpAddressPrefixList(PrefixListId),
    Ip6AddressPrefixList(PrefixListId),
    IpNextHopPrefixList(PrefixListId),
    Ip6NextHopPrefixList(PrefixListId),
    IpNextHopAddress(Ipv4Addr),
    Ip6NextHopAddress(Ipv6Addr),
    Tag(SetTagValue),
    Metric(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u32")] u32),
    LocalPreference(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u32")] u32),
    Peer(String),
}

impl ApiType for MatchAction {
    const API_SCHEMA: Schema = ObjectSchema::new(
        "FRR match action",
        &[
            (
                "key",
                false,
                &StringSchema::new("The key indicating on which value to match.")
                    .format(&ApiStringFormat::Enum(&[
                        EnumEntry::new("route-type", "Match the EVPN route type."),
                        EnumEntry::new("vni", "Match the VNI of an EVPN route."),
                        EnumEntry::new(
                            "ip-address-prefix-list",
                            "Match the IPv4 CIDR to a prefix-list.",
                        ),
                        EnumEntry::new(
                            "ip6-address-prefix-list",
                            "Match the IPv6 CIDR to a prefix-list",
                        ),
                        EnumEntry::new(
                            "ip-next-hop-prefix-list",
                            "Match the IPv4 next-hop to a prefix-list.",
                        ),
                        EnumEntry::new(
                            "ip6-next-hop-prefix-list",
                            "Match the IPv6 next-hop to a prefix-list.",
                        ),
                        EnumEntry::new(
                            "ip-next-hop-address",
                            "Match the next-hop to an IPv4 address.",
                        ),
                        EnumEntry::new(
                            "ip6-next-hop-address",
                            "Match the next-hop to an IPv6 address.",
                        ),
                        EnumEntry::new("metric", "Match the metric of the route."),
                        EnumEntry::new("tag", "Match the tag of the route."),
                        EnumEntry::new("local-preference", "Match the local preference."),
                        EnumEntry::new(
                            "peer",
                            "Match the peer IP address, interface name or peer group.",
                        ),
                    ]))
                    .schema(),
            ),
            (
                "value",
                true,
                &StringSchema::new("The value that should be matched - depends on the given key.")
                    .schema(),
            ),
        ],
    )
    .schema();
}

#[cfg(feature = "frr")]
pub mod frr {
    //! Route Map Entry FRR types
    //!
    //! This module contains implementations of conversion traits for the section config types, so
    //! they can be converted to the respective proxmox-frr types. This enables easy conversion to
    //! the proxmox-frr types and makes it possible to generate the FRR configuration for the Route
    //! Map entries.

    use super::*;

    use std::collections::HashMap;

    use proxmox_frr::ser::{
        route_map::{
            RouteMapEntry as FrrRouteMapEntry, RouteMapExitAction as FrrRouteMapExitAction,
            RouteMapMatch as FrrRouteMapMatch, RouteMapName as FrrRouteMapName,
            RouteMapSet as FrrRouteMapSet,
        },
        FrrConfig,
    };

    use crate::sdn::route_map::RouteMapAction;

    impl From<MatchAction> for FrrRouteMapMatch {
        fn from(value: MatchAction) -> Self {
            match value {
                MatchAction::RouteType(evpn_route_type) => Self::RouteType(evpn_route_type),
                MatchAction::Vni(vni) => Self::Vni(vni),
                MatchAction::IpAddressPrefixList(prefix_list_name) => {
                    Self::IpAddressPrefixList(prefix_list_name.into())
                }
                MatchAction::Ip6AddressPrefixList(prefix_list_name) => {
                    Self::Ip6AddressPrefixList(prefix_list_name.into())
                }
                MatchAction::IpNextHopPrefixList(prefix_list_name) => {
                    Self::IpNextHopPrefixList(prefix_list_name.into())
                }
                MatchAction::Ip6NextHopPrefixList(prefix_list_name) => {
                    Self::Ip6NextHopPrefixList(prefix_list_name.into())
                }
                MatchAction::IpNextHopAddress(ipv4_addr) => Self::IpNextHopAddress(*ipv4_addr),
                MatchAction::Ip6NextHopAddress(ipv6_addr) => Self::Ip6NextHopAddress(*ipv6_addr),
                MatchAction::Metric(metric) => Self::Metric(metric),
                MatchAction::LocalPreference(local_preference) => {
                    Self::LocalPreference(local_preference)
                }
                MatchAction::Peer(ip_addr) => Self::Peer(ip_addr),
                MatchAction::Tag(tag) => Self::Tag(tag),
            }
        }
    }

    impl From<SetAction> for FrrRouteMapSet {
        fn from(value: SetAction) -> Self {
            match value {
                SetAction::IpNextHopPeerAddress => Self::IpNextHopPeerAddress,
                SetAction::IpNextHopUnchanged => Self::IpNextHopUnchanged,
                SetAction::IpNextHop(ipv4_addr) => Self::IpNextHop(*ipv4_addr),
                SetAction::Ip6NextHopPeerAddress => Self::Ip6NextHopPeerAddress,
                SetAction::Ip6NextHopPreferGlobal => Self::Ip6NextHopPreferGlobal,
                SetAction::Ip6NextHop(ipv6_addr) => Self::Ip6NextHop(*ipv6_addr),
                SetAction::LocalPreference(local_preference) => {
                    Self::LocalPreference(local_preference)
                }
                SetAction::Tag(tag) => Self::Tag(tag),
                SetAction::Weight(weight) => Self::Weight(weight),
                SetAction::Metric(metric) => Self::Metric(metric),
                SetAction::Src(src) => Self::Src(src),
            }
        }
    }

    impl From<ExitAction> for FrrRouteMapExitAction {
        fn from(value: ExitAction) -> Self {
            match value {
                ExitAction::OnMatchNext => FrrRouteMapExitAction::OnMatchNext,
                ExitAction::OnMatchGoto(n) => FrrRouteMapExitAction::OnMatchGoto(n),
                ExitAction::Continue(n) => FrrRouteMapExitAction::Continue(n),
            }
        }
    }

    impl From<RouteMapId> for FrrRouteMapName {
        fn from(value: RouteMapId) -> Self {
            FrrRouteMapName::new(value.0)
        }
    }

    impl From<RouteMapEntry> for FrrRouteMapEntry {
        fn from(value: RouteMapEntry) -> FrrRouteMapEntry {
            FrrRouteMapEntry {
                seq: value.id.order,
                action: match value.action {
                    RouteMapAction::Permit => proxmox_frr::ser::route_map::AccessAction::Permit,
                    RouteMapAction::Deny => proxmox_frr::ser::route_map::AccessAction::Deny,
                },
                matches: value
                    .match_actions
                    .into_iter()
                    .map(|match_action| match_action.into_inner().into())
                    .collect(),
                sets: value
                    .set_actions
                    .into_iter()
                    .map(|set_action| set_action.into_inner().into())
                    .collect(),
                call: value.call.map(FrrRouteMapName::from),
                exit_action: value.exit_action.map(|value| value.into_inner().into()),
                custom_frr_config: Default::default(),
            }
        }
    }

    /// Add a list of Route Map Entries to a [`FrrConfig`].
    ///
    /// This method takes a list of Route Map Entries and adds them to given FRR configuration.
    /// If a route map with the same name as at least one entry in the config exists in the FRR
    /// configuration, then the *whole* route map will get overwritten with the route map from the
    /// configuration.
    pub fn build_frr_route_maps(
        config: impl IntoIterator<Item = RouteMap>,
        frr_config: &mut FrrConfig,
    ) -> Result<(), anyhow::Error> {
        let mut config_route_map: HashMap<FrrRouteMapName, Vec<FrrRouteMapEntry>> = HashMap::new();

        for route_map in config.into_iter() {
            let RouteMap::RouteMapEntry(route_map) = route_map;
            let route_map_name = FrrRouteMapName::new(route_map.id.route_map_id.to_string());

            if let Some(frr_route_map) = config_route_map.get_mut(&route_map_name) {
                let idx =
                    frr_route_map.partition_point(|element| element.seq <= route_map.id().order());
                frr_route_map.insert(idx, route_map.into());
            } else {
                config_route_map.insert(route_map_name, vec![route_map.into()]);
            }
        }

        for (name, entries) in config_route_map {
            frr_config.routemaps.insert(name, entries);
        }

        Ok(())
    }
}

pub mod api {
    //! API type for Route Map Entries.
    //!
    //! Since Route Map Entries encode information in their ID, these types help converting to /
    //! from the Section Config types.
    use super::*;

    #[api(
        properties: {
            set: {
                type: Array,
                description: "A list of set actions for this Route Map entry",
                optional: true,
                items: {
                    type: String,
                    description: "A set action",
                    format: &ApiStringFormat::PropertyString(&SetAction::API_SCHEMA),
            }
            },
            "match": {
                type: Array,
                description: "A list of match actions for this Route Map entry",
                optional: true,
                items: {
                    type: String,
                    description: "A match action",
                    format: &ApiStringFormat::PropertyString(&MatchAction::API_SCHEMA),
                }
            },
            "exit-action": {
                type: String,
                description: "Exit action for the route map.",
                optional: true,
                format: &ApiStringFormat::PropertyString(&ExitAction::API_SCHEMA),
            },
        }
    )]
    #[derive(Debug, Clone, Serialize, Deserialize, Updater)]
    #[serde(rename_all = "kebab-case")]
    /// Route Map entry
    pub struct RouteMapEntry {
        /// name of the Route Map
        #[updater(skip)]
        pub route_map_id: RouteMapId,
        /// seq nr of the Route Map
        #[updater(skip)]
        #[serde(deserialize_with = "proxmox_serde::perl::deserialize_u16")]
        pub order: u16,
        pub action: RouteMapAction,
        #[serde(default, rename = "set")]
        pub set_actions: Vec<PropertyString<SetAction>>,
        #[serde(default, rename = "match")]
        pub match_actions: Vec<PropertyString<MatchAction>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub call: Option<RouteMapId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exit_action: Option<PropertyString<ExitAction>>,
    }

    impl RouteMapEntry {
        /// Return the ID of the Route Map this entry belongs to.
        pub fn route_map_id(&self) -> &RouteMapId {
            &self.route_map_id
        }

        /// Return the order for this Route Map entry.
        pub fn order(&self) -> u16 {
            self.order
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Hash)]
    #[serde(rename_all = "kebab-case")]
    /// Deletable properties for Route Map entries.
    pub enum RouteMapDeletableProperties {
        Set,
        Match,
        Call,
        ExitAction,
    }

    impl From<super::RouteMapEntry> for RouteMapEntry {
        fn from(value: super::RouteMapEntry) -> RouteMapEntry {
            RouteMapEntry {
                route_map_id: value.id.route_map_id,
                order: value.id.order,
                action: value.action,
                set_actions: value.set_actions,
                match_actions: value.match_actions,
                call: value.call,
                exit_action: value.exit_action,
            }
        }
    }

    impl From<RouteMapEntry> for super::RouteMapEntry {
        fn from(value: RouteMapEntry) -> super::RouteMapEntry {
            super::RouteMapEntry {
                id: RouteMapEntryId {
                    route_map_id: value.route_map_id,
                    order: value.order,
                },
                action: value.action,
                set_actions: value.set_actions,
                match_actions: value.match_actions,
                call: value.call,
                exit_action: value.exit_action,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use proxmox_section_config::typed::ApiSectionDataEntry;

    use super::*;

    #[test]
    fn test_simple_route_map() -> Result<(), anyhow::Error> {
        let section_config = r#"
route-map-entry: test_underscore_123
  action permit
  set key=tag,value=23487
  set key=tag,value=untagged
  set key=metric,value=+rtt
  set key=local-preference,value=-12345
  set key=ip-next-hop,value=192.0.2.0
  match key=vni,value=23487
  match key=vni,value=23487
  call some-other-route-map
  exit-action key=on-match-goto,value=1234
"#;

        RouteMap::parse_section_config("route-maps.cfg", section_config)?;
        Ok(())
    }
}

use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr};

use proxmox_network_types::ip_address::{Ipv4Cidr, Ipv6Cidr};
use serde::{Deserialize, Serialize};

use crate::ser::route_map::RouteMapName;
use crate::ser::{AccessAction, FrrWord, InterfaceName, IpRoute};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BgpRouterName {
    asn: u32,
    vrf: Option<FrrWord>,
}

impl BgpRouterName {
    pub fn new(asn: u32, vrf: Option<FrrWord>) -> Self {
        Self { asn, vrf }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NeighborRemoteAs {
    Internal,
    External,
    #[serde(untagged)]
    Asn(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u32")] u32),
}

// Each flag requires the previous flag to be set. It is not possible to set replace-as without
// no-prepend.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalAsFlags {
    NoPrepend,
    #[serde(rename = "no-prepend replace-as")]
    ReplaceAs,
    #[serde(rename = "no-prepend replace-as dual-as")]
    DualAs,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct LocalAsSettings {
    pub asn: u32,
    #[serde(default)]
    pub mode: Option<LocalAsFlags>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NeighborGroup {
    pub name: FrrWord,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub bfd: bool,
    #[serde(default)]
    pub local_as: Option<LocalAsSettings>,
    pub remote_as: NeighborRemoteAs,
    #[serde(default)]
    pub ips: Vec<IpAddr>,
    #[serde(default)]
    pub interfaces: Vec<InterfaceName>,
    pub ebgp_multihop: Option<u8>,
    pub update_source: Option<InterfaceName>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ipv4UnicastAF {
    #[serde(flatten)]
    pub common_options: CommonAddressFamilyOptions,
    #[serde(default)]
    pub networks: Vec<Ipv4Cidr>,
    #[serde(default)]
    pub redistribute: Vec<Redistribution>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ipv6UnicastAF {
    #[serde(flatten)]
    pub common_options: CommonAddressFamilyOptions,
    #[serde(default)]
    pub networks: Vec<Ipv6Cidr>,
    #[serde(default)]
    pub redistribute: Vec<Redistribution>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct L2vpnEvpnAF {
    #[serde(flatten)]
    pub common_options: CommonAddressFamilyOptions,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub advertise_all_vni: Option<bool>,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub advertise_default_gw: Option<bool>,
    #[serde(default)]
    pub default_originate: Vec<DefaultOriginate>,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub advertise_ipv4_unicast: Option<bool>,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub advertise_ipv6_unicast: Option<bool>,
    pub autort_as: Option<u32>,
    pub route_targets: Option<RouteTargets>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultOriginate {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedistributeProtocol {
    Connected,
    Static,
    Ospf,
    Kernel,
    Isis,
    Ospf6,
    Openfabric,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Redistribution {
    pub protocol: RedistributeProtocol,
    pub metric: Option<u32>,
    pub route_map: Option<RouteMapName>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RouteTargets {
    #[serde(default)]
    pub import: Vec<FrrWord>,
    #[serde(default)]
    pub export: Vec<FrrWord>,
    #[serde(default)]
    pub both: Vec<FrrWord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AddressFamilyNeighbor {
    pub name: String,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub soft_reconfiguration_inbound: Option<bool>,
    pub route_map_in: Option<RouteMapName>,
    pub route_map_out: Option<RouteMapName>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CommonAddressFamilyOptions {
    #[serde(default)]
    pub import_vrf: Vec<FrrWord>,
    #[serde(default)]
    pub neighbors: Vec<AddressFamilyNeighbor>,
    #[serde(default)]
    pub custom_frr_config: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct AddressFamilies {
    pub ipv4_unicast: Option<Ipv4UnicastAF>,
    pub ipv6_unicast: Option<Ipv6UnicastAF>,
    pub l2vpn_evpn: Option<L2vpnEvpnAF>,
}

impl AddressFamilies {
    /// Extend this [`AddressFamilies`] with another.
    ///
    /// For each address family: if `self` already has it, extend its neighbors, networks, and
    /// redistribute lists. If `self` doesn't have it, take it from `other`.
    pub fn extend(&mut self, other: AddressFamilies) {
        match (self.ipv4_unicast.as_mut(), other.ipv4_unicast) {
            (Some(existing), Some(incoming)) => {
                existing
                    .common_options
                    .neighbors
                    .extend(incoming.common_options.neighbors);
                existing
                    .common_options
                    .import_vrf
                    .extend(incoming.common_options.import_vrf);
                existing
                    .common_options
                    .custom_frr_config
                    .extend(incoming.common_options.custom_frr_config);
                existing.networks.extend(incoming.networks);
                existing.redistribute.extend(incoming.redistribute);
            }
            (None, Some(incoming)) => {
                self.ipv4_unicast = Some(incoming);
            }
            _ => {}
        }

        match (self.ipv6_unicast.as_mut(), other.ipv6_unicast) {
            (Some(existing), Some(incoming)) => {
                existing
                    .common_options
                    .neighbors
                    .extend(incoming.common_options.neighbors);
                existing
                    .common_options
                    .import_vrf
                    .extend(incoming.common_options.import_vrf);
                existing
                    .common_options
                    .custom_frr_config
                    .extend(incoming.common_options.custom_frr_config);
                existing.networks.extend(incoming.networks);
                existing.redistribute.extend(incoming.redistribute);
            }
            (None, Some(incoming)) => {
                self.ipv6_unicast = Some(incoming);
            }
            _ => {}
        }

        // l2vpn_evpn: only take from other if self doesn't have it (fabric never sets this)
        if self.l2vpn_evpn.is_none() {
            self.l2vpn_evpn = other.l2vpn_evpn;
        }
    }
}

impl BgpRouter {
    /// Merge a fabric-generated [`BgpRouter`] into an existing one.
    ///
    /// Appends the fabric's neighbor groups and merges address families. Keeps the existing
    /// router's ASN, router-id, and other top-level settings. The caller is responsible for
    /// setting `local_as` on the fabric's neighbor group if the ASNs differ.
    pub fn merge_fabric(&mut self, other: BgpRouter) {
        self.neighbor_groups.extend(other.neighbor_groups);
        self.address_families.extend(other.address_families);

        if self.default_ipv4_unicast.is_none() {
            self.default_ipv4_unicast = other.default_ipv4_unicast;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Vrf {
    pub vni: Option<u32>,
    #[serde(default)]
    pub ip_routes: Vec<IpRoute>,
    #[serde(default)]
    pub custom_frr_config: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BgpRouter {
    pub asn: u32,
    pub router_id: Ipv4Addr,
    #[serde(default)]
    pub coalesce_time: Option<u32>,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub default_ipv4_unicast: Option<bool>,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub hard_administrative_reset: Option<bool>,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub graceful_restart_notification: Option<bool>,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub disable_ebgp_connected_route_check: Option<bool>,
    #[serde(default, deserialize_with = "proxmox_serde::perl::deserialize_bool")]
    pub bestpath_as_path_multipath_relax: Option<bool>,
    #[serde(default)]
    pub neighbor_groups: Vec<NeighborGroup>,
    #[serde(default)]
    pub address_families: AddressFamilies,
    #[serde(default)]
    pub custom_frr_config: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommunityListName(String);

impl Display for CommunityListName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl CommunityListName {
    pub fn new(name: String) -> Self {
        Self(name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExtCommunityRouteTarget {
    asn: u16,
    value: u32,
}

impl std::str::FromStr for ExtCommunityRouteTarget {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some((asn, value)) = value.split_once(':') {
            return Ok(Self {
                asn: asn.parse()?,
                value: value.parse()?,
            });
        }

        anyhow::bail!("can not parse route target: {value}")
    }
}

impl Display for ExtCommunityRouteTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.asn, self.value)
    }
}

proxmox_serde::forward_serialize_to_display!(ExtCommunityRouteTarget);
proxmox_serde::forward_deserialize_to_from_str!(ExtCommunityRouteTarget);

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum StandardExtCommunityListMatch {
    #[serde(rename = "rt")]
    RouteTarget(ExtCommunityRouteTarget),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExpandedExtCommunityListEntry {
    pub action: AccessAction,
    pub match_entry: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StandardExtCommunityListEntry {
    pub action: AccessAction,
    pub match_entry: StandardExtCommunityListMatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", content = "entries", rename_all = "kebab-case")]
pub enum ExtCommunityList {
    Standard(Vec<StandardExtCommunityListEntry>),
    Expanded(Vec<ExpandedExtCommunityListEntry>),
}

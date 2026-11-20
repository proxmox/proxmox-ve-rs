use std::{
    collections::{BTreeMap, HashMap},
    convert::Infallible,
    error::Error,
    fmt::Display,
    net::IpAddr,
    str::FromStr,
};

use proxmox_network_types::ip_address::{Cidr, IpRange, IpRangeError};
use proxmox_schema::{ApiType, ObjectSchema, StringSchema, property_string::PropertyString};
use serde::Deserialize;

use crate::{
    common::Allowlist,
    firewall::types::{
        Ipset,
        ipset::{IpsetEntry, IpsetName, IpsetScope},
    },
    sdn::{SdnNameError, SubnetName, VnetName, ZoneName, conntrack::VrfCtZone},
};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SdnConfigError {
    ZoneNotFound,
    VnetNotFound,
    MismatchedCidrGateway,
    MismatchedSubnetZone,
    NameError(SdnNameError),
    InvalidDhcpRange(IpRangeError),
    DuplicateVnetName,
}

impl Error for SdnConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SdnConfigError::NameError(e) => Some(e),
            SdnConfigError::InvalidDhcpRange(e) => Some(e),
            _ => None,
        }
    }
}

impl Display for SdnConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdnConfigError::NameError(err) => write!(f, "invalid name: {err}"),
            SdnConfigError::InvalidDhcpRange(err) => write!(f, "invalid dhcp range: {err}"),
            SdnConfigError::ZoneNotFound => write!(f, "zone not found"),
            SdnConfigError::VnetNotFound => write!(f, "vnet not found"),
            SdnConfigError::MismatchedCidrGateway => {
                write!(f, "mismatched ip address family for gateway and CIDR")
            }
            SdnConfigError::DuplicateVnetName => write!(f, "vnet name occurs in multiple zones"),
            SdnConfigError::MismatchedSubnetZone => {
                write!(f, "subnet zone does not match actual zone")
            }
        }
    }
}

/// The type of an SDN zone.
///
/// Zone types that are not known to this version, e.g. ones added by a newer pve-network, are
/// represented by [`ZoneType::Unknown`], so that they do not prevent reading the configuration.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ZoneType {
    Simple,
    Vlan,
    Qinq,
    Vxlan,
    Evpn,
    Unknown(String),
}

proxmox_serde::forward_deserialize_to_from_str!(ZoneType);
proxmox_serde::forward_serialize_to_display!(ZoneType);

impl FromStr for ZoneType {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "simple" => Ok(ZoneType::Simple),
            "vlan" => Ok(ZoneType::Vlan),
            "qinq" => Ok(ZoneType::Qinq),
            "vxlan" => Ok(ZoneType::Vxlan),
            "evpn" => Ok(ZoneType::Evpn),
            _ => Ok(ZoneType::Unknown(s.to_string())),
        }
    }
}

impl Display for ZoneType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ZoneType::Simple => "simple",
            ZoneType::Vlan => "vlan",
            ZoneType::Qinq => "qinq",
            ZoneType::Vxlan => "vxlan",
            ZoneType::Evpn => "evpn",
            ZoneType::Unknown(ty) => ty,
        })
    }
}

/// The type of the DHCP server of an SDN zone.
///
/// Like [`ZoneType`], types that are not known to this version are represented by
/// [`DhcpType::Unknown`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DhcpType {
    Dnsmasq,
    Unknown(String),
}
proxmox_serde::forward_deserialize_to_from_str!(DhcpType);
proxmox_serde::forward_serialize_to_display!(DhcpType);

impl FromStr for DhcpType {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dnsmasq" => Ok(DhcpType::Dnsmasq),
            _ => Ok(DhcpType::Unknown(s.to_string())),
        }
    }
}

impl Display for DhcpType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DhcpType::Dnsmasq => "dnsmasq",
            DhcpType::Unknown(ty) => ty,
        })
    }
}

/// Struct for deserializing a zone entry of the SDN running config
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ZoneRunningConfig {
    #[serde(rename = "type")]
    ty: ZoneType,
    dhcp: Option<DhcpType>,
    #[serde(
        default,
        rename = "ct-zone",
        deserialize_with = "proxmox_serde::perl::deserialize_u16"
    )]
    ct_zone: Option<u16>,
    /// pve-network stores the nodes of a zone as an object keyed by the node names
    #[serde(default)]
    nodes: Option<BTreeMap<String, PerlBool>>,
}

/// A boolean as stored by perl, which can also be a number or a string.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct PerlBool(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_bool")] bool);

/// Struct for deserializing the zones of the SDN running config
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
pub struct ZonesRunningConfig {
    ids: HashMap<ZoneName, ZoneRunningConfig>,
}

/// Represents the dhcp-range property string used in the SDN configuration
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DhcpRange {
    #[serde(rename = "start-address")]
    start: IpAddr,
    #[serde(rename = "end-address")]
    end: IpAddr,
}

impl ApiType for DhcpRange {
    const API_SCHEMA: proxmox_schema::Schema = ObjectSchema::new(
        "DHCP range",
        &[
            (
                "end-address",
                false,
                &StringSchema::new("end address of DHCP range").schema(),
            ),
            (
                "start-address",
                false,
                &StringSchema::new("start address of DHCP range").schema(),
            ),
        ],
    )
    // ignore properties added by a newer pve-network instead of failing to parse the range
    .additional_properties(true)
    .schema();
}

impl TryFrom<DhcpRange> for IpRange {
    type Error = IpRangeError;

    fn try_from(value: DhcpRange) -> Result<Self, Self::Error> {
        IpRange::new(value.start, value.end)
    }
}

/// Struct for deserializing a subnet entry of the SDN running config
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubnetRunningConfig {
    vnet: VnetName,
    gateway: Option<IpAddr>,
    snat: Option<u8>,
    #[serde(rename = "dhcp-range")]
    dhcp_range: Option<Vec<PropertyString<DhcpRange>>>,
}

/// Struct for deserializing the subnets of the SDN running config
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
pub struct SubnetsRunningConfig {
    ids: HashMap<SubnetName, SubnetRunningConfig>,
}

/// Struct for deserializing a vnet entry of the SDN running config
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VnetRunningConfig {
    tag: Option<u32>,
    zone: ZoneName,
}

/// struct for deserializing the vnets of the SDN running config
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
pub struct VnetsRunningConfig {
    ids: HashMap<VnetName, VnetRunningConfig>,
}

/// Struct for deserializing the SDN running config
///
/// usually taken from the content of /etc/pve/sdn/.running-config
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Default)]
pub struct RunningConfig {
    zones: Option<ZonesRunningConfig>,
    subnets: Option<SubnetsRunningConfig>,
    vnets: Option<VnetsRunningConfig>,
}

/// A struct containing the configuration for an SDN subnet
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubnetConfig {
    name: SubnetName,
    gateway: Option<IpAddr>,
    snat: bool,
    dhcp_range: Vec<IpRange>,
}

impl SubnetConfig {
    pub fn new(
        name: SubnetName,
        gateway: impl Into<Option<IpAddr>>,
        snat: bool,
        dhcp_range: impl IntoIterator<Item = IpRange>,
    ) -> Result<Self, SdnConfigError> {
        let gateway = gateway.into();

        if let Some(gateway) = gateway {
            if !(gateway.is_ipv4() && name.cidr().is_ipv4()
                || gateway.is_ipv6() && name.cidr().is_ipv6())
            {
                return Err(SdnConfigError::MismatchedCidrGateway);
            }
        }

        Ok(Self {
            name,
            gateway,
            snat,
            dhcp_range: dhcp_range.into_iter().collect(),
        })
    }

    pub fn try_from_running_config(
        name: SubnetName,
        running_config: SubnetRunningConfig,
    ) -> Result<Self, SdnConfigError> {
        let snat = running_config
            .snat
            .map(|snat| snat != 0)
            .unwrap_or_else(|| false);

        let dhcp_range: Vec<IpRange> = match running_config.dhcp_range {
            Some(dhcp_range) => dhcp_range
                .into_iter()
                .map(PropertyString::into_inner)
                .map(IpRange::try_from)
                .collect::<Result<Vec<IpRange>, IpRangeError>>()
                .map_err(SdnConfigError::InvalidDhcpRange)?,
            None => Vec::new(),
        };

        // pve-network accepts an IPv4 gateway outside of the subnet for any /32 subnet, so it can
        // store one for an IPv6 subnet as well. Such a gateway cannot be used, so ignore it instead
        // of rejecting the whole configuration.
        let mut gateway = running_config.gateway;

        if let Some(ignored) = gateway.take_if(|gateway| gateway.is_ipv4() != name.cidr().is_ipv4())
        {
            log::warn!(
                "ignoring gateway {ignored} of subnet {}, its address family differs",
                name.cidr()
            );
        }

        Self::new(name, gateway, snat, dhcp_range)
    }

    pub fn name(&self) -> &SubnetName {
        &self.name
    }

    pub fn gateway(&self) -> Option<&IpAddr> {
        self.gateway.as_ref()
    }

    pub fn snat(&self) -> bool {
        self.snat
    }

    pub fn cidr(&self) -> &Cidr {
        self.name.cidr()
    }

    pub fn dhcp_ranges(&self) -> impl Iterator<Item = &IpRange> + '_ {
        self.dhcp_range.iter()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VnetConfig {
    name: VnetName,
    tag: Option<u32>,
    subnets: BTreeMap<Cidr, SubnetConfig>,
}

impl VnetConfig {
    pub fn new(name: VnetName, tag: Option<u32>) -> Self {
        Self {
            name,
            subnets: BTreeMap::default(),
            tag,
        }
    }

    pub fn from_subnets(
        name: VnetName,
        subnets: impl IntoIterator<Item = SubnetConfig>,
    ) -> Result<Self, SdnConfigError> {
        let mut config = Self::new(name, None);
        config.add_subnets(subnets)?;
        Ok(config)
    }

    pub fn from_subnets_and_tag(
        name: VnetName,
        tag: Option<u32>,
        subnets: impl IntoIterator<Item = SubnetConfig>,
    ) -> Result<Self, SdnConfigError> {
        let mut config = Self::new(name, None);
        config.tag = tag;
        config.add_subnets(subnets)?;
        Ok(config)
    }

    pub fn add_subnets(
        &mut self,
        subnets: impl IntoIterator<Item = SubnetConfig>,
    ) -> Result<(), SdnConfigError> {
        self.subnets
            .extend(subnets.into_iter().map(|subnet| (*subnet.cidr(), subnet)));
        Ok(())
    }

    pub fn add_subnet(
        &mut self,
        subnet: SubnetConfig,
    ) -> Result<Option<SubnetConfig>, SdnConfigError> {
        Ok(self.subnets.insert(*subnet.cidr(), subnet))
    }

    pub fn subnets(&self) -> impl Iterator<Item = &SubnetConfig> + '_ {
        self.subnets.values()
    }

    pub fn subnet(&self, cidr: &Cidr) -> Option<&SubnetConfig> {
        self.subnets.get(cidr)
    }

    pub fn name(&self) -> &VnetName {
        &self.name
    }

    pub fn tag(&self) -> &Option<u32> {
        &self.tag
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ZoneConfig {
    name: ZoneName,
    ty: ZoneType,
    vnets: BTreeMap<VnetName, VnetConfig>,
    #[serde(default)]
    ct_zone: Option<VrfCtZone>,
    #[serde(default)]
    nodes: Option<BTreeMap<String, PerlBool>>,
}

impl ZoneConfig {
    pub fn new(name: ZoneName, ty: ZoneType) -> Self {
        Self {
            name,
            ty,
            vnets: BTreeMap::default(),
            ct_zone: None,
            nodes: None,
        }
    }

    pub fn from_vnets(
        name: ZoneName,
        ty: ZoneType,
        vnets: impl IntoIterator<Item = VnetConfig>,
    ) -> Result<Self, SdnConfigError> {
        let mut config = Self::new(name, ty);
        config.add_vnets(vnets)?;
        Ok(config)
    }

    pub fn add_vnets(
        &mut self,
        vnets: impl IntoIterator<Item = VnetConfig>,
    ) -> Result<(), SdnConfigError> {
        self.vnets
            .extend(vnets.into_iter().map(|vnet| (vnet.name.clone(), vnet)));

        Ok(())
    }

    pub fn add_vnet(&mut self, vnet: VnetConfig) -> Result<Option<VnetConfig>, SdnConfigError> {
        Ok(self.vnets.insert(vnet.name.clone(), vnet))
    }

    pub fn vnets(&self) -> impl Iterator<Item = &VnetConfig> + '_ {
        self.vnets.values()
    }

    pub fn vnet(&self, name: &VnetName) -> Option<&VnetConfig> {
        self.vnets.get(name)
    }

    pub fn vnet_mut(&mut self, name: &VnetName) -> Option<&mut VnetConfig> {
        self.vnets.get_mut(name)
    }

    pub fn name(&self) -> &ZoneName {
        &self.name
    }

    pub fn ty(&self) -> &ZoneType {
        &self.ty
    }

    /// The conntrack zone of a zone with a dedicated VRF.
    pub fn ct_zone(&self) -> Option<VrfCtZone> {
        self.ct_zone
    }

    pub fn set_ct_zone(&mut self, ct_zone: Option<VrfCtZone>) {
        self.ct_zone = ct_zone;
    }

    /// Whether the zone exists on `node`. A zone without a `nodes` property exists on all nodes,
    /// one with an empty `nodes` property on none.
    pub fn is_on_node(&self, node: &str) -> bool {
        self.nodes
            .as_ref()
            .is_none_or(|nodes| nodes.get(node).is_some_and(|enabled| enabled.0))
    }
}

/// Representation of a Proxmox VE SDN configuration
///
/// This struct should not be instantiated directly but rather through reading the configuration
/// from a concrete config struct (e.g [`RunningConfig`]) and then converting into this common
/// representation.
///
/// # Invariants
/// * Every Vnet name is unique, even if they are in different zones
/// * Subnets can only be added to a zone if their name contains the same zone they are added to
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct SdnConfig {
    zones: BTreeMap<ZoneName, ZoneConfig>,
}

impl SdnConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_zones(zones: impl IntoIterator<Item = ZoneConfig>) -> Result<Self, SdnConfigError> {
        let mut config = Self::default();
        config.add_zones(zones)?;
        Ok(config)
    }

    /// adds a collection of zones to the configuration, overwriting existing zones with the same
    /// name
    pub fn add_zones(
        &mut self,
        zones: impl IntoIterator<Item = ZoneConfig>,
    ) -> Result<(), SdnConfigError> {
        for zone in zones {
            self.add_zone(zone)?;
        }

        Ok(())
    }

    /// adds a zone to the configuration, returning the old zone config if the zone already existed
    pub fn add_zone(&mut self, mut zone: ZoneConfig) -> Result<Option<ZoneConfig>, SdnConfigError> {
        let vnets = std::mem::take(&mut zone.vnets);

        let zone_name = zone.name().clone();
        let old_zone = self.zones.insert(zone_name.clone(), zone);

        for vnet in vnets.into_values() {
            self.add_vnet(&zone_name, vnet)?;
        }

        Ok(old_zone)
    }

    pub fn add_vnet(
        &mut self,
        zone_name: &ZoneName,
        mut vnet: VnetConfig,
    ) -> Result<Option<VnetConfig>, SdnConfigError> {
        for zone in self.zones.values() {
            if zone.name() != zone_name && zone.vnets.contains_key(vnet.name()) {
                return Err(SdnConfigError::DuplicateVnetName);
            }
        }

        if let Some(zone) = self.zones.get_mut(zone_name) {
            let subnets = std::mem::take(&mut vnet.subnets);

            let vnet_name = vnet.name().clone();
            let old_vnet = zone.vnets.insert(vnet_name.clone(), vnet);

            for subnet in subnets.into_values() {
                self.add_subnet(zone_name, &vnet_name, subnet)?;
            }

            return Ok(old_vnet);
        }

        Err(SdnConfigError::ZoneNotFound)
    }

    pub fn add_subnet(
        &mut self,
        zone_name: &ZoneName,
        vnet_name: &VnetName,
        subnet: SubnetConfig,
    ) -> Result<Option<SubnetConfig>, SdnConfigError> {
        if zone_name != subnet.name().zone() {
            return Err(SdnConfigError::MismatchedSubnetZone);
        }

        if let Some(zone) = self.zones.get_mut(zone_name) {
            if let Some(vnet) = zone.vnets.get_mut(vnet_name) {
                return Ok(vnet.subnets.insert(*subnet.name().cidr(), subnet));
            } else {
                return Err(SdnConfigError::VnetNotFound);
            }
        }

        Err(SdnConfigError::ZoneNotFound)
    }

    pub fn zone(&self, name: &ZoneName) -> Option<&ZoneConfig> {
        self.zones.get(name)
    }

    pub fn zones(&self) -> impl Iterator<Item = &ZoneConfig> + '_ {
        self.zones.values()
    }

    pub fn vnet(&self, name: &VnetName) -> Option<(&ZoneConfig, &VnetConfig)> {
        // we can do this because we enforce the invariant that every VNet name must be unique!
        for zone in self.zones.values() {
            if let Some(vnet) = zone.vnet(name) {
                return Some((zone, vnet));
            }
        }

        None
    }

    pub fn vnets(&self) -> impl Iterator<Item = (&ZoneConfig, &VnetConfig)> + '_ {
        self.zones()
            .flat_map(|zone| zone.vnets().map(move |vnet| (zone, vnet)))
    }

    /// Generates multiple [`Ipset`] for all SDN VNets.
    ///
    /// # Arguments
    /// * `filter` - A [`Allowlist`] of VNet names for which IPsets should get returned
    ///
    /// It generates the following [`Ipset`] for all VNets in the config:
    /// * all: Contains all CIDRs of all subnets in the VNet
    /// * gateway: Contains all gateways of all subnets in the VNet (if any gateway exists)
    /// * no-gateway: Matches all CIDRs of all subnets, except for the gateways (if any gateway
    ///   exists)
    /// * dhcp: Contains all DHCP ranges of all subnets in the VNet (if any dhcp range exists)
    pub fn ipsets<'a>(
        &'a self,
        filter: Option<&'a Allowlist<VnetName>>,
    ) -> impl Iterator<Item = Ipset> + 'a {
        self.zones
            .values()
            .flat_map(|zone| zone.vnets())
            .filter(move |vnet| {
                filter
                    .map(|list| list.is_allowed(&vnet.name))
                    .unwrap_or(true)
            })
            .flat_map(|vnet| {
                let mut ipset_all = Ipset::new(IpsetName::new(
                    IpsetScope::Sdn,
                    format!("{}-all", vnet.name),
                ));
                ipset_all.comment = Some(format!("All subnets of VNet {}", vnet.name));

                let mut ipset_gateway = Ipset::new(IpsetName::new(
                    IpsetScope::Sdn,
                    format!("{}-gateway", vnet.name),
                ));
                ipset_gateway.comment = Some(format!("All gateways of VNet {}", vnet.name));

                let mut ipset_all_wo_gateway = Ipset::new(IpsetName::new(
                    IpsetScope::Sdn,
                    format!("{}-no-gateway", vnet.name),
                ));
                ipset_all_wo_gateway.comment = Some(format!(
                    "All subnets of VNet {}, excluding gateways",
                    vnet.name
                ));

                let mut ipset_dhcp = Ipset::new(IpsetName::new(
                    IpsetScope::Sdn,
                    format!("{}-dhcp", vnet.name),
                ));
                ipset_dhcp.comment = Some(format!("DHCP ranges of VNet {}", vnet.name));

                for subnet in vnet.subnets.values() {
                    ipset_all.push((*subnet.cidr()).into());

                    ipset_all_wo_gateway.push((*subnet.cidr()).into());

                    if let Some(gateway) = subnet.gateway {
                        let gateway_nomatch = IpsetEntry::new(Cidr::from(gateway), true, None);
                        ipset_all_wo_gateway.push(gateway_nomatch);

                        ipset_gateway.push(Cidr::from(gateway).into());
                    }

                    ipset_dhcp.extend(subnet.dhcp_range.iter().cloned().map(IpsetEntry::from));
                }

                [ipset_all, ipset_gateway, ipset_all_wo_gateway, ipset_dhcp]
            })
    }
}

impl TryFrom<RunningConfig> for SdnConfig {
    type Error = SdnConfigError;

    fn try_from(mut value: RunningConfig) -> Result<Self, Self::Error> {
        let mut config = SdnConfig::default();

        if let Some(running_zones) = value.zones.take() {
            config.add_zones(running_zones.ids.into_iter().map(|(name, running_config)| {
                // an invalid conntrack zone must not prevent reading the rest of the configuration
                let ct_zone = running_config.ct_zone.and_then(|ct_zone| {
                    VrfCtZone::try_from(ct_zone)
                        .inspect_err(|err| log::warn!("zone {name}: ignoring ct-zone - {err}"))
                        .ok()
                });

                let mut zone = ZoneConfig::new(name, running_config.ty);
                zone.set_ct_zone(ct_zone);
                zone.nodes = running_config.nodes;
                zone
            }))?;
        }

        if let Some(running_vnets) = value.vnets.take() {
            for (name, running_config) in running_vnets.ids {
                config.add_vnet(
                    &running_config.zone,
                    VnetConfig::new(name, running_config.tag),
                )?;
            }
        }

        if let Some(running_subnets) = value.subnets.take() {
            for (name, running_config) in running_subnets.ids {
                let zone_name = name.zone().clone();
                let vnet_name = running_config.vnet.clone();

                config.add_subnet(
                    &zone_name,
                    &vnet_name,
                    SubnetConfig::try_from_running_config(name, running_config)?,
                )?;
            }
        }

        Ok(config)
    }
}

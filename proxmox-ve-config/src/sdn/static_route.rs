//! Static routes stored as repeatable property strings in simple SDN zones.

use std::collections::BTreeMap;
use std::net::IpAddr;

use anyhow::{Error, bail};
use proxmox_network_types::Cidr;
use proxmox_schema::{api, property_string::PropertyString};
use serde::{Deserialize, Serialize};

use crate::common::valid::Validatable;
use crate::sdn::ZoneName;
use crate::sdn::fabric::section_config::interface::InterfaceName;

#[api(
    properties: {
        via: { type: String, optional: true, format: &proxmox_schema::api_types::IP_FORMAT },
        iface: { type: InterfaceName, optional: true },
        distance: { type: Integer, optional: true, minimum: 1, maximum: 255 },
    },
)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
/// A static route in a simple zone. The destination VRF is determined by the zone.
pub struct StaticRoute {
    /// Destination prefix, including 0.0.0.0/0 or ::/0 for a default route.
    pub prefix: Cidr,
    /// Next-hop gateway address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<IpAddr>,
    /// Outgoing interface, required for IPv6 link-local gateways.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iface: Option<InterfaceName>,
    /// Administrative distance. FRR's default is 1; 255 prevents installation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distance: Option<u8>,
}

impl Validatable for StaticRoute {
    type Error = Error;

    fn validate(&self) -> Result<(), Error> {
        // staticd stores the network address, so a prefix with host bits set would never match
        // the running config and frr-reload would replace the route on every reload
        let canonical = match self.prefix {
            Cidr::Ipv4(cidr) => Cidr::Ipv4(cidr.canonical()),
            Cidr::Ipv6(cidr) => Cidr::Ipv6(cidr.canonical()),
        };
        if self.prefix != canonical {
            bail!(
                "prefix '{}' has host bits set, use '{canonical}' instead",
                self.prefix
            );
        }
        if self.via.is_none() && self.iface.is_none() {
            bail!("a static route requires a gateway (via) or an outgoing interface (iface)");
        }
        if let Some(via) = self.via {
            if via.is_ipv6() != self.prefix.is_ipv6() {
                bail!("gateway and destination prefix must use the same address family");
            }
            if let IpAddr::V6(via) = via {
                if via.is_unicast_link_local() && self.iface.is_none() {
                    bail!("an IPv6 link-local gateway requires an outgoing interface (iface)");
                }
            }
        }
        if let Some(iface) = &self.iface {
            let iface = iface.as_str();
            if ["null0", "blackhole", "reject"].contains(&iface.to_ascii_lowercase().as_str())
                || iface.parse::<IpAddr>().is_ok()
            {
                bail!("'{iface}' is not an outgoing interface");
            }
        }
        if self.distance == Some(0) {
            bail!("administrative distance must be between 1 and 255");
        }
        Ok(())
    }
}

/// The subset of zones.cfg needed to generate static routes, as represented by the perl parser.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ZoneRoutesConfig {
    pub ids: BTreeMap<ZoneName, ZoneRoutes>,
}

/// Routing-related properties of a single SDN zone.
#[derive(Clone, Debug, Deserialize)]
pub struct ZoneRoutes {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(
        default,
        rename = "dedicated-vrf",
        deserialize_with = "proxmox_serde::perl::deserialize_bool"
    )]
    pub dedicated_vrf: bool,
    pub nodes: Option<BTreeMap<String, serde_json::Value>>,
    #[serde(default, deserialize_with = "deserialize_routes_lossy")]
    pub route: Vec<PropertyString<StaticRoute>>,
}

/// Skip routes that do not parse, so that a single invalid route does not fail the whole config.
fn deserialize_routes_lossy<'de, D>(
    deserializer: D,
) -> Result<Vec<PropertyString<StaticRoute>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let routes = Vec::<String>::deserialize(deserializer)?;
    Ok(routes
        .into_iter()
        .filter_map(|route| match route.parse() {
            Ok(parsed) => Some(parsed),
            Err(err) => {
                log::warn!("skipping static route '{route}': {err}");
                None
            }
        })
        .collect())
}

#[cfg(feature = "frr")]
impl ZoneRoutesConfig {
    /// Generate routes only on nodes participating in the zone.
    ///
    /// Invalid routes are skipped with a warning, so that they do not prevent generating the rest
    /// of the FRR configuration.
    pub fn routes_for_node(&self, node: &str) -> Vec<proxmox_frr::ser::IpRoute> {
        let mut routes = Vec::new();
        for (zone, config) in &self.ids {
            if config.route.is_empty() {
                continue;
            }
            if config.ty != "simple" {
                log::warn!("zone '{zone}': static routes are only supported in simple zones");
                continue;
            }
            // without a dedicated VRF, the routes would end up in the routing table of the host
            if !config.dedicated_vrf {
                log::warn!("zone '{zone}': static routes require a dedicated VRF");
                continue;
            }
            if config
                .nodes
                .as_ref()
                .is_some_and(|nodes| !nodes.contains_key(node))
            {
                continue;
            }
            for route in &config.route {
                match zone_route_to_frr(zone, route) {
                    Ok(route) => routes.push(route),
                    Err(err) => {
                        log::warn!("zone '{zone}': skipping route '{}': {err}", route.prefix)
                    }
                }
            }
        }
        routes
    }
}

#[cfg(feature = "frr")]
fn zone_route_to_frr(
    zone: &ZoneName,
    route: &StaticRoute,
) -> Result<proxmox_frr::ser::IpRoute, Error> {
    use proxmox_frr::ser::{InterfaceName as FrrInterfaceName, IpOrInterface, IpRoute};

    let to_frr = |name: &InterfaceName| FrrInterfaceName::try_from(name.as_str());

    route.validate()?;

    let mut frr_route = IpRoute::new(route.prefix, route.via.map(IpOrInterface::Ip));
    frr_route.iface = route.iface.as_ref().map(to_frr).transpose()?;
    frr_route.distance = route.distance;
    frr_route.destination_vrf = Some(FrrInterfaceName::try_from(format!("vrf_{zone}"))?);
    Ok(frr_route)
}

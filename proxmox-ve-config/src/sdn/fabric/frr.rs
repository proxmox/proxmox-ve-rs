use std::net::{IpAddr, Ipv4Addr};

use tracing;

use proxmox_frr::ser::openfabric::{OpenfabricInterface, OpenfabricRouter, OpenfabricRouterName};
use proxmox_frr::ser::ospf::{self, OspfInterface, OspfRouter};
use proxmox_frr::ser::route_map::{AccessListName, RouteMapEntry, RouteMapMatch, RouteMapSet};
use proxmox_frr::ser::{self, FrrConfig, FrrProtocol, FrrWord, Interface, InterfaceName};
use proxmox_network_types::ip_address::Cidr;
use proxmox_sdn_types::net::Net;

use crate::common::valid::Valid;
use crate::sdn::fabric::section_config::protocol::{
    openfabric::{OpenfabricInterfaceProperties, OpenfabricProperties},
    ospf::OspfInterfaceProperties,
};
use crate::sdn::fabric::section_config::{fabric::FabricId, node::NodeId};
use crate::sdn::fabric::{FabricConfig, FabricEntry};

/// Constructs the FRR config from the the passed [`Valid<FabricConfig>`].
///
/// Iterates over the [`FabricConfig`] and constructs all the FRR routers, interfaces, route-maps,
/// etc.
pub fn build_fabric(
    current_node: NodeId,
    config: Valid<FabricConfig>,
    frr_config: &mut FrrConfig,
) -> Result<(), anyhow::Error> {
    let mut routemap_seq = 100;
    let mut current_router_id: Option<Ipv4Addr> = None;
    let mut current_net: Option<Net> = None;

    for (fabric_id, entry) in config.into_inner().iter() {
        match entry {
            FabricEntry::Openfabric(openfabric_entry) => {
                // Get the current node of this fabric, if it doesn't exist, skip this fabric and
                // don't generate any FRR config.
                let Ok(node) = openfabric_entry.node_section(&current_node) else {
                    continue;
                };

                if current_net.is_none() {
                    current_net = match (node.ip(), node.ip6()) {
                        (Some(ip), _) => Some(ip.into()),
                        (_, Some(ip6)) => Some(ip6.into()),
                        (_, _) => None,
                    }
                }

                let net = current_net
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("no IPv4 or IPv6 set for node"))?;
                let (router_name, router_item) = build_openfabric_router(fabric_id, net.clone())?;

                if frr_config
                    .openfabric
                    .router
                    .insert(router_name, router_item)
                    .is_some()
                {
                    tracing::error!("duplicate OpenFabric router");
                }

                // Create dummy interface for fabric
                let (interface, interface_name) = build_openfabric_dummy_interface(
                    fabric_id,
                    node.ip().is_some(),
                    node.ip6().is_some(),
                )?;

                if frr_config
                    .openfabric
                    .interfaces
                    .insert(interface_name, interface)
                    .is_some()
                {
                    tracing::error!(
                        "An interface with the same name as the dummy interface exists"
                    );
                }

                let fabric = openfabric_entry.fabric_section();

                for interface in node.properties().interfaces.iter() {
                    let (interface, interface_name) = build_openfabric_interface(
                        fabric_id,
                        interface,
                        fabric.properties(),
                        node.ip().is_some(),
                        node.ip6().is_some(),
                    )?;

                    if frr_config
                        .openfabric
                        .interfaces
                        .insert(interface_name, interface)
                        .is_some()
                    {
                        tracing::warn!("An interface cannot be in multiple openfabric fabrics");
                    }
                }

                if let Some(ip) = node.ip() {
                    let routemap_name =
                        ser::route_map::RouteMapName::new("pve_openfabric".to_owned());
                    let routemap = frr_config
                        .routemaps
                        .entry(routemap_name.clone())
                        .or_default();

                    let mut routemap_entry = build_source_routemap(ip.into(), routemap_seq);
                    routemap_seq += 10;

                    if let Some(prefix_list_id) = &fabric.properties().route_filter {
                        routemap_entry.matches = vec![RouteMapMatch::IpAddressPrefixList(
                            prefix_list_id.clone().into(),
                        )];
                    } else if let Some(cidr) = fabric.ip_prefix() {
                        let access_list_name =
                            AccessListName::new(format!("pve_openfabric_{fabric_id}_ips"));

                        let rule = ser::route_map::AccessListRule {
                            action: ser::route_map::AccessAction::Permit,
                            network: Cidr::from(cidr),
                            is_ipv6: false,
                            seq: None,
                        };

                        frr_config
                            .access_lists
                            .insert(access_list_name.clone(), vec![rule]);

                        routemap_entry.matches =
                            vec![RouteMapMatch::IpAddressAccessList(access_list_name)];
                    }

                    routemap.push(routemap_entry);

                    let protocol_routemap = frr_config
                        .protocol_routemaps
                        .entry(FrrProtocol::Openfabric)
                        .or_default();

                    protocol_routemap.v4 = Some(routemap_name)
                }

                if let Some(ip) = node.ip6() {
                    let routemap_name =
                        ser::route_map::RouteMapName::new("pve_openfabric6".to_owned());
                    let routemap = frr_config
                        .routemaps
                        .entry(routemap_name.clone())
                        .or_default();

                    let mut routemap_entry = build_source_routemap(ip.into(), routemap_seq);
                    routemap_seq += 10;

                    if let Some(prefix_list_id) = &fabric.properties().route_filter {
                        routemap_entry.matches = vec![RouteMapMatch::Ip6AddressPrefixList(
                            prefix_list_id.clone().into(),
                        )];
                    } else if let Some(cidr) = fabric.ip6_prefix() {
                        let access_list_name =
                            AccessListName::new(format!("pve_openfabric_{fabric_id}_ip6s"));

                        let rule = ser::route_map::AccessListRule {
                            action: ser::route_map::AccessAction::Permit,
                            network: Cidr::from(cidr),
                            is_ipv6: true,
                            seq: None,
                        };

                        frr_config
                            .access_lists
                            .insert(access_list_name.clone(), vec![rule]);

                        routemap_entry.matches =
                            vec![RouteMapMatch::Ip6AddressAccessList(access_list_name)];
                    }

                    routemap.push(routemap_entry);

                    let protocol_routemap = frr_config
                        .protocol_routemaps
                        .entry(FrrProtocol::Openfabric)
                        .or_default();

                    protocol_routemap.v6 = Some(routemap_name)
                }
            }
            FabricEntry::Ospf(ospf_entry) => {
                let Ok(node) = ospf_entry.node_section(&current_node) else {
                    continue;
                };

                let router_id = current_router_id
                    .get_or_insert(node.ip().expect("node must have an ipv4 address"));

                let fabric = ospf_entry.fabric_section();

                let frr_word_area = ser::FrrWord::new(fabric.properties().area.to_string())?;
                let frr_area = ser::ospf::Area::new(frr_word_area)?;

                if frr_config.ospf.router.is_none() {
                    frr_config.ospf.router = Some(build_ospf_router(*router_id)?);
                }

                // Add dummy interface
                let (interface, interface_name) =
                    build_ospf_dummy_interface(fabric_id, frr_area.clone())?;

                if frr_config
                    .ospf
                    .interfaces
                    .insert(interface_name, interface)
                    .is_some()
                {
                    tracing::error!(
                        "An interface with the same name as the dummy interface exists"
                    );
                }

                for interface in node.properties().interfaces.iter() {
                    let (interface, interface_name) =
                        build_ospf_interface(frr_area.clone(), interface)?;

                    if frr_config
                        .ospf
                        .interfaces
                        .insert(interface_name, interface)
                        .is_some()
                    {
                        tracing::warn!("An interface cannot be in multiple ospf fabrics");
                    }
                }

                let routemap_name = ser::route_map::RouteMapName::new("pve_ospf".to_owned());
                let routemap = frr_config
                    .routemaps
                    .entry(routemap_name.clone())
                    .or_default();

                let source_ip = node
                    .ip()
                    .ok_or_else(|| anyhow::anyhow!("node must have an ipv4 address"))?;

                let mut routemap_entry = build_source_routemap(source_ip.into(), routemap_seq);
                routemap_seq += 10;

                if let Some(prefix_list_id) = &fabric.properties().route_filter {
                    routemap_entry.matches = vec![RouteMapMatch::IpAddressPrefixList(
                        prefix_list_id.clone().into(),
                    )];
                } else if let Some(ipv4cidr) = fabric.ip_prefix() {
                    let access_list_name = AccessListName::new(format!("pve_ospf_{fabric_id}_ips"));

                    let rule = ser::route_map::AccessListRule {
                        action: ser::route_map::AccessAction::Permit,
                        network: Cidr::from(ipv4cidr),
                        is_ipv6: false,
                        seq: None,
                    };

                    frr_config
                        .access_lists
                        .insert(access_list_name.clone(), vec![rule]);

                    routemap_entry.matches =
                        vec![RouteMapMatch::IpAddressAccessList(access_list_name)];
                }

                routemap.push(routemap_entry);

                let protocol_routemap = frr_config
                    .protocol_routemaps
                    .entry(FrrProtocol::Ospf)
                    .or_default();

                protocol_routemap.v4 = Some(routemap_name);
            }
        }
    }

    Ok(())
}

/// Helper that builds a OSPF router with a the router_id.
fn build_ospf_router(router_id: Ipv4Addr) -> Result<OspfRouter, anyhow::Error> {
    Ok(ser::ospf::OspfRouter { router_id })
}

/// Helper that builds a OpenFabric router from a fabric_id and a [`Net`].
fn build_openfabric_router(
    fabric_id: &FabricId,
    net: Net,
) -> Result<(OpenfabricRouterName, OpenfabricRouter), anyhow::Error> {
    let router_item = ser::openfabric::OpenfabricRouter { net };
    let frr_word_id = FrrWord::new(fabric_id.to_string())?;
    let router_name = frr_word_id.into();
    Ok((router_name, router_item))
}

/// Helper that builds a OSPF interface from an [`ospf::Area`] and the [`OspfInterfaceProperties`].
fn build_ospf_interface(
    area: ser::ospf::Area,
    interface: &OspfInterfaceProperties,
) -> Result<(Interface<OspfInterface>, InterfaceName), anyhow::Error> {
    let frr_interface = ser::ospf::OspfInterface {
        area,
        // Interfaces are always non-passive
        passive: None,
        network_type: if interface.ip.is_some() {
            None
        } else {
            Some(ser::ospf::NetworkType::PointToPoint)
        },
    };

    let interface_name = interface.name.as_ref().try_into()?;
    Ok((frr_interface.into(), interface_name))
}

/// Helper that builds the OSPF dummy interface using the [`FabricId`] and the [`ospf::Area`].
fn build_ospf_dummy_interface(
    fabric_id: &FabricId,
    area: ospf::Area,
) -> Result<(Interface<OspfInterface>, InterfaceName), anyhow::Error> {
    let frr_interface = ser::ospf::OspfInterface {
        area,
        passive: Some(true),
        network_type: None,
    };
    let interface_name = format!("dummy_{}", fabric_id).try_into()?;
    Ok((frr_interface.into(), interface_name))
}

/// Helper that builds the OpenFabric interface.
///
/// Takes the [`FabricId`], [`OpenfabricInterfaceProperties`], [`OpenfabricProperties`] and flags for
/// ipv4 and ipv6.
fn build_openfabric_interface(
    fabric_id: &FabricId,
    interface: &OpenfabricInterfaceProperties,
    fabric_config: &OpenfabricProperties,
    is_ipv4: bool,
    is_ipv6: bool,
) -> Result<(Interface<OpenfabricInterface>, InterfaceName), anyhow::Error> {
    let frr_word = FrrWord::new(fabric_id.to_string())?;
    let mut frr_interface = ser::openfabric::OpenfabricInterface {
        fabric_id: frr_word.into(),
        // Every interface is not passive by default
        passive: None,
        // Get properties from fabric
        hello_interval: fabric_config.hello_interval,
        csnp_interval: fabric_config.csnp_interval,
        hello_multiplier: interface.hello_multiplier,
        is_ipv4,
        is_ipv6,
    };
    // If no specific hello_interval is set, get default one from fabric
    // config
    if frr_interface.hello_interval.is_none() {
        frr_interface.hello_interval = fabric_config.hello_interval;
    }
    let interface_name = interface.name.as_str().try_into()?;
    Ok((frr_interface.into(), interface_name))
}

/// Helper that builds a OpenFabric interface using a [`FabricId`] and ipv4/6 flags.
fn build_openfabric_dummy_interface(
    fabric_id: &FabricId,
    is_ipv4: bool,
    is_ipv6: bool,
) -> Result<(Interface<OpenfabricInterface>, InterfaceName), anyhow::Error> {
    let frr_word = FrrWord::new(fabric_id.to_string())?;
    let frr_interface = ser::openfabric::OpenfabricInterface {
        fabric_id: frr_word.into(),
        passive: Some(true),
        is_ipv4,
        is_ipv6,
        hello_interval: None,
        csnp_interval: None,
        hello_multiplier: None,
    };
    let interface_name = format!("dummy_{}", fabric_id).try_into()?;
    Ok((frr_interface.into(), interface_name))
}

/// Helper that builds a RouteMap for the OpenFabric protocol.
fn build_source_routemap(router_ip: IpAddr, seq: u16) -> RouteMapEntry {
    RouteMapEntry {
        seq,
        action: ser::route_map::AccessAction::Permit,
        matches: Vec::new(),
        sets: vec![RouteMapSet::Src(router_ip)],
        custom_frr_config: Vec::new(),
        call: None,
        exit_action: None,
    }
}

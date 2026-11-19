#![cfg(feature = "frr")]
use std::net::Ipv4Addr;
use std::str::FromStr;

use proxmox_frr::ser::bgp::{AddressFamilies, BgpRouter, CommonAddressFamilyOptions, L2vpnEvpnAF};
use proxmox_frr::ser::route_map::{AccessAction, RouteMapEntry, RouteMapName};
use proxmox_frr::ser::{
    FrrConfig, FrrProtocol, FrrWord, IpProtocolRouteMap, VrfName, serializer::dump,
};
use proxmox_section_config::typed::ApiSectionDataEntry;
use proxmox_ve_config::sdn::{
    fabric::{FabricConfig, frr::build_fabric, section_config::node::NodeId},
    prefix_list::{PrefixList, frr::build_frr_prefix_lists},
    route_map::{RouteMap, frr::build_frr_route_maps},
};

mod helper;

/*
 * Use the macros `helper::get_section_config!()` to get the section config as a string. This uses
 * the function name and checks for "/resources/cfg/{function-name}/fabrics.cfg" files.
 * With the `helper::reference_name!("<hostname>")` macro you can get the snapshot file of the
 * function for this specific hostname.
 */

#[test]
fn openfabric_default() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let mut frr_config = FrrConfig::default();
    build_fabric(
        NodeId::from_str("pve").expect("invalid nodeid"),
        config.clone(),
        &mut frr_config,
    )
    .unwrap();

    let mut output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);

    frr_config = FrrConfig::default();
    build_fabric(
        NodeId::from_str("pve1").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve1"), output);
}

#[test]
fn ospf_default() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_fabric(
        NodeId::from_str("pve").expect("invalid nodeid"),
        config.clone(),
        &mut frr_config,
    )
    .unwrap();

    let mut output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);

    frr_config = FrrConfig::default();
    build_fabric(
        NodeId::from_str("pve1").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve1"), output);
}

#[test]
fn openfabric_verification_fail() {
    let result = FabricConfig::parse_section_config(helper::get_fabrics_config!());
    assert!(result.is_err());
}

#[test]
fn ospf_verification_fail() {
    let result = FabricConfig::parse_section_config(helper::get_fabrics_config!());
    assert!(result.is_err());
}

#[test]
fn openfabric_loopback_prefix_fail() {
    let result = FabricConfig::parse_section_config(helper::get_fabrics_config!());
    assert!(result.is_err());
}

#[test]
fn ospf_loopback_prefix_fail() {
    let result = FabricConfig::parse_section_config(helper::get_fabrics_config!());
    assert!(result.is_err());
}

#[test]
fn openfabric_multi_fabric() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_fabric(
        NodeId::from_str("pve1").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve1"), output);
}

#[test]
fn ospf_multi_fabric() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_fabric(
        NodeId::from_str("pve1").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();
    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve1"), output);
}

#[test]
fn openfabric_dualstack() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_fabric(
        NodeId::from_str("pve").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);
}

#[test]
fn openfabric_ipv6_only() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_fabric(
        NodeId::from_str("pve").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);
}

#[test]
fn vrf_prefix_overlap_is_scoped_by_zone() {
    let raw = r#"
ospf_fabric: first
        area 0
        ip_prefix 10.0.0.0/24
        zone zoneone

ospf_fabric: second
        area 1
        ip_prefix 10.0.0.0/24
        zone zonetwo

ospf_node: first_pve
        interfaces name=eth0
        ip 10.0.0.1

ospf_node: second_pve
        interfaces name=eth1
        ip 10.0.0.1
"#;

    assert!(FabricConfig::parse_section_config(raw).is_ok());
    assert!(
        FabricConfig::parse_section_config(&raw.replace("zone zonetwo", "zone zoneone")).is_err()
    );
}

#[test]
fn protocol_routemaps_are_scoped_by_vrf() {
    let raw = r#"
ospf_fabric: ospf
        area 0
        ip_prefix 10.0.0.0/24
        zone zoneone

ospf_node: ospf_pve
        interfaces name=eth0
        ip 10.0.0.1

bgp_fabric: bgp
        bfd 0
        ip_prefix 10.0.1.0/24
        zone zonetwo

bgp_node: bgp_pve
        asn 65001
        interfaces name=eth1
        ip 10.0.1.1
        role internal
"#;
    let config = FabricConfig::parse_section_config(raw).unwrap();
    let mut frr_config = FrrConfig::default();
    let correct_src = RouteMapName::new("correct_src").unwrap();
    let correct_src_entry = RouteMapEntry {
        seq: 1,
        action: AccessAction::Permit,
        matches: Vec::new(),
        sets: Vec::new(),
        custom_frr_config: Vec::new(),
        call: None,
        exit_action: None,
    };
    frr_config
        .routemaps
        .insert(correct_src.clone(), vec![correct_src_entry.clone()]);
    frr_config.protocol_routemaps.insert(
        FrrProtocol::Bgp,
        IpProtocolRouteMap {
            v4: Some(correct_src.clone()),
            v6: None,
        },
    );

    build_fabric(NodeId::from_str("pve").unwrap(), config, &mut frr_config).unwrap();

    assert_eq!(frr_config.routemaps[&correct_src], vec![correct_src_entry]);

    let ospf_routemap = &frr_config.vrf_protocol_routemaps
        [&VrfName::Custom(FrrWord::new("vrf_zoneone").unwrap())][&FrrProtocol::Ospf];
    assert_eq!(
        ospf_routemap.v4.as_ref().unwrap(),
        &RouteMapName::new("pve_ospf_vrf_zoneone").unwrap()
    );
    let bgp_routemap = &frr_config.vrf_protocol_routemaps
        [&VrfName::Custom(FrrWord::new("vrf_zonetwo").unwrap())][&FrrProtocol::Bgp];
    assert_eq!(
        bgp_routemap.v4.as_ref().unwrap(),
        &RouteMapName::new("pve_bgp_vrf_zonetwo").unwrap()
    );
    assert!(
        !frr_config
            .protocol_routemaps
            .contains_key(&FrrProtocol::Ospf)
    );
    assert_eq!(
        frr_config.protocol_routemaps[&FrrProtocol::Bgp].v4,
        Some(correct_src)
    );
}

#[test]
fn ospf_router_id_is_selected_per_vrf() {
    let raw = r#"
ospf_fabric: red
        area 0
        ip_prefix 10.0.0.0/24
        zone red

ospf_node: red_pve
        interfaces name=eth0
        ip 10.0.0.1

ospf_fabric: blue
        area 0
        ip_prefix 10.0.0.0/24
        zone blue

ospf_node: blue_pve
        interfaces name=eth1
        ip 10.0.0.2

ospf_node: blue_pve2
        interfaces name=eth1
        ip 10.0.0.1
"#;
    let config = FabricConfig::parse_section_config(raw).unwrap();
    let mut frr_config = FrrConfig::default();

    build_fabric(NodeId::from_str("pve").unwrap(), config, &mut frr_config).unwrap();

    let router_id = |vrf: &str| {
        frr_config.ospf.vrf_router[&VrfName::Custom(FrrWord::new(vrf).unwrap())].router_id
    };
    assert_eq!(router_id("vrf_red"), Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(router_id("vrf_blue"), Ipv4Addr::new(10, 0, 0, 2));
}

#[test]
fn vrf() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let route_maps =
        RouteMap::parse_section_config("route-maps.cfg", helper::get_route_maps_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_frr_route_maps(
        route_maps
            .into_iter()
            .map(|(_, route_map_entry)| route_map_entry),
        &mut frr_config,
    )
    .unwrap();
    build_fabric(
        NodeId::from_str("pve").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);
}

/// Fabrics in the default VRF and in a zone VRF on the same node.
#[test]
fn vrf_default() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_fabric(
        NodeId::from_str("pve").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);
}

/// OSPF fabrics sharing the router of the default VRF and of a zone VRF, with redistributions of
/// the same source.
#[test]
fn ospf_shared_redistribute() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_fabric(
        NodeId::from_str("pve").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();
    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);
}

/// Redistributions of OSPF and BGP fabrics in zone VRFs.
#[test]
fn vrf_redistribute() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let route_maps =
        RouteMap::parse_section_config("route-maps.cfg", helper::get_route_maps_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_frr_route_maps(
        route_maps
            .into_iter()
            .map(|(_, route_map_entry)| route_map_entry),
        &mut frr_config,
    )
    .unwrap();
    build_fabric(
        NodeId::from_str("pve").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);
}

/// Route filters of OSPF and BGP fabrics in zone VRFs.
#[test]
fn vrf_route_filter() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let prefix_lists =
        PrefixList::parse_section_config("prefix-lists.cfg", helper::get_prefix_lists_config!())
            .unwrap();
    let mut frr_config = FrrConfig::default();

    build_frr_prefix_lists(
        prefix_lists.into_iter().map(|(_, prefix_list)| prefix_list),
        &mut frr_config,
    )
    .unwrap();
    build_fabric(
        NodeId::from_str("pve").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);
}

/// IPv6-only and dual-stack BGP fabrics in zone VRFs.
#[test]
fn vrf_ipv6() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let route_maps =
        RouteMap::parse_section_config("route-maps.cfg", helper::get_route_maps_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_frr_route_maps(
        route_maps
            .into_iter()
            .map(|(_, route_map_entry)| route_map_entry),
        &mut frr_config,
    )
    .unwrap();
    build_fabric(
        NodeId::from_str("pve").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);
}

#[test]
fn bgp_default() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_fabric(
        NodeId::from_string("pve".to_owned()).expect("invalid nodeid"),
        config.clone(),
        &mut frr_config,
    )
    .unwrap();

    let mut output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);

    frr_config = FrrConfig::default();
    build_fabric(
        NodeId::from_string("pve1".to_owned()).expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve1"), output);
}

#[test]
fn bgp_ipv6_only() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();
    let mut frr_config = FrrConfig::default();

    build_fabric(
        NodeId::from_string("pve".to_owned()).expect("invalid nodeid"),
        config.clone(),
        &mut frr_config,
    )
    .unwrap();

    let mut output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);

    frr_config = FrrConfig::default();
    build_fabric(
        NodeId::from_string("pve1".to_owned()).expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve1"), output);
}

/// Test that build_fabric merges into an existing EVPN router and sets local-as
/// when the ASNs differ.
#[test]
fn bgp_merge_with_evpn() {
    let raw = std::fs::read_to_string("tests/fabric/cfg/bgp_default/fabrics.cfg")
        .expect("cannot find config file");
    let config = FabricConfig::parse_section_config(&raw).unwrap();

    // Pre-populate with an EVPN-like router using a different ASN
    let mut frr_config = FrrConfig::default();
    let evpn_router = BgpRouter {
        asn: 65000,
        router_id: Ipv4Addr::new(10, 10, 10, 1),
        coalesce_time: Some(1000),
        default_ipv4_unicast: Some(false),
        hard_administrative_reset: None,
        graceful_restart_notification: None,
        disable_ebgp_connected_route_check: None,
        bestpath_as_path_multipath_relax: None,
        neighbor_groups: Vec::new(),
        address_families: AddressFamilies {
            ipv4_unicast: None,
            ipv6_unicast: None,
            l2vpn_evpn: Some(L2vpnEvpnAF {
                common_options: CommonAddressFamilyOptions {
                    import_vrf: Vec::new(),
                    neighbors: Vec::new(),
                    custom_frr_config: Vec::new(),
                },
                advertise_all_vni: Some(true),
                advertise_default_gw: None,
                default_originate: Vec::new(),
                advertise_ipv4_unicast: None,
                advertise_ipv6_unicast: None,
                autort_as: None,
                route_targets: None,
            }),
        },
        custom_frr_config: Vec::new(),
    };
    frr_config
        .bgp
        .vrf_router
        .insert(VrfName::Default, evpn_router);

    build_fabric(
        NodeId::from_str("pve").expect("invalid nodeid"),
        config,
        &mut frr_config,
    )
    .unwrap();

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);
}

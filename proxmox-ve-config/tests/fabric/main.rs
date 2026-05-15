#![cfg(feature = "frr")]
use std::net::Ipv4Addr;
use std::str::FromStr;

use proxmox_frr::ser::bgp::{AddressFamilies, BgpRouter, CommonAddressFamilyOptions, L2vpnEvpnAF};
use proxmox_frr::ser::{serializer::dump, FrrConfig, VrfName};
use proxmox_ve_config::sdn::fabric::{
    frr::build_fabric, section_config::node::NodeId, FabricConfig,
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

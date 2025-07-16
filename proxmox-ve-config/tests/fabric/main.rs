#![cfg(feature = "frr")]
use proxmox_frr::serializer::dump;
use proxmox_ve_config::sdn::{
    fabric::{section_config::node::NodeId, FabricConfig},
    frr::FrrConfigBuilder,
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

    let mut frr_config = FrrConfigBuilder::default()
        .add_fabrics(config.clone())
        .build(NodeId::from_string("pve".to_owned()).expect("invalid nodeid"))
        .expect("error building frr config");

    let mut output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);

    frr_config = FrrConfigBuilder::default()
        .add_fabrics(config.clone())
        .build(NodeId::from_string("pve1".to_owned()).expect("invalid nodeid"))
        .expect("error building frr config");

    output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve1"), output);
}

#[test]
fn ospf_default() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();

    let mut frr_config = FrrConfigBuilder::default()
        .add_fabrics(config.clone())
        .build(NodeId::from_string("pve".to_owned()).expect("invalid nodeid"))
        .expect("error building frr config");

    let mut output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);

    frr_config = FrrConfigBuilder::default()
        .add_fabrics(config)
        .build(NodeId::from_string("pve1".to_owned()).expect("invalid nodeid"))
        .expect("error building frr config");

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

    let frr_config = FrrConfigBuilder::default()
        .add_fabrics(config)
        .build(NodeId::from_string("pve1".to_owned()).expect("invalid nodeid"))
        .expect("error building frr config");

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve1"), output);
}

#[test]
fn ospf_multi_fabric() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();

    let frr_config = FrrConfigBuilder::default()
        .add_fabrics(config)
        .build(NodeId::from_string("pve1".to_owned()).expect("invalid nodeid"))
        .expect("error building frr config");

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve1"), output);
}

#[test]
fn openfabric_dualstack() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();

    let frr_config = FrrConfigBuilder::default()
        .add_fabrics(config)
        .build(NodeId::from_string("pve".to_owned()).expect("invalid nodeid"))
        .expect("error building frr config");

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);
}

#[test]
fn openfabric_ipv6_only() {
    let config = FabricConfig::parse_section_config(helper::get_fabrics_config!()).unwrap();

    let frr_config = FrrConfigBuilder::default()
        .add_fabrics(config)
        .build(NodeId::from_string("pve".to_owned()).expect("invalid nodeid"))
        .expect("error building frr config");

    let output = dump(&frr_config).expect("error dumping stuff");

    insta::assert_snapshot!(helper::reference_name!("pve"), output);
}

#![cfg(feature = "frr")]

use proxmox_ve_config::sdn::prefix_list::{frr::build_frr_prefix_lists, *};

use proxmox_frr::ser::{route_map::PrefixListRule as FrrPrefixListRule, FrrConfig};

use proxmox_frr::ser::route_map::{AccessAction, PrefixListName};
use proxmox_frr::ser::serializer::dump;
use proxmox_network_types::Cidr;
use proxmox_section_config::typed::ApiSectionDataEntry;

#[test]
fn test_build_prefix_list() -> Result<(), anyhow::Error> {
    let section_config = r#"
prefix-list: example-1
  entries action=permit,prefix=192.0.2.0/24
  entries action=permit,prefix=192.0.2.0/24,le=32
  entries action=permit,prefix=192.0.2.0/24,le=32,ge=24,seq=123
  entries action=permit,prefix=192.0.2.0/24,ge=24
  entries action=permit,prefix=192.0.2.0/24,ge=24,le=31

prefix-list: example-3
  entries action=permit,prefix=192.0.2.0/24,seq=333
  entries action=permit,prefix=198.51.100.0/24,seq=222
  entries action=permit,prefix=203.0.113.0/24,seq=111

prefix-list: example-2
  entries action=deny,prefix=192.0.2.0/24,le=25
  entries action=permit,prefix=192.0.2.0/24
"#;

    let config = PrefixList::parse_section_config("prefix-lists.cfg", section_config)?;
    let mut frr_config = FrrConfig::default();

    build_frr_prefix_lists(
        config
            .into_iter()
            .map(|(_, route_map_entry)| route_map_entry),
        &mut frr_config,
    )?;

    assert_eq!(
        dump(&frr_config)?,
        r#"!
ip prefix-list example-1 permit 192.0.2.0/24
ip prefix-list example-1 permit 192.0.2.0/24 le 32
ip prefix-list example-1 seq 123 permit 192.0.2.0/24 le 32 ge 24
ip prefix-list example-1 permit 192.0.2.0/24 ge 24
ip prefix-list example-1 permit 192.0.2.0/24 le 31 ge 24
!
ip prefix-list example-2 deny 192.0.2.0/24 le 25
ip prefix-list example-2 permit 192.0.2.0/24
!
ip prefix-list example-3 seq 333 permit 192.0.2.0/24
ip prefix-list example-3 seq 222 permit 198.51.100.0/24
ip prefix-list example-3 seq 111 permit 203.0.113.0/24
"#
    );

    Ok(())
}

#[test]
fn test_build_prefix_list_overwrite() -> Result<(), anyhow::Error> {
    let section_config = r#"
prefix-list: example-1
  entries action=permit,prefix=192.0.2.0/24
"#;

    let config = PrefixList::parse_section_config("prefix-lists.cfg", section_config)?;

    let example_1_prefix_list = vec![FrrPrefixListRule {
        action: AccessAction::Deny,
        network: Cidr::new_v4([198, 51, 100, 0], 24).unwrap(),
        seq: None,
        le: None,
        ge: None,
        is_ipv6: false,
    }];

    let mut frr_config = FrrConfig::default();

    frr_config.prefix_lists.insert(
        PrefixListName::new("example-1".to_string()),
        example_1_prefix_list.clone(),
    );

    build_frr_prefix_lists(
        config
            .into_iter()
            .map(|(_, route_map_entry)| route_map_entry),
        &mut frr_config,
    )?;

    let new_prefix_list = frr_config
        .prefix_lists
        .get(&PrefixListName::new("example-1".to_string()))
        .expect("'example-1' prefix list exists");

    assert_ne!(&example_1_prefix_list, new_prefix_list);

    let generated_frr_config = dump(&frr_config)?;

    assert_eq!(
        generated_frr_config,
        r#"!
ip prefix-list example-1 permit 192.0.2.0/24
"#
    );

    Ok(())
}

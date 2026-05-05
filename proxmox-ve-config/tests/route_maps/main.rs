#![cfg(feature = "frr")]

use proxmox_ve_config::sdn::route_map::{frr::build_frr_route_maps, *};

use proxmox_frr::ser::{serializer::dump, FrrConfig};
use proxmox_section_config::typed::ApiSectionDataEntry;

#[test]
fn test_build_route_map_order() -> Result<(), anyhow::Error> {
    let section_config = r#"
route-map-entry: another_20
  action deny

route-map-entry: another_50
  action deny

route-map-entry: another_60
  action deny

route-map-entry: another_40
  action deny

route-map-entry: another_30
  action deny
"#;

    let config = RouteMap::parse_section_config("route-maps.cfg", section_config)?;
    let mut frr_config = FrrConfig::default();

    build_frr_route_maps(
        config
            .into_iter()
            .map(|(_, route_map_entry)| route_map_entry),
        &mut frr_config,
    )?;

    assert_eq!(
        dump(&frr_config)?,
        r#"!
route-map another deny 20
exit
!
route-map another deny 30
exit
!
route-map another deny 40
exit
!
route-map another deny 50
exit
!
route-map another deny 60
exit
"#
    );

    Ok(())
}

#[test]
fn test_build_route_map() -> Result<(), anyhow::Error> {
    let section_config = r#"
route-map-entry: another_67
  action deny
  match key=vni,value=313373
  match key=peer,value=some_peergroup

route-map-entry: example_122
  action deny
  match key=route-type,value=es
  match key=vni,value=313373
  match key=ip-address-prefix-list,value=some_prefix_list
  match key=ip-next-hop-prefix-list,value=some_other_prefix_list
  match key=ip-next-hop-address,value=192.0.2.45
  match key=metric,value=8347
  match key=local-preference,value=8347
  match key=peer,value=some_interface
  match key=peer,value=some_peergroup
  set key=ip6-next-hop-peer-address
  set key=ip6-next-hop-prefer-global
  set key=ip6-next-hop,value=2001:DB8::1

route-map-entry: example_123
  action permit
  match key=ip6-address-prefix-list,value=some_prefix_list
  match key=ip6-next-hop-prefix-list,value=some_other_prefix_list
  match key=ip6-next-hop-address,value=2001:DB8:cafe::BeeF
  set key=ip-next-hop-peer-address
  set key=ip-next-hop-unchanged
  set key=ip-next-hop,value=198.51.100.3
  set key=local-preference,value=1234
  set key=tag,value=untagged
  set key=weight,value=20
  set key=metric,value=+rtt
"#;

    let config = RouteMap::parse_section_config("route-maps.cfg", section_config)?;
    let mut frr_config = FrrConfig::default();

    build_frr_route_maps(
        config
            .into_iter()
            .map(|(_, route_map_entry)| route_map_entry),
        &mut frr_config,
    )?;

    assert_eq!(
        dump(&frr_config)?,
        r#"!
route-map another deny 67
 match evpn vni 313373
 match peer some_peergroup
exit
!
route-map example deny 122
 match evpn route-type es
 match evpn vni 313373
 match ip address prefix-list some_prefix_list
 match ip next-hop prefix-list some_other_prefix_list
 match ip next-hop address 192.0.2.45
 match metric 8347
 match local-preference 8347
 match peer some_interface
 match peer some_peergroup
 set ipv6 next-hop peer-address
 set ipv6 next-hop prefer-global
 set ipv6 next-hop global 2001:db8::1
exit
!
route-map example permit 123
 match ipv6 address prefix-list some_prefix_list
 match ipv6 next-hop prefix-list some_other_prefix_list
 match ipv6 next-hop address 2001:db8:cafe::beef
 set ip next-hop peer-address
 set ip next-hop unchanged
 set ip next-hop 198.51.100.3
 set local-preference 1234
 set tag untagged
 set weight 20
 set metric +rtt
exit
"#
    );

    Ok(())
}

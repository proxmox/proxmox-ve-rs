#![cfg(feature = "frr")]

use anyhow::Error;
use proxmox_frr::ser::{FrrConfig, IpRoute, serializer::dump};
use proxmox_schema::property_string::PropertyString;
use proxmox_ve_config::common::valid::Validatable;
use proxmox_ve_config::sdn::fabric::{
    FabricConfig, frr::build_fabric, section_config::node::NodeId,
};
use proxmox_ve_config::sdn::static_route::{StaticRoute, ZoneRoutesConfig};
use serde_json::json;

#[test]
fn simple_zone_routes_to_frr() -> Result<(), Error> {
    // This is the zones.cfg representation in the SDN running configuration. Repeated route
    // properties remain an array, including routes with the same prefix for ECMP and failover.
    let zones: ZoneRoutesConfig = serde_json::from_value(json!({"ids": {
        "isolated": {
            "type": "simple",
            "dedicated-vrf": 1,
            "nodes": {"pve1": 1},
            "route": [
                "prefix=0.0.0.0/0,via=192.0.2.1",
                "prefix=0.0.0.0/0,via=192.0.2.2,distance=1",
                "prefix=0.0.0.0/0,via=192.0.2.3,distance=200",
                "prefix=::/0,via=fe80::1,iface=uplink0",
                "prefix=2001:db8:20::/64,iface=uplink1,distance=10"
            ]
        },
        "shared": {
            "type": "simple",
            "dedicated-vrf": 1,
            "route": [
                "prefix=0.0.0.0/0,via=198.51.100.1,iface=eth0,distance=5",
                "prefix=::/0,via=2001:db8::1",
                "prefix=203.0.113.0/24,iface=ppp0"
            ]
        },
        "disabled": {
            "type": "simple",
            "dedicated-vrf": 1,
            "nodes": {},
            "route": ["prefix=192.0.2.0/24,iface=unused0"]
        },
        "novrf": {
            "type": "simple",
            "route": ["prefix=198.51.100.0/24,via=192.0.2.1"]
        },
        "unused": {"type": "vlan"}
    }}))?;
    let config = FrrConfig {
        ip_routes: zones.routes_for_node("pve1"),
        ..Default::default()
    };
    let output = dump(&config)?;
    insta::assert_snapshot!("simple_zone_routes_pve1", output);

    let config = FrrConfig {
        ip_routes: zones.routes_for_node("pve2"),
        ..Default::default()
    };
    let output = dump(&config)?;
    insta::assert_snapshot!("simple_zone_routes_pve2", output);
    Ok(())
}

#[test]
fn validate_route_properties() {
    for value in [
        "prefix=0.0.0.0/0,via=192.0.2.1",
        "prefix=::/0,via=fe80::1,iface=eth0",
        "prefix=10.0.0.0/8,iface=eth0.100,distance=255",
        "prefix=::/0,via=2001:db8::1",
    ] {
        let route = value.parse::<PropertyString<StaticRoute>>().unwrap();
        route.validate().unwrap();
        let encoded = route.to_property_string().unwrap();
        encoded
            .parse::<PropertyString<StaticRoute>>()
            .unwrap()
            .validate()
            .unwrap();
    }

    for value in [
        "prefix=0.0.0.0/0",
        "via=192.0.2.1",
        "prefix=0.0.0.0/33,via=192.0.2.1",
        "prefix=10.0.0.1/24,via=192.0.2.1",
        "prefix=2001:db8::1/64,via=2001:db8::ffff",
        "prefix=0.0.0.0/0,via=2001:db8::1",
        "prefix=::/0,via=192.0.2.1",
        "prefix=::/0,via=fe80::1",
        "prefix=0.0.0.0/0,iface=",
        "prefix=0.0.0.0/0,iface=interface-too-long",
        "prefix=0.0.0.0/0,iface=eth0 vrf default",
        "prefix=0.0.0.0/0,iface=eth0\nexit",
        "prefix=0.0.0.0/0,iface=blackhole",
        "prefix=0.0.0.0/0,iface=Null0",
        "prefix=0.0.0.0/0,iface=192.0.2.1",
        "prefix=0.0.0.0/0,via=192.0.2.1,distance=0",
        "prefix=0.0.0.0/0,via=192.0.2.1,distance=256",
        "prefix=0.0.0.0/0,via=192.0.2.1,vrf=vrf_other",
        "prefix=0.0.0.0/0,via=192.0.2.1,nexthop-vrf=default",
        "prefix=0.0.0.0/0,via=192.0.2.1,via=192.0.2.2",
    ] {
        let result = value
            .parse::<PropertyString<StaticRoute>>()
            .map_err(Error::from)
            .and_then(|route| route.validate());
        assert!(result.is_err(), "accepted invalid route: {value}");
    }
}

#[test]
fn skip_routes_in_other_zone_types() -> Result<(), Error> {
    for ty in ["vlan", "qinq", "vxlan", "evpn", "faucet"] {
        let zones: ZoneRoutesConfig = serde_json::from_value(json!({"ids": {
            "zone1": {"type": ty, "route": ["prefix=0.0.0.0/0,via=192.0.2.1"]}
        }}))?;
        assert!(zones.routes_for_node("pve1").is_empty());
    }
    Ok(())
}

#[test]
fn skip_invalid_routes() -> Result<(), Error> {
    // Invalid routes must not prevent generating the valid ones, or the rest of the FRR config.
    let zones: ZoneRoutesConfig = serde_json::from_value(json!({"ids": {
        "zone1": {
            "type": "simple",
            "dedicated-vrf": 1,
            "route": [
                "prefix=10.0.0.1/24,via=192.0.2.1",
                "prefix=0.0.0.0/0,via=192.0.2.1",
                "prefix=0.0.0.0/0,via=192.0.2.1,unknown=1",
                "prefix=::/0,via=fe80::1"
            ]
        }
    }}))?;
    let config = FrrConfig {
        ip_routes: zones.routes_for_node("pve1"),
        ..Default::default()
    };
    assert_eq!(config.ip_routes.len(), 1);
    assert!(dump(&config)?.contains("ip route 0.0.0.0/0 192.0.2.1"));
    Ok(())
}

#[test]
fn preserve_legacy_evpn_routes() -> Result<(), Error> {
    // The historical 'vrf' field is actually the outgoing interface, not a destination VRF.
    let route: IpRoute = serde_json::from_value(json!({
        "prefix": "203.0.113.0/24", "via": "10.255.255.2", "vrf": "xvrf_zone1"
    }))?;
    let mut config = FrrConfig::default();
    config.ip_routes.push(route);
    config.ip_routes.push(serde_json::from_value(json!({
        "is_ipv6": 1, "prefix": "2001:db8::/64", "via": "fe80::2", "vrf": "xvrf_zone1"
    }))?);
    assert_eq!(
        serde_json::to_value(&config.ip_routes[0])?["vrf"],
        "xvrf_zone1"
    );
    config.bgp.vrfs.insert(
        "vrf_zone1".try_into()?,
        serde_json::from_value(json!({
            "ip_routes": [{"prefix": "203.0.113.0/24", "via": "null0"}]
        }))?,
    );
    let output = dump(&config)?;
    insta::assert_snapshot!(output);
    Ok(())
}

#[test]
fn vrf_fabrics_with_static_routes() -> Result<(), Error> {
    let fabrics = FabricConfig::parse_section_config(include_str!("cfg/fabrics.cfg"))?;
    let zones: ZoneRoutesConfig = serde_json::from_str(include_str!("cfg/zones.json"))?;
    let mut config = FrrConfig::default();

    // Both fabrics use the same subnet, and both zones route the same IPv4 and IPv6 prefixes.
    // Static routes must be rendered in the VRF of their own zone.
    build_fabric(
        NodeId::from_string("pve1".to_owned())?,
        fabrics,
        &mut config,
    )?;
    config.ip_routes.extend(zones.routes_for_node("pve1"));

    let output = dump(&config)?;
    insta::assert_snapshot!(output);
    Ok(())
}

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use proxmox_network_types::ip_address::{Cidr, IpRange};
use proxmox_network_types::mac_address::MacAddress;

use proxmox_ve_config::sdn::{
    SubnetName, VnetName, ZoneName,
    config::{
        RunningConfig, SdnConfig, SdnConfigError, SubnetConfig, VnetConfig, ZoneConfig, ZoneType,
    },
    ipam::{Ipam, IpamDataVm, IpamEntry, IpamJson},
};

#[test]
fn parse_running_config() {
    let running_config: RunningConfig =
        serde_json::from_str(include_str!("resources/running-config.json")).unwrap();

    let parsed_config = SdnConfig::try_from(running_config).unwrap();

    let sdn_config = SdnConfig::from_zones([ZoneConfig::from_vnets(
        ZoneName::from_str("zone0").unwrap(),
        ZoneType::Simple,
        [
            VnetConfig::from_subnets_and_tag(
                VnetName::from_str("vnet0").unwrap(),
                Some(100),
                [
                    SubnetConfig::new(
                        SubnetName::from_str("zone0-fd80::-64").unwrap(),
                        Some(Ipv6Addr::new(0xFD80, 0, 0, 0, 0, 0, 0, 0x1).into()),
                        true,
                        [IpRange::new_v6(
                            [0xFD80, 0, 0, 0, 0, 0, 0, 0x1000],
                            [0xFD80, 0, 0, 0, 0, 0, 0, 0xFFFF],
                        )
                        .unwrap()],
                    )
                    .unwrap(),
                    SubnetConfig::new(
                        SubnetName::from_str("zone0-10.101.0.0-16").unwrap(),
                        Some(Ipv4Addr::new(10, 101, 1, 1).into()),
                        true,
                        [
                            IpRange::new_v4([10, 101, 98, 100], [10, 101, 98, 200]).unwrap(),
                            IpRange::new_v4([10, 101, 99, 100], [10, 101, 99, 200]).unwrap(),
                        ],
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
            VnetConfig::from_subnets(
                VnetName::from_str("vnet1").unwrap(),
                [SubnetConfig::new(
                    SubnetName::from_str("zone0-10.102.0.0-16").unwrap(),
                    None,
                    false,
                    [],
                )
                .unwrap()],
            )
            .unwrap(),
        ],
    )
    .unwrap()])
    .unwrap();

    assert_eq!(sdn_config, parsed_config);
}

#[test]
fn parse_running_config_from_newer_pve_network() {
    // unknown zone and DHCP types, an unknown property in a DHCP range and an IPv4 gateway for an
    // IPv6 /32 subnet must not prevent reading the configuration
    let running_config: RunningConfig = serde_json::from_value(serde_json::json!({
        "zones": {
            "ids": {
                "zone0": { "type": "faucet", "dhcp": "kea" },
            },
        },
        "vnets": {
            "ids": {
                "vnet0": { "type": "vnet", "zone": "zone0" },
            },
        },
        "subnets": {
            "ids": {
                "zone0-10.0.0.0-24": {
                    "type": "subnet",
                    "vnet": "vnet0",
                    "gateway": "10.0.0.1",
                    "dhcp-range": [
                        "start-address=10.0.0.100,end-address=10.0.0.200,unknown=value",
                    ],
                },
                "zone0-fd00::-32": {
                    "type": "subnet",
                    "vnet": "vnet0",
                    "gateway": "192.0.2.1",
                },
            },
        },
    }))
    .expect("valid running config");

    let sdn_config = SdnConfig::try_from(running_config).expect("valid SDN config");

    let zone = sdn_config
        .zone(&ZoneName::from_str("zone0").unwrap())
        .expect("zone exists");
    assert_eq!(zone.ty(), &ZoneType::Unknown("faucet".to_string()));
    assert_eq!(zone.ty().to_string(), "faucet");

    let vnet = zone
        .vnet(&VnetName::from_str("vnet0").unwrap())
        .expect("vnet exists");

    let subnet_v4 = vnet
        .subnet(&Cidr::from_str("10.0.0.0/24").unwrap())
        .expect("IPv4 subnet exists");
    assert_eq!(
        subnet_v4.gateway(),
        Some(&IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)))
    );
    assert_eq!(
        subnet_v4.dhcp_ranges().collect::<Vec<_>>(),
        [&IpRange::new_v4([10, 0, 0, 100], [10, 0, 0, 200]).unwrap()]
    );

    let subnet_v6 = vnet
        .subnet(&Cidr::from_str("fd00::/32").unwrap())
        .expect("IPv6 subnet exists");
    assert_eq!(subnet_v6.gateway(), None);
}

#[test]
fn sdn_config() {
    let mut sdn_config = SdnConfig::new();

    let zone0_name = ZoneName::new("zone0".to_string()).unwrap();
    let zone1_name = ZoneName::new("zone1".to_string()).unwrap();

    let vnet0_name = VnetName::new("vnet0".to_string()).unwrap();
    let vnet1_name = VnetName::new("vnet1".to_string()).unwrap();

    let zone0 = ZoneConfig::new(zone0_name.clone(), ZoneType::Qinq);
    sdn_config.add_zone(zone0).unwrap();

    let vnet0 = VnetConfig::new(vnet0_name.clone(), None);
    assert_eq!(
        sdn_config.add_vnet(&zone1_name, vnet0.clone()),
        Err(SdnConfigError::ZoneNotFound)
    );

    sdn_config.add_vnet(&zone0_name, vnet0.clone()).unwrap();

    let subnet = SubnetConfig::new(
        SubnetName::new(zone0_name.clone(), Cidr::new_v4([10, 0, 0, 0], 16).unwrap()),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        true,
        [],
    )
    .unwrap();

    assert_eq!(
        sdn_config.add_subnet(&zone0_name, &vnet1_name, subnet.clone()),
        Err(SdnConfigError::VnetNotFound),
    );

    sdn_config
        .add_subnet(&zone0_name, &vnet0_name, subnet)
        .unwrap();

    let zone1 = ZoneConfig::from_vnets(
        zone1_name.clone(),
        ZoneType::Evpn,
        [VnetConfig::from_subnets(
            vnet1_name.clone(),
            [SubnetConfig::new(
                SubnetName::new(
                    zone0_name.clone(),
                    Cidr::new_v4([192, 168, 0, 0], 24).unwrap(),
                ),
                None,
                false,
                [],
            )
            .unwrap()],
        )
        .unwrap()],
    )
    .unwrap();

    assert_eq!(
        sdn_config.add_zones([zone1]),
        Err(SdnConfigError::MismatchedSubnetZone),
    );

    let zone1 = ZoneConfig::new(zone1_name.clone(), ZoneType::Evpn);
    sdn_config.add_zone(zone1).unwrap();

    assert_eq!(
        sdn_config.add_vnet(&zone1_name, vnet0.clone()),
        Err(SdnConfigError::DuplicateVnetName),
    )
}

#[test]
fn parse_ipam() {
    let ipam_json: IpamJson = serde_json::from_str(include_str!("resources/ipam.db")).unwrap();
    let ipam = Ipam::try_from(ipam_json).unwrap();

    let zone_name = ZoneName::new("zone0".to_string()).unwrap();

    assert_eq!(
        Ipam::from_entries([
            IpamEntry::new(
                SubnetName::new(
                    zone_name.clone(),
                    Cidr::new_v6([0xFD80, 0, 0, 0, 0, 0, 0, 0], 64).unwrap()
                ),
                IpamDataVm::new(
                    Ipv6Addr::new(0xFD80, 0, 0, 0, 0, 0, 0, 0x1000),
                    1000,
                    MacAddress::new([0xBC, 0x24, 0x11, 0, 0, 0x01]),
                    "test0".to_string()
                )
                .into()
            )
            .unwrap(),
            IpamEntry::new(
                SubnetName::new(
                    zone_name.clone(),
                    Cidr::new_v4([10, 101, 0, 0], 16).unwrap()
                ),
                IpamDataVm::new(
                    Ipv4Addr::new(10, 101, 99, 101),
                    1000,
                    MacAddress::new([0xBC, 0x24, 0x11, 0, 0, 0x01]),
                    "test0".to_string()
                )
                .into()
            )
            .unwrap(),
        ])
        .unwrap(),
        ipam
    )
}

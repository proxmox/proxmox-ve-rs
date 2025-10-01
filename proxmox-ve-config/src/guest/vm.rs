use std::collections::BTreeMap;
use std::io;
use std::str::FromStr;

use anyhow::{bail, Error};
use serde::Deserialize;

use proxmox_network_types::ip_address::{Ipv4Cidr, Ipv6Cidr};
use proxmox_network_types::mac_address::MacAddress;
use proxmox_schema::property_string::PropertyString;
use proxmox_schema::{ApiType, BooleanSchema, KeyAliasInfo, ObjectSchema, StringSchema};
use proxmox_sortable_macro::sortable;

use crate::firewall::parse::match_digits;

/// All possible models of network devices for both QEMU and LXC guests.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum NetworkDeviceModel {
    VirtIO,
    Veth,
    E1000,
    Vmxnet3,
    RTL8139,
}

proxmox_serde::forward_deserialize_to_from_str!(NetworkDeviceModel);

impl FromStr for NetworkDeviceModel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "virtio" => Ok(NetworkDeviceModel::VirtIO),
            "e1000" => Ok(NetworkDeviceModel::E1000),
            "rtl8139" => Ok(NetworkDeviceModel::RTL8139),
            "vmxnet3" => Ok(NetworkDeviceModel::Vmxnet3),
            "veth" => Ok(NetworkDeviceModel::Veth),
            _ => bail!("Invalid network device model: {s}"),
        }
    }
}

/// Representation of the network device property string of a QEMU guest.
///
/// It currently only cotains properties that are required for the firewall to function, there are
/// still missing properties that can be contained in the schema.
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct QemuNetworkDevice {
    model: NetworkDeviceModel,
    #[serde(rename = "macaddr")]
    mac_address: MacAddress,
    firewall: Option<bool>,
}

impl ApiType for QemuNetworkDevice {
    #[sortable]
    const API_SCHEMA: proxmox_schema::Schema = ObjectSchema::new(
        "QEMU Network Device",
        &sorted!([
            (
                "firewall",
                true,
                &BooleanSchema::new("firewall enabled for this network device").schema(),
            ),
            (
                "macaddr",
                false,
                &StringSchema::new("mac address for this network device").schema(),
            ),
            (
                "model",
                false,
                &StringSchema::new("type of this network device").schema(),
            ),
        ]),
    )
    .additional_properties(true)
    .key_alias_info(KeyAliasInfo::new(
        "model",
        &sorted!(["e1000", "rtl8139", "virtio", "vmxnet3"]),
        "macaddr",
    ))
    .schema();
}

/// Representation of possible values for an LXC guest IPv4 field.
#[derive(Debug, Copy, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum LxcIpv4Addr {
    Ip(Ipv4Cidr),
    Dhcp,
    Manual,
}

proxmox_serde::forward_deserialize_to_from_str!(LxcIpv4Addr);

impl LxcIpv4Addr {
    pub fn cidr(&self) -> Option<Ipv4Cidr> {
        match self {
            LxcIpv4Addr::Ip(ipv4_cidr) => Some(*ipv4_cidr),
            _ => None,
        }
    }
}

impl FromStr for LxcIpv4Addr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "dhcp" => LxcIpv4Addr::Dhcp,
            "manual" => LxcIpv4Addr::Manual,
            _ => LxcIpv4Addr::Ip(s.parse()?),
        })
    }
}

/// Representation of possible values for an LXC guest IPv6 field.
#[derive(Debug, Copy, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum LxcIpv6Addr {
    Ip(Ipv6Cidr),
    Dhcp,
    Auto,
    Manual,
}

proxmox_serde::forward_deserialize_to_from_str!(LxcIpv6Addr);

impl LxcIpv6Addr {
    pub fn cidr(&self) -> Option<Ipv6Cidr> {
        match self {
            LxcIpv6Addr::Ip(ipv6_cidr) => Some(*ipv6_cidr),
            _ => None,
        }
    }
}

impl FromStr for LxcIpv6Addr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "dhcp" => LxcIpv6Addr::Dhcp,
            "manual" => LxcIpv6Addr::Manual,
            "auto" => LxcIpv6Addr::Auto,
            _ => LxcIpv6Addr::Ip(s.parse()?),
        })
    }
}

/// Representation of the network device property string of a LXC guest.
///
/// It currently only cotains properties that are required for the firewall to function, there are
/// still missing properties that can be contained in the schema.
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct LxcNetworkDevice {
    #[serde(rename = "type")]
    ty: NetworkDeviceModel,
    #[serde(rename = "hwaddr")]
    mac_address: MacAddress,
    firewall: Option<bool>,
    ip: Option<LxcIpv4Addr>,
    ip6: Option<LxcIpv6Addr>,
}

impl ApiType for LxcNetworkDevice {
    #[sortable]
    const API_SCHEMA: proxmox_schema::Schema = ObjectSchema::new(
        "LXC Network Device",
        &sorted!([
            (
                "firewall",
                true,
                &BooleanSchema::new("firewall enabled for this network device").schema(),
            ),
            (
                "hwaddr",
                false,
                &StringSchema::new("mac address for this network device").schema(),
            ),
            (
                "ip",
                true,
                &StringSchema::new("IP settings for this network device").schema(),
            ),
            (
                "ip6",
                true,
                &StringSchema::new("IPv6 settings for this network device").schema(),
            ),
            (
                "type",
                false,
                &StringSchema::new("type of the network device").schema(),
            ),
        ]),
    )
    .additional_properties(true)
    .schema();
}

/// Container type that can hold both LXC and QEMU network devices.
#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum NetworkDevice {
    Qemu(QemuNetworkDevice),
    Lxc(LxcNetworkDevice),
}

/// default return value for [`NetworkDevice::has_firewall()`]
pub const NETWORK_DEVICE_FIREWALL_DEFAULT: bool = false;

impl NetworkDevice {
    pub fn model(&self) -> NetworkDeviceModel {
        match self {
            NetworkDevice::Qemu(qemu_network_device) => qemu_network_device.model,
            NetworkDevice::Lxc(lxc_network_device) => lxc_network_device.ty,
        }
    }

    /// Returns the MAC address of the network device
    pub fn mac_address(&self) -> MacAddress {
        match self {
            NetworkDevice::Qemu(qemu_network_device) => qemu_network_device.mac_address,
            NetworkDevice::Lxc(lxc_network_device) => lxc_network_device.mac_address,
        }
    }

    /// Returns the IPv4 of the network device, if set in the configuration (LXC only).
    pub fn ip(&self) -> Option<Ipv4Cidr> {
        if let NetworkDevice::Lxc(device) = self {
            return device.ip?.cidr();
        }

        None
    }

    /// Returns the IPv6 of the network device, if set in the configuration (LXC only).
    pub fn ip6(&self) -> Option<Ipv6Cidr> {
        if let NetworkDevice::Lxc(device) = self {
            return device.ip6?.cidr();
        }

        None
    }

    /// Whether the firewall is enabled for this network device, defaults to [`NETWORK_DEVICE_FIREWALL_DEFAULT`]
    pub fn has_firewall(&self) -> bool {
        let firewall_option = match self {
            NetworkDevice::Qemu(qemu_network_device) => qemu_network_device.firewall,
            NetworkDevice::Lxc(lxc_network_device) => lxc_network_device.firewall,
        };

        firewall_option.unwrap_or(NETWORK_DEVICE_FIREWALL_DEFAULT)
    }
}

impl FromStr for NetworkDevice {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(qemu_device) = s.parse::<PropertyString<QemuNetworkDevice>>() {
            return Ok(NetworkDevice::Qemu(qemu_device.into_inner()));
        }

        if let Ok(lxc_device) = s.parse::<PropertyString<LxcNetworkDevice>>() {
            return Ok(NetworkDevice::Lxc(lxc_device.into_inner()));
        }

        bail!("not a valid network device property string: {s}")
    }
}

#[derive(Debug, Default)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct NetworkConfig {
    network_devices: BTreeMap<i64, NetworkDevice>,
}

impl NetworkConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn index_from_net_key(key: &str) -> Result<i64, Error> {
        if let Some(digits) = key.strip_prefix("net") {
            if let Some((digits, rest)) = match_digits(digits) {
                let index: i64 = digits.parse()?;

                if (0..31).contains(&index) && rest.is_empty() {
                    return Ok(index);
                }
            }
        }

        bail!("No index found in net key string: {key}")
    }

    pub fn network_devices(&self) -> &BTreeMap<i64, NetworkDevice> {
        &self.network_devices
    }

    pub fn parse<R: io::BufRead>(input: R) -> Result<Self, Error> {
        let mut network_devices = BTreeMap::new();

        for line in input.lines() {
            let line = line?;
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with('[') {
                break;
            }

            if line.starts_with("net") {
                log::trace!("parsing net config line: {line}");

                if let Some((mut key, mut value)) = line.split_once(':') {
                    if key.is_empty() || value.is_empty() {
                        continue;
                    }

                    key = key.trim();
                    value = value.trim();

                    if let Ok(index) = Self::index_from_net_key(key) {
                        let network_device = NetworkDevice::from_str(value)?;

                        let exists = network_devices.insert(index, network_device);

                        if exists.is_some() {
                            bail!("Duplicated config key detected: {key}");
                        }
                    } else {
                        bail!("Encountered invalid net key in cfg: {key}");
                    }
                }
            }
        }

        Ok(Self { network_devices })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use super::*;

    #[test]
    fn test_parse_mac_address() {
        for input in [
            "aa:aa:aa:11:22:33",
            "AA:BB:FF:11:22:33",
            "bc:24:11:AA:bb:Ef",
        ] {
            let mac_address = input.parse::<MacAddress>().expect("valid mac address");

            assert_eq!(input.to_uppercase(), mac_address.to_string());
        }

        for input in [
            "aa:aa:aa:11:22:33:aa",
            "AA:BB:FF:11:22",
            "AA:BB:GG:11:22:33",
            "AABBGG112233",
            "",
        ] {
            input
                .parse::<MacAddress>()
                .expect_err("invalid mac address");
        }
    }

    #[test]
    fn test_eui64_link_local_address() {
        let mac_address: MacAddress = "BC:24:11:49:8D:75".parse().expect("valid MAC address");

        let link_local_address =
            Ipv6Addr::from_str("fe80::be24:11ff:fe49:8d75").expect("valid IPv6 address");

        assert_eq!(link_local_address, mac_address.eui64_link_local_address());
    }

    #[test]
    fn test_parse_network_device() {
        let mut network_device: NetworkDevice =
            "virtio=AA:AA:AA:17:19:81,bridge=public,firewall=1,queues=4"
                .parse()
                .expect("valid network configuration");

        assert_eq!(
            network_device,
            NetworkDevice::Qemu(QemuNetworkDevice {
                model: NetworkDeviceModel::VirtIO,
                mac_address: MacAddress::new([0xAA, 0xAA, 0xAA, 0x17, 0x19, 0x81]),
                firewall: Some(true),
            })
        );

        network_device = "model=virtio,macaddr=AA:AA:AA:17:19:81,bridge=public"
            .parse()
            .expect("valid network configuration");

        assert_eq!(
            network_device,
            NetworkDevice::Qemu(QemuNetworkDevice {
                model: NetworkDeviceModel::VirtIO,
                mac_address: MacAddress::new([0xAA, 0xAA, 0xAA, 0x17, 0x19, 0x81]),
                firewall: None,
            })
        );

        assert!(!network_device.has_firewall());

        network_device = "model=virtio,macaddr=AA:AA:AA:17:19:81,bridge=public,firewall=1,queues=4"
            .parse()
            .expect("valid network configuration");

        assert_eq!(
            network_device,
            NetworkDevice::Qemu(QemuNetworkDevice {
                model: NetworkDeviceModel::VirtIO,
                mac_address: MacAddress::new([0xAA, 0xAA, 0xAA, 0x17, 0x19, 0x81]),
                firewall: Some(true),
            })
        );

        assert!(network_device.has_firewall());

        network_device =
            "name=eth0,bridge=public,firewall=0,hwaddr=AA:AA:AA:E2:3E:24,ip=dhcp,type=veth"
                .parse()
                .expect("valid network configuration");

        assert_eq!(
            network_device,
            NetworkDevice::Lxc(LxcNetworkDevice {
                ty: NetworkDeviceModel::Veth,
                mac_address: MacAddress::new([0xAA, 0xAA, 0xAA, 0xE2, 0x3E, 0x24]),
                firewall: Some(false),
                ip: Some(LxcIpv4Addr::Dhcp),
                ip6: None,
            })
        );

        "model=virtio"
            .parse::<NetworkDevice>()
            .expect_err("invalid network configuration");

        "bridge=public,firewall=0"
            .parse::<NetworkDevice>()
            .expect_err("invalid network configuration");

        "".parse::<NetworkDevice>()
            .expect_err("invalid network configuration");

        "name=eth0,bridge=public,firewall=0,hwaddr=AA:AA:AG:E2:3E:24,ip=dhcp,type=veth"
            .parse::<NetworkDevice>()
            .expect_err("invalid network configuration");
    }

    #[test]
    fn test_parse_network_config() {
        let mut guest_config = "\
boot: order=scsi0;net0
cores: 4
cpu: host
memory: 8192
meta: creation-qemu=8.0.2,ctime=1700141675
name: hoan-sdn
net0: virtio=AA:BB:CC:F2:FE:75,bridge=public
numa: 0
ostype: l26
parent: uwu
scsi0: local-lvm:vm-999-disk-0,discard=on,iothread=1,size=32G
scsihw: virtio-scsi-single
smbios1: uuid=addb0cc6-0393-4269-a504-1eb46604cb8a
sockets: 1
vmgenid: 13bcbb05-3608-4d74-bf4f-d5d20c3538e8

[snapshot]
boot: order=scsi0;ide2;net0
cores: 4
cpu: x86-64-v2-AES
ide2: NFS-iso:iso/proxmox-ve_8.0-2.iso,media=cdrom,size=1166488K
memory: 8192
meta: creation-qemu=8.0.2,ctime=1700141675
name: test
net2: virtio=AA:AA:AA:F2:FE:75,bridge=public,firewall=1
numa: 0
ostype: l26
parent: pre-SDN
scsi0: local-lvm:vm-999-disk-0,discard=on,iothread=1,size=32G
scsihw: virtio-scsi-single
smbios1: uuid=addb0cc6-0393-4269-a504-1eb46604cb8a
snaptime: 1700143513
sockets: 1
vmgenid: 706fbe99-d28b-4047-a9cd-3677c859ca8a

[snapshott]
boot: order=scsi0;ide2;net0
cores: 4
cpu: host
ide2: NFS-iso:iso/proxmox-ve_8.0-2.iso,media=cdrom,size=1166488K
memory: 8192
meta: creation-qemu=8.0.2,ctime=1700141675
name: hoan-sdn
net0: virtio=AA:AA:FF:F2:FE:75,bridge=public,firewall=0
numa: 0
ostype: l26
parent: SDN
scsi0: local-lvm:vm-999-disk-0,discard=on,iothread=1,size=32G
scsihw: virtio-scsi-single
smbios1: uuid=addb0cc6-0393-4269-a504-1eb46604cb8a
snaptime: 1700158473
sockets: 1
vmgenid: 706fbe99-d28b-4047-a9cd-3677c859ca8a"
            .as_bytes();

        let mut network_config: NetworkConfig =
            NetworkConfig::parse(guest_config).expect("valid network configuration");

        assert_eq!(network_config.network_devices().len(), 1);

        assert_eq!(
            network_config.network_devices()[&0],
            NetworkDevice::Qemu(QemuNetworkDevice {
                model: NetworkDeviceModel::VirtIO,
                mac_address: MacAddress::new([0xAA, 0xBB, 0xCC, 0xF2, 0xFE, 0x75]),
                firewall: None,
            })
        );

        guest_config = "\
arch: amd64
cores: 1
features: nesting=1
hostname: dnsct
memory: 512
net0: name=eth0,bridge=data,firewall=1,hwaddr=BC:24:11:47:83:11,ip=dhcp,ip6=auto,type=veth
net2:   name=eth0,bridge=data,firewall=0,hwaddr=BC:24:11:47:83:12,ip=123.123.123.123/24,type=veth  
net5: name=eth0,bridge=data,firewall=1,hwaddr=BC:24:11:47:83:13,ip6=fd80::1/64,type=veth
ostype: alpine
rootfs: local-lvm:vm-10001-disk-0,size=1G
swap: 512
unprivileged: 1"
            .as_bytes();

        network_config = NetworkConfig::parse(guest_config).expect("valid network configuration");

        assert_eq!(network_config.network_devices().len(), 3);

        assert_eq!(
            network_config.network_devices()[&0],
            NetworkDevice::Lxc(LxcNetworkDevice {
                ty: NetworkDeviceModel::Veth,
                mac_address: MacAddress::new([0xBC, 0x24, 0x11, 0x47, 0x83, 0x11]),
                firewall: Some(true),
                ip: Some(LxcIpv4Addr::Dhcp),
                ip6: Some(LxcIpv6Addr::Auto),
            })
        );

        assert_eq!(
            network_config.network_devices()[&2],
            NetworkDevice::Lxc(LxcNetworkDevice {
                ty: NetworkDeviceModel::Veth,
                mac_address: MacAddress::new([0xBC, 0x24, 0x11, 0x47, 0x83, 0x12]),
                firewall: Some(false),
                ip: Some(LxcIpv4Addr::Ip(
                    Ipv4Cidr::from_str("123.123.123.123/24").expect("valid ipv4")
                )),
                ip6: None,
            })
        );

        assert_eq!(
            network_config.network_devices()[&5],
            NetworkDevice::Lxc(LxcNetworkDevice {
                ty: NetworkDeviceModel::Veth,
                mac_address: MacAddress::new([0xBC, 0x24, 0x11, 0x47, 0x83, 0x13]),
                firewall: Some(true),
                ip: None,
                ip6: Some(LxcIpv6Addr::Ip(
                    Ipv6Cidr::from_str("fd80::1/64").expect("valid ipv6")
                )),
            })
        );

        NetworkConfig::parse(
            "netqwe: name=eth0,bridge=data,firewall=1,hwaddr=BC:24:11:47:83:11,ip=dhcp,type=veth"
                .as_bytes(),
        )
        .expect_err("invalid net key");

        NetworkConfig::parse(
            "net0 name=eth0,bridge=data,firewall=1,hwaddr=BC:24:11:47:83:11,ip=dhcp,type=veth"
                .as_bytes(),
        )
        .expect_err("invalid net key");

        NetworkConfig::parse(
            "net33: name=eth0,bridge=data,firewall=1,hwaddr=BC:24:11:47:83:11,ip=dhcp,type=veth"
                .as_bytes(),
        )
        .expect_err("invalid net key");
    }
}

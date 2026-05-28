use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{Error, bail};
use serde::{Deserialize, Serialize};

use proxmox_schema::{ApiStringFormat, UpdaterType, api, api_string_type, const_regex};

const_regex! {
    NET_AFI_REGEX = r"^(?:[a-fA-F0-9]{2})$";
    // Variable length area: 0 to 13 bytes (0 to 26 hex digits) according to ISO 10589
    NET_AREA_REGEX = r"^(?:[a-fA-F0-9]{2}){0,13}$";
    NET_SYSTEM_ID_REGEX = r"^(?:[a-fA-F0-9]{4})\.(?:[a-fA-F0-9]{4})\.(?:[a-fA-F0-9]{4})$";
    NET_SELECTOR_REGEX = r"^(?:[a-fA-F0-9]{2})$";
}

const NET_AFI_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&NET_AFI_REGEX);
const NET_AREA_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&NET_AREA_REGEX);
const NET_SYSTEM_ID_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&NET_SYSTEM_ID_REGEX);
const NET_SELECTOR_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&NET_SELECTOR_REGEX);

api_string_type! {
    /// Address Family authority Identifier - 49 The AFI value 49 is what IS-IS (and openfabric) uses
    /// for private addressing.
    #[api(format: &NET_AFI_FORMAT)]
    #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    struct NetAFI(String);
}

impl Default for NetAFI {
    fn default() -> Self {
        Self("49".to_owned())
    }
}

impl UpdaterType for NetAFI {
    type Updater = Option<NetAFI>;
}

api_string_type! {
    /// Area identifier: Variable length (0-13 bytes / 0-26 hex digits) according to ISO 10589
    /// IS-IS area number that identifies the routing domain. All routers in the same area must
    /// have the same area identifier. Can be empty or up to 26 hex digits.
    #[api(format: &NET_AREA_FORMAT)]
    #[derive(Debug, Deserialize, Serialize, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
    struct NetArea(String);
}

impl Default for NetArea {
    fn default() -> Self {
        Self("0001".to_owned())
    }
}

impl UpdaterType for NetArea {
    type Updater = Option<NetArea>;
}

api_string_type! {
    /// System identifier: 1921.6800.1002 - for system identifiers we recommend to use IP address or
    /// MAC address of the router itself. The way to construct this is to keep all of the zeroes of the
    /// router IP address, and then change the periods from being every three numbers to every four
    /// numbers. The address that is listed here is 192.168.1.2, which if expanded will turn into
    /// 192.168.001.002. Then all one has to do is move the dots to have four numbers instead of three.
    /// This gives us 1921.6800.1002.
    #[api(format: &NET_SYSTEM_ID_FORMAT)]
    #[derive(Debug, Deserialize, Serialize, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
    struct NetSystemId(String);
}

impl UpdaterType for NetSystemId {
    type Updater = Option<NetSystemId>;
}

/// Convert IP-Address to a NET address with the default afi, area and selector values. Note that a
/// valid Ipv4Addr is always a valid SystemId as well.
impl From<Ipv4Addr> for NetSystemId {
    fn from(value: Ipv4Addr) -> Self {
        let octets = value.octets();

        let system_id_str = format!(
            "{:03}{:01}.{:02}{:02}.{:01}{:03}",
            octets[0],
            octets[1] / 100,
            octets[1] % 100,
            octets[2] / 10,
            octets[2] % 10,
            octets[3]
        );

        Self(system_id_str)
    }
}

/// Convert IPv6-Address to a NET address with the default afi, area and selector values. Note that a
/// valid Ipv6Addr is always a valid SystemId as well.
impl From<Ipv6Addr> for NetSystemId {
    fn from(value: Ipv6Addr) -> Self {
        let segments = value.segments();

        // Use the last 3 segments (out of 8) of the IPv6 address
        let system_id_str = format!(
            "{:04x}.{:04x}.{:04x}",
            segments[5], segments[6], segments[7]
        );

        Self(system_id_str)
    }
}

api_string_type! {
    /// NET selector: 00 Must always be 00. This setting indicates “this system” or “local system.”
    #[api(format: &NET_SELECTOR_FORMAT)]
    #[derive(Debug, Deserialize, Serialize, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
    struct NetSelector(String);
}

impl UpdaterType for NetSelector {
    type Updater = Option<NetSelector>;
}

impl Default for NetSelector {
    fn default() -> Self {
        Self("00".to_owned())
    }
}

/// The Network Entity Title (NET).
///
/// Every OpenFabric node is identified through the NET. It has a network and a host
/// part.
/// The first part is the network part (also called area). The entire OpenFabric fabric has to have
/// the same network part (afi + area). The first number is the [`NetAFI`] and the second is the
/// [`NetArea`].
/// e.g.: "49.0001"
/// The second part is the host part, which has to differ on every node in the fabric, but *not*
/// between fabrics on the same node. It contains the [`NetSystemId`] and the [`NetSelector`].
/// e.g.: "1921.6800.1002.00"
#[api]
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Net {
    afi: NetAFI,
    area: NetArea,
    system: NetSystemId,
    selector: NetSelector,
}

proxmox_serde::forward_serialize_to_display!(Net);
proxmox_serde::forward_deserialize_to_from_str!(Net);

impl UpdaterType for Net {
    type Updater = Option<Net>;
}

impl std::str::FromStr for Net {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(".").collect();

        // Minimum: AFI.SystemID(3 parts).Selector = 5 parts
        // With area: AFI.Area.SystemID(3 parts).Selector = 6+ parts
        if parts.len() < 5 {
            bail!("invalid NET format: {s} (expected at least AFI.SystemID.Selector)")
        }

        // Last part is selector (2 hex digits)
        let selector_idx = parts.len() - 1;
        let selector = parts[selector_idx];

        // Three parts before selector are system ID (xxxx.xxxx.xxxx)
        let system_id_parts = &parts[selector_idx - 3..selector_idx];
        let system = format!(
            "{}.{}.{}",
            system_id_parts[0], system_id_parts[1], system_id_parts[2]
        );

        // First part is AFI (2 hex digits)
        let afi = parts[0];

        // Everything between AFI and system ID is the area (can be empty)
        let area_parts = &parts[1..selector_idx - 3];
        let area = area_parts.join("");

        Ok(Self {
            afi: NetAFI::from_str(afi)?,
            area: NetArea::from_string(area)?,
            system: NetSystemId::from_string(system)?,
            selector: NetSelector::from_str(selector)?,
        })
    }
}

impl Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Format area with dots every 4 hex digits for readability
        let area_str = self.area.0.as_str();
        let area_formatted = if area_str.is_empty() {
            String::new()
        } else {
            let chunks: Vec<&str> = area_str
                .as_bytes()
                .chunks(4)
                .map(|chunk| std::str::from_utf8(chunk).unwrap())
                .collect();
            format!(".{}", chunks.join("."))
        };

        write!(
            f,
            "{}{}.{}.{}",
            self.afi, area_formatted, self.system, self.selector
        )
    }
}

/// Default NET address for a given Ipv4Addr. This adds the default afi, area and selector to the
/// address.
impl From<Ipv4Addr> for Net {
    fn from(value: Ipv4Addr) -> Self {
        Self {
            afi: NetAFI::default(),
            area: NetArea::default(),
            system: value.into(),
            selector: NetSelector::default(),
        }
    }
}

/// Default NET address for a given Ipv6Addr. This adds the default afi, area and selector to the
/// address.
impl From<Ipv6Addr> for Net {
    fn from(value: Ipv6Addr) -> Self {
        Self {
            afi: NetAFI::default(),
            area: NetArea::default(),
            system: value.into(),
            selector: NetSelector::default(),
        }
    }
}

/// Default NET address for a given IpAddr (can be either Ipv4 or Ipv6). This adds the default afi,
/// area and selector to the address.
impl From<IpAddr> for Net {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ipv4_addr) => ipv4_addr.into(),
            IpAddr::V6(ipv6_addr) => ipv6_addr.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_net_from_str() {
        let input = "49.0001.1921.6800.1002.00";
        let net = input.parse::<Net>().expect("this net should parse");
        assert_eq!(net.afi, NetAFI("49".to_owned()));
        assert_eq!(net.area, NetArea("0001".to_owned()));
        assert_eq!(net.system, NetSystemId("1921.6800.1002".to_owned()));
        assert_eq!(net.selector, NetSelector("00".to_owned()));

        let input = "45.0200.0100.1001.ba1f.01";
        let net = input.parse::<Net>().expect("this net should parse");
        assert_eq!(net.afi, NetAFI("45".to_owned()));
        assert_eq!(net.area, NetArea("0200".to_owned()));
        assert_eq!(net.system, NetSystemId("0100.1001.ba1f".to_owned()));
        assert_eq!(net.selector, NetSelector("01".to_owned()));
    }

    #[test]
    fn test_net_from_str_failed() {
        let input = "49.0001.1921.6800.1002.000";
        input.parse::<Net>().expect_err("invalid NET selector");

        let input = "49.0001.1921.6800.1002.00.00";
        input
            .parse::<Net>()
            .expect_err("invalid amount of elements");

        let input = "49.0001.1921.6800.10002.00";
        input.parse::<Net>().expect_err("invalid system id");

        let input = "49.0001.1921.6800.1z02.00";
        input.parse::<Net>().expect_err("invalid system id");

        let input = "409.0001.1921.6800.1002.00";
        input.parse::<Net>().expect_err("invalid AFI");

        // Area can now be variable length (0-26 hex digits), so 5 digits is valid
        // but 27 digits would be invalid
        let input = "49.0123.4567.8901.2345.6789.0123.4569.1921.6800.1002.00";
        input
            .parse::<Net>()
            .expect_err("area too long (>26 hex digits)");

        // Too few parts
        let input = "49.1921.6800.00";
        input.parse::<Net>().expect_err("not enough parts");
    }

    #[test]
    fn test_net_display() {
        let net = Net {
            afi: NetAFI("49".to_owned()),
            area: NetArea("0001".to_owned()),
            system: NetSystemId("1921.6800.1002".to_owned()),
            selector: NetSelector("00".to_owned()),
        };
        assert_eq!(format!("{net}"), "49.0001.1921.6800.1002.00");
    }

    #[test]
    fn test_net_from_ipv4() {
        let ip: Ipv4Addr = "192.168.1.100".parse().unwrap();
        let net: Net = ip.into();
        assert_eq!(format!("{net}"), "49.0001.1921.6800.1100.00");

        let ip1: Ipv4Addr = "10.10.2.245".parse().unwrap();
        let net1: Net = ip1.into();
        assert_eq!(format!("{net1}"), "49.0001.0100.1000.2245.00");

        let ip2: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let net2: Net = ip2.into();
        assert_eq!(format!("{net2}"), "49.0001.0010.0100.1001.00");
    }

    #[test]
    fn test_net_from_ipv6() {
        // 2001:db8::1 -> [2001, 0db8, 0, 0, 0, 0, 0, 1]
        // last 3 segments: [0, 0, 1]
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let net: Net = ip.into();
        assert_eq!(format!("{net}"), "49.0001.0000.0000.0001.00");

        // fe80::1234:5678:abcd -> [fe80, 0, 0, 0, 0, 1234, 5678, abcd]
        // last 3 segments: [1234, 5678, abcd]
        let ip1: Ipv6Addr = "fe80::1234:5678:abcd".parse().unwrap();
        let net1: Net = ip1.into();
        assert_eq!(format!("{net1}"), "49.0001.1234.5678.abcd.00");

        // 2001:0db8:85a3::8a2e:370:7334 -> [2001, 0db8, 85a3, 0, 0, 8a2e, 0370, 7334]
        // last 3 segments: [8a2e, 0370, 7334]
        let ip2: Ipv6Addr = "2001:0db8:85a3::8a2e:370:7334".parse().unwrap();
        let net2: Net = ip2.into();
        assert_eq!(format!("{net2}"), "49.0001.8a2e.0370.7334.00");

        // ::1 -> [0, 0, 0, 0, 0, 0, 0, 1]
        // last 3 segments: [0, 0, 1]
        let ip3: Ipv6Addr = "::1".parse().unwrap();
        let net3: Net = ip3.into();
        assert_eq!(format!("{net3}"), "49.0001.0000.0000.0001.00");

        // a:b::0 -> [a, b, 0, 0, 0, 0, 0, 0]
        // last 3 segments: [0, 0, 0]
        let ip4: Ipv6Addr = "a:b::0".parse().unwrap();
        let net4: Net = ip4.into();
        assert_eq!(format!("{net4}"), "49.0001.0000.0000.0000.00");
    }

    #[test]
    fn test_net_variable_length_area() {
        // Test with no area (just AFI)
        let input = "49.1921.6800.1002.00";
        let net = input.parse::<Net>().expect("should parse NET with no area");
        assert_eq!(net.afi, NetAFI("49".to_owned()));
        assert_eq!(net.area, NetArea("".to_owned()));
        assert_eq!(net.system, NetSystemId("1921.6800.1002".to_owned()));
        assert_eq!(net.selector, NetSelector("00".to_owned()));
        assert_eq!(format!("{net}"), "49.1921.6800.1002.00");

        // Test with 2 hex digit area
        let input = "49.01.1921.6800.1002.00";
        let net = input
            .parse::<Net>()
            .expect("should parse NET with 2-digit area");
        assert_eq!(net.area, NetArea("01".to_owned()));
        assert_eq!(format!("{net}"), "49.01.1921.6800.1002.00");

        // Test with 4 hex digit area (standard)
        let input = "49.0001.1921.6800.1002.00";
        let net = input
            .parse::<Net>()
            .expect("should parse NET with 4-digit area");
        assert_eq!(net.area, NetArea("0001".to_owned()));
        assert_eq!(format!("{net}"), "49.0001.1921.6800.1002.00");

        // Test with 8 hex digit area (formatted with dots every 4 digits)
        let input = "49.0001.0002.1921.6800.1002.00";
        let net = input
            .parse::<Net>()
            .expect("should parse NET with 8-digit area");
        assert_eq!(net.area, NetArea("00010002".to_owned()));
        // Should be formatted with dots every 4 hex digits
        assert_eq!(format!("{net}"), "49.0001.0002.1921.6800.1002.00");

        // Test with 12 hex digit area
        let input = "49.0001.0002.0003.1921.6800.1002.00";
        let net = input
            .parse::<Net>()
            .expect("should parse NET with 12-digit area");
        assert_eq!(net.area, NetArea("000100020003".to_owned()));
        assert_eq!(format!("{net}"), "49.0001.0002.0003.1921.6800.1002.00");

        // Test with maximum length area (26 hex digits = 13 bytes)
        let input = "49.0123.4567.89ab.cdef.0123.4567.89.1921.6800.1002.00";
        let net = input
            .parse::<Net>()
            .expect("should parse NET with 26-digit area");
        assert_eq!(net.area, NetArea("0123456789abcdef0123456789".to_owned()));
        assert_eq!(
            format!("{net}"),
            "49.0123.4567.89ab.cdef.0123.4567.89.1921.6800.1002.00"
        );

        // Odd-length area (5 hex digits) is invalid: area must be byte-aligned
        let input = "49.12345.1921.6800.1002.00";
        input
            .parse::<Net>()
            .expect_err("odd-length area is not byte-aligned");

        // Area exceeding 13 bytes (28 hex digits) must be rejected
        let input = "49.0123.4567.89ab.cdef.0123.4567.89ab.1921.6800.1002.00";
        input
            .parse::<Net>()
            .expect_err("area exceeds maximum of 13 bytes (26 hex digits)");
    }
}

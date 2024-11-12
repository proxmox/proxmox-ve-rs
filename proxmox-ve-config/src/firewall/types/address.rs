use std::fmt::{self, Display};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;

use anyhow::{bail, format_err, Error};
use serde_with::{DeserializeFromStr, SerializeDisplay};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    V4,
    V6,
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Family::V4 => f.write_str("Ipv4"),
            Family::V6 => f.write_str("Ipv6"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum Cidr {
    Ipv4(Ipv4Cidr),
    Ipv6(Ipv6Cidr),
}

impl Cidr {
    pub fn new_v4(addr: impl Into<Ipv4Addr>, mask: u8) -> Result<Self, Error> {
        Ok(Cidr::Ipv4(Ipv4Cidr::new(addr, mask)?))
    }

    pub fn new_v6(addr: impl Into<Ipv6Addr>, mask: u8) -> Result<Self, Error> {
        Ok(Cidr::Ipv6(Ipv6Cidr::new(addr, mask)?))
    }

    pub const fn family(&self) -> Family {
        match self {
            Cidr::Ipv4(_) => Family::V4,
            Cidr::Ipv6(_) => Family::V6,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        matches!(self, Cidr::Ipv4(_))
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, Cidr::Ipv6(_))
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Ipv4(ip) => f.write_str(ip.to_string().as_str()),
            Self::Ipv6(ip) => f.write_str(ip.to_string().as_str()),
        }
    }
}

impl std::str::FromStr for Cidr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if let Ok(ip) = s.parse::<Ipv4Cidr>() {
            return Ok(Cidr::Ipv4(ip));
        }

        if let Ok(ip) = s.parse::<Ipv6Cidr>() {
            return Ok(Cidr::Ipv6(ip));
        }

        bail!("invalid ip address or CIDR: {s:?}");
    }
}

impl From<Ipv4Cidr> for Cidr {
    fn from(cidr: Ipv4Cidr) -> Self {
        Cidr::Ipv4(cidr)
    }
}

impl From<Ipv6Cidr> for Cidr {
    fn from(cidr: Ipv6Cidr) -> Self {
        Cidr::Ipv6(cidr)
    }
}

const IPV4_LENGTH: u8 = 32;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Ipv4Cidr {
    addr: Ipv4Addr,
    mask: u8,
}

impl Ipv4Cidr {
    pub fn new(addr: impl Into<Ipv4Addr>, mask: u8) -> Result<Self, Error> {
        if mask > 32 {
            bail!("mask out of range for ipv4 cidr ({mask})");
        }

        Ok(Self {
            addr: addr.into(),
            mask,
        })
    }

    pub fn contains_address(&self, other: &Ipv4Addr) -> bool {
        let bits = u32::from_be_bytes(self.addr.octets());
        let other_bits = u32::from_be_bytes(other.octets());

        let shift_amount: u32 = IPV4_LENGTH.saturating_sub(self.mask).into();

        bits.checked_shr(shift_amount).unwrap_or(0)
            == other_bits.checked_shr(shift_amount).unwrap_or(0)
    }

    pub fn address(&self) -> &Ipv4Addr {
        &self.addr
    }

    pub fn mask(&self) -> u8 {
        self.mask
    }
}

impl<T: Into<Ipv4Addr>> From<T> for Ipv4Cidr {
    fn from(value: T) -> Self {
        Self {
            addr: value.into(),
            mask: 32,
        }
    }
}

impl std::str::FromStr for Ipv4Cidr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s.find('/') {
            None => Self {
                addr: s.parse()?,
                mask: 32,
            },
            Some(pos) => {
                let mask: u8 = s[(pos + 1)..]
                    .parse()
                    .map_err(|_| format_err!("invalid mask in ipv4 cidr: {s:?}"))?;

                Self::new(s[..pos].parse::<Ipv4Addr>()?, mask)?
            }
        })
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", &self.addr, self.mask)
    }
}

const IPV6_LENGTH: u8 = 128;

#[derive(Clone, Copy, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Ipv6Cidr {
    addr: Ipv6Addr,
    mask: u8,
}

impl Ipv6Cidr {
    pub fn new(addr: impl Into<Ipv6Addr>, mask: u8) -> Result<Self, Error> {
        if mask > IPV6_LENGTH {
            bail!("mask out of range for ipv6 cidr");
        }

        Ok(Self {
            addr: addr.into(),
            mask,
        })
    }

    pub fn contains_address(&self, other: &Ipv6Addr) -> bool {
        let bits = u128::from_be_bytes(self.addr.octets());
        let other_bits = u128::from_be_bytes(other.octets());

        let shift_amount: u32 = IPV6_LENGTH.saturating_sub(self.mask).into();

        bits.checked_shr(shift_amount).unwrap_or(0)
            == other_bits.checked_shr(shift_amount).unwrap_or(0)
    }

    pub fn address(&self) -> &Ipv6Addr {
        &self.addr
    }

    pub fn mask(&self) -> u8 {
        self.mask
    }
}

impl std::str::FromStr for Ipv6Cidr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(match s.find('/') {
            None => Self {
                addr: s.parse()?,
                mask: 128,
            },
            Some(pos) => {
                let mask: u8 = s[(pos + 1)..]
                    .parse()
                    .map_err(|_| format_err!("invalid mask in ipv6 cidr: {s:?}"))?;

                Self::new(s[..pos].parse::<Ipv6Addr>()?, mask)?
            }
        })
    }
}

impl fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", &self.addr, self.mask)
    }
}

impl<T: Into<Ipv6Addr>> From<T> for Ipv6Cidr {
    fn from(addr: T) -> Self {
        Self {
            addr: addr.into(),
            mask: 128,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum IpRangeError {
    MismatchedFamilies,
    StartGreaterThanLast,
    InvalidFormat,
}

impl std::error::Error for IpRangeError {}

impl Display for IpRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IpRangeError::MismatchedFamilies => "mismatched ip address families",
            IpRangeError::StartGreaterThanLast => "start is greater than last",
            IpRangeError::InvalidFormat => "invalid ip range format",
        })
    }
}

/// Represents a range of IPv4 or IPv6 addresses.
///
/// For more information see [`AddressRange`]
#[derive(Clone, Copy, Debug, PartialEq, Eq, SerializeDisplay, DeserializeFromStr)]
pub enum IpRange {
    V4(AddressRange<Ipv4Addr>),
    V6(AddressRange<Ipv6Addr>),
}

impl IpRange {
    /// Returns the family of the IpRange.
    pub fn family(&self) -> Family {
        match self {
            IpRange::V4(_) => Family::V4,
            IpRange::V6(_) => Family::V6,
        }
    }

    /// Creates a new [`IpRange`] from two [`IpAddr`].
    ///
    /// # Errors
    ///
    /// This function will return an error if start and last IP address are not from the same family.
    pub fn new(start: impl Into<IpAddr>, last: impl Into<IpAddr>) -> Result<Self, IpRangeError> {
        match (start.into(), last.into()) {
            (IpAddr::V4(start), IpAddr::V4(last)) => Self::new_v4(start, last),
            (IpAddr::V6(start), IpAddr::V6(last)) => Self::new_v6(start, last),
            _ => Err(IpRangeError::MismatchedFamilies),
        }
    }

    /// construct a new Ipv4 Range
    pub fn new_v4(
        start: impl Into<Ipv4Addr>,
        last: impl Into<Ipv4Addr>,
    ) -> Result<Self, IpRangeError> {
        Ok(IpRange::V4(AddressRange::new_v4(start, last)?))
    }

    pub fn new_v6(
        start: impl Into<Ipv6Addr>,
        last: impl Into<Ipv6Addr>,
    ) -> Result<Self, IpRangeError> {
        Ok(IpRange::V6(AddressRange::new_v6(start, last)?))
    }
}

impl std::str::FromStr for IpRange {
    type Err = IpRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(range) = s.parse() {
            return Ok(IpRange::V4(range));
        }

        if let Ok(range) = s.parse() {
            return Ok(IpRange::V6(range));
        }

        Err(IpRangeError::InvalidFormat)
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpRange::V4(range) => range.fmt(f),
            IpRange::V6(range) => range.fmt(f),
        }
    }
}

/// Represents a range of IP addresses from start to last.
///
/// This type is for encapsulation purposes for the [`IpRange`] enum and should be instantiated via
/// that enum.
///
/// # Invariants
///
/// * start and last have the same IP address family
/// * start is less than or equal to last
///
/// # Textual representation
///
/// Two IP addresses separated by a hyphen, e.g.: `127.0.0.1-127.0.0.255`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange<T> {
    start: T,
    last: T,
}

impl AddressRange<Ipv4Addr> {
    pub(crate) fn new_v4(
        start: impl Into<Ipv4Addr>,
        last: impl Into<Ipv4Addr>,
    ) -> Result<AddressRange<Ipv4Addr>, IpRangeError> {
        let (start, last) = (start.into(), last.into());

        if start > last {
            return Err(IpRangeError::StartGreaterThanLast);
        }

        Ok(Self { start, last })
    }
}

impl AddressRange<Ipv6Addr> {
    pub(crate) fn new_v6(
        start: impl Into<Ipv6Addr>,
        last: impl Into<Ipv6Addr>,
    ) -> Result<AddressRange<Ipv6Addr>, IpRangeError> {
        let (start, last) = (start.into(), last.into());

        if start > last {
            return Err(IpRangeError::StartGreaterThanLast);
        }

        Ok(Self { start, last })
    }
}

impl<T> AddressRange<T> {
    pub fn start(&self) -> &T {
        &self.start
    }

    pub fn last(&self) -> &T {
        &self.last
    }
}

impl std::str::FromStr for AddressRange<Ipv4Addr> {
    type Err = IpRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((start, last)) = s.split_once('-') {
            let start_address = start
                .parse::<Ipv4Addr>()
                .map_err(|_| IpRangeError::InvalidFormat)?;

            let last_address = last
                .parse::<Ipv4Addr>()
                .map_err(|_| IpRangeError::InvalidFormat)?;

            return Self::new_v4(start_address, last_address);
        }

        Err(IpRangeError::InvalidFormat)
    }
}

impl std::str::FromStr for AddressRange<Ipv6Addr> {
    type Err = IpRangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((start, last)) = s.split_once('-') {
            let start_address = start
                .parse::<Ipv6Addr>()
                .map_err(|_| IpRangeError::InvalidFormat)?;

            let last_address = last
                .parse::<Ipv6Addr>()
                .map_err(|_| IpRangeError::InvalidFormat)?;

            return Self::new_v6(start_address, last_address);
        }

        Err(IpRangeError::InvalidFormat)
    }
}

impl<T: fmt::Display> fmt::Display for AddressRange<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.last)
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum IpEntry {
    Cidr(Cidr),
    Range(IpRange),
}

impl std::str::FromStr for IpEntry {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if let Ok(cidr) = s.parse() {
            return Ok(IpEntry::Cidr(cidr));
        }

        if let Ok(range) = s.parse() {
            return Ok(IpEntry::Range(range));
        }

        bail!("Invalid IP entry: {s}");
    }
}

impl fmt::Display for IpEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Cidr(ip) => ip.fmt(f),
            Self::Range(range) => range.fmt(f),
        }
    }
}

impl IpEntry {
    fn family(&self) -> Family {
        match self {
            Self::Cidr(cidr) => cidr.family(),
            Self::Range(range) => range.family(),
        }
    }
}

impl From<Cidr> for IpEntry {
    fn from(value: Cidr) -> Self {
        IpEntry::Cidr(value)
    }
}

impl From<IpRange> for IpEntry {
    fn from(value: IpRange) -> Self {
        IpEntry::Range(value)
    }
}

#[derive(Clone, Debug, DeserializeFromStr)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct IpList {
    // guaranteed to have the same family
    entries: Vec<IpEntry>,
    family: Family,
}

impl Deref for IpList {
    type Target = Vec<IpEntry>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl<T: Into<IpEntry>> From<T> for IpList {
    fn from(value: T) -> Self {
        let entry = value.into();

        Self {
            family: entry.family(),
            entries: vec![entry],
        }
    }
}

impl std::str::FromStr for IpList {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            bail!("Empty IP specification!")
        }

        let mut entries = Vec::new();
        let mut current_family = None;

        for element in s.split(',') {
            let entry: IpEntry = element.parse()?;

            if let Some(family) = current_family {
                if family != entry.family() {
                    bail!("Incompatible families in IPList!")
                }
            } else {
                current_family = Some(entry.family());
            }

            entries.push(entry);
        }

        if entries.is_empty() {
            bail!("empty ip list")
        }

        Ok(IpList {
            entries,
            family: current_family.unwrap(), // must be set due to length check above
        })
    }
}

impl IpList {
    pub fn new(entries: Vec<IpEntry>) -> Result<Self, Error> {
        let family = entries.iter().try_fold(None, |result, entry| {
            if let Some(family) = result {
                if entry.family() != family {
                    bail!("non-matching families in entries list");
                }

                Ok(Some(family))
            } else {
                Ok(Some(entry.family()))
            }
        })?;

        if let Some(family) = family {
            return Ok(Self { entries, family });
        }

        bail!("no elements in ip list entries");
    }

    pub fn family(&self) -> Family {
        self.family
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_v4_cidr() {
        let mut cidr: Ipv4Cidr = "0.0.0.0/0".parse().expect("valid IPv4 CIDR");

        assert_eq!(cidr.addr, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(cidr.mask, 0);

        assert!(cidr.contains_address(&Ipv4Addr::new(0, 0, 0, 0)));
        assert!(cidr.contains_address(&Ipv4Addr::new(255, 255, 255, 255)));

        cidr = "192.168.100.1".parse().expect("valid IPv4 CIDR");

        assert_eq!(cidr.addr, Ipv4Addr::new(192, 168, 100, 1));
        assert_eq!(cidr.mask, 32);

        assert!(cidr.contains_address(&Ipv4Addr::new(192, 168, 100, 1)));
        assert!(!cidr.contains_address(&Ipv4Addr::new(192, 168, 100, 2)));
        assert!(!cidr.contains_address(&Ipv4Addr::new(192, 168, 100, 0)));

        cidr = "10.100.5.0/24".parse().expect("valid IPv4 CIDR");

        assert_eq!(cidr.mask, 24);

        assert!(cidr.contains_address(&Ipv4Addr::new(10, 100, 5, 0)));
        assert!(cidr.contains_address(&Ipv4Addr::new(10, 100, 5, 1)));
        assert!(cidr.contains_address(&Ipv4Addr::new(10, 100, 5, 100)));
        assert!(cidr.contains_address(&Ipv4Addr::new(10, 100, 5, 255)));
        assert!(!cidr.contains_address(&Ipv4Addr::new(10, 100, 4, 255)));
        assert!(!cidr.contains_address(&Ipv4Addr::new(10, 100, 6, 0)));

        "0.0.0.0/-1".parse::<Ipv4Cidr>().unwrap_err();
        "0.0.0.0/33".parse::<Ipv4Cidr>().unwrap_err();
        "256.256.256.256/10".parse::<Ipv4Cidr>().unwrap_err();

        "fe80::1/64".parse::<Ipv4Cidr>().unwrap_err();
        "qweasd".parse::<Ipv4Cidr>().unwrap_err();
        "".parse::<Ipv4Cidr>().unwrap_err();
    }

    #[test]
    fn test_v6_cidr() {
        let mut cidr: Ipv6Cidr = "abab::1/64".parse().expect("valid IPv6 CIDR");

        assert_eq!(cidr.addr, Ipv6Addr::new(0xABAB, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(cidr.mask, 64);

        assert!(cidr.contains_address(&Ipv6Addr::new(0xABAB, 0, 0, 0, 0, 0, 0, 0)));
        assert!(cidr.contains_address(&Ipv6Addr::new(
            0xABAB, 0, 0, 0, 0xAAAA, 0xAAAA, 0xAAAA, 0xAAAA
        )));
        assert!(cidr.contains_address(&Ipv6Addr::new(
            0xABAB, 0, 0, 0, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF
        )));
        assert!(!cidr.contains_address(&Ipv6Addr::new(0xABAB, 0, 0, 1, 0, 0, 0, 0)));
        assert!(!cidr.contains_address(&Ipv6Addr::new(
            0xABAA, 0, 0, 0, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF
        )));

        cidr = "eeee::1".parse().expect("valid IPv6 CIDR");

        assert_eq!(cidr.mask, 128);

        assert!(cidr.contains_address(&Ipv6Addr::new(0xEEEE, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!cidr.contains_address(&Ipv6Addr::new(
            0xEEED, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF
        )));
        assert!(!cidr.contains_address(&Ipv6Addr::new(0xEEEE, 0, 0, 0, 0, 0, 0, 0)));

        "eeee::1/-1".parse::<Ipv6Cidr>().unwrap_err();
        "eeee::1/129".parse::<Ipv6Cidr>().unwrap_err();
        "gggg::1/64".parse::<Ipv6Cidr>().unwrap_err();

        "192.168.0.1".parse::<Ipv6Cidr>().unwrap_err();
        "qweasd".parse::<Ipv6Cidr>().unwrap_err();
        "".parse::<Ipv6Cidr>().unwrap_err();
    }

    #[test]
    fn test_parse_ip_entry() {
        let mut entry: IpEntry = "10.0.0.1".parse().expect("valid IP entry");

        assert_eq!(entry, Cidr::new_v4([10, 0, 0, 1], 32).unwrap().into());

        entry = "10.0.0.0/16".parse().expect("valid IP entry");

        assert_eq!(entry, Cidr::new_v4([10, 0, 0, 0], 16).unwrap().into());

        entry = "192.168.0.1-192.168.99.255"
            .parse()
            .expect("valid IP entry");

        assert_eq!(
            entry,
            IpRange::new_v4([192, 168, 0, 1], [192, 168, 99, 255])
                .expect("valid IP range")
                .into()
        );

        entry = "fe80::1".parse().expect("valid IP entry");

        assert_eq!(
            entry,
            Cidr::new_v6([0xFE80, 0, 0, 0, 0, 0, 0, 1], 128)
                .unwrap()
                .into()
        );

        entry = "fe80::1/48".parse().expect("valid IP entry");

        assert_eq!(
            entry,
            Cidr::new_v6([0xFE80, 0, 0, 0, 0, 0, 0, 1], 48)
                .unwrap()
                .into()
        );

        entry = "fd80::1-fd80::ffff".parse().expect("valid IP entry");

        assert_eq!(
            entry,
            IpRange::new_v6(
                [0xFD80, 0, 0, 0, 0, 0, 0, 1],
                [0xFD80, 0, 0, 0, 0, 0, 0, 0xFFFF],
            )
            .expect("valid IP range")
            .into()
        );

        "192.168.100.0-192.168.99.255"
            .parse::<IpEntry>()
            .unwrap_err();
        "192.168.100.0-fe80::1".parse::<IpEntry>().unwrap_err();
        "192.168.100.0-192.168.200.0/16"
            .parse::<IpEntry>()
            .unwrap_err();
        "192.168.100.0-192.168.200.0-192.168.250.0"
            .parse::<IpEntry>()
            .unwrap_err();
        "qweasd".parse::<IpEntry>().unwrap_err();
    }

    #[test]
    fn test_parse_ip_list() {
        let mut ip_list: IpList = "192.168.0.1,192.168.100.0/24,172.16.0.0-172.32.255.255"
            .parse()
            .expect("valid IP list");

        assert_eq!(
            ip_list,
            IpList {
                entries: vec![
                    IpEntry::Cidr(Cidr::new_v4([192, 168, 0, 1], 32).unwrap()),
                    IpEntry::Cidr(Cidr::new_v4([192, 168, 100, 0], 24).unwrap()),
                    IpRange::new_v4([172, 16, 0, 0], [172, 32, 255, 255])
                        .unwrap()
                        .into(),
                ],
                family: Family::V4,
            }
        );

        ip_list = "fe80::1/64".parse().expect("valid IP list");

        assert_eq!(
            ip_list,
            IpList {
                entries: vec![IpEntry::Cidr(
                    Cidr::new_v6([0xFE80, 0, 0, 0, 0, 0, 0, 1], 64).unwrap()
                ),],
                family: Family::V6,
            }
        );

        "192.168.0.1,fe80::1".parse::<IpList>().unwrap_err();

        "".parse::<IpList>().unwrap_err();
        "proxmox".parse::<IpList>().unwrap_err();
    }

    #[test]
    fn test_construct_ip_list() {
        let mut ip_list = IpList::new(vec![Cidr::new_v4([10, 0, 0, 0], 8).unwrap().into()])
            .expect("valid ip list");

        assert_eq!(ip_list.family(), Family::V4);

        ip_list =
            IpList::new(vec![Cidr::new_v6([0x000; 8], 8).unwrap().into()]).expect("valid ip list");

        assert_eq!(ip_list.family(), Family::V6);

        IpList::new(vec![]).expect_err("empty ip list is invalid");

        IpList::new(vec![
            Cidr::new_v4([10, 0, 0, 0], 8).unwrap().into(),
            Cidr::new_v6([0x0000; 8], 8).unwrap().into(),
        ])
        .expect_err("cannot mix ip families in ip list");
    }

    #[test]
    fn test_ip_range() {
        IpRange::new([10, 0, 0, 2], [10, 0, 0, 1]).unwrap_err();

        IpRange::new(
            [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x1000],
            [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0],
        )
        .unwrap_err();

        let v4_range = IpRange::new([10, 0, 0, 0], [10, 0, 0, 100]).unwrap();
        assert_eq!(v4_range.family(), Family::V4);

        let v6_range = IpRange::new(
            [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0],
            [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x1000],
        )
        .unwrap();
        assert_eq!(v6_range.family(), Family::V6);

        "10.0.0.1-10.0.0.100".parse::<IpRange>().unwrap();
        "2001:db8::1-2001:db8::f".parse::<IpRange>().unwrap();

        "10.0.0.1-2001:db8::1000".parse::<IpRange>().unwrap_err();
        "2001:db8::1-192.168.0.2".parse::<IpRange>().unwrap_err();

        "10.0.0.1-10.0.0.0".parse::<IpRange>().unwrap_err();
        "2001:db8::1-2001:db8::0".parse::<IpRange>().unwrap_err();
    }
}

use std::fmt;
use std::ops::Deref;

use anyhow::{bail, Error};
use proxmox_network_types::ip_address::{Cidr, Family, IpRange};
use serde_with::DeserializeFromStr;

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
}

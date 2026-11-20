//! Conntrack zones of SDN zones.
//!
//! Proxmox VE reserves the conntrack zones 16384 to 32767 (0x4000 to 0x7fff). These are all
//! conntrack zones whose two most significant bits are 01, so the whole block can be matched with a
//! single bitmask (`ct zone & 0xc000 == 0x4000`). SDN zones with a dedicated VRF get their
//! conntrack zone from the first 1024 conntrack zones of this block.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::sdn::config::{SdnConfig, ZoneConfig};

/// The conntrack zone of an SDN zone with a dedicated VRF.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "u16")]
pub struct VrfCtZone(u16);

impl VrfCtZone {
    /// The first conntrack zone for zones with a dedicated VRF, the start of the reserved block.
    pub const FIRST: u16 = 16384;

    /// The number of conntrack zones for zones with a dedicated VRF.
    pub const COUNT: u16 = 1024;

    /// Returns `None` if `ct_zone` is not in the range for zones with a dedicated VRF.
    pub fn new(ct_zone: u16) -> Option<Self> {
        (Self::FIRST..Self::FIRST + Self::COUNT)
            .contains(&ct_zone)
            .then_some(Self(ct_zone))
    }

    /// The conntrack zone ID.
    pub fn id(self) -> u16 {
        self.0
    }

    /// The position of the conntrack zone within the range for zones with a dedicated VRF.
    pub fn index(self) -> u16 {
        self.0 - Self::FIRST
    }
}

impl TryFrom<u16> for VrfCtZone {
    type Error = String;

    fn try_from(ct_zone: u16) -> Result<Self, Self::Error> {
        Self::new(ct_zone).ok_or_else(|| {
            format!(
                "conntrack zone {ct_zone} is out of range ({} - {})",
                Self::FIRST,
                Self::FIRST + Self::COUNT - 1
            )
        })
    }
}

/// A zone VRF with a conntrack zone and the interfaces enslaved to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfCtZoneEntry {
    ct_zone: VrfCtZone,
    interfaces: BTreeSet<String>,
}

impl VrfCtZoneEntry {
    /// The conntrack zone of the VRF.
    pub fn ct_zone(&self) -> VrfCtZone {
        self.ct_zone
    }

    /// The interfaces enslaved to the VRF, not including the VRF device itself.
    pub fn interfaces(&self) -> impl Iterator<Item = &str> + '_ {
        self.interfaces.iter().map(String::as_str)
    }
}

/// The zone VRFs with a conntrack zone, keyed by the name of their VRF device.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VrfCtZones {
    vrfs: BTreeMap<String, VrfCtZoneEntry>,
}

impl VrfCtZones {
    /// The name of the VRF device of a zone with a dedicated VRF.
    pub fn vrf_name(zone: &ZoneConfig) -> String {
        format!("vrf_{}", zone.name())
    }

    /// The VRFs of the zones with a conntrack zone that exist on `node`.
    ///
    /// The VRF device of a zone is only created on the nodes of the zone, so an interface with the
    /// same name on another node is not the VRF of the zone and must not get its conntrack zone.
    pub fn for_node(config: &SdnConfig, node: &str) -> Self {
        let mut ct_zones = Self::default();

        for zone in config.zones().filter(|zone| zone.is_on_node(node)) {
            ct_zones.add_zone(zone);
        }

        ct_zones
    }

    /// Adds the VRF of a zone, if the zone has a conntrack zone.
    pub fn add_zone(&mut self, zone: &ZoneConfig) {
        if let Some(ct_zone) = zone.ct_zone() {
            self.vrfs.insert(
                Self::vrf_name(zone),
                VrfCtZoneEntry {
                    ct_zone,
                    interfaces: BTreeSet::new(),
                },
            );
        }
    }

    /// Adds an interface to the VRF device `vrf`.
    ///
    /// Returns `false` and ignores the interface if `vrf` is not the VRF of a zone with a
    /// conntrack zone.
    pub fn add_interface(&mut self, vrf: &str, interface: impl Into<String>) -> bool {
        match self.vrfs.get_mut(vrf) {
            Some(entry) => {
                entry.interfaces.insert(interface.into());
                true
            }
            None => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.vrfs.is_empty()
    }

    /// Iterates over the VRF devices and their entries.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &VrfCtZoneEntry)> + '_ {
        self.vrfs.iter().map(|(vrf, entry)| (vrf.as_str(), entry))
    }

    /// Iterates over all interfaces whose traffic belongs to a conntrack zone.
    ///
    /// These are the VRF devices themselves, as packets pass the netfilter hooks on the VRF device
    /// as well, and the interfaces enslaved to them.
    pub fn interfaces(&self) -> impl Iterator<Item = (&str, VrfCtZone)> + '_ {
        self.iter().flat_map(|(vrf, entry)| {
            std::iter::once(vrf)
                .chain(entry.interfaces())
                .map(|interface| (interface, entry.ct_zone()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vrf_ct_zone_range() {
        assert_eq!(VrfCtZone::new(16384).map(VrfCtZone::index), Some(0));
        assert_eq!(VrfCtZone::new(17407).map(VrfCtZone::index), Some(1023));
        assert_eq!(VrfCtZone::new(16383), None);
        assert_eq!(VrfCtZone::new(17408), None);
    }

    #[test]
    fn vrf_ct_zones() {
        use crate::sdn::ZoneName;
        use crate::sdn::config::ZoneType;

        let zone = |name: &str, ct_zone: Option<u16>| {
            let mut zone =
                ZoneConfig::new(ZoneName::new(name.to_string()).unwrap(), ZoneType::Simple);
            zone.set_ct_zone(ct_zone.and_then(VrfCtZone::new));
            zone
        };

        let mut ct_zones = VrfCtZones::default();
        assert!(ct_zones.is_empty());

        ct_zones.add_zone(&zone("red", Some(16384)));
        ct_zones.add_zone(&zone("blue", Some(16389)));
        ct_zones.add_zone(&zone("green", None));

        assert!(ct_zones.add_interface("vrf_red", "vnetr1"));
        assert!(ct_zones.add_interface("vrf_red", "bond0.101"));
        assert!(ct_zones.add_interface("vrf_blue", "vnetb"));
        // VRFs that are not zone VRFs with a conntrack zone
        assert!(!ct_zones.add_interface("vrf_green", "vnetg"));
        assert!(!ct_zones.add_interface("vrf_mgmt", "eth0"));
        // the prefix is part of the name
        assert!(!ct_zones.add_interface("red", "eth1"));

        let entries: Vec<_> = ct_zones
            .iter()
            .map(|(vrf, entry)| {
                (
                    vrf,
                    entry.ct_zone().id(),
                    entry.interfaces().collect::<Vec<_>>(),
                )
            })
            .collect();

        assert_eq!(
            entries,
            [
                ("vrf_blue", 16389, vec!["vnetb"]),
                ("vrf_red", 16384, vec!["bond0.101", "vnetr1"]),
            ]
        );

        let interfaces: Vec<_> = ct_zones
            .interfaces()
            .map(|(interface, ct_zone)| (interface, ct_zone.id()))
            .collect();

        assert_eq!(
            interfaces,
            [
                ("vrf_blue", 16389),
                ("vnetb", 16389),
                ("vrf_red", 16384),
                ("bond0.101", 16384),
                ("vnetr1", 16384),
            ]
        );
    }
}

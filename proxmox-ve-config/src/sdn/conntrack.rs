//! Conntrack zones of SDN zones.
//!
//! Proxmox VE reserves the conntrack zones 16384 to 32767 (0x4000 to 0x7fff). These are all
//! conntrack zones whose two most significant bits are 01, so the whole block can be matched with a
//! single bitmask (`ct zone & 0xc000 == 0x4000`). SDN zones with a dedicated VRF get their
//! conntrack zone from the first 1024 conntrack zones of this block.

use serde::Deserialize;

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
}

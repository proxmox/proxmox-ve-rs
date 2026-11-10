use std::fmt;
use std::str::FromStr;

use anyhow::{Error, format_err};

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Vmid(u32);

proxmox_serde::forward_deserialize_to_from_str!(Vmid);
proxmox_serde::forward_serialize_to_display!(Vmid);

impl Vmid {
    pub fn new(id: u32) -> Self {
        Vmid(id)
    }

    pub fn raw_value(&self) -> u32 {
        self.0
    }
}

impl From<u32> for Vmid {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl proxmox_serde::perl::FromU32 for Vmid {
    fn from_u32(value: u32) -> Self {
        Self::new(value)
    }

    fn from_none<E: serde::de::Error>() -> Result<Self, E> {
        Err(E::invalid_type(serde::de::Unexpected::Option, &"a vmid"))
    }
}

impl fmt::Display for Vmid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for Vmid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            s.parse()
                .map_err(|_| format_err!("not a valid vmid: {s:?}"))?,
        ))
    }
}

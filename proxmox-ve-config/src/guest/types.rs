use std::fmt;
use std::str::FromStr;

use anyhow::{format_err, Error};
use serde_with::{DeserializeFromStr, SerializeDisplay};

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, SerializeDisplay, DeserializeFromStr,
)]
pub struct Vmid(u32);

impl Vmid {
    pub fn new(id: u32) -> Self {
        Vmid(id)
    }
}

impl From<u32> for Vmid {
    fn from(value: u32) -> Self {
        Self::new(value)
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

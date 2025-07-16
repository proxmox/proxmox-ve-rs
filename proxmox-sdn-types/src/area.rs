use std::{fmt::Display, net::Ipv4Addr};

use anyhow::Error;
use proxmox_schema::{ApiType, Schema, StringSchema, UpdaterType};
use serde_with::{DeserializeFromStr, SerializeDisplay};

/// An OSPF Area.
///
/// Internally the area is just a 32 bit number and is often represented in dotted-decimal
/// notation, like an IPv4. FRR also allows us to specify it as a number or an IPv4-Address.
/// To keep a nice user experience we keep whichever format the user entered.
#[derive(
    Debug, DeserializeFromStr, SerializeDisplay, Clone, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum Area {
    Number(u32),
    IpAddress(Ipv4Addr),
}

impl ApiType for Area {
    const API_SCHEMA: Schema =
        StringSchema::new("The OSPF area, which can be a number or a ip-address.").schema();
}

impl UpdaterType for Area {
    type Updater = Option<Area>;
}

impl std::str::FromStr for Area {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = Ipv4Addr::from_str(s) {
            Ok(Self::IpAddress(ip))
        } else if let Ok(number) = u32::from_str(s) {
            Ok(Self::Number(number))
        } else {
            anyhow::bail!("Area is not a number, nor an ip address");
        }
    }
}

impl Display for Area {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Area::Number(n) => write!(f, "{n}"),
            Area::IpAddress(i) => write!(f, "{i}"),
        }
    }
}

impl Area {
    /// Get the IPv4 representation of the area.
    ///
    /// If it already is stored as a an IPv4 address, it is returned directly.
    /// Otherwise, the number is converted to an IPv4 address.
    pub fn get_ipv4_representation(&self) -> Ipv4Addr {
        match self {
            Area::Number(n) => Ipv4Addr::from(*n),
            Area::IpAddress(ip) => *ip,
        }
    }
}

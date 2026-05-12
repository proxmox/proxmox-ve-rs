pub mod area;
pub mod bgp;
pub mod net;
pub mod openfabric;
pub mod wireguard;

use serde::{Deserialize, Serialize};

use proxmox_schema::api;

/// Enum for representing signedness of Integer in [`IntegerWithSign`].
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum Sign {
    #[serde(rename = "-")]
    Negative,
    #[serde(rename = "+")]
    Positive,
}

proxmox_serde::forward_display_to_serialize!(Sign);
proxmox_serde::forward_from_str_to_deserialize!(Sign);

/// An absolute or relative integer value.
///
/// This is used for representing certain keys in the FRR route maps (e.g. metric). They can be set
/// to either a static value (no sign) or to a value relative to the existing value (with sign).
/// For instance, a value of 50 would set the metric to 50, but a value of +50 would add 50 to the
/// existing metric value.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ModifyNumber {
    Absolute(u32),
    Relative(i32),
}

impl std::fmt::Display for ModifyNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absolute(n) => n.fmt(f),
            Self::Relative(n) => {
                if n.is_negative() {
                    n.fmt(f)
                } else {
                    write!(f, "+{n}")
                }
            }
        }
    }
}

impl std::str::FromStr for ModifyNumber {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with(&['+', '-']) {
            return Ok(Self::Relative(s.parse()?));
        }

        Ok(Self::Absolute(s.parse()?))
    }
}
proxmox_serde::forward_deserialize_to_from_str!(ModifyNumber);
proxmox_serde::forward_serialize_to_display!(ModifyNumber);

#[api(
    type: Integer,
    minimum: 1,
    maximum: 16_777_215,
)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
/// Represents a VXLAN VNI (24-bit unsigned integer).
pub struct Vni(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u32")] u32);

impl Vni {
    /// Returns the VNI as u32.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_parse_modify_number() {
        assert_eq!(
            ModifyNumber::from_str("+32").expect("valid ModifyNumber"),
            ModifyNumber::Relative(32),
        );

        assert_eq!(
            ModifyNumber::from_str("-31322").expect("valid ModifyNumber"),
            ModifyNumber::Relative(-31322),
        );

        assert_eq!(
            ModifyNumber::from_str("32").expect("valid ModifyNumber"),
            ModifyNumber::Absolute(32),
        );
    }

    #[test]
    fn test_display_modify_number() {
        for s in &["+32", "-1234", "43344"] {
            let integer_with_sign: ModifyNumber = s.parse().expect("is a valid ModifyNumber");
            assert_eq!(&integer_with_sign.to_string(), s)
        }
    }
}

pub mod config;
pub mod fabric;
#[cfg(feature = "frr")]
pub mod frr;
pub mod ipam;

use std::{error::Error, fmt::Display, str::FromStr};

use proxmox_network_types::ip_address::Cidr;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SdnNameError {
    Empty,
    TooLong,
    InvalidSymbols,
    InvalidSubnetCidr,
    InvalidSubnetFormat,
}

impl Error for SdnNameError {}

impl Display for SdnNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SdnNameError::TooLong => "name too long",
            SdnNameError::InvalidSymbols => "invalid symbols in name",
            SdnNameError::InvalidSubnetCidr => "invalid cidr in name",
            SdnNameError::InvalidSubnetFormat => "invalid format for subnet name",
            SdnNameError::Empty => "name is empty",
        })
    }
}

fn validate_sdn_name(name: &str) -> Result<(), SdnNameError> {
    if name.is_empty() {
        return Err(SdnNameError::Empty);
    }

    if name.len() > 8 {
        return Err(SdnNameError::TooLong);
    }

    // safe because of empty check
    if !name.chars().next().unwrap().is_ascii_alphabetic() {
        return Err(SdnNameError::InvalidSymbols);
    }

    if !name.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(SdnNameError::InvalidSymbols);
    }

    Ok(())
}

/// represents the name of an sdn zone
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ZoneName(String);

proxmox_serde::forward_deserialize_to_from_str!(ZoneName);

impl ZoneName {
    /// construct a new zone name
    ///
    /// # Errors
    ///
    /// This function will return an error if the name is empty, too long (>8 characters), starts
    /// with a non-alphabetic symbol or if there are non alphanumeric symbols contained in the name.
    pub fn new(name: String) -> Result<Self, SdnNameError> {
        validate_sdn_name(&name)?;
        Ok(ZoneName(name))
    }
}

impl AsRef<str> for ZoneName {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl FromStr for ZoneName {
    type Err = SdnNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl Display for ZoneName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// represents the name of an sdn vnet
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VnetName(String);

proxmox_serde::forward_deserialize_to_from_str!(VnetName);

impl VnetName {
    /// construct a new vnet name
    ///
    /// # Errors
    ///
    /// This function will return an error if the name is empty, too long (>8 characters), starts
    /// with a non-alphabetic symbol or if there are non alphanumeric symbols contained in the name.
    pub fn new(name: String) -> Result<Self, SdnNameError> {
        validate_sdn_name(&name)?;
        Ok(VnetName(name))
    }

    pub fn name(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for VnetName {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl FromStr for VnetName {
    type Err = SdnNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl Display for VnetName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// represents the name of an sdn subnet
///
/// # Textual representation
/// A subnet name has the form `{zone_id}-{cidr_ip}-{cidr_mask}`
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubnetName(ZoneName, Cidr);

proxmox_serde::forward_deserialize_to_from_str!(SubnetName);

impl SubnetName {
    pub fn new(zone: ZoneName, cidr: Cidr) -> Self {
        SubnetName(zone, cidr)
    }

    pub fn zone(&self) -> &ZoneName {
        &self.0
    }

    pub fn cidr(&self) -> &Cidr {
        &self.1
    }
}

impl FromStr for SubnetName {
    type Err = SdnNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((name, cidr_part)) = s.split_once('-') {
            if let Some((ip, netmask)) = cidr_part.split_once('-') {
                let zone_name = ZoneName::from_str(name)?;

                let cidr: Cidr = format!("{ip}/{netmask}")
                    .parse()
                    .map_err(|_| SdnNameError::InvalidSubnetCidr)?;

                return Ok(Self(zone_name, cidr));
            }
        }

        Err(SdnNameError::InvalidSubnetFormat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_name() {
        ZoneName::new("zone0".to_string()).unwrap();

        assert_eq!(ZoneName::new("".to_string()), Err(SdnNameError::Empty));

        assert_eq!(
            ZoneName::new("3qwe".to_string()),
            Err(SdnNameError::InvalidSymbols)
        );

        assert_eq!(
            ZoneName::new("qweqweqwe".to_string()),
            Err(SdnNameError::TooLong)
        );

        assert_eq!(
            ZoneName::new("qß".to_string()),
            Err(SdnNameError::InvalidSymbols)
        );
    }

    #[test]
    fn test_vnet_name() {
        VnetName::new("vnet0".to_string()).unwrap();

        assert_eq!(VnetName::new("".to_string()), Err(SdnNameError::Empty));

        assert_eq!(
            VnetName::new("3qwe".to_string()),
            Err(SdnNameError::InvalidSymbols)
        );

        assert_eq!(
            VnetName::new("qweqweqwe".to_string()),
            Err(SdnNameError::TooLong)
        );

        assert_eq!(
            VnetName::new("qß".to_string()),
            Err(SdnNameError::InvalidSymbols)
        );
    }

    #[test]
    fn test_subnet_name() {
        assert_eq!(
            "qweqweqwe-10.101.0.0-16".parse::<SubnetName>(),
            Err(SdnNameError::TooLong),
        );

        assert_eq!(
            "zone0_10.101.0.0-16".parse::<SubnetName>(),
            Err(SdnNameError::InvalidSubnetFormat),
        );

        assert_eq!(
            "zone0-10.101.0.0_16".parse::<SubnetName>(),
            Err(SdnNameError::InvalidSubnetFormat),
        );

        assert_eq!(
            "zone0-10.101.0.0-33".parse::<SubnetName>(),
            Err(SdnNameError::InvalidSubnetCidr),
        );

        assert_eq!(
            "zone0-10.101.0.0-16".parse::<SubnetName>().unwrap(),
            SubnetName::new(
                ZoneName::new("zone0".to_string()).unwrap(),
                Cidr::new_v4([10, 101, 0, 0], 16).unwrap()
            )
        )
    }
}

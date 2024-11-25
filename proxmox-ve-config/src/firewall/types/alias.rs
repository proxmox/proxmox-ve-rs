use std::fmt::Display;
use std::str::FromStr;

use anyhow::{bail, format_err, Error};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::firewall::parse::{match_name, match_non_whitespace};
use crate::firewall::types::address::Cidr;

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum AliasScope {
    Datacenter,
    Guest,
}

impl FromStr for AliasScope {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "dc" => AliasScope::Datacenter,
            "guest" => AliasScope::Guest,
            _ => bail!("invalid scope for alias: {s}"),
        })
    }
}

impl Display for AliasScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AliasScope::Datacenter => "dc",
            AliasScope::Guest => "guest",
        })
    }
}

/// Represents the name of an alias in a firewall rule in the RULES section of the firewall
/// configuration.
#[derive(Debug, Clone, DeserializeFromStr, SerializeDisplay)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct AliasName {
    scope: AliasScope,
    name: String,
}

impl Display for AliasName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}/{}", self.scope, self.name))
    }
}

impl FromStr for AliasName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('/') {
            Some((prefix, name)) if !name.is_empty() => Ok(Self::new(prefix.parse()?, name)),
            _ => {
                bail!("Invalid Alias name!")
            }
        }
    }
}

impl AliasName {
    /// Creates a new [`AliasName`].
    ///
    /// It will convert any ASCII characters contained in the name into lowercase. This is for
    /// maintaining backwards-compatiblity with pve-firewall, where all aliases are lowercased when
    /// reading from the config.
    pub fn new(scope: AliasScope, name: impl Into<String>) -> Self {
        let mut lowercase_name = name.into();
        lowercase_name.make_ascii_lowercase();

        Self {
            scope,
            name: lowercase_name,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn scope(&self) -> &AliasScope {
        &self.scope
    }
}

/// Represents an Alias stored in the ALIASES section of the firewall configuration.
///
/// Since they contain no scope in the firewall configuration itself, this struct also does not
/// contain a scope. The scope has to be inferred from the Context where this Alias is stored, if
/// that is necessary.
#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Alias {
    name: String,
    address: Cidr,
    comment: Option<String>,
}

impl Alias {
    /// Creates a new [`Alias`].
    ///
    /// It will convert any ASCII characters contained in the name into lowercase. This is for
    /// maintaining backwards-compatiblity with pve-firewall, where all aliases are lowercased when
    /// reading from the config.
    pub fn new(
        name: impl Into<String>,
        address: impl Into<Cidr>,
        comment: impl Into<Option<String>>,
    ) -> Self {
        let mut lowercase_name = name.into();
        lowercase_name.make_ascii_lowercase();

        Self {
            name: lowercase_name,
            address: address.into(),
            comment: comment.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn address(&self) -> &Cidr {
        &self.address
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }
}

impl FromStr for Alias {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (name, line) =
            match_name(s.trim_start()).ok_or_else(|| format_err!("expected an alias name"))?;

        let (address, line) = match_non_whitespace(line.trim_start())
            .ok_or_else(|| format_err!("expected a value for alias {name:?}"))?;

        let address: Cidr = address.parse()?;

        let line = line.trim_start();

        let comment = match line.strip_prefix('#') {
            Some(comment) => Some(comment.trim().to_string()),
            None if !line.is_empty() => bail!("trailing characters in alias: {line:?}"),
            None => None,
        };

        Ok(Alias::new(name, address, comment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_alias() {
        for alias in [
            "local_network 10.0.0.0/32",
            "test-_123-___-a---- 10.0.0.1/32",
        ] {
            alias.parse::<Alias>().expect("valid alias");
        }

        for alias in ["-- 10.0.0.1/32", "0asd 10.0.0.1/32", "__test 10.0.0.0/32"] {
            alias.parse::<Alias>().expect_err("invalid alias");
        }

        let alias = "pRoxMox 10.0.0.0/32 # a comment"
            .parse::<Alias>()
            .expect("valid alias");
        assert_eq!(alias.name(), "proxmox");
        assert_eq!(
            alias.address(),
            &Cidr::new_v4([10, 0, 0, 0], 32).expect("valid CIDR")
        );
        assert_eq!(alias.comment(), Some("a comment"));
    }

    #[test]
    fn test_parse_alias_name() {
        for name in ["dc/proxmox_123", "guest/proxmox-123"] {
            name.parse::<AliasName>().expect("valid alias name");
        }

        for name in ["proxmox/proxmox_123", "guests/proxmox-123", "dc/", "/name"] {
            name.parse::<AliasName>().expect_err("invalid alias name");
        }
    }

    #[test]
    fn test_parse_alias_case() {
        for name in ["dc/PROxMoX", "guest/PROXMOX"] {
            let alias_name = name.parse::<AliasName>().expect("valid alias name");
            assert_eq!(alias_name.name(), "proxmox");
        }
    }
}

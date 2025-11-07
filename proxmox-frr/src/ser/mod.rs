pub mod openfabric;
pub mod ospf;
pub mod route_map;
pub mod serializer;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::str::FromStr;

use crate::ser::route_map::{AccessList, ProtocolRouteMap, RouteMap};

use thiserror::Error;

/// Generic FRR router.
///
/// This generic FRR router contains all the protocols that we implement.
/// In FRR this is e.g.:
/// ```text
/// router openfabric test
/// !....
/// ! or
/// router ospf
/// !....
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Router {
    Openfabric(openfabric::OpenfabricRouter),
    Ospf(ospf::OspfRouter),
}

impl From<openfabric::OpenfabricRouter> for Router {
    fn from(value: openfabric::OpenfabricRouter) -> Self {
        Router::Openfabric(value)
    }
}

/// Generic FRR routername.
///
/// The variants represent different protocols. Some have `router <protocol> <name>`, others have
/// `router <protocol> <process-id>`, some only have `router <protocol>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RouterName {
    Openfabric(openfabric::OpenfabricRouterName),
    Ospf(ospf::OspfRouterName),
}

impl From<openfabric::OpenfabricRouterName> for RouterName {
    fn from(value: openfabric::OpenfabricRouterName) -> Self {
        Self::Openfabric(value)
    }
}

impl Display for RouterName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Openfabric(r) => r.fmt(f),
            Self::Ospf(r) => r.fmt(f),
        }
    }
}

/// The interface name is the same on ospf and openfabric, but it is an enum so that we can have
/// two different entries in the btreemap. This allows us to have an interface in a ospf and
/// openfabric fabric.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InterfaceName {
    Openfabric(CommonInterfaceName),
    Ospf(CommonInterfaceName),
}

impl Display for InterfaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceName::Openfabric(frr_word) => frr_word.fmt(f),
            InterfaceName::Ospf(frr_word) => frr_word.fmt(f),
        }
    }
}

/// Generic FRR Interface.
///
/// In FRR config it looks like this:
/// ```text
/// interface <name>
/// ! ...
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Interface {
    Openfabric(openfabric::OpenfabricInterface),
    Ospf(ospf::OspfInterface),
}

impl From<openfabric::OpenfabricInterface> for Interface {
    fn from(value: openfabric::OpenfabricInterface) -> Self {
        Self::Openfabric(value)
    }
}

impl From<ospf::OspfInterface> for Interface {
    fn from(value: ospf::OspfInterface) -> Self {
        Self::Ospf(value)
    }
}

#[derive(Error, Debug)]
pub enum FrrWordError {
    #[error("word is empty")]
    IsEmpty,
    #[error("word contains invalid character")]
    InvalidCharacter,
}

/// A simple FRR Word.
///
/// Every string argument or value in FRR is an FrrWord. FrrWords must only contain ascii
/// characters and must not have a whitespace.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FrrWord(String);

impl FrrWord {
    pub fn new<T: AsRef<str> + Into<String>>(name: T) -> Result<Self, FrrWordError> {
        if name.as_ref().is_empty() {
            return Err(FrrWordError::IsEmpty);
        }

        if name
            .as_ref()
            .as_bytes()
            .iter()
            .any(|c| !c.is_ascii() || c.is_ascii_whitespace())
        {
            eprintln!("invalid char in: \"{}\"", name.as_ref());
            return Err(FrrWordError::InvalidCharacter);
        }

        Ok(Self(name.into()))
    }
}

impl FromStr for FrrWord {
    type Err = FrrWordError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Display for FrrWord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for FrrWord {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Error, Debug)]
pub enum CommonInterfaceNameError {
    #[error("interface name too long")]
    TooLong,
}

/// Name of a interface, which is common between all protocols.
///
/// FRR itself doesn't enforce any limits, but the kernel does. Linux only allows interface names
/// to be a maximum of 16 bytes. This is enforced by this struct.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommonInterfaceName(String);

impl TryFrom<&str> for CommonInterfaceName {
    type Error = CommonInterfaceNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for CommonInterfaceName {
    type Error = CommonInterfaceNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl CommonInterfaceName {
    pub fn new<T: AsRef<str> + Into<String>>(s: T) -> Result<Self, CommonInterfaceNameError> {
        if s.as_ref().len() <= 15 {
            Ok(Self(s.into()))
        } else {
            Err(CommonInterfaceNameError::TooLong)
        }
    }
}

impl Display for CommonInterfaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Main FRR config.
///
/// Contains the two main frr building blocks: routers and interfaces. It also holds other
/// top-level FRR options, such as access-lists, router-maps and protocol-routemaps. This struct
/// gets generated using the `FrrConfigBuilder` in `proxmox-ve-config`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FrrConfig {
    pub router: BTreeMap<RouterName, Router>,
    pub interfaces: BTreeMap<InterfaceName, Interface>,
    pub access_lists: Vec<AccessList>,
    pub routemaps: Vec<RouteMap>,
    pub protocol_routemaps: BTreeSet<ProtocolRouteMap>,
}

impl FrrConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn router(&self) -> impl Iterator<Item = (&RouterName, &Router)> + '_ {
        self.router.iter()
    }

    pub fn interfaces(&self) -> impl Iterator<Item = (&InterfaceName, &Interface)> + '_ {
        self.interfaces.iter()
    }

    pub fn access_lists(&self) -> impl Iterator<Item = &AccessList> + '_ {
        self.access_lists.iter()
    }
    pub fn routemaps(&self) -> impl Iterator<Item = &RouteMap> + '_ {
        self.routemaps.iter()
    }

    pub fn protocol_routemaps(&self) -> impl Iterator<Item = &ProtocolRouteMap> + '_ {
        self.protocol_routemaps.iter()
    }
}

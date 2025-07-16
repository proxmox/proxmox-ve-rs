use serde::{Deserialize, Serialize};
use std::fmt::Display;

use proxmox_schema::{api, UpdaterType};

/// The OpenFabric CSNP Interval.
///
/// The Complete Sequence Number Packets (CSNP) interval in seconds. The interval range is 1 to
/// 600.
#[api(
    type: Integer,
    minimum: 1,
    maximum: 600,
)]
#[derive(Serialize, Deserialize, Hash, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct CsnpInterval(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u16")] u16);

impl UpdaterType for CsnpInterval {
    type Updater = Option<CsnpInterval>;
}

impl Display for CsnpInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The OpenFabric Hello Interval.
///
/// The Hello Interval for a given interface in seconds. The range is 1 to 600. Hello packets are
/// used to establish and maintain adjacency between OpenFabric neighbors.
#[api(
    type: Integer,
    minimum: 1,
    maximum: 600,
)]
#[derive(Serialize, Deserialize, Hash, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct HelloInterval(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u16")] u16);

impl UpdaterType for HelloInterval {
    type Updater = Option<HelloInterval>;
}

impl Display for HelloInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The OpenFabric Hello Multiplier.
///
/// This is the multiplier for the hello holding time on a given interface. The range is 2 to 100.
#[api(
    type: Integer,
    minimum: 2,
    maximum: 100,
)]
#[derive(Serialize, Deserialize, Hash, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct HelloMultiplier(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u16")] u16);

impl UpdaterType for HelloMultiplier {
    type Updater = Option<HelloMultiplier>;
}

impl Display for HelloMultiplier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

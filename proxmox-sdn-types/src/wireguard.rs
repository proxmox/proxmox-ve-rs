//! API types for the WireGuard fabric.

use std::fmt::Display;

use proxmox_schema::{api, UpdaterType};
use serde::{Deserialize, Serialize};

/// Persistent keep-alive interval. Specifies how often a authenticated, empty
/// packet will be sent to the peer to keep e.g. stateful firewall open or NAT
/// mappings.
///
/// Interval in seconds, between 1 and 65535 inclusive.
#[api(
    type: Integer,
    minimum: 1,
)]
#[derive(Serialize, Deserialize, Hash, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct PersistentKeepalive(
    #[serde(deserialize_with = "proxmox_serde::perl::deserialize_u16")] u16,
);

impl PersistentKeepalive {
    /// Determines whether the given `PersistentKeepalive` value means that it is
    /// turned off.
    pub fn is_off(&self) -> bool {
        self.0 == 0
    }

    pub fn raw(&self) -> u16 {
        self.0
    }
}

impl UpdaterType for PersistentKeepalive {
    type Updater = Option<PersistentKeepalive>;
}

impl Display for PersistentKeepalive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

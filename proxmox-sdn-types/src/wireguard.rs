//! API types for the WireGuard fabric.

use std::fmt::Display;

use proxmox_schema::{api, UpdaterType};
use serde::{Deserialize, Serialize};

/// Persistent keep-alive interval, in seconds, between 0 and 65535 inclusive.
///
/// When set to a non-zero value, an authenticated empty packet is sent to the
/// peer at that interval to keep stateful firewall mappings or NAT translations
/// open. A value of 0, or the absence of this property, disables the feature.
#[api(
    type: Integer,
    minimum: 0,
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

use serde::{Deserialize, Serialize};

use crate::ModifyNumber;

/// Represents a BGP metric value, as used in FRR.
///
/// A metric can either be a numeric value, or certain 'magic' values. For more information see the
/// respective enum variants.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum SetMetricValue {
    /// Set the metric to the round-trip-time.
    #[serde(rename = "rtt")]
    Rtt,
    /// Add the round-trip-time to the metric.
    #[serde(rename = "+rtt")]
    AddRtt,
    /// Subtract the round-trip-time from the metric.
    #[serde(rename = "-rtt")]
    SubtractRtt,
    /// Use the IGP value when importing from another IGP.
    #[serde(rename = "igp")]
    Igp,
    /// Use the accumulated IGP value when importing from another IGP.
    #[serde(rename = "aigp")]
    Aigp,
    /// Set the metric to a fixed numeric value.
    #[serde(untagged)]
    Numeric(ModifyNumber),
}

impl<T: Into<ModifyNumber>> From<T> for SetMetricValue {
    fn from(value: T) -> Self {
        Self::Numeric(value.into())
    }
}

/// An EVPN route-type, as used in the FRR route maps.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EvpnRouteType {
    Ead,
    MacIp,
    Multicast,
    #[serde(rename = "es")]
    EthernetSegment,
    Prefix,
}

/// An tag value, as used in the FRR route maps.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SetTagValue {
    Untagged,
    #[serde(untagged)]
    Numeric(#[serde(deserialize_with = "proxmox_serde::perl::deserialize_u32")] u32),
}

impl SetTagValue {
    pub fn new(value: u32) -> Self {
        SetTagValue::Numeric(value)
    }
}

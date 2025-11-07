use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Information about the Neighbor (Peer) of the Adjacency.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Neighbor {
    /// The full state of the neighbor. This is "{converged}/{role}".
    #[serde(rename = "nbrState")]
    pub neighbor_state: String,
    /// The uptime of the interface
    #[serde(rename = "upTime")]
    pub up_time: String,
    /// The real address of the peer.
    /// OSPF deduplicates neighbors, so if two areas have the same peer, OSPF selects one ip to
    /// drive the adjacency. This is the "real" ip that the neighbor has, so every area has another
    /// ip here.
    #[serde(rename = "ifaceAddress")]
    pub interface_address: String,
    /// The interface name of this adjacency. This is always a combination of interface
    /// name and address. e.g. "ens21:5.5.5.3".
    #[serde(rename = "ifaceName")]
    pub interface_name: String,
}

/// The parsed OSPF neighbors
#[derive(Debug, Deserialize, Default)]
pub struct Neighbors {
    /// The OSPF neighbors. This is nearly always a ip-address - neighbor mapping.
    pub neighbors: HashMap<String, Vec<Neighbor>>,
}

/// All possible OSPF network-types that can be returned from frr
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum NetworkType {
    #[serde(rename = "Null")]
    Null,
    #[serde(rename(deserialize = "POINTOPOINT", serialize = "Point-To-Point"))]
    PointToPoint,
    #[serde(rename(deserialize = "BROADCAST", serialize = "Broadcast"))]
    Broadcast,
    #[serde(rename = "NBMA")]
    Nbma,
    #[serde(rename(deserialize = "POINTOMULTIPOINT", serialize = "Point-To-Multipoint"))]
    PointToMultipoint,
    #[serde(rename(deserialize = "VIRTUALLINK", serialize = "Virtual Link"))]
    VirtualLink,
    #[serde(rename(deserialize = "LOOPBACK", serialize = "Loopback"))]
    Loopback,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Interface {
    /// The interface state
    pub if_up: bool,
    /// The network type (e.g. point-to-point, broadcast, etc.)
    ///
    /// Note there is also a "state" property, but that models the state of the interface (ism),
    /// which can also be "point-to-point", but it can also be e.g. "Down" or e.g. "DROther"!
    /// So networkType is the configured network type and state is the state of interface, which
    /// sometimes is the same as the networkType.
    pub network_type: NetworkType,
}

#[derive(Debug, Deserialize, Default)]
pub struct Interfaces {
    pub interfaces: HashMap<String, Interface>,
}

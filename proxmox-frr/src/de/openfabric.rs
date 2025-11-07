use serde::{Deserialize, Serialize};

/// State of the adjacency of a OpenFabric neighbor
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdjacencyState {
    Initializing,
    Up,
    Down,
    Unknown,
}

/// Neighbor Interface
///
/// Interface used to communicate with a specific neighbor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NeighborInterface {
    /// The name of the interface
    pub name: String,
    /// The state of the adjacency, this is "Up" when everything is well
    pub state: Option<AdjacencyState>,
    /// Time since the last adj-flap (basically the uptime)
    #[serde(rename = "last-ago")]
    pub last_ago: String,
}

/// Adjacency information
///
/// Circuits are Layer-2 Broadcast domains (Either point-to-point or LAN).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Circuit {
    /// The hostname of the adjacency peer
    pub adj: Option<String>,
    /// The interface of the neighbor
    pub interface: Option<NeighborInterface>,
}

/// An openfabric area the same as SDN fabric.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Area {
    /// The are name, this is the same as the fabric_id, so the name of the fabric.
    pub area: String,
    /// Circuits are Layer-2 Broadcast domains (Either point-to-point or LAN).
    pub circuits: Vec<Circuit>,
}

/// The parsed neighbors.
///
/// This models the output of:
/// `vtysh -c 'show openfabric neighbor json'`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Neighbors {
    /// Every sdn fabric is also an openfabric 'area'
    pub areas: Vec<Area>,
}

/// The NetworkType of a OpenFabric interface
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkType {
    #[serde(rename(deserialize = "p2p", serialize = "Point-To-Point"))]
    PointToPoint,
    #[serde(rename(deserialize = "lan", serialize = "Broadcast"))]
    Lan,
    #[serde(rename(deserialize = "loopback", serialize = "Loopback"))]
    Loopback,
    #[serde(rename = "Unknown")]
    Unknown,
}

/// The State of a OpenFabric interface
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CircuitState {
    Init,
    Config,
    Up,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub struct Interface {
    pub name: String,
    pub state: CircuitState,
    #[serde(rename = "type")]
    pub ty: NetworkType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceCircuits {
    pub interface: Interface,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct InterfaceArea {
    pub area: String,
    pub circuits: Vec<InterfaceCircuits>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Interfaces {
    pub areas: Vec<InterfaceArea>,
}

use std::{collections::HashMap, net::IpAddr};

use proxmox_network_types::ip_address::Cidr;
use serde::{Deserialize, Serialize};

pub mod evpn;
pub mod openfabric;
pub mod ospf;

/// A nexthop of a route
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NextHop {
    /// IP of the nexthop
    pub ip: Option<IpAddr>,
    /// Name of the outgoing interface
    #[serde(rename = "interfaceName")]
    pub interface_name: Option<String>,
    /// If the nexthop is active
    pub active: Option<bool>,
    /// If this nexthop entry is reachable from this host
    pub unreachable: Option<bool>,
    /// If this nexthop entry is a duplicate of another (the first one has this unset)
    pub duplicate: Option<bool>,
}

/// route
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Route {
    /// Array of all the nexthops associated with this route. When you have e.g. two
    /// connections between two nodes, there is going to be one route, but two nexthops.
    pub nexthops: Vec<NextHop>,
    /// Metric of the route
    pub metric: i32,
    /// Protocol from which the route originates
    pub protocol: String,
    #[serde(rename = "vrfName")]
    pub vrf_name: String,
    /// If the route is installed in the kernel routing table
    pub installed: Option<bool>,
}

/// Struct to parse zebra routes by FRR.
///
/// To get the routes from FRR, instead of asking the daemon of every protocol for their
/// routes we simply ask zebra which routes have been inserted and filter them by protocol.
/// The following command is used to accomplish this: `show ip route <protocol> json`.
/// This struct can be used the deserialize the output of that command.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Routes(pub HashMap<Cidr, Vec<Route>>);

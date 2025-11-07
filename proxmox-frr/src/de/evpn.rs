use std::{collections::HashMap, net::IpAddr};

use proxmox_network_types::mac_address::MacAddress;
use serde::Deserialize;
use serde_repr::Deserialize_repr;

/// All EVPN routes
#[derive(Debug, Default, Deserialize)]
pub struct Routes(pub HashMap<String, Entry>);

/// The evpn routes a stored in a hashtable, which has a numPrefix and numPath key at
/// the end which stores the number of paths and prefixes. These two keys have a i32
/// value, while the other entries have a normal [`Route`] entry.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Entry {
    /// Route
    Route(Route),
    // This stores the numPrefix and numPath properties (which are not used) (this is
    // a workaround)
    Metadata(i32),
}

/// An EVPN route
#[derive(Debug, Deserialize)]
pub struct Route {
    /// The full EVPN prefix
    pub prefix: String,
    /// Length of the prefix
    #[serde(rename = "prefixLen")]
    pub prefix_len: i32,
    /// Paths to the EVPN route
    pub paths: Vec<Vec<Path>>,
}

/// An EVPN Route Path
#[derive(Debug, Deserialize)]
pub struct Path {
    /// Is this path valid
    pub valid: bool,
    /// Is this the best path
    pub bestpath: Option<bool>,
    /// Reason for selection (longer explanatory string)
    #[serde(rename = "selectionReason")]
    pub selection_reason: Option<String>,
    /// From where the EVPN Route path comes
    #[serde(rename = "pathFrom")]
    pub path_from: PathFrom,
    /// EVPN route type
    #[serde(rename = "routeType")]
    pub route_type: RouteType,
    /// Ethernet tag
    #[serde(rename = "ethTag")]
    pub ethernet_tag: i32,
    /// Mac Address length
    #[serde(rename = "macLen")]
    pub mac_length: Option<i32>,
    /// Mac Address
    pub mac: Option<MacAddress>,
    /// IP Address lenght
    #[serde(rename = "ipLen")]
    pub ip_length: Option<i32>,
    /// IP Address
    pub ip: Option<IpAddr>,
    /// Local Preference of the path
    #[serde(rename = "locPrf")]
    pub local_preference: Option<i32>,
    /// Weight of the path
    pub weight: i32,
    /// PeerId, can be either IP or unspecified
    #[serde(rename = "peerId")]
    pub peer_id: PeerId,
    /// AS path of the EVPN route
    #[serde(rename = "path")]
    pub as_path: String,
    /// Origin of the route
    pub origin: Origin,
    /// Extended BGP Community
    #[serde(rename = "extendedCommunity")]
    pub extended_community: ExtendedCommunity,
    /// Nexthops
    pub nexthops: Vec<Nexthop>,
}

/// PeerId of the EVPN route path
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PeerId {
    /// IP Address
    IpAddr(IpAddr),
    /// Not specified
    Unspec(String),
}

/// Nexthop of a EVPN path
#[derive(Debug, Deserialize)]
pub struct Nexthop {
    /// IP of the nexthop
    pub ip: IpAddr,
    /// Hostname of the nexthop
    pub hostname: String,
    /// Afi of the ip
    pub afi: Option<Protocol>,
    /// Used
    pub used: bool,
}

/// Protocol AFI for a EVPN nexthop
#[derive(Debug, Deserialize)]
pub enum Protocol {
    /// IPV4
    #[serde(rename = "ipv4")]
    IPv4,
    /// IPV6
    #[serde(rename = "ipv6")]
    IPv6,
}

/// Extended Community for EVPN route
#[derive(Debug, Deserialize)]
pub struct ExtendedCommunity {
    /// String with all the BGP ExtendedCommunities (this also contains the
    /// RouteTarget)
    pub string: String,
}

/// Origin of the EVPN route
#[derive(Debug, Deserialize)]
pub enum Origin {
    /// Interior Gateway Protocol
    #[serde(rename = "IGP")]
    Igp,
    #[serde(rename = "EGP")]
    /// Exterior Gateway Protocol
    Egp,
    #[serde(rename = "incomplete")]
    /// Incomplete
    Incomplete,
}

/// EVPN RouteType
#[derive(Debug, Deserialize_repr)]
#[repr(u8)]
pub enum RouteType {
    /// EthernetAutoDiscovery
    EthernetAutoDiscovery = 1,
    /// MacIpAdvertisement
    MacIpAdvertisement = 2,
    /// InclusiveMulticastEthernetTag
    InclusiveMulticastEthernetTag = 3,
    /// EthernetSegment
    EthernetSegment = 4,
    /// IpPrefix
    IpPrefix = 5,
}

/// From where the EVPN route path comes
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathFrom {
    /// Internal
    Internal,
    /// External
    External,
}

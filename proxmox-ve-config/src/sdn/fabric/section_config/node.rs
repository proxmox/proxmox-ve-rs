use const_format::concatcp;
use proxmox_schema::api_types::{IP_V4_SCHEMA, IP_V6_SCHEMA};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use proxmox_network_types::ip_address::api_types::{Ipv4Addr, Ipv6Addr};

use proxmox_schema::{
    api, api_string_type, const_regex, AllOfSchema, ApiStringFormat, ApiType, ObjectSchema, Schema,
    StringSchema, UpdaterType,
};

use crate::sdn::fabric::section_config::{
    fabric::{FabricId, FABRIC_ID_REGEX_STR},
    protocol::openfabric::OpenfabricNodeProperties,
};

pub const NODE_ID_REGEX_STR: &str = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]){0,61}(?:[a-zA-Z0-9]){0,1})";

const_regex! {
    pub NODE_ID_REGEX = concatcp!(r"^", NODE_ID_REGEX_STR, r"$");
    pub NODE_SECTION_ID_REGEX = concatcp!(r"^", FABRIC_ID_REGEX_STR, r"_", NODE_ID_REGEX_STR, r"$");
}

pub const NODE_ID_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&NODE_ID_REGEX);
pub const NODE_SECTION_ID_FORMAT: ApiStringFormat =
    ApiStringFormat::Pattern(&NODE_SECTION_ID_REGEX);

api_string_type! {
    /// ID of a node in an SDN fabric.
    ///
    /// This corresponds to the hostname of the node.
    #[api(format: &NODE_ID_FORMAT)]
    #[derive(Debug, Deserialize, Serialize, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, UpdaterType)]
    pub struct NodeId(String);
}

/// ID of a node in the section config.
///
/// This corresponds to the ID of the fabric, that contains this node, as well as the hostname of
/// the node. They are joined by an underscore.
///
/// This struct is a helper for parsing the string into the two separate parts. It (de-)serializes
/// from and into a String.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, SerializeDisplay, DeserializeFromStr,
)]
pub struct NodeSectionId {
    pub(crate) fabric_id: FabricId,
    pub(crate) node_id: NodeId,
}

impl ApiType for NodeSectionId {
    const API_SCHEMA: Schema = StringSchema::new("ID of a SDN node in the section config")
        .format(&NODE_SECTION_ID_FORMAT)
        .schema();
}

impl NodeSectionId {
    /// Build a new [`NodeSectionId`] from the passed [`FabricId`] and [`NodeId`].
    pub fn new(fabric_id: FabricId, node_id: NodeId) -> Self {
        Self { fabric_id, node_id }
    }

    /// Get the fabric part of the [`NodeSectionId`].
    pub fn fabric_id(&self) -> &FabricId {
        &self.fabric_id
    }

    /// Get the node part of the [`NodeSectionId`].
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }
}

impl std::str::FromStr for NodeSectionId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (fabric_id, node_id) = value.split_once("_").unwrap();

        Ok(Self {
            fabric_id: FabricId::from_string(fabric_id.to_string())?,
            node_id: NodeId::from_string(node_id.to_string())?,
        })
    }
}

impl std::fmt::Display for NodeSectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}_{}", self.fabric_id, self.node_id)
    }
}

const NODE_SECTION_SCHEMA: Schema = ObjectSchema::new(
    "Common properties for a node in an SDN fabric.",
    &[
        ("id", false, &NodeSectionId::API_SCHEMA),
        ("ip", true, &IP_V4_SCHEMA),
        ("ip6", true, &IP_V6_SCHEMA),
    ],
)
.schema();

/// A node section in an SDN fabric config.
///
/// This struct contains all the properties that are required for any node, regardless of
/// protocol. Properties that are specific to a protocol can be passed via the type parameter.
///
/// This is mainly used by the [`Node`] and [`super::Section`] enums to specify which types of nodes can exist,
/// without having to re-define common properties for every node. It also simplifies accessing
/// common properties by encapsulating the specific properties to [`NodeSection<T>::properties`].
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct NodeSection<T> {
    pub(crate) id: NodeSectionId,

    /// IPv4 for this node in the fabric
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip: Option<Ipv4Addr>,

    /// IPv6 for this node in the fabric
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip6: Option<Ipv6Addr>,

    #[serde(flatten)]
    pub(crate) properties: T,
}

impl<T> NodeSection<T> {
    /// Get the protocol-specific properties of the [`NodeSection`].
    pub fn properties(&self) -> &T {
        &self.properties
    }

    /// Get a mutable reference to the protocol-specific properties of the [`NodeSection`].
    pub fn properties_mut(&mut self) -> &mut T {
        &mut self.properties
    }

    /// Get the id of the [`NodeSection`].
    pub fn id(&self) -> &NodeSectionId {
        &self.id
    }

    /// Get the IPv4 address (Router-ID) of the [`NodeSection`].
    ///
    /// Either the [`NodeSection::ip`] (IPv4) address or the [`NodeSection::ip6`] (IPv6) address *must*
    /// be set. This is checked during the validation, so it's guaranteed. OpenFabric can also be
    /// used dual-stack, so both IPv4 and IPv6 addresses can be set.
    pub fn ip(&self) -> Option<std::net::Ipv4Addr> {
        self.ip.as_deref().copied()
    }

    /// Get the IPv6 address (Router-ID) of the [`NodeSection`].
    ///
    /// Either the [`NodeSection::ip`] (IPv4) address or the [`NodeSection::ip6`] (IPv6) address *must*
    /// be set. This is checked during the validation, so it's guaranteed. OpenFabric can also be
    /// used dual-stack, so both IPv4 and IPv6 addresses can be set.
    pub fn ip6(&self) -> Option<std::net::Ipv6Addr> {
        self.ip6.as_deref().copied()
    }
}

impl<T: ApiType> ApiType for NodeSection<T> {
    const API_SCHEMA: Schema = AllOfSchema::new(
        "Node in an SDN fabric.",
        &[&NODE_SECTION_SCHEMA, &T::API_SCHEMA],
    )
    .schema();
}

/// Enum containing all types of nodes.
#[api(
    "id-property": "id",
    "id-schema": {
        type: String,
        description: "Node ID",
        format: &NODE_ID_FORMAT,
    },
    "type-key": "protocol",
)]
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case", tag = "protocol")]
pub enum Node {
    Openfabric(NodeSection<OpenfabricNodeProperties>),
}

impl Node {
    /// Get the id of the [`Node`].
    pub fn id(&self) -> &NodeSectionId {
        match self {
            Node::Openfabric(node_section) => node_section.id(),
        }
    }

    /// Get the ip (IPv4) of the [`Node`].
    pub fn ip(&self) -> Option<std::net::Ipv4Addr> {
        match self {
            Node::Openfabric(node_section) => node_section.ip(),
        }
    }

    /// Get the ip (IPv6) of the [`Node`].
    pub fn ip6(&self) -> Option<std::net::Ipv6Addr> {
        match self {
            Node::Openfabric(node_section) => node_section.ip6(),
        }
    }
}

impl From<NodeSection<OpenfabricNodeProperties>> for Node {
    fn from(value: NodeSection<OpenfabricNodeProperties>) -> Self {
        Self::Openfabric(value)
    }
}

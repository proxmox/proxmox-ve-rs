use const_format::concatcp;
use proxmox_schema::api_types::{IP_V4_SCHEMA, IP_V6_SCHEMA};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use proxmox_network_types::ip_address::api_types::{Ipv4Addr, Ipv6Addr};

use proxmox_schema::{
    api, api_string_type, const_regex, AllOfSchema, ApiStringFormat, ApiType, ObjectSchema, Schema,
    StringSchema, UpdaterType,
};

use crate::common::valid::Validatable;
use crate::sdn::fabric::section_config::{
    fabric::{FabricId, FABRIC_ID_REGEX_STR},
    protocol::{openfabric::OpenfabricNodeProperties, ospf::OspfNodeProperties},
};
use crate::sdn::fabric::FabricConfigError;

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
    Ospf(NodeSection<OspfNodeProperties>),
}

impl Node {
    /// Get the id of the [`Node`].
    pub fn id(&self) -> &NodeSectionId {
        match self {
            Node::Openfabric(node_section) => node_section.id(),
            Node::Ospf(node_section) => node_section.id(),
        }
    }

    /// Get the ip (IPv4) of the [`Node`].
    pub fn ip(&self) -> Option<std::net::Ipv4Addr> {
        match self {
            Node::Openfabric(node_section) => node_section.ip(),
            Node::Ospf(node_section) => node_section.ip(),
        }
    }

    /// Get the ip (IPv6) of the [`Node`].
    pub fn ip6(&self) -> Option<std::net::Ipv6Addr> {
        match self {
            Node::Openfabric(node_section) => node_section.ip6(),
            Node::Ospf(node_section) => node_section.ip6(),
        }
    }
}

impl Validatable for Node {
    type Error = FabricConfigError;

    fn validate(&self) -> Result<(), Self::Error> {
        match self {
            Node::Openfabric(node_section) => node_section.validate(),
            Node::Ospf(node_section) => node_section.validate(),
        }
    }
}

impl From<NodeSection<OpenfabricNodeProperties>> for Node {
    fn from(value: NodeSection<OpenfabricNodeProperties>) -> Self {
        Self::Openfabric(value)
    }
}

impl From<NodeSection<OspfNodeProperties>> for Node {
    fn from(value: NodeSection<OspfNodeProperties>) -> Self {
        Self::Ospf(value)
    }
}

/// API types for SDN fabric node configurations.
///
/// This module provides specialized types that are used for API interactions when retrieving,
/// creating, or updating fabric/node configurations. These types serialize differently than their
/// section-config configuration counterparts to be nicer client-side.
///
/// The module includes:
/// - [`api::NodeData<T>`]: API-friendly version of [`NodeSection<T>`] that flattens the node identifier
///   into separate `fabric_id` and `node_id` fields
/// - [`api::Node`]: API-version of [`super::Node`]
/// - [`api::NodeDataUpdater`]
/// - [`api::NodeDeletableProperties`]
///
/// These types include conversion methods to transform between API representations and internal
/// configuration objects.
pub mod api {
    use serde::{Deserialize, Serialize};

    use proxmox_schema::{Updater, UpdaterType};

    use crate::sdn::fabric::section_config::protocol::{
        openfabric::{
            OpenfabricNodeDeletableProperties, OpenfabricNodeProperties,
            OpenfabricNodePropertiesUpdater,
        },
        ospf::{OspfNodeDeletableProperties, OspfNodeProperties, OspfNodePropertiesUpdater},
    };

    use super::*;

    /// API-equivalent to [`NodeSection<T>`].
    ///
    /// The difference is that instead of serializing fabric_id and node_id into a single string
    /// (`{fabric_id}_{node_id}`), are serialized normally as two distinct properties. This
    /// prevents us from needing to parse the node_id in the frontend using `split("_")`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NodeData<T> {
        fabric_id: FabricId,
        node_id: NodeId,

        /// IPv4 for this node in the Ospf fabric
        #[serde(skip_serializing_if = "Option::is_none")]
        ip: Option<Ipv4Addr>,

        /// IPv6 for this node in the Ospf fabric
        #[serde(skip_serializing_if = "Option::is_none")]
        ip6: Option<Ipv6Addr>,

        #[serde(flatten)]
        properties: T,
    }

    impl<T> From<NodeSection<T>> for NodeData<T> {
        fn from(value: NodeSection<T>) -> Self {
            Self {
                fabric_id: value.id.fabric_id,
                node_id: value.id.node_id,
                ip: value.ip,
                ip6: value.ip6,
                properties: value.properties,
            }
        }
    }

    impl<T> From<NodeData<T>> for NodeSection<T> {
        fn from(value: NodeData<T>) -> Self {
            let id = NodeSectionId::new(value.fabric_id, value.node_id);

            Self {
                id,
                ip: value.ip,
                ip6: value.ip6,
                properties: value.properties,
            }
        }
    }

    /// API-equivalent to [`super::Node`].
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case", tag = "protocol")]
    pub enum Node {
        Openfabric(NodeData<OpenfabricNodeProperties>),
        Ospf(NodeData<OspfNodeProperties>),
    }

    impl From<super::Node> for Node {
        fn from(value: super::Node) -> Self {
            match value {
                super::Node::Openfabric(node_section) => Self::Openfabric(node_section.into()),
                super::Node::Ospf(node_section) => Self::Ospf(node_section.into()),
            }
        }
    }

    impl From<Node> for super::Node {
        fn from(value: Node) -> Self {
            match value {
                Node::Openfabric(node_section) => Self::Openfabric(node_section.into()),
                Node::Ospf(node_section) => Self::Ospf(node_section.into()),
            }
        }
    }

    impl UpdaterType for NodeData<OpenfabricNodeProperties> {
        type Updater =
            NodeDataUpdater<OpenfabricNodePropertiesUpdater, OpenfabricNodeDeletableProperties>;
    }

    impl UpdaterType for NodeData<OspfNodeProperties> {
        type Updater = NodeDataUpdater<OspfNodePropertiesUpdater, OspfNodeDeletableProperties>;
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NodeDataUpdater<T, D> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) ip: Option<Ipv4Addr>,

        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) ip6: Option<Ipv6Addr>,

        #[serde(flatten)]
        pub(crate) properties: T,

        #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
        pub(crate) delete: Vec<NodeDeletableProperties<D>>,
    }

    impl<T: UpdaterType + Updater, D> UpdaterType for NodeDataUpdater<T, D> {
        type Updater = NodeDataUpdater<T::Updater, D>;
    }

    impl<T: Updater, D> Updater for NodeDataUpdater<T, D> {
        fn is_empty(&self) -> bool {
            T::is_empty(&self.properties)
                && self.ip.is_none()
                && self.ip6.is_none()
                && self.delete.is_empty()
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case", tag = "protocol")]
    pub enum NodeUpdater {
        Openfabric(
            NodeDataUpdater<OpenfabricNodePropertiesUpdater, OpenfabricNodeDeletableProperties>,
        ),
        Ospf(NodeDataUpdater<OspfNodePropertiesUpdater, OspfNodeDeletableProperties>),
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum NodeDeletableProperties<T> {
        Ip,
        Ip6,
        #[serde(untagged)]
        Protocol(T),
    }
}

pub mod fabric;
pub mod interface;
pub mod node;
pub mod protocol;

use const_format::concatcp;
use serde::{Deserialize, Serialize};

use crate::sdn::fabric::section_config::{
    fabric::{Fabric, FabricSection, FABRIC_ID_REGEX_STR},
    node::{Node, NodeSection, NODE_ID_REGEX_STR},
    protocol::{
        openfabric::{OpenfabricNodeProperties, OpenfabricProperties},
        ospf::{OspfNodeProperties, OspfProperties},
    },
};

use proxmox_schema::{api, const_regex, ApiStringFormat};

/// Represents a value that can be one of two given types.
///
/// This is used for the fabrics section config, where values could either be Fabrics or Nodes. It
/// can be used to split the sections contained in the config into their concrete types safely.
pub enum FabricOrNode<F, N> {
    Fabric(F),
    Node(N),
}

impl From<Section> for FabricOrNode<Fabric, Node> {
    fn from(section: Section) -> Self {
        match section {
            Section::OpenfabricFabric(fabric_section) => Self::Fabric(fabric_section.into()),
            Section::OspfFabric(fabric_section) => Self::Fabric(fabric_section.into()),
            Section::OpenfabricNode(node_section) => Self::Node(node_section.into()),
            Section::OspfNode(node_section) => Self::Node(node_section.into()),
        }
    }
}

const_regex! {
    pub SECTION_ID_REGEX = concatcp!(r"^", FABRIC_ID_REGEX_STR, r"(?:_", NODE_ID_REGEX_STR, r")?$");
}

pub const SECTION_ID_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&SECTION_ID_REGEX);

/// A section in the SDN fabrics config.
///
/// It contains two variants for every protocol: The fabric and the node. They are represented
/// respectively by [`FabricSection`] and [`NodeSection`] which encapsulate the common properties
/// of fabrics and nodes and take the specific properties for the protocol as a type parameter.
#[api(
    "id-property": "id",
    "id-schema": {
        type: String,
        description: "fabric/node id",
        format: &SECTION_ID_FORMAT,
    },
    "type-key": "type",
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum Section {
    OpenfabricFabric(FabricSection<OpenfabricProperties>),
    OspfFabric(FabricSection<OspfProperties>),
    OpenfabricNode(NodeSection<OpenfabricNodeProperties>),
    OspfNode(NodeSection<OspfNodeProperties>),
}

impl From<FabricSection<OpenfabricProperties>> for Section {
    fn from(section: FabricSection<OpenfabricProperties>) -> Self {
        Self::OpenfabricFabric(section)
    }
}

impl From<FabricSection<OspfProperties>> for Section {
    fn from(section: FabricSection<OspfProperties>) -> Self {
        Self::OspfFabric(section)
    }
}

impl From<NodeSection<OpenfabricNodeProperties>> for Section {
    fn from(section: NodeSection<OpenfabricNodeProperties>) -> Self {
        Self::OpenfabricNode(section)
    }
}

impl From<NodeSection<OspfNodeProperties>> for Section {
    fn from(section: NodeSection<OspfNodeProperties>) -> Self {
        Self::OspfNode(section)
    }
}

impl From<Fabric> for Section {
    fn from(fabric: Fabric) -> Self {
        match fabric {
            Fabric::Openfabric(fabric_section) => fabric_section.into(),
            Fabric::Ospf(fabric_section) => fabric_section.into(),
        }
    }
}

impl From<Node> for Section {
    fn from(node: Node) -> Self {
        match node {
            Node::Openfabric(node_section) => node_section.into(),
            Node::Ospf(node_section) => node_section.into(),
        }
    }
}

pub mod fabric;
pub mod interface;
pub mod node;
pub mod protocol;

use const_format::concatcp;
use protocol::wireguard::WireGuardProperties;
use serde::{Deserialize, Serialize};

use crate::sdn::fabric::section_config::{
    fabric::{Fabric, FabricSection, FABRIC_ID_REGEX_STR},
    node::{Node, NodeSection, NODE_ID_REGEX_STR},
    protocol::{
        openfabric::{OpenfabricNodeProperties, OpenfabricProperties},
        ospf::{OspfNodeProperties, OspfProperties},
        wireguard::WireGuardNode,
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
            Section::WireGuardFabric(fabric_section) => Self::Fabric(fabric_section.into()),
            Section::OpenfabricNode(node_section) => Self::Node(node_section.into()),
            Section::OspfNode(node_section) => Self::Node(node_section.into()),
            Section::WireGuardNode(node_section) => Self::Node(node_section.into()),
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
    #[serde(rename = "wireguard_fabric")]
    WireGuardFabric(FabricSection<WireGuardProperties>),
    OpenfabricNode(NodeSection<OpenfabricNodeProperties>),
    OspfNode(NodeSection<OspfNodeProperties>),
    #[serde(rename = "wireguard_node")]
    WireGuardNode(NodeSection<WireGuardNode>),
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

impl From<FabricSection<WireGuardProperties>> for Section {
    fn from(section: FabricSection<WireGuardProperties>) -> Self {
        Self::WireGuardFabric(section)
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

impl From<NodeSection<WireGuardNode>> for Section {
    fn from(section: NodeSection<WireGuardNode>) -> Self {
        Self::WireGuardNode(section)
    }
}

impl From<Fabric> for Section {
    fn from(fabric: Fabric) -> Self {
        match fabric {
            Fabric::Openfabric(fabric_section) => fabric_section.into(),
            Fabric::Ospf(fabric_section) => fabric_section.into(),
            Fabric::WireGuard(fabric_section) => fabric_section.into(),
        }
    }
}

impl From<Node> for Section {
    fn from(node: Node) -> Self {
        match node {
            Node::Openfabric(node_section) => node_section.into(),
            Node::Ospf(node_section) => node_section.into(),
            Node::WireGuard(node_section) => node_section.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::sdn::fabric::FabricConfig;
    use proxmox_section_config::typed::ApiSectionDataEntry;

    use super::*;

    #[test]
    fn test_wireguard_fabric() -> Result<(), anyhow::Error> {
        let section_config = r#"
wireguard_fabric: wireg

wireguard_node: wireg_external
    role external
    endpoint 192.0.2.1:123
    public_key Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=

wireguard_node: wireg_pve1
    role internal
    endpoint 192.0.2.2
    interfaces name=wg0,listen_port=51111,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    peers type=internal,node=pve2,node_iface=wg0,iface=wg0

wireguard_node: wireg_pve2
    role internal
    endpoint 192.0.2.3
    interfaces name=wg0,listen_port=51111,public_key=Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=
    peers type=internal,node=pve1,node_iface=wg0,iface=wg0
"#;
        let parsed_config = Section::parse_section_config("fabrics.cfg", section_config)?;
        FabricConfig::from_section_config(parsed_config).expect("valid wireguard configuration");

        Ok(())
    }
}

use std::collections::HashMap;
use std::ops::Deref;

use anyhow::bail;

use proxmox_network_types::endpoint::ServiceEndpoint;
use proxmox_network_types::ip_address::{Ipv4Cidr, Ipv6Cidr};
use proxmox_sdn_types::wireguard::PersistentKeepalive;
use proxmox_wireguard::{WireGuardConfig, WireGuardInterface, WireGuardPeer};

use crate::common::valid::Valid;
use crate::sdn::fabric::section_config::fabric::Fabric;
use crate::sdn::fabric::section_config::node::Node;
use crate::sdn::fabric::section_config::protocol::wireguard::private_keys::WireGuardPrivateKeys;
use crate::sdn::fabric::section_config::protocol::wireguard::{WireGuardNode, WireGuardNodePeer};
use crate::sdn::fabric::{section_config::node::NodeId, FabricConfig};

pub struct WireGuardConfigBuilder {
    fabrics: Valid<FabricConfig>,
    private_keys: WireGuardPrivateKeys,
}

impl WireGuardConfigBuilder {
    pub fn new(fabrics: Valid<FabricConfig>, private_keys: WireGuardPrivateKeys) -> Self {
        Self {
            fabrics,
            private_keys,
        }
    }

    pub fn build(
        self,
        current_node: NodeId,
    ) -> Result<HashMap<String, WireGuardConfig>, anyhow::Error> {
        let mut wireguard_config = HashMap::new();

        for fabric_entry in self.fabrics.values() {
            let Fabric::WireGuard(fabric_config) = fabric_entry.fabric() else {
                continue;
            };

            let Ok(Node::WireGuard(node_config)) = fabric_entry.get_node(&current_node) else {
                continue;
            };

            let WireGuardNode::Internal(node_properties) = node_config.properties() else {
                continue;
            };

            for interface in node_properties.interfaces() {
                let private_key = self
                    .private_keys
                    .get(&current_node, interface.name())
                    .ok_or_else(|| anyhow::anyhow!("could not find private key for node"))?;

                let wireguard_interface = WireGuardInterface {
                    private_key: *private_key,
                    listen_port: Some(interface.listen_port),
                    fw_mark: None,
                };

                let mut wireguard_peers = Vec::new();

                for peer in &node_properties.peers {
                    let peer = peer.deref();

                    let Ok(Node::WireGuard(referenced_node)) = fabric_entry.get_node(peer.node())
                    else {
                        bail!(
                            "could not find node referenced in peer definition: {}",
                            peer.node()
                        )
                    };

                    let peer_config = match (referenced_node.properties(), peer) {
                        (
                            WireGuardNode::Internal(wireguard_node),
                            WireGuardNodePeer::Internal(peer),
                        ) => {
                            if peer.iface != interface.name {
                                continue;
                            }

                            let peer_interface = wireguard_node
                                .interfaces()
                                .find(|interface| interface.name == peer.node_iface)
                                .ok_or_else(|| {
                                    anyhow::format_err!("could not find referenced iface")
                                })?;

                            let endpoint = peer
                                .endpoint
                                .as_ref()
                                .or(wireguard_node.endpoint.as_ref())
                                .map(|endpoint| {
                                    ServiceEndpoint::new(
                                        endpoint.to_string(),
                                        peer_interface.listen_port,
                                    )
                                });

                            let mut allowed_ips = Vec::new();

                            if let Some(ip) = referenced_node.ip() {
                                allowed_ips.push(Ipv4Cidr::from(ip).into())
                            }

                            if let Some(ip) = peer_interface.ip() {
                                allowed_ips.push(Ipv4Cidr::new(*ip.address(), 32)?.into())
                            }

                            if let Some(ip) = peer_interface.ip6() {
                                allowed_ips.push(Ipv6Cidr::new(*ip.address(), 128)?.into())
                            }

                            allowed_ips.extend(&wireguard_node.allowed_ips);
                            allowed_ips.extend(&peer.allowed_ips);

                            WireGuardPeer {
                                public_key: peer_interface.public_key,
                                preshared_key: None,
                                allowed_ips,
                                endpoint,
                                persistent_keepalive: fabric_config
                                    .properties()
                                    .persistent_keepalive
                                    .as_ref()
                                    .map(PersistentKeepalive::raw),
                            }
                        }
                        (
                            WireGuardNode::External(referenced_node),
                            WireGuardNodePeer::External(peer),
                        ) => {
                            if peer.iface != interface.name {
                                continue;
                            }

                            let mut allowed_ips = Vec::new();
                            allowed_ips.extend(&referenced_node.allowed_ips);
                            allowed_ips.extend(&peer.allowed_ips);

                            let endpoint = peer
                                .endpoint
                                .clone()
                                .unwrap_or_else(|| referenced_node.endpoint.clone());

                            WireGuardPeer {
                                public_key: referenced_node.public_key,
                                preshared_key: None,
                                allowed_ips,
                                endpoint: Some(endpoint),
                                persistent_keepalive: fabric_config
                                    .properties()
                                    .persistent_keepalive
                                    .as_ref()
                                    .map(PersistentKeepalive::raw),
                            }
                        }
                        _ => {
                            bail!("invalid combination of peer / node types")
                        }
                    };

                    wireguard_peers.push(peer_config);
                }

                wireguard_config.insert(
                    interface.name.to_string(),
                    WireGuardConfig {
                        interface: wireguard_interface,
                        peers: wireguard_peers,
                    },
                );
            }
        }

        Ok(wireguard_config)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use proxmox_section_config::typed::ApiSectionDataEntry;
    use proxmox_wireguard::PrivateKey;

    use crate::sdn::fabric::{
        section_config::{protocol::wireguard::WireGuardInterfaceName, Section},
        FabricConfig,
    };

    use super::*;

    fn mock_private_key() -> PrivateKey {
        let bytes: [u8; 32] =
            proxmox_base64::decode("qGXl+84iE1teMyQeL1DgkuLivKKYasx6fOYqBfr3QEI=")
                .expect("valid base64")
                .try_into()
                .expect("is 32 byte array");

        PrivateKey::from(bytes)
    }

    fn mock_private_key_data(interfaces: &[&(&str, &str)]) -> WireGuardPrivateKeys {
        let mut private_keys = BTreeMap::new();

        for (node_id, interface_name) in interfaces {
            let interfaces: &mut BTreeMap<WireGuardInterfaceName, PrivateKey> = private_keys
                .entry(NodeId::from_str(node_id).unwrap())
                .or_default();

            interfaces.insert(
                WireGuardInterfaceName::from_str(interface_name).unwrap(),
                mock_private_key(),
            );
        }

        WireGuardPrivateKeys(private_keys)
    }

    #[test]
    fn test_wireguard_config_generation() -> Result<(), anyhow::Error> {
        let section_config = r#"
wireguard_fabric: wireg

wireguard_node: wireg_external
    role external
    endpoint 192.0.2.1:123
    allowed_ips 198.51.0.123/32
    public_key O+Kzrochm6klMILjSKVw83xb3YyXXLpmZj9n/ICM5xE=

wireguard_node: wireg_pve1
    role internal
    endpoint 192.0.2.2
    allowed_ips 203.0.113.0/25
    interfaces name=wg0,listen_port=51111,public_key=GDPUAnPOY5xGIjYXmcGyXZXbocjBr21dGQ5vwnjmdzA=,ip=198.51.100.1/24
    peers type=internal,node=pve2,node_iface=wg0,iface=wg0

wireguard_node: wireg_pve2
    role internal
    endpoint 192.0.2.3
    interfaces name=wg0,listen_port=51111,public_key=y0kOpXfo9ff4KoUwO3H1cRuwObbKwsK8mAkwXxNvKUc=
    peers type=internal,node=pve1,node_iface=wg0,iface=wg0
    peers type=external,node=external,iface=wg0
"#;
        let mut parsed_config = Section::parse_section_config("fabrics.cfg", section_config)?;

        let mut fabric_config = FabricConfig::from_section_config(parsed_config)
            .expect("valid wireguard configuration");

        let private_keys = mock_private_key_data(&[&("pve1", "wg0"), &("pve2", "wg0")]);

        let mut builder = WireGuardConfigBuilder::new(fabric_config, private_keys.clone());

        let pve1_wg0_config = r#"[Interface]
PrivateKey = qGXl+84iE1teMyQeL1DgkuLivKKYasx6fOYqBfr3QEI=
ListenPort = 51111

[Peer]
PublicKey = y0kOpXfo9ff4KoUwO3H1cRuwObbKwsK8mAkwXxNvKUc=
Endpoint = 192.0.2.3:51111
"#;

        pretty_assertions::assert_eq!(
            pve1_wg0_config,
            builder
                .build("pve1".parse()?)?
                .remove("wg0")
                .expect("wg0 config has been generated")
                .to_raw_config()
                .expect("wireguard config can be serialized")
        );

        parsed_config = Section::parse_section_config("fabrics.cfg", section_config)?;
        fabric_config = FabricConfig::from_section_config(parsed_config)
            .expect("valid wireguard configuration");

        builder = WireGuardConfigBuilder::new(fabric_config, private_keys);

        let pve2_wg0_config = r#"[Interface]
PrivateKey = qGXl+84iE1teMyQeL1DgkuLivKKYasx6fOYqBfr3QEI=
ListenPort = 51111

[Peer]
PublicKey = GDPUAnPOY5xGIjYXmcGyXZXbocjBr21dGQ5vwnjmdzA=
AllowedIPs = 198.51.100.1/32, 203.0.113.0/25
Endpoint = 192.0.2.2:51111

[Peer]
PublicKey = O+Kzrochm6klMILjSKVw83xb3YyXXLpmZj9n/ICM5xE=
AllowedIPs = 198.51.0.123/32
Endpoint = 192.0.2.1:123
"#;

        pretty_assertions::assert_eq!(
            pve2_wg0_config,
            builder
                .build("pve2".parse()?)?
                .remove("wg0")
                .expect("wg0 config has been generated")
                .to_raw_config()
                .expect("wireguard config can be serialized")
        );

        Ok(())
    }
}

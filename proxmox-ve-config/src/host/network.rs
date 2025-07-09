use std::collections::HashMap;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct IpLink {
    ifname: String,
    #[serde(default)]
    altnames: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct InterfaceMapping {
    mapping: HashMap<String, String>,
}

impl std::ops::Deref for InterfaceMapping {
    type Target = HashMap<String, String>;

    fn deref(&self) -> &Self::Target {
        &self.mapping
    }
}

impl FromIterator<IpLink> for InterfaceMapping {
    fn from_iter<T: IntoIterator<Item = IpLink>>(iter: T) -> Self {
        let mut mapping = HashMap::new();

        for iface in iter.into_iter() {
            for altname in iface.altnames {
                mapping.insert(altname, iface.ifname.clone());
            }
        }

        Self { mapping }
    }
}

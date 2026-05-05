//! Section config types for FRR Prefix Lists.
//!
//! This module contains the API types for representing FRR Prefix Lists as section config. Each
//! entry in the section config represents a Prefix List and its entries.
//!
//! A simple FRR Prefix List looks like this:
//!
//! ```text
//! ip prefix-list example-list permit 192.0.2.0/24 ge 25 le 26
//! ip prefix-list example-list permit 192.0.2.0/24 le 28 ge 29
//! ip prefix-list example-list deny 192.0.2.0/24 le 24
//! ```
//!
//! The corresponding section config entry looks like this:
//!
//! ```text
//! prefix-list: example_list
//!   entries action=permit,prefix=192.0.2.0/24,ge=25,le=26
//!   entries action=permit,prefix=192.0.2.0/24,ge=28,le=29
//!   entries action=deny,prefix=192.0.2.0/24,le=24
//! ```

use const_format::concatcp;
use serde::{Deserialize, Serialize};

use proxmox_network_types::Cidr;
use proxmox_schema::{
    api, api_string_type, const_regex, property_string::PropertyString, ApiStringFormat, Updater,
    UpdaterType,
};

pub const PREFIX_LIST_ID_REGEX_STR: &str =
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]){0,30}(?:[a-zA-Z0-9]){0,1})";

const_regex! {
    pub PREFIX_LIST_ID_REGEX = concatcp!(r"^", PREFIX_LIST_ID_REGEX_STR, r"$");
}

pub const PREFIX_LIST_ID_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&PREFIX_LIST_ID_REGEX);

api_string_type! {
    /// ID of a Prefix List.
    #[api(format: &PREFIX_LIST_ID_FORMAT)]
    #[derive(Debug, Deserialize, Serialize, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, UpdaterType)]
    pub struct PrefixListId(String);
}

#[api()]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Action for an entry in a Prefix List.
pub enum PrefixListAction {
    /// permit
    Permit,
    /// deny
    Deny,
}

#[api(
    properties: {
        entries: {
            type: Array,
            optional: true,
            items: {
                type: String,
                description: "An entry in a prefix list",
                format: &ApiStringFormat::PropertyString(&PrefixListEntry::API_SCHEMA),
            }
        },
    }
)]
#[derive(Debug, Clone, Serialize, Deserialize, Updater)]
/// IP Prefix List
///
/// Corresponds to the FRR IP Prefix lists, as described in its [documentation](https://docs.frrouting.org/en/latest/filter.html#ip-prefix-list)
pub struct PrefixListSection {
    #[updater(skip)]
    id: PrefixListId,
    /// The entries in this prefix list
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub entries: Vec<PropertyString<PrefixListEntry>>,
}

impl PrefixListSection {
    /// Return the ID of the Prefix List.
    pub fn id(&self) -> &PrefixListId {
        &self.id
    }
}

#[api()]
#[derive(Debug, Clone, Serialize, Deserialize)]
/// IP Prefix List Entry
///
/// Corresponds to the FRR IP Prefix lists, as described in its [documentation](https://docs.frrouting.org/en/latest/filter.html#ip-prefix-list)
pub struct PrefixListEntry {
    action: PrefixListAction,
    prefix: Cidr,
    /// Prefix length - entry will be applied if the prefix length is less than or equal to this
    /// value.
    #[serde(skip_serializing_if = "Option::is_none")]
    le: Option<u32>,
    /// Prefix length - entry will be applied if the prefix length is greater than or equal to this
    /// value.
    #[serde(skip_serializing_if = "Option::is_none")]
    ge: Option<u32>,
    /// The sequence number for this prefix list entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u32>,
}

#[api(
    "id-property": "id",
    "id-schema": {
        type: String,
        description: "Prefix List Section ID",
        format: &PREFIX_LIST_ID_FORMAT,
    },
    "type-key": "type",
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum PrefixList {
    PrefixList(PrefixListSection),
}

#[cfg(feature = "frr")]
pub mod frr {
    use super::*;

    use proxmox_frr::ser::{
        route_map::{
            self, PrefixListName as FrrPrefixListName, PrefixListRule as FrrPrefixListRule,
        },
        FrrConfig,
    };

    impl From<PrefixListId> for FrrPrefixListName {
        fn from(value: PrefixListId) -> Self {
            FrrPrefixListName::new(value.0)
        }
    }

    impl From<PrefixListEntry> for FrrPrefixListRule {
        fn from(value: PrefixListEntry) -> Self {
            FrrPrefixListRule {
                action: match value.action {
                    PrefixListAction::Permit => route_map::AccessAction::Permit,
                    PrefixListAction::Deny => route_map::AccessAction::Deny,
                },
                network: value.prefix,
                seq: value.seq,
                le: value.le,
                ge: value.ge,
                is_ipv6: value.prefix.is_ipv6(),
            }
        }
    }

    /// Add a list of Prefix Lists to an [`FrrConfig`].
    ///
    /// This will overwrite existing Prefix Lists in the [`FrrConfig`]. Since this will be used for
    /// generating the FRR configuration from the SDN stack, this enables users to override Prefix
    /// Lists that are predefined by our stack.
    pub fn build_frr_prefix_lists(
        prefix_lists: impl IntoIterator<Item = PrefixList>,
        frr_config: &mut FrrConfig,
    ) -> Result<(), anyhow::Error> {
        for prefix_list in prefix_lists {
            let PrefixList::PrefixList(prefix_list) = prefix_list;
            let prefix_list_name = FrrPrefixListName::new(prefix_list.id.0);

            frr_config.prefix_lists.insert(
                prefix_list_name,
                prefix_list
                    .entries
                    .into_iter()
                    .map(|prefix_list| prefix_list.into_inner().into())
                    .collect(),
            );
        }

        Ok(())
    }
}

pub mod api {
    use super::*;

    pub type PrefixList = PrefixListSection;
    pub type PrefixListUpdater = PrefixListSectionUpdater;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    /// Deletable properties for [`PrefixList`].
    pub enum PrefixListDeletableProperties {
        Entries,
    }
}

#[cfg(test)]
mod tests {
    use proxmox_section_config::typed::ApiSectionDataEntry;

    use super::*;

    #[test]
    fn test_simple_prefix_list() -> Result<(), anyhow::Error> {
        let section_config = r#"
prefix-list: somelist
  entries action=permit,prefix=192.0.2.0/24
  entries action=permit,prefix=192.0.2.0/24,le=32
  entries action=permit,prefix=192.0.2.0/24,le=32,ge=24,seq=123
  entries action=permit,prefix=192.0.2.0/24,ge=24
  entries action=permit,prefix=192.0.2.0/24,ge=24,le=31
"#;

        PrefixList::parse_section_config("prefix-lists.cfg", section_config)?;
        Ok(())
    }
}

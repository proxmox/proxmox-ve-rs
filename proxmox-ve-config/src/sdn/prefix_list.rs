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

use std::ops::{Deref, DerefMut};

use const_format::concatcp;
use serde::{Deserialize, Serialize};

use proxmox_network_types::Cidr;
use proxmox_schema::{
    api, api_string_type, const_regex, property_string::PropertyString, ApiStringFormat,
    UpdaterType,
};

use crate::common::valid::Validatable;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
/// IP Prefix List
///
/// Corresponds to the FRR IP Prefix lists, as described in its [documentation](https://docs.frrouting.org/en/latest/filter.html#ip-prefix-list)
pub struct PrefixListSection {
    pub(crate) id: PrefixListId,
    /// The entries in this prefix list
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) entries: Vec<PropertyString<PrefixListEntry>>,
}

impl Validatable for PrefixListSection {
    type Error = anyhow::Error;

    fn validate(&self) -> Result<(), Self::Error> {
        for entry in &self.entries {
            entry.validate()?
        }

        Ok(())
    }
}

impl PrefixListSection {
    pub fn new(id: PrefixListId) -> Self {
        Self {
            id,
            entries: Vec::new(),
        }
    }

    /// Return the ID of the Prefix List.
    pub fn id(&self) -> &PrefixListId {
        &self.id
    }

    /// Try to update this [`PrefixListSection`].
    ///
    /// This method fails if the given entry list is not valid.
    pub fn try_update(
        &mut self,
        updater: api::PrefixListUpdater,
        delete: Option<Vec<api::PrefixListDeletableProperties>>,
    ) -> Result<(), anyhow::Error> {
        let api::PrefixListUpdater { entries } = updater;

        if let Some(entries) = entries {
            self.try_set_api_entries(entries.into_iter().map(PropertyString::into_inner))?;
        }

        for deletable_property in delete.unwrap_or_default() {
            match deletable_property {
                api::PrefixListDeletableProperties::Entries => {
                    self.entries = Vec::new();
                }
            }
        }

        Ok(())
    }

    /// Returns the value for the next sequence number that should be inserted.
    ///
    /// This mirrors the logic in FRR by returning the highest existing sequence number + 5.
    pub fn next_seq_number(&self) -> u32 {
        self.entries
            .iter()
            .max_by_key(|entry| entry.seq)
            .map(|entry| entry.seq + 5)
            .unwrap_or(5)
    }

    /// Returns an iterator over all entries.
    pub fn entries(&self) -> impl IntoIterator<Item = &PrefixListEntry> {
        self.entries.iter().map(Deref::deref)
    }

    /// Returns the entry with sequence number `seq`.
    pub fn entry(&self, seq: u32) -> Option<&PrefixListEntry> {
        self.entries
            .iter()
            .find(|entry| entry.seq == seq)
            .map(Deref::deref)
    }

    /// Returns a mutable reference to the entry with sequence number `seq`.
    pub fn entry_mut(&mut self, seq: u32) -> Option<&mut PrefixListEntry> {
        self.entries
            .iter_mut()
            .find(|entry| entry.seq == seq)
            .map(DerefMut::deref_mut)
    }

    /// Returns the position of the entry with sequence number seq.
    pub fn entry_position(&self, seq: u32) -> Option<usize> {
        self.entries.iter().position(|entry| entry.seq == seq)
    }

    /// Sets the entries for this prefix list.
    pub fn try_set_api_entries(
        &mut self,
        entries: impl IntoIterator<Item = api::PrefixListEntry>,
    ) -> Result<(), anyhow::Error> {
        let old_entries = std::mem::take(&mut self.entries);

        for entry in entries {
            if let Err(error) = self.try_insert_api_entry(entry) {
                self.entries = old_entries;
                return Err(error);
            }
        }

        Ok(())
    }

    /// Try to insert a [`api::PrefixListEntry`].
    ///
    /// This method fails if the given entry has a sequence number, that already exists in the
    /// configuration. If no sequence number is set in the entry, then a new sequence number will be
    /// auto-generated via [`Self::next_seq_number`].
    pub fn try_insert_api_entry(
        &mut self,
        entry: api::PrefixListEntry,
    ) -> Result<(), anyhow::Error> {
        if let Some(seq) = entry.seq {
            if self.entry_position(seq).is_some() {
                anyhow::bail!("entry with sequence number {seq} already exists!");
            }
        }

        let entry = PrefixListEntry {
            action: entry.action,
            prefix: entry.prefix,
            le: entry.le,
            ge: entry.ge,
            seq: entry.seq.unwrap_or_else(|| self.next_seq_number()),
        };

        self.try_insert_entry(entry)
    }

    /// Try to insert an entry.
    ///
    /// This method fails if the sequence number from the entry already exists in the
    /// configuration.
    pub fn try_insert_entry(&mut self, entry: PrefixListEntry) -> Result<(), anyhow::Error> {
        if self.entry(entry.seq).is_some() {
            anyhow::bail!("entry with sequence number {} already exists", entry.seq);
        }

        entry.validate()?;

        self.entries.push(entry.into());
        Ok(())
    }

    /// Removes the entry with the given sequence number and returns it.
    pub fn remove_entry(&mut self, seq: u32) -> Option<PrefixListEntry> {
        self.entry_position(seq)
            .map(|index| self.entries.remove(index).into_inner())
    }

    /// Try to update an entry in [`PrefixListSection`].
    ///
    /// This method fails if the new entry has a sequence number that already exists in the
    /// [`PrefixListSection`].
    pub fn try_update_entry(
        &mut self,
        old_seq: u32,
        updater: api::PrefixListEntryUpdater,
        delete: Vec<api::PrefixListEntryDeletableProperties>,
    ) -> Result<(), anyhow::Error> {
        let api::PrefixListEntryUpdater {
            action,
            prefix,
            le,
            ge,
            seq,
        } = updater;

        if let Some(seq) = seq {
            if seq != old_seq && self.entry(seq).is_some() {
                anyhow::bail!("entry with sequence number {seq} already exists!");
            }
        }

        let original_entry = self.remove_entry(old_seq).ok_or_else(|| {
            anyhow::anyhow!("entry with sequence number {old_seq} does not exist!")
        })?;
        let mut new_entry = original_entry.clone();

        if let Some(seq) = seq {
            new_entry.seq = seq;
        }

        if let Some(action) = action {
            new_entry.action = action;
        }

        if let Some(prefix) = prefix {
            new_entry.prefix = prefix;
        }

        if let Some(le) = le {
            new_entry.le = Some(le);
        }

        if let Some(ge) = ge {
            new_entry.ge = Some(ge);
        }

        for property in delete {
            match property {
                api::PrefixListEntryDeletableProperties::Le => new_entry.le = None,
                api::PrefixListEntryDeletableProperties::Ge => new_entry.ge = None,
                api::PrefixListEntryDeletableProperties::Seq => {
                    new_entry.seq = self.next_seq_number()
                }
            }
        }

        if let Err(error) = self.try_insert_entry(new_entry) {
            // Restore the original entry on failure; it was valid by construction.
            self.entries.push(original_entry.into());
            return Err(error);
        }

        Ok(())
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
    seq: u32,
}

impl Validatable for PrefixListEntry {
    type Error = anyhow::Error;

    fn validate(&self) -> Result<(), Self::Error> {
        // Ensure that:
        // prefixmask <= ge <= le

        let (max_mask, current_mask) = match self.prefix {
            Cidr::Ipv4(ipv4_cidr) => (32, ipv4_cidr.mask() as u32),
            Cidr::Ipv6(ipv6_cidr) => (128, ipv6_cidr.mask() as u32),
        };

        if let Some(le) = self.le {
            if le > max_mask {
                anyhow::bail!("Prefix <= must not be greater than {max_mask}");
            }

            if current_mask > le {
                anyhow::bail!("Prefix <= must not be less than {current_mask}");
            }

            if let Some(ge) = self.ge {
                if ge > le {
                    anyhow::bail!("Prefix >= ({ge}) must not be greater than Prefix <= ({le})");
                }
            }
        }

        if let Some(ge) = self.ge {
            if ge > max_mask {
                anyhow::bail!("Prefix >= must not be greater than {max_mask}");
            }

            if current_mask > ge {
                anyhow::bail!("Prefix >= must not be less than {current_mask}");
            }
        }

        Ok(())
    }
}

impl PrefixListEntry {
    pub fn seq(&self) -> u32 {
        self.seq
    }
}

/// Prefix List section config entry.
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
    /// A prefix list.
    PrefixList(PrefixListSection),
}

impl Validatable for PrefixList {
    type Error = anyhow::Error;

    fn validate(&self) -> Result<(), Self::Error> {
        let PrefixList::PrefixList(prefix_list_section) = self;
        prefix_list_section.validate()
    }
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
                seq: Some(value.seq),
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
    use serde::{Deserialize, Serialize};

    use proxmox_network_types::Cidr;
    use proxmox_schema::{api, property_string::PropertyString, ApiStringFormat, Updater};

    use super::{PrefixListAction, PrefixListId, PrefixListSection};

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
    /// IP Prefix List API type.
    ///
    /// In the API, specifying the sequence number for entries is optional, so model that constraint here in
    /// the API type by using the respective entry API type.
    pub struct PrefixList {
        #[updater(skip)]
        pub(crate) id: PrefixListId,
        /// The entries in this prefix list
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        #[updater(serde(skip_serializing_if = "Option::is_none"))]
        pub(crate) entries: Vec<PropertyString<PrefixListEntry>>,
    }

    impl PrefixList {
        pub fn id(&self) -> &PrefixListId {
            &self.id
        }
    }

    impl TryFrom<PrefixList> for PrefixListSection {
        type Error = anyhow::Error;

        fn try_from(value: PrefixList) -> Result<Self, Self::Error> {
            let mut section = Self {
                id: value.id,
                entries: Vec::new(),
            };

            for entry in value.entries {
                section.try_insert_api_entry(entry.into_inner())?;
            }

            Ok(section)
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    /// Deletable properties for [`PrefixList`].
    pub enum PrefixListDeletableProperties {
        Entries,
    }

    #[api()]
    #[derive(Debug, Clone, Serialize, Deserialize, Updater)]
    /// IP Prefix List Entry API type.
    ///
    /// In the API, specifying the sequence number is optional, so model that constraint here in
    /// the API type.
    pub struct PrefixListEntry {
        pub(crate) action: PrefixListAction,
        pub(crate) prefix: Cidr,
        /// Prefix length - entry will be applied if the prefix length is less than or equal to this
        /// value.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) le: Option<u32>,
        /// Prefix length - entry will be applied if the prefix length is greater than or equal to this
        /// value.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub(crate) ge: Option<u32>,
        /// The sequence number for this prefix list entry.
        pub(crate) seq: Option<u32>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum PrefixListEntryDeletableProperties {
        Le,
        Ge,
        Seq,
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
  entries action=permit,prefix=192.0.2.0/24,seq=22
  entries action=permit,prefix=192.0.2.0/24,le=32,seq=122
  entries action=permit,prefix=192.0.2.0/24,le=32,ge=24,seq=123
  entries action=permit,prefix=192.0.2.0/24,ge=24,seq=232
  entries action=permit,prefix=192.0.2.0/24,ge=24,le=31,seq=222
"#;

        PrefixList::parse_section_config("prefix-lists.cfg", section_config)?;
        Ok(())
    }

    #[test]
    fn test_prefix_list_seq_nr() -> Result<(), anyhow::Error> {
        let mut prefix_list = PrefixListSection::new(
            PrefixListId::from_string("test".to_string()).expect("valid prefix list id"),
        );

        assert_eq!(prefix_list.next_seq_number(), 5);

        prefix_list
            .try_insert_entry(PrefixListEntry {
                action: PrefixListAction::Permit,
                prefix: Cidr::new_v4([192, 0, 2, 0], 24).expect("valid cidr"),
                le: None,
                ge: None,
                seq: 100,
            })
            .expect("valid entry");

        assert_eq!(prefix_list.next_seq_number(), 105);

        prefix_list.remove_entry(100).expect("could be removed");
        assert_eq!(prefix_list.next_seq_number(), 5);

        Ok(())
    }

    #[test]
    fn test_prefix_list_entry_update() -> Result<(), anyhow::Error> {
        let mut prefix_list = PrefixListSection::new(
            PrefixListId::from_string("test".to_string()).expect("valid prefix list id"),
        );

        assert_eq!(prefix_list.next_seq_number(), 5);

        prefix_list
            .try_insert_entry(PrefixListEntry {
                action: PrefixListAction::Permit,
                prefix: Cidr::new_v4([192, 0, 2, 0], 24).expect("valid cidr"),
                le: None,
                ge: None,
                seq: 100,
            })
            .expect("valid entry");

        prefix_list
            .try_insert_entry(PrefixListEntry {
                action: PrefixListAction::Permit,
                prefix: Cidr::new_v4([192, 0, 2, 0], 24).expect("valid cidr"),
                le: None,
                ge: None,
                seq: 200,
            })
            .expect("valid entry");

        prefix_list
            .try_update_entry(
                100,
                api::PrefixListEntryUpdater {
                    action: None,
                    prefix: None,
                    le: None,
                    ge: None,
                    seq: Some(200),
                },
                Vec::new(),
            )
            .expect_err("seq nr already exists");

        prefix_list
            .try_update_entry(
                150,
                api::PrefixListEntryUpdater {
                    action: None,
                    prefix: None,
                    le: None,
                    ge: None,
                    seq: Some(100),
                },
                Vec::new(),
            )
            .expect_err("old seq nr doesn't exist");

        prefix_list
            .try_update_entry(
                100,
                api::PrefixListEntryUpdater {
                    action: None,
                    prefix: None,
                    le: None,
                    ge: None,
                    seq: Some(10),
                },
                Vec::new(),
            )
            .expect("changing sequence number from 100 to 10 works");

        prefix_list
            .entry(10)
            .expect("entry has been successfully updated");

        Ok(())
    }

    #[test]
    fn test_invalid_prefix_list_entry() -> Result<(), anyhow::Error> {
        let mut prefix_list = PrefixListSection::new(
            PrefixListId::from_string("test".to_string()).expect("valid prefix list id"),
        );

        prefix_list
            .try_insert_entry(PrefixListEntry {
                action: PrefixListAction::Permit,
                prefix: Cidr::new_v4([192, 0, 2, 0], 24).expect("valid cidr"),
                le: Some(23),
                ge: None,
                seq: 100,
            })
            .expect_err("le smaller than prefix mask");

        prefix_list
            .try_insert_entry(PrefixListEntry {
                action: PrefixListAction::Permit,
                prefix: Cidr::new_v4([192, 0, 2, 0], 24).expect("valid cidr"),
                le: None,
                ge: Some(23),
                seq: 100,
            })
            .expect_err("ge smaller than prefix mask");

        prefix_list
            .try_insert_entry(PrefixListEntry {
                action: PrefixListAction::Permit,
                prefix: Cidr::new_v4([192, 0, 2, 0], 24).expect("valid cidr"),
                le: Some(25),
                ge: Some(27),
                seq: 100,
            })
            .expect_err("ge greater than le");

        prefix_list
            .try_insert_entry(PrefixListEntry {
                action: PrefixListAction::Permit,
                prefix: Cidr::new_v4([192, 0, 2, 0], 24).expect("valid cidr"),
                le: None,
                ge: None,
                seq: 100,
            })
            .expect("valid entry");

        prefix_list
            .try_insert_entry(PrefixListEntry {
                action: PrefixListAction::Permit,
                prefix: Cidr::new_v4([192, 0, 2, 0], 24).expect("valid cidr"),
                le: None,
                ge: None,
                seq: 100,
            })
            .expect_err("entry with seq already exists");

        Ok(())
    }

    #[test]
    fn test_prefix_list_entry_update_rolls_back_on_validation_failure() -> Result<(), anyhow::Error>
    {
        let mut prefix_list = PrefixListSection::new(
            PrefixListId::from_string("test".to_string()).expect("valid prefix list id"),
        );

        prefix_list
            .try_insert_entry(PrefixListEntry {
                action: PrefixListAction::Permit,
                prefix: Cidr::new_v4([192, 0, 2, 0], 24).expect("valid cidr"),
                le: Some(28),
                ge: Some(25),
                seq: 100,
            })
            .expect("valid entry");

        prefix_list
            .try_update_entry(
                100,
                api::PrefixListEntryUpdater {
                    action: None,
                    prefix: None,
                    le: Some(23),
                    ge: None,
                    seq: None,
                },
                Vec::new(),
            )
            .expect_err("le smaller than prefix mask");

        let entry = prefix_list.entry(100).expect("original entry preserved");
        assert_eq!(entry.le, Some(28));
        assert_eq!(entry.ge, Some(25));

        Ok(())
    }
}

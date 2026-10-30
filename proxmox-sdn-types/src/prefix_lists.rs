use const_format::concatcp;

use proxmox_schema::{ApiStringFormat, UpdaterType, api, api_string_type, const_regex};

pub const PREFIX_LIST_ID_REGEX_STR: &str =
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]){0,30}(?:[a-zA-Z0-9]){0,1})";

const_regex! {
    pub PREFIX_LIST_ID_REGEX = concatcp!(r"^", PREFIX_LIST_ID_REGEX_STR, r"$");
}

pub const PREFIX_LIST_ID_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&PREFIX_LIST_ID_REGEX);

api_string_type! {
    /// ID of a Prefix List.
    #[api(format: &PREFIX_LIST_ID_FORMAT)]
    #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, UpdaterType)]
    pub struct PrefixListId(String);
}

proxmox_serde::forward_serialize_to_display!(PrefixListId);
proxmox_serde::forward_deserialize_to_from_str!(PrefixListId);

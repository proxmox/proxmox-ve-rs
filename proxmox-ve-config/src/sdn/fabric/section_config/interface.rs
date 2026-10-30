use const_format::concatcp;

use proxmox_schema::{ApiStringFormat, UpdaterType, api, api_string_type, const_regex};

pub const INTERFACE_NAME_REGEX_STR: &str = "[[:ascii:]]+";

const_regex! {
    pub INTERFACE_NAME_REGEX = concatcp!(r"^", INTERFACE_NAME_REGEX_STR, r"$");
}

pub const INTERFACE_NAME_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&INTERFACE_NAME_REGEX);

api_string_type! {
    /// Name of a network interface.
    ///
    /// The interface name can have a maximum of 15 characters. This is a kernel limit.
    #[api(
        min_length: 1,
        max_length: 15,
        format: &INTERFACE_NAME_FORMAT,
    )]
    #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, UpdaterType)]
    pub struct InterfaceName(String);
}

proxmox_serde::forward_serialize_to_display!(InterfaceName);
proxmox_serde::forward_deserialize_to_from_str!(InterfaceName);

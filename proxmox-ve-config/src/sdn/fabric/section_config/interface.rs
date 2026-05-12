use const_format::concatcp;
use serde::{Deserialize, Serialize};

use proxmox_schema::{api, api_string_type, const_regex, ApiStringFormat, UpdaterType};

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
    #[derive(Debug, Deserialize, Serialize, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, UpdaterType)]
    pub struct InterfaceName(String);
}

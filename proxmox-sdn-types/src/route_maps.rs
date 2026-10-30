use anyhow::format_err;
use const_format::concatcp;
use serde::{Deserialize, Serialize};

use proxmox_schema::{
    ApiStringFormat, ApiType, Schema, StringSchema, UpdaterType, api, api_string_type,
    api_types::NON_EMPTY_NO_WHITESPACE_FORMAT, const_regex,
};

pub const ROUTE_MAP_ID_REGEX_STR: &str =
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]){0,30}(?:[a-zA-Z0-9]){0,1})";

pub const ROUTE_MAP_ORDER_REGEX_STR: &str = r"\d+";

const_regex! {
    pub ROUTE_MAP_ID_REGEX = concatcp!(r"^", ROUTE_MAP_ID_REGEX_STR, r"$");
    pub ROUTE_MAP_SECTION_ID_REGEX = concatcp!(r"^", ROUTE_MAP_ID_REGEX_STR, r"_", ROUTE_MAP_ORDER_REGEX_STR, r"$");
}

pub const ROUTE_MAP_SECTION_ID_FORMAT: ApiStringFormat =
    ApiStringFormat::Pattern(&ROUTE_MAP_SECTION_ID_REGEX);

pub const ROUTE_MAP_ID_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&ROUTE_MAP_ID_REGEX);

api_string_type! {
    /// ID of a Route Map.
    #[api(format: &ROUTE_MAP_ID_FORMAT)]
    #[derive(Debug, Deserialize, Serialize, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, UpdaterType)]
    pub struct RouteMapId(String);
}

/// The ID of a Route Map entry in the section config (name + order).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteMapEntryId {
    /// name of the Route Map
    route_map_id: RouteMapId,
    /// seq nr of the Route Map
    order: u16,
}

impl RouteMapEntryId {
    /// Create a new Route Map Entry ID.
    pub fn new(route_map_id: RouteMapId, order: u16) -> Self {
        Self {
            route_map_id,
            order,
        }
    }

    /// Returns the name part of the Route Map section id.
    pub fn route_map_id(&self) -> &RouteMapId {
        &self.route_map_id
    }

    /// Returns the order part of the Route Map section id.
    pub fn order(&self) -> u16 {
        self.order
    }
}

impl ApiType for RouteMapEntryId {
    const API_SCHEMA: Schema = StringSchema::new("ID of a Route Map entry in the section config")
        .format(&ROUTE_MAP_SECTION_ID_FORMAT)
        .schema();
}

impl std::fmt::Display for RouteMapEntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}_{}", self.route_map_id, self.order)
    }
}

proxmox_serde::forward_serialize_to_display!(RouteMapEntryId);

impl std::str::FromStr for RouteMapEntryId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, order) = value
            .rsplit_once("_")
            .ok_or_else(|| format_err!("invalid RouteMap section id: {}", value))?;

        Ok(Self {
            route_map_id: RouteMapId::from_string(name.to_string())?,
            order: order.parse()?,
        })
    }
}

proxmox_serde::forward_deserialize_to_from_str!(RouteMapEntryId);

api_string_type! {
    /// Peer to match in a Route Map entry, for example an IP address or an interface name.
    #[api(format: &NON_EMPTY_NO_WHITESPACE_FORMAT)]
    #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, UpdaterType)]
    pub struct RouteMapPeer(String);
}

proxmox_serde::forward_serialize_to_display!(RouteMapPeer);
proxmox_serde::forward_deserialize_to_from_str!(RouteMapPeer);

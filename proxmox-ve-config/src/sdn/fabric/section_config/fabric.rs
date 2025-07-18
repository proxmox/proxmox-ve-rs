use const_format::concatcp;
use serde::{Deserialize, Serialize};

use proxmox_network_types::ip_address::{Ipv4Cidr, Ipv6Cidr};
use proxmox_schema::{
    api, api_string_type, const_regex, AllOfSchema, ApiStringFormat, ApiType, ObjectSchema, Schema,
    Updater, UpdaterType,
};

use crate::common::valid::Validatable;
use crate::sdn::fabric::section_config::protocol::openfabric::{
    OpenfabricDeletableProperties, OpenfabricProperties, OpenfabricPropertiesUpdater,
};
use crate::sdn::fabric::section_config::protocol::ospf::{
    OspfDeletableProperties, OspfProperties, OspfPropertiesUpdater,
};
use crate::sdn::fabric::FabricConfigError;

pub const FABRIC_ID_REGEX_STR: &str = r"(?:[a-zA-Z0-9])(?:[a-zA-Z0-9\-]){0,6}(?:[a-zA-Z0-9])?";

const_regex! {
    pub FABRIC_ID_REGEX = concatcp!(r"^", FABRIC_ID_REGEX_STR, r"$");
}

pub const FABRIC_ID_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&FABRIC_ID_REGEX);

api_string_type! {
    /// ID of an SDN fabric.
    #[api(format: &FABRIC_ID_FORMAT)]
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    pub struct FabricId(String);
}

/// A fabric section in an SDN fabric config.
///
/// This struct contains all the properties that are required for any fabric, regardless of
/// protocol. Properties that are specific to a protocol can be passed via the type parameter.
///
/// This is mainly used by the [`Fabric`] and [`super::Section`] enums to specify which types of fabrics can exist,
/// without having to re-define common properties for every fabric. It also simplifies accessing
/// common properties by encapsulating the specific properties to [`FabricSection<T>::properties`].
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct FabricSection<T> {
    pub(crate) id: FabricId,

    /// IPv4 Prefix that contains the Node IPs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip_prefix: Option<Ipv4Cidr>,

    /// IPv6 Prefix that contains the Node IPs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip6_prefix: Option<Ipv6Cidr>,

    #[serde(flatten)]
    pub(crate) properties: T,
}

impl<T> FabricSection<T> {
    /// Get the protocol-specific properties of [`FabricSection`].
    pub fn properties(&self) -> &T {
        &self.properties
    }

    /// Get a mutable reference to the protocol-specific properties of [`FabricSection`].
    pub fn properties_mut(&mut self) -> &mut T {
        &mut self.properties
    }

    /// Get the id of [`FabricSection`].
    pub fn id(&self) -> &FabricId {
        &self.id
    }

    /// Get the ip-prefix (IPv4 CIDR) of [`FabricSection`].
    pub fn ip_prefix(&self) -> Option<Ipv4Cidr> {
        self.ip_prefix
    }

    /// Get the ip6-prefix (IPv6 CIDR) of [`FabricSection`].
    pub fn ip6_prefix(&self) -> Option<Ipv6Cidr> {
        self.ip6_prefix
    }
}

const FABRIC_SECTION_SCHEMA: Schema = ObjectSchema::new(
    "Common properties for fabrics in an SDN fabric.",
    &[
        ("id", false, &FabricId::API_SCHEMA),
        ("ip6_prefix", true, &Ipv6Cidr::API_SCHEMA),
        ("ip_prefix", true, &Ipv4Cidr::API_SCHEMA),
    ],
)
.schema();

impl<T: ApiType> ApiType for FabricSection<T> {
    const API_SCHEMA: Schema = AllOfSchema::new(
        "Fabric in an SDN fabric.",
        &[&FABRIC_SECTION_SCHEMA, &T::API_SCHEMA],
    )
    .schema();
}

/// Updater for a [`FabricSection<T>`]
///
/// This specifies the updater type for the common properties in [`FabricSection<T>`], as well as
/// provides the delete property for deleting properties on updates.
///
/// It also provides a blanket implementation of [`Updater`] for any type parameter that implements
/// Updater as well.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FabricSectionUpdater<T, D> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip_prefix: Option<Ipv4Cidr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ip6_prefix: Option<Ipv6Cidr>,

    #[serde(flatten)]
    pub(crate) properties: T,

    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::new")]
    pub(crate) delete: Vec<FabricDeletableProperties<D>>,
}

impl<T: Updater, D> Updater for FabricSectionUpdater<T, D> {
    fn is_empty(&self) -> bool {
        T::is_empty(&self.properties)
            && self.ip_prefix.is_none()
            && self.ip6_prefix.is_none()
            && self.delete.is_empty()
    }
}

impl UpdaterType for FabricSection<OpenfabricProperties> {
    type Updater = FabricSectionUpdater<OpenfabricPropertiesUpdater, OpenfabricDeletableProperties>;
}

impl UpdaterType for FabricSection<OspfProperties> {
    type Updater = FabricSectionUpdater<OspfPropertiesUpdater, OspfDeletableProperties>;
}

/// Enum containing all types of fabrics.
///
/// It utilizes [`FabricSection<T>`] to define all possible types of fabrics. For parsing the
/// configuration, please use the [`Section`] enum, which contains the Node sections as well. This
/// struct is used for sorting the sections into their sub-types after parsing the configuration
/// via [`Section`].
#[api(
    "id-property": "id",
    "id-schema": {
        type: String,
        description: "Fabric ID",
        format: &FABRIC_ID_FORMAT,
    },
    "type-key": "protocol",
)]
#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case", tag = "protocol")]
pub enum Fabric {
    Openfabric(FabricSection<OpenfabricProperties>),
    Ospf(FabricSection<OspfProperties>),
}

impl UpdaterType for Fabric {
    type Updater = FabricUpdater;
}

impl Fabric {
    /// Get the id of the [`Fabric`].
    ///
    /// This is a common property for all protocols.
    pub fn id(&self) -> &FabricId {
        match self {
            Self::Openfabric(fabric_section) => fabric_section.id(),
            Self::Ospf(fabric_section) => fabric_section.id(),
        }
    }

    /// Get the ip-prefix (IPv4 CIDR) of the [`Fabric`].
    ///
    /// This is a common property for all protocols.
    pub fn ip_prefix(&self) -> Option<Ipv4Cidr> {
        match self {
            Fabric::Openfabric(fabric_section) => fabric_section.ip_prefix(),
            Fabric::Ospf(fabric_section) => fabric_section.ip_prefix(),
        }
    }

    /// Get the ip6-prefix (IPv6 CIDR) of the [`Fabric`].
    ///
    /// This is a common property for all protocols.
    pub fn ip6_prefix(&self) -> Option<Ipv6Cidr> {
        match self {
            Fabric::Openfabric(fabric_section) => fabric_section.ip6_prefix(),
            Fabric::Ospf(fabric_section) => fabric_section.ip6_prefix(),
        }
    }
}

impl Validatable for Fabric {
    type Error = FabricConfigError;

    /// Validate the [`Fabric`] by calling the validation function for the respective protocol.
    fn validate(&self) -> Result<(), Self::Error> {
        match self {
            Fabric::Openfabric(fabric_section) => fabric_section.validate(),
            Fabric::Ospf(fabric_section) => fabric_section.validate(),
        }
    }
}

impl From<FabricSection<OpenfabricProperties>> for Fabric {
    fn from(section: FabricSection<OpenfabricProperties>) -> Self {
        Fabric::Openfabric(section)
    }
}

impl From<FabricSection<OspfProperties>> for Fabric {
    fn from(section: FabricSection<OspfProperties>) -> Self {
        Fabric::Ospf(section)
    }
}

/// Enum containing all updater types for fabrics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "protocol")]
pub enum FabricUpdater {
    Openfabric(<FabricSection<OpenfabricProperties> as UpdaterType>::Updater),
    Ospf(<FabricSection<OspfProperties> as UpdaterType>::Updater),
}

impl Updater for FabricUpdater {
    fn is_empty(&self) -> bool {
        match self {
            FabricUpdater::Openfabric(updater) => updater.is_empty(),
            FabricUpdater::Ospf(updater) => updater.is_empty(),
        }
    }
}

/// Deletable properties for a [`FabricSection<T>`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", untagged)]
pub enum FabricDeletableProperties<T> {
    IpPrefix,
    Ip6Prefix,
    #[serde(untagged)]
    Protocol(T),
}

pub mod api {
    pub type Fabric = super::Fabric;
    pub type FabricUpdater = super::FabricUpdater;
}

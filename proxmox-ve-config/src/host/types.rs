use std::{fmt::Display, str::FromStr};

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum BridgeNameError {
    #[error("name is too long")]
    TooLong,
}

#[derive(Error, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct BridgeName(String);

impl BridgeName {
    pub fn new(name: String) -> Result<Self, BridgeNameError> {
        if name.len() > 15 {
            return Err(BridgeNameError::TooLong);
        }

        Ok(Self(name))
    }

    pub fn name(&self) -> &str {
        &self.0
    }
}

impl FromStr for BridgeName {
    type Err = BridgeNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl Display for BridgeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for BridgeName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

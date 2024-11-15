use std::io;

use anyhow::Error;
use serde::Deserialize;

use crate::firewall::parse::serde_option_bool;
use crate::firewall::types::log::LogLevel;
use crate::firewall::types::rule::{Direction, Verdict};

use super::common::ParserConfig;
use super::types::Rule;

pub struct Config {
    pub(crate) config: super::common::Config<Options>,
}

/// default return value for [`Config::enabled()`]
pub const BRIDGE_ENABLED_DEFAULT: bool = false;
/// default return value for [`Config::policy_forward()`]
pub const BRIDGE_POLICY_FORWARD: Verdict = Verdict::Accept;

impl Config {
    pub fn parse<R: io::BufRead>(input: R) -> Result<Self, Error> {
        let parser_config = ParserConfig {
            guest_iface_names: false,
            ipset_scope: None,
            allowed_directions: vec![Direction::Forward],
        };

        Ok(Self {
            config: super::common::Config::parse(input, &parser_config)?,
        })
    }

    pub fn enabled(&self) -> bool {
        self.config.options.enable.unwrap_or(BRIDGE_ENABLED_DEFAULT)
    }

    pub fn rules(&self) -> impl Iterator<Item = &Rule> + '_ {
        self.config.rules.iter()
    }

    pub fn log_level_forward(&self) -> LogLevel {
        self.config.options.log_level_forward.unwrap_or_default()
    }

    pub fn policy_forward(&self) -> Verdict {
        self.config
            .options
            .policy_forward
            .unwrap_or(BRIDGE_POLICY_FORWARD)
    }
}

#[derive(Debug, Default, Deserialize)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct Options {
    #[serde(default, with = "serde_option_bool")]
    enable: Option<bool>,

    policy_forward: Option<Verdict>,

    log_level_forward: Option<LogLevel>,
}

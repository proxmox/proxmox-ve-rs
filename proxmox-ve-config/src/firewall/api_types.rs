//! Conversions between the `proxmox-firewall-api-types` wire types and this crate's
//! nftables-oriented firewall types.
//!
//! Enabled by the optional `api-types` feature. The wire types are the API/`.fw`-facing
//! representation; the types here additionally carry the nftables lowering semantics (per-family
//! ICMP type/code, service-port resolution, address-family homogeneity, ...). Where both sides
//! share the on-disk `.fw` string format the conversion re-parses that format; where the local type
//! carries extra semantics it validates while lowering. All conversions are fallible for that
//! reason.
//!
//! The tests double as a wire-compatibility check: each feeds a value taken from the real `.fw`
//! fixtures through the API type and asserts it lowers to the same value the daemon's own parser
//! produces.

use proxmox_firewall_api_types::{
    FirewallAddressMatch, FirewallAliasReference, FirewallFWPolicy, FirewallIOPolicy,
    FirewallIcmpType, FirewallIpsetReference, FirewallLogLevel, FirewallLogRateLimit,
    FirewallPacketRateTimescale, FirewallPortList, FirewallRule, FirewallRuleListEntry,
    FirewallRuleType,
};

use crate::firewall::types::alias::RuleAliasName;
use crate::firewall::types::ipset::RuleIpsetName;
use crate::firewall::types::log::{LogLevel, LogRateLimit, LogRateLimitTimescale};
use crate::firewall::types::port::PortList;
use crate::firewall::types::rule::{Direction, Kind, Rule, RuleGroup, Verdict};
use crate::firewall::types::rule_match::{Icmp, Icmpv6, IpAddrMatch, RuleMatch, RuleOptions};

/// Convert a (family-agnostic) API ICMP type into the IPv4 [`Icmp`] match.
///
/// Reuses the existing IPv4 parser, which applies the iptables->nftables type/code mapping. Names
/// that are only valid for IPv6 are rejected.
impl TryFrom<&FirewallIcmpType> for Icmp {
    type Error = anyhow::Error;

    fn try_from(value: &FirewallIcmpType) -> Result<Self, Self::Error> {
        value.to_string().parse()
    }
}

/// Convert a (family-agnostic) API ICMP type into the IPv6 [`Icmpv6`] match.
///
/// Names that are only valid for IPv4 are rejected.
impl TryFrom<&FirewallIcmpType> for Icmpv6 {
    type Error = anyhow::Error;

    fn try_from(value: &FirewallIcmpType) -> Result<Self, Self::Error> {
        value.to_string().parse()
    }
}

/// Convert an API source/destination address match into the nftables [`IpAddrMatch`].
///
/// Both sides share the `.fw` format: an IP/CIDR/range list, a `+scope/name` ipset reference, or a
/// `scope/name` alias reference.
impl TryFrom<&FirewallAddressMatch> for IpAddrMatch {
    type Error = anyhow::Error;

    fn try_from(value: &FirewallAddressMatch) -> Result<Self, Self::Error> {
        value.to_string().parse()
    }
}

/// Convert an API TCP/UDP port list into the nftables [`PortList`].
///
/// Service names are resolved against `/etc/services` by the local parser, so an unknown name is
/// rejected here.
impl TryFrom<&FirewallPortList> for PortList {
    type Error = anyhow::Error;

    fn try_from(value: &FirewallPortList) -> Result<Self, Self::Error> {
        value.to_string().parse()
    }
}

/// Convert an API alias reference into the nftables [`RuleAliasName`] (scoped or legacy).
impl TryFrom<&FirewallAliasReference> for RuleAliasName {
    type Error = anyhow::Error;

    fn try_from(value: &FirewallAliasReference) -> Result<Self, Self::Error> {
        value.to_string().parse()
    }
}

/// Convert an API ipset reference into the nftables [`RuleIpsetName`] (scoped or legacy).
impl TryFrom<&FirewallIpsetReference> for RuleIpsetName {
    type Error = anyhow::Error;

    fn try_from(value: &FirewallIpsetReference) -> Result<Self, Self::Error> {
        value.to_string().parse()
    }
}

/// Convert an API log level into the nftables [`LogLevel`].
///
/// The API spells the warning level `warning`; the local parser accepts that spelling.
impl TryFrom<&FirewallLogLevel> for LogLevel {
    // `Self::Error` is ambiguous here because `LogLevel` also has an `Error` variant.
    type Error = anyhow::Error;

    fn try_from(value: &FirewallLogLevel) -> Result<Self, anyhow::Error> {
        value.to_string().parse()
    }
}

/// Convert an API packet-rate timescale into the nftables [`LogRateLimitTimescale`].
impl TryFrom<FirewallPacketRateTimescale> for LogRateLimitTimescale {
    type Error = anyhow::Error;

    fn try_from(value: FirewallPacketRateTimescale) -> Result<Self, Self::Error> {
        Ok(match value {
            FirewallPacketRateTimescale::Second => LogRateLimitTimescale::Second,
            FirewallPacketRateTimescale::Minute => LogRateLimitTimescale::Minute,
            FirewallPacketRateTimescale::Hour => LogRateLimitTimescale::Hour,
            FirewallPacketRateTimescale::Day => LogRateLimitTimescale::Day,
            #[cfg(feature = "enum-fallback")]
            FirewallPacketRateTimescale::UnknownEnumValue(scale) => {
                anyhow::bail!("unknown packet-rate timescale: {scale}")
            }
        })
    }
}

/// Convert an API log rate-limit into the nftables [`LogRateLimit`], applying the documented
/// defaults for any field the API leaves unset.
impl TryFrom<&FirewallLogRateLimit> for LogRateLimit {
    type Error = anyhow::Error;

    fn try_from(value: &FirewallLogRateLimit) -> Result<Self, Self::Error> {
        let defaults = LogRateLimit::default();

        let burst = match value.burst {
            Some(burst) => i64::try_from(burst)?,
            None => defaults.burst(),
        };

        let (rate, per) = match &value.rate {
            Some(rate) => (
                i64::try_from(rate.packets)?,
                LogRateLimitTimescale::try_from(rate.timescale)?,
            ),
            None => (defaults.rate(), defaults.per()),
        };

        Ok(LogRateLimit::new(value.enable, rate, per, burst))
    }
}

/// Convert an API forward policy into the nftables [`Verdict`].
impl TryFrom<FirewallFWPolicy> for Verdict {
    type Error = anyhow::Error;

    fn try_from(value: FirewallFWPolicy) -> Result<Self, Self::Error> {
        Ok(match value {
            FirewallFWPolicy::Accept => Verdict::Accept,
            FirewallFWPolicy::Drop => Verdict::Drop,
            #[cfg(feature = "enum-fallback")]
            FirewallFWPolicy::UnknownEnumValue(policy) => {
                anyhow::bail!("unknown forward policy: {policy}")
            }
        })
    }
}

/// Convert an API input/output policy into the nftables [`Verdict`].
impl TryFrom<FirewallIOPolicy> for Verdict {
    type Error = anyhow::Error;

    fn try_from(value: FirewallIOPolicy) -> Result<Self, Self::Error> {
        Ok(match value {
            FirewallIOPolicy::Accept => Verdict::Accept,
            FirewallIOPolicy::Drop => Verdict::Drop,
            FirewallIOPolicy::Reject => Verdict::Reject,
            #[cfg(feature = "enum-fallback")]
            FirewallIOPolicy::UnknownEnumValue(policy) => {
                anyhow::bail!("unknown input/output policy: {policy}")
            }
        })
    }
}

/// Lower a wire API firewall rule into the daemon's parsed [`Rule`].
///
/// The wire form pre-decomposes what a `.fw` line packs together - the verdict, an optional macro,
/// and the rule type/direction are separate fields - so this re-emits each already-parsed field in
/// its shared `.fw` string form and delegates to the authoritative `from_options` constructors. That
/// reuses the daemon's own validation (dport/icmp-type exclusivity, the protocol-dependent ICMP
/// dispatch with the iptables-to-nftables type/code rewrite, address-family homogeneity, and the
/// group-rule field restrictions) instead of re-deriving it here.
impl TryFrom<&FirewallRule> for Rule {
    type Error = anyhow::Error;

    fn try_from(value: &FirewallRule) -> Result<Self, Self::Error> {
        // Destructure exhaustively (no `..`) so a newly added wire field fails to compile here
        // instead of being silently dropped.
        let FirewallRule {
            action,
            comment,
            dest,
            dport,
            enable,
            icmp_type,
            iface,
            log,
            r#macro,
            proto,
            source,
            sport,
            ty,
        } = value;

        // pve-firewall marks a disabled rule with a leading `|` and round-trips that as enable=0, so
        // a rule is disabled exactly when `enable` is explicitly zero; unset stays enabled.
        let disabled = matches!(enable, Some(0));

        let options = RuleOptions {
            proto: proto.clone(),
            dport: dport.as_ref().map(ToString::to_string),
            sport: sport.as_ref().map(ToString::to_string),
            dest: dest.as_ref().map(ToString::to_string),
            source: source.as_ref().map(ToString::to_string),
            iface: iface.clone(),
            log: log.as_ref().map(LogLevel::try_from).transpose()?,
            icmp_type: icmp_type.as_ref().map(ToString::to_string),
        };

        let kind = match ty {
            FirewallRuleType::Group => {
                // For a group rule the wire `action` carries the security-group name. A macro is
                // meaningless here and is not a rule option, so reject it explicitly;
                // `RuleGroup::from_options` rejects every field other than the interface.
                if r#macro.is_some() {
                    anyhow::bail!("a security group rule must not carry a macro");
                }
                Kind::Group(RuleGroup::from_options(action.clone(), options)?)
            }
            FirewallRuleType::In => lower_match(Direction::In, action, r#macro, options)?,
            FirewallRuleType::Out => lower_match(Direction::Out, action, r#macro, options)?,
            FirewallRuleType::Forward => lower_match(Direction::Forward, action, r#macro, options)?,
            #[cfg(feature = "enum-fallback")]
            FirewallRuleType::UnknownEnumValue(other) => {
                anyhow::bail!("unknown firewall rule type: {other}")
            }
        };

        Ok(Rule {
            disabled,
            kind,
            comment: comment.clone(),
        })
    }
}

/// Build a [`Kind::Match`] for a directional rule, parsing the wire `action` as the [`Verdict`].
///
/// A security-group name sent with a directional rule type fails to parse as a verdict, which is the
/// intended rejection.
fn lower_match(
    dir: Direction,
    action: &str,
    fw_macro: &Option<String>,
    options: RuleOptions,
) -> Result<Kind, anyhow::Error> {
    let verdict: Verdict = action.parse()?;
    Ok(Kind::Match(RuleMatch::from_options(
        dir,
        verdict,
        fw_macro.clone(),
        options,
    )?))
}

/// Lower a wire API rule list entry into its position and parsed [`Rule`].
///
/// The `ipversion` is read-only (the firewall computes it from the addresses) and `digest` is a
/// concurrency token; neither is part of the parsed rule, so both are dropped. This is a free
/// function rather than a `TryFrom` impl because the orphan rule forbids implementing a foreign
/// trait for the tuple output `(u64, Rule)`.
pub fn lower_rule_list_entry(entry: &FirewallRuleListEntry) -> Result<(u64, Rule), anyhow::Error> {
    let FirewallRuleListEntry {
        pos,
        ipversion: _,
        digest: _,
        rule,
    } = entry;
    Ok((*pos, Rule::try_from(rule)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use proxmox_firewall_api_types::{
        FirewallAliasScope, FirewallConntrackHelper, FirewallIcmpTypeName, FirewallIpsetScope,
    };
    use proxmox_schema::CommaSeparatedList;
    use proxmox_schema::property_string::PropertyString;

    use crate::firewall::types::rule_match::{IcmpCode, IcmpType};

    #[test]
    fn icmp_v4_conversion_applies_mapping() {
        // a shared name maps to a named nftables type
        let icmp = Icmp::try_from(&FirewallIcmpType::Named(FirewallIcmpTypeName::EchoRequest))
            .expect("echo-request is valid for IPv4");
        assert_eq!(icmp.ty(), Some(&IcmpType::Named("echo-request")));
        assert_eq!(icmp.code(), None);

        // an iptables name that nftables expresses as a type/code pair
        let icmp = Icmp::try_from(&FirewallIcmpType::Named(
            FirewallIcmpTypeName::PortUnreachable,
        ))
        .expect("port-unreachable is valid for IPv4");
        assert_eq!(icmp.ty(), Some(&IcmpType::Numeric(3)));
        assert_eq!(icmp.code(), Some(&IcmpCode::Numeric(3)));

        // numeric passes straight through
        let icmp = Icmp::try_from(&FirewallIcmpType::Numeric(8)).expect("numeric is always valid");
        assert_eq!(icmp.ty(), Some(&IcmpType::Numeric(8)));
    }

    #[test]
    fn icmp_v6_conversion() {
        // numeric is always valid for IPv6 as well
        assert!(Icmpv6::try_from(&FirewallIcmpType::Numeric(128)).is_ok());

        // reject-route is IPv6-only; also guards the fixed mapping key (was "reject-route'")
        assert!(
            Icmpv6::try_from(&FirewallIcmpType::Named(FirewallIcmpTypeName::RejectRoute)).is_ok()
        );
    }

    #[test]
    fn address_match_lowers_via_fw_format() {
        // an IP/CIDR/range list lowers to the IP variant, family-checked by the local parser
        let api = "10.0.0.0/8,192.168.0.0-192.168.255.255"
            .parse::<FirewallAddressMatch>()
            .expect("valid address match");
        let lowered = IpAddrMatch::try_from(&api).expect("convertible");
        assert!(matches!(lowered, IpAddrMatch::Ip(_)));
        assert_eq!(
            lowered,
            "10.0.0.0/8,192.168.0.0-192.168.255.255".parse().unwrap()
        );

        // an ipset reference lowers to the Set variant
        let api = "+sdn/vnet0"
            .parse::<FirewallAddressMatch>()
            .expect("valid ipset match");
        assert!(matches!(
            IpAddrMatch::try_from(&api).expect("convertible"),
            IpAddrMatch::Set(_)
        ));

        // an alias reference lowers to the Alias variant
        let api = "dc/network"
            .parse::<FirewallAddressMatch>()
            .expect("valid alias match");
        assert!(matches!(
            IpAddrMatch::try_from(&api).expect("convertible"),
            IpAddrMatch::Alias(_)
        ));
    }

    #[test]
    fn port_list_lowers_via_fw_format() {
        // numbers and ranges lower unchanged (range separator ':' is shared)
        let api = "80:85,443"
            .parse::<FirewallPortList>()
            .expect("valid port list");
        assert_eq!(
            PortList::try_from(&api).expect("convertible"),
            "80:85,443".parse().unwrap()
        );

        // a service name is resolved to its number by the local parser
        let api = "https"
            .parse::<FirewallPortList>()
            .expect("valid port list");
        assert_eq!(
            PortList::try_from(&api).expect("convertible"),
            "443".parse().unwrap()
        );
    }

    #[test]
    fn alias_reference_lowers_via_fw_format() {
        let scoped =
            FirewallAliasReference::new(FirewallAliasScope::Datacenter, "network".to_string())
                .expect("valid alias");
        assert_eq!(
            RuleAliasName::try_from(&scoped).expect("convertible"),
            "dc/network".parse().unwrap()
        );

        let legacy = FirewallAliasReference::new(FirewallAliasScope::None, "network".to_string())
            .expect("valid alias");
        assert_eq!(
            RuleAliasName::try_from(&legacy).expect("convertible"),
            "network".parse().unwrap()
        );
    }

    #[test]
    fn ipset_reference_lowers_via_fw_format() {
        let scoped = FirewallIpsetReference::new(FirewallIpsetScope::Sdn, "vnet0".to_string())
            .expect("valid ipset");
        assert_eq!(
            RuleIpsetName::try_from(&scoped).expect("convertible"),
            "+sdn/vnet0".parse().unwrap()
        );
    }

    #[test]
    fn log_level_lowers_warning_spelling() {
        // the API spells it "warning"; the daemon's parser accepts that spelling
        assert_eq!(
            LogLevel::try_from(&FirewallLogLevel::Warning).expect("convertible"),
            LogLevel::Warning
        );
        assert_eq!(
            LogLevel::try_from(&FirewallLogLevel::Nolog).expect("convertible"),
            LogLevel::Nolog
        );
    }

    #[test]
    fn log_rate_limit_lowers_value_and_defaults() {
        // a full value as written in host.fw
        let api = "enable=1,rate=10/second,burst=5"
            .parse::<PropertyString<FirewallLogRateLimit>>()
            .expect("valid rate limit")
            .into_inner();
        assert_eq!(
            LogRateLimit::try_from(&api).expect("convertible"),
            "enable=1,rate=10/second,burst=5".parse().unwrap()
        );

        // unset fields fall back to the daemon defaults (rate 1/second, burst 5)
        let api = FirewallLogRateLimit {
            enable: false,
            burst: None,
            rate: None,
        };
        assert_eq!(
            LogRateLimit::try_from(&api).expect("convertible"),
            LogRateLimit::new(false, 1, LogRateLimitTimescale::Second, 5)
        );
    }

    #[test]
    fn policies_lower_to_verdict() {
        assert_eq!(
            Verdict::try_from(FirewallFWPolicy::Accept).unwrap(),
            Verdict::Accept
        );
        assert_eq!(
            Verdict::try_from(FirewallFWPolicy::Drop).unwrap(),
            Verdict::Drop
        );

        assert_eq!(
            Verdict::try_from(FirewallIOPolicy::Accept).unwrap(),
            Verdict::Accept
        );
        assert_eq!(
            Verdict::try_from(FirewallIOPolicy::Drop).unwrap(),
            Verdict::Drop
        );
        assert_eq!(
            Verdict::try_from(FirewallIOPolicy::Reject).unwrap(),
            Verdict::Reject
        );
    }

    #[test]
    fn conntrack_helper_list_parses_fw_value() {
        // the isomorphic case: the typed list parses the exact `.fw` value the daemon stores today
        // (see proxmox-firewall/tests/input/host.fw), gaining validation over the current Vec<String>
        let helpers: CommaSeparatedList<FirewallConntrackHelper> =
            "amanda,ftp,irc,netbios-ns,pptp,sane,sip,snmp,tftp"
                .parse()
                .expect("valid conntrack helper list");
        assert_eq!(helpers.len(), 9);
        assert_eq!(helpers[0], FirewallConntrackHelper::Amanda);
        assert_eq!(helpers[3], FirewallConntrackHelper::NetbiosNs);

        // an unknown helper is rejected, unlike the raw string list; with the enum-fallback
        // feature it is instead accepted as an unknown value, so only assert this without it
        #[cfg(not(feature = "enum-fallback"))]
        "ftp,bogus"
            .parse::<CommaSeparatedList<FirewallConntrackHelper>>()
            .expect_err("unknown conntrack helper must be rejected");
    }

    #[test]
    fn rule_lowers_like_the_fw_parser() {
        // Each case pairs a wire API rule with the equivalent `.fw` line; lowering the wire rule
        // must produce exactly what the daemon's own `.fw` parser produces for that line.
        let cases: &[(serde_json::Value, &str)] = &[
            // a directional match with protocol, port, address and log level
            (
                serde_json::json!({
                    "type": "in", "action": "ACCEPT", "proto": "tcp",
                    "dport": "443", "source": "10.0.0.0/8", "log": "nolog",
                }),
                "IN ACCEPT -p tcp -dport 443 -source 10.0.0.0/8 -log nolog",
            ),
            // a security group reference: the wire `action` carries the group name
            (
                serde_json::json!({"type": "group", "action": "network1", "iface": "net0"}),
                "GROUP network1 -i net0",
            ),
            // a macro rule: the wire form splits MACRO(VERDICT) into separate fields
            (
                serde_json::json!({"type": "in", "macro": "DNS", "action": "ACCEPT"}),
                "IN DNS(ACCEPT)",
            ),
            // IPv6 ICMP, dispatched via the protocol and lowered to the nftables name
            (
                serde_json::json!({
                    "type": "in", "action": "ACCEPT", "proto": "ipv6-icmp",
                    "icmp-type": "neighbor-solicitation", "log": "info",
                }),
                "IN ACCEPT -p ipv6-icmp -icmp-type neighbor-solicitation -log info",
            ),
            // a disabled rule: enable=0 corresponds to the `|` prefix
            (
                serde_json::json!({"type": "in", "action": "DROP", "enable": 0}),
                "|IN DROP",
            ),
        ];

        for (wire, line) in cases {
            let rule: FirewallRule = serde_json::from_value(wire.clone()).expect("valid wire rule");
            let lowered = Rule::try_from(&rule).expect("wire rule lowers");
            let parsed: Rule = line.parse().expect("valid .fw line");
            assert_eq!(lowered, parsed, "mismatch lowering `{line}`");
        }
    }

    #[test]
    fn rule_lowering_rejects_invalid_combinations() {
        let reject = |value: serde_json::Value| {
            let rule: FirewallRule = serde_json::from_value(value).expect("valid wire rule");
            Rule::try_from(&rule)
        };

        // dport and icmp-type are mutually exclusive
        reject(serde_json::json!({
            "type": "in", "action": "ACCEPT", "proto": "icmp",
            "dport": "80", "icmp-type": "echo-request",
        }))
        .expect_err("dport together with icmp-type must be rejected");

        // a macro is meaningless on a group rule
        reject(serde_json::json!({"type": "group", "action": "network1", "macro": "DNS"}))
            .expect_err("a macro on a group rule must be rejected");

        // a group name used as a directional verdict
        reject(serde_json::json!({"type": "in", "action": "network1"}))
            .expect_err("a non-verdict action on a directional rule must be rejected");

        // group rules permit only an interface
        reject(serde_json::json!({"type": "group", "action": "network1", "proto": "tcp"}))
            .expect_err("a group rule with a protocol must be rejected");
    }

    #[test]
    fn rule_list_entry_lowers_dropping_metadata() {
        let entry: FirewallRuleListEntry = serde_json::from_value(serde_json::json!({
            "pos": 7,
            "type": "in",
            "action": "ACCEPT",
            "digest": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        }))
        .expect("valid wire rule list entry");

        let (pos, rule) = lower_rule_list_entry(&entry).expect("list entry lowers");
        assert_eq!(pos, 7);
        assert_eq!(rule, "IN ACCEPT".parse().unwrap());
    }
}

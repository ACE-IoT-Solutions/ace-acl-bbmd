/// Pure-Rust ACL rule matching engine.
///
/// All IP addresses are pre-parsed to u32 for fast bitwise network matching.
/// Rules are sorted by priority at construction time so the hot path is a
/// simple linear scan with no allocations.

use crate::inspect;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RsRuleAction {
    Allow,
    Deny,
    Log,
    AllowLog,
}

impl RsRuleAction {
    pub fn from_str(s: &str) -> Self {
        match s {
            "allow" => RsRuleAction::Allow,
            "deny" => RsRuleAction::Deny,
            "log" => RsRuleAction::Log,
            "allow_log" => RsRuleAction::AllowLog,
            _ => RsRuleAction::Deny,
        }
    }

    #[inline]
    pub fn is_allow(self) -> bool {
        matches!(self, RsRuleAction::Allow | RsRuleAction::AllowLog)
    }
}

pub struct RsACLRule {
    pub name: String,
    pub action: RsRuleAction,
    pub priority: i32,
    pub source_network_addr: Option<u32>,
    pub source_network_mask: u32,
    pub dest_network_addr: Option<u32>,
    pub dest_network_mask: u32,
    pub source_device: Option<u32>,
    pub dest_device: Option<u32>,
    pub message_types: Vec<String>,
    pub match_all_types: bool,
}

impl RsACLRule {
    #[inline]
    fn matches_source(&self, src_ip: u32, src_device: Option<u32>) -> bool {
        if let Some(net_addr) = self.source_network_addr {
            if (src_ip & self.source_network_mask) != net_addr {
                return false;
            }
        }
        if let Some(expected) = self.source_device {
            if src_device != Some(expected) {
                return false;
            }
        }
        true
    }

    #[inline]
    fn matches_dest(&self, dst_ip: Option<u32>, dst_device: Option<u32>) -> bool {
        // None = broadcast, always matches
        if let Some(dst) = dst_ip {
            if let Some(net_addr) = self.dest_network_addr {
                if (dst & self.dest_network_mask) != net_addr {
                    return false;
                }
            }
        }
        if let Some(expected) = self.dest_device {
            if dst_device != Some(expected) {
                return false;
            }
        }
        true
    }

    #[inline]
    fn matches_message_type(&self, msg_type: &str) -> bool {
        if self.match_all_types {
            return true;
        }
        self.message_types.iter().any(|t| t == msg_type)
    }

    #[inline]
    pub fn matches(
        &self,
        src_ip: u32,
        dst_ip: Option<u32>,
        msg_type: &str,
        src_device: Option<u32>,
        dst_device: Option<u32>,
    ) -> bool {
        self.matches_source(src_ip, src_device)
            && self.matches_dest(dst_ip, dst_device)
            && self.matches_message_type(msg_type)
    }
}

pub struct RsACLEngine {
    pub rules: Vec<RsACLRule>,
    pub default_action: RsRuleAction,
}

impl RsACLEngine {
    pub fn new(mut rules: Vec<RsACLRule>, default_action: RsRuleAction) -> Self {
        rules.sort_by_key(|r| r.priority);
        RsACLEngine {
            rules,
            default_action,
        }
    }

    /// Find first matching rule and return (allowed, rule_name).
    pub fn find_matching_rule(
        &self,
        src_ip: u32,
        dst_ip: Option<u32>,
        msg_type: &str,
        src_device: Option<u32>,
        dst_device: Option<u32>,
    ) -> (bool, String) {
        for rule in &self.rules {
            if rule.matches(src_ip, dst_ip, msg_type, src_device, dst_device) {
                return (rule.action.is_allow(), rule.name.clone());
            }
        }
        (self.default_action.is_allow(), "default".to_string())
    }

    /// Full pipeline: decode raw NPDU/APDU bytes, then match ACL rules.
    ///
    /// `bvll_type` overrides the detected message type when provided (non-empty).
    /// This matches the Python ACLEngine.check_packet() semantics.
    ///
    /// Returns (allowed, rule_name, detected_message_type).
    pub fn check_packet_raw(
        &self,
        pdu_data: &[u8],
        src_ip: u32,
        dst_ip: Option<u32>,
        bvll_type: &str,
    ) -> (bool, String, &'static str) {
        let info = inspect::inspect_packet(pdu_data);

        // Use bvll_type override if provided, otherwise use detected type
        let msg_type: &str = if !bvll_type.is_empty() {
            // bvll_type is a caller-owned string, but we only need it for matching.
            // We can't return it as &'static str, so we'll return the detected one
            // for informational purposes and match on bvll_type.
            bvll_type
        } else {
            info.message_type
        };

        let src_device = info.source_device;
        let dst_device = info.dest_device;

        let (allowed, rule_name) =
            self.find_matching_rule(src_ip, dst_ip, msg_type, src_device, dst_device);

        (allowed, rule_name, info.message_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(name: &str, action: RsRuleAction, priority: i32, cidr: &str) -> RsACLRule {
        let net: ipnet::Ipv4Net = cidr.parse().unwrap();
        RsACLRule {
            name: name.to_string(),
            action,
            priority,
            source_network_addr: Some(u32::from(net.network())),
            source_network_mask: u32::from(net.netmask()),
            dest_network_addr: None,
            dest_network_mask: 0,
            source_device: None,
            dest_device: None,
            message_types: vec![],
            match_all_types: true,
        }
    }

    #[test]
    fn test_basic_allow() {
        let rules = vec![make_rule("r1", RsRuleAction::Allow, 0, "10.1.0.0/16")];
        let engine = RsACLEngine::new(rules, RsRuleAction::Deny);
        // 10.1.2.3
        let ip = (10 << 24) | (1 << 16) | (2 << 8) | 3;
        let (allowed, name) = engine.find_matching_rule(ip, None, "who_is", None, None);
        assert!(allowed);
        assert_eq!(name, "r1");
    }

    #[test]
    fn test_no_match_uses_default() {
        let rules = vec![make_rule("r1", RsRuleAction::Allow, 0, "10.1.0.0/16")];
        let engine = RsACLEngine::new(rules, RsRuleAction::Deny);
        // 172.16.1.1 — won't match
        let ip = (172 << 24) | (16 << 16) | (1 << 8) | 1;
        let (allowed, name) = engine.find_matching_rule(ip, None, "who_is", None, None);
        assert!(!allowed);
        assert_eq!(name, "default");
    }

    #[test]
    fn test_priority_ordering() {
        let rules = vec![
            make_rule("deny_first", RsRuleAction::Deny, 1, "10.0.0.0/8"),
            make_rule("allow_later", RsRuleAction::Allow, 10, "10.1.0.0/16"),
        ];
        let engine = RsACLEngine::new(rules, RsRuleAction::Deny);
        let ip = (10 << 24) | (1 << 16) | (2 << 8) | 3;
        let (allowed, name) = engine.find_matching_rule(ip, None, "who_is", None, None);
        assert!(!allowed);
        assert_eq!(name, "deny_first");
    }
}

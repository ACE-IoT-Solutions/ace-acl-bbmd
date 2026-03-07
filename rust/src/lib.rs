use pyo3::prelude::*;
use std::net::Ipv4Addr;

mod engine;
mod inspect;

use engine::{RsACLEngine, RsRuleAction};

/// Python-facing ACL rule for building the engine from Python.
#[pyclass(name = "RustACLRule")]
#[derive(Clone)]
struct PyACLRule {
    name: String,
    action: String,
    priority: i32,
    source_network_addr: Option<u32>,
    source_network_mask: u32,
    dest_network_addr: Option<u32>,
    dest_network_mask: u32,
    source_device: Option<u32>,
    dest_device: Option<u32>,
    message_types: Vec<String>,
    match_all_types: bool,
    enabled: bool,
}

#[pymethods]
impl PyACLRule {
    #[new]
    #[pyo3(signature = (
        name,
        action,
        priority,
        source_network = None,
        dest_network = None,
        source_device = None,
        dest_device = None,
        message_types = None,
        enabled = true,
    ))]
    fn new(
        name: String,
        action: String,
        priority: i32,
        source_network: Option<&str>,
        dest_network: Option<&str>,
        source_device: Option<u32>,
        dest_device: Option<u32>,
        message_types: Option<Vec<String>>,
        enabled: bool,
    ) -> PyResult<Self> {
        let (source_network_addr, source_network_mask) = match source_network {
            Some(cidr) => parse_cidr(cidr)?,
            None => (None, 0),
        };
        let (dest_network_addr, dest_network_mask) = match dest_network {
            Some(cidr) => parse_cidr(cidr)?,
            None => (None, 0),
        };

        let msg_types = message_types.unwrap_or_default();
        let match_all = msg_types.is_empty() || msg_types.iter().any(|t| t == "all");

        Ok(PyACLRule {
            name,
            action,
            priority,
            source_network_addr,
            source_network_mask,
            dest_network_addr,
            dest_network_mask,
            source_device,
            dest_device,
            message_types: msg_types,
            match_all_types: match_all,
            enabled,
        })
    }
}

/// Parse "10.1.0.0/16" into (network_u32, mask_u32)
fn parse_cidr(cidr: &str) -> PyResult<(Option<u32>, u32)> {
    let net: ipnet::Ipv4Net = cidr
        .parse()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid CIDR: {e}")))?;
    let addr_u32 = u32::from(net.network());
    let mask_u32 = u32::from(net.netmask());
    Ok((Some(addr_u32), mask_u32))
}

/// Parse "10.1.2.3:47808" or "10.1.2.3" into u32
fn parse_ip_str(ip_str: &str) -> Option<u32> {
    let ip_part = ip_str.split(':').next()?;
    let addr: Ipv4Addr = ip_part.parse().ok()?;
    Some(u32::from(addr))
}

/// The main Python-facing engine.
#[pyclass(name = "RustACLEngine")]
struct PyACLEngine {
    inner: RsACLEngine,
}

#[pymethods]
impl PyACLEngine {
    #[new]
    #[pyo3(signature = (rules, default_action = "deny"))]
    fn new(rules: Vec<PyACLRule>, default_action: &str) -> Self {
        let rs_rules: Vec<engine::RsACLRule> = rules
            .into_iter()
            .filter(|r| r.enabled)
            .map(|r| engine::RsACLRule {
                name: r.name,
                action: RsRuleAction::from_str(&r.action),
                priority: r.priority,
                source_network_addr: r.source_network_addr,
                source_network_mask: r.source_network_mask,
                dest_network_addr: r.dest_network_addr,
                dest_network_mask: r.dest_network_mask,
                source_device: r.source_device,
                dest_device: r.dest_device,
                message_types: r.message_types,
                match_all_types: r.match_all_types,
            })
            .collect();

        let default = RsRuleAction::from_str(default_action);

        PyACLEngine {
            inner: RsACLEngine::new(rs_rules, default),
        }
    }

    /// Check a packet and return (allowed: bool, rule_name: str).
    ///
    /// source_addr / dest_addr are strings like "10.1.2.3:47808" or "10.1.2.3".
    /// dest_addr can be None for broadcast.
    #[pyo3(signature = (source_addr, dest_addr = None, message_type = "all", source_device = None, dest_device = None))]
    fn check(
        &self,
        source_addr: &str,
        dest_addr: Option<&str>,
        message_type: &str,
        source_device: Option<u32>,
        dest_device: Option<u32>,
    ) -> (bool, String) {
        let src_ip = parse_ip_str(source_addr).unwrap_or(0);
        let dst_ip = dest_addr.and_then(parse_ip_str);

        self.inner
            .find_matching_rule(src_ip, dst_ip, message_type, source_device, dest_device)
    }

    /// Batch check multiple packets. Returns list of (allowed, rule_name).
    ///
    /// Each packet is (source_addr, dest_addr_or_none, message_type).
    fn check_batch(
        &self,
        packets: Vec<(String, Option<String>, String)>,
    ) -> Vec<(bool, String)> {
        packets
            .iter()
            .map(|(src, dst, msg)| {
                let src_ip = parse_ip_str(src).unwrap_or(0);
                let dst_ip = dst.as_deref().and_then(parse_ip_str);
                self.inner.find_matching_rule(src_ip, dst_ip, msg, None, None)
            })
            .collect()
    }

    /// Full-pipeline check: decode NPDU/APDU in Rust, then match ACL rules.
    ///
    /// Returns (allowed, rule_name, detected_message_type).
    ///
    /// `pdu_data`: raw BACnet NPDU bytes (after BVLL header).
    /// `source_addr`: IP:port string of the packet source.
    /// `dest_addr`: IP:port string or None for broadcast.
    /// `bvll_type`: BVLL-level message type override (e.g. "original_broadcast").
    ///              Empty string or None to auto-detect from APDU.
    #[pyo3(signature = (pdu_data, source_addr, dest_addr = None, bvll_type = None))]
    fn check_packet(
        &self,
        pdu_data: &[u8],
        source_addr: &str,
        dest_addr: Option<&str>,
        bvll_type: Option<&str>,
    ) -> (bool, String, String) {
        let src_ip = parse_ip_str(source_addr).unwrap_or(0);
        let dst_ip = dest_addr.and_then(parse_ip_str);
        let bvll = bvll_type.unwrap_or("");

        let (allowed, rule_name, detected_type) =
            self.inner.check_packet_raw(pdu_data, src_ip, dst_ip, bvll);

        (allowed, rule_name, detected_type.to_string())
    }

    /// Return the number of rules in the engine.
    fn rule_count(&self) -> usize {
        self.inner.rules.len()
    }
}

#[pymodule]
fn ace_acl_engine(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyACLRule>()?;
    m.add_class::<PyACLEngine>()?;
    Ok(())
}

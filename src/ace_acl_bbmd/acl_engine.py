"""
ACL Engine for BACnet Packet Filtering

This module provides advanced packet inspection and filtering capabilities
for BACnet messages, including deep packet inspection for application layer
message types.

Rule matching is delegated to a native Rust engine (ace_acl_engine) for
high throughput.  Packet inspection (BACnet NPDU/APDU decoding) remains in
Python since it depends on bacpypes3.
"""

import logging
from typing import Optional, Tuple, Dict, Any
from datetime import datetime

from bacpypes3.pdu import PDU, IPv4Address
from bacpypes3.npdu import NPDU
from bacpypes3.apdu import APDU, UnconfirmedRequestPDU, ConfirmedRequestPDU

from .models.acl import ACLConfig, ACLRule, RuleAction, MessageType

logger = logging.getLogger(__name__)

try:
    from ace_acl_engine import RustACLEngine, RustACLRule
    _RUST_AVAILABLE = True
    logger.info("Rust ACL engine loaded — using native rule matching")
except ImportError:
    _RUST_AVAILABLE = False
    logger.warning("Rust ACL engine not available — falling back to Python rule matching")


def _build_rust_engine(config: ACLConfig) -> "RustACLEngine":
    """Build a RustACLEngine from a Python ACLConfig."""
    rust_rules = []
    for r in config.rules:
        rust_rules.append(RustACLRule(
            name=r.name,
            action=r.action.value,
            priority=r.priority,
            source_network=str(r.source_network) if r.source_network else None,
            dest_network=str(r.dest_network) if r.dest_network else None,
            source_device=r.source_device,
            dest_device=r.dest_device,
            message_types=[mt.value for mt in r.message_types],
            enabled=r.enabled,
        ))
    return RustACLEngine(rust_rules, default_action=config.default_action.value)


class PacketInfo:
    """Extracted information from a BACnet packet."""

    def __init__(self):
        self.source_addr: Optional[IPv4Address] = None
        self.dest_addr: Optional[IPv4Address] = None
        self.source_network: Optional[int] = None
        self.dest_network: Optional[int] = None
        self.source_device: Optional[int] = None
        self.dest_device: Optional[int] = None
        self.message_type: str = "unknown"
        self.apdu_type: Optional[str] = None
        self.service_choice: Optional[int] = None
        self.object_type: Optional[str] = None
        self.property_id: Optional[str] = None
        self.priority: Optional[int] = None
        self.is_broadcast: bool = False
        self.packet_size: int = 0


class ACLEngine:
    """
    Advanced ACL engine for BACnet packet filtering.

    Packet inspection (BACnet NPDU/APDU decoding) is done in Python.
    Rule matching is delegated to a native Rust engine when available,
    falling back to the pure-Python implementation otherwise.
    """

    def __init__(self, config: ACLConfig):
        self.config = config
        self._rule_cache: Dict[str, Any] = {}
        self._rust_engine: Optional["RustACLEngine"] = None
        self._rules_by_name: Dict[str, ACLRule] = {}
        self._rebuild_rust_engine()

    def _rebuild_rust_engine(self) -> None:
        """(Re)build the Rust engine and the name→rule lookup from current config."""
        self._rules_by_name = {r.name: r for r in self.config.rules}
        if _RUST_AVAILABLE:
            try:
                self._rust_engine = _build_rust_engine(self.config)
                logger.debug("Rust ACL engine built with %d rules", len(self.config.rules))
            except Exception as e:
                logger.error("Failed to build Rust ACL engine, falling back to Python: %s", e)
                self._rust_engine = None

    def inspect_packet(
        self, pdu_data: bytes, source: IPv4Address, dest: Optional[IPv4Address] = None
    ) -> PacketInfo:
        """
        Perform deep packet inspection on BACnet packet data.

        Args:
            pdu_data: Raw packet data
            source: Source IP address
            dest: Destination IP address (None for broadcast)

        Returns:
            PacketInfo with extracted packet details
        """
        info = PacketInfo()
        info.source_addr = source
        info.dest_addr = dest
        info.is_broadcast = dest is None
        info.packet_size = len(pdu_data)

        try:
            # Try to decode NPDU
            pdu = PDU(pdu_data)
            npdu = NPDU.decode(pdu)

            # Extract network layer information
            if hasattr(npdu, "npduSADR") and npdu.npduSADR:
                info.source_network = npdu.npduSADR.addrNet
                # Extract device ID from network address if possible
                if len(npdu.npduSADR.addrAddr) >= 1:
                    info.source_device = npdu.npduSADR.addrAddr[0]

            if hasattr(npdu, "npduDADR") and npdu.npduDADR:
                info.dest_network = npdu.npduDADR.addrNet
                if len(npdu.npduDADR.addrAddr) >= 1:
                    info.dest_device = npdu.npduDADR.addrAddr[0]

            # Try to decode APDU for application layer info
            if hasattr(npdu, "pduData") and npdu.pduData:
                try:
                    apdu_pdu = PDU(npdu.pduData)
                    apdu = APDU.decode(apdu_pdu)

                    # Determine APDU type
                    if isinstance(apdu, UnconfirmedRequestPDU):
                        info.apdu_type = "unconfirmed_request"
                        info.service_choice = apdu.apduService

                        # Map common service choices to message types
                        if apdu.apduService == 8:  # whoIs
                            info.message_type = MessageType.WHO_IS.value
                        elif apdu.apduService == 0:  # iAm
                            info.message_type = MessageType.I_AM.value

                    elif isinstance(apdu, ConfirmedRequestPDU):
                        info.apdu_type = "confirmed_request"
                        info.service_choice = apdu.apduService

                        # Map service choices
                        if apdu.apduService == 12:  # readProperty
                            info.message_type = MessageType.READ_PROPERTY.value
                        elif apdu.apduService == 15:  # writeProperty
                            info.message_type = MessageType.WRITE_PROPERTY.value

                        # Try to extract object and property info
                        self._extract_service_parameters(apdu, info)

                except Exception as e:
                    logger.debug(f"Could not decode APDU: {e}")

        except Exception as e:
            logger.debug(f"Could not decode NPDU: {e}")

        return info

    def _extract_service_parameters(self, apdu: APDU, info: PacketInfo) -> None:
        """Extract service-specific parameters from APDU."""
        try:
            if hasattr(apdu, "objectIdentifier"):
                info.object_type = str(apdu.objectIdentifier[0])

            if hasattr(apdu, "propertyIdentifier"):
                info.property_id = str(apdu.propertyIdentifier)

            if hasattr(apdu, "priority"):
                info.priority = apdu.priority

        except Exception as e:
            logger.debug(f"Could not extract service parameters: {e}")

    def check_packet(
        self,
        pdu_data: bytes,
        source: IPv4Address,
        dest: Optional[IPv4Address] = None,
        bvll_type: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], PacketInfo]:
        """
        Check if a packet is allowed by ACL rules.

        Args:
            pdu_data: Raw packet data
            source: Source IP address
            dest: Destination IP address
            bvll_type: BVLL message type if known

        Returns:
            Tuple of (allowed, rule_name, packet_info)
        """
        # --- Fast path: Rust engine (NPDU decode + rule matching in Rust) ---
        if self._rust_engine is not None:
            src_str = str(source) if source else ""
            dst_str = str(dest) if dest else None

            allowed, rule_name, detected_type = self._rust_engine.check_packet(
                pdu_data,
                src_str,
                dst_str,
                bvll_type,
            )

            # Build a minimal PacketInfo for callers that need it
            info = PacketInfo()
            info.source_addr = source
            info.dest_addr = dest
            info.is_broadcast = dest is None
            info.packet_size = len(pdu_data)
            info.message_type = bvll_type if bvll_type else detected_type

            # Time-range check (not yet in Rust) — only for named rules
            if rule_name != "default":
                rule = self._rules_by_name.get(rule_name)
                if rule and rule.time_range and not self._check_time_range(rule.time_range):
                    allowed = self.config.default_action in (RuleAction.ALLOW, RuleAction.ALLOW_LOG)
                    rule_name = "default"
            return allowed, rule_name, info

        # --- Fallback: pure Python ---
        info = self.inspect_packet(pdu_data, source, dest)
        if bvll_type:
            info.message_type = bvll_type
        rule = self.config.find_matching_rule(
            source_addr=info.source_addr,
            dest_addr=info.dest_addr,
            message_type=info.message_type,
            source_device=info.source_device,
            dest_device=info.dest_device,
        )

        if rule:
            if rule.time_range and not self._check_time_range(rule.time_range):
                rule = None

        if rule:
            allowed = rule.action in (RuleAction.ALLOW, RuleAction.ALLOW_LOG)
            return allowed, rule.name, info

        allowed = self.config.default_action in (RuleAction.ALLOW, RuleAction.ALLOW_LOG)
        return allowed, "default", info

    def _check_time_range(self, time_range) -> bool:
        """Check if current time is within the specified time range."""
        now = datetime.now()
        current_time = now.strftime("%H:%M")
        current_day = now.strftime("%a").lower()

        # Check day of week
        if time_range.days and current_day not in time_range.days:
            return False

        # Check time
        if time_range.start <= current_time <= time_range.end:
            return True

        # Handle overnight ranges (e.g., 22:00 to 02:00)
        if time_range.start > time_range.end:
            if current_time >= time_range.start or current_time <= time_range.end:
                return True

        return False

    def get_cut_through_decision(
        self, source: IPv4Address, packet_info: Optional[PacketInfo] = None
    ) -> bool:
        """
        Determine if a source is eligible for cut-through forwarding.

        Args:
            source: Source IP address
            packet_info: Optional pre-inspected packet info

        Returns:
            True if eligible for cut-through forwarding
        """
        return self.config.is_cut_through_eligible(source)

    def update_config(self, new_config: ACLConfig) -> None:
        """
        Update the ACL configuration.

        Args:
            new_config: New ACL configuration
        """
        old_rules = len(self.config.rules) if self.config else 0
        self.config = new_config
        self._rule_cache.clear()
        self._rebuild_rust_engine()

        new_rules = len(new_config.rules)
        logger.info(
            f"ACL configuration updated: {old_rules} -> {new_rules} rules, "
            f"default_action={new_config.default_action.value}"
        )


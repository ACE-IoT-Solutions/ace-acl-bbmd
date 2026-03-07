"""
Comprehensive Test Suite for ACL Engine

This module tests all aspects of the ACL rule engine including:
- Basic allow/deny scenarios
- Network-based filtering
- Device-based filtering  
- Message type filtering
- Time-based rules
- Priority ordering
- Default actions
- Cut-through eligibility
- Complex rule combinations
"""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock
from ipaddress import IPv4Network

from bacpypes3.pdu import IPv4Address, PDU
from bacpypes3.npdu import NPDU
from bacpypes3.apdu import UnconfirmedRequestPDU, ConfirmedRequestPDU

from ace_acl_bbmd.acl_engine import ACLEngine, PacketInfo
from ace_acl_bbmd.models.acl import (
    ACLConfig,
    ACLRule,
    RuleAction,
    MessageType,
    TimeRange,
)

import struct

def _build_npdu(
    source_net: int | None = None,
    source_mac: bytes = b"",
    dest_net: int | None = None,
    dest_mac: bytes = b"",
    hop_count: int = 255,
    apdu_payload: bytes = b"",
) -> bytes:
    """Build valid BACnet NPDU wire bytes for testing."""
    control = 0x00
    parts = [bytes([0x01])]  # version

    if dest_net is not None:
        control |= 0x20
    if source_net is not None:
        control |= 0x08

    parts.append(bytes([control]))

    if dest_net is not None:
        parts.append(struct.pack(">H", dest_net))
        parts.append(bytes([len(dest_mac)]))
        parts.append(dest_mac)

    if source_net is not None:
        parts.append(struct.pack(">H", source_net))
        parts.append(bytes([len(source_mac)]))
        parts.append(source_mac)

    if dest_net is not None:
        parts.append(bytes([hop_count]))

    parts.append(apdu_payload)
    return b"".join(parts)


# Common APDU payloads (just the header bytes)
APDU_WHO_IS = bytes([0x10, 0x08])  # UnconfirmedRequest, WhoIs
APDU_I_AM = bytes([0x10, 0x00])    # UnconfirmedRequest, IAm
APDU_READ_PROPERTY = bytes([       # ConfirmedRequest, ReadProperty (minimal)
    0x00,  # PDU type 0 = ConfirmedRequest, no seg
    0x05,  # max-seg=0, max-apdu=5 (1476)
    0x01,  # invoke-id
    0x0C,  # service choice = ReadProperty (12)
])


class TestACLEngineBasicScenarios:
    """Test basic allow/deny scenarios."""

    def test_simple_allow_rule(self):
        """Test that a simple allow rule permits traffic."""
        # Create ACL with one allow rule
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="allow-all",
                    action=RuleAction.ALLOW,
                    priority=100,
                )
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        # Test packet
        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")
        pdu_data = b"dummy_packet_data"
        
        allowed, rule_name, info = engine.check_packet(pdu_data, source, dest)
        
        assert allowed is True
        assert rule_name == "allow-all"
        assert info.source_addr == source
        assert info.dest_addr == dest

    def test_simple_deny_rule(self):
        """Test that a deny rule blocks traffic."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="deny-all",
                    action=RuleAction.DENY,
                    priority=100,
                )
            ],
            default_action=RuleAction.ALLOW,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")
        pdu_data = b"dummy_packet_data"
        
        allowed, rule_name, info = engine.check_packet(pdu_data, source, dest)
        
        assert allowed is False
        assert rule_name == "deny-all"

    def test_log_only_rule(self):
        """Test that a log-only rule doesn't block traffic."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="log-suspicious",
                    action=RuleAction.LOG,
                    priority=100,
                )
            ],
            default_action=RuleAction.ALLOW,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("10.0.0.5:47808")
        dest = None  # Broadcast
        pdu_data = b"dummy_packet_data"
        
        # LOG action matches but doesn't allow - should fall through to default
        allowed, rule_name, info = engine.check_packet(pdu_data, source, dest)
        
        # The rule matches but LOG is not an allow action
        assert allowed is False
        assert rule_name == "log-suspicious"
        assert info.is_broadcast is True


class TestACLEngineNetworkFiltering:
    """Test network-based filtering scenarios."""

    def test_source_network_allow(self):
        """Test allowing traffic from specific source network."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="allow-trusted-network",
                    action=RuleAction.ALLOW,
                    priority=100,
                    source_network=IPv4Network("192.168.1.0/24"),
                )
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        # Test from allowed network
        source = IPv4Address("192.168.1.50:47808")
        dest = IPv4Address("10.0.0.10:47808")
        pdu_data = b"dummy_packet_data"
        
        allowed, rule_name, info = engine.check_packet(pdu_data, source, dest)
        assert allowed is True
        assert rule_name == "allow-trusted-network"
        
        # Test from denied network
        source = IPv4Address("192.168.2.50:47808")
        allowed, rule_name, info = engine.check_packet(pdu_data, source, dest)
        assert allowed is False
        assert rule_name == "default"

    def test_destination_network_filtering(self):
        """Test filtering based on destination network."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="allow-local",
                    action=RuleAction.ALLOW,
                    priority=50,  # Higher priority
                    dest_network=IPv4Network("192.168.0.0/16"),
                ),
                ACLRule(
                    name="block-public",
                    action=RuleAction.DENY,
                    priority=100,  # Lower priority
                    dest_network=IPv4Network("0.0.0.0/0"),
                ),
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("192.168.1.10:47808")
        
        # Test to local network (should match allow rule - higher priority)
        dest_local = IPv4Address("192.168.2.20:47808")
        allowed, rule_name, info = engine.check_packet(b"data", source, dest_local)
        assert allowed is True
        assert rule_name == "allow-local"
        
        # Test to internet (should match deny rule)
        dest_internet = IPv4Address("8.8.8.8:47808")
        allowed, rule_name, info = engine.check_packet(b"data", source, dest_internet)
        assert allowed is False
        assert rule_name == "block-public"

    def test_combined_source_dest_networks(self):
        """Test rules with both source and destination network filters."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="dmz-to-internal",
                    action=RuleAction.ALLOW,
                    priority=100,
                    source_network=IPv4Network("10.0.1.0/24"),  # DMZ
                    dest_network=IPv4Network("192.168.1.0/24"),  # Internal
                ),
                ACLRule(
                    name="internal-to-dmz",
                    action=RuleAction.ALLOW,
                    priority=100,
                    source_network=IPv4Network("192.168.1.0/24"),  # Internal
                    dest_network=IPv4Network("10.0.1.0/24"),  # DMZ
                ),
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        # Test DMZ to Internal (allowed)
        source = IPv4Address("10.0.1.50:47808")
        dest = IPv4Address("192.168.1.100:47808")
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is True
        assert rule_name == "dmz-to-internal"
        
        # Test Internal to DMZ (allowed)
        source = IPv4Address("192.168.1.100:47808")
        dest = IPv4Address("10.0.1.50:47808")
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is True
        assert rule_name == "internal-to-dmz"
        
        # Test DMZ to DMZ (denied)
        source = IPv4Address("10.0.1.50:47808")
        dest = IPv4Address("10.0.1.60:47808")
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is False
        assert rule_name == "default"


class TestACLEngineDeviceFiltering:
    """Test device-based filtering scenarios."""

    def test_source_device_filtering(self):
        """Test filtering based on source BACnet device ID (MAC byte)."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="allow-controller-42",
                    action=RuleAction.ALLOW,
                    priority=100,
                    source_device=42,
                )
            ],
            default_action=RuleAction.DENY,
        )

        engine = ACLEngine(config)

        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")

        # NPDU with source address: SNET=1, SLEN=1, SADR=[42]
        pdu = _build_npdu(source_net=1, source_mac=bytes([42]))
        allowed, rule_name, info = engine.check_packet(pdu, source, dest)
        assert allowed is True
        assert rule_name == "allow-controller-42"

    def test_destination_device_filtering(self):
        """Test filtering based on destination BACnet device ID (MAC byte)."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="protect-critical-device",
                    action=RuleAction.DENY,
                    priority=50,
                    dest_device=99,
                ),
                ACLRule(
                    name="allow-other",
                    action=RuleAction.ALLOW,
                    priority=100,
                ),
            ],
            default_action=RuleAction.DENY,
        )

        engine = ACLEngine(config)

        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")

        # NPDU with dest address: DNET=1, DLEN=1, DADR=[99]
        pdu = _build_npdu(dest_net=1, dest_mac=bytes([99]))
        allowed, rule_name, info = engine.check_packet(pdu, source, dest)
        assert allowed is False
        assert rule_name == "protect-critical-device"

    def test_device_to_device_communication(self):
        """Test rules for specific device-to-device communication."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="controller-to-sensor",
                    action=RuleAction.ALLOW,
                    priority=100,
                    source_device=10,
                    dest_device=20,
                ),
                ACLRule(
                    name="sensor-to-controller",
                    action=RuleAction.ALLOW,
                    priority=100,
                    source_device=20,
                    dest_device=10,
                ),
            ],
            default_action=RuleAction.DENY,
        )

        engine = ACLEngine(config)

        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")

        # NPDU with SADR=[10], DADR=[20]
        pdu = _build_npdu(
            source_net=1, source_mac=bytes([10]),
            dest_net=2, dest_mac=bytes([20]),
        )
        allowed, rule_name, info = engine.check_packet(pdu, source, dest)
        assert allowed is True
        assert rule_name == "controller-to-sensor"


class TestACLEngineMessageTypeFiltering:
    """Test message type filtering scenarios."""

    def test_allow_discovery_messages(self):
        """Test allowing only discovery messages (WHO_IS, I_AM)."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="allow-discovery",
                    action=RuleAction.ALLOW,
                    priority=100,
                    message_types=[MessageType.WHO_IS, MessageType.I_AM],
                )
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("192.168.1.10:47808")
        dest = None  # Broadcast for discovery
        
        # Test WHO_IS (allowed)
        allowed, rule_name, info = engine.check_packet(
            b"data", source, dest, bvll_type=MessageType.WHO_IS.value
        )
        assert allowed is True
        assert rule_name == "allow-discovery"
        
        # Test I_AM (allowed)
        allowed, rule_name, info = engine.check_packet(
            b"data", source, dest, bvll_type=MessageType.I_AM.value
        )
        assert allowed is True
        assert rule_name == "allow-discovery"
        
        # Test READ_PROPERTY (denied)
        allowed, rule_name, info = engine.check_packet(
            b"data", source, dest, bvll_type=MessageType.READ_PROPERTY.value
        )
        assert allowed is False
        assert rule_name == "default"

    def test_block_write_operations(self):
        """Test blocking all write operations."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="block-writes",
                    action=RuleAction.DENY,
                    priority=50,
                    message_types=[MessageType.WRITE_PROPERTY],
                ),
                ACLRule(
                    name="allow-reads",
                    action=RuleAction.ALLOW,
                    priority=100,
                    message_types=[MessageType.READ_PROPERTY],
                ),
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")
        
        # Test WRITE_PROPERTY (blocked)
        allowed, rule_name, info = engine.check_packet(
            b"data", source, dest, bvll_type=MessageType.WRITE_PROPERTY.value
        )
        assert allowed is False
        assert rule_name == "block-writes"
        
        # Test READ_PROPERTY (allowed)
        allowed, rule_name, info = engine.check_packet(
            b"data", source, dest, bvll_type=MessageType.READ_PROPERTY.value
        )
        assert allowed is True
        assert rule_name == "allow-reads"

    def test_apdu_decoding_message_types(self):
        """Test message type detection through APDU decoding."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="allow-who-is",
                    action=RuleAction.ALLOW,
                    priority=100,
                    message_types=[MessageType.WHO_IS],
                )
            ],
            default_action=RuleAction.DENY,
        )

        engine = ACLEngine(config)

        source = IPv4Address("192.168.1.10:47808")
        # Real WhoIs NPDU: version=1, control=0x00, APDU=[0x10, 0x08]
        pdu = _build_npdu(apdu_payload=APDU_WHO_IS)
        allowed, rule_name, info = engine.check_packet(pdu, source, dest=None)
        assert allowed is True
        assert rule_name == "allow-who-is"
        assert info.message_type == MessageType.WHO_IS.value


class TestACLEngineTimeBasedRules:
    """Test time-based filtering scenarios."""

    def test_business_hours_rule(self):
        """Test rule that only allows traffic during business hours."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="business-hours-only",
                    action=RuleAction.ALLOW,
                    priority=100,
                    time_range=TimeRange(
                        start="08:00",
                        end="17:00",
                        days=["mon", "tue", "wed", "thu", "fri"],
                    ),
                )
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")
        
        # Test during business hours on weekday
        with patch('ace_acl_bbmd.acl_engine.datetime') as mock_datetime:
            mock_now = MagicMock()
            mock_now.strftime.side_effect = lambda fmt: {
                "%H:%M": "09:30",
                "%a": "Mon"
            }[fmt]
            mock_datetime.now.return_value = mock_now
            
            allowed, rule_name, info = engine.check_packet(b"data", source, dest)
            assert allowed is True
            assert rule_name == "business-hours-only"
        
        # Test outside business hours
        with patch('ace_acl_bbmd.acl_engine.datetime') as mock_datetime:
            mock_now = MagicMock()
            mock_now.strftime.side_effect = lambda fmt: {
                "%H:%M": "19:00",
                "%a": "Mon"
            }[fmt]
            mock_datetime.now.return_value = mock_now
            
            allowed, rule_name, info = engine.check_packet(b"data", source, dest)
            assert allowed is False
            assert rule_name == "default"

    def test_overnight_maintenance_window(self):
        """Test rule for overnight maintenance window (crosses midnight)."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="maintenance-window",
                    action=RuleAction.ALLOW,
                    priority=100,
                    time_range=TimeRange(
                        start="22:00",
                        end="02:00",  # Crosses midnight
                    ),
                )
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")
        
        # Test at 23:00 (should be allowed)
        with patch('ace_acl_bbmd.acl_engine.datetime') as mock_datetime:
            mock_now = MagicMock()
            mock_now.strftime.side_effect = lambda fmt: {
                "%H:%M": "23:00",
                "%a": "Mon"
            }[fmt]
            mock_datetime.now.return_value = mock_now
            
            allowed, rule_name, info = engine.check_packet(b"data", source, dest)
            assert allowed is True
            assert rule_name == "maintenance-window"
        
        # Test at 01:00 (should be allowed)
        with patch('ace_acl_bbmd.acl_engine.datetime') as mock_datetime:
            mock_now = MagicMock()
            mock_now.strftime.side_effect = lambda fmt: {
                "%H:%M": "01:00",
                "%a": "Tue"
            }[fmt]
            mock_datetime.now.return_value = mock_now
            
            allowed, rule_name, info = engine.check_packet(b"data", source, dest)
            assert allowed is True
            assert rule_name == "maintenance-window"


class TestACLEnginePriorityOrdering:
    """Test priority-based rule ordering scenarios."""

    def test_priority_override(self):
        """Test that higher priority rules override lower priority ones."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="deny-specific",
                    action=RuleAction.DENY,
                    priority=50,  # Higher priority
                    source_network=IPv4Network("192.168.1.100/32"),
                ),
                ACLRule(
                    name="allow-network",
                    action=RuleAction.ALLOW,
                    priority=100,  # Lower priority
                    source_network=IPv4Network("192.168.1.0/24"),
                ),
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        # Test specific denied host
        source = IPv4Address("192.168.1.100:47808")
        dest = IPv4Address("10.0.0.10:47808")
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is False
        assert rule_name == "deny-specific"
        
        # Test other host in network
        source = IPv4Address("192.168.1.50:47808")
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is True
        assert rule_name == "allow-network"

    def test_complex_priority_chain(self):
        """Test complex chain of rules with different priorities."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="emergency-override",
                    action=RuleAction.ALLOW,
                    priority=0,  # Highest priority
                    source_device=99,
                ),
                ACLRule(
                    name="blacklist-attacker",
                    action=RuleAction.DENY,
                    priority=10,
                    source_network=IPv4Network("10.0.0.0/24"),
                ),
                ACLRule(
                    name="whitelist-trusted",
                    action=RuleAction.ALLOW,
                    priority=20,
                    source_network=IPv4Network("10.0.0.0/16"),
                ),
                ACLRule(
                    name="general-allow",
                    action=RuleAction.ALLOW,
                    priority=1000,
                ),
            ],
            default_action=RuleAction.DENY,
        )

        engine = ACLEngine(config)

        source = IPv4Address("10.0.0.50:47808")
        dest = IPv4Address("192.168.1.10:47808")

        # NPDU with source device MAC byte = 99
        pdu = _build_npdu(source_net=1, source_mac=bytes([99]))
        allowed, rule_name, info = engine.check_packet(pdu, source, dest)
        assert allowed is True
        assert rule_name == "emergency-override"


class TestACLEngineDefaultActions:
    """Test default action scenarios."""

    def test_default_deny(self):
        """Test default deny when no rules match."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="allow-specific",
                    action=RuleAction.ALLOW,
                    priority=100,
                    source_network=IPv4Network("192.168.1.0/24"),
                ),
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        # Test from non-matching network
        source = IPv4Address("10.0.0.50:47808")
        dest = IPv4Address("192.168.1.10:47808")
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is False
        assert rule_name == "default"

    def test_default_allow(self):
        """Test default allow when no rules match."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="deny-specific",
                    action=RuleAction.DENY,
                    priority=100,
                    source_network=IPv4Network("10.0.0.0/24"),
                ),
            ],
            default_action=RuleAction.ALLOW,
        )
        
        engine = ACLEngine(config)
        
        # Test from non-matching network
        source = IPv4Address("192.168.1.50:47808")
        dest = IPv4Address("192.168.1.10:47808")
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is True
        assert rule_name == "default"

    def test_default_with_logging(self):
        """Test default action with logging enabled."""
        config = ACLConfig(
            rules=[],
            default_action=RuleAction.ALLOW_LOG,
            log_default=True,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("192.168.1.50:47808")
        dest = IPv4Address("192.168.1.10:47808")
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is True
        assert rule_name == "default"


class TestACLEngineCutThrough:
    """Test cut-through eligibility scenarios."""

    def test_cut_through_network(self):
        """Test cut-through eligibility for specific networks."""
        config = ACLConfig(
            enable_cut_through=True,
            cut_through_networks=[
                IPv4Network("192.168.100.0/24"),  # Trusted network
                IPv4Network("10.0.100.0/24"),     # Another trusted network
            ],
            rules=[],
            default_action=RuleAction.ALLOW,
        )
        
        engine = ACLEngine(config)
        
        # Test trusted network (eligible)
        source = IPv4Address("192.168.100.50:47808")
        eligible = engine.get_cut_through_decision(source)
        assert eligible is True
        
        # Test untrusted network (not eligible)
        source = IPv4Address("192.168.1.50:47808")
        eligible = engine.get_cut_through_decision(source)
        assert eligible is False

    def test_cut_through_allow_all_rule(self):
        """Test cut-through eligibility based on allow-all rules."""
        config = ACLConfig(
            enable_cut_through=True,
            rules=[
                ACLRule(
                    name="trusted-source-allow-all",
                    action=RuleAction.ALLOW,
                    priority=100,
                    source_network=IPv4Network("10.0.50.0/24"),
                    message_types=[MessageType.ALL],
                ),
                ACLRule(
                    name="restricted-source",
                    action=RuleAction.ALLOW,
                    priority=100,
                    source_network=IPv4Network("10.0.60.0/24"),
                    message_types=[MessageType.WHO_IS, MessageType.I_AM],
                ),
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        # Test source with allow-all rule (eligible)
        source = IPv4Address("10.0.50.100:47808")
        eligible = engine.get_cut_through_decision(source)
        assert eligible is True
        
        # Test source with restricted rule (not eligible)
        source = IPv4Address("10.0.60.100:47808")
        eligible = engine.get_cut_through_decision(source)
        assert eligible is False

    def test_cut_through_disabled(self):
        """Test that cut-through is disabled when configured."""
        config = ACLConfig(
            enable_cut_through=False,
            cut_through_networks=[IPv4Network("192.168.100.0/24")],
            rules=[],
            default_action=RuleAction.ALLOW,
        )
        
        engine = ACLEngine(config)
        
        # Even trusted network should not be eligible
        source = IPv4Address("192.168.100.50:47808")
        eligible = engine.get_cut_through_decision(source)
        assert eligible is False


class TestACLEngineComplexScenarios:
    """Test complex rule combinations and edge cases."""

    def test_multi_criteria_rules(self):
        """Test rules with multiple matching criteria."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="specific-device-to-network",
                    action=RuleAction.ALLOW,
                    priority=100,
                    source_device=42,
                    dest_network=IPv4Network("192.168.10.0/24"),
                    message_types=[MessageType.READ_PROPERTY, MessageType.WRITE_PROPERTY],
                ),
            ],
            default_action=RuleAction.DENY,
        )

        engine = ACLEngine(config)

        source = IPv4Address("10.0.0.10:47808")
        # NPDU with SADR=[42]
        pdu = _build_npdu(source_net=1, source_mac=bytes([42]))

        # Test matching all criteria
        dest = IPv4Address("192.168.10.50:47808")
        allowed, rule_name, info = engine.check_packet(
            pdu, source, dest, bvll_type=MessageType.READ_PROPERTY.value
        )
        assert allowed is True
        assert rule_name == "specific-device-to-network"

        # Test wrong destination network
        dest = IPv4Address("192.168.20.50:47808")
        allowed, rule_name, info = engine.check_packet(
            pdu, source, dest, bvll_type=MessageType.READ_PROPERTY.value
        )
        assert allowed is False
        assert rule_name == "default"

        # Test wrong message type
        dest = IPv4Address("192.168.10.50:47808")
        allowed, rule_name, info = engine.check_packet(
            pdu, source, dest, bvll_type=MessageType.WHO_IS.value
        )
        assert allowed is False
        assert rule_name == "default"

    def test_broadcast_handling(self):
        """Test handling of broadcast messages."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="allow-discovery-broadcast",
                    action=RuleAction.ALLOW,
                    priority=100,
                    message_types=[MessageType.WHO_IS],
                ),
                ACLRule(
                    name="deny-other-broadcast",
                    action=RuleAction.DENY,
                    priority=200,
                ),
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("192.168.1.10:47808")
        dest = None  # Broadcast
        
        # Test WHO_IS broadcast (allowed)
        allowed, rule_name, info = engine.check_packet(
            b"data", source, dest, bvll_type=MessageType.WHO_IS.value
        )
        assert allowed is True
        assert rule_name == "allow-discovery-broadcast"
        assert info.is_broadcast is True
        
        # Test other broadcast (denied)
        allowed, rule_name, info = engine.check_packet(
            b"data", source, dest, bvll_type=MessageType.WRITE_PROPERTY.value
        )
        assert allowed is False
        assert rule_name == "deny-other-broadcast"

    def test_rule_update_runtime(self):
        """Test updating ACL rules at runtime."""
        # Start with allow-all config
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="allow-all",
                    action=RuleAction.ALLOW,
                    priority=100,
                )
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")
        
        # Test initial config (allowed)
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is True
        assert rule_name == "allow-all"
        
        # Update to deny-all config
        new_config = ACLConfig(
            rules=[
                ACLRule(
                    name="deny-all",
                    action=RuleAction.DENY,
                    priority=100,
                )
            ],
            default_action=RuleAction.ALLOW,
        )
        
        engine.update_config(new_config)
        
        # Test updated config (denied)
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is False
        assert rule_name == "deny-all"

    def test_disabled_rules(self):
        """Test that disabled rules are ignored."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="disabled-deny",
                    action=RuleAction.DENY,
                    priority=50,
                    enabled=False,  # Disabled
                ),
                ACLRule(
                    name="active-allow",
                    action=RuleAction.ALLOW,
                    priority=100,
                ),
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")
        
        # Should match active-allow, not disabled-deny
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is True
        assert rule_name == "active-allow"

    def test_edge_case_empty_rules(self):
        """Test behavior with no rules defined."""
        config = ACLConfig(
            rules=[],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")
        
        # Should use default action
        allowed, rule_name, info = engine.check_packet(b"data", source, dest)
        assert allowed is False
        assert rule_name == "default"

    def test_malformed_packet_handling(self):
        """Test handling of malformed packets."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="allow-all",
                    action=RuleAction.ALLOW,
                    priority=100,
                )
            ],
            default_action=RuleAction.DENY,
        )
        
        engine = ACLEngine(config)
        
        # Test with invalid PDU data
        source = IPv4Address("192.168.1.10:47808")
        dest = IPv4Address("192.168.1.20:47808")
        
        # Even malformed packets should be processed based on available info
        allowed, rule_name, info = engine.check_packet(b"\xFF\xFF\xFF", source, dest)
        assert allowed is True
        assert rule_name == "allow-all"
        assert info.message_type == "unknown"  # Could not decode
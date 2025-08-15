"""
Tests for ACL models
"""

import pytest
from ipaddress import IPv4Address, IPv4Network

from ace_acl_bbmd.models.acl import (
    RuleAction, MessageType, TimeRange, ACLRule, ACLConfig
)


class TestACLRule:
    """Test ACL rule functionality."""
    
    def test_rule_creation(self):
        """Test creating an ACL rule."""
        rule = ACLRule(
            name="test_rule",
            action=RuleAction.ALLOW,
            priority=10,
            source_network="192.168.1.0/24",
            message_types=[MessageType.WHO_IS, MessageType.I_AM],
        )
        
        assert rule.name == "test_rule"
        assert rule.action == RuleAction.ALLOW
        assert rule.priority == 10
        assert isinstance(rule.source_network, IPv4Network)
        assert MessageType.WHO_IS in rule.message_types
    
    def test_matches_source(self):
        """Test source matching."""
        rule = ACLRule(
            name="test",
            action=RuleAction.ALLOW,
            source_network="192.168.1.0/24",
            source_device=12345,
        )
        
        # Network match
        assert rule.matches_source(IPv4Address("192.168.1.100"), 12345)
        assert not rule.matches_source(IPv4Address("192.168.2.100"), 12345)
        
        # Device match
        assert not rule.matches_source(IPv4Address("192.168.1.100"), 54321)
        
        # No constraints
        rule_any = ACLRule(name="any", action=RuleAction.ALLOW)
        assert rule_any.matches_source(IPv4Address("10.0.0.1"))
    
    def test_matches_destination(self):
        """Test destination matching."""
        rule = ACLRule(
            name="test",
            action=RuleAction.ALLOW,
            dest_network="10.1.0.0/16",
        )
        
        # Network match
        assert rule.matches_destination(IPv4Address("10.1.2.3"))
        assert not rule.matches_destination(IPv4Address("10.2.2.3"))
        
        # Broadcast always matches
        assert rule.matches_destination(None)
    
    def test_matches_message_type(self):
        """Test message type matching."""
        rule = ACLRule(
            name="test",
            action=RuleAction.ALLOW,
            message_types=[MessageType.READ_PROPERTY, MessageType.WRITE_PROPERTY],
        )
        
        assert rule.matches_message_type("read_property")
        assert rule.matches_message_type("write_property")
        assert not rule.matches_message_type("who_is")
        
        # ALL matches everything
        rule_all = ACLRule(
            name="all",
            action=RuleAction.ALLOW,
            message_types=[MessageType.ALL],
        )
        assert rule_all.matches_message_type("anything")
    
    def test_time_range(self):
        """Test time range validation."""
        time_range = TimeRange(
            start="08:00",
            end="17:00",
            days=["mon", "tue", "wed", "thu", "fri"],
        )
        
        assert time_range.start == "08:00"
        assert time_range.end == "17:00"
        assert "mon" in time_range.days
        
        # Invalid time format should raise error
        with pytest.raises(ValueError):
            TimeRange(start="8:00", end="17:00")


class TestACLConfig:
    """Test ACL configuration functionality."""
    
    def test_config_creation(self):
        """Test creating ACL configuration."""
        config = ACLConfig(
            rules=[
                ACLRule(name="rule1", action=RuleAction.ALLOW, priority=10),
                ACLRule(name="rule2", action=RuleAction.DENY, priority=20),
            ],
            default_action=RuleAction.DENY,
            enable_cut_through=True,
            cut_through_networks=["10.0.0.0/8"],
        )
        
        assert len(config.rules) == 2
        assert config.default_action == RuleAction.DENY
        assert config.enable_cut_through
        assert len(config.cut_through_networks) == 1
    
    def test_get_sorted_rules(self):
        """Test rule sorting by priority."""
        config = ACLConfig(
            rules=[
                ACLRule(name="rule3", action=RuleAction.ALLOW, priority=30),
                ACLRule(name="rule1", action=RuleAction.ALLOW, priority=10),
                ACLRule(name="rule2", action=RuleAction.ALLOW, priority=20),
                ACLRule(name="disabled", action=RuleAction.DENY, priority=5, enabled=False),
            ]
        )
        
        sorted_rules = config.get_sorted_rules()
        assert len(sorted_rules) == 3  # Disabled rule excluded
        assert sorted_rules[0].name == "rule1"
        assert sorted_rules[1].name == "rule2"
        assert sorted_rules[2].name == "rule3"
    
    def test_find_matching_rule(self):
        """Test finding matching rules."""
        config = ACLConfig(
            rules=[
                ACLRule(
                    name="deny_10",
                    action=RuleAction.DENY,
                    priority=10,
                    source_network="10.0.0.0/24",
                ),
                ACLRule(
                    name="allow_192",
                    action=RuleAction.ALLOW,
                    priority=20,
                    source_network="192.168.0.0/16",
                ),
            ]
        )
        
        # Should match first rule
        rule = config.find_matching_rule(
            source_addr=IPv4Address("10.0.0.100"),
            dest_addr=None,
            message_type="who_is",
        )
        assert rule is not None
        assert rule.name == "deny_10"
        
        # Should match second rule
        rule = config.find_matching_rule(
            source_addr=IPv4Address("192.168.1.100"),
            dest_addr=None,
            message_type="who_is",
        )
        assert rule is not None
        assert rule.name == "allow_192"
        
        # No match
        rule = config.find_matching_rule(
            source_addr=IPv4Address("172.16.0.1"),
            dest_addr=None,
            message_type="who_is",
        )
        assert rule is None
    
    def test_is_cut_through_eligible(self):
        """Test cut-through eligibility checking."""
        config = ACLConfig(
            enable_cut_through=True,
            cut_through_networks=["10.1.0.0/16", "192.168.100.0/24"],
            rules=[
                ACLRule(
                    name="allow_all_172",
                    action=RuleAction.ALLOW,
                    priority=10,
                    source_network="172.16.0.0/12",
                    message_types=[MessageType.ALL],
                ),
            ],
        )
        
        # In cut-through network list
        assert config.is_cut_through_eligible(IPv4Address("10.1.2.3"))
        assert config.is_cut_through_eligible(IPv4Address("192.168.100.50"))
        
        # Has allow-all rule
        assert config.is_cut_through_eligible(IPv4Address("172.16.1.1"))
        
        # Not eligible
        assert not config.is_cut_through_eligible(IPv4Address("8.8.8.8"))
        
        # Disabled cut-through
        config.enable_cut_through = False
        assert not config.is_cut_through_eligible(IPv4Address("10.1.2.3"))
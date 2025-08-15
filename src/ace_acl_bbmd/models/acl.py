"""
ACL Rule Models for BACnet BBMD

This module defines the structure for Access Control List rules that
determine which BACnet packets are allowed through the BBMD.
"""

from enum import Enum
from typing import List, Optional, Union
from ipaddress import IPv4Network

from pydantic import BaseModel, Field, field_validator
from bacpypes3.pdu import IPv4Address


class RuleAction(str, Enum):
    """ACL rule actions."""

    ALLOW = "allow"
    DENY = "deny"
    LOG = "log"  # Log but don't block
    ALLOW_LOG = "allow_log"  # Allow and log


class MessageType(str, Enum):
    """BACnet message types for filtering."""

    # BVLL Message Types
    ORIGINAL_UNICAST = "original_unicast"
    ORIGINAL_BROADCAST = "original_broadcast"
    FORWARDED_NPDU = "forwarded_npdu"
    DISTRIBUTE_BROADCAST = "distribute_broadcast"
    REGISTER_FOREIGN_DEVICE = "register_foreign_device"
    READ_BDT = "read_bdt"
    WRITE_BDT = "write_bdt"
    READ_FDT = "read_fdt"
    DELETE_FDT_ENTRY = "delete_fdt_entry"
    # Higher level message types (from NPDU)
    WHO_IS = "who_is"
    I_AM = "i_am"
    READ_PROPERTY = "read_property"
    WRITE_PROPERTY = "write_property"
    ALL = "all"  # Match all message types


class TimeRange(BaseModel):
    """Time range for rule application."""

    start: str = Field(..., pattern=r"^\d{2}:\d{2}$", description="Start time HH:MM")
    end: str = Field(..., pattern=r"^\d{2}:\d{2}$", description="End time HH:MM")
    days: Optional[List[str]] = Field(
        default=None, description="Days of week (mon, tue, wed, thu, fri, sat, sun)"
    )


class ACLRule(BaseModel):
    """Individual ACL rule."""

    name: str = Field(..., description="Rule name for identification")
    action: RuleAction = Field(..., description="Action to take")
    priority: int = Field(
        default=100, ge=0, le=1000, description="Rule priority (0=highest)"
    )

    # Source/Destination filters
    source_network: Optional[Union[IPv4Network, str]] = Field(
        default=None, description="Source network in CIDR notation"
    )
    source_device: Optional[int] = Field(
        default=None, ge=0, le=4194303, description="Source BACnet device instance"
    )
    dest_network: Optional[Union[IPv4Network, str]] = Field(
        default=None, description="Destination network in CIDR notation"
    )
    dest_device: Optional[int] = Field(
        default=None, ge=0, le=4194303, description="Destination BACnet device instance"
    )

    # Message type filter
    message_types: List[MessageType] = Field(
        default_factory=lambda: [MessageType.ALL], description="Message types to match"
    )

    # Time-based restrictions
    time_range: Optional[TimeRange] = Field(
        default=None, description="Time range when rule is active"
    )

    # Metrics and logging
    log_matches: bool = Field(default=False, description="Log when rule matches")
    enabled: bool = Field(default=True, description="Whether rule is active")

    @field_validator("source_network", "dest_network", mode="before")
    @classmethod
    def validate_network(
        cls, v: Optional[Union[IPv4Network, str]]
    ) -> Optional[IPv4Network]:
        if v is None:
            return None
        if isinstance(v, str):
            return IPv4Network(v)
        return v

    def matches_source(
        self, addr: IPv4Address, device_id: Optional[int] = None
    ) -> bool:
        """Check if source matches this rule."""
        if self.source_network:
            # Extract IP from BACPypes3 IPv4Address (format: "192.168.1.1:47808")
            ip_str = str(addr).split(':')[0]
            try:
                from ipaddress import ip_address
                if ip_address(ip_str) not in self.source_network:
                    return False
            except ValueError:
                return False
        if self.source_device is not None and device_id != self.source_device:
            return False
        return True

    def matches_destination(
        self, addr: Optional[IPv4Address], device_id: Optional[int] = None
    ) -> bool:
        """Check if destination matches this rule."""
        if addr is None:  # Broadcast
            return True
        if self.dest_network:
            # Extract IP from BACPypes3 IPv4Address (format: "192.168.1.1:47808")
            ip_str = str(addr).split(':')[0]
            try:
                from ipaddress import ip_address
                if ip_address(ip_str) not in self.dest_network:
                    return False
            except ValueError:
                return False
        if self.dest_device is not None and device_id != self.dest_device:
            return False
        return True

    def matches_message_type(self, msg_type: str) -> bool:
        """Check if message type matches this rule."""
        if MessageType.ALL in self.message_types:
            return True
        return msg_type in [mt.value for mt in self.message_types]


class ACLConfig(BaseModel):
    """Complete ACL configuration."""

    rules: List[ACLRule] = Field(default_factory=list, description="List of ACL rules")
    default_action: RuleAction = Field(
        default=RuleAction.DENY, description="Default action if no rules match"
    )
    log_default: bool = Field(
        default=True, description="Log packets that hit default action"
    )

    # Performance optimization
    enable_cut_through: bool = Field(
        default=True, description="Enable cut-through forwarding for allow-all rules"
    )
    cut_through_networks: List[IPv4Network] = Field(
        default_factory=list, description="Networks eligible for cut-through forwarding"
    )

    def get_sorted_rules(self) -> List[ACLRule]:
        """Get rules sorted by priority (ascending)."""
        return sorted([r for r in self.rules if r.enabled], key=lambda r: r.priority)

    def find_matching_rule(
        self,
        source_addr: IPv4Address,
        dest_addr: Optional[IPv4Address],
        message_type: str,
        source_device: Optional[int] = None,
        dest_device: Optional[int] = None,
    ) -> Optional[ACLRule]:
        """Find the first matching rule for a packet."""
        for rule in self.get_sorted_rules():
            if (
                rule.matches_source(source_addr, source_device)
                and rule.matches_destination(dest_addr, dest_device)
                and rule.matches_message_type(message_type)
            ):
                return rule
        return None

    def is_cut_through_eligible(self, source_addr: IPv4Address) -> bool:
        """Check if source is eligible for cut-through forwarding."""
        if not self.enable_cut_through:
            return False

        # Check if source is in cut-through networks
        # Extract IP from BACPypes3 IPv4Address (format: "192.168.1.1:47808")
        ip_str = str(source_addr).split(':')[0]
        try:
            from ipaddress import ip_address
            source_ip = ip_address(ip_str)
            for network in self.cut_through_networks:
                if source_ip in network:
                    return True
        except ValueError:
            pass

        # Check if there's an allow-all rule for this source
        for rule in self.get_sorted_rules():
            if (
                rule.action in (RuleAction.ALLOW, RuleAction.ALLOW_LOG)
                and rule.matches_source(source_addr)
                and MessageType.ALL in rule.message_types
                and rule.dest_network is None
                and rule.dest_device is None
            ):
                return True

        return False


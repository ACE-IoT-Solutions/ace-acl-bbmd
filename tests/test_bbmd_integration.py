"""
Integration Tests for ACL BBMD

This module tests the integration of the BBMD with ACL engine and metrics.
"""

import pytest
import pytest_asyncio
import asyncio
from unittest.mock import MagicMock, patch, AsyncMock
from ipaddress import IPv4Network

from bacpypes3.pdu import IPv4Address
from bacpypes3.ipv4.bvll import LPDU, OriginalUnicastNPDU, OriginalBroadcastNPDU

from ace_acl_bbmd.bbmd import ACLBBMD
from ace_acl_bbmd.models.acl import ACLConfig, ACLRule, RuleAction, MessageType
from ace_acl_bbmd.config import BBMDConfig


class TestBBMDIntegration:
    """Test BBMD integration with ACL engine."""

    @pytest.fixture
    def config(self):
        """Create a test BBMD configuration."""
        return BBMDConfig(
            bbmd_address="192.168.1.1:47808",
            acl=ACLConfig(
                rules=[
                    ACLRule(
                        name="allow-local",
                        action=RuleAction.ALLOW,
                        priority=100,
                        source_network=IPv4Network("192.168.1.0/24"),
                    ),
                    ACLRule(
                        name="deny-untrusted",
                        action=RuleAction.DENY,
                        priority=50,
                        source_network=IPv4Network("10.0.0.0/24"),
                    ),
                    ACLRule(
                        name="allow-discovery",
                        action=RuleAction.ALLOW,
                        priority=100,
                        message_types=[MessageType.WHO_IS, MessageType.I_AM],
                    ),
                ],
                default_action=RuleAction.DENY,
                enable_cut_through=True,
                cut_through_networks=[IPv4Network("192.168.100.0/24")],
            ),
            enable_metrics=True,
        )

    @pytest_asyncio.fixture
    async def bbmd(self, config):
        """Create an ACLBBMD instance."""
        bbmd = ACLBBMD(config=config)
        yield bbmd
        # Clean up
        if hasattr(bbmd, '_cache_cleanup_handle') and bbmd._cache_cleanup_handle:
            bbmd._cache_cleanup_handle.cancel()

    def create_lpdu(self, source, dest=None, lpdu_class=OriginalUnicastNPDU, data=b"test_data"):
        """Helper to create mock LPDU."""
        lpdu = MagicMock(spec=LPDU)
        lpdu.pduSource = IPv4Address(source)
        lpdu.pduDestination = IPv4Address(dest) if dest else None
        lpdu.__class__ = lpdu_class
        lpdu.encode = MagicMock(return_value=data)
        lpdu.pduData = data
        lpdu.pduUserData = None
        return lpdu

    @pytest.mark.asyncio
    async def test_acl_allows_local_traffic(self, bbmd):
        """Test that local network traffic is allowed."""
        lpdu = self.create_lpdu("192.168.1.10:47808", "192.168.1.20:47808")
        
        confirmation_called = False
        async def mock_confirmation(self, lpdu):
            nonlocal confirmation_called
            confirmation_called = True
        
        with patch.object(bbmd.__class__.__bases__[0], 'confirmation', mock_confirmation):
            await bbmd.confirmation(lpdu)
        
        assert confirmation_called  # Packet was forwarded
        assert bbmd.metrics.get_snapshot().packets_allowed == 1

    @pytest.mark.asyncio
    async def test_acl_denies_untrusted_traffic(self, bbmd):
        """Test that untrusted network traffic is denied."""
        lpdu = self.create_lpdu("10.0.0.50:47808", "192.168.1.20:47808")
        
        confirmation_called = False
        async def mock_confirmation(self, lpdu):
            nonlocal confirmation_called
            confirmation_called = True
        
        with patch.object(bbmd.__class__.__bases__[0], 'confirmation', mock_confirmation):
            await bbmd.confirmation(lpdu)
        
        assert not confirmation_called  # Packet was blocked
        assert bbmd.metrics.get_snapshot().packets_denied == 1

    @pytest.mark.asyncio
    async def test_message_type_filtering(self, bbmd):
        """Test filtering by message type."""
        # WHO_IS should be allowed from any source
        lpdu = self.create_lpdu("172.16.0.10:47808", None, OriginalBroadcastNPDU)
        
        # Mock message type detection
        with patch.object(bbmd.acl_engine, 'check_packet') as mock_check:
            mock_check.return_value = (True, "allow-discovery", MagicMock())
            
            confirmation_called = False
            async def mock_confirmation(self, lpdu):
                nonlocal confirmation_called
                confirmation_called = True
            
            with patch.object(bbmd.__class__.__bases__[0], 'confirmation', mock_confirmation):
                await bbmd.confirmation(lpdu)
            
            # Should be allowed by discovery rule
            assert confirmation_called

    @pytest.mark.asyncio
    async def test_priority_ordering(self, bbmd):
        """Test that higher priority rules override lower ones."""
        # Traffic from 10.0.0.0/24 should be denied (priority 50)
        # even if it matches other rules
        lpdu = self.create_lpdu("10.0.0.100:47808", "192.168.1.20:47808")
        
        confirmation_called = False
        async def mock_confirmation(self, lpdu):
            nonlocal confirmation_called
            confirmation_called = True
        
        with patch.object(bbmd.__class__.__bases__[0], 'confirmation', mock_confirmation):
            await bbmd.confirmation(lpdu)
        
        assert not confirmation_called  # Denied by higher priority rule
        assert "deny-untrusted" in bbmd.metrics.get_snapshot().rule_hit_counts

    @pytest.mark.asyncio  
    async def test_cut_through_eligibility(self, bbmd):
        """Test cut-through forwarding eligibility."""
        # Check cut-through network
        eligible_source = IPv4Address("192.168.100.50:47808")
        assert bbmd._is_cut_through_eligible(eligible_source) is True
        
        # Check non-eligible network
        non_eligible = IPv4Address("10.0.0.50:47808")
        assert bbmd._is_cut_through_eligible(non_eligible) is False
        
        # Verify caching
        assert eligible_source in bbmd._cut_through_cache
        assert bbmd._cut_through_cache[eligible_source] is True

    @pytest.mark.asyncio
    async def test_metrics_collection(self, bbmd):
        """Test comprehensive metrics collection."""
        # Process various packets
        test_cases = [
            ("192.168.1.10:47808", "192.168.1.20:47808", True),   # Allow local
            ("192.168.1.20:47808", "192.168.1.30:47808", True),   # Allow local
            ("10.0.0.10:47808", "192.168.1.20:47808", False),     # Deny untrusted
            ("172.16.0.10:47808", "192.168.1.20:47808", False),   # Default deny
        ]
        
        for source, dest, should_allow in test_cases:
            lpdu = self.create_lpdu(source, dest)
            
            async def mock_confirmation(self, lpdu):
                pass
            
            with patch.object(bbmd.__class__.__bases__[0], 'confirmation', mock_confirmation):
                await bbmd.confirmation(lpdu)
        
        # Check metrics
        snapshot = bbmd.metrics.get_snapshot()
        assert snapshot.total_packets == 4
        assert snapshot.packets_allowed == 2
        assert snapshot.packets_denied == 2
        
        # Check rule hits
        assert "allow-local" in snapshot.rule_hit_counts
        assert "deny-untrusted" in snapshot.rule_hit_counts
        assert "default" in snapshot.rule_hit_counts

    @pytest.mark.asyncio
    async def test_broadcast_forwarding(self, bbmd):
        """Test broadcast packet forwarding."""
        lpdu = self.create_lpdu("192.168.1.10:47808", None, OriginalBroadcastNPDU)
        
        # Mock _forward_broadcast
        with patch.object(bbmd, '_forward_broadcast', new_callable=AsyncMock) as mock_forward:
            await bbmd.confirmation(lpdu)
            mock_forward.assert_called_once()

    @pytest.mark.asyncio
    async def test_default_action(self, bbmd):
        """Test default action when no rules match."""
        # Traffic from unknown network should hit default deny
        lpdu = self.create_lpdu("172.16.0.50:47808", "192.168.1.20:47808")
        
        confirmation_called = False
        async def mock_confirmation(self, lpdu):
            nonlocal confirmation_called
            confirmation_called = True
        
        with patch.object(bbmd.__class__.__bases__[0], 'confirmation', mock_confirmation):
            await bbmd.confirmation(lpdu)
        
        assert not confirmation_called  # Default deny
        assert bbmd.metrics.get_snapshot().rule_hit_counts.get("default", 0) > 0

    @pytest.mark.asyncio
    async def test_concurrent_packet_processing(self, bbmd):
        """Test handling multiple concurrent packets."""
        # Create multiple packets
        packets = []
        for i in range(10):
            source = f"192.168.1.{10+i}:47808"
            lpdu = self.create_lpdu(source, "192.168.1.100:47808")
            packets.append(lpdu)
        
        # Process concurrently
        async def mock_confirmation(self, lpdu):
            await asyncio.sleep(0.001)  # Simulate processing time
        
        with patch.object(bbmd.__class__.__bases__[0], 'confirmation', mock_confirmation):
            tasks = [bbmd.confirmation(lpdu) for lpdu in packets]
            await asyncio.gather(*tasks)
        
        # All should be processed
        assert bbmd.metrics.get_snapshot().total_packets == 10
        assert bbmd.metrics.get_snapshot().packets_allowed == 10


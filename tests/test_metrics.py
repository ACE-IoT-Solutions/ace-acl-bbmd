"""
Tests for prometheus-based metrics collection
"""

import pytest
import time
from datetime import datetime
from pathlib import Path
import tempfile
from prometheus_client import CollectorRegistry, REGISTRY
from bacpypes3.pdu import IPv4Address

from ace_acl_bbmd.models.metrics import (
    MetricsCollector, MetricsConfig, DeviceTracker, MetricsSnapshot,
    BACNET_SERVICES, initialize_metrics
)


class TestDeviceTracker:
    """Test device tracker functionality."""
    
    def test_device_tracking(self):
        """Test tracking active devices."""
        tracker = DeviceTracker(timeout_seconds=2)
        
        # Add devices
        tracker.update_device(12345, "192.168.1.100")
        tracker.update_device(12346, "192.168.1.101")
        
        assert tracker.get_active_count() == 2
        
        # Wait for timeout
        time.sleep(2.1)
        
        # Add new device
        tracker.update_device(12347, "192.168.1.102")
        
        # Old devices should be timed out
        assert tracker.get_active_count() == 1
        
        # Cleanup should remove old devices
        tracker.cleanup()
        assert len(tracker.devices) == 1
        assert 12347 in tracker.devices


class TestMetricsCollector:
    """Test prometheus metrics collector functionality."""
    
    @pytest.fixture
    def registry(self):
        """Create a new registry for isolated testing."""
        return CollectorRegistry()
    
    @pytest.fixture
    def collector(self, registry):
        """Create metrics collector with custom registry."""
        config = MetricsConfig(
            enable_http_server=False,  # Don't start HTTP server in tests
            enable_file_export=False,   # Don't start file export in tests
            registry=registry
        )
        return MetricsCollector(config)
    
    def test_collector_creation(self, collector):
        """Test creating metrics collector."""
        assert collector.start_time is not None
        assert collector.device_tracker is not None
        assert len(collector._packet_counts) == 0
        assert len(collector._rule_counts) == 0
    
    def test_record_packet_basic(self, collector, registry):
        """Test recording basic packet metrics."""
        # Record allowed packet
        collector.record_packet(
            source_addr=IPv4Address("192.168.1.100:47808"),
            dest_addr=IPv4Address("192.168.1.200:47808"),
            message_type="original_unicast",
            packet_size=100,
            action="allow",
            rule_name="test_rule",
        )
        
        # Check prometheus metrics
        def get_sample_value(sample_name, labels):
            for metric in registry.collect():
                for sample in metric.samples:
                    if sample.name == sample_name:
                        if all(sample.labels.get(k) == v for k, v in labels.items()):
                            return sample.value
            return None
        
        assert get_sample_value('bacnet_packets_total', {'action': 'allow', 'rule_name': 'test_rule'}) == 1
        assert get_sample_value('bacnet_packets_bytes_total', {'action': 'allow', 'rule_name': 'test_rule'}) == 100
        assert get_sample_value('bacnet_bvll_messages_total', {'message_type': 'original_unicast', 'action': 'allow'}) == 1
        
        # Check legacy counters
        assert collector._packet_counts['allow'] == 1
        assert collector._packet_counts['total'] == 1
        assert collector._rule_counts['test_rule'] == 1
    
    def test_record_packet_with_device(self, collector, registry):
        """Test recording packet with device information."""
        collector.record_packet(
            source_addr=IPv4Address("192.168.1.100:47808"),
            dest_addr=None,
            message_type="original_broadcast",
            packet_size=200,
            action="allow",
            source_device=12345,
        )
        
        # Check device was tracked
        assert collector.device_tracker.get_active_count() == 1
        
        # Check device metrics
        def get_sample_value(sample_name, labels):
            for metric in registry.collect():
                for sample in metric.samples:
                    if sample.name == sample_name:
                        if all(sample.labels.get(k) == v for k, v in labels.items()):
                            return sample.value
            return None
        
        assert get_sample_value('bacnet_device_packets_total', 
                          {'device_id': '12345', 'ip_address': '192.168.1.100', 'action': 'allow'}) == 1
        assert get_sample_value('bacnet_active_devices', {}) == 1
    
    def test_record_packet_with_application_layer(self, collector, registry):
        """Test recording packet with application layer information."""
        # WHO_IS message
        collector.record_packet(
            source_addr=IPv4Address("192.168.1.100:47808"),
            dest_addr=None,
            message_type="original_broadcast",
            packet_size=50,
            action="allow",
            service_choice=34,  # whoIs
            apdu_type="unconfirmed_request",
        )
        
        # Check application message metrics
        def get_sample_value(sample_name, labels):
            for metric in registry.collect():
                for sample in metric.samples:
                    if sample.name == sample_name:
                        if all(sample.labels.get(k) == v for k, v in labels.items()):
                            return sample.value
            return None
        
        assert get_sample_value('bacnet_application_messages_total',
                          {'message_type': 'unconfirmed_request', 'service_name': 'whoIs', 'action': 'allow'}) == 1
    
    def test_record_cut_through_packet(self, collector, registry):
        """Test recording cut-through packet."""
        collector.record_packet(
            source_addr=IPv4Address("192.168.100.50:47808"),
            dest_addr=None,
            message_type="original_broadcast",
            packet_size=150,
            action="allow",
            cut_through=True,
        )
        
        # Check cut-through metrics
        def get_sample_value(sample_name, labels):
            for metric in registry.collect():
                for sample in metric.samples:
                    if sample.name == sample_name:
                        if all(sample.labels.get(k) == v for k, v in labels.items()):
                            return sample.value
            return None
        
        assert get_sample_value('bacnet_cut_through_packets_total',
                          {'source_network': '192.168.100.0/24'}) == 1
    
    def test_record_bbmd_forward(self, collector, registry):
        """Test recording BBMD forwarding metrics."""
        collector.record_bbmd_forward(
            bbmd_addr="192.168.2.10:47808",
            message_type="forwarded_broadcast",
            packet_size=200,
            direction="out",
        )
        
        # Check BBMD forward metrics
        def get_sample_value(sample_name, labels):
            for metric in registry.collect():
                for sample in metric.samples:
                    if sample.name == sample_name:
                        if all(sample.labels.get(k) == v for k, v in labels.items()):
                            return sample.value
            return None
        
        assert get_sample_value('bacnet_bbmd_forwards_total',
                          {'peer_address': '192.168.2.10:47808', 
                           'message_type': 'forwarded_broadcast',
                           'direction': 'out'}) == 1
    
    def test_get_legacy_snapshot(self, collector):
        """Test getting legacy metrics snapshot."""
        # Record some packets
        for i in range(5):
            collector.record_packet(
                source_addr=IPv4Address(f"192.168.1.{i+1}:47808"),
                dest_addr=None,
                message_type="who_is",
                packet_size=100,
                action="allow",
                rule_name="allow_discovery",
            )
        
        # Record denied packet
        collector.record_packet(
            source_addr=IPv4Address("10.0.0.1:47808"),
            dest_addr=None,
            message_type="write_property",
            packet_size=200,
            action="deny",
            rule_name="deny_writes",
        )
        
        # Get snapshot
        snapshot = collector.get_snapshot()
        
        assert isinstance(snapshot, MetricsSnapshot)
        assert snapshot.total_packets == 6
        assert snapshot.packets_allowed == 5
        assert snapshot.packets_denied == 1
        assert snapshot.rule_hit_counts["allow_discovery"] == 5
        assert snapshot.rule_hit_counts["deny_writes"] == 1
    
    def test_file_export(self):
        """Test metrics file export."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.prom') as f:
            temp_path = Path(f.name)
        
        try:
            config = MetricsConfig(
                enable_http_server=False,
                enable_file_export=True,
                file_export_path=temp_path,
                file_export_interval=1,  # Short interval for testing
            )
            collector = MetricsCollector(config)
            
            # Record some metrics
            collector.record_packet(
                source_addr=IPv4Address("192.168.1.100:47808"),
                dest_addr=None,
                message_type="who_is",
                packet_size=100,
                action="allow",
            )
            
            # Wait for export
            time.sleep(1.5)
            
            # Check file was created and contains metrics
            assert temp_path.exists()
            content = temp_path.read_text()
            assert "bacnet_packets_total" in content
            assert "bacnet_bvll_messages_total" in content
            
        finally:
            temp_path.unlink(missing_ok=True)
    
    def test_prometheus_text_format(self, collector):
        """Test getting metrics in Prometheus text format."""
        # Record some metrics
        collector.record_packet(
            source_addr=IPv4Address("192.168.1.100:47808"),
            dest_addr=None,
            message_type="who_is",
            packet_size=100,
            action="allow",
            service_choice=34,  # whoIs
            apdu_type="unconfirmed_request",
            source_device=12345,
        )
        
        # Get prometheus format
        metrics_text = collector.get_prometheus_metrics().decode('utf-8')
        
        # Check expected metrics are present
        assert "bacnet_packets_total" in metrics_text
        assert "bacnet_packets_bytes_total" in metrics_text
        assert "bacnet_application_messages_total" in metrics_text
        assert "bacnet_device_packets_total" in metrics_text
        assert "bacnet_active_devices" in metrics_text
        assert "bacnet_bbmd_info" in metrics_text
    
    def test_bacnet_services_mapping(self):
        """Test BACnet service name mapping."""
        assert BACNET_SERVICES[12] == "readProperty"
        assert BACNET_SERVICES[15] == "writeProperty"
        assert BACNET_SERVICES[34] == "whoIs"
        assert BACNET_SERVICES[26] == "iAm"
"""
Metrics Models for BACnet BBMD using Prometheus Client

This module defines metrics collection using the prometheus-client library
for monitoring packet processing, message types, and device communications.
"""

import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict
from pathlib import Path
import threading

from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    Summary,
    Info,
    CollectorRegistry,
    generate_latest,
    write_to_textfile,
    start_http_server,
    REGISTRY
)
from pydantic import BaseModel, Field
from bacpypes3.pdu import IPv4Address

logger = logging.getLogger(__name__)

# BACnet Application Layer Service Choices
BACNET_SERVICES = {
    # Alarm and Event Services
    0: "acknowledgeAlarm",
    1: "confirmedCOVNotification",
    2: "confirmedEventNotification",
    3: "getAlarmSummary",
    4: "getEnrollmentSummary",
    5: "subscribeCOV",
    6: "atomicReadFile",
    7: "atomicWriteFile",
    8: "addListElement",
    9: "removeListElement",
    10: "createObject",
    11: "deleteObject",
    12: "readProperty",
    13: "readPropertyConditional",  # Removed in version 1 revision 12
    14: "readPropertyMultiple",
    15: "writeProperty",
    16: "writePropertyMultiple",
    17: "deviceCommunicationControl",
    18: "confirmedPrivateTransfer",
    19: "confirmedTextMessage",
    20: "reinitializeDevice",
    21: "vtOpen",
    22: "vtClose",
    23: "vtData",
    24: "authenticate",  # Removed in version 1 revision 11
    25: "requestKey",    # Removed in version 1 revision 11
    26: "iAm",
    27: "iHave",
    28: "unconfirmedCOVNotification",
    29: "unconfirmedEventNotification",
    30: "unconfirmedPrivateTransfer",
    31: "unconfirmedTextMessage",
    32: "timeSynchronization",
    33: "whoHas",
    34: "whoIs",
    35: "readRange",
    36: "utcTimeSynchronization",
    37: "lifeSafetyOperation",
    38: "subscribeCOVProperty",
    39: "getEventInformation",
    40: "writeGroup",
    # Additional services continue...
}

# Module-level variables for metrics (will be initialized per collector)
_metrics_initialized = False
packets_total = None
packets_bytes_total = None
application_messages_total = None
bvll_messages_total = None
device_packets_total = None
bbmd_forwards_total = None
cut_through_packets_total = None
active_devices = None
foreign_devices_registered = None
packet_processing_time = None
bbmd_info = None


def initialize_metrics(registry: CollectorRegistry = REGISTRY):
    """Initialize prometheus metrics with the specified registry."""
    global packets_total, packets_bytes_total, application_messages_total
    global bvll_messages_total, device_packets_total, bbmd_forwards_total
    global cut_through_packets_total, active_devices, foreign_devices_registered
    global packet_processing_time, bbmd_info, _metrics_initialized
    
    # Clear existing metrics from registry if re-initializing
    if _metrics_initialized and registry == REGISTRY:
        # Using default registry, metrics already exist
        return
    
    # Packet processing metrics
    packets_total = Counter(
        'bacnet_packets_total',
        'Total number of packets processed',
        ['action', 'rule_name'],
        registry=registry
    )
    
    packets_bytes_total = Counter(
        'bacnet_packets_bytes_total',
        'Total bytes processed',
        ['action', 'rule_name'],
        registry=registry
    )
    
    # Application layer message type metrics
    application_messages_total = Counter(
        'bacnet_application_messages_total',
        'Total application layer messages by type',
        ['message_type', 'service_name', 'action'],
        registry=registry
    )
    
    # BVLL message type metrics
    bvll_messages_total = Counter(
        'bacnet_bvll_messages_total',
        'Total BVLL messages by type',
        ['message_type', 'action'],
        registry=registry
    )
    
    # Device-specific metrics
    device_packets_total = Counter(
        'bacnet_device_packets_total',
        'Packets per device',
        ['device_id', 'ip_address', 'action'],
        registry=registry
    )
    
    # BBMD forwarding metrics
    bbmd_forwards_total = Counter(
        'bacnet_bbmd_forwards_total',
        'BBMD forwarding operations',
        ['peer_address', 'message_type', 'direction'],
        registry=registry
    )
    
    # Cut-through metrics
    cut_through_packets_total = Counter(
        'bacnet_cut_through_packets_total',
        'Packets processed via cut-through',
        ['source_network'],
        registry=registry
    )
    
    # Current state gauges
    active_devices = Gauge(
        'bacnet_active_devices',
        'Number of active devices seen in the last 5 minutes',
        registry=registry
    )
    
    foreign_devices_registered = Gauge(
        'bacnet_foreign_devices_registered',
        'Number of registered foreign devices',
        registry=registry
    )
    
    # Performance metrics
    packet_processing_time = Histogram(
        'bacnet_packet_processing_seconds',
        'Time spent processing packets',
        ['packet_type'],
        registry=registry
    )
    
    # System info
    bbmd_info = Info(
        'bacnet_bbmd',
        'BBMD system information',
        registry=registry
    )
    
    _metrics_initialized = True


# Initialize with default registry on module import
initialize_metrics()


class MetricsConfig(BaseModel):
    """Configuration for metrics collection."""
    
    enable_http_server: bool = Field(default=False, description="Enable HTTP metrics endpoint")
    http_port: int = Field(default=9090, description="HTTP server port for metrics")
    enable_file_export: bool = Field(default=False, description="Enable file-based metrics export")
    file_export_path: Optional[Path] = Field(default=None, description="Path for metrics file export")
    file_export_interval: int = Field(default=60, description="Interval in seconds for file export")
    registry: Optional[CollectorRegistry] = Field(default=None, exclude=True)
    
    model_config = {"arbitrary_types_allowed": True}


class DeviceTracker:
    """Track active devices for gauge metrics."""
    
    def __init__(self, timeout_seconds: int = 300):
        self.timeout_seconds = timeout_seconds
        self.devices: Dict[int, tuple[str, float]] = {}  # device_id -> (ip, last_seen)
        self._lock = threading.Lock()
    
    def update_device(self, device_id: int, ip_address: str) -> None:
        """Update device last seen time."""
        with self._lock:
            self.devices[device_id] = (ip_address, time.time())
    
    def get_active_count(self) -> int:
        """Get count of recently active devices."""
        cutoff = time.time() - self.timeout_seconds
        with self._lock:
            return sum(1 for _, (_, last_seen) in self.devices.items() if last_seen > cutoff)
    
    def cleanup(self) -> None:
        """Remove stale devices."""
        cutoff = time.time() - self.timeout_seconds
        with self._lock:
            self.devices = {
                dev_id: (ip, last_seen) 
                for dev_id, (ip, last_seen) in self.devices.items() 
                if last_seen > cutoff
            }


class MetricsSnapshot(BaseModel):
    """Legacy metrics snapshot for compatibility."""
    
    timestamp: datetime = Field(default_factory=datetime.now)
    duration_seconds: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    packets_allowed: int = 0
    packets_denied: int = 0
    packets_cut_through: int = 0
    message_type_counts: Dict[str, int] = Field(default_factory=dict)
    rule_hit_counts: Dict[str, int] = Field(default_factory=dict)


class MetricsCollector:
    """Prometheus-based metrics collector for BBMD."""
    
    def __init__(self, config: Optional[MetricsConfig] = None):
        self.config = config or MetricsConfig()
        self.start_time = datetime.now()
        
        # Use custom registry if provided
        self.registry = self.config.registry or REGISTRY
        
        # Initialize metrics with the registry
        initialize_metrics(self.registry)
        
        # Device tracking
        self.device_tracker = DeviceTracker()
        
        # For legacy compatibility
        self._packet_counts = defaultdict(int)
        self._rule_counts = defaultdict(int)
        
        # Start HTTP server if enabled
        if self.config.enable_http_server:
            self._start_http_server()
        
        # Start file export if enabled
        if self.config.enable_file_export and self.config.file_export_path:
            self._start_file_export()
        
        # Set initial BBMD info
        bbmd_info.info({
            'version': '1.0.0',
            'start_time': self.start_time.isoformat()
        })
    
    def _start_http_server(self) -> None:
        """Start Prometheus HTTP metrics server."""
        try:
            start_http_server(self.config.http_port, registry=self.registry)
            logger.info(f"Prometheus metrics server started on port {self.config.http_port}")
        except Exception as e:
            logger.error(f"Failed to start metrics HTTP server: {e}")
    
    def _start_file_export(self) -> None:
        """Start periodic file export."""
        def export_loop():
            while True:
                try:
                    self._export_to_file()
                    time.sleep(self.config.file_export_interval)
                except Exception as e:
                    logger.error(f"Metrics file export error: {e}")
                    time.sleep(self.config.file_export_interval)
        
        thread = threading.Thread(target=export_loop, daemon=True)
        thread.start()
        logger.info(f"Started metrics file export to {self.config.file_export_path}")
    
    def _export_to_file(self) -> None:
        """Export metrics to file."""
        if self.config.file_export_path:
            # Ensure directory exists
            self.config.file_export_path.parent.mkdir(parents=True, exist_ok=True)
            write_to_textfile(str(self.config.file_export_path), self.registry)
    
    def record_packet(
        self,
        source_addr: IPv4Address,
        dest_addr: Optional[IPv4Address],
        message_type: str,
        packet_size: int,
        action: str,
        rule_name: Optional[str] = None,
        source_device: Optional[int] = None,
        dest_device: Optional[int] = None,
        cut_through: bool = False,
        service_choice: Optional[int] = None,
        apdu_type: Optional[str] = None,
    ) -> None:
        """Record metrics for a processed packet."""
        # Update prometheus counters
        packets_total.labels(action=action, rule_name=rule_name or "none").inc()
        packets_bytes_total.labels(action=action, rule_name=rule_name or "none").inc(packet_size)
        
        # Track BVLL message types
        bvll_messages_total.labels(message_type=message_type, action=action).inc()
        
        # Track application layer messages if we have service info
        if service_choice is not None:
            service_name = BACNET_SERVICES.get(service_choice, f"unknown_{service_choice}")
            application_messages_total.labels(
                message_type=apdu_type or "unknown",
                service_name=service_name,
                action=action
            ).inc()
        
        # Track device metrics
        if source_device is not None:
            ip_str = str(source_addr).split(':')[0]  # Extract IP from BACPypes3 format
            device_packets_total.labels(
                device_id=str(source_device),
                ip_address=ip_str,
                action=action
            ).inc()
            
            # Update device tracker for gauge
            self.device_tracker.update_device(source_device, ip_str)
            active_devices.set(self.device_tracker.get_active_count())
        
        # Track cut-through
        if cut_through:
            source_ip = str(source_addr).split(':')[0]
            source_network = ".".join(source_ip.split('.')[:3]) + ".0/24"
            cut_through_packets_total.labels(source_network=source_network).inc()
        
        # Update legacy counters for compatibility
        self._packet_counts[action] += 1
        self._packet_counts['total'] += 1
        if rule_name:
            self._rule_counts[rule_name] += 1
    
    def record_bbmd_forward(
        self,
        bbmd_addr: str,
        message_type: str,
        packet_size: int,
        direction: str = "in",
    ) -> None:
        """Record BBMD forwarding metrics."""
        bbmd_forwards_total.labels(
            peer_address=bbmd_addr,
            message_type=message_type,
            direction=direction
        ).inc()
    
    def update_foreign_devices(self, count: int) -> None:
        """Update foreign device registration count."""
        foreign_devices_registered.set(count)
    
    def record_processing_time(self, packet_type: str, duration_seconds: float) -> None:
        """Record packet processing time."""
        packet_processing_time.labels(packet_type=packet_type).observe(duration_seconds)
    
    def get_snapshot(self, duration_seconds: Optional[int] = None) -> MetricsSnapshot:
        """Get legacy metrics snapshot for compatibility."""
        if duration_seconds is None:
            duration_seconds = int((datetime.now() - self.start_time).total_seconds())
        
        # Clean up old devices
        self.device_tracker.cleanup()
        
        return MetricsSnapshot(
            duration_seconds=duration_seconds,
            total_packets=self._packet_counts.get('total', 0),
            total_bytes=0,  # Not tracked separately in prometheus version
            packets_allowed=self._packet_counts.get('allow', 0),
            packets_denied=self._packet_counts.get('deny', 0),
            packets_cut_through=0,  # Would need separate tracking
            message_type_counts={},  # Would need separate tracking
            rule_hit_counts=dict(self._rule_counts),
        )
    
    def get_prometheus_metrics(self) -> bytes:
        """Get current metrics in Prometheus text format."""
        return generate_latest(self.registry)
    
    def reset(self) -> None:
        """Reset all metrics."""
        # Note: Prometheus counters cannot be reset - they are meant to be monotonic
        # This is kept for compatibility but doesn't actually reset prometheus metrics
        self._packet_counts.clear()
        self._rule_counts.clear()
        self.device_tracker.devices.clear()
        logger.warning("MetricsCollector.reset() called - prometheus counters are not reset")
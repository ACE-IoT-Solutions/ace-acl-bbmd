#!/usr/bin/env python3
"""
Example of using the ACL BBMD with Prometheus metrics.

This example shows:
1. Enabling the HTTP metrics endpoint
2. Enabling file-based metrics export
3. Accessing metrics programmatically
"""

import asyncio
import time
from pathlib import Path
from bacpypes3.pdu import IPv4Address

from ace_acl_bbmd.config import BBMDConfig
from ace_acl_bbmd.bbmd import ACLBBMD
from ace_acl_bbmd.models.acl import ACLConfig, ACLRule, RuleAction, MessageType
from ace_acl_bbmd.models.metrics import MetricsConfig
from ipaddress import IPv4Network


async def main():
    """Run example BBMD with Prometheus metrics."""
    
    # Create configuration with metrics enabled
    config = BBMDConfig(
        bbmd_address="127.0.0.1:47808",
        
        # Enable metrics collection
        enable_metrics=True,
        
        # Enable Prometheus HTTP endpoint
        metrics_http_enabled=True,
        metrics_http_port=9090,
        
        # Enable file export
        metrics_file_export_enabled=True,
        metrics_file_export_path=Path("/tmp/bbmd_metrics.prom"),
        metrics_file_export_interval=30,  # Export every 30 seconds
        
        # ACL configuration
        acl=ACLConfig(
            rules=[
                ACLRule(
                    name="allow-local",
                    action=RuleAction.ALLOW,
                    priority=100,
                    source_network=IPv4Network("192.168.1.0/24"),
                ),
                ACLRule(
                    name="allow-discovery",
                    action=RuleAction.ALLOW,
                    priority=90,
                    message_types=[MessageType.WHO_IS, MessageType.I_AM],
                ),
                ACLRule(
                    name="deny-writes",
                    action=RuleAction.DENY,
                    priority=50,
                    message_types=[MessageType.WRITE_PROPERTY],
                    log_matches=True,
                ),
            ],
            default_action=RuleAction.DENY,
            enable_cut_through=True,
            cut_through_networks=[IPv4Network("192.168.100.0/24")],
        )
    )
    
    # Create BBMD
    print("Starting BBMD with Prometheus metrics...")
    bbmd = ACLBBMD(config=config)
    
    print(f"Prometheus metrics available at: http://localhost:{config.metrics_http_port}/metrics")
    print(f"Metrics exported to file: {config.metrics_file_export_path}")
    
    # Simulate some traffic for metrics
    print("\nSimulating packet processing...")
    
    # Simulate various packets
    test_packets = [
        # Local network traffic
        ("192.168.1.10:47808", "192.168.1.20:47808", "who_is", "allow", "allow-local", None, 12345),
        ("192.168.1.20:47808", "192.168.1.30:47808", "i_am", "allow", "allow-discovery", 26, 12346),
        
        # Discovery from external
        ("10.0.0.10:47808", None, "who_is", "allow", "allow-discovery", 34, None),
        
        # Denied write
        ("10.0.0.50:47808", "192.168.1.100:47808", "write_property", "deny", "deny-writes", 15, 99999),
        
        # Cut-through traffic
        ("192.168.100.50:47808", None, "original_broadcast", "allow", "cut_through", None, None),
        
        # Default deny
        ("172.16.0.10:47808", "192.168.1.50:47808", "read_property", "deny", "default", 12, None),
    ]
    
    for source, dest, msg_type, action, rule, service_choice, device_id in test_packets:
        bbmd.metrics.record_packet(
            source_addr=IPv4Address(source),
            dest_addr=IPv4Address(dest) if dest else None,
            message_type=msg_type,
            packet_size=100,
            action=action,
            rule_name=rule,
            source_device=device_id,
            service_choice=service_choice,
            apdu_type="unconfirmed_request" if service_choice in [34, 26] else "confirmed_request",
            cut_through=(rule == "cut_through")
        )
        
        # Simulate some BBMD forwarding
        if msg_type == "original_broadcast":
            bbmd.metrics.record_bbmd_forward(
                "192.168.2.10:47808",
                "forwarded_broadcast",
                100,
                "out"
            )
    
    # Update foreign device count
    bbmd.metrics.update_foreign_devices(3)
    
    # Wait a bit for metrics to be visible
    await asyncio.sleep(2)
    
    # Get metrics programmatically
    print("\nPrometheus metrics (first 1000 chars):")
    metrics_text = bbmd.metrics.get_prometheus_metrics().decode('utf-8')
    print(metrics_text[:1000] + "..." if len(metrics_text) > 1000 else metrics_text)
    
    # Get legacy snapshot
    print("\nLegacy metrics snapshot:")
    snapshot = bbmd.metrics.get_snapshot()
    print(f"  Total packets: {snapshot.total_packets}")
    print(f"  Allowed: {snapshot.packets_allowed}")
    print(f"  Denied: {snapshot.packets_denied}")
    print(f"  Rule hits: {dict(snapshot.rule_hit_counts)}")
    
    print("\nMetrics server will continue running. Press Ctrl+C to stop.")
    
    try:
        # Keep running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping BBMD...")


if __name__ == "__main__":
    asyncio.run(main())
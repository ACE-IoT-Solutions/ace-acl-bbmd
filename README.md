# ACE ACL BBMD

An Access Control List (ACL) enabled BACnet/IP Broadcast Management Device (BBMD) built on BACPypes3.

## Overview

The ACE ACL BBMD extends the standard BACnet BBMD functionality with powerful access control features:

- **Packet Filtering**: ACL rules to allow/deny packets based on source, destination, and message type
- **Cut-Through Forwarding**: Performance optimization for trusted networks
- **Metrics Collection**: Detailed tracking of message types and device communications
- **Flexible Configuration**: YAML/TOML configuration with hot-reload support
- **Time-Based Rules**: Rules that activate during specific time windows
- **Deep Packet Inspection**: Application-layer filtering for BACnet services

## Features

### Access Control
- Network-based filtering (CIDR notation)
- Device-level filtering (BACnet device IDs)
- Message type filtering (BVLL and application layer)
- Priority-based rule evaluation
- Default allow/deny policies
- Time-of-day and day-of-week restrictions

### Performance Optimization
- Cut-through forwarding for trusted networks
- Configurable packet queues
- Metrics collection with minimal overhead
- Caching for frequently accessed rules

### Monitoring & Metrics
- Per-device packet counters
- Per-BBMD peer statistics
- Message type breakdown
- ACL rule hit counters
- Top talkers identification
- Denied packet tracking

## Installation

```bash
# Clone the repository
git clone https://github.com/ACE-IoT-Solutions/ace-acl-bbmd.git
cd ace-acl-bbmd

# Install with uv (recommended)
uv sync

# Or install with pip
pip install .
```

## Configuration

### Basic Configuration (config/bbmd_config.yaml)

```yaml
# BBMD Network Settings
bbmd_address: "192.168.1.100/24:47808"
interface: "eth0"  # Optional

# Peer BBMDs
bdt_entries:
  - "192.168.1.101:47808"
  - "192.168.2.100:47808"

# ACL Configuration
acl:
  default_action: deny
  log_default: true
  
  rules:
    # Allow all from management network
    - name: "allow_management"
      action: allow
      priority: 10
      source_network: "192.168.100.0/24"
      message_types: [all]
    
    # Allow BACnet discovery
    - name: "allow_discovery"
      action: allow
      priority: 20
      message_types: [who_is, i_am]
```

### ACL Rule Structure

```yaml
rules:
  - name: "rule_name"
    action: allow|deny|log|allow_log
    priority: 0-1000  # Lower = higher priority
    
    # Source filters
    source_network: "192.168.1.0/24"
    source_device: 12345
    
    # Destination filters
    dest_network: "10.1.0.0/16"
    dest_device: 54321
    
    # Message type filter
    message_types:
      - who_is
      - i_am
      - read_property
      - write_property
      - all
    
    # Time restrictions
    time_range:
      start: "08:00"
      end: "17:00"
      days: ["mon", "tue", "wed", "thu", "fri"]
    
    # Options
    log_matches: true
    enabled: true
```

### Metrics Configuration

```yaml
# Enable metrics collection
enable_metrics: true

# Prometheus HTTP endpoint
metrics_http_enabled: true
metrics_http_port: 9090  # Access at http://localhost:9090/metrics

# File-based metrics export
metrics_file_export_enabled: true
metrics_file_export_path: /var/lib/bbmd/metrics.prom
metrics_file_export_interval: 60  # seconds
```

### Cut-Through Configuration

```yaml
acl:
  enable_cut_through: true
  cut_through_networks:
    - "10.1.0.0/16"      # Trusted internal network
    - "192.168.100.0/24" # Management network
```

## Usage

### Running the BBMD

```bash
# Run with configuration file
ace-acl-bbmd --config config/bbmd_config.yaml

# Run with separate ACL file
ace-acl-bbmd --config config/bbmd_config.yaml --acl config/custom_acl.yaml

# Validate configuration
ace-acl-bbmd --config config/bbmd_config.yaml --validate

# Enable debug logging
ace-acl-bbmd --config config/bbmd_config.yaml --debug
```

### CLI Options

```
usage: ace-acl-bbmd [-h] --config CONFIG [--acl ACL] [--validate] [--debug]
                    [--metrics-port METRICS_PORT]

ACL-enabled BACnet BBMD

options:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        Path to BBMD configuration file (YAML or TOML)
  --acl ACL, -a ACL     Path to separate ACL configuration file
  --validate, -v        Validate configuration and exit
  --debug, -d           Enable debug logging
  --metrics-port METRICS_PORT, -m METRICS_PORT
                        Port for metrics HTTP endpoint (optional)
```

## Message Types

### BVLL Message Types
- `original_unicast` - Direct unicast messages
- `original_broadcast` - Local broadcast messages
- `forwarded_npdu` - Forwarded messages from other BBMDs
- `distribute_broadcast` - Broadcast distribution requests
- `register_foreign_device` - Foreign device registration
- `read_bdt` - Read broadcast distribution table
- `write_bdt` - Write broadcast distribution table
- `read_fdt` - Read foreign device table
- `delete_fdt_entry` - Delete foreign device entry

### Application Layer Types
- `who_is` - Device discovery request
- `i_am` - Device discovery response
- `read_property` - Read object property
- `write_property` - Write object property
- `all` - Match all message types

## Prometheus Metrics

The BBMD exports comprehensive metrics using the prometheus-client library:

### Available Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `bacnet_packets_total` | Counter | Total packets processed | action, rule_name |
| `bacnet_packets_bytes_total` | Counter | Total bytes processed | action, rule_name |
| `bacnet_application_messages_total` | Counter | Application layer messages | message_type, service_name, action |
| `bacnet_bvll_messages_total` | Counter | BVLL messages by type | message_type, action |
| `bacnet_device_packets_total` | Counter | Packets per device | device_id, ip_address, action |
| `bacnet_bbmd_forwards_total` | Counter | BBMD forwarding operations | peer_address, message_type, direction |
| `bacnet_cut_through_packets_total` | Counter | Cut-through packets | source_network |
| `bacnet_active_devices` | Gauge | Active devices (5min window) | - |
| `bacnet_foreign_devices_registered` | Gauge | Registered foreign devices | - |
| `bacnet_packet_processing_seconds` | Histogram | Processing time | packet_type |
| `bacnet_bbmd_info` | Info | System information | version, start_time |

### Example Prometheus Queries

```promql
# Packet rate by action (5min)
rate(bacnet_packets_total[5m])

# Top denied source devices
topk(10, sum by (device_id, ip_address) (bacnet_device_packets_total{action="deny"}))

# Application message breakdown
sum by (service_name) (rate(bacnet_application_messages_total[5m]))

# Cut-through effectiveness
(sum(rate(bacnet_cut_through_packets_total[5m])) / sum(rate(bacnet_packets_total[5m]))) * 100

# Average packet processing time
histogram_quantile(0.95, rate(bacnet_packet_processing_seconds_bucket[5m]))
```

### Example Usage

```python
# See examples/prometheus_metrics_example.py for a complete example
from ace_acl_bbmd.config import BBMDConfig
from ace_acl_bbmd.bbmd import ACLBBMD

config = BBMDConfig(
    bbmd_address="192.168.1.100:47808",
    enable_metrics=True,
    metrics_http_enabled=True,
    metrics_http_port=9090,
    # ... other config
)

bbmd = ACLBBMD(config=config)
# Metrics available at http://localhost:9090/metrics
```

## Architecture

```
+------------------+
|   Application    |
|  (BACnet Stack)  |
+--------+---------+
         |
+--------v---------+
|   ACL BBMD       | <-- ACL Rules
|  - Filtering     | <-- Prometheus Metrics
|  - Forwarding    | <-- Cut-through
+--------+---------+
         |
+--------v---------+
|   BVLLCodec      |
+--------+---------+
         |
+--------v---------+
| UDPMultiplexer   |
+--------+---------+
         |
+--------v---------+
| IPv4DatagramSvr  |
+------------------+
```

## Development

### Project Structure

```
ace-acl-bbmd/
├── src/ace_acl_bbmd/
│   ├── __init__.py
│   ├── __main__.py      # CLI entry point
│   ├── bbmd.py          # ACL BBMD implementation
│   ├── acl_engine.py    # ACL rule engine
│   ├── config.py        # Configuration management
│   └── models/
│       ├── acl.py       # ACL models
│       └── metrics.py   # Metrics models
├── config/
│   ├── bbmd_config.yaml # Example BBMD config
│   └── acl_example.yaml # Example ACL config
├── tests/
│   ├── test_acl_models.py
│   ├── test_metrics.py
│   └── test_config.py
└── pyproject.toml
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=ace_acl_bbmd

# Run specific test
uv run pytest tests/test_acl_models.py
```

### Code Quality

```bash
# Format code
uv run ruff format .

# Lint code
uv run ruff check .

# Type checking
uv run pyrefly check src
```

## License

This project is proprietary to ACE IoT Solutions.

## Support

For support, please contact: andrew@aceiotsolutions.com
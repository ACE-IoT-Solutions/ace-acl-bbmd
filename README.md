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

### High-Performance Rust ACL Engine
- Native Rust rule matching engine via PyO3 for high-throughput packet filtering
- Full BACnet NPDU/APDU decoding in Rust using [rusty-bacnet](https://github.com/jscott3201/rusty-bacnet) (`bacnet-encoding` crate)
- Pre-computed u32 bitmask IP/CIDR matching (no per-packet string parsing)
- **5.3M packets/sec** full pipeline (decode + match) at 100 rules
- **1,300x faster** than pure-Python rule matching
- Graceful fallback to Python when the Rust extension is not installed

### Performance Optimization
- Cut-through forwarding for trusted networks
- Configurable packet queues
- Metrics collection with minimal overhead

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

# Install Python package with uv (recommended)
uv sync

# Or install with pip
pip install .
```

### Rust ACL Engine (optional, recommended)

The Rust engine is optional but provides ~1,300x faster rule matching. It requires Rust 1.93+ and [maturin](https://www.maturin.rs/).

```bash
# Install maturin
uv pip install maturin

# Build and install the Rust extension (release mode)
cd rust
maturin develop --release
cd ..
```

The Python ACL engine will automatically detect and use the Rust extension when available. If not installed, it falls back to pure-Python rule matching with no code changes needed.

### Docker

The container image includes the Rust ACL engine pre-built. Pull from the GitHub Container Registry:

```bash
docker pull ghcr.io/ace-iot-solutions/ace-acl-bbmd:main
```

Run with environment variables:

```bash
docker run -d --name ace-bbmd \
  --network host \
  -e BBMD_ADDRESS="192.168.1.100/24:47808" \
  -e BBMD_BDT_ENTRIES="192.168.1.101:47808,192.168.2.100:47808" \
  -e BBMD_ACL_DEFAULT_ACTION=deny \
  -e BBMD_METRICS_HTTP_ENABLED=true \
  ghcr.io/ace-iot-solutions/ace-acl-bbmd:main
```

Or mount your own config and ACL rules files:

```bash
docker run -d --name ace-bbmd \
  --network host \
  -e BBMD_GENERATE_CONFIG=false \
  -v /path/to/bbmd_config.yaml:/app/config/runtime.yaml:ro \
  -v /path/to/acl_rules.yaml:/app/config/acl_rules.yaml:ro \
  -e BBMD_ACL_RULES_FILE=/app/config/acl_rules.yaml \
  ghcr.io/ace-iot-solutions/ace-acl-bbmd:main
```

### Container Environment Variables

All configuration can be set via environment variables at container launch:

| Variable | Default | Description |
|---|---|---|
| **Network** | | |
| `BBMD_ADDRESS` | `0.0.0.0:47808` | BBMD listen address (IP/mask:port) |
| `BBMD_INTERFACE` | _(none)_ | Network interface to bind to |
| `BBMD_BDT_ENTRIES` | _(none)_ | Comma-separated peer BBMD addresses |
| `BBMD_ACCEPT_FOREIGN_DEVICES` | `true` | Accept foreign device registrations |
| `BBMD_MAX_FOREIGN_DEVICES` | `100` | Maximum foreign devices |
| **Logging** | | |
| `BBMD_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `BBMD_LOG_FILE` | _(none)_ | Log file path (logs to stdout if unset) |
| **Metrics** | | |
| `BBMD_ENABLE_METRICS` | `true` | Enable metrics collection |
| `BBMD_METRICS_INTERVAL` | `60` | Metrics snapshot interval (seconds) |
| `BBMD_METRICS_RETENTION` | `3600` | Metrics retention period (seconds) |
| `BBMD_METRICS_HTTP_ENABLED` | `true` | Enable Prometheus HTTP endpoint |
| `BBMD_METRICS_HTTP_PORT` | `9090` | Prometheus HTTP port |
| `BBMD_METRICS_FILE_EXPORT_ENABLED` | `false` | Enable metrics file export |
| `BBMD_METRICS_FILE_EXPORT_PATH` | `/app/metrics/bbmd_metrics.prom` | Metrics export file path |
| `BBMD_METRICS_FILE_EXPORT_INTERVAL` | `60` | Metrics export interval (seconds) |
| **Performance** | | |
| `BBMD_MAX_PACKET_SIZE` | `1476` | Maximum BACnet packet size |
| `BBMD_QUEUE_SIZE` | `1000` | Packet processing queue size |
| **ACL** | | |
| `BBMD_ACL_DEFAULT_ACTION` | `deny` | Default action (allow, deny, log, allow_log) |
| `BBMD_ACL_LOG_DEFAULT` | `true` | Log packets hitting default action |
| `BBMD_ACL_ENABLE_CUT_THROUGH` | `true` | Enable cut-through forwarding |
| `BBMD_ACL_CUT_THROUGH_NETWORKS` | _(none)_ | Comma-separated trusted CIDRs |
| `BBMD_ACL_RULES_FILE` | _(none)_ | Path to mounted ACL rules YAML file |
| **Entrypoint** | | |
| `BBMD_GENERATE_CONFIG` | `true` | Generate config from env vars (set `false` to use mounted file) |

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
|   ACL BBMD       | <-- ACL Rules + Prometheus Metrics
|  - Filtering     |
|  - Forwarding    |
|  - Cut-through   |
+--------+---------+
         |
+--------v---------+     +-------------------------+
|  ACL Engine      |---->|  Rust ACL Engine (PyO3) |
|  (Python bridge) |     |  - NPDU/APDU decode     |
|                  |     |    (bacnet-encoding)     |
|                  |     |  - u32 bitmask matching  |
+--------+---------+     +-------------------------+
         |                  (fallback: pure Python)
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
│   ├── acl_engine.py    # ACL rule engine (Python + Rust bridge)
│   ├── config.py        # Configuration management
│   └── models/
│       ├── acl.py       # ACL models
│       └── metrics.py   # Metrics models
├── rust/                # Rust ACL engine (PyO3 extension)
│   ├── pyproject.toml   # maturin build config
│   ├── Cargo.toml       # Rust dependencies
│   └── src/
│       ├── lib.rs       # PyO3 bindings
│       ├── engine.rs    # Rule matching engine
│       └── inspect.rs   # BACnet NPDU/APDU packet inspection
├── benchmarks/
│   └── bench_acl_engine.py  # Throughput benchmarks
├── config/
│   ├── bbmd_config.yaml # Example BBMD config
│   └── acl_example.yaml # Example ACL config
├── tests/
│   ├── test_acl_models.py
│   ├── test_acl_engine.py
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

### Running Benchmarks

```bash
# Basic benchmark (100 rules, 20% deny)
uv run python -m benchmarks.bench_acl_engine --rules 100 --deny-pct 0.20

# With scaling analysis across rule counts
uv run python -m benchmarks.bench_acl_engine --rules 100 --deny-pct 0.20 --scaling
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
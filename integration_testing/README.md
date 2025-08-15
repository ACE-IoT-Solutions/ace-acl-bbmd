# ACL BBMD Integration Testing Environment

This directory contains a complete Docker/Podman-based testing environment for the ACE ACL BBMD with multiple networks, simulated BACnet devices, and comprehensive monitoring.

## Architecture

The test environment simulates a real-world BACnet deployment with:

### Networks
- **Management Network (192.168.100.0/24)** - Full administrative access
- **Building 1 Network (10.1.0.0/24)** - HVAC controllers
- **Building 2 Network (10.2.0.0/24)** - IoT devices
- **Monitoring Network (10.3.0.0/24)** - Read-only monitoring stations
- **Backbone Network (172.20.0.0/24)** - Inter-BBMD communication

### BBMDs
- **Management BBMD** - Unrestricted access, audit logging
- **Building 1 BBMD** - Manages HVAC controllers with write permissions
- **Building 2 BBMD** - Manages IoT devices with restricted permissions
- **Monitoring BBMD** - Read-only access to all networks

### Simulated Devices
- **HVAC Controllers** - Can read/write to IoT devices
- **IoT Sensors** - Limited write capabilities
- **Monitoring Stations** - Read-only access
- **Discovery Scanner** - Performs Who-Is/I-Am discovery
- **Management Station** - Full control capabilities
- **Rogue Device** - Tests ACL blocking (device ID 666666)

## Quick Start

### Prerequisites
- Docker or Podman
- Docker Compose or Podman Compose
- Port availability: 47810-47813 (UDP), 9090-9093, 3000

### Starting the Environment

```bash
cd integration_testing
./scripts/start_test_env.sh
```

This will:
1. Build all Docker images
2. Start all BBMDs and devices
3. Start Prometheus and Grafana
4. Display access URLs

### Accessing Services

- **Grafana Dashboard**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9099
- **BBMD Metrics**:
  - Management: http://localhost:9090/metrics
  - Building 1: http://localhost:9091/metrics
  - Building 2: http://localhost:9092/metrics
  - Monitoring: http://localhost:9093/metrics

### Running Tests

```bash
./scripts/test_scenarios.sh
```

This runs various test scenarios including:
- Discovery message propagation
- HVAC to IoT control permissions
- Write operation restrictions
- Monitoring read-only enforcement
- Rogue device blocking
- Management network full access
- ACL runtime reload
- Metrics collection verification

### Stopping the Environment

```bash
./scripts/stop_test_env.sh
```

Options to remove volumes and logs will be presented.

## ACL Configuration

Each BBMD has its own ACL configuration demonstrating different security policies:

### Management BBMD (`bbmd_mgmt`)
- Default: ALLOW
- Logs all write operations for audit
- Full cut-through for performance

### Building 1 BBMD (`bbmd1`)
- Default: DENY
- Allows HVAC controllers to write to IoT devices
- Blocks IoT devices from writing to HVAC
- Cut-through for local HVAC network

### Building 2 BBMD (`bbmd2`)
- Default: DENY
- Blocks rogue device (666666)
- Logs all IoT write attempts
- No cut-through (full inspection)

### Monitoring BBMD (`bbmd3`)
- Default: DENY
- Read-only access to all networks
- Blocks all write operations
- Cut-through for local monitoring network

## Testing ACL Runtime Reload

The BBMDs support runtime ACL reloading. To test:

```bash
# Modify an ACL file
docker exec -it bbmd1 vi /app/config/acl_rules.yaml

# The BBMD will automatically detect and reload the changes
# Check logs to confirm reload
docker compose logs bbmd1 | grep "ACL configuration reloaded"
```

## Monitoring and Metrics

### Prometheus Metrics
All BBMDs expose Prometheus metrics including:
- `bacnet_packets_total` - Total packets by action (allow/deny)
- `bacnet_application_messages_total` - Messages by BACnet service type
- `bacnet_bytes_total` - Total bytes processed
- `bacnet_processing_duration_seconds` - Processing latency
- `bacnet_active_foreign_devices` - Current foreign device count
- `bacnet_rule_hit_count` - ACL rule match counts

### Grafana Dashboard
Pre-configured dashboard shows:
- Packet rates by BBMD and action
- BACnet service distribution
- Active foreign devices
- Top ACL rules by hit count
- BBMD status table

## Troubleshooting

### View BBMD Logs
```bash
docker compose logs -f bbmd1
```

### Check Device Status
```bash
docker compose ps
```

### Query Metrics Directly
```bash
# Total packets
curl -s http://localhost:9090/metrics | grep bacnet_packets_total

# Using Prometheus
docker compose exec prometheus promtool query instant http://localhost:9090 'bacnet_packets_total'
```

### Network Connectivity
```bash
# Test inter-BBMD communication
docker compose exec bbmd1 ping bbmd2
```

## Advanced Usage

### Adding More Devices
Edit `docker-compose.yml` to add more simulated devices:

```yaml
new_device:
  build:
    context: .
    dockerfile: Dockerfile.device
  networks:
    building1:
      ipv4_address: 10.1.0.103
  command: [
    "python", "/app/bacnet_device_simulator.py",
    "--device-id", "100103",
    "--device-name", "New-Device",
    "--local-address", "10.1.0.103:47808",
    "--bbmd-address", "10.1.0.2:47808",
    "--behavior", "normal"
  ]
```

### Custom ACL Rules
Modify ACL rules in `configs/bbmdX/acl_rules.yaml` and they will be automatically reloaded.

### Performance Testing
Increase device count and message rates in the simulator scripts to stress test the ACL engine.

## File Structure

```
integration_testing/
├── Dockerfile.bbmd          # BBMD container image
├── Dockerfile.device        # Device simulator image
├── docker-compose.yml       # Complete environment definition
├── configs/                 # Configuration files
│   ├── bbmd1/              # Building 1 BBMD configs
│   ├── bbmd2/              # Building 2 BBMD configs
│   ├── bbmd3/              # Monitoring BBMD configs
│   ├── bbmd_mgmt/          # Management BBMD configs
│   ├── prometheus.yml      # Prometheus scrape configs
│   └── grafana/            # Grafana provisioning
├── devices/                # Device simulators
│   └── bacnet_device_simulator.py
├── scripts/                # Management scripts
│   ├── start_test_env.sh   # Start environment
│   ├── stop_test_env.sh    # Stop environment
│   └── test_scenarios.sh   # Run test scenarios
├── logs/                   # BBMD log files (created at runtime)
└── metrics/                # Metrics export files (created at runtime)
```
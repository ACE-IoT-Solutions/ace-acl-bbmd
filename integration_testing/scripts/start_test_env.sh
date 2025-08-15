#!/bin/bash
# Start the integration test environment

set -e

echo "Starting ACL BBMD Integration Test Environment"
echo "============================================="
echo ""

# Create necessary directories
echo "Creating directories..."
mkdir -p logs/{bbmd1,bbmd2,bbmd3,bbmd_mgmt}
mkdir -p metrics/{bbmd1,bbmd2,bbmd3,bbmd_mgmt}

# Check if running with Docker or Podman
if command -v podman &> /dev/null; then
    COMPOSE_CMD="podman-compose"
    echo "Using Podman Compose"
elif command -v docker &> /dev/null; then
    COMPOSE_CMD="docker compose"
    echo "Using Docker Compose"
else
    echo "Error: Neither Docker nor Podman found!"
    exit 1
fi

# Build images
echo ""
echo "Building Docker images..."
$COMPOSE_CMD build

# Start services
echo ""
echo "Starting services..."
$COMPOSE_CMD up -d

# Wait for services to be ready
echo ""
echo "Waiting for services to start..."
sleep 10

# Check service status
echo ""
echo "Service Status:"
echo "==============="
$COMPOSE_CMD ps

# Show access information
echo ""
echo "Access Information:"
echo "==================="
echo "Grafana Dashboard: http://localhost:3000 (admin/admin)"
echo "Prometheus: http://localhost:9099"
echo ""
echo "BBMD Metrics Endpoints:"
echo "  Management BBMD: http://localhost:9090/metrics"
echo "  Building 1 BBMD: http://localhost:9091/metrics"
echo "  Building 2 BBMD: http://localhost:9092/metrics"
echo "  Monitoring BBMD: http://localhost:9093/metrics"
echo ""
echo "BBMD UDP Ports:"
echo "  Management BBMD: 47810/udp"
echo "  Building 1 BBMD: 47811/udp"
echo "  Building 2 BBMD: 47812/udp"
echo "  Monitoring BBMD: 47813/udp"
echo ""
echo "Logs are available in: ./logs/"
echo ""
echo "To view logs for a specific BBMD:"
echo "  $COMPOSE_CMD logs -f bbmd1"
echo ""
echo "To run test scenarios:"
echo "  ./scripts/test_scenarios.sh"
echo ""
echo "To stop the environment:"
echo "  ./scripts/stop_test_env.sh"
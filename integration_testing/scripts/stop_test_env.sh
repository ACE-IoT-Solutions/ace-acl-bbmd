#!/bin/bash
# Stop the integration test environment

echo "Stopping ACL BBMD Integration Test Environment"
echo "============================================="
echo ""

# Check if running with Docker or Podman
if command -v podman &> /dev/null; then
    COMPOSE_CMD="podman-compose"
elif command -v docker &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    echo "Error: Neither Docker nor Podman found!"
    exit 1
fi

# Stop services
echo "Stopping services..."
$COMPOSE_CMD down

# Optional: Clean up volumes
read -p "Remove volumes (persistent data)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Removing volumes..."
    $COMPOSE_CMD down -v
fi

# Optional: Clean up logs and metrics
read -p "Remove logs and metrics? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Removing logs and metrics..."
    rm -rf logs/ metrics/
fi

echo ""
echo "Environment stopped."
#!/bin/bash
# Test scenarios for ACL BBMD integration testing

set -e

echo "ACL BBMD Integration Test Scenarios"
echo "==================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper function to run tests
run_test() {
    local test_name=$1
    local expected_result=$2
    shift 2
    local command="$@"
    
    echo -n "Testing: $test_name... "
    
    if eval "$command"; then
        if [ "$expected_result" = "success" ]; then
            echo -e "${GREEN}PASS${NC}"
            return 0
        else
            echo -e "${RED}FAIL${NC} (Expected failure but succeeded)"
            return 1
        fi
    else
        if [ "$expected_result" = "failure" ]; then
            echo -e "${GREEN}PASS${NC} (Failed as expected)"
            return 0
        else
            echo -e "${RED}FAIL${NC}"
            return 1
        fi
    fi
}

# Test 1: Discovery Messages
echo -e "\n${YELLOW}Test 1: Discovery Messages${NC}"
echo "All devices should be able to send Who-Is/I-Am"
sleep 5
# Check logs for discovery messages

# Test 2: HVAC to IoT Control
echo -e "\n${YELLOW}Test 2: HVAC Controllers Writing to IoT Devices${NC}"
docker exec hvac_controller_1 python /app/bacnet_device_simulator.py \
    --device-id 100101 \
    --device-name "HVAC-Test" \
    --local-address "10.1.0.101:47809" \
    --bbmd-address "10.1.0.2:47808" \
    --behavior controller &
HVAC_PID=$!
sleep 10
kill $HVAC_PID 2>/dev/null || true

# Test 3: IoT Write Restrictions
echo -e "\n${YELLOW}Test 3: IoT Devices Write Restrictions${NC}"
echo "IoT devices should be blocked from writing to HVAC"
# This should be logged as denied in BBMD logs

# Test 4: Monitoring Read-Only Access
echo -e "\n${YELLOW}Test 4: Monitoring Network Read-Only${NC}"
echo "Monitoring devices should only be able to read"
# Check that monitoring devices can read but not write

# Test 5: Rogue Device Blocking
echo -e "\n${YELLOW}Test 5: Rogue Device Blocking${NC}"
echo "Device 666666 should be completely blocked"
# Check BBMD2 logs for blocked attempts

# Test 6: Management Full Access
echo -e "\n${YELLOW}Test 6: Management Network Full Access${NC}"
echo "Management station should have unrestricted access"
# Verify management station can perform all operations

# Test 7: ACL Runtime Reload
echo -e "\n${YELLOW}Test 7: ACL Runtime Reload${NC}"
echo "Modifying ACL rules and verifying reload"

# Create a more restrictive ACL
cat > ./configs/bbmd1/acl_rules_restrictive.yaml << EOF
default_action: deny
log_default: true

rules:
  - name: "emergency_lockdown"
    action: deny
    priority: 1
    message_types: [all]
    log_matches: true
    enabled: true
    description: "Emergency lockdown - deny all"
EOF

# Copy new ACL over the existing one
docker exec bbmd1 cp /app/config/acl_rules_restrictive.yaml /app/config/acl_rules.yaml
sleep 3

echo "ACL should now be in lockdown mode"
# Verify all traffic is blocked

# Restore original ACL
docker exec bbmd1 cp /app/config/acl_rules.yaml.bak /app/config/acl_rules.yaml 2>/dev/null || true

# Test 8: Metrics Collection
echo -e "\n${YELLOW}Test 8: Metrics Collection${NC}"
echo "Checking Prometheus metrics endpoints"

for bbmd in bbmd1 bbmd2 bbmd3 bbmd_mgmt; do
    if curl -s http://localhost:909${bbmd: -1}/metrics | grep -q "bacnet_packets_total"; then
        echo -e "  $bbmd metrics: ${GREEN}OK${NC}"
    else
        echo -e "  $bbmd metrics: ${RED}FAIL${NC}"
    fi
done

# Test 9: Foreign Device Registration
echo -e "\n${YELLOW}Test 9: Foreign Device Registration${NC}"
echo "Testing foreign device registration and limits"
# Create foreign devices and test registration

# Summary
echo -e "\n${YELLOW}Test Summary${NC}"
echo "============="
echo "View detailed results in:"
echo "  - BBMD logs: ./logs/"
echo "  - Prometheus: http://localhost:9099"
echo "  - Grafana: http://localhost:3000 (admin/admin)"
echo ""
echo "To view real-time metrics:"
echo "  docker compose exec prometheus promtool query instant http://localhost:9090 'bacnet_packets_total'"
echo ""
echo "To view ACL hit counts:"
echo "  docker compose exec prometheus promtool query instant http://localhost:9090 'bacnet_rule_hit_count'"
#!/bin/bash
# Demonstration of ACL runtime reloading

echo "ACL Runtime Reload Demonstration"
echo "================================"
echo ""

# Create initial ACL config
cat > demo_acl.yaml << 'EOF'
# Initial ACL - Allow all
default_action: allow
log_default: false

rules:
  - name: "allow_all_initial"
    action: allow
    priority: 100
    message_types: [all]
    log_matches: false
    enabled: true
EOF

echo "1. Starting BBMD with initial ACL (allow all)..."
echo "   Command: ace-acl-bbmd --config config/bbmd_config_clean.yaml --acl demo_acl.yaml"
echo ""

# Start BBMD in background
uv run ace-acl-bbmd --config ../config/bbmd_config_clean.yaml --acl demo_acl.yaml &
BBMD_PID=$!

# Wait for startup
sleep 3

echo ""
echo "2. BBMD is running with initial ACL configuration"
echo "   - Default action: ALLOW"
echo "   - Rules: 1 (allow_all_initial)"
echo ""
echo "3. Updating ACL configuration in 5 seconds..."
sleep 5

# Update ACL to be more restrictive
cat > demo_acl.yaml << 'EOF'
# Updated ACL - More restrictive
default_action: deny
log_default: true

rules:
  # Allow discovery messages only
  - name: "allow_discovery_only"
    action: allow
    priority: 10
    message_types:
      - who_is
      - i_am
    log_matches: true
    enabled: true
    
  # Deny all writes
  - name: "deny_all_writes"
    action: deny
    priority: 20
    message_types:
      - write_property
    log_matches: true
    enabled: true
    
  # Allow reads from specific network
  - name: "allow_local_reads"
    action: allow
    priority: 30
    source_network: "192.168.1.0/24"
    message_types:
      - read_property
    log_matches: false
    enabled: true
EOF

echo ""
echo "4. ACL configuration updated!"
echo "   - Default action: DENY"
echo "   - Rules: 3 (discovery only, deny writes, allow local reads)"
echo ""
echo "   The BBMD should automatically reload the new ACL configuration..."
echo ""

# Wait to see the reload
sleep 5

echo ""
echo "5. Updating ACL one more time in 5 seconds..."
sleep 5

# Final update - back to permissive
cat > demo_acl.yaml << 'EOF'
# Final ACL - Permissive with logging
default_action: allow
log_default: false

enable_cut_through: true
cut_through_networks:
  - "192.168.100.0/24"

rules:
  # Log all write operations
  - name: "log_writes"
    action: allow_log
    priority: 10
    message_types:
      - write_property
    log_matches: true
    enabled: true
    
  # Block specific device
  - name: "block_device_666"
    action: deny
    priority: 5
    source_device: 666
    log_matches: true
    enabled: true
EOF

echo ""
echo "6. Final ACL configuration updated!"
echo "   - Default action: ALLOW"
echo "   - Cut-through enabled for 192.168.100.0/24"
echo "   - Rules: 2 (log writes, block device 666)"
echo ""

sleep 5

echo ""
echo "7. Stopping BBMD..."
kill $BBMD_PID 2>/dev/null
wait $BBMD_PID 2>/dev/null

# Cleanup
rm -f demo_acl.yaml

echo ""
echo "Demo completed!"
echo ""
echo "Key points demonstrated:"
echo "- ACL configuration can be updated without restarting BBMD"
echo "- File changes are detected automatically"
echo "- New rules take effect immediately"
echo "- Cut-through networks can be modified at runtime"
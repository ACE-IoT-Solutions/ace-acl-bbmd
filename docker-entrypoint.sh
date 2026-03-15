#!/bin/sh
set -e

# Generate runtime config from environment variables.
# If the user mounts their own config file, this is skipped.
CONFIG_FILE="/app/config/runtime.yaml"

if [ ! -f "$CONFIG_FILE" ] || [ "${BBMD_GENERATE_CONFIG:-true}" = "true" ]; then

    # ---- BBMD core settings ----
    BBMD_ADDRESS="${BBMD_ADDRESS:-0.0.0.0:47808}"
    BBMD_INTERFACE="${BBMD_INTERFACE:-}"
    BBMD_BDT_ENTRIES="${BBMD_BDT_ENTRIES:-}"          # comma-separated
    BBMD_ACCEPT_FOREIGN_DEVICES="${BBMD_ACCEPT_FOREIGN_DEVICES:-true}"
    BBMD_MAX_FOREIGN_DEVICES="${BBMD_MAX_FOREIGN_DEVICES:-100}"

    # ---- BACnet device identity ----
    BBMD_DEVICE_INSTANCE="${BBMD_DEVICE_INSTANCE:-999}"
    BBMD_DEVICE_NAME="${BBMD_DEVICE_NAME:-ACE-ACL-BBMD}"
    BBMD_VENDOR_NAME="${BBMD_VENDOR_NAME:-ACE IoT Solutions}"
    BBMD_VENDOR_IDENTIFIER="${BBMD_VENDOR_IDENTIFIER:-999}"
    BBMD_MODEL_NAME="${BBMD_MODEL_NAME:-ACE ACL BBMD}"
    BBMD_DESCRIPTION="${BBMD_DESCRIPTION:-ACL-enabled BACnet/IP Broadcast Management Device}"

    # ---- Logging ----
    BBMD_LOG_LEVEL="${BBMD_LOG_LEVEL:-INFO}"
    BBMD_LOG_FILE="${BBMD_LOG_FILE:-}"

    # ---- Metrics ----
    BBMD_ENABLE_METRICS="${BBMD_ENABLE_METRICS:-true}"
    BBMD_METRICS_INTERVAL="${BBMD_METRICS_INTERVAL:-60}"
    BBMD_METRICS_RETENTION="${BBMD_METRICS_RETENTION:-3600}"
    BBMD_METRICS_HTTP_ENABLED="${BBMD_METRICS_HTTP_ENABLED:-true}"
    BBMD_METRICS_HTTP_PORT="${BBMD_METRICS_HTTP_PORT:-9090}"
    BBMD_METRICS_FILE_EXPORT_ENABLED="${BBMD_METRICS_FILE_EXPORT_ENABLED:-false}"
    BBMD_METRICS_FILE_EXPORT_PATH="${BBMD_METRICS_FILE_EXPORT_PATH:-/app/metrics/bbmd_metrics.prom}"
    BBMD_METRICS_FILE_EXPORT_INTERVAL="${BBMD_METRICS_FILE_EXPORT_INTERVAL:-60}"

    # ---- Performance ----
    BBMD_MAX_PACKET_SIZE="${BBMD_MAX_PACKET_SIZE:-1476}"
    BBMD_QUEUE_SIZE="${BBMD_QUEUE_SIZE:-1000}"

    # ---- ACL ----
    BBMD_ACL_DEFAULT_ACTION="${BBMD_ACL_DEFAULT_ACTION:-deny}"
    BBMD_ACL_LOG_DEFAULT="${BBMD_ACL_LOG_DEFAULT:-true}"
    BBMD_ACL_ENABLE_CUT_THROUGH="${BBMD_ACL_ENABLE_CUT_THROUGH:-true}"
    BBMD_ACL_CUT_THROUGH_NETWORKS="${BBMD_ACL_CUT_THROUGH_NETWORKS:-}"  # comma-separated CIDRs

    # ---- Write config ----
    cat > "$CONFIG_FILE" <<YAML
# Auto-generated from environment variables
bbmd_address: "${BBMD_ADDRESS}"

device_instance: ${BBMD_DEVICE_INSTANCE}
device_name: "${BBMD_DEVICE_NAME}"
vendor_name: "${BBMD_VENDOR_NAME}"
vendor_identifier: ${BBMD_VENDOR_IDENTIFIER}
model_name: "${BBMD_MODEL_NAME}"
description: "${BBMD_DESCRIPTION}"
YAML

    # Optional fields
    [ -n "$BBMD_INTERFACE" ] && echo "interface: \"${BBMD_INTERFACE}\"" >> "$CONFIG_FILE"

    # BDT entries
    if [ -n "$BBMD_BDT_ENTRIES" ]; then
        echo "bdt_entries:" >> "$CONFIG_FILE"
        echo "$BBMD_BDT_ENTRIES" | tr ',' '\n' | while read -r entry; do
            entry=$(echo "$entry" | xargs)  # trim whitespace
            [ -n "$entry" ] && echo "  - \"${entry}\"" >> "$CONFIG_FILE"
        done
    else
        echo "bdt_entries: []" >> "$CONFIG_FILE"
    fi

    cat >> "$CONFIG_FILE" <<YAML

accept_foreign_devices: ${BBMD_ACCEPT_FOREIGN_DEVICES}
max_foreign_devices: ${BBMD_MAX_FOREIGN_DEVICES}

log_level: "${BBMD_LOG_LEVEL}"
YAML

    [ -n "$BBMD_LOG_FILE" ] && echo "log_file: \"${BBMD_LOG_FILE}\"" >> "$CONFIG_FILE"

    cat >> "$CONFIG_FILE" <<YAML

enable_metrics: ${BBMD_ENABLE_METRICS}
metrics_interval: ${BBMD_METRICS_INTERVAL}
metrics_retention: ${BBMD_METRICS_RETENTION}
metrics_http_enabled: ${BBMD_METRICS_HTTP_ENABLED}
metrics_http_port: ${BBMD_METRICS_HTTP_PORT}
metrics_file_export_enabled: ${BBMD_METRICS_FILE_EXPORT_ENABLED}
metrics_file_export_path: "${BBMD_METRICS_FILE_EXPORT_PATH}"
metrics_file_export_interval: ${BBMD_METRICS_FILE_EXPORT_INTERVAL}

max_packet_size: ${BBMD_MAX_PACKET_SIZE}
queue_size: ${BBMD_QUEUE_SIZE}

acl:
  default_action: ${BBMD_ACL_DEFAULT_ACTION}
  log_default: ${BBMD_ACL_LOG_DEFAULT}
  enable_cut_through: ${BBMD_ACL_ENABLE_CUT_THROUGH}
YAML

    # Cut-through networks
    if [ -n "$BBMD_ACL_CUT_THROUGH_NETWORKS" ]; then
        echo "  cut_through_networks:" >> "$CONFIG_FILE"
        echo "$BBMD_ACL_CUT_THROUGH_NETWORKS" | tr ',' '\n' | while read -r cidr; do
            cidr=$(echo "$cidr" | xargs)
            [ -n "$cidr" ] && echo "    - \"${cidr}\"" >> "$CONFIG_FILE"
        done
    fi

    # ACL rules are complex — load from a mounted file if provided
    if [ -n "$BBMD_ACL_RULES_FILE" ] && [ -f "$BBMD_ACL_RULES_FILE" ]; then
        echo "  # Rules loaded from ${BBMD_ACL_RULES_FILE} via --acl flag" >> "$CONFIG_FILE"
    else
        echo "  rules: []" >> "$CONFIG_FILE"
    fi

    echo "Generated runtime config from environment variables"
fi

# If a separate ACL rules file is provided, pass it via --acl
if [ -n "$BBMD_ACL_RULES_FILE" ] && [ -f "$BBMD_ACL_RULES_FILE" ]; then
    exec "$@" --acl "$BBMD_ACL_RULES_FILE"
else
    exec "$@"
fi

# ACL Runtime Reloading

The ACE ACL BBMD supports runtime reloading of ACL configurations without restarting the service. This allows you to update security policies on the fly.

## Configuration Structure

The recommended setup separates BBMD configuration from ACL rules:

1. **BBMD Configuration** (`bbmd_config.yaml`) - Contains network settings, logging, metrics, etc.
2. **ACL Configuration** (`acl_rules.yaml`) - Contains only the ACL rules

## Usage

### Starting with Separate ACL File

```bash
ace-acl-bbmd --config config/bbmd_config_clean.yaml --acl config/acl_rules.yaml
```

When you use the `--acl` flag, the BBMD will:
1. Load the initial ACL configuration
2. Start watching the file for changes
3. Automatically reload when the file is modified

### Example Workflow

1. **Start BBMD with initial ACL**:
```yaml
# acl_rules.yaml - Initial permissive policy
default_action: allow
rules:
  - name: "allow_all"
    action: allow
    priority: 100
    message_types: [all]
```

2. **Update ACL while running**:
```yaml
# acl_rules.yaml - Updated restrictive policy
default_action: deny
log_default: true

rules:
  # Allow discovery only
  - name: "allow_discovery"
    action: allow
    priority: 10
    message_types: [who_is, i_am]
    
  # Block write operations
  - name: "deny_writes"
    action: deny
    priority: 20
    message_types: [write_property]
    log_matches: true
```

3. **The BBMD automatically detects the change and reloads**:
```
2025-08-05 14:30:00 - ace_acl_bbmd.acl_reload - INFO - ACL configuration file changed: /path/to/acl_rules.yaml
2025-08-05 14:30:00 - ace_acl_bbmd.acl_engine - INFO - ACL configuration updated: 1 -> 2 rules, default_action=deny
2025-08-05 14:30:00 - ace_acl_bbmd.bbmd - INFO - BBMD ACL configuration updated
```

## Features

### What Can Be Changed at Runtime

- Default action (allow/deny/log)
- ACL rules (add, remove, modify)
- Rule priorities
- Cut-through networks
- Logging settings
- Time-based restrictions

### What Cannot Be Changed

- BBMD network address
- BDT peer list
- Metrics configuration
- Log file paths

## Implementation Details

The reload mechanism uses:
- **File watching**: Uses the `watchdog` library to monitor file changes
- **MD5 hashing**: Prevents unnecessary reloads if content hasn't changed
- **Cooldown period**: 2-second cooldown between reloads to handle rapid edits
- **Validation**: New configurations are validated before applying
- **Atomic updates**: ACL engine updates are atomic to prevent inconsistent state

## Best Practices

1. **Test ACL changes** in a development environment first
2. **Use version control** for ACL configuration files
3. **Monitor logs** after changes to ensure rules work as expected
4. **Keep backups** of working ACL configurations
5. **Document rule changes** with comments in the YAML file

## Troubleshooting

If ACL reload fails:
1. Check logs for validation errors
2. Verify YAML syntax is correct
3. Ensure file permissions allow reading
4. Check that rule names are unique
5. Validate network CIDR notations

## Example ACL Configurations

See `config/acl_example.yaml` for comprehensive examples of ACL rules and patterns.
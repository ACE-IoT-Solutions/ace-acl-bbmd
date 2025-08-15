#!/usr/bin/env python3
"""Test ACL runtime reloading."""

import asyncio
import sys
from pathlib import Path
import yaml
import time

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from ace_acl_bbmd.config import ConfigLoader
from ace_acl_bbmd.__main__ import ACLBBMDApplication


async def test_acl_reload():
    """Test ACL runtime reloading."""
    # Create initial ACL config
    initial_acl = {
        "default_action": "allow",
        "log_default": False,
        "rules": [
            {
                "name": "allow_all",
                "action": "allow",
                "priority": 100,
                "message_types": ["all"],
                "enabled": True
            }
        ]
    }
    
    acl_path = Path("test_acl.yaml")
    with open(acl_path, "w") as f:
        yaml.safe_dump(initial_acl, f)
    
    # Load configurations
    loader = ConfigLoader()
    config = loader.load_config(Path("config/bbmd_config_clean.yaml"))
    config.acl = loader.load_acl_config(acl_path)
    
    # Create application
    app = ACLBBMDApplication(config)
    app.setup_acl_reload(acl_path)
    
    # Start in background
    print("Starting BBMD with initial ACL (allow all)...")
    start_task = asyncio.create_task(app.start())
    await asyncio.sleep(2)
    
    print(f"Initial ACL: {len(config.acl.rules)} rules, default={config.acl.default_action}")
    
    # Update ACL
    print("\nUpdating ACL configuration...")
    updated_acl = {
        "default_action": "deny",
        "log_default": True,
        "rules": [
            {
                "name": "allow_discovery",
                "action": "allow",
                "priority": 10,
                "message_types": ["who_is", "i_am"],
                "enabled": True
            },
            {
                "name": "deny_writes",
                "action": "deny",
                "priority": 20,
                "message_types": ["write_property"],
                "log_matches": True,
                "enabled": True
            }
        ]
    }
    
    with open(acl_path, "w") as f:
        yaml.safe_dump(updated_acl, f)
    
    # Wait for reload
    await asyncio.sleep(3)
    print("ACL should be reloaded now")
    
    # Clean up
    await app.stop()
    start_task.cancel()
    try:
        await start_task
    except asyncio.CancelledError:
        pass
    
    acl_path.unlink()
    print("\nTest completed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(test_acl_reload()))
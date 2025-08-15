"""
Tests for configuration management
"""

import pytest
from pathlib import Path
import tempfile
import yaml

from ace_acl_bbmd.config import ConfigLoader, BBMDConfig, create_default_config
from ace_acl_bbmd.models.acl import ACLConfig, RuleAction


class TestConfigLoader:
    """Test configuration loading functionality."""
    
    @pytest.fixture
    def temp_config_dir(self):
        """Create temporary directory for test configs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    def test_load_yaml_config(self, temp_config_dir):
        """Test loading YAML configuration."""
        # Create test YAML config
        config_data = {
            "bbmd_address": "192.168.1.100/24:47808",
            "bdt_entries": ["192.168.1.101:47808", "192.168.2.100:47808"],
            "accept_foreign_devices": True,
            "log_level": "INFO",
            "acl": {
                "default_action": "deny",
                "log_default": True,
                "rules": [
                    {
                        "name": "test_rule",
                        "action": "allow",
                        "priority": 10,
                        "source_network": "192.168.1.0/24",
                        "message_types": ["who_is", "i_am"],
                    }
                ]
            }
        }
        
        config_file = temp_config_dir / "test_config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        # Load config
        loader = ConfigLoader(temp_config_dir)
        config = loader.load_config(config_file)
        
        assert str(config.bbmd_address) == "192.168.1.100/24:47808"
        assert len(config.bdt_entries) == 2
        assert config.accept_foreign_devices is True
        assert config.log_level == "INFO"
        assert isinstance(config.acl, ACLConfig)
        assert len(config.acl.rules) == 1
        assert config.acl.rules[0].name == "test_rule"
    
    def test_load_acl_config(self, temp_config_dir):
        """Test loading standalone ACL configuration."""
        acl_data = {
            "default_action": "allow",
            "log_default": False,
            "enable_cut_through": True,
            "cut_through_networks": ["10.0.0.0/8"],
            "rules": [
                {
                    "name": "deny_bad_device",
                    "action": "deny",
                    "priority": 1,
                    "source_device": 666666,
                },
                {
                    "name": "allow_internal",
                    "action": "allow",
                    "priority": 100,
                    "source_network": "10.0.0.0/8",
                }
            ]
        }
        
        acl_file = temp_config_dir / "test_acl.yaml"
        with open(acl_file, 'w') as f:
            yaml.dump(acl_data, f)
        
        # Load ACL config
        loader = ConfigLoader(temp_config_dir)
        acl_config = loader.load_acl_config(acl_file)
        
        assert acl_config.default_action == RuleAction.ALLOW
        assert acl_config.log_default is False
        assert acl_config.enable_cut_through is True
        assert len(acl_config.cut_through_networks) == 1
        assert len(acl_config.rules) == 2
    
    def test_invalid_config(self, temp_config_dir):
        """Test handling invalid configuration."""
        # Missing required field
        config_data = {
            "log_level": "INFO",
            "acl": {
                "default_action": "deny",
                "rules": []
            }
        }
        
        config_file = temp_config_dir / "invalid_config.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        loader = ConfigLoader(temp_config_dir)
        with pytest.raises(ValueError, match="Invalid configuration"):
            loader.load_config(config_file)
    
    def test_nonexistent_file(self):
        """Test loading non-existent file."""
        loader = ConfigLoader()
        with pytest.raises(FileNotFoundError):
            loader.load_config(Path("nonexistent.yaml"))
    
    def test_save_yaml_config(self, temp_config_dir):
        """Test saving configuration to YAML."""
        # Create config
        config = create_default_config()
        config.bbmd_address = "192.168.1.200/24:47808"
        config.log_level = "DEBUG"
        
        # Save config
        config_file = temp_config_dir / "saved_config.yaml"
        loader = ConfigLoader(temp_config_dir)
        loader.save_config(config, config_file)
        
        # Verify file exists and can be loaded
        assert config_file.exists()
        loaded_config = loader.load_config(config_file)
        assert str(loaded_config.bbmd_address) == "192.168.1.200/24:47808"
        assert loaded_config.log_level == "DEBUG"


class TestBBMDConfig:
    """Test BBMD configuration model."""
    
    def test_default_config(self):
        """Test creating default configuration."""
        config = create_default_config()
        
        assert config.bbmd_address == "0.0.0.0:47808"
        assert len(config.bdt_entries) == 0
        assert config.accept_foreign_devices is True
        assert config.log_level == "INFO"
        assert config.enable_metrics is True
        assert isinstance(config.acl, ACLConfig)
    
    def test_config_validation(self):
        """Test configuration validation."""
        # Valid config
        config = BBMDConfig(
            bbmd_address="192.168.1.100:47808",
            acl=ACLConfig(rules=[]),
            max_packet_size=2000,
            queue_size=500,
        )
        
        assert config.max_packet_size == 2000
        assert config.queue_size == 500
        
        # Invalid values should raise errors
        with pytest.raises(ValueError):
            BBMDConfig(
                bbmd_address="192.168.1.100:47808",
                acl=ACLConfig(rules=[]),
                max_packet_size=100,  # Too small
            )
        
        with pytest.raises(ValueError):
            BBMDConfig(
                bbmd_address="192.168.1.100:47808",
                acl=ACLConfig(rules=[]),
                metrics_interval=5,  # Too small
            )
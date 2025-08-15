"""
Configuration Management for ACL BBMD

This module handles loading and managing configuration from YAML/TOML files
for the ACL-enabled BBMD.
"""

import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from ipaddress import IPv4Network

import yaml
from bacpypes3.pdu import IPv4Address

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # Fallback for older Python

from pydantic import BaseModel, Field, field_validator, ValidationError

from .models.acl import ACLConfig

logger = logging.getLogger(__name__)


class BBMDConfig(BaseModel):
    """Complete BBMD configuration."""

    # BBMD network settings - store as string for Pydantic compatibility
    bbmd_address: str = Field(
        ..., description="BBMD IP address and port (e.g., 192.168.1.10/24:47808)"
    )
    interface: Optional[str] = Field(
        default=None, description="Network interface to bind to"
    )

    # BDT (Broadcast Distribution Table) - store as strings
    bdt_entries: List[str] = Field(
        default_factory=list, description="List of peer BBMD addresses"
    )

    # Foreign device settings
    accept_foreign_devices: bool = Field(
        default=True, description="Whether to accept foreign device registrations"
    )
    max_foreign_devices: int = Field(
        default=100, ge=0, description="Maximum number of foreign devices"
    )

    # ACL configuration - can be in this file or loaded separately
    acl: Optional[ACLConfig] = Field(None, description="Access Control List configuration")

    # Logging settings
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: Optional[Path] = Field(default=None, description="Log file path")
    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format string",
    )

    # Metrics settings
    enable_metrics: bool = Field(default=True, description="Enable metrics collection")
    metrics_interval: int = Field(
        default=60, ge=10, description="Metrics snapshot interval in seconds"
    )
    metrics_retention: int = Field(
        default=3600, ge=60, description="Metrics retention period in seconds"
    )
    
    # Prometheus metrics settings
    metrics_http_enabled: bool = Field(
        default=False, description="Enable Prometheus HTTP metrics endpoint"
    )
    metrics_http_port: int = Field(
        default=9090, ge=1024, le=65535, description="Port for Prometheus HTTP server"
    )
    metrics_file_export_enabled: bool = Field(
        default=False, description="Enable periodic metrics file export"
    )
    metrics_file_export_path: Optional[Path] = Field(
        default=None, description="Path for metrics file export"
    )
    metrics_file_export_interval: int = Field(
        default=60, ge=10, description="Interval for metrics file export in seconds"
    )

    # Performance settings
    max_packet_size: int = Field(
        default=1476, ge=512, le=65535, description="Maximum packet size"
    )
    queue_size: int = Field(default=1000, ge=100, description="Packet queue size")

    @field_validator("bbmd_address")
    @classmethod
    def validate_bbmd_address(cls, v: str) -> str:
        """Validate BBMD address format."""
        try:
            # Test that it can be parsed as IPv4Address
            IPv4Address(v)
            return v
        except Exception as e:
            raise ValueError(f"Invalid BBMD address format: {e}")

    @field_validator("bdt_entries")
    @classmethod
    def validate_bdt_entries(cls, v: List[str]) -> List[str]:
        """Validate BDT entry formats."""
        for addr in v:
            try:
                IPv4Address(addr)
            except Exception as e:
                raise ValueError(f"Invalid BDT entry '{addr}': {e}")
        return v

    def get_bbmd_address(self) -> IPv4Address:
        """Get BBMD address as IPv4Address object."""
        return IPv4Address(self.bbmd_address)

    def get_bdt_entries(self) -> List[IPv4Address]:
        """Get BDT entries as IPv4Address objects."""
        return [IPv4Address(addr) for addr in self.bdt_entries]


class ConfigLoader:
    """Configuration loader for ACL BBMD."""

    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize configuration loader.

        Args:
            config_dir: Configuration directory path
        """
        self.config_dir = config_dir or Path("config")

    def load_config(self, config_file: Path) -> BBMDConfig:
        """
        Load configuration from YAML or TOML file.

        Args:
            config_file: Path to configuration file

        Returns:
            BBMDConfig instance

        Raises:
            ValueError: Invalid configuration
            FileNotFoundError: Configuration file not found
        """
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")

        # Determine file type
        suffix = config_file.suffix.lower()

        if suffix in (".yaml", ".yml"):
            config_data = self._load_yaml(config_file)
        elif suffix == ".toml":
            config_data = self._load_toml(config_file)
        else:
            raise ValueError(f"Unsupported configuration file type: {suffix}")

        # Validate and create configuration
        try:
            # Handle nested ACL configuration
            if "acl" in config_data and isinstance(config_data["acl"], dict):
                config_data["acl"] = ACLConfig(**config_data["acl"])

            config = BBMDConfig(**config_data)
            logger.info(f"Configuration loaded from {config_file}")
            return config

        except ValidationError as e:
            logger.error(f"Configuration validation failed: {e}")
            raise ValueError(f"Invalid configuration: {e}")

    def _load_yaml(self, file_path: Path) -> Dict[str, Any]:
        """Load YAML configuration file."""
        try:
            with open(file_path, "r") as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Failed to parse YAML: {e}")

    def _load_toml(self, file_path: Path) -> Dict[str, Any]:
        """Load TOML configuration file."""
        try:
            with open(file_path, "rb") as f:
                return tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise ValueError(f"Failed to parse TOML: {e}")

    def load_acl_config(self, acl_file: Path) -> ACLConfig:
        """
        Load standalone ACL configuration.

        Args:
            acl_file: Path to ACL configuration file

        Returns:
            ACLConfig instance
        """
        if not acl_file.exists():
            raise FileNotFoundError(f"ACL configuration file not found: {acl_file}")

        # Load file based on type
        suffix = acl_file.suffix.lower()

        if suffix in (".yaml", ".yml"):
            acl_data = self._load_yaml(acl_file)
        elif suffix == ".toml":
            acl_data = self._load_toml(acl_file)
        else:
            raise ValueError(f"Unsupported ACL file type: {suffix}")

        try:
            return ACLConfig(**acl_data)
        except ValidationError as e:
            logger.error(f"ACL configuration validation failed: {e}")
            raise ValueError(f"Invalid ACL configuration: {e}")

    def watch_config(self, config_file: Path, callback):
        """
        Watch configuration file for changes.

        Args:
            config_file: Configuration file to watch
            callback: Function to call when file changes
        """
        # This would use watchdog or similar library
        # For now, just a placeholder
        logger.info(f"Config watching not yet implemented for {config_file}")

    def save_config(self, config: BBMDConfig, config_file: Path) -> None:
        """
        Save configuration to file.

        Args:
            config: Configuration to save
            config_file: Target file path
        """
        # Convert to dictionary
        config_dict = config.model_dump()

        # Determine file type
        suffix = config_file.suffix.lower()

        if suffix in (".yaml", ".yml"):
            self._save_yaml(config_dict, config_file)
        elif suffix == ".toml":
            self._save_toml(config_dict, config_file)
        else:
            raise ValueError(f"Unsupported configuration file type: {suffix}")

        logger.info(f"Configuration saved to {config_file}")

    def _save_yaml(self, data: Dict[str, Any], file_path: Path) -> None:
        """Save configuration as YAML."""
        # Convert special types to strings
        data = self._convert_to_serializable(data)

        with open(file_path, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)

    def _save_toml(self, data: Dict[str, Any], file_path: Path) -> None:
        """Save configuration as TOML."""
        # Note: Would need tomlkit for writing TOML files
        raise NotImplementedError("TOML saving not yet implemented")

    def _convert_to_serializable(self, data: Any) -> Any:
        """Recursively convert objects to serializable types."""
        if isinstance(data, Path):
            return str(data)
        elif isinstance(data, IPv4Network):
            return str(data)
        elif hasattr(data, "value"):  # Handle enums
            return data.value
        elif isinstance(data, dict):
            return {k: self._convert_to_serializable(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._convert_to_serializable(item) for item in data]
        return data


def create_default_config() -> BBMDConfig:
    """Create a default BBMD configuration."""
    return BBMDConfig(
        bbmd_address="0.0.0.0:47808",
        acl=ACLConfig(
            rules=[],
            default_action="deny",
            log_default=True,
        ),
    )


def validate_config_file(config_file: Path) -> bool:
    """
    Validate a configuration file.

    Args:
        config_file: Path to configuration file

    Returns:
        True if valid, False otherwise
    """
    try:
        loader = ConfigLoader()
        loader.load_config(config_file)
        return True
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        return False


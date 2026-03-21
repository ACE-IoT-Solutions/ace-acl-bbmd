#!/usr/bin/env python3
"""
ACL BBMD CLI Entry Point

Launches a full BACnet device (Who-Is/I-Am, ReadProperty, etc.) that also
acts as an ACL-filtered Broadcast Management Device.
"""

import asyncio
import argparse
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

from bacpypes3.debugging import ModuleLogger
from bacpypes3.basetypes import BDTEntry, IPMode
from bacpypes3.local.device import DeviceObject
from bacpypes3.local.networkport import NetworkPortObject

from .application import ACLBBMDApplication
from .config import ConfigLoader, BBMDConfig
from .models.acl import ACLConfig, RuleAction
from .models.metrics import MetricsCollector, MetricsConfig
from .acl_reload import ACLReloadManager

# Debugging
_debug = 0
_log = ModuleLogger(globals())

# Module logger
logger = logging.getLogger(__name__)


def _build_objects(config: BBMDConfig):
    """Build the DeviceObject and NetworkPortObject from configuration."""
    device_object = DeviceObject(
        objectIdentifier=("device", config.device_instance),
        objectName=config.device_name,
        vendorName=config.vendor_name,
        vendorIdentifier=config.vendor_identifier,
        modelName=config.model_name,
        description=config.description,
    )

    network_port_object = NetworkPortObject(
        config.bbmd_address,
        objectIdentifier=("network-port", 1),
        objectName="NetworkPort-1",
    )

    # Configure as BBMD
    network_port_object.bacnetIPMode = IPMode.bbmd
    network_port_object.bbmdAcceptFDRegistrations = config.accept_foreign_devices
    network_port_object.bbmdForeignDeviceTable = []

    # Populate BDT
    bdt = []
    for addr_str in config.bdt_entries:
        bdt.append(BDTEntry(addr_str))
    network_port_object.bbmdBroadcastDistributionTable = bdt

    return [device_object, network_port_object]


class ACLBBMDRunner:
    """Manages the lifecycle of the ACL BBMD application."""

    def __init__(self, config: BBMDConfig, acl_path: Optional[Path] = None):
        self.config = config
        self.acl_path = acl_path
        self.app: Optional[ACLBBMDApplication] = None
        self.running = False
        self.acl_reload_manager = ACLReloadManager()

        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure logging based on configuration."""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        logging.basicConfig(
            level=log_level,
            format=self.config.log_format,
        )
        if self.config.log_file:
            log_dir = self.config.log_file.parent
            log_dir.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(self.config.log_file)
            file_handler.setFormatter(logging.Formatter(self.config.log_format))
            logging.getLogger().addHandler(file_handler)

    async def start(self) -> None:
        """Start the application."""
        logger.info(
            "Starting ACL BBMD: device=%d name=%s addr=%s",
            self.config.device_instance,
            self.config.device_name,
            self.config.bbmd_address,
        )

        # Build metrics collector
        metrics_collector = None
        if self.config.enable_metrics:
            metrics_config = MetricsConfig(
                enable_http_server=self.config.metrics_http_enabled,
                http_port=self.config.metrics_http_port,
                enable_file_export=self.config.metrics_file_export_enabled,
                file_export_path=self.config.metrics_file_export_path,
                file_export_interval=self.config.metrics_file_export_interval,
            )
            metrics_collector = MetricsCollector(metrics_config)

        # Build BACnet objects
        objects = _build_objects(self.config)

        # ACL config
        acl_config = self.config.acl
        if not acl_config:
            logger.warning("No ACL configuration provided, using default allow-all policy")
            acl_config = ACLConfig(default_action=RuleAction.ALLOW, rules=[])

        # Create the application — this wires up the full stack:
        #   Application ↔ ASAP ↔ NSAP ↔ ACLBBMDLinkLayer ↔ BVLLCodec ↔ UDP
        self.app = ACLBBMDApplication.from_object_list(
            objects,
            acl_config=acl_config,
            metrics_collector=metrics_collector,
        )

        # Set up ACL file reloading
        if self.acl_path:
            def reload_callback(new_config):
                if self.app:
                    self.app.update_acl_config(new_config)
                    logger.info("ACL configuration reloaded from %s", self.acl_path)

            self.acl_reload_manager.add_reload_callback(reload_callback)
            self.acl_reload_manager.start_watching(self.acl_path)
            logger.info("Watching ACL configuration file: %s", self.acl_path)

        # Start metrics reporting
        if self.config.enable_metrics and metrics_collector:
            asyncio.create_task(self._metrics_reporter(metrics_collector))

        self.running = True
        logger.info("ACL BBMD started successfully — device %d responding to BACnet services", self.config.device_instance)

        while self.running:
            await asyncio.sleep(1)

    async def stop(self) -> None:
        """Stop the application."""
        logger.info("Stopping ACL BBMD...")
        self.running = False

        if self.app and self.app.bbmd_link_layer:
            layer = self.app.bbmd_link_layer
            if hasattr(layer, "_cache_cleanup_handle") and layer._cache_cleanup_handle:
                layer._cache_cleanup_handle.cancel()
            if hasattr(layer, "_fdt_clock_handle") and layer._fdt_clock_handle:
                layer._fdt_clock_handle.cancel()
            layer.close()

        self.acl_reload_manager.stop_watching()
        logger.info("ACL BBMD stopped")

    async def _metrics_reporter(self, metrics: MetricsCollector) -> None:
        """Periodically report metrics."""
        while self.running:
            await asyncio.sleep(self.config.metrics_interval)
            if not self.running:
                break
            snapshot = metrics.get_snapshot()
            logger.info(
                "Metrics: packets=%d, allowed=%d, denied=%d",
                snapshot.total_packets,
                snapshot.packets_allowed,
                snapshot.packets_denied,
            )
            if snapshot.rule_hit_counts:
                top_rules = sorted(
                    snapshot.rule_hit_counts.items(), key=lambda x: x[1], reverse=True
                )[:3]
                if top_rules:
                    logger.info(
                        "Top rules: %s",
                        [f"{rule}:{count}" for rule, count in top_rules],
                    )


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="ACL-enabled BACnet BBMD",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default configuration
  ace-acl-bbmd --config config/bbmd_config.yaml

  # Run with specific ACL file
  ace-acl-bbmd --config config/bbmd_config.yaml --acl config/custom_acl.yaml

  # Validate configuration without running
  ace-acl-bbmd --config config/bbmd_config.yaml --validate

  # Enable debug logging
  ace-acl-bbmd --config config/bbmd_config.yaml --debug
        """,
    )

    parser.add_argument(
        "--config", "-c",
        type=Path,
        required=True,
        help="Path to BBMD configuration file (YAML or TOML)",
    )
    parser.add_argument(
        "--acl", "-a",
        type=Path,
        help="Path to separate ACL configuration file (overrides config file)",
    )
    parser.add_argument(
        "--validate", "-v",
        action="store_true",
        help="Validate configuration and exit",
    )
    parser.add_argument(
        "--debug", "-d",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--metrics-port", "-m",
        type=int,
        help="Port for metrics HTTP endpoint (optional)",
    )

    return parser


async def async_main(args: argparse.Namespace) -> int:
    """Async main function."""
    loader = ConfigLoader()

    try:
        config = loader.load_config(args.config)

        acl_path = None
        if args.acl:
            config.acl = loader.load_acl_config(args.acl)
            acl_path = args.acl
        elif not config.acl:
            logger.warning("No ACL configuration provided, using default allow-all policy")

    except Exception as e:
        logger.error("Failed to load configuration: %s", e)
        return 1

    if args.validate:
        print("Configuration is valid")
        return 0

    if args.debug:
        config.log_level = "DEBUG"

    if args.metrics_port:
        config.metrics_http_port = args.metrics_port
        config.metrics_http_enabled = True

    runner = ACLBBMDRunner(config, acl_path=acl_path)

    def signal_handler(sig, frame):
        logger.info("Received signal %s", sig)
        asyncio.create_task(runner.stop())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        await runner.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error("Application error: %s", e)
        return 1
    finally:
        await runner.stop()

    return 0


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    return asyncio.run(async_main(args))


if __name__ == "__main__":
    sys.exit(main())

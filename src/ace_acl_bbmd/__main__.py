#!/usr/bin/env python3
"""
ACL BBMD CLI Entry Point

This module provides the command-line interface for running the ACL-enabled
BACnet BBMD.
"""

import asyncio
import argparse
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

from bacpypes3.debugging import ModuleLogger
from bacpypes3.ipv4.link import IPv4DatagramServer
from bacpypes3.ipv4.service import UDPMultiplexer
from bacpypes3.ipv4.bvll import BVLLCodec
from bacpypes3.comm import bind

from .bbmd import ACLBBMD
from .config import ConfigLoader, BBMDConfig
from .models.metrics import MetricsCollector
from .acl_reload import ACLReloadManager

# Debugging
_debug = 0
_log = ModuleLogger(globals())

# Module logger
logger = logging.getLogger(__name__)


class ACLBBMDApplication:
    """Main application class for ACL BBMD."""

    def __init__(self, config: BBMDConfig):
        """
        Initialize the ACL BBMD application.

        Args:
            config: BBMD configuration
        """
        self.config = config
        self.bbmd: Optional[ACLBBMD] = None
        self.running = False
        self.metrics = None  # Will be set by BBMD if metrics are enabled
        self.acl_reload_manager = ACLReloadManager()
        self.acl_path: Optional[Path] = None

        # Set up logging
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure logging based on configuration."""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)

        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format=self.config.log_format,
        )

        # Add file handler if specified
        if self.config.log_file:
            # Create log directory if it doesn't exist
            log_dir = self.config.log_file.parent
            log_dir.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(self.config.log_file)
            file_handler.setFormatter(logging.Formatter(self.config.log_format))
            logging.getLogger().addHandler(file_handler)

    def setup_acl_reload(self, acl_path: Path) -> None:
        """Set up ACL configuration reloading."""
        self.acl_path = acl_path
        
        # Add reload callback
        def reload_callback(new_config):
            if self.bbmd:
                self.bbmd.update_acl_config(new_config)
                logger.info(f"ACL configuration reloaded from {acl_path}")
        
        self.acl_reload_manager.add_reload_callback(reload_callback)
        self.acl_reload_manager.start_watching(acl_path)
        logger.info(f"Watching ACL configuration file: {acl_path}")

    async def start(self) -> None:
        """Start the BBMD application."""
        logger.info(f"Starting ACL BBMD on {self.config.bbmd_address}")

        try:
            # Create the BBMD instance
            self.bbmd = ACLBBMD(
                config=self.config,  # Pass the full config, BBMD will handle metrics setup
            )
            
            # Get the metrics collector from BBMD if enabled
            if self.config.enable_metrics:
                self.metrics = self.bbmd.metrics

            # Add peer BBMDs from configuration
            for peer_addr in self.config.get_bdt_entries():
                self.bbmd.add_peer(peer_addr)
                logger.info(f"Added BBMD peer: {peer_addr}")

            # Create the stack
            self.codec = BVLLCodec()
            self.multiplexer = UDPMultiplexer()
            self.server = IPv4DatagramServer(
                address=self.config.get_bbmd_address(),
            )

            # Bind the layers
            bind(self.bbmd, self.codec, self.multiplexer.annexJ)
            bind(self.multiplexer, self.server)

            # Start metrics reporting if enabled
            if self.config.enable_metrics:
                asyncio.create_task(self._metrics_reporter())

            self.running = True
            logger.info("ACL BBMD started successfully")

            # Keep running until stopped
            while self.running:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Failed to start BBMD: {e}")
            raise

    async def stop(self) -> None:
        """Stop the BBMD application."""
        logger.info("Stopping ACL BBMD...")
        self.running = False

        # Clean up resources
        if self.bbmd:
            # Cancel cache cleanup if running
            if hasattr(self.bbmd, "_cache_cleanup_handle") and self.bbmd._cache_cleanup_handle:
                self.bbmd._cache_cleanup_handle.cancel()
            
            # Cancel FDT cleanup if running
            if hasattr(self.bbmd, "_fdt_clock_handle") and self.bbmd._fdt_clock_handle:
                self.bbmd._fdt_clock_handle.cancel()
        
        # Close the server
        if hasattr(self, "server") and self.server:
            self.server.close()
            
        # Stop ACL file watching
        self.acl_reload_manager.stop_watching()

        logger.info("ACL BBMD stopped")

    async def _metrics_reporter(self) -> None:
        """Periodically report metrics."""
        if not self.metrics:
            return
            
        while self.running:
            await asyncio.sleep(self.config.metrics_interval)

            if not self.running:
                break

            # Get metrics snapshot
            snapshot = self.metrics.get_snapshot()

            # Log summary metrics
            logger.info(
                f"Metrics: packets={snapshot.total_packets}, "
                f"allowed={snapshot.packets_allowed}, "
                f"denied={snapshot.packets_denied}"
            )

            # Log rule hit counts if any
            if snapshot.rule_hit_counts:
                top_rules = sorted(snapshot.rule_hit_counts.items(), key=lambda x: x[1], reverse=True)[:3]
                if top_rules:
                    logger.info(f"Top rules: {[f'{rule}:{count}' for rule, count in top_rules]}")


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
        "--config",
        "-c",
        type=Path,
        required=True,
        help="Path to BBMD configuration file (YAML or TOML)",
    )

    parser.add_argument(
        "--acl",
        "-a",
        type=Path,
        help="Path to separate ACL configuration file (overrides config file)",
    )

    parser.add_argument(
        "--validate",
        "-v",
        action="store_true",
        help="Validate configuration and exit",
    )

    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Enable debug logging",
    )

    parser.add_argument(
        "--metrics-port",
        "-m",
        type=int,
        help="Port for metrics HTTP endpoint (optional)",
    )

    return parser


async def async_main(args: argparse.Namespace) -> int:
    """Async main function."""
    # Load configuration
    loader = ConfigLoader()

    try:
        config = loader.load_config(args.config)

        # Load ACL from separate file if provided
        acl_path = None
        if args.acl:
            config.acl = loader.load_acl_config(args.acl)
            acl_path = args.acl
        elif not config.acl:
            # No ACL in config or separate file
            logger.warning("No ACL configuration provided, using default allow-all policy")

    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        return 1

    # Validate only mode
    if args.validate:
        print("Configuration is valid")
        return 0

    # Override debug logging if requested
    if args.debug:
        config.log_level = "DEBUG"
        _debug = 1  # Enable BACpypes debugging

    # Create and run application
    app = ACLBBMDApplication(config)
    
    # Set up ACL reloading if using separate file
    if acl_path:
        app.setup_acl_reload(acl_path)

    # Set up signal handlers
    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}")
        asyncio.create_task(app.stop())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        await app.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Application error: {e}")
        return 1
    finally:
        await app.stop()

    return 0


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Run async main
    return asyncio.run(async_main(args))


if __name__ == "__main__":
    sys.exit(main())


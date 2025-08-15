#!/usr/bin/env python3
"""
BACnet Device Simulator for Integration Testing

Simulates various BACnet devices that can send different message types
to test ACL rules and BBMD functionality.
"""

import asyncio
import argparse
import logging
import random
from typing import List, Optional
from ipaddress import IPv4Address

from bacpypes3.debugging import ModuleLogger
from bacpypes3.app import Application
from bacpypes3.comm import bind
from bacpypes3.basetypes import PropertyIdentifier
from bacpypes3.pdu import Address, GlobalBroadcast
from bacpypes3.npdu import (
    IAmRequest,
    WhoIsRequest,
    ReadPropertyRequest,
    WritePropertyRequest,
)
from bacpypes3.ipv4.link import IPv4DatagramServer
from bacpypes3.ipv4.service import UDPMultiplexer
from bacpypes3.ipv4.bvll import (
    BVLLCodec,
    RegisterForeignDevice,
    OriginalBroadcastNPDU,
)

# Debugging
_debug = 0
_log = ModuleLogger(globals())

logger = logging.getLogger(__name__)


class SimulatedDevice:
    """Simulates a BACnet device for testing."""

    def __init__(
        self,
        device_id: int,
        device_name: str,
        local_address: str,
        bbmd_address: str,
        behavior: str = "normal",
    ):
        self.device_id = device_id
        self.device_name = device_name
        self.local_address = local_address
        self.bbmd_address = bbmd_address
        self.behavior = behavior
        self.running = True

        # Parse addresses
        self.local_addr = Address(local_address)
        self.bbmd_addr = Address(bbmd_address)

        # Statistics
        self.messages_sent = 0
        self.messages_received = 0

    async def start(self):
        """Start the simulated device."""
        logger.info(
            f"Starting {self.device_name} (ID: {self.device_id}) "
            f"on {self.local_address} -> BBMD: {self.bbmd_address}"
        )

        # Create the network stack
        self.app = Application(self.device_id, self.local_addr)
        self.codec = BVLLCodec()
        self.multiplexer = UDPMultiplexer()
        self.server = IPv4DatagramServer(
            address=(str(self.local_addr.addrAddr), self.local_addr.addrPort)
        )

        # Bind the layers
        bind(self.app, self.codec, self.multiplexer.annexJ)
        bind(self.multiplexer, self.server)

        # Register as foreign device if needed
        if self.behavior != "local":
            await self._register_foreign_device()

        # Start behavior based on device type
        if self.behavior == "discovery":
            asyncio.create_task(self._discovery_behavior())
        elif self.behavior == "monitor":
            asyncio.create_task(self._monitor_behavior())
        elif self.behavior == "controller":
            asyncio.create_task(self._controller_behavior())
        elif self.behavior == "rogue":
            asyncio.create_task(self._rogue_behavior())
        else:
            asyncio.create_task(self._normal_behavior())

    async def stop(self):
        """Stop the simulated device."""
        self.running = False
        if hasattr(self, "server"):
            self.server.close()
        logger.info(f"Stopped {self.device_name}")

    async def _register_foreign_device(self):
        """Register as a foreign device with the BBMD."""
        logger.info(f"{self.device_name}: Registering as foreign device")
        
        # Create registration request
        pdu = RegisterForeignDevice(ttl=300)  # 5 minute TTL
        pdu.pduDestination = self.bbmd_addr
        
        # Send registration
        await self.codec.request(pdu)
        self.messages_sent += 1

    async def _discovery_behavior(self):
        """Device that primarily does discovery (Who-Is/I-Am)."""
        while self.running:
            # Send Who-Is broadcast
            who_is = WhoIsRequest()
            who_is.pduDestination = GlobalBroadcast()
            
            logger.debug(f"{self.device_name}: Sending Who-Is")
            await self.app.request(who_is)
            self.messages_sent += 1

            # Wait for responses and send I-Am
            await asyncio.sleep(2)
            
            # Send I-Am response
            i_am = IAmRequest()
            i_am.iAmDeviceIdentifier = self.device_id
            i_am.pduDestination = GlobalBroadcast()
            
            logger.debug(f"{self.device_name}: Sending I-Am")
            await self.app.request(i_am)
            self.messages_sent += 1

            await asyncio.sleep(random.randint(10, 30))

    async def _monitor_behavior(self):
        """Device that monitors others (reads properties)."""
        target_devices = [100001, 100002, 200001, 200002]  # Example targets
        
        while self.running:
            # Pick a random target
            target = random.choice(target_devices)
            
            # Send read property request
            read_req = ReadPropertyRequest()
            read_req.objectIdentifier = ("device", target)
            read_req.propertyIdentifier = PropertyIdentifier("objectName")
            read_req.pduDestination = Address(f"{target // 100000}.0.0.{target % 100}:47808")
            
            logger.debug(f"{self.device_name}: Reading property from device {target}")
            await self.app.request(read_req)
            self.messages_sent += 1

            await asyncio.sleep(random.randint(5, 15))

    async def _controller_behavior(self):
        """Device that controls others (reads and writes)."""
        while self.running:
            # Alternate between reads and writes
            if random.random() < 0.7:  # 70% reads
                await self._send_read_property()
            else:  # 30% writes
                await self._send_write_property()
            
            await asyncio.sleep(random.randint(3, 10))

    async def _rogue_behavior(self):
        """Malicious device behavior for testing blocking."""
        while self.running:
            # Rapid fire writes (should be blocked)
            for _ in range(5):
                await self._send_write_property()
                await asyncio.sleep(0.1)
            
            # Try to register frequently
            await self._register_foreign_device()
            
            await asyncio.sleep(5)

    async def _normal_behavior(self):
        """Normal mixed device behavior."""
        while self.running:
            action = random.choice([
                self._send_who_is,
                self._send_i_am,
                self._send_read_property,
                self._send_write_property,
            ])
            
            await action()
            await asyncio.sleep(random.randint(10, 30))

    async def _send_who_is(self):
        """Send a Who-Is request."""
        who_is = WhoIsRequest()
        who_is.pduDestination = GlobalBroadcast()
        
        logger.debug(f"{self.device_name}: Sending Who-Is")
        await self.app.request(who_is)
        self.messages_sent += 1

    async def _send_i_am(self):
        """Send an I-Am response."""
        i_am = IAmRequest()
        i_am.iAmDeviceIdentifier = self.device_id
        i_am.pduDestination = GlobalBroadcast()
        
        logger.debug(f"{self.device_name}: Sending I-Am")
        await self.app.request(i_am)
        self.messages_sent += 1

    async def _send_read_property(self):
        """Send a read property request."""
        target = random.randint(100001, 300002)
        
        read_req = ReadPropertyRequest()
        read_req.objectIdentifier = ("device", target)
        read_req.propertyIdentifier = PropertyIdentifier("presentValue")
        read_req.pduDestination = Address(f"10.{target // 100000}.0.{target % 100}:47808")
        
        logger.debug(f"{self.device_name}: Reading from device {target}")
        await self.app.request(read_req)
        self.messages_sent += 1

    async def _send_write_property(self):
        """Send a write property request."""
        target = random.randint(100001, 300002)
        
        write_req = WritePropertyRequest()
        write_req.objectIdentifier = ("device", target)
        write_req.propertyIdentifier = PropertyIdentifier("presentValue")
        write_req.propertyValue = random.randint(0, 100)
        write_req.pduDestination = Address(f"10.{target // 100000}.0.{target % 100}:47808")
        
        logger.debug(f"{self.device_name}: Writing to device {target}")
        await self.app.request(write_req)
        self.messages_sent += 1


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="BACnet Device Simulator")
    parser.add_argument("--device-id", type=int, required=True, help="Device ID")
    parser.add_argument("--device-name", default="SimDevice", help="Device name")
    parser.add_argument("--local-address", required=True, help="Local address (IP:port)")
    parser.add_argument("--bbmd-address", required=True, help="BBMD address (IP:port)")
    parser.add_argument(
        "--behavior",
        choices=["normal", "discovery", "monitor", "controller", "rogue"],
        default="normal",
        help="Device behavior pattern",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    
    # Create and start device
    device = SimulatedDevice(
        device_id=args.device_id,
        device_name=args.device_name,
        local_address=args.local_address,
        bbmd_address=args.bbmd_address,
        behavior=args.behavior,
    )
    
    try:
        await device.start()
        # Keep running
        while device.running:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        await device.stop()
        logger.info(
            f"Device stats - Sent: {device.messages_sent}, "
            f"Received: {device.messages_received}"
        )


if __name__ == "__main__":
    asyncio.run(main())
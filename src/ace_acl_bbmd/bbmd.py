"""
ACL-Enabled BBMD Implementation

This module extends the BACPypes3 BIPBBMD class to add Access Control List
functionality with metrics collection and cut-through forwarding optimization.
"""

import asyncio
from typing import Optional, Dict, Callable
import logging

from bacpypes3.debugging import bacpypes_debugging, ModuleLogger
from bacpypes3.pdu import PDU, Address, LocalBroadcast, IPv4Address
from bacpypes3.ipv4.service import BIPBBMD
from bacpypes3.ipv4.bvll import (
    LPDU,
    ForwardedNPDU,
    OriginalBroadcastNPDU,
    OriginalUnicastNPDU,
    DistributeBroadcastToNetwork,
    RegisterForeignDevice,
    Result,
)
from bacpypes3.npdu import NPDU

from .models.acl import ACLConfig, RuleAction
from .models.metrics import MetricsCollector, MetricsConfig

# Debugging
_debug = 0
_log = ModuleLogger(globals())

# Set up logging
logger = logging.getLogger(__name__)


@bacpypes_debugging
class ACLBBMD(BIPBBMD):
    """
    ACL-enabled BACnet/IP Broadcast Management Device.

    This BBMD implementation adds Access Control List functionality to filter
    packets based on configurable rules, with support for metrics collection
    and cut-through forwarding optimization.
    """

    _debug: Callable[..., None]
    _warning: Callable[..., None]

    def __init__(
        self,
        addr: Optional[IPv4Address] = None,
        acl_config: Optional[ACLConfig] = None,
        metrics_collector: Optional[MetricsCollector] = None,
        config: Optional['BBMDConfig'] = None,
        **kwargs,
    ):
        """
        Initialize ACL-enabled BBMD.

        Args:
            addr: BBMD IP address (or use config.bbmd_address)
            acl_config: ACL configuration (or use config.acl)
            metrics_collector: Optional metrics collector
            config: BBMDConfig object (alternative to individual params)
            **kwargs: Additional arguments for BIPBBMD
        """
        # Handle config object
        if config:
            from .config import BBMDConfig
            if isinstance(config, BBMDConfig):
                addr = addr or config.get_bbmd_address()
                acl_config = acl_config or config.acl
                if config.enable_metrics and not metrics_collector:
                    # Create metrics config from BBMD config
                    metrics_config = MetricsConfig(
                        enable_http_server=config.metrics_http_enabled,
                        http_port=config.metrics_http_port,
                        enable_file_export=config.metrics_file_export_enabled,
                        file_export_path=config.metrics_file_export_path,
                        file_export_interval=config.metrics_file_export_interval,
                    )
                    metrics_collector = MetricsCollector(metrics_config)
        
        if not addr:
            raise ValueError("Either addr or config with bbmd_address must be provided")
        if not acl_config:
            # ACL config is optional - can be loaded separately
            logger.warning("No ACL configuration provided, using default allow-all policy")
            from .models.acl import ACLConfig, RuleAction
            acl_config = ACLConfig(default_action=RuleAction.ALLOW, rules=[])
            
        if _debug:
            ACLBBMD._debug("__init__ %r", addr)

        super().__init__(addr, **kwargs)

        self.acl_config = acl_config
        self.metrics = metrics_collector or MetricsCollector()
        
        # Create ACL engine
        from .acl_engine import ACLEngine
        self.acl_engine = ACLEngine(self.acl_config)

        # Cache for cut-through eligible sources
        self._cut_through_cache: Dict[IPv4Address, bool] = {}
        self._cache_cleanup_handle: Optional[asyncio.Handle] = None
        
        # Track cut-through sources
        self._cut_through_sources: Dict[str, bool] = {}

        # Start cache cleanup task
        self._schedule_cache_cleanup()

    def _schedule_cache_cleanup(self) -> None:
        """Schedule periodic cache cleanup."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No event loop running, skip scheduling
            self._cache_cleanup_handle = None
            return
        self._cache_cleanup_handle = loop.call_later(
            300, self._cleanup_cache
        )  # 5 minutes

    def _cleanup_cache(self) -> None:
        """Clean up cut-through cache."""
        self._cut_through_cache.clear()
        self._schedule_cache_cleanup()

    def _check_acl(
        self,
        source_addr: IPv4Address,
        dest_addr: Optional[IPv4Address],
        message_type: str,
        lpdu: LPDU,
    ) -> tuple[bool, Optional[str]]:
        """
        Check if packet is allowed by ACL rules.

        Returns:
            Tuple of (allowed, rule_name)
        """
        # Get raw NPDU bytes from the LPDU payload
        pdu_data = lpdu.pduData if hasattr(lpdu, 'pduData') and lpdu.pduData else b""

        # Use ACL engine to check packet
        allowed, rule_name, packet_info = self.acl_engine.check_packet(
            pdu_data=pdu_data,
            source=source_addr,
            dest=dest_addr,
            bvll_type=message_type,
        )

        # Record metrics
        self.metrics.record_packet(
            source_addr=source_addr,
            dest_addr=dest_addr,
            message_type=message_type,
            packet_size=len(pdu_data),
            action="allow" if allowed else "deny",
            rule_name=rule_name,
            source_device=packet_info.source_device if packet_info else None,
            dest_device=packet_info.dest_device if packet_info else None,
            cut_through=False,
        )

        # Log if needed
        action = "allow" if allowed else "deny"
        if rule_name == "default" and self.acl_config.log_default:
            logger.info(
                f"ACL default: action={action}, "
                f"src={source_addr}, dst={dest_addr}, type={message_type}"
            )
        elif rule_name != "default":
            # Check if the matched rule has logging enabled
            rule = self.acl_config.find_matching_rule(
                source_addr=source_addr,
                dest_addr=dest_addr,
                message_type=message_type,
                source_device=packet_info.source_device if packet_info else None,
                dest_device=packet_info.dest_device if packet_info else None,
            )
            if rule and (rule.log_matches or rule.action in (RuleAction.LOG, RuleAction.ALLOW_LOG)):
                logger.info(
                    f"ACL match: rule={rule.name}, action={rule.action}, "
                    f"src={source_addr}, dst={dest_addr}, type={message_type}"
                )

        return allowed, rule_name

    def _is_cut_through_eligible(self, source_addr: IPv4Address) -> bool:
        """Check if source is eligible for cut-through forwarding."""
        # Check cache first
        if source_addr in self._cut_through_cache:
            return self._cut_through_cache[source_addr]

        # Check configuration using ACL engine
        eligible = self.acl_engine.get_cut_through_decision(source_addr)

        # Cache result
        self._cut_through_cache[source_addr] = eligible

        return eligible

    async def indication(self, pdu: PDU) -> None:
        """
        Handle outgoing packets from the network layer.

        This method intercepts packets before they are sent to check ACL rules.
        """
        if _debug:
            ACLBBMD._debug("indication %r", pdu)

        # For locally originated packets, we generally allow them
        # ACL primarily controls forwarded/received packets
        await super().indication(pdu)

    async def confirmation(self, lpdu: LPDU) -> None:
        """
        Handle incoming packets from the link layer.

        This method intercepts all incoming packets to apply ACL rules
        before processing or forwarding them.
        """
        if _debug:
            ACLBBMD._debug("confirmation %r", lpdu)

        # Determine message type for ACL checking
        message_type = lpdu.__class__.__name__.lower()

        # Extract source address
        source_addr = lpdu.pduSource
        if not isinstance(source_addr, IPv4Address):
            # Convert if needed
            source_addr = IPv4Address(str(source_addr))

        # Determine destination for ACL check
        dest_addr = None
        if hasattr(lpdu, "pduDestination") and lpdu.pduDestination:
            if isinstance(lpdu.pduDestination, IPv4Address):
                dest_addr = lpdu.pduDestination
            elif hasattr(lpdu.pduDestination, "addrType"):
                if lpdu.pduDestination.addrType == Address.localBroadcastAddr:
                    dest_addr = None  # Broadcast

        # Special handling for forwarded NPDUs
        if isinstance(lpdu, ForwardedNPDU):
            # The real source is in bvlciAddress
            source_addr = lpdu.bvlciAddress
            message_type = "forwarded_npdu"
        elif isinstance(lpdu, DistributeBroadcastToNetwork):
            message_type = "distribute_broadcast"
        elif isinstance(lpdu, OriginalBroadcastNPDU):
            message_type = "original_broadcast"
        elif isinstance(lpdu, OriginalUnicastNPDU):
            message_type = "original_unicast"
        elif isinstance(lpdu, RegisterForeignDevice):
            message_type = "register_foreign_device"

        # Check cut-through eligibility for broadcast/forward operations
        cut_through = False
        if isinstance(lpdu, (OriginalBroadcastNPDU, DistributeBroadcastToNetwork)):
            cut_through = self._is_cut_through_eligible(source_addr)
            if cut_through:
                # For cut-through, forward immediately then process
                logger.debug(f"Cut-through forwarding from {source_addr}")
                self.metrics.record_packet(
                    source_addr=source_addr,
                    dest_addr=None,
                    message_type=message_type,
                    packet_size=len(lpdu.pduData) if hasattr(lpdu, "pduData") else 0,
                    action="allow",
                    rule_name="cut_through",
                    cut_through=True,
                )

                # Forward first (cut-through)
                await self._forward_broadcast(lpdu, source_addr)

                # Then continue processing for metrics
                await super().confirmation(lpdu)
                return

        # Apply ACL check
        allowed, rule_name = self._check_acl(source_addr, dest_addr, message_type, lpdu)

        if not allowed:
            logger.info(
                f"Packet blocked by ACL: {rule_name}, src={source_addr}, type={message_type}"
            )

            # Send appropriate error response if needed
            if isinstance(lpdu, RegisterForeignDevice):
                # Send registration denied
                xpdu = Result(
                    code=0x0030, destination=lpdu.pduSource, user_data=lpdu.pduUserData
                )
                await self.request(xpdu)

            return

        # Packet allowed, continue normal processing
        await super().confirmation(lpdu)

    async def _forward_broadcast(self, lpdu: LPDU, source_addr: IPv4Address) -> None:
        """
        Forward broadcast packet to peers and foreign devices.

        This is used for cut-through forwarding.
        """
        if isinstance(lpdu, OriginalBroadcastNPDU):
            # Make a forwarded PDU
            xpdu = ForwardedNPDU(source_addr, lpdu.pduData, user_data=lpdu.pduUserData)

            # Send to peers
            for bdte in self.bbmdBDT:
                if bdte != self.bbmdAddress:
                    xpdu.pduDestination = IPv4Address(bdte.addrBroadcastTuple)
                    await self.request(xpdu)
                    self.metrics.record_bbmd_forward(
                        str(bdte), "forwarded_broadcast", len(lpdu.pduData), "out"
                    )

            # Send to foreign devices
            for fdte in self.bbmdFDT:
                xpdu.pduDestination = fdte.fdAddress
                await self.request(xpdu)

        elif isinstance(lpdu, DistributeBroadcastToNetwork):
            # Build a forwarded NPDU
            xpdu = ForwardedNPDU(source_addr, lpdu.pduData, user_data=lpdu.pduUserData)

            # Send to peers
            for bdte in self.bbmdBDT:
                if bdte == self.bbmdAddress:
                    xpdu.pduDestination = LocalBroadcast()
                    await self.request(xpdu)
                else:
                    xpdu.pduDestination = IPv4Address(bdte.addrBroadcastTuple)
                    await self.request(xpdu)
                    self.metrics.record_bbmd_forward(
                        str(bdte), "distribute_broadcast", len(lpdu.pduData), "out"
                    )

            # Send to other foreign devices
            for fdte in self.bbmdFDT:
                if fdte.fdAddress != source_addr:
                    xpdu.pduDestination = fdte.fdAddress
                    await self.request(xpdu)
    
    def update_acl_config(self, new_config: ACLConfig) -> None:
        """
        Update ACL configuration at runtime.
        
        Args:
            new_config: New ACL configuration
        """
        self.acl_config = new_config
        self.acl_engine.update_config(new_config)
        
        # Clear cut-through cache as networks may have changed
        self._cut_through_cache.clear()
        
        logger.info("BBMD ACL configuration updated")


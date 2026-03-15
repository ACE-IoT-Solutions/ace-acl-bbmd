"""
ACL-enhanced BBMD Link Layer

Replaces bacpypes3's BBMDLinkLayer with one that uses ACLBBMD instead of
plain BIPBBMD, providing the same codec/multiplexer/server mini-stack but
with ACL filtering on the BVLL layer.
"""

from __future__ import annotations

from typing import Optional

from bacpypes3.debugging import bacpypes_debugging, ModuleLogger
from bacpypes3.comm import bind
from bacpypes3.pdu import IPv4Address
from bacpypes3.ipv4 import IPv4DatagramServer
from bacpypes3.ipv4.bvll import BVLLCodec
from bacpypes3.ipv4.service import UDPMultiplexer

from .bbmd import ACLBBMD
from .models.acl import ACLConfig
from .models.metrics import MetricsCollector

_debug = 0
_log = ModuleLogger(globals())


@bacpypes_debugging
class ACLBBMDLinkLayer(ACLBBMD):
    """
    Link layer mini-stack: ACLBBMD → BVLLCodec → UDPMultiplexer → IPv4DatagramServer.

    Drop-in replacement for bacpypes3's BBMDLinkLayer that adds ACL filtering.
    The Application binds to this via the NetworkServiceAccessPoint.
    """

    codec: BVLLCodec
    multiplexer: UDPMultiplexer
    server: IPv4DatagramServer

    def __init__(
        self,
        local_address: IPv4Address,
        acl_config: Optional[ACLConfig] = None,
        metrics_collector: Optional[MetricsCollector] = None,
        **kwargs,
    ) -> None:
        if _debug:
            ACLBBMDLinkLayer._debug("__init__ %r", local_address)

        ACLBBMD.__init__(
            self,
            addr=local_address,
            acl_config=acl_config,
            metrics_collector=metrics_collector,
            **kwargs,
        )

        self.codec = BVLLCodec()
        self.multiplexer = UDPMultiplexer()
        self.server = IPv4DatagramServer(local_address)

        bind(self, self.codec, self.multiplexer.annexJ)
        bind(self.multiplexer, self.server)

    def close(self):
        if _debug:
            ACLBBMDLinkLayer._debug("close")
        self.server.close()

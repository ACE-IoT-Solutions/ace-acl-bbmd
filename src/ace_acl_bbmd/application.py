"""
ACL BBMD Application

Subclasses bacpypes3's Application to use ACLBBMDLinkLayer instead of the
stock BBMDLinkLayer, so the device responds to all required BACnet services
(Who-Is, ReadProperty, etc.) while also performing ACL-filtered BBMD
forwarding.
"""

from __future__ import annotations

import logging
from typing import Optional, List

from bacpypes3.debugging import bacpypes_debugging, ModuleLogger
from bacpypes3.app import Application
from bacpypes3.basetypes import IPMode, NetworkType, ProtocolLevel, BDTEntry
from bacpypes3.local.networkport import NetworkPortObject
from bacpypes3.object import DeviceObject, Object
from bacpypes3.local.device import DeviceObject as LocalDeviceObject
from bacpypes3.primitivedata import ObjectIdentifier

from .link import ACLBBMDLinkLayer
from .models.acl import ACLConfig
from .models.metrics import MetricsCollector, MetricsConfig

_debug = 0
_log = ModuleLogger(globals())
logger = logging.getLogger(__name__)


@bacpypes_debugging
class ACLBBMDApplication(Application):
    """
    Full BACnet Application with ACL-enhanced BBMD link layer.

    Inherits all standard device services from Application:
      - Who-Is / I-Am
      - Who-Has / I-Have
      - ReadProperty / WriteProperty
      - ReadPropertyMultiple / WritePropertyMultiple
      - ReadRange
      - Change of Value (COV)

    Overrides the BBMD link layer to use ACLBBMDLinkLayer for packet filtering.
    """

    _debug_contents = ("acl_config", "bbmd_link_layer")

    acl_config: Optional[ACLConfig]
    metrics_collector: Optional[MetricsCollector]
    bbmd_link_layer: Optional[ACLBBMDLinkLayer]

    def __init__(
        self,
        acl_config: Optional[ACLConfig] = None,
        metrics_collector: Optional[MetricsCollector] = None,
        **kwargs,
    ):
        if _debug:
            ACLBBMDApplication._debug("__init__")

        super().__init__(**kwargs)

        self.acl_config = acl_config
        self.metrics_collector = metrics_collector
        self.bbmd_link_layer = None

    @classmethod
    def from_object_list(
        cls,
        objects: List[Object],
        acl_config: Optional[ACLConfig] = None,
        metrics_collector: Optional[MetricsCollector] = None,
        **kwargs,
    ) -> ACLBBMDApplication:
        """
        Build an ACLBBMDApplication from a list of BACnet objects.

        Same as Application.from_object_list() but stores ACL config
        so it is available when the BBMD link layer is created.
        """
        if _debug:
            ACLBBMDApplication._debug("from_object_list %r", objects)

        from bacpypes3.appservice import ApplicationServiceAccessPoint
        from bacpypes3.netservice import (
            NetworkServiceAccessPoint,
            NetworkServiceElement,
            RouterInfoCache,
        )
        from bacpypes3.comm import bind

        # find device object
        device_object = None
        for obj in objects:
            if isinstance(obj, DeviceObject):
                if device_object is not None:
                    raise RuntimeError("duplicate device object")
                device_object = obj
        if device_object is None:
            raise RuntimeError("missing device object")

        device_info_cache = kwargs.pop("device_info_cache", None)
        router_info_cache = kwargs.pop("router_info_cache", None)
        ase_id = kwargs.pop("aseID", None)

        app = cls(
            acl_config=acl_config,
            metrics_collector=metrics_collector,
            device_info_cache=device_info_cache,
            aseID=ase_id,
        )

        app.asap = ApplicationServiceAccessPoint(
            device_object, app.device_info_cache
        )
        app.nsap = NetworkServiceAccessPoint(router_info_cache=router_info_cache)
        app.nse = NetworkServiceElement()
        bind(app.nse, app.nsap)
        bind(app, app.asap, app.nsap)

        for obj in objects:
            app.add_object(obj)

        return app

    def add_object(self, obj):
        """
        Add an object to the application.

        Overrides Application.add_object() to intercept NetworkPortObject
        in BBMD mode and use ACLBBMDLinkLayer instead of the stock BBMDLinkLayer.
        """
        if _debug:
            ACLBBMDApplication._debug("add_object %r", obj)

        # For non-NetworkPort objects or non-BBMD modes, use the base class.
        # We only intercept BBMD-mode IPv4 network ports.
        if not isinstance(obj, NetworkPortObject):
            return super().add_object(obj)

        if (
            getattr(obj, "protocolLevel", None) != ProtocolLevel.bacnetApplication
            or getattr(obj, "networkType", None) != NetworkType.ipv4
            or getattr(obj, "bacnetIPMode", None) != IPMode.bbmd
        ):
            return super().add_object(obj)

        # --- BBMD-mode IPv4 NetworkPort: use our ACL link layer ---

        # Register the object in name/identifier dicts (same as base class)
        object_name = obj.objectName
        if not object_name:
            raise RuntimeError("object name required")
        object_identifier = obj.objectIdentifier
        if not object_identifier:
            raise RuntimeError("object identifier required")
        if object_name in self.objectName:
            raise RuntimeError(f"already an object with name {object_name!r}")
        if object_identifier in self.objectIdentifier:
            raise RuntimeError(
                f"already an object with identifier {object_identifier!r}"
            )
        self.objectName[object_name] = obj
        self.objectIdentifier[object_identifier] = obj
        obj._app = self

        # Create our ACL-enhanced link layer
        link_address = obj.address
        if _debug:
            ACLBBMDApplication._debug("    - link_address: %r", link_address)

        link_layer = ACLBBMDLinkLayer(
            local_address=link_address,
            acl_config=self.acl_config,
            metrics_collector=self.metrics_collector,
        )

        # Add BDT peers
        for bdt_entry in getattr(obj, "bbmdBroadcastDistributionTable", []):
            if _debug:
                ACLBBMDApplication._debug("    - bdt_entry: %r", bdt_entry)
            link_layer.add_peer(bdt_entry.address)

        self.link_layers[obj.objectIdentifier] = link_layer
        self.bbmd_link_layer = link_layer

        # Bind to NSAP
        if obj.networkNumber == 0:
            self.nsap.bind(link_layer, address=link_address)
        else:
            self.nsap.bind(
                link_layer, net=obj.networkNumber, address=link_address
            )

        logger.info(
            "ACL BBMD link layer bound on %s with %d ACL rules",
            link_address,
            len(self.acl_config.rules) if self.acl_config else 0,
        )

    def update_acl_config(self, new_config: ACLConfig) -> None:
        """Update ACL configuration at runtime."""
        self.acl_config = new_config
        if self.bbmd_link_layer:
            self.bbmd_link_layer.update_acl_config(new_config)
        logger.info("ACL configuration updated")

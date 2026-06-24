"""SCCM extension model registry.

Each module here defines `BaseAsset` subclasses the convert phase uses to produce
OpenGraph nodes/edges. Models are imported here so the convert pipeline can resolve
them by name and so callers can do `from openhound_sccm.models import ComputerNode`.
"""
from .computer import ComputerNode
from .group import GroupNode
from .graph_edge import GraphEdge
from .sccm_admin_user import SCCMAdminUser
from .sccm_client_device import SCCMClientDevice
from .sccm_collection import SCCMCollection
from .sccm_security_role import SCCMSecurityRole
from .sccm_site import SCCMSite
from .stub_node import StubNode
from .user import UserNode

__all__ = ["ComputerNode", "GraphEdge", "GroupNode", "SCCMAdminUser", "SCCMClientDevice", "SCCMCollection", "SCCMSecurityRole", "SCCMSite", "StubNode", "UserNode"]

"""SCCM extension model registry.

Each module here defines `BaseAsset` subclasses the convert phase uses to produce
OpenGraph nodes/edges. Models are imported here so the convert pipeline can resolve
them by name and so callers can do `from openhound_sccm.models import ComputerNode`.
"""
from .computer import ComputerNode
from .group import GroupNode
from .replication_edge import ReplicationEdge
from .sccm_site import SCCMSite
from .user import UserNode

__all__ = ["ComputerNode", "GroupNode", "ReplicationEdge", "SCCMSite", "UserNode"]

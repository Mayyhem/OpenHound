"""SCCM extension model registry.

Each module here defines one or more `BaseAsset` subclasses that the OpenHound
convert phase invokes to produce OpenGraph nodes/edges. Models are imported
here so `@app.asset` decorators register with the app on package import.

Phase 4 added the 11 derived edge models under ``models/derived/``. The actual
edge fan-out is performed by the single ``DerivedEdges`` aggregator
(``models/derived/aggregator.py``); the other 10 are schema-only placeholders
that register their edge kinds with ``app.assets`` for documentation.
"""

from .computer import Computer
from .group import Group
from .group_membership import GroupMembership
from .mssql_database import MSSQLDatabase
from .mssql_database_role import MSSQLDatabaseRole
from .mssql_database_user import MSSQLDatabaseUser
from .mssql_login import MSSQLLogin
from .mssql_server import MSSQLServer
from .mssql_server_role import MSSQLServerRole
from .sccm_admin_user import SCCMAdminUser
from .sccm_client_device import SCCMClientDevice
from .sccm_collection import SCCMCollection
from .sccm_security_role import SCCMSecurityRole
from .sccm_site import SCCMSite
from .user import User

# Derived edge models (Phase 4).
from .derived.admins_replicated_to import AdminsReplicatedToEdge
from .derived.aggregator import DerivedEdges
from .derived.all_permissions import AllPermissionsEdge
from .derived.assign_all_permissions import AssignAllPermissionsEdge
from .derived.coerce_and_relay import CoerceAndRelayEdge
from .derived.contains import ContainsEdge
from .derived.derived_node import DerivedNode
from .derived.local_admin_required import LocalAdminRequiredEdge
from .derived.mssql_gettgs import MSSQLGetTGSEdge
from .derived.mssql_sysadmin import MSSQLSysadminEdge
from .derived.role_assignment import RoleAssignmentEdge
from .derived.same_host_as import SameHostAsEdge
from .derived.secret_policy import SecretPolicyEdge

__all__ = [
    # Base node models.
    "Computer",
    "Group",
    "GroupMembership",
    "MSSQLDatabase",
    "MSSQLDatabaseRole",
    "MSSQLDatabaseUser",
    "MSSQLLogin",
    "MSSQLServer",
    "MSSQLServerRole",
    "SCCMAdminUser",
    "SCCMClientDevice",
    "SCCMCollection",
    "SCCMSecurityRole",
    "SCCMSite",
    "User",
    # Phase 4 derived edge models.
    "AdminsReplicatedToEdge",
    "DerivedEdges",
    "DerivedNode",
    "AllPermissionsEdge",
    "AssignAllPermissionsEdge",
    "CoerceAndRelayEdge",
    "ContainsEdge",
    "LocalAdminRequiredEdge",
    "MSSQLGetTGSEdge",
    "MSSQLSysadminEdge",
    "RoleAssignmentEdge",
    "SameHostAsEdge",
    "SecretPolicyEdge",
]

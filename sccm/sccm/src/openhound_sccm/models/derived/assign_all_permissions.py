"""SCCM_AssignAllPermissions derived-edge schema placeholder.

SMS Provider computer -> every primary site in its hierarchy. Materialised in
``sccm.assign_all_permissions_edges``; emitter is ``aggregator.py``.
"""

from __future__ import annotations

from openhound.core.asset import EdgeDef

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk

from ._placeholder import register_placeholder

SCCMAssignAllPermissionsEdge = register_placeholder(
    name="SCCMAssignAllPermissionsEdge",
    description="Schema-only placeholder for SCCM_AssignAllPermissions; emitter in aggregator.py.",
    edges=[
        EdgeDef(kind=ek.SCCM_ASSIGN_ALL_PERMISSIONS, start=nk.COMPUTER, end=nk.SCCM_SITE,
                description="SMS Provider host -> primary sites in hierarchy."),
    ],
)

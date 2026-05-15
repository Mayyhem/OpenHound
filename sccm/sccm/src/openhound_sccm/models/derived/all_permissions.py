"""SCCM_AllPermissions derived-edge schema placeholder.

A Full Administrator with both ``All Systems`` and ``All Users and User Groups``
collections in scope gets ``SCCM_AllPermissions`` to every site in the hierarchy.
Materialised in ``sccm.all_permissions_edges``; emitter is ``aggregator.py``.
"""

from __future__ import annotations

from openhound.core.asset import EdgeDef

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk

from ._placeholder import register_placeholder

SCCMAllPermissionsEdge = register_placeholder(
    name="SCCMAllPermissionsEdge",
    description="Schema-only placeholder for SCCM_AllPermissions; emitter in aggregator.py.",
    edges=[
        EdgeDef(kind=ek.SCCM_ALL_PERMISSIONS, start=nk.SCCM_ADMIN_USER, end=nk.SCCM_SITE,
                description="Full admin with universal scope -> every site in hierarchy."),
    ],
)

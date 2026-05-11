"""Role-assignment derived-edge schema placeholder.

Three edge kinds dispatched from a single SQL row in
``sccm.role_assignment_edges``:

  * ``SCCM_FullAdministrator``       — role_id = SMS0001R
  * ``SCCM_ApplicationAdministrator`` — role_id = SMS0009R
  * ``SCCM_AssignSpecificPermissions`` — any other unmapped role
  * (plus the rare custom-role kinds from ROLE_EDGE_MAP, when present)

The actual emitter is ``models/derived/aggregator.py::DerivedEdges``.
"""

from __future__ import annotations

from openhound.core.asset import EdgeDef

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk

from ._placeholder import register_placeholder

RoleAssignmentEdge = register_placeholder(
    name="RoleAssignmentEdge",
    description="Schema-only placeholder for SCCM role-assignment edges; emitter in aggregator.py.",
    edges=[
        EdgeDef(kind=ek.SCCM_FULL_ADMINISTRATOR, start=nk.SCCM_ADMIN_USER, end=nk.SCCM_CLIENT_DEVICE,
                description="Full Administrator (SMS0001R) on a collection -> every device in scope."),
        EdgeDef(kind=ek.SCCM_APPLICATION_ADMINISTRATOR, start=nk.SCCM_ADMIN_USER, end=nk.SCCM_CLIENT_DEVICE,
                description="Application Administrator (SMS0009R) -> every device in scope."),
        EdgeDef(kind=ek.SCCM_ASSIGN_SPECIFIC_PERMISSIONS, start=nk.SCCM_ADMIN_USER, end=nk.SCCM_CLIENT_DEVICE,
                description="Catch-all custom role -> device."),
    ],
)

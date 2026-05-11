"""SCCM_Contains derived-edge schema placeholder.

The actual emitter is ``models/derived/aggregator.py::DerivedEdges``, which
reads ``sccm.contains_edges`` (one row per (site, global object) pair, where
``global object`` is an SCCM_Collection / SCCM_AdminUser / SCCM_SecurityRole
that lives at the hierarchy root).
"""

from __future__ import annotations

from openhound.core.asset import EdgeDef

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk

from ._placeholder import register_placeholder

ContainsEdge = register_placeholder(
    name="ContainsEdge",
    description="Schema-only placeholder for SCCM_Contains; fan-out lives in aggregator.py.",
    edges=[
        EdgeDef(kind=ek.SCCM_CONTAINS, start=nk.SCCM_SITE, end=nk.SCCM_COLLECTION,
                description="Site contains a global Collection in its hierarchy."),
        EdgeDef(kind=ek.SCCM_CONTAINS, start=nk.SCCM_SITE, end=nk.SCCM_ADMIN_USER,
                description="Site contains a global AdminUser in its hierarchy."),
        EdgeDef(kind=ek.SCCM_CONTAINS, start=nk.SCCM_SITE, end=nk.SCCM_SECURITY_ROLE,
                description="Site contains a global SecurityRole in its hierarchy."),
    ],
)

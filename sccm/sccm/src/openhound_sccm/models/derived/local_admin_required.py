"""LocalAdminRequired derived-edge schema placeholder.

For each site, the SMS Site Server -> every co-located site system. Resolved
via ``adminservice_site_systems`` joined to ``ldap_computers`` for the SID.
Emitter: ``aggregator.py``.
"""

from __future__ import annotations

from openhound.core.asset import EdgeDef

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk

from ._placeholder import register_placeholder

LocalAdminRequiredEdge = register_placeholder(
    name="LocalAdminRequiredEdge",
    description="Schema-only placeholder for LocalAdminRequired; emitter in aggregator.py.",
    edges=[
        EdgeDef(kind=ek.LOCAL_ADMIN_REQUIRED, start=nk.COMPUTER, end=nk.COMPUTER,
                description="Site server -> co-located site systems."),
    ],
)

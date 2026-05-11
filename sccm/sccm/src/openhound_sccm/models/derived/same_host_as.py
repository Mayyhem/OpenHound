"""SameHostAs derived-edge schema placeholder.

Bidirectional SCCM_ClientDevice <-> Computer edge for a single host. Match is
SID-based (``ad_object_sid``) with hostname fallback. Materialised in
``sccm.same_host_as_edges``; emitter is ``aggregator.py``.
"""

from __future__ import annotations

from openhound.core.asset import EdgeDef

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk

from ._placeholder import register_placeholder

SameHostAsEdge = register_placeholder(
    name="SameHostAsEdge",
    description="Schema-only placeholder for SameHostAs; emitter in aggregator.py.",
    edges=[
        EdgeDef(kind=ek.SAME_HOST_AS, start=nk.SCCM_CLIENT_DEVICE, end=nk.COMPUTER,
                description="ClientDevice -> Computer co-location."),
        EdgeDef(kind=ek.SAME_HOST_AS, start=nk.COMPUTER, end=nk.SCCM_CLIENT_DEVICE,
                description="Computer -> ClientDevice co-location."),
    ],
)

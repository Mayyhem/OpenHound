"""SCCM_AdminsReplicatedTo derived edge — schema-only placeholder.

The actual edge fan-out is performed by ``models/derived/aggregator.py::DerivedEdges``,
which reads the materialised ``sccm.admins_replicated_to_edges`` view.

This class exists so the edge kind is registered with ``app.assets`` for OpenHound's
automated documentation (and so the historic ``len(app.assets)`` count stays stable).
It is not bound to a DLT resource and therefore does not fire at convert time.
"""

from __future__ import annotations

from typing import ClassVar

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef
from pydantic import ConfigDict

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk
from openhound_sccm.main import app


@app.asset(
    description="Schema-only placeholder. See aggregator.py for the actual emitter.",
    edges=[
        EdgeDef(
            kind=ek.SCCM_ADMINS_REPLICATED_TO,
            start=nk.SCCM_SITE,
            end=nk.SCCM_SITE,
            description="Site A's admins are replicated to site B (CAS<->Primary or Primary->Secondary).",
        ),
    ],
)
class AdminsReplicatedToEdge(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # No fields. This class is never instantiated at convert time because no DLT
    # resource is bound to it. The edge fan-out is in aggregator.py.

    @property
    def as_node(self):
        return None

    @property
    def edges(self):
        return iter(())

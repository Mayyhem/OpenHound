"""SCCM_Site node model.

Reads from the ``ldap_sites`` DLT table. Yields one SCCM_Site node per
mSSMSSite object discovered in the System Management container.

Unlike Computer/User/Group, ``SCCM_Site`` is a platform-specific kind — it is
*not* an AD principal — so the kind list is just ``[SCCM_Site]`` (no ``Base``).

The node id is the site code itself (e.g. ``CAS``, ``PS1``). Phase 1 does no
ID rewriting; later phases will rewrite Collection / AdminUser / SecurityRole
ids to root-scoped values via the hierarchies table, but Site itself is
stable across the hierarchy.

Edges emitted from this model are limited to relationships derived from a
single site's own attributes (none in Phase 1 — the hierarchy-driven
``SCCM_AdminsReplicatedTo`` edges live in
``models/derived/admins_replicated_to.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar, Optional

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, NodeDef
from pydantic import ConfigDict

from openhound_sccm.graph import SCCMNode, SCCMNodeProperties
from openhound_sccm.kinds import nodes as nk
from openhound_sccm.main import app


@dataclass
class SCCMSiteProperties(SCCMNodeProperties):
    """Properties carried on every SCCM_Site node.

    ``siteCode``, ``parentSiteCode`` and ``siteType`` are inherited from
    ``SCCMNodeProperties`` and are not redeclared here. We only add the
    site-specific fields (``siteGuid``, ``sourceForest``) and the ``Type``
    marker that mirrors ConfigManBearPig's output.
    """

    siteGuid: Optional[str] = field(default=None, metadata={"description": "Site GUID parsed from mSSMSHealthState"})
    sourceForest: Optional[str] = field(default=None, metadata={"description": "Source forest reported by mSSMSSourceForest"})
    Type: str = field(default="SCCM_Site", metadata={"description": "Marker matching CMBP property"})


@app.asset(
    description="SCCM Site node",
    node=NodeDef(
        kind=nk.SCCM_SITE,
        description="SCCM site discovered via the System Management container in AD",
        icon="server",
        properties=SCCMSiteProperties,
    ),
    edges=[],
)
class SCCMSite(BaseAsset):
    """SCCMSite asset — one row per mSSMSSite from ``ldap_sites``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # Raw fields from ldap_sites JSONL
    site_code: str
    site_guid: Optional[str] = None
    distinguished_name: Optional[str] = None
    source_forest: Optional[str] = None
    site_type: Optional[str] = None
    parent_site_code: Optional[str] = None

    @property
    def as_node(self) -> SCCMNode:
        return SCCMNode(
            kinds=[nk.SCCM_SITE],
            properties=SCCMSiteProperties(
                node_id=self.site_code,
                name=self.site_code,
                displayname=self.site_code,
                environmentid=self.site_code,
                siteCode=self.site_code,
                parentSiteCode=self.parent_site_code,
                siteType=self.site_type,
                siteGuid=self.site_guid,
                sourceForest=self.source_forest,
                Type="SCCM_Site",
                distinguishedName=self.distinguished_name,
            ),
        )

    @property
    def edges(self):
        # Site-only edges (none right now; SCCM_AdminsReplicatedTo lives in
        # models/derived/admins_replicated_to.py and reads the materialised
        # sccm.admins_replicated_to_edges view from transforms.py).
        return iter(())

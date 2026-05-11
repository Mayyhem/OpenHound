"""SCCM_Collection node model.

Reads from the ``adminservice_collections`` DLT table (one row per
``SMS_Collection`` entry returned by the AdminService REST API on each SMS
Provider). Yields one ``SCCM_Collection`` node per row.

Like ``SCCMAdminUser``, the node id includes the *root* site code so that
collections are not duplicated across CAS / Primary / Secondary boundaries.
The hierarchy lookup happens via ``self._lookup.hierarchy_root`` (see
Risk 1 in the master plan).
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
class SCCMCollectionProperties(SCCMNodeProperties):
    """Properties carried on every SCCM_Collection node."""

    collectionID: Optional[str] = field(default=None, metadata={"description": "CollectionID from SMS_Collection"})
    collectionType: Optional[int] = field(default=None, metadata={"description": "1=user collection, 2=device collection"})
    memberCount: Optional[int] = field(default=None, metadata={"description": "Reported MemberCount"})
    limitToCollectionID: Optional[str] = field(default=None, metadata={"description": "LimitToCollectionID parent collection"})
    SCCMInfra: Optional[bool] = field(default=True, metadata={"description": "Marker that this is SCCM infrastructure"})
    Type: str = field(default="SCCM_Collection", metadata={"description": "Marker matching CMBP property"})
    domain: Optional[str] = field(default=None, metadata={"description": "AD domain"})


@app.asset(
    description="SCCM collection node",
    node=NodeDef(
        kind=nk.SCCM_COLLECTION,
        description="SCCM collection discovered via the AdminService SMS_Collection endpoint",
        icon="folder",
        properties=SCCMCollectionProperties,
    ),
    edges=[],
)
class SCCMCollection(BaseAsset):
    """SCCM_Collection asset - one row per SMS_Collection entry from ``adminservice_collections``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    collection_id: str
    site_code: str
    name: Optional[str] = None
    collection_type: Optional[int] = None
    member_count: Optional[int] = None
    limiting_collection_id: Optional[str] = None
    domain: Optional[str] = None
    source: Optional[str] = "AdminService-SMS_Collection"

    @property
    def as_node(self) -> SCCMNode:
        lookup = getattr(self, "_lookup", None)
        root_site_code = (
            lookup.hierarchy_root(self.site_code) if lookup and self.site_code else self.site_code
        ) or self.site_code or ""

        node_id = f"{self.collection_id}@{root_site_code}"
        display = f"{self.name}@{root_site_code}" if self.name else node_id

        return SCCMNode(
            kinds=[nk.SCCM_COLLECTION],
            properties=SCCMCollectionProperties(
                node_id=node_id,
                name=display,
                displayname=display,
                environmentid=self.domain or "",
                collectionID=self.collection_id,
                collectionType=self.collection_type,
                memberCount=self.member_count,
                limitToCollectionID=self.limiting_collection_id,
                siteCode=self.site_code,
                rootSiteCode=root_site_code,
                SCCMInfra=True,
                collectionSource=[self.source] if self.source else None,
                Type="SCCM_Collection",
            ),
        )

    @property
    def edges(self):
        # SCCM_HasMember (collection -> client device) lives in
        # models/derived/* and is computed by SQL views in Phase 4.
        return iter(())

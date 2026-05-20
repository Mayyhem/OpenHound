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
    """Properties carried on every SCCM_Collection node.

    Attributes:
        collectionID: CollectionID from SMS_Collection.
        collectionType: 1 = user collection, 2 = device collection.
        memberCount: Reported MemberCount.
        limitToCollectionID: LimitToCollectionID parent collection.
        SCCMInfra: Marker that this is SCCM infrastructure (always True).
        Type: Marker matching CMBP property (always "SCCM_Collection").
        domain: AD domain.
    """

    collectionID: Optional[str] = field(default=None, metadata={"description": "CollectionID from SMS_Collection"})
    collectionType: Optional[int] = field(default=None, metadata={"description": "1=user collection, 2=device collection"})
    memberCount: Optional[int] = field(default=None, metadata={"description": "Reported MemberCount"})
    limitToCollectionID: Optional[str] = field(default=None, metadata={"description": "LimitToCollectionID parent collection"})
    limitToCollectionName: Optional[str] = field(default=None, metadata={"description": "Display name of the limit-to collection"})
    members: Optional[list[str]] = field(default=None, metadata={"description": "List of GUID:<smsGuid> member device ids (PS1 form)"})
    comment: Optional[str] = field(default=None, metadata={"description": "Free-text description of the collection (SMS_Collection.Comment)"})
    isBuiltIn: Optional[bool] = field(default=None, metadata={"description": "Built-in default collection (All Systems, etc.)"})
    lastChangeTime: Optional[str] = field(default=None, metadata={"description": "Last time the collection definition changed"})
    lastMemberChangeTime: Optional[str] = field(default=None, metadata={"description": "Last time membership changed"})
    collectionVariablesCount: Optional[int] = field(default=None, metadata={"description": "Number of collection-level variables defined"})
    sourceSiteCode: Optional[str] = field(default=None, metadata={"description": "Site code that surfaced this collection"})
    SCCMInfra: Optional[bool] = field(default=True, metadata={"description": "Marker that this is SCCM infrastructure"})
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
    comment: Optional[str] = None
    is_built_in: Optional[bool] = None
    last_change_time: Optional[str] = None
    last_member_change_time: Optional[str] = None
    collection_variables_count: Optional[int] = None
    domain: Optional[str] = None
    source: Optional[str] = "AdminService-SMS_Collection"

    @property
    def as_node(self) -> SCCMNode:
        from ..log_context import trace_node
        # PS1 polls every SMS Provider in the hierarchy (one per primary
        # site) and tags each collection with that provider's site code.
        # The same collection therefore shows up as <id>@CAS *and* <id>@PS1
        # — two distinct nodes. Using the raw site_code in the node id
        # preserves that split. ``rootSiteCode`` below still resolves to
        # the hierarchy root so cross-site queries can pivot on it.
        site_for_id = self.site_code or ""
        trace_node("SCCM_Collection", f"{self.collection_id}@{site_for_id}", self.name)
        root_site_code = (
            self._lookup.hierarchy_root(self.site_code) if self.site_code else None
        ) or self.site_code or ""

        node_id = f"{self.collection_id}@{site_for_id}"
        # PS1 emits ``name`` = bare collection name (no @site suffix). Match
        # so BloodHound queries against ``c.name = 'All Systems'`` work.
        display = self.name or node_id

        # ``limitToCollectionName`` — display name of the limit-to
        # parent. PS1 derives it by looking up the parent's
        # ``CollectionID`` in the ``SMS_Collection`` list. We do the
        # same via a per-collection ``adminservice_collections`` join.
        limit_to_name: Optional[str] = None
        if self.limiting_collection_id:
            try:
                client = self._lookup.client
                schema = self._lookup.schema
                row = client.execute(
                    f"SELECT DISTINCT name "
                    f"FROM {schema}.adminservice_collections "
                    f"WHERE collection_id = ? AND name IS NOT NULL AND name <> '' "
                    f"LIMIT 1",
                    [self.limiting_collection_id],
                ).fetchone()
                if row:
                    limit_to_name = row[0] or None
            except Exception:
                pass

        # ``members`` — PS1 emits the list of GUID:<smsGuid> device ids
        # that are members of this collection. Pull them from
        # ``adminservice_collection_members``. Different SMS Providers
        # return different shapes for the same collection — CAS-side
        # rows sometimes carry placeholder strings ("Provisioning Device"
        # etc.) instead of real GUIDs, while PS1-side rows carry the
        # canonical UUID. To get a clean per-collection member set,
        # query across *all* site_codes for this collection_id and keep
        # only entries shaped like a UUID (``XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX``).
        members: Optional[list[str]] = None
        try:
            client = self._lookup.client
            schema = self._lookup.schema
            rows = client.execute(
                f"SELECT DISTINCT guid "
                f"FROM {schema}.adminservice_collection_members "
                f"WHERE collection_id = ? "
                f"  AND guid IS NOT NULL AND guid <> '' "
                f"  AND length(guid) = 36 "  # UUID with dashes
                f"  AND guid LIKE '________-____-____-____-____________' "
                f"ORDER BY guid",
                [self.collection_id],
            ).fetchall()
            if rows:
                members = [f"GUID:{g}" for (g,) in rows]
        except Exception:
            pass

        return SCCMNode(
            kinds=[nk.SCCM_COLLECTION],
            properties=SCCMCollectionProperties(
                node_id=node_id,
                name=display,
                displayname=display,
                environmentid=self.domain or None,
                collectionID=self.collection_id,
                collectionType=self.collection_type,
                memberCount=self.member_count,
                limitToCollectionID=self.limiting_collection_id,
                limitToCollectionName=limit_to_name,
                members=members,
                comment=self.comment or None,
                isBuiltIn=self.is_built_in,
                lastChangeTime=self.last_change_time or None,
                lastMemberChangeTime=self.last_member_change_time or None,
                collectionVariablesCount=self.collection_variables_count,
                sourceSiteCode=self.site_code,
                siteCode=self.site_code,
                rootSiteCode=root_site_code,
                SCCMInfra=True,
                collectionSource=[self.source] if self.source else None,
            ),
        )

    @property
    def edges(self):
        # SCCM_HasMember (collection -> client device) lives in
        # models/derived/* and is computed by SQL views in Phase 4.
        return iter(())

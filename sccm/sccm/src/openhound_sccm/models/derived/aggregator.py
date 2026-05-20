"""Single derived-edges aggregator.

The 11 derived edge SQL views materialised by ``transforms.py`` are read
back into the converter via this *one* model. We use the "single trigger
row" pattern documented in ``models/derived/admins_replicated_to.py``:

  * A new ``derived_edges`` DLT resource yields exactly ONE trigger row at
    collect time.
  * That row instantiates this ``DerivedEdges`` model once during convert.
  * The model's ``edges`` property opens ``self._lookup.client`` and
    iterates every derived-edge view, yielding one ``Edge`` per row.

Why one big model instead of 11?
--------------------------------
OpenHound's ``Converter.run`` binds models to DLT resources by matching
``dlt_resource.validator.model``. Each model needs at least one row from
its bound resource for ``as_node`` / ``edges`` to fire. Because the
derived edge tables only exist in DuckDB after preproc runs, exposing
them as 11 separate tables would require either:

  1. a synthetic JSONL writer in ``transforms.py`` (more plumbing), or
  2. 11 separate DLT trigger resources (10 of them yielding one row each
     with no real input).

A single aggregator model keeps the wiring trivial and lets every edge
kind share the same DuckDB connection. The 10 per-category placeholder
models live alongside this file purely to register their edge schemas
with ``app.assets`` for OpenGraph documentation purposes.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, ClassVar, Optional

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import (
    Edge,
    EdgePath,
    EdgeProperties,
)
from pydantic import ConfigDict

from openhound_sccm.graph import SCCMNode, SCCMNodeProperties, SCCMEdgeProperties
from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk
from openhound_sccm.main import app


# ---------------------------------------------------------------------------
# Permissive properties dataclass for synthesised MSSQL nodes.
# ---------------------------------------------------------------------------
# The MSSQL_Login / MSSQL_DatabaseUser nodes synthesised from
# ``mssql_sysadmin_edges`` carry CMBP-specific fields (``loginType``,
# ``memberOfRoles``, ``database``, ``login``, ``SCCMInfra``) that aren't on
# the canonical SCCMNodeProperties surface. We extend the dataclass with the
# minimum extras needed so the conversion pipeline accepts them.

@dataclass
class _MSSQLSynthProperties(SCCMNodeProperties):
    loginType: Optional[str] = field(default=None, metadata={"description": "MSSQL login type (Windows / SQL)"})
    memberOfRoles: Optional[list[str]] = field(default=None, metadata={"description": "MSSQL roles this login/user is a member of"})
    SCCMInfra: Optional[bool] = field(default=None, metadata={"description": "Whether this is SCCM-managed infrastructure"})
    SCCMSite: Optional[str] = field(default=None, metadata={"description": "SCCM site code this MSSQL principal belongs to"})
    database: Optional[str] = field(default=None, metadata={"description": "MSSQL database name (DatabaseUser only)"})
    login: Optional[str] = field(default=None, metadata={"description": "Login name backing this DatabaseUser"})
    # ``SQLServer`` mirrors PS1: the server id (``<computer_SID>:1433``) the
    # principal lives on. PS1 emits this on every Database / Login /
    # DatabaseUser / DatabaseRole node; the id is already encoded in the
    # node_id but readers expect a separate property.
    SQLServer: Optional[str] = field(default=None, metadata={"description": "Parent MSSQL_Server node id"})
    isFixedRole: Optional[bool] = field(default=None, metadata={"description": "True for the SQL-server-shipped roles (sysadmin / db_owner / etc.)"})
    Type: Optional[str] = field(default=None, metadata={"description": "CMBP-style Type marker"})

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------

def _trav_props(reason: str | None = None) -> EdgeProperties:
    """Build an EdgeProperties marked traversable.

    ``EdgeProperties`` from openhound.core base only carries ``composed``
    and ``traversable`` fields; the more SCCM-specific fields live in
    ``SCCMEdgeProperties`` but those don't roundtrip through the convert
    serialiser cleanly. We keep edges minimal for now.
    """
    return EdgeProperties(traversable=True)


# CMBP/PS1 marks these edge kinds as non-traversable (informational only). BH
# uses ``traversable`` to decide attack-path participation; mirror CMBP so the
# two collectors yield equivalent traversal behaviour in BloodHound.
_NON_TRAVERSABLE_KINDS: frozenset[str] = frozenset({
    "MemberOf",
    "SCCM_HasMember",
    "SCCM_IsAssigned",
    "SCCM_HasStoredAccount",
    "MSSQL_ServiceAccountFor",
})

# Edge kinds CMBP/PS1 tag with ``SCCMInfra=True`` (the edge is part of SCCM
# infrastructure traversal). Mirror so BH agrees across collectors.
_SCCM_INFRA_EDGE_KINDS: frozenset[str] = frozenset({
    "SCCM_IsMappedTo",
})


def _emit_edge(
    start: str,
    end: str,
    kind: str,
    collection_source: str | None = None,
    is_possible: bool = False,
) -> Edge | None:
    """Defensive Edge factory — drops empty endpoints to avoid framework errors.

    When ``collection_source`` is supplied the edge gets a SCCMEdgeProperties
    instance carrying a single-element ``collectionSource`` list. The
    output.py packager dedupes edges by ``(start, end, kind, collectionSource)``
    so distinct discovery paths produce distinct JSON edge rows — mirroring
    CMBP's ``rename_node`` duplicate-retention behaviour for SCCM_HasClient
    and similar edges.

    Edge kinds listed in ``_NON_TRAVERSABLE_KINDS`` are marked
    ``traversable=False`` to match CMBP/PS1's BH traversal hints.

    ``is_possible=True`` marks edges that CMBP labels as "possible" (inferred
    rather than directly observed). When ``SOURCES__SCCM__DISABLE_POSSIBLE_EDGES``
    is true these edges are suppressed entirely, matching CMBP's
    ``--disable-possible-edges`` flag.
    """
    if not start or not end:
        return None
    if is_possible and os.environ.get(
        "SOURCES__SCCM__DISABLE_POSSIBLE_EDGES", ""
    ).lower() in ("1", "true", "yes"):
        return None
    traversable = kind not in _NON_TRAVERSABLE_KINDS
    sccm_infra = True if kind in _SCCM_INFRA_EDGE_KINDS else None
    if collection_source or sccm_infra is not None:
        props: EdgeProperties = SCCMEdgeProperties(
            traversable=traversable,
            collectionSource=[collection_source] if collection_source else None,
            SCCMInfra=sccm_infra,
        )
    else:
        props = EdgeProperties(traversable=traversable)
    from ...log_context import trace_edge
    trace_edge(kind, start, end)
    return Edge(
        kind=kind,
        start=EdgePath(value=start, match_by="id"),
        end=EdgePath(value=end, match_by="id"),
        properties=props,
    )


# PS1 emits ``collectionSource`` lists in a specific stable order reflecting
# the discovery-phase precedence (Registry → MSSQL → AdminService families →
# SCCM_Invoke-PostProcessing → LDAP). Match that exact ordering so list
# equality holds across collectors (BloodHound queries against
# ``e.collectionSource[0]`` and similar return identical results).
_COLLECTION_SOURCE_ORDER: tuple[str, ...] = (
    "RemoteRegistry-MultisiteComponentServers",
    "RemoteRegistry-Identification",
    "RemoteRegistry-ComponentServer",
    "RemoteRegistry-CurrentUser",
    "Local-SMS_Authority",
    "MSSQL-ScanForEPA",
    "MSSQL",
    "MSSQL-EPA",
    "LDAP-MSSQLSvc",
    "AdminService-SMS_Sites",
    "AdminService-SMS_SCI_SiteDefinition",
    "AdminService-SMS_SCI_SysResUse",
    "AdminService-SMS_SCI_Reserved",
    "AdminService-SMS_Admin",
    "AdminService-SMS_Role",
    "AdminService-SMS_Collection",
    "AdminService-SMS_FullCollectionMembership",
    "AdminService-SMS_CombinedDeviceResources",
    "AdminService-ClientDevices",
    "AdminService-SMS_R_System",
    "AdminService-SMS_R_User",
    "AdminService-Hierarchy",
    "AdminService-SecretPolicy",
    "WMI-UsersSeen",
    "SMB-Signing",
    "LDAP-mSSMSSite",
    "LDAP-mSSMSManagementPoint",
    "LDAP-GenericAllSystemManagement",
    "LDAP-CmRcService",
    "SCCM_Invoke-PostProcessing",
)
_COLLECTION_SOURCE_RANK: dict[str, int] = {
    tag: idx for idx, tag in enumerate(_COLLECTION_SOURCE_ORDER)
}


def _sort_sources(sources: list[str]) -> list[str]:
    """Order a collection_source list by PS1's discovery-phase precedence.

    Unknown tags sort to the end in insertion order, so newly-added phases
    don't silently swap the list shape on the canonical-tag prefix that
    BloodHound queries care about.
    """
    default_rank = len(_COLLECTION_SOURCE_ORDER)
    return sorted(sources, key=lambda s: _COLLECTION_SOURCE_RANK.get(s, default_rank))


def _emit_grouped_edges(rows, default_kind: str | None = None):
    """Group ``(start, end, kind?, source)`` rows by ``(start, end, kind)`` and
    yield one ``Edge`` per group with the merged ``collectionSource`` list,
    ordered by PS1's discovery-phase precedence.

    Used for edge kinds where PS1 emits a single edge with multiple source
    tags reflecting every channel that contributed to discovery (MSSQL
    hierarchy edges, SCCM_AssignAllPermissions on MSSQL_Database, etc.).

    ``rows`` is an iterable of 3-tuples ``(start, end, source)`` when
    ``default_kind`` is given, or 4-tuples ``(start, end, kind, source)`` when
    each row carries its own kind. ``source`` may be ``None`` — empty sources
    are filtered from the merged list, preserving CMBP/PS1's behaviour of
    omitting absent provenance.
    """
    from collections import OrderedDict
    grouped: dict[tuple[str, str, str], list[str]] = OrderedDict()
    for row in rows:
        if default_kind is not None:
            start, end, source = row
            kind = default_kind
        else:
            start, end, kind, source = row
        if not start or not end:
            continue
        key = (start, end, kind)
        bucket = grouped.setdefault(key, [])
        if source and source not in bucket:
            bucket.append(source)
    for (start, end, kind), sources in grouped.items():
        traversable = kind not in _NON_TRAVERSABLE_KINDS
        sccm_infra = True if kind in _SCCM_INFRA_EDGE_KINDS else None
        props = SCCMEdgeProperties(
            traversable=traversable,
            collectionSource=_sort_sources(sources) if sources else None,
            SCCMInfra=sccm_infra,
        )
        yield Edge(
            kind=kind,
            start=EdgePath(value=start, match_by="id"),
            end=EdgePath(value=end, match_by="id"),
            properties=props,
        )


# ---------------------------------------------------------------------------
# Node-emission helpers (for MSSQL_Login / MSSQL_DatabaseUser nodes synthesised
# from mssql_sysadmin_edges fan-out).
# ---------------------------------------------------------------------------


def _mk_mssql_node(node_id: str, kinds: list[str], **fields: Any) -> SCCMNode:
    """Build a synthesised MSSQL_Login / MSSQL_DatabaseUser node.

    SCCMNode subclasses openhound's abstract Node and sets ``id`` from
    ``properties.node_id`` in ``__post_init__``.
    """
    return SCCMNode(
        kinds=kinds,
        properties=_MSSQLSynthProperties(
            node_id=node_id,
            name=fields.get("name") or node_id,
            displayname=fields.get("displayname") or fields.get("name") or node_id,
            environmentid=fields.get("environmentid") or None,
            collectionSource=fields.get("collectionSource"),
            siteCode=fields.get("SCCMSite"),
            SCCMSite=fields.get("SCCMSite"),
            SCCMInfra=fields.get("SCCMInfra"),
            loginType=fields.get("loginType"),
            memberOfRoles=fields.get("memberOfRoles"),
            database=fields.get("database"),
            login=fields.get("login"),
            Type=fields.get("Type"),
        ),
    )


# ---------------------------------------------------------------------------
# All edge kinds the aggregator can emit, declared up-front so OpenHound's
# automated docs see them.
# ---------------------------------------------------------------------------

_DECLARED_EDGES = [
    EdgeDef(kind=ek.SCCM_ADMINS_REPLICATED_TO, start=nk.SCCM_SITE, end=nk.SCCM_SITE,
            description="Sites that share admin replication"),
    EdgeDef(kind=ek.SCCM_CONTAINS, start=nk.SCCM_SITE, end=nk.SCCM_COLLECTION,
            description="Site contains a global Collection"),
    EdgeDef(kind=ek.SCCM_CONTAINS, start=nk.SCCM_SITE, end=nk.SCCM_ADMIN_USER,
            description="Site contains a global AdminUser"),
    EdgeDef(kind=ek.SCCM_CONTAINS, start=nk.SCCM_SITE, end=nk.SCCM_SECURITY_ROLE,
            description="Site contains a global SecurityRole"),
    EdgeDef(kind=ek.SCCM_FULL_ADMINISTRATOR, start=nk.SCCM_ADMIN_USER, end=nk.SCCM_CLIENT_DEVICE,
            description="Full Administrator -> client device via collection scope"),
    EdgeDef(kind=ek.SCCM_APPLICATION_ADMINISTRATOR, start=nk.SCCM_ADMIN_USER, end=nk.SCCM_CLIENT_DEVICE,
            description="Application Administrator -> client device"),
    EdgeDef(kind=ek.SCCM_ASSIGN_SPECIFIC_PERMISSIONS, start=nk.SCCM_ADMIN_USER, end=nk.SCCM_CLIENT_DEVICE,
            description="Generic role-assignment edge"),
    EdgeDef(kind=ek.SCCM_ALL_PERMISSIONS, start=nk.SCCM_ADMIN_USER, end=nk.SCCM_SITE,
            description="Full admin with universal scope -> every site in hierarchy"),
    EdgeDef(kind=ek.SAME_HOST_AS, start=nk.SCCM_CLIENT_DEVICE, end=nk.COMPUTER,
            description="ClientDevice <-> Computer co-location"),
    EdgeDef(kind=ek.SAME_HOST_AS, start=nk.COMPUTER, end=nk.SCCM_CLIENT_DEVICE,
            description="Computer <-> ClientDevice co-location"),
    EdgeDef(kind=ek.LOCAL_ADMIN_REQUIRED, start=nk.COMPUTER, end=nk.COMPUTER,
            description="Site server -> co-located site systems"),
    EdgeDef(kind=ek.SCCM_ASSIGN_ALL_PERMISSIONS, start=nk.COMPUTER, end=nk.SCCM_SITE,
            description="SMS Provider host -> primary sites in hierarchy"),
    EdgeDef(kind=ek.SCCM_ASSIGN_ALL_PERMISSIONS, start=nk.MSSQL_DATABASE, end=nk.SCCM_SITE,
            description="CM_<site> MSSQL_Database -> primary site"),
    EdgeDef(kind=ek.MSSQL_HAS_LOGIN, start=nk.COMPUTER, end=nk.MSSQL_LOGIN,
            description="Sysadmin Computer -> MSSQL_Login"),
    EdgeDef(kind=ek.MSSQL_CONTAINS, start=nk.MSSQL_SERVER, end=nk.MSSQL_LOGIN,
            description="Server contains login"),
    EdgeDef(kind=ek.MSSQL_CONTAINS, start=nk.MSSQL_DATABASE, end=nk.MSSQL_DATABASE_USER,
            description="Database contains DatabaseUser"),
    EdgeDef(kind=ek.MSSQL_MEMBER_OF, start=nk.MSSQL_LOGIN, end=nk.MSSQL_SERVER_ROLE,
            description="Login -> sysadmin"),
    EdgeDef(kind=ek.MSSQL_MEMBER_OF, start=nk.MSSQL_DATABASE_USER, end=nk.MSSQL_DATABASE_ROLE,
            description="DatabaseUser -> db_owner"),
    EdgeDef(kind=ek.MSSQL_IS_MAPPED_TO, start=nk.MSSQL_LOGIN, end=nk.MSSQL_DATABASE_USER,
            description="Login -> DatabaseUser"),
    EdgeDef(kind=ek.MSSQL_HOST_FOR, start=nk.COMPUTER, end=nk.MSSQL_SERVER,
            description="Computer hosts MSSQL Server"),
    EdgeDef(kind=ek.MSSQL_EXECUTE_ON_HOST, start=nk.MSSQL_SERVER, end=nk.COMPUTER,
            description="MSSQL Server -> hosting Computer (execute as host context)"),
    EdgeDef(kind=ek.MSSQL_CONTROL_SERVER, start=nk.MSSQL_SERVER_ROLE, end=nk.MSSQL_SERVER,
            description="sysadmin server role -> MSSQL Server (full server control)"),
    EdgeDef(kind=ek.MSSQL_CONTROL_DB, start=nk.MSSQL_DATABASE_ROLE, end=nk.MSSQL_DATABASE,
            description="db_owner database role -> Database (full DB control)"),
    EdgeDef(kind=ek.MSSQL_CONTAINS, start=nk.MSSQL_SERVER, end=nk.MSSQL_SERVER_ROLE,
            description="Server contains sysadmin server role"),
    EdgeDef(kind=ek.MSSQL_CONTAINS, start=nk.MSSQL_SERVER, end=nk.MSSQL_DATABASE,
            description="Server contains Database"),
    EdgeDef(kind=ek.MSSQL_CONTAINS, start=nk.MSSQL_DATABASE, end=nk.MSSQL_DATABASE_ROLE,
            description="Database contains db_owner database role"),
    EdgeDef(kind=ek.MSSQL_GET_TGS, start=nk.USER, end=nk.MSSQL_LOGIN,
            description="Service account -> any login on its server"),
    EdgeDef(kind=ek.MSSQL_GET_ADMIN_TGS, start=nk.USER, end=nk.MSSQL_SERVER,
            description="Service account -> MSSQL Server (Kerberoastable via MSSQLSvc SPN)"),
    EdgeDef(kind=ek.MSSQL_SERVICE_ACCOUNT_FOR, start=nk.USER, end=nk.MSSQL_SERVER,
            description="Service account -> MSSQL Server"),
    EdgeDef(kind=ek.HAS_SESSION, start=nk.COMPUTER, end=nk.USER,
            description="DB Computer -> service account user"),
    EdgeDef(kind=ek.COERCE_AND_RELAY_TO_ADMIN_SERVICE, start=nk.GROUP, end=nk.SCCM_SITE,
            description="Auth users -> site (NTLM relay to AdminService)"),
    EdgeDef(kind=ek.COERCE_AND_RELAY_TO_MSSQL, start=nk.GROUP, end=nk.MSSQL_LOGIN,
            description="Auth users -> MSSQL login (NTLM relay)"),
    EdgeDef(kind=ek.COERCE_AND_RELAY_TO_SMB, start=nk.GROUP, end=nk.COMPUTER,
            description="Auth users -> Computer (SMB relay)"),
    EdgeDef(kind=ek.COERCE_AND_RELAY_TO_SMB_LEGACY, start=nk.GROUP, end=nk.COMPUTER,
            description="Auth users -> Computer (typo'd legacy form)"),
    EdgeDef(kind=ek.SCCM_HAS_NETWORK_ACCESS_ACCOUNT, start=nk.SCCM_CLIENT_DEVICE, end=nk.USER,
            description="ClientDevice -> NAA secret"),
    EdgeDef(kind=ek.SCCM_HAS_STORED_ACCOUNT, start=nk.SCCM_CLIENT_DEVICE, end=nk.USER,
            description="ClientDevice -> stored account secret"),
    EdgeDef(kind=ek.SCCM_HAS_STORED_ACCOUNT, start=nk.SCCM_SITE, end=nk.USER,
            description="Site -> stored account user (SMS_SCI_Reserved)"),
    EdgeDef(kind=ek.SCCM_HAS_COLLECTION_VAR, start=nk.SCCM_CLIENT_DEVICE, end=nk.BASE,
            description="ClientDevice -> collection variable secret"),
    EdgeDef(kind=ek.SCCM_HAS_TASK_SEQUENCE, start=nk.SCCM_CLIENT_DEVICE, end=nk.BASE,
            description="ClientDevice -> task sequence secret"),
    # Phase 6 additions
    EdgeDef(kind=ek.SCCM_HAS_MEMBER, start=nk.SCCM_COLLECTION, end=nk.SCCM_CLIENT_DEVICE,
            description="Collection -> client device membership"),
    EdgeDef(kind=ek.SCCM_HAS_CLIENT, start=nk.SCCM_SITE, end=nk.SCCM_CLIENT_DEVICE,
            description="Site -> client device assignment"),
    EdgeDef(kind=ek.SCCM_HAS_AD_LAST_LOGON_USER, start=nk.SCCM_CLIENT_DEVICE, end=nk.USER,
            description="Device -> last AD logon user"),
    EdgeDef(kind=ek.SCCM_HAS_CURRENT_USER, start=nk.SCCM_CLIENT_DEVICE, end=nk.USER,
            description="Device -> current AD user"),
    EdgeDef(kind=ek.SCCM_HAS_PRIMARY_USER, start=nk.SCCM_CLIENT_DEVICE, end=nk.USER,
            description="Device -> primary user"),
    EdgeDef(kind=ek.SCCM_IS_ASSIGNED, start=nk.SCCM_ADMIN_USER, end=nk.SCCM_SECURITY_ROLE,
            description="Admin -> security role assignment"),
    EdgeDef(kind=ek.SCCM_IS_ASSIGNED, start=nk.SCCM_ADMIN_USER, end=nk.SCCM_COLLECTION,
            description="Admin -> collection scope assignment"),
    EdgeDef(kind=ek.SCCM_IS_MAPPED_TO, start=nk.USER, end=nk.SCCM_ADMIN_USER,
            description="AD user -> SCCM admin mapping"),
    EdgeDef(kind=ek.SCCM_IS_MAPPED_TO, start=nk.GROUP, end=nk.SCCM_ADMIN_USER,
            description="AD group -> SCCM admin mapping"),
    EdgeDef(kind=ek.MEMBER_OF, start=nk.COMPUTER, end=nk.GROUP,
            description="Extra Computer -> Group via SMS_R_System SecurityGroupName"),
    EdgeDef(kind=ek.MEMBER_OF, start=nk.USER, end=nk.GROUP,
            description="Extra User -> Group via SMS_R_User SecurityGroupName"),
]


@app.asset(
    description="Aggregator for all derived edges materialised in DuckDB by transforms.py.",
    edges=_DECLARED_EDGES,
)
class DerivedEdges(BaseAsset):
    """Single trigger model that fans out every derived edge view.

    The bound DLT resource (``derived_edges`` in source.py) yields one
    trigger row at collect time. ``edges`` reads each materialised view
    via ``self._lookup.client`` and yields the union.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # Single trigger column. Value doesn't matter — the model only fires
    # once per collect.
    trigger: str = "derived_edges"

    # ---------------------------------------------------------------- nodes
    @property
    def as_node(self) -> SCCMNode | None:
        # The aggregator emits *edges* only. MSSQL_Login / MSSQL_DatabaseUser
        # nodes referenced by mssql_sysadmin_edges fan-out are not emitted
        # here — see comment in the edges generator below.
        return None

    # ---------------------------------------------------------------- edges
    @property
    def edges(self):
        lookup = getattr(self, "_lookup", None)
        if lookup is None:
            logger.warning("DerivedEdges has no lookup; skipping all derived edges")
            return

        client = lookup.client
        schema = lookup.schema

        # Each block is wrapped in try/except so one bad view doesn't
        # silence the rest. Order doesn't matter for correctness.

        # --- SCCM_AdminsReplicatedTo -----------------------------------
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.admins_replicated_to_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_ADMINS_REPLICATED_TO, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("admins_replicated_to_edges read failed: %s", exc)

        # --- SCCM_Contains ----------------------------------------------
        try:
            for start, end, _kind, collection_source in client.execute(
                f"SELECT start_id, end_id, end_kind, collection_source FROM {schema}.contains_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_CONTAINS, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("contains_edges read failed: %s", exc)

        # --- Role assignments (FullAdmin / AppAdmin / specific ...) ---
        try:
            for start, end, kind, collection_source in client.execute(
                f"SELECT start_id, end_id, edge_kind, collection_source FROM {schema}.role_assignment_edges"
            ).fetchall():
                e = _emit_edge(start, end, kind, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("role_assignment_edges read failed: %s", exc)

        # --- SCCM_AllPermissions ---------------------------------------
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.all_permissions_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_ALL_PERMISSIONS, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("all_permissions_edges read failed: %s", exc)

        # --- SameHostAs (bidirectional) --------------------------------
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.same_host_as_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SAME_HOST_AS, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("same_host_as_edges read failed: %s", exc)

        # --- LocalAdminRequired ----------------------------------------
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.local_admin_required_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.LOCAL_ADMIN_REQUIRED, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("local_admin_required_edges read failed: %s", exc)

        # --- SCCM_AssignAllPermissions ---------------------------------
        # The MSSQL_Database -> primary site branch fans out across the
        # MSSQL_Server's provenance tags (see transforms.py), so the same
        # group-and-merge strategy applies. Other rows (SMS Provider host
        # -> primary site) yield a single source row each and pass through
        # the grouping unchanged.
        try:
            rows = client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.assign_all_permissions_edges"
            ).fetchall()
            for e in _emit_grouped_edges(rows, default_kind=ek.SCCM_ASSIGN_ALL_PERMISSIONS):
                yield e
        except Exception as exc:
            logger.warning("assign_all_permissions_edges read failed: %s", exc)

        # --- MSSQL sysadmin fan-out (8 edges + 2 nodes per row) -------
        # ``has_registry_confirmation`` mirrors the same flag used by
        # ``mssql_server_hierarchy_edges`` and the matching gate in CMBP-
        # python's ``_create_mssql_sysadmin_edges``: when
        # ``--disable-possible-edges`` is set and the site DB host wasn't
        # confirmed via the ``Multisite Component Servers`` registry
        # subkey, the database-dependent edges (IsMappedTo to
        # DatabaseUser, Database->DatabaseUser Contains, DatabaseUser->
        # db_owner MemberOf) are skipped. The login-side fan-out
        # (HasLogin, Server->Login Contains, Login->sysadmin MemberOf)
        # always fires.
        dpe_on = (
            os.environ.get("SOURCES__SCCM__DISABLE_POSSIBLE_EDGES", "").lower()
            in ("1", "true", "yes")
        )
        try:
            rows = client.execute(
                f"SELECT start_id, server_id, database_id, login_name, site_code, "
                f"collection_source, has_registry_confirmation "
                f"FROM {schema}.mssql_sysadmin_edges"
            ).fetchall()
        except Exception as exc:
            logger.warning("mssql_sysadmin_edges read failed: %s", exc)
            rows = []
        for (
            sysadmin_sid,
            server_id,
            database_id,
            login_name,
            site_code,
            collection_source,
            has_registry_confirmation,
        ) in rows:
            login_id = f"{login_name}@{server_id}"
            db_user_id = f"{login_name}@{database_id}"
            sysadmin_role_id = f"sysadmin@{server_id}"
            db_owner_role_id = f"db_owner@{database_id}"

            emit_db_edges = (not dpe_on) or bool(has_registry_confirmation)

            # Login-side edges fire for every sysadmin row. These only
            # reference MSSQL_Login / MSSQL_ServerRole sysadmin, both of
            # which the per-server hierarchy view always emits.
            login_edges = (
                _emit_edge(sysadmin_sid, login_id, ek.MSSQL_HAS_LOGIN, collection_source=collection_source),
                _emit_edge(server_id, login_id, ek.MSSQL_CONTAINS, collection_source=collection_source),
                _emit_edge(login_id, sysadmin_role_id, ek.MSSQL_MEMBER_OF, collection_source=collection_source),
            )
            for e in login_edges:
                if e:
                    yield e

            # Database-side edges only fire when the database hierarchy
            # is emitted (matches CMBP-python's gate so both collectors
            # agree on edge counts when registry isn't reachable).
            if emit_db_edges:
                db_edges = (
                    _emit_edge(login_id, db_user_id, ek.MSSQL_IS_MAPPED_TO, collection_source=collection_source),
                    _emit_edge(database_id, db_user_id, ek.MSSQL_CONTAINS, collection_source=collection_source),
                    _emit_edge(db_user_id, db_owner_role_id, ek.MSSQL_MEMBER_OF, collection_source=collection_source),
                )
                for e in db_edges:
                    if e:
                        yield e

        # --- MSSQL per-server structural hierarchy edges (HostFor, ----
        # ExecuteOnHost, ControlServer, ControlDB, plus the three
        # boilerplate Contains edges Server->sysadmin / Server->Database
        # / Database->db_owner). Built per MSSQL_Server in transforms.py.
        #
        # The view fans out one row per (edge, contributing channel) so
        # PS1's multi-source ``collectionSource`` list is reproduced.
        # ``_emit_grouped_edges`` regroups the rows by (start, end, kind)
        # and yields a single Edge per group with the merged source list.
        try:
            rows = client.execute(
                f"SELECT start_id, end_id, edge_kind, collection_source FROM {schema}.mssql_server_hierarchy_edges"
            ).fetchall()
            for e in _emit_grouped_edges(rows):
                yield e
        except Exception as exc:
            logger.warning("mssql_server_hierarchy_edges read failed: %s", exc)

        # --- CoerceAndRelay (3 flavours + 1 typo'd legacy) -------------
        try:
            for start, end, kind, _v, _t, collection_source in client.execute(
                f"SELECT start_id, end_id, edge_kind, victim_fqdn, target_fqdn, collection_source "
                f"FROM {schema}.coerce_and_relay_edges"
            ).fetchall():
                e = _emit_edge(start, end, kind, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("coerce_and_relay_edges read failed: %s", exc)

        # --- MSSQL_GetTGS / MSSQL_GetAdminTGS / MSSQL_ServiceAccountFor / HasSession --
        try:
            for start, end, kind, collection_source in client.execute(
                f"SELECT start_id, end_id, edge_kind, collection_source FROM {schema}.mssql_gettgs_edges"
            ).fetchall():
                e = _emit_edge(start, end, kind, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("mssql_gettgs_edges read failed: %s", exc)

        # --- Secret-policy edges --------------------------------------
        try:
            for start, end, kind, collection_source in client.execute(
                f"SELECT start_id, end_id, edge_kind, collection_source FROM {schema}.secret_policy_edges"
            ).fetchall():
                e = _emit_edge(start, end, kind, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("secret_policy_edges read failed: %s", exc)

        # --- Phase 6: SCCM_HasMember (Collection -> ClientDevice) ------
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.has_member_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_HAS_MEMBER, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("has_member_edges read failed: %s", exc)

        # --- Phase 6: SCCM_HasClient (Site -> ClientDevice) ------------
        # PS1 groups the two AdminService-source rows into one Edge per
        # (site, device) but keeps any cmrc-synth (``LDAP-CmRcService``)
        # row as a *separate* Edge — even when start/end match an
        # AdminService edge. Mirror that here: AdminService rows go
        # through ``_emit_grouped_edges``; cmrc-synth rows are emitted
        # as standalone Edges.
        try:
            rows = client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.has_client_edges"
            ).fetchall()
            adminservice_rows = []
            cmrc_rows = []
            for r in rows:
                start, end, source = r
                if source == "LDAP-CmRcService":
                    cmrc_rows.append(r)
                else:
                    adminservice_rows.append(r)
            for e in _emit_grouped_edges(adminservice_rows, default_kind=ek.SCCM_HAS_CLIENT):
                yield e
            for start, end, source in cmrc_rows:
                e = _emit_edge(start, end, ek.SCCM_HAS_CLIENT, collection_source=source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("has_client_edges read failed: %s", exc)

        # --- Phase 6: SCCM_HasADLastLogonUser / HasCurrentUser / HasPrimaryUser
        try:
            for start, end, kind, collection_source in client.execute(
                f"SELECT start_id, end_id, edge_kind, collection_source FROM {schema}.client_user_edges"
            ).fetchall():
                e = _emit_edge(start, end, kind, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("client_user_edges read failed: %s", exc)

        # --- Phase 6: SCCM_IsAssigned (admin -> role/collection) -------
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.is_assigned_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_IS_ASSIGNED, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("is_assigned_edges read failed: %s", exc)

        # --- Phase 6: SCCM_IsMappedTo (User/Group -> SCCM_AdminUser) ---
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.is_mapped_to_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_IS_MAPPED_TO, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("is_mapped_to_edges read failed: %s", exc)

        # --- Phase 6: extra MemberOf edges from SMS_R_System -----------
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.r_system_member_of_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.MEMBER_OF, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("r_system_member_of_edges read failed: %s", exc)

        # --- Phase 6: extra MemberOf edges from SMS_R_User -------------
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.r_user_member_of_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.MEMBER_OF, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("r_user_member_of_edges read failed: %s", exc)

        # --- Phase 6: HasSession from registry / WMI per-host
        # current/last-logged-on-user data (Computer -> User).
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.registry_has_session_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.HAS_SESSION, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("registry_has_session_edges read failed: %s", exc)

        # --- Phase 6: SCCM_HasStoredAccount (Site -> User from SMS_SCI_Reserved)
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.has_stored_account_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_HAS_STORED_ACCOUNT, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("has_stored_account_edges read failed: %s", exc)

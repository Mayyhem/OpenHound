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


def _emit_edge(start: str, end: str, kind: str, collection_source: str | None = None) -> Edge | None:
    """Defensive Edge factory — drops empty endpoints to avoid framework errors.

    When ``collection_source`` is supplied the edge gets a SCCMEdgeProperties
    instance carrying a single-element ``collectionSource`` list. The
    output.py packager dedupes edges by ``(start, end, kind, collectionSource)``
    so distinct discovery paths produce distinct JSON edge rows — mirroring
    CMBP's ``rename_node`` duplicate-retention behaviour for SCCM_HasClient
    and similar edges.
    """
    if not start or not end:
        return None
    if collection_source:
        props: EdgeProperties = SCCMEdgeProperties(
            traversable=True,
            collectionSource=[collection_source],
        )
    else:
        props = _trav_props()
    return Edge(
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
            environmentid=fields.get("environmentid", ""),
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
            for start, end in client.execute(
                f"SELECT start_id, end_id FROM {schema}.admins_replicated_to_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_ADMINS_REPLICATED_TO)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("admins_replicated_to_edges read failed: %s", exc)

        # --- SCCM_Contains ----------------------------------------------
        try:
            for start, end, _kind in client.execute(
                f"SELECT start_id, end_id, end_kind FROM {schema}.contains_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_CONTAINS)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("contains_edges read failed: %s", exc)

        # --- Role assignments (FullAdmin / AppAdmin / specific ...) ---
        try:
            for start, end, kind in client.execute(
                f"SELECT start_id, end_id, edge_kind FROM {schema}.role_assignment_edges"
            ).fetchall():
                e = _emit_edge(start, end, kind)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("role_assignment_edges read failed: %s", exc)

        # --- SCCM_AllPermissions ---------------------------------------
        try:
            for start, end in client.execute(
                f"SELECT start_id, end_id FROM {schema}.all_permissions_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_ALL_PERMISSIONS)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("all_permissions_edges read failed: %s", exc)

        # --- SameHostAs (bidirectional) --------------------------------
        try:
            for start, end in client.execute(
                f"SELECT start_id, end_id FROM {schema}.same_host_as_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SAME_HOST_AS)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("same_host_as_edges read failed: %s", exc)

        # --- LocalAdminRequired ----------------------------------------
        try:
            for start, end in client.execute(
                f"SELECT start_id, end_id FROM {schema}.local_admin_required_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.LOCAL_ADMIN_REQUIRED)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("local_admin_required_edges read failed: %s", exc)

        # --- SCCM_AssignAllPermissions ---------------------------------
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.assign_all_permissions_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_ASSIGN_ALL_PERMISSIONS, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("assign_all_permissions_edges read failed: %s", exc)

        # --- MSSQL sysadmin fan-out (8 edges + 2 nodes per row) -------
        try:
            rows = client.execute(
                f"SELECT start_id, server_id, database_id, login_name, site_code "
                f"FROM {schema}.mssql_sysadmin_edges"
            ).fetchall()
        except Exception as exc:
            logger.warning("mssql_sysadmin_edges read failed: %s", exc)
            rows = []
        for sysadmin_sid, server_id, database_id, login_name, site_code in rows:
            login_id = f"{login_name}@{server_id}"
            db_user_id = f"{login_name}@{database_id}"
            sysadmin_role_id = f"sysadmin@{server_id}"
            db_owner_role_id = f"db_owner@{database_id}"

            # Nodes — synthesised here because no separate table exists for
            # these convert-time MSSQL principals. Properties intentionally
            # minimal; matches CMBP `_create_mssql_sysadmin_edges`.
            # NOTE — synthesised MSSQL_Login / MSSQL_DatabaseUser nodes are not
            # emitted here because OpenHound's convert pipeline only accepts
            # ``Edge`` objects from a model's ``edges`` generator (nodes go
            # through ``as_node`` which is single-valued). BloodHound's
            # graph DB will create stub nodes on first reference, which is
            # adequate for Phase 4. Phase 6 may add a dedicated synthesised-
            # node resource if richer node properties are needed.

            # Edges
            for e in (
                _emit_edge(sysadmin_sid, login_id, ek.MSSQL_HAS_LOGIN),
                _emit_edge(server_id, login_id, ek.MSSQL_CONTAINS),
                _emit_edge(login_id, sysadmin_role_id, ek.MSSQL_MEMBER_OF),
                _emit_edge(login_id, db_user_id, ek.MSSQL_IS_MAPPED_TO),
                _emit_edge(database_id, db_user_id, ek.MSSQL_CONTAINS),
                _emit_edge(db_user_id, db_owner_role_id, ek.MSSQL_MEMBER_OF),
            ):
                if e:
                    yield e

        # --- MSSQL per-server structural hierarchy edges (HostFor, ----
        # ExecuteOnHost, ControlServer, ControlDB, plus the three
        # boilerplate Contains edges Server->sysadmin / Server->Database
        # / Database->db_owner). Built per MSSQL_Server in transforms.py.
        try:
            for start, end, kind in client.execute(
                f"SELECT start_id, end_id, edge_kind FROM {schema}.mssql_server_hierarchy_edges"
            ).fetchall():
                e = _emit_edge(start, end, kind)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("mssql_server_hierarchy_edges read failed: %s", exc)

        # --- CoerceAndRelay (3 flavours + 1 typo'd legacy) -------------
        try:
            for start, end, kind, _v, _t in client.execute(
                f"SELECT start_id, end_id, edge_kind, victim_fqdn, target_fqdn "
                f"FROM {schema}.coerce_and_relay_edges"
            ).fetchall():
                e = _emit_edge(start, end, kind)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("coerce_and_relay_edges read failed: %s", exc)

        # --- MSSQL_GetTGS / MSSQL_GetAdminTGS / MSSQL_ServiceAccountFor / HasSession --
        try:
            for start, end, kind in client.execute(
                f"SELECT start_id, end_id, edge_kind FROM {schema}.mssql_gettgs_edges"
            ).fetchall():
                e = _emit_edge(start, end, kind)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("mssql_gettgs_edges read failed: %s", exc)

        # --- Secret-policy edges --------------------------------------
        try:
            for start, end, kind in client.execute(
                f"SELECT start_id, end_id, edge_kind FROM {schema}.secret_policy_edges"
            ).fetchall():
                e = _emit_edge(start, end, kind)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("secret_policy_edges read failed: %s", exc)

        # --- Phase 6: SCCM_HasMember (Collection -> ClientDevice) ------
        try:
            for start, end in client.execute(
                f"SELECT start_id, end_id FROM {schema}.has_member_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_HAS_MEMBER)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("has_member_edges read failed: %s", exc)

        # --- Phase 6: SCCM_HasClient (Site -> ClientDevice) ------------
        try:
            for start, end, collection_source in client.execute(
                f"SELECT start_id, end_id, collection_source FROM {schema}.has_client_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_HAS_CLIENT, collection_source=collection_source)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("has_client_edges read failed: %s", exc)

        # --- Phase 6: SCCM_HasADLastLogonUser / HasCurrentUser / HasPrimaryUser
        try:
            for start, end, kind in client.execute(
                f"SELECT start_id, end_id, edge_kind FROM {schema}.client_user_edges"
            ).fetchall():
                e = _emit_edge(start, end, kind)
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
            for start, end in client.execute(
                f"SELECT start_id, end_id FROM {schema}.r_system_member_of_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.MEMBER_OF)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("r_system_member_of_edges read failed: %s", exc)

        # --- Phase 6: extra MemberOf edges from SMS_R_User -------------
        try:
            for start, end in client.execute(
                f"SELECT start_id, end_id FROM {schema}.r_user_member_of_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.MEMBER_OF)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("r_user_member_of_edges read failed: %s", exc)

        # --- Phase 6: HasSession from registry / WMI per-host
        # current/last-logged-on-user data (Computer -> User).
        try:
            for start, end in client.execute(
                f"SELECT start_id, end_id FROM {schema}.registry_has_session_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.HAS_SESSION)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("registry_has_session_edges read failed: %s", exc)

        # --- Phase 6: SCCM_HasStoredAccount (Site -> User from SMS_SCI_Reserved)
        try:
            for start, end in client.execute(
                f"SELECT start_id, end_id FROM {schema}.has_stored_account_edges"
            ).fetchall():
                e = _emit_edge(start, end, ek.SCCM_HAS_STORED_ACCOUNT)
                if e:
                    yield e
        except Exception as exc:
            logger.warning("has_stored_account_edges read failed: %s", exc)

"""Synthesised node aggregator for MSSQL principals referenced by edges.

The Phase 4 ``mssql_sysadmin_edges`` SQL view emits MSSQL_HasLogin /
MSSQL_Contains / MSSQL_MemberOf / MSSQL_IsMappedTo edges that reference
MSSQL_Login / MSSQL_DatabaseUser / MSSQL_DatabaseRole / MSSQL_ServerRole /
MSSQL_Database node ids. Until this model existed those endpoints were
"stub on first reference" inside BHE — graphically valid but missing
properties (Type, SCCMSite, login, database, ...).

Pattern
-------
The bound DLT resource (``derived_nodes`` in source.py) replicates the
same Python-side fan-out as ``transforms._build_mssql_sysadmin_edges`` and
yields one row *per synthesised node*. Each row carries:

* ``kind``       — one of MSSQL_Login / MSSQL_DatabaseUser /
                   MSSQL_DatabaseRole / MSSQL_ServerRole / MSSQL_Database.
* ``node_id``    — same id used on the edge endpoint side
                   (``login@server``, ``login@server\\db``, ``role@scope``).
* ``name``       — display name (login string, role name, db name, ...).
* ``server``     — MSSQL server FQDN (carried as ``SQLServer`` property).
* ``database``   — DB name (only on database-scoped kinds).
* ``login``      — backing login (only on DatabaseUser).
* ``site_code``  — SCCM site this principal is associated with.
* ``domain``     — domain string for ``environmentid``.

Convert binds rows -> ``DerivedNode`` -> ``as_node`` -> one SCCMNode.
The model emits no edges (those are handled by ``DerivedEdges``).
"""

from __future__ import annotations

from typing import ClassVar, Optional

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, NodeDef
from pydantic import ConfigDict

from openhound_sccm.graph import SCCMNode
from openhound_sccm.kinds import nodes as nk
from openhound_sccm.main import app

from .aggregator import _MSSQLSynthProperties

# Map row "kind" tokens to (node-kind constant, default Type marker).
_KIND_MAP = {
    "MSSQL_Server": (nk.MSSQL_SERVER, "MSSQL_Server"),
    "MSSQL_Login": (nk.MSSQL_LOGIN, "MSSQL_Login"),
    "MSSQL_DatabaseUser": (nk.MSSQL_DATABASE_USER, "MSSQL_DatabaseUser"),
    "MSSQL_DatabaseRole": (nk.MSSQL_DATABASE_ROLE, "MSSQL_DatabaseRole"),
    "MSSQL_ServerRole": (nk.MSSQL_SERVER_ROLE, "MSSQL_ServerRole"),
    "MSSQL_Database": (nk.MSSQL_DATABASE, "MSSQL_Database"),
}


@app.asset(
    description="Synthesised MSSQL principal nodes (Login / DatabaseUser / Role / Database)",
    node=NodeDef(
        kind=nk.MSSQL_LOGIN,  # representative; the model emits any of 5 kinds at runtime
        description="MSSQL principal node synthesised from mssql_sysadmin_edges fan-out",
        icon="key",
        properties=_MSSQLSynthProperties,
    ),
    edges=[],
)
class DerivedNode(BaseAsset):
    """One synthesised MSSQL principal node per row of ``derived_nodes``.

    The bound DLT resource yields rows whose ``kind`` field selects which
    node kind to emit. ``edges`` is always empty.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # All fields are optional except ``kind`` and ``node_id`` because each
    # row only populates the subset that's relevant to its kind.
    kind: str
    node_id: str
    name: Optional[str] = None
    displayname: Optional[str] = None
    server: Optional[str] = None
    database: Optional[str] = None
    login: Optional[str] = None
    login_type: Optional[str] = None
    site_code: Optional[str] = None
    domain: Optional[str] = None
    is_fixed_role: Optional[bool] = None
    member_of_roles: Optional[list[str]] = None
    sccm_infra: Optional[bool] = None
    source: Optional[str] = "Synth-MSSQL"

    @property
    def as_node(self) -> SCCMNode | None:
        from ...log_context import trace_node
        spec = _KIND_MAP.get(self.kind)
        if spec is None:
            return None
        node_kind, type_marker = spec
        name = self.name or self.node_id
        trace_node(self.kind, self.node_id, name)
        # ``SQLServer`` is the parent server id (``<computer_SID>:1433``).
        # For Server itself, this is just the node_id. For Database /
        # Login / DatabaseUser / Role kinds, the server id is the prefix
        # of node_id up to ``\`` (for Database/Role) or after ``@`` and
        # before any ``\`` (for Login/DatabaseUser).
        sql_server: Optional[str] = None
        nid = self.node_id or ""
        if self.kind == "MSSQL_Server":
            sql_server = nid
        elif "@" in nid:
            # Login: <domain>\<sam>@<SID>:1433
            # DatabaseUser: <domain>\<sam>@<SID>:1433\CM_<site>
            after_at = nid.split("@", 1)[1]
            sql_server = after_at.split("\\", 1)[0] or None
        elif "\\" in nid:
            # Database: <SID>:1433\CM_<site>
            # DatabaseRole/ServerRole: <role>@<SID>:1433 — handled above
            sql_server = nid.split("\\", 1)[0] or None
        return SCCMNode(
            kinds=[node_kind],
            properties=_MSSQLSynthProperties(
                node_id=self.node_id,
                name=name,
                displayname=self.displayname or name,
                environmentid=self.domain or None,
                collectionSource=[self.source] if self.source else None,
                siteCode=self.site_code,
                SCCMSite=self.site_code,
                SCCMInfra=self.sccm_infra,
                loginType=self.login_type,
                memberOfRoles=self.member_of_roles,
                database=self.database,
                login=self.login,
                SQLServer=sql_server,
                isFixedRole=self.is_fixed_role,
                Type=type_marker,
            ),
        )

    @property
    def edges(self):
        return iter(())

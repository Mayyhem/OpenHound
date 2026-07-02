"""GraphEdge: one ``graph_edges`` preproc row -> one OpenGraph edge.

MSSQL specialization of the shared
:class:`openhound_collector_common.graph.graph_edge.GraphEdge`. The shared model
emits a generic :class:`GraphEdgeProperties` carrying only ``traversable`` +
``collection_source``; MSSQL edges additionally carry MSSQLHound's documentation
bag (``general`` / ``windowsAbuse`` / ``linuxAbuse`` / ``opsec`` / ``references``
/ ``composition``) plus the typed ``withGrant`` / ``ownerPrincipalID`` props, so
the BloodHound entity panel is fully populated (project rule: port every
property). This subclass therefore overrides ``edges`` to emit the richer
:class:`~openhound_mssql.graph.MSSQLEdgeProperties`.

``edge_rules.build_graph_edges`` already decided each edge's ``traversable`` flag
in preproc (kind partition + the ``--disable-*`` toggles), so it is read straight
off the row rather than recomputed from an allow-list. The property-bag columns
arrive snake_case from DuckDB (``windows_abuse`` ...) and are mapped onto the
camelCase ``MSSQLEdgeProperties`` field names here (the two-layer casing rule:
DuckDB columns snake_case, emitted keys CMBP-cased).
"""
from __future__ import annotations

import logging
from typing import Iterator

from openhound.core.models.entries_dataclass import Edge, EdgePath
from openhound_collector_common.graph.graph_edge import GraphEdge as _BaseGraphEdge
from pydantic import ConfigDict

from ..graph import MSSQLEdgeProperties

logger = logging.getLogger(__name__)


class GraphEdge(_BaseGraphEdge):
    """One ``graph_edges`` row -> one OpenGraph ``Edge`` with the full MSSQL bag.

    Endpoints are matched by ``id``. ``traversable`` is read from the row (decided
    in preproc). Never produces a node.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    # Property-bag columns from graph_edges (snake_case, as DuckDB returns them).
    # Optional so a row that omits a key (Go only sets non-empty props) maps to a
    # None field, which convert's asdict-then-filter then drops.
    traversable: bool | None = None
    general: str | None = None
    windows_abuse: str | None = None
    linux_abuse: str | None = None
    opsec: str | None = None
    references: str | None = None
    composition: str | None = None
    with_grant: bool | None = None
    owner_principal_id: str | None = None
    # Stage-7b typed props + linked-server bag (snake_case DuckDB columns).
    credential_id: str | None = None
    proxy_id: str | None = None
    local_login: str | None = None
    remote_login: str | None = None
    remote_current_login: str | None = None
    data_source: str | None = None
    link_path: str | None = None
    product: str | None = None
    provider: str | None = None
    data_access: bool | None = None
    rpc_out: bool | None = None
    uses_impersonation: bool | None = None
    remote_is_sysadmin: bool | None = None
    remote_is_security_admin: bool | None = None
    remote_has_control_server: bool | None = None
    remote_has_impersonate_any_login: bool | None = None
    remote_is_mixed_mode: bool | None = None

    @property
    def edges(self) -> Iterator[Edge]:
        """Yield one ``Edge`` for this row, carrying the MSSQL documentation bag.

        A row missing ``start_id`` / ``end_id`` / ``kind`` is dropped with a
        warning rather than emitting a malformed edge (mirrors the base model).
        The Stage-7b typed props (credentialId/proxyId) and the linked-server
        property bag are carried verbatim so the entity panel matches Go.
        """
        if not self.start_id or not self.end_id or not self.kind:
            logger.warning(
                "GraphEdge: dropping incomplete row (start=%r end=%r kind=%r)",
                self.start_id, self.end_id, self.kind,
            )
            return
        logger.debug("GraphEdge: emitting %s -[%s]-> %s",
                     self.start_id, self.kind, self.end_id)
        yield Edge(
            kind=self.kind,
            start=EdgePath(match_by="id", value=self.start_id),
            end=EdgePath(match_by="id", value=self.end_id),
            properties=MSSQLEdgeProperties(
                traversable=bool(self.traversable),
                general=self.general,
                windowsAbuse=self.windows_abuse,
                linuxAbuse=self.linux_abuse,
                opsec=self.opsec,
                references=self.references,
                composition=self.composition,
                withGrant=self.with_grant,
                ownerPrincipalID=self.owner_principal_id,
                credentialId=self.credential_id,
                proxyId=self.proxy_id,
                localLogin=self.local_login,
                remoteLogin=self.remote_login,
                remoteCurrentLogin=self.remote_current_login,
                dataSource=self.data_source,
                path=self.link_path,
                product=self.product,
                provider=self.provider,
                dataAccess=self.data_access,
                rpcOut=self.rpc_out,
                usesImpersonation=self.uses_impersonation,
                remoteIsSysadmin=self.remote_is_sysadmin,
                remoteIsSecurityAdmin=self.remote_is_security_admin,
                remoteHasControlServer=self.remote_has_control_server,
                remoteHasImpersonateAnyLogin=self.remote_has_impersonate_any_login,
                remoteIsMixedMode=self.remote_is_mixed_mode,
            ),
        )


__all__ = ["GraphEdge"]

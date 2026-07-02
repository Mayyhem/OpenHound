"""``linked_server_targets`` row -> foreign linked-server stub ``MSSQL_Server`` node.

When a SQL Server links to a DIFFERENT host (e.g. ps1-db's ``CAS-DB`` link), Go
emits a minimal stub ``MSSQL_Server`` node for that remote target so the LinkedTo
/ LinkedAsAdmin edge connects two server *nodes* instead of dangling at a bare
hostname (``collector.generateOutput`` linked-node loop, collector.go:2488-2527).
The stub id is the foreign host's ``<computerSID>:<port>`` (resolved at collect
time); its only properties are ``name`` (data source truncated at the first
``\\``/``,``/``:``), ``isLinkedServerTarget=true`` and
``hasLinksFromServers=[<localServerOID>]``, with the server icon.

The preproc ``linked_server_targets`` table (built by
:func:`openhound_mssql.linked_server_nodes.build_linked_server_targets`) already
did the dedupe + name truncation, so this convert asset is a thin row->node mapper.
Like ``ADNode`` it is a plain :class:`BaseAsset` wired straight into the convert
NODE_SPECS (it reuses the registered ``MSSQL_Server`` kind, so it needs no NodeDef
of its own).
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict

from ..graph import LinkedServerStubProperties, MSSQLNode
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class LinkedServerStubNode(BaseAsset):
    """One ``linked_server_targets`` row -> one stub ``MSSQL_Server`` OpenGraph node."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    id: Optional[str] = None
    name: Optional[str] = None
    hasLinksFromServers: Optional[Any] = None  # list[str] from the VARCHAR[] column
    isLinkedServerTarget: Optional[Any] = None

    @property
    def as_node(self) -> MSSQLNode | None:
        """Build the foreign linked-server stub node (Go linked-node loop)."""
        if not self.id:
            logger.warning("LinkedServerStubNode: dropping row with no id")
            return None
        name = self.name or self.id
        props = LinkedServerStubProperties(
            name=name,
            displayname=name,
            environmentid=self.id,  # the stub IS its own environment (a server node)
            isLinkedServerTarget=True,
            hasLinksFromServers=list(self.hasLinksFromServers) if self.hasLinksFromServers else [],
        )
        return MSSQLNode(
            kinds=[nk.SERVER],
            properties=props,
            object_identifier=self.id,
            icon=nk.ICONS[nk.SERVER],
        )

    @property
    def edges(self):
        """Linked-server edges (LinkedTo/LinkedAsAdmin) are derived in Stage 7b."""
        return iter(())


__all__ = ["LinkedServerStubNode"]

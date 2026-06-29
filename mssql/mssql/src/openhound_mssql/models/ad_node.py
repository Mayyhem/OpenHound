"""``ad_nodes`` row -> Active Directory node (Computer/User/Group + ``Base``).

The AD nodes are the BloodHound-native principals the MSSQL graph attaches edges
to (the host Computer, the domain logins/groups, service accounts, credential
identities, local groups, Authenticated Users). They are built in preproc by
:func:`openhound_mssql.ad_nodes.build_ad_nodes` (a port of Go ``createADNodes``),
which already did the SID resolution, the kind selection, and the dedupe — so
this convert asset is a thin row -> node mapper. Each node:

* carries the kinds the preproc row chose (``[Computer|User|Group, "Base"]``),
* has **NO icon** (only the seven ``MSSQL_*`` kinds get an icon — spec §5),
* keys on the SID-based id (or ``<host>-<SID>`` / ``<domain>-S-1-5-11``),
* emits only the AD properties that are set on the row (Go sets props
  conditionally; we drop ``None`` values so absent keys don't appear).

Unlike the ``MSSQL_*`` assets there is no ``environmentid`` server scoping on AD
nodes — they are global BloodHound objects (Go emits them with ``metadata: {}``,
no source_kind). We still pass the framework-required base ``NodeProperties``
fields (``name``/``displayname``/``environmentid``); ``environmentid`` is left
empty because an AD principal is not scoped to one SQL Server.

This is a plain :class:`BaseAsset`, NOT an ``@app.asset``-registered NodeDef:
the AD kinds (Computer/User/Group) are BloodHound-native and carry no icon, but a
registered ``NodeDef`` requires an icon and would declare one into the OpenGraph
schema. So — exactly like SCCM's ``ComputerNode``/``UserNode``/``GroupNode`` — the
asset is wired straight into the convert NODE_SPECS and never registered as a kind
definition. The convert pipeline instantiates it per ``ad_nodes`` row and reads
``as_node`` directly.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from openhound.core.asset import BaseAsset
from pydantic import ConfigDict

from ..graph import ADProperties, MSSQLNode
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class ADNode(BaseAsset):
    """One ``ad_nodes`` row -> one AD OpenGraph node.

    The preproc ``ad_nodes`` table is the single source: ``id`` + ``kinds`` (the
    primary AD kind + ``Base``) + the optional AD property columns. ``extra="allow"``
    lets any future column pass through harmlessly.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    id: Optional[str] = None
    kinds: Optional[Any] = None  # list[str] from the DuckDB VARCHAR[] column
    name: Optional[str] = None
    SID: Optional[str] = None
    domain: Optional[str] = None
    isDomainPrincipal: Optional[Any] = None
    SAMAccountName: Optional[str] = None
    isActiveDirectoryPrincipal: Optional[Any] = None
    isEnabled: Optional[Any] = None
    distinguishedName: Optional[str] = None
    userPrincipalName: Optional[str] = None
    DNSHostName: Optional[str] = None

    @property
    def as_node(self) -> MSSQLNode | None:
        """Build the AD node (Go createADNodes node shape)."""
        if not self.id:
            # A row with no id can't be keyed — drop it (shouldn't happen).
            logger.warning("ADNode: dropping ad_nodes row with no id")
            return None
        kinds = list(self.kinds) if self.kinds else [nk.USER, nk.BASE]

        props = ADProperties(
            name=self.name or "",
            displayname=self.name or "",
            environmentid="",  # AD principals aren't scoped to one SQL Server.
        )
        # Set only the AD properties that are present on the row (Go conditionals).
        if self.SID is not None:
            props.SID = self.SID
        if self.domain is not None:
            props.domain = self.domain
        if self.isDomainPrincipal is not None:
            props.isDomainPrincipal = _as_bool(self.isDomainPrincipal)
        if self.SAMAccountName is not None:
            props.SAMAccountName = self.SAMAccountName
        if self.isActiveDirectoryPrincipal is not None:
            props.isActiveDirectoryPrincipal = _as_bool(self.isActiveDirectoryPrincipal)
        if self.isEnabled is not None:
            props.isEnabled = _as_bool(self.isEnabled)
        if self.distinguishedName is not None:
            props.distinguishedName = self.distinguishedName
        if self.userPrincipalName is not None:
            props.userPrincipalName = self.userPrincipalName
        if self.DNSHostName is not None:
            props.DNSHostName = self.DNSHostName

        # No icon on AD nodes (spec §5): icon defaults to None on MSSQLNode.
        return MSSQLNode(kinds=kinds, properties=props, object_identifier=self.id)

    @property
    def edges(self):
        """AD-attached edges (HasSession / MemberOf / GetTGS / ...) are Stage 7b."""
        return iter(())


def _as_bool(value) -> bool:
    """Coerce a raw DuckDB value (0/1, bool, 'true') to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "t", "yes", "y")
    return False


__all__ = ["ADNode"]

"""MSSQL sysadmin derived-edge schema placeholder.

For every (sysadmin Computer, site DB Computer) pair the aggregator emits eight
MSSQL edges plus two synthesised nodes (MSSQL_Login, MSSQL_DatabaseUser).
Materialised in ``sccm.mssql_sysadmin_edges``; emitter is ``aggregator.py``.

Edges fanned out:
  * MSSQL_HasLogin       (Computer        -> MSSQL_Login)
  * MSSQL_Contains       (MSSQL_Server    -> MSSQL_Login)
  * MSSQL_MemberOf       (MSSQL_Login     -> MSSQL_ServerRole sysadmin)
  * MSSQL_IsMappedTo     (MSSQL_Login     -> MSSQL_DatabaseUser)
  * MSSQL_Contains       (MSSQL_Database  -> MSSQL_DatabaseUser)
  * MSSQL_MemberOf       (MSSQL_DatabaseUser -> MSSQL_DatabaseRole db_owner)
  * MSSQL_HostFor        (Computer        -> MSSQL_Server)  [emitted from MSSQLServer node model where present]
  * MSSQL_ControlServer  (post-graph; not in this Phase)
"""

from __future__ import annotations

from openhound.core.asset import EdgeDef

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk

from ._placeholder import register_placeholder

MSSQLSysadminEdge = register_placeholder(
    name="MSSQLSysadminEdge",
    description="Schema-only placeholder for MSSQL sysadmin fan-out; emitter in aggregator.py.",
    edges=[
        EdgeDef(kind=ek.MSSQL_HAS_LOGIN, start=nk.COMPUTER, end=nk.MSSQL_LOGIN,
                description="Sysadmin Computer -> MSSQL_Login."),
        EdgeDef(kind=ek.MSSQL_CONTAINS, start=nk.MSSQL_SERVER, end=nk.MSSQL_LOGIN,
                description="Server contains login."),
        EdgeDef(kind=ek.MSSQL_CONTAINS, start=nk.MSSQL_DATABASE, end=nk.MSSQL_DATABASE_USER,
                description="Database contains DatabaseUser."),
        EdgeDef(kind=ek.MSSQL_MEMBER_OF, start=nk.MSSQL_LOGIN, end=nk.MSSQL_SERVER_ROLE,
                description="Login -> sysadmin server role."),
        EdgeDef(kind=ek.MSSQL_MEMBER_OF, start=nk.MSSQL_DATABASE_USER, end=nk.MSSQL_DATABASE_ROLE,
                description="DatabaseUser -> db_owner database role."),
        EdgeDef(kind=ek.MSSQL_IS_MAPPED_TO, start=nk.MSSQL_LOGIN, end=nk.MSSQL_DATABASE_USER,
                description="Login -> DatabaseUser mapping."),
    ],
)

"""MSSQL_GetTGS / MSSQL_GetAdminTGS / ServiceAccountFor / HasSession schema placeholder.

The SQL service account (resolved from ``wmi_sql_service_accounts.service_account``
to ``ldap_users.object_sid``) gets:

  * MSSQL_ServiceAccountFor — service-account User -> MSSQL_Server
  * HasSession              — DB-host Computer    -> service-account User
  * MSSQL_GetTGS            — service-account User -> every MSSQL_Login on that server
  * MSSQL_GetAdminTGS       — service-account User -> MSSQL_Server (Kerberoastable via SPN)

Materialised in ``sccm.mssql_gettgs_edges``; emitter is ``aggregator.py``.
"""

from __future__ import annotations

from openhound.core.asset import EdgeDef

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk

from ._placeholder import register_placeholder

MSSQLGetTGSEdge = register_placeholder(
    name="MSSQLGetTGSEdge",
    description="Schema-only placeholder for MSSQL Kerberoasting edges; emitter in aggregator.py.",
    edges=[
        EdgeDef(kind=ek.MSSQL_GET_TGS, start=nk.USER, end=nk.MSSQL_LOGIN,
                description="Service account -> any login on its server (Kerberoast)."),
        EdgeDef(kind=ek.MSSQL_GET_ADMIN_TGS, start=nk.USER, end=nk.MSSQL_SERVER,
                description="Service account -> MSSQL Server (Kerberoastable via MSSQLSvc SPN)."),
        EdgeDef(kind=ek.MSSQL_SERVICE_ACCOUNT_FOR, start=nk.USER, end=nk.MSSQL_SERVER,
                description="Service account -> MSSQL Server (this account runs the service)."),
        EdgeDef(kind=ek.HAS_SESSION, start=nk.COMPUTER, end=nk.USER,
                description="DB host Computer has a session for the service account user."),
    ],
)

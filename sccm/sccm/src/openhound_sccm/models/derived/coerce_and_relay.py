"""CoerceAndRelay derived-edge schema placeholder.

Three flavours, all originating from the Authenticated Users group node:

  * SCCM_CoerceAndRelayToAdminService — auth users -> SCCM_Site (per site
    that has a Provider with NTLM unrestricted)
  * MSSQL_CoerceAndRelayToMSSQL       — auth users -> MSSQL_Login (per
    victim Computer with EPA Off on the site DB)
  * SCCM_CoerceAndRelayToSMB          — auth users -> Computer (per host
    with SMB signing not required)
  * SCCM_CoerceAndRelaytoSMB          — same set as above, lowercase 'to'
    (PS-typo'd duplicate kept for parity)

Materialised in ``sccm.coerce_and_relay_edges``; emitter is ``aggregator.py``.
"""

from __future__ import annotations

from openhound.core.asset import EdgeDef

from openhound_sccm.kinds import edges as ek
from openhound_sccm.kinds import nodes as nk

from ._placeholder import register_placeholder

SCCMCoerceAndRelayEdge = register_placeholder(
    name="SCCMCoerceAndRelayEdge",
    description="Schema-only placeholder for CoerceAndRelay edges; emitter in aggregator.py.",
    edges=[
        EdgeDef(kind=ek.COERCE_AND_RELAY_TO_ADMIN_SERVICE, start=nk.GROUP, end=nk.SCCM_SITE,
                description="Auth Users -> Site (NTLM relay to AdminService)."),
        EdgeDef(kind=ek.COERCE_AND_RELAY_TO_MSSQL, start=nk.GROUP, end=nk.MSSQL_LOGIN,
                description="Auth Users -> MSSQL_Login (NTLM relay to MSSQL with EPA Off)."),
        EdgeDef(kind=ek.COERCE_AND_RELAY_TO_SMB, start=nk.GROUP, end=nk.COMPUTER,
                description="Auth Users -> Computer (SMB relay to host with signing off)."),
        EdgeDef(kind=ek.COERCE_AND_RELAY_TO_SMB_LEGACY, start=nk.GROUP, end=nk.COMPUTER,
                description="PS-typo'd legacy form of CoerceAndRelayToSMB."),
    ],
)

"""MSSQL_Server node model.

Reads from the ``mssql_epa_flags`` DLT table. Yields one MSSQL_Server node per
host:port that responded to a TDS PRELOGIN probe on TCP/1433. The node id is
``<computer_SID>:1433`` (matching PS1's ConfigManBearPig.ps1 ~ line 6346). The
CMBP collector also produces this kind through both the registry path
(``RemoteRegistry-MultisiteComponentServers``) and the TDS path (``MSSQL-TDS``);
we use the EPA-flag table here because TDS prelogin is the authoritative
one-row-per-listening-server source.

Cross-cutting edges (MSSQL_HostFor, MSSQL_Contains, MSSQL_HasLogin, etc.)
live in ``models/derived/`` and are computed in Phase 4 from SQL views; this
model only emits the node itself.
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
class MSSQLServerProperties(SCCMNodeProperties):
    """Properties carried on every MSSQL_Server node.

    Property names mirror PS1's ConfigManBearPig.ps1 output for parity:
    ``dnsHostName`` (lowercase prefix), ``SQLServiceAccountName`` /
    ``SQLServiceAccountDomainSID`` (when WMI / AdminService surfaced the
    service identity), ``databases`` (comma-list of ``CM_<site>`` names),
    ``extendedProtection`` (PS1's ``Off`` / ``Allowed/Required`` string
    form rather than the boolean form CMBP/early-OH used), and the
    ``forceEncryption`` flag from the SQL server's
    ``SuperSocketNetLib::ForceEncryption`` registry value. Earlier OH
    versions used different names (``hostFQDN``, ``port``,
    ``mssqlExtendedProtectionForAuthentication``) — these are dropped to
    avoid duplicate-key noise; the PS1-style names are the canonical ones.
    """

    SQLServicePort: Optional[int] = field(default=1433, metadata={"description": "TCP port the SQL listener is bound to (always 1433 for default instance)"})
    dnsHostName: Optional[str] = field(default=None, metadata={"description": "FQDN of the host (PS1's lowercase-d convention)"})
    extendedProtection: Optional[str] = field(default=None, metadata={"description": "EPA mode as PS1 reports it: 'Off', 'Allowed', 'Required', 'Allowed/Required'"})
    forceEncryption: Optional[str] = field(default=None, metadata={"description": "SuperSocketNetLib::ForceEncryption — 'Yes' / 'No'"})
    SQLServiceAccountName: Optional[str] = field(default=None, metadata={"description": "sAMAccountName of the SQL service account (matches PS1)"})
    SQLServiceAccountDomainSID: Optional[str] = field(default=None, metadata={"description": "AD SID of the SQL service account (matches PS1)"})
    databases: Optional[str] = field(default=None, metadata={"description": "Comma-separated CM_<site_code> database names hosted on this server"})
    SCCMSite: Optional[str] = field(default=None, metadata={"description": "Primary site code this server's SCCM DB belongs to"})
    SCCMInfra: Optional[bool] = field(default=True, metadata={"description": "Marker that this is SCCM infrastructure"})


@app.asset(
    description="MSSQL Server node",
    node=NodeDef(
        kind=nk.MSSQL_SERVER,
        description="Microsoft SQL Server instance discovered via TDS PRELOGIN on TCP/1433",
        icon="database",
        properties=MSSQLServerProperties,
    ),
    edges=[],
)
class MSSQLServer(BaseAsset):
    """MSSQL_Server asset — one row per (hostname, port) from ``mssql_epa_flags``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # Raw fields from mssql_epa_flags JSONL
    hostname: str
    port: Optional[int] = 1433
    epa: Optional[str] = None
    epa_value: Optional[int] = None
    epa_enabled: Optional[bool] = None
    fqdn: Optional[str] = None
    domain: Optional[str] = None
    source: Optional[str] = "MSSQL-TDS"

    @property
    def as_node(self) -> SCCMNode:
        from ..log_context import trace_node
        port = self.port or 1433
        host = (self.hostname or "").lower()
        display = self.fqdn or host
        # PS1 keys MSSQL_Server nodes by the SQL host's AD computer SID,
        # not by FQDN. Look up the SID; if AD resolution fails (unlikely
        # but possible for offline hosts) fall back to the FQDN form so
        # something still gets emitted.
        computer_sid = self._lookup.computer_sid_by_hostname(host) if host else None
        node_id = f"{computer_sid}:{port}" if computer_sid else f"{host}:{port}"
        trace_node("MSSQL_Server", node_id, display)

        # Look up the PS1-style fields. ``adminservice_site_systems``
        # carries one row per (site_code, role, hostname, service_account)
        # for every site system surfaced by the SMS_SCI_SysResUse query;
        # the row for role ``SMS SQL Server`` at this host gives us the
        # site code, the service-account SAM, and (via a follow-up
        # principal lookup) its SID. The same row also lets us derive
        # ``CM_<site>`` for ``databases``.
        sql_site = None
        sql_service_account = None
        databases = None
        try:
            client = self._lookup.client
            schema = self._lookup.schema
            row = client.execute(
                f"SELECT site_code, service_account "
                f"FROM {schema}.adminservice_site_systems "
                f"WHERE LOWER(hostname) = ? AND LOWER(role) = 'sms sql server' "
                f"LIMIT 1",
                [host],
            ).fetchone()
            if row:
                sql_site = row[0] or None
                sql_service_account = (row[1] or "").strip() or None
                if sql_site:
                    databases = f"CM_{sql_site}"
        except Exception:
            pass

        # ``forceEncryption`` and (overriding) ``extendedProtection`` from
        # the SQL server's SuperSocketNetLib registry path, populated by
        # ``registry_mssql_settings``. When that probe didn't run (no
        # registry access, host offline) the values stay None and
        # ``extendedProtection`` falls back to the TDS-prelogin derived
        # label below.
        force_encryption = None
        registry_epa = None
        try:
            client = self._lookup.client
            schema = self._lookup.schema
            row = client.execute(
                f"SELECT force_encryption, extended_protection "
                f"FROM {schema}.registry_mssql_settings "
                f"WHERE LOWER(hostname) = ? "
                f"LIMIT 1",
                [host],
            ).fetchone()
            if row:
                force_encryption = row[0] or None
                registry_epa = row[1] or None
        except Exception:
            pass

        sql_service_sid = (
            self._lookup.principal_sid_by_account_name(sql_service_account)
            if sql_service_account
            else None
        )

        # ``extendedProtection`` precedence:
        #   1. ``registry_mssql_settings`` value (PS1's source of truth —
        #      reads the SuperSocketNetLib registry directly).
        #   2. ``mssql_epa_flags`` TDS-prelogin-derived integer (0/1/2).
        #   3. ``epa_enabled`` boolean fallback.
        # PS1 uses "Allowed/Required" specifically when ForceEncryption
        # is on with EPA mode 1 (Allowed) because the on-wire effect is
        # the same as Required; we don't replicate that compound string
        # here unless the registry path tells us so.
        epa_label = registry_epa
        if epa_label is None:
            ep_int = self.epa_value
            if ep_int == 0:
                epa_label = "Off"
            elif ep_int == 1:
                epa_label = "Allowed"
            elif ep_int == 2:
                epa_label = "Required"
            elif self.epa_enabled is True:
                epa_label = "Required"
            elif self.epa_enabled is False:
                epa_label = "Off"

        return SCCMNode(
            kinds=[nk.MSSQL_SERVER],
            properties=MSSQLServerProperties(
                node_id=node_id,
                name=f"{display}:{port}",
                displayname=f"{display}:{port}",
                environmentid=self.domain or None,
                dnsHostName=self.fqdn or host,
                SQLServicePort=port,
                extendedProtection=epa_label,
                forceEncryption=force_encryption,
                SQLServiceAccountName=(
                    (sql_service_account or "").split("\\", 1)[-1] or None
                ),
                SQLServiceAccountDomainSID=sql_service_sid,
                databases=databases,
                SCCMSite=sql_site,
                SCCMInfra=True,
                collectionSource=[self.source] if self.source else None,
            ),
        )

    @property
    def edges(self):
        return iter(())

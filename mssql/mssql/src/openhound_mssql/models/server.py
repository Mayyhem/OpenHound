"""``servers`` raw row -> ``MSSQL_Server`` node (collector.go createServerNode).

The MSSQL_Server node is the *root / environment* node: its id is the server
ObjectIdentifier, and that same id is the ``environmentid`` of every other node
in the graph. There is one ``servers`` row per collected target, so this asset
emits exactly one server node.

Property derivation follows Go ``createServerNode`` exactly, including the
conditional (only-present) keys. The canonical FQDN and the ``<fqdn>:<port>``
display name are resolved at COLLECT time (collection/server.py) and read here
verbatim from the row — convert never re-derives them from the tool host's
domain. Two further enrichments come from the preproc DuckDB via ``self._lookup``:

* the four ``domainPrincipalsWith{Sysadmin,ControlServer,Securityadmin,
  ImpersonateAnyLogin}`` arrays + ``isAnyDomainPrincipalSysadmin`` come from the
  ``effective_high_priv_summary`` table (``transforms`` already ran the nested-role
  / effective-permission BFS that the Go ``createServerNode`` does inline).
* the CVE-2025-49758 verdict comes from :func:`openhound_mssql.cve.check_cve_2025_49758`
  on the engine version.

CVE hyphen-key fix (D11 / spec §7): the four CVE properties are emitted with the
EXACT hyphenated keys MSSQLHound uses (``isVulnerableToCVE-2025-49758``,
``CVE-2025-49758_patchKB``, ``CVE-2025-49758_requiredVersion``,
``CVE-2025-49758_updateName``). ``graph.ServerProperties`` declares them with
underscores (hyphens aren't valid Python identifiers), so :data:`PROPERTY_KEY_REMAP`
tells ``convert_pipeline`` to rename them at emit time.
"""
from __future__ import annotations

import logging
from typing import Any, ClassVar, Optional

from openhound.core.asset import BaseAsset, NodeDef
from pydantic import ConfigDict

from ..cve import check_cve_2025_49758
from ..graph import MSSQLNode, ServerProperties
from ..kinds import nodes as nk
from ..main import app
from . import _common

logger = logging.getLogger(__name__)


@app.asset(
    node=NodeDef(
        kind=nk.SERVER,
        description="A Microsoft SQL Server instance (root/environment node).",
        icon=nk.ICONS[nk.SERVER]["name"],
        properties=ServerProperties,
        color=nk.ICONS[nk.SERVER]["color"],
    ),
    edges=[],
    description="MSSQL_Server node built from the raw servers table.",
)
class MSSQLServer(BaseAsset):
    """One raw ``servers`` row -> one ``MSSQL_Server`` OpenGraph node.

    Field names are dlt's snake_case normalization of the collected query columns
    (``ServerName`` -> ``server_name``, ``ProductVersion`` -> ``product_version``,
    the merged ``isMixedModeAuthEnabled`` -> ``is_mixed_mode_auth_enabled``, ...).
    ``extra="allow"`` lets any unexpected/version-specific column pass through.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    # Identity / version columns from SERVER_PROPERTIES (+ collect-time merges).
    server_name: Optional[str] = None              # SERVERPROPERTY('ServerName') -> sqlServerName
    machine_name: Optional[str] = None             # SERVERPROPERTY('MachineName') -> hostname
    instance_name: Optional[str] = None
    product_version: Optional[str] = None           # -> versionNumber
    product_level: Optional[str] = None
    edition: Optional[str] = None
    is_clustered: Optional[Any] = None
    full_version: Optional[str] = None              # @@VERSION banner -> version
    fqdn: Optional[str] = None                      # collect-time canonical FQDN
    sql_server_name_display: Optional[str] = None   # collect-time "<fqdn>:<port>"
    # Security columns merged onto the row in collection (server.py).
    is_mixed_mode_auth_enabled: Optional[Any] = None
    force_encryption: Optional[str] = None
    strict_encryption: Optional[str] = None
    extended_protection: Optional[str] = None
    service_account: Optional[str] = None

    # Rename the underscore CVE keys graph.py declares to MSSQLHound's exact
    # hyphenated spelling at emit time (convert_pipeline applies this).
    PROPERTY_KEY_REMAP: ClassVar[dict[str, str]] = {
        "isVulnerableToCVE_2025_49758": "isVulnerableToCVE-2025-49758",
        "CVE_2025_49758_updateName": "CVE-2025-49758_updateName",
        "CVE_2025_49758_patchKB": "CVE-2025-49758_patchKB",
        "CVE_2025_49758_requiredVersion": "CVE-2025-49758_requiredVersion",
    }

    @property
    def as_node(self) -> MSSQLNode | None:
        """Build the MSSQL_Server node (collector.go createServerNode)."""
        server_oid = _common.server_oid_for(self._lookup)
        if not server_oid:
            # No server context -> can't key the root node; drop it.
            logger.warning("MSSQLServer: dropping row with no derivable server_oid")
            return None

        hostname = (self.machine_name or "").split("\\", 1)[0]
        # Collect-time-resolved values; sql_server_name_for() reads them back from
        # the row (with fallbacks) so the name matches every node's SQLServer prop.
        fqdn = self.fqdn or hostname
        sql_server_name = _common.sql_server_name_for(self._lookup) or server_oid
        port = _common._DEFAULT_PORT

        props = ServerProperties(
            name=sql_server_name,
            displayname=sql_server_name,
            environmentid=server_oid,
            hostname=hostname,
            fqdn=fqdn,
            sqlServerName=self.server_name or "",   # original SQL Server name (short)
            version=self.full_version or "",
            versionNumber=self.product_version or "",
            edition=self.edition or "",
            productLevel=self.product_level or "",
            isClustered=_common.as_bool(self.is_clustered),
            port=port,
            isMixedModeAuthEnabled=_common.as_bool(self.is_mixed_mode_auth_enabled),
        )

        # instanceName: only present for a named instance (Go: if InstanceName != "").
        if self.instance_name:
            props.instanceName = self.instance_name

        # EPA verdicts: only present when collected (Go: if != "").
        if self.force_encryption:
            props.forceEncryption = self.force_encryption
        if self.strict_encryption:
            props.strictEncryption = self.strict_encryption
        if self.extended_protection:
            props.extendedProtection = self.extended_protection

        # CVE-2025-49758: verdict from the engine version. The bool is always set;
        # the metadata keys only when non-empty (matches Go createServerNode). The
        # underscore field names here are remapped to hyphens at emit time.
        self._apply_cve(props)

        # Service account: first account, NetBIOS prefix stripped (Go behavior).
        if self.service_account:
            props.serviceAccount = self._strip_netbios(self.service_account)

        # databases[]: names of online databases on this server.
        db_names = [
            row.get("name")
            for row in self._lookup.table_rows("databases")
            if row.get("name")
        ]
        if db_names:
            props.databases = db_names

        # linkedToServers[]: the names of every linked server configured here (Go
        # createServerNode reads info.LinkedServers[].Name). The recursive probe's
        # level-0 rows (source_server is this server) name the directly-configured
        # links; deeper rows are chained discoveries through remote hosts.
        linked_names: list[str] = []
        for row in self._lookup.table_rows("linked_server_flags"):
            if row.get("server_oid") != server_oid:
                continue
            name = row.get("linked_server")
            if name and name not in linked_names:
                linked_names.append(name)
        if linked_names:
            props.linkedToServers = linked_names

        # isLinkedServerTarget / hasLinksFromServers: set when a loopback link
        # resolves back to THIS server (Go createServerNode self-reference merge,
        # collector.go:2698-2711). The preproc server_link_self table carries the
        # flag for the collected server; absent => no self-link.
        self_row = next(
            (r for r in self._lookup.table_rows("server_link_self")
             if r.get("server_oid") == server_oid),
            None,
        )
        if self_row and _common.as_bool(self_row.get("isLinkedServerTarget")):
            props.isLinkedServerTarget = True
            props.hasLinksFromServers = list(self_row.get("hasLinksFromServers") or [server_oid])

        # servicePrincipalNames[] is populated in Stage 7 (SPN discovery). Left at
        # its empty default here so the key exists for the entity panel.

        # Effective high-priv enrichment from preproc (domainPrincipalsWith* +
        # isAnyDomainPrincipalSysadmin). transforms already ran the nested-role /
        # effective-permission BFS that Go createServerNode does inline.
        summary = self._lookup.effective_high_priv(server_oid)
        props.domainPrincipalsWithSysadmin = list(
            summary.get("domainPrincipalsWithSysadmin") or []
        )
        props.domainPrincipalsWithControlServer = list(
            summary.get("domainPrincipalsWithControlServer") or []
        )
        props.domainPrincipalsWithSecurityadmin = list(
            summary.get("domainPrincipalsWithSecurityadmin") or []
        )
        props.domainPrincipalsWithImpersonateAnyLogin = list(
            summary.get("domainPrincipalsWithImpersonateAnyLogin") or []
        )
        props.isAnyDomainPrincipalSysadmin = bool(
            summary.get("isAnyDomainPrincipalSysadmin")
        )

        return MSSQLNode(
            kinds=[nk.SERVER],
            properties=props,
            object_identifier=server_oid,
            icon=nk.ICONS[nk.SERVER],
        )

    @property
    def edges(self):
        """Server edges (Owns/HostFor/CoerceAndRelay/...) are Stages 6/7."""
        return iter(())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _apply_cve(self, props: ServerProperties) -> None:
        """Run the CVE-2025-49758 check and set the (underscore) CVE props.

        Prefers the numeric ProductVersion; falls back to the @@VERSION banner
        (matches Go ``CheckCVE202549758(info.VersionNumber, info.Version)``). An
        unparseable version yields a clean not-vulnerable verdict with no metadata
        (cve.check_cve_2025_49758 handles that), so the bool is always emitted.
        """
        version_input = self.product_version or self.full_version or ""
        verdict = check_cve_2025_49758(version_input)
        props.isVulnerableToCVE_2025_49758 = bool(verdict["vulnerable"])
        # Metadata keys only when non-empty (Go sets them conditionally).
        if verdict["update_name"]:
            props.CVE_2025_49758_updateName = verdict["update_name"]
        if verdict["patch_kb"]:
            props.CVE_2025_49758_patchKB = verdict["patch_kb"]
        if verdict["required_version"]:
            props.CVE_2025_49758_requiredVersion = verdict["required_version"]
        logger.debug(
            "MSSQLServer: CVE-2025-49758 vulnerable=%s (version=%r)",
            props.isVulnerableToCVE_2025_49758, version_input,
        )

    @staticmethod
    def _strip_netbios(account: str) -> str:
        """Strip a leading ``DOMAIN\\`` from a service account name (Go behavior)."""
        idx = account.find("\\")
        return account[idx + 1:] if idx != -1 else account


__all__ = ["MSSQLServer"]

"""SCCM_Site node model.

Reads from the ``ldap_sites`` DLT table. Yields one SCCM_Site node per
mSSMSSite object discovered in the System Management container.

Unlike Computer/User/Group, ``SCCM_Site`` is a platform-specific kind — it is
*not* an AD principal — so the kind list is just ``[SCCM_Site]`` (no ``Base``).

The node id is the site code itself (e.g. ``CAS``, ``PS1``). Phase 1 does no
ID rewriting; later phases will rewrite Collection / AdminUser / SecurityRole
ids to root-scoped values via the hierarchies table, but Site itself is
stable across the hierarchy.

Edges emitted from this model are limited to relationships derived from a
single site's own attributes (none in Phase 1 — the hierarchy-driven
``SCCM_AdminsReplicatedTo`` edges live in
``models/derived/admins_replicated_to.py``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar, Optional

from dlt.common.libs.pydantic import DltConfig
from openhound.core.asset import BaseAsset, NodeDef
from pydantic import ConfigDict

from openhound_sccm.graph import SCCMNode, SCCMNodeProperties
from openhound_sccm.kinds import nodes as nk
from openhound_sccm.log_context import trace_node
from openhound_sccm.main import app


@dataclass
class SCCMSiteProperties(SCCMNodeProperties):
    """Properties carried on every SCCM_Site node.

    ``siteCode``, ``parentSiteCode``, ``siteType`` and ``collectionSource`` are
    inherited from ``SCCMNodeProperties``. The remaining fields mirror the
    CMBP/PowerShell ``ConfigManBearPig.ps1`` property surface so existing
    BloodHound queries against CMBP-produced graphs work unchanged against
    OH-produced graphs.
    """

    siteGuid: Optional[str] = field(default=None, metadata={"description": "Site GUID parsed from mSSMSHealthState"})
    siteGUID: Optional[str] = field(default=None, metadata={"description": "Site GUID (CMBP/PS1 uppercase spelling)"})
    sourceForest: Optional[str] = field(default=None, metadata={"description": "Source forest reported by mSSMSSourceForest"})
    Type: str = field(default="SCCM_Site", metadata={"description": "Marker matching CMBP property"})
    displayName: Optional[str] = field(default=None, metadata={"description": "Human-readable site name from SMS_SCI_SiteDefinition.SiteName / SMS_Site.SiteName"})
    siteServerName: Optional[str] = field(default=None, metadata={"description": "FQDN of the primary site server (SMS_Site.ServerName)"})
    siteServerFQDN: Optional[str] = field(default=None, metadata={"description": "FQDN of the primary site server (PS1 alias)"})
    siteServerDomainSID: Optional[str] = field(default=None, metadata={"description": "AD SID of the primary site server's computer account"})
    SQLServerName: Optional[str] = field(default=None, metadata={"description": "FQDN of the MSSQL server hosting the site DB (SMS_SCI_SiteDefinition.SQLServerName)"})
    SQLServerFQDN: Optional[str] = field(default=None, metadata={"description": "FQDN of the MSSQL server (PS1 alias)"})
    SQLDatabaseName: Optional[str] = field(default=None, metadata={"description": "Name of the CM_<site> database"})
    SQLServerDomainSID: Optional[str] = field(default=None, metadata={"description": "AD SID of the SQL server's computer account"})
    SQLServicePort: Optional[str] = field(default=None, metadata={"description": "TCP port the SQL service listens on (CMBP/PS1 emit as string, e.g. '1433')"})
    SQLServiceAccountName: Optional[str] = field(default=None, metadata={"description": "Bare sAMAccountName of the SQL service account (no DOMAIN\\ prefix)"})
    SQLServiceAccountDomainSID: Optional[str] = field(default=None, metadata={"description": "AD SID of the SQL service account"})
    reportToSite: Optional[str] = field(default=None, metadata={"description": "SMS_SCI_SiteDefinition.ReportingSiteCode — parent site in the hierarchy"})
    rootSiteCode: Optional[str] = field(default=None, metadata={"description": "Hierarchy root site code (CAS for CAS-led hierarchies, else self)"})
    SCCMInfra: bool = field(default=True, metadata={"description": "Marker that this is SCCM infrastructure (always True for a Site)"})
    version: Optional[str] = field(default=None, metadata={"description": "SCCM site version from SMS_Site.Version"})
    buildNumber: Optional[int] = field(default=None, metadata={"description": "SCCM build number parsed from version (e.g. 9106 from '5.00.9106.1000'). CMBP/PS1 emit as int."})
    versionCVEs: Optional[list[str]] = field(default=None, metadata={"description": "Known CVEs for this site version (computed from version + CVE table)"})
    installDir: Optional[str] = field(default=None, metadata={"description": "SMS_Site.InstallDir — site server installation directory"})
    siteSystemRoles: Optional[list[str]] = field(default=None, metadata={"description": "List of 'RoleName@hostname' entries for site systems serving this site"})
    adminUsers: Optional[list[str]] = field(default=None, metadata={"description": "List of admin user logon names assigned to this site"})
    storedAccounts: Optional[list[str]] = field(default=None, metadata={"description": "List of stored account names (SMS_SCI_Reserved) for this site"})


@app.asset(
    description="SCCM Site node",
    node=NodeDef(
        kind=nk.SCCM_SITE,
        description="SCCM site discovered via the System Management container in AD",
        icon="server",
        properties=SCCMSiteProperties,
    ),
    edges=[],
)
class SCCMSite(BaseAsset):
    """SCCMSite asset — one row per mSSMSSite from ``ldap_sites``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # Raw fields from ldap_sites JSONL
    site_code: str
    site_guid: Optional[str] = None
    distinguished_name: Optional[str] = None
    source_forest: Optional[str] = None
    site_type: Optional[str] = None
    parent_site_code: Optional[str] = None
    # Properties folded in from the ldap_sites AdminService fold-in
    # (SMS_Site / SMS_SCI_SiteDefinition / SMS_SCI_SysResUse). SID fields
    # are NOT folded in at collector time — they're resolved against
    # ldap_computers / ldap_users at convert time via ``_lookup`` below.
    display_name: Optional[str] = None
    site_server_name: Optional[str] = None
    sql_server_name: Optional[str] = None
    sql_database_name: Optional[str] = None
    sql_service_account_name: Optional[str] = None
    version: Optional[str] = None
    collection_source: Optional[list[str]] = None

    @property
    def as_node(self) -> SCCMNode:
        trace_node(nk.SCCM_SITE, self.site_code, self.display_name or self.site_code)
        # `_lookup` is injected by the framework at convert time, but parity
        # tests instantiate SCCMSite without one — keep the outer `_lookup is
        # not None` guard so `test_sccm_site_node_tolerates_missing_enrichment`
        # keeps passing. Inside the guard, calls are direct (lookup methods
        # already handle missing-table cases internally and return None / empty).
        lookup = getattr(self, "_lookup", None)

        # AdminService-derived enrichment (display name, site server, SQL host
        # / db / service account, version, site type, parent site code). The
        # Phase 1 ``ldap_sites`` collector emits these as ``None`` because
        # AdminService doesn't run until Phase 7; we resolve them here from
        # the AdminService DLT tables that Phase 7 wrote. If the row already
        # carries a value (e.g. from a future collector that fills it in),
        # the row wins — the lookup is only a fallback.
        display_name = self.display_name
        site_server_name = self.site_server_name
        sql_server_name = self.sql_server_name
        sql_database_name = self.sql_database_name
        sql_service_account_name = self.sql_service_account_name
        version = self.version
        site_type = self.site_type
        parent_site_code = self.parent_site_code
        install_dir: Optional[str] = None
        if lookup is not None:
            (
                e_display,
                e_server,
                e_sql_server,
                e_sql_db,
                e_sql_svc,
                e_version,
                e_type,
                e_parent,
                e_install_dir,
            ) = lookup.admin_enrichment_for_site(self.site_code)
            display_name = display_name or e_display
            site_server_name = site_server_name or e_server
            sql_server_name = sql_server_name or e_sql_server
            sql_database_name = sql_database_name or e_sql_db
            sql_service_account_name = sql_service_account_name or e_sql_svc
            version = version or e_version
            site_type = site_type or e_type
            parent_site_code = parent_site_code or e_parent
            install_dir = e_install_dir

        # versionCVEs — computed from version via the CMBP-derived CVE table.
        version_cves: Optional[list[str]] = None
        build_number: Optional[int] = None
        if version:
            from openhound_sccm.cve_table import lookup_cves
            version_cves = lookup_cves(version) or None
            # buildNumber is the 3rd dotted segment of version "5.00.9106.1000" → 9106
            # (int per CMBP/PS1).
            parts = version.split(".")
            if len(parts) >= 3 and parts[2].isdigit():
                build_number = int(parts[2])

        site_server_sid: Optional[str] = None
        sql_server_sid: Optional[str] = None
        sql_service_account_sid: Optional[str] = None
        root_site_code: Optional[str] = None
        site_system_roles: Optional[list[str]] = None
        admin_users: Optional[list[str]] = None
        stored_accounts: Optional[list[str]] = None
        if lookup is not None:
            if site_server_name:
                site_server_sid = lookup.computer_sid_by_hostname(site_server_name)
            if sql_server_name:
                sql_server_sid = lookup.computer_sid_by_hostname(sql_server_name)
            root_site_code = lookup.hierarchy_root(self.site_code) or self.site_code
            roles = lookup.site_system_roles_for_site(self.site_code)
            site_system_roles = list(roles) if roles else None
            a = lookup.admin_user_logon_names_for_site(self.site_code)
            admin_users = list(a) if a else None
            s = lookup.stored_account_labels_for_site(self.site_code)
            stored_accounts = list(s) if s else None
            # Merge in additional collection-source tags surfaced by
            # convert-time joins against non-AdminService tables
            # (RemoteRegistry, Local-SMS_Authority, SMS_SCI_Reserved)
            # plus AdminService-SMS_Sites / -SMS_SCI_SiteDefinition tags
            # for LDAP-discovered sites that also surface via Phase 7.
            extras = lookup.extra_collection_sources_for_site(self.site_code)
            if extras:
                existing = list(self.collection_source or [])
                for tag in extras:
                    if tag not in existing:
                        existing.append(tag)
                # Overwrite in-place; the dataclass field is bound below.
                object.__setattr__(self, "collection_source", existing)

        # SQL service account normalization. PS1 emits the bare sAMAccountName,
        # except for Secondary sites where SCCM reports "LocalSystem" — in that
        # case the actual SQL service runs as the site server's machine account
        # (``<HOSTNAME>$``). Map that explicitly so SEC sites match CMBP/PS1.
        sql_svc_bare: Optional[str] = sql_service_account_name
        if sql_svc_bare and "\\" in sql_svc_bare:
            sql_svc_bare = sql_svc_bare.split("\\", 1)[-1]
        if sql_svc_bare and sql_svc_bare.lower() == "localsystem" and site_server_name:
            short = site_server_name.split(".", 1)[0]
            sql_svc_bare = f"{short.upper()}$"
        # Now resolve SID for the (possibly remapped) account.
        if lookup is not None and sql_svc_bare:
            sql_service_account_sid = lookup.principal_sid_by_account_name(sql_svc_bare)

        # parentSiteCode default — PS1 emits the literal string "None" when a
        # site has no parent (CAS root). Match that convention so BloodHound
        # queries that filter on parentSiteCode == 'None' work.
        parent_value: Optional[str] = parent_site_code if parent_site_code else "None"

        display = display_name or self.site_code
        return SCCMNode(
            kinds=[nk.SCCM_SITE],
            properties=SCCMSiteProperties(
                node_id=self.site_code,
                name=self.site_code,
                displayname=display,
                environmentid=self.site_code,
                siteCode=self.site_code,
                parentSiteCode=parent_value,
                rootSiteCode=root_site_code,
                siteType=site_type,
                siteGuid=self.site_guid,
                siteGUID=self.site_guid,
                sourceForest=self.source_forest,
                Type="SCCM_Site",
                distinguishedName=self.distinguished_name,
                displayName=display_name,
                siteServerName=site_server_name,
                siteServerFQDN=site_server_name,
                siteServerDomainSID=site_server_sid,
                SQLServerName=sql_server_name,
                SQLServerFQDN=sql_server_name,
                SQLDatabaseName=sql_database_name,
                SQLServerDomainSID=sql_server_sid,
                SQLServicePort="1433",
                SQLServiceAccountName=sql_svc_bare,
                SQLServiceAccountDomainSID=sql_service_account_sid,
                reportToSite=parent_site_code,
                SCCMInfra=True,
                collectionSource=self.collection_source,
                version=version,
                buildNumber=build_number,
                versionCVEs=version_cves,
                installDir=install_dir,
                siteSystemRoles=site_system_roles,
                adminUsers=admin_users,
                storedAccounts=stored_accounts,
            ),
        )

    @property
    def edges(self):
        # Site-only edges (none right now; SCCM_AdminsReplicatedTo lives in
        # models/derived/admins_replicated_to.py and reads the materialised
        # sccm.admins_replicated_to_edges view from transforms.py).
        return iter(())

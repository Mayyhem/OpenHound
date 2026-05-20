"""Computer node model.

Reads from the ``ldap_computers`` DLT table. Yields one Computer node per AD
computer account, with kinds=[Computer, Base] to match ConfigManBearPig output.

Edges emitted from this model are limited to relationships that derive *only*
from a single computer's own attributes. Cross-cutting edges
(LocalAdminRequired, CoerceAndRelay*, SameHostAs, etc.) live in
``models/derived/`` and consume materialised SQL views.
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
class ComputerProperties(SCCMNodeProperties):
    """Properties carried on every Computer node.

    Field names match the camelCase used by ConfigManBearPig's output so the
    test runner's wildcard patterns (e.g. ``dNSHostName: cas-pss.$Domain``)
    match unchanged.

    Attributes:
        objectGuid: AD objectGUID.
        operatingSystem: Operating system from AD.
        operatingSystemVersion: OS version from AD.
        servicePrincipalName: AD SPNs.
        networkBootServer: Whether this computer is a PXE-enabled DP.
        Type: Marker matching CMBP property (always "Computer").
        domain: AD domain (NetBIOS or DNS).
        SCCMInfra: True when this Computer hosts an SCCM site system / DP / MP / SMS Provider role.
        SCCMSiteSystemRoles: List of 'RoleName@SiteCode' entries from SMS_SCI_SysResUse.
    """

    objectGuid: Optional[str] = field(default=None, metadata={"description": "AD objectGUID"})
    operatingSystem: Optional[str] = field(default=None, metadata={"description": "Operating system from AD"})
    operatingSystemVersion: Optional[str] = field(default=None, metadata={"description": "OS version from AD"})
    servicePrincipalName: Optional[list[str]] = field(default=None, metadata={"description": "AD SPNs"})
    networkBootServer: Optional[bool] = field(default=None, metadata={"description": "Whether this computer is a PXE-enabled DP"})
    Type: Optional[str] = field(default="Computer", metadata={"description": "Marker matching CMBP property"})
    SCCMInfra: Optional[bool] = field(default=None, metadata={"description": "True when this Computer hosts an SCCM site system / DP / MP / SMS Provider role"})
    SCCMSiteSystemRoles: Optional[list[str]] = field(default=None, metadata={"description": "List of 'RoleName@SiteCode' entries from SMS_SCI_SysResUse"})
    # PS1-style property names for AD-derived Computer fields. PS1 emits
    # ``Domain``, ``SamAccountName``, ``DNSHostName``, ``Enabled``,
    # ``IsDomainPrincipal``, ``CN`` on Computer nodes (PascalCase /
    # uppercase). The base ``SCCMNodeProperties`` declares
    # ``samAccountName`` / ``dNSHostName`` / ``enabled`` /
    # ``isDomainPrincipal`` for use by SCCM-namespace kinds; we override
    # here with the AD-namespace spellings PS1 uses and leave the base
    # fields ``None`` so they don't double-emit.
    Domain: Optional[str] = field(default=None, metadata={"description": "AD domain (PS1 PascalCase form)"})
    SamAccountName: Optional[str] = field(default=None, metadata={"description": "sAMAccountName (PS1 PascalCase form)"})
    DNSHostName: Optional[str] = field(default=None, metadata={"description": "dNSHostName (PS1 PascalCase form)"})
    Enabled: Optional[bool] = field(default=None, metadata={"description": "Whether the AD account is enabled (PS1 PascalCase form)"})
    IsDomainPrincipal: Optional[bool] = field(default=None, metadata={"description": "Whether this principal is sourced from AD (PS1 PascalCase form)"})
    CN: Optional[str] = field(default=None, metadata={"description": "Common name (last RDN of distinguishedName)"})
    objectClass: Optional[list[str]] = field(default=None, metadata={"description": "AD objectClass list"})
    SCCMHasClientRemoteControlSPN: Optional[bool] = field(default=None, metadata={"description": "True when the computer has the CmRcService SPN registered (PS1 form)"})
    SMBSigningRequired: Optional[bool] = field(default=None, metadata={"description": "Whether the host requires SMB signing (PS1 form)"})
    SCCMHostsContentLibrary: Optional[bool] = field(default=None, metadata={"description": "True when the host exposes the SCCMContentLib$ SMB share (Distribution Point indicator)"})
    SCCMIsPXESupportEnabled: Optional[bool] = field(default=None, metadata={"description": "True when the host is configured as a PXE-enabled DP"})
    SCCMResourceIDs: Optional[list[str]] = field(default=None, metadata={"description": "List of ResourceID@SiteCode strings for the device's SMS_R_System resources"})
    SCCMClientDeviceIdentifier: Optional[str] = field(default=None, metadata={"description": "GUID:<smsGuid> of the matched SCCM_ClientDevice, when the computer is also an SCCM client"})
    disableLoopbackCheck: Optional[str] = field(default=None, metadata={"description": "LSA DisableLoopbackCheck setting (PS1 string form: 'Enabled' / 'Disabled')"})
    restrictReceivingNtlmTraffic: Optional[str] = field(default=None, metadata={"description": "LSA MSV1_0 RestrictReceivingNtlmTraffic setting (PS1 string form: 'Off' / 'Deny_All' / 'Deny_Inbound_Explicit')"})
    SCCMClientCertificateRequired: Optional[bool] = field(default=None, metadata={"description": "True when the management point's SMSTRC endpoint returned 403 (client certificate required)"})


@app.asset(
    description="AD Computer node",
    node=NodeDef(
        kind=nk.COMPUTER,
        description="Active Directory computer account discovered via LDAP",
        icon="desktop",
        properties=ComputerProperties,
    ),
    edges=[],
)
class Computer(BaseAsset):
    """Computer asset — one row per AD computer account from ``ldap_computers``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    # Raw fields from ldap_computers JSONL
    object_sid: str
    object_guid: Optional[str] = None
    sam_account_name: Optional[str] = None
    name: Optional[str] = None
    distinguished_name: Optional[str] = None
    dns_host_name: Optional[str] = None
    operating_system: Optional[str] = None
    operating_system_version: Optional[str] = None
    enabled: Optional[bool] = None
    service_principal_names: Optional[list[str]] = None
    member_of_dns: Optional[list[str]] = None
    primary_group_id: Optional[int] = None
    source: Optional[str] = "LDAP"
    domain: Optional[str] = None

    @property
    def as_node(self) -> SCCMNode:
        from ..log_context import trace_node_with_properties
        display = self.name or (self.sam_account_name or "").rstrip("$") or self.object_sid
        # Look up SCCM-infra role membership at convert time so the
        # output-stage prune can keep this Computer when there's no
        # SCCM_AdminUser node (e.g. low-priv runs). The lookup probes
        # smb_site_servers / smb_distribution_points / http_*_points /
        # ldap_sms_providers and returns True if any row matches.
        sccm_infra = self._lookup.computer_is_sccm_infra(self.object_sid, self.dns_host_name) or None
        roles = self._lookup.computer_site_system_roles(self.object_sid, self.dns_host_name)
        sccm_site_system_roles = list(roles) if roles else None
        # ``CN`` — first RDN of the distinguishedName (e.g.
        # ``CN=PS1-MP,OU=Site Servers,...`` → ``PS1-MP``). PS1 emits this
        # alongside ``name`` on every Computer node.
        cn: Optional[str] = None
        if self.distinguished_name:
            first = self.distinguished_name.split(",", 1)[0]
            if first.upper().startswith("CN="):
                cn = first[3:] or None

        # SCCMHasClientRemoteControlSPN — true when the computer carries
        # the ``CmRcService/*`` SPN (registered by the SCCM client agent
        # at install time). PS1 emits this as a marker for cmrc-synth
        # candidates.
        has_cmrc_spn: Optional[bool] = None
        if self.service_principal_names:
            spns = self.service_principal_names if isinstance(self.service_principal_names, list) else [self.service_principal_names]
            has_cmrc_spn = any(
                str(s).lower().startswith("cmrcservice/") for s in spns
            ) or None

        # SMBSigningRequired — joined in from the SMB probe table. The
        # smb_signing_status row carries a ``signing_required`` boolean
        # per hostname.
        smb_signing: Optional[bool] = None
        # SCCMHostsContentLibrary / SCCMIsPXESupportEnabled — joined from
        # ``smb_distribution_points`` which carries both flags per host.
        hosts_content_library: Optional[bool] = None
        is_pxe_enabled: Optional[bool] = None
        # SCCMResourceIDs / SCCMClientDeviceIdentifier — looked up from
        # ``adminservice_client_devices`` by AD object SID. The same
        # computer may have multiple ResourceID@SiteCode entries (one per
        # SMS Provider that surfaced it).
        sccm_resource_ids: Optional[list[str]] = None
        sccm_client_device_id: Optional[str] = None
        try:
            client = self._lookup.client
            schema = self._lookup.schema
            row = client.execute(
                f"SELECT signing_required FROM {schema}.smb_signing_status "
                f"WHERE LOWER(hostname) = LOWER(?) LIMIT 1",
                [self.dns_host_name or ""],
            ).fetchone()
            if row and row[0] is not None:
                smb_signing = bool(row[0])
        except Exception:
            pass
        try:
            row = client.execute(
                f"SELECT hosts_content_library, is_pxe_enabled "
                f"FROM {schema}.smb_distribution_points "
                f"WHERE LOWER(hostname) = LOWER(?) LIMIT 1",
                [self.dns_host_name or ""],
            ).fetchone()
            if row:
                if row[0] is not None:
                    hosts_content_library = bool(row[0])
                if row[1] is not None:
                    is_pxe_enabled = bool(row[1])
            else:
                # PS1 emits these on every host the SMB enumeration block
                # reached, defaulting to False (ConfigManBearPig.ps1 lines
                # 9161 / 9169). `smb_signing_status` is the rowset of SMB-
                # reached hosts in OH, so use it as the "False" indicator
                # when the host wasn't found in smb_distribution_points.
                reached = client.execute(
                    f"SELECT 1 FROM {schema}.smb_signing_status "
                    f"WHERE LOWER(hostname) = LOWER(?) LIMIT 1",
                    [self.dns_host_name or ""],
                ).fetchone()
                if reached:
                    hosts_content_library = False
                    is_pxe_enabled = False
        except Exception:
            pass

        # PS1 also flips ``networkBootServer=True`` when an
        # ``(&(objectclass=connectionPoint)(netbootserver=*))`` or
        # ``(objectclass=intellimirrorSCP)`` object exists under the
        # computer's DN (ConfigManBearPig.ps1:3367-3371). This is an
        # LDAP-only signal — independent of the SMB DP probe — so a
        # caller running ``-m LDAP`` still gets PXE-DP marking. Join by
        # parent DN against ``ldap_network_boot_servers``.
        try:
            if self.distinguished_name:
                nbs_row = client.execute(
                    f"SELECT 1 FROM {schema}.ldap_network_boot_servers "
                    f"WHERE LOWER(parent_dn) = LOWER(?) LIMIT 1",
                    [self.distinguished_name],
                ).fetchone()
                if nbs_row:
                    # Promote to True regardless of what SMB said. If SMB
                    # contradicted (returned False), the LDAP evidence is
                    # at least as strong — PS1 unconditionally sets True.
                    is_pxe_enabled = True
        except Exception:
            pass

        # LSA registry settings populated by ``registry_mssql_settings``.
        # OH only probes SQL hosts (matching PS1's emission scope), so
        # most Computer nodes leave these None.
        disable_loopback: Optional[str] = None
        restrict_ntlm: Optional[str] = None
        try:
            row = client.execute(
                f"SELECT disable_loopback_check, restrict_receiving_ntlm_traffic "
                f"FROM {schema}.registry_mssql_settings "
                f"WHERE LOWER(hostname) = LOWER(?) LIMIT 1",
                [self.dns_host_name or ""],
            ).fetchone()
            if row:
                disable_loopback = row[0] or None
                restrict_ntlm = row[1] or None
        except Exception:
            pass

        # SCCMClientCertificateRequired — PS1 sets this on every host
        # confirmed as a Management Point, Distribution Point, or SMS
        # Provider (ConfigManBearPig.ps1 lines 8714-8881). The value is
        # True if any probed endpoint on the host returned 403 (the
        # signal that the IIS site requires client certificates); False
        # otherwise. None when the host isn't confirmed in any of the
        # three HTTP role tables.
        sccm_client_cert_required: Optional[bool] = None
        try:
            host_needle = self.dns_host_name or ""
            confirmed = False
            any_403 = False
            for table, col in (
                ("http_management_points", "hostname"),
                ("http_distribution_points", "hostname"),
                ("http_smsproviders", "hostname"),
            ):
                row = client.execute(
                    f"SELECT MAX(CASE WHEN status = 403 THEN 1 ELSE 0 END) "
                    f"FROM {schema}.{table} "
                    f"WHERE LOWER({col}) = LOWER(?)",
                    [host_needle],
                ).fetchone()
                if row and row[0] is not None:
                    confirmed = True
                    if row[0] == 1:
                        any_403 = True
            if confirmed:
                sccm_client_cert_required = any_403
        except Exception:
            pass
        try:
            rows = client.execute(
                f"SELECT DISTINCT resource_id, site_code, guid "
                f"FROM {schema}.adminservice_client_devices "
                f"WHERE ad_object_sid = ? "
                f"  AND resource_id IS NOT NULL AND site_code IS NOT NULL "
                f"ORDER BY site_code, resource_id",
                [self.object_sid],
            ).fetchall()
            if rows:
                sccm_resource_ids = [f"{rid}@{sc}" for rid, sc, _g in rows]
                # SCCMClientDeviceIdentifier picks the first non-empty guid.
                for _rid, _sc, g in rows:
                    if g:
                        sccm_client_device_id = f"GUID:{g}"
                        break
        except Exception:
            pass
        # SMS_R_System fan-out — PS1 emits SCCMResourceIDs on every Computer
        # that AdminService's SMS_R_System discovered (lines 7360-7365 of
        # ConfigManBearPig.ps1), including AD-pushed hosts without a CCM
        # client. ``adminservice_client_devices`` only contains SCCM clients,
        # so non-client hosts (DC, WAC, HYPER-V) need the R_System fallback.
        try:
            sam = (self.sam_account_name or "").rstrip("$")
            if sam:
                rs_rows = client.execute(
                    f"SELECT DISTINCT resource_id, site_code "
                    f"FROM {schema}.adminservice_r_system_security_groups "
                    f"WHERE UPPER(machine_name) = UPPER(?) "
                    f"  AND resource_id IS NOT NULL AND site_code IS NOT NULL "
                    f"ORDER BY site_code, resource_id",
                    [sam],
                ).fetchall()
                if rs_rows:
                    extra = [f"{rid}@{sc}" for rid, sc in rs_rows]
                    if sccm_resource_ids:
                        # Merge + dedupe, preserve order
                        seen = set(sccm_resource_ids)
                        for e in extra:
                            if e not in seen:
                                sccm_resource_ids.append(e)
                                seen.add(e)
                    else:
                        sccm_resource_ids = extra
        except Exception:
            pass

        # Build the per-Computer collectionSource list. ``self.source`` carries
        # the discovery channel that produced this LDAP row; we then fold in
        # additional sources that other resources contributed:
        #   * ``LDAP-connectionPoint`` / ``LDAP-intellimirrorSCP`` — when this
        #     Computer is the parent of a network-boot SCP object
        #     (ldap_network_boot_servers).
        #   * ``LDAP-GenericAllSystemManagement`` — when this Computer's SID
        #     appears in the System Management container's DACL with
        #     GenericAll rights (ldap_system_management_acl).
        # Both gates mirror PS1's per-source collectionSource fan-out so
        # downstream queries against the array see the same values.
        collection_sources: list[str] = []
        if self.source:
            collection_sources.append(self.source)
        try:
            if self.distinguished_name:
                for (src,) in client.execute(
                    f"SELECT DISTINCT source FROM {schema}.ldap_network_boot_servers "
                    f"WHERE LOWER(parent_dn) = LOWER(?)",
                    [self.distinguished_name],
                ).fetchall():
                    if src and src not in collection_sources:
                        collection_sources.append(src)
        except Exception:
            pass
        try:
            acl_row = client.execute(
                f"SELECT 1 FROM {schema}.ldap_system_management_acl "
                f"WHERE principal_sid = ? LIMIT 1",
                [self.object_sid],
            ).fetchone()
            if acl_row and "LDAP-GenericAllSystemManagement" not in collection_sources:
                collection_sources.append("LDAP-GenericAllSystemManagement")
        except Exception:
            pass

        props = ComputerProperties(
            node_id=self.object_sid,
            name=display,
            displayname=display,
            environmentid=self.domain or None,
            distinguishedName=self.distinguished_name,
            objectGuid=self.object_guid,
            operatingSystem=self.operating_system,
            operatingSystemVersion=self.operating_system_version,
            servicePrincipalName=self.service_principal_names,
            collectionSource=collection_sources or None,
            Type="Computer",
            # PS1-style PascalCase names — leave the base-class
            # camelCase ones None so they don't double-emit.
            Domain=self.domain,
            SamAccountName=self.sam_account_name,
            DNSHostName=self.dns_host_name,
            Enabled=self.enabled,
            IsDomainPrincipal=True,
            CN=cn,
            objectClass=["top", "person", "organizationalPerson", "user", "computer"],
            SCCMHasClientRemoteControlSPN=has_cmrc_spn,
            SMBSigningRequired=smb_signing,
            SCCMHostsContentLibrary=hosts_content_library,
            SCCMIsPXESupportEnabled=is_pxe_enabled,
            # PS1 also surfaces ``networkBootServer`` as a synonym
            # for ``SCCMIsPXESupportEnabled`` (both reflect WDS/PXE).
            networkBootServer=is_pxe_enabled,
            SCCMResourceIDs=sccm_resource_ids,
            SCCMClientDeviceIdentifier=sccm_client_device_id,
            disableLoopbackCheck=disable_loopback,
            restrictReceivingNtlmTraffic=restrict_ntlm,
            SCCMClientCertificateRequired=sccm_client_cert_required,
            SCCMInfra=sccm_infra,
            SCCMSiteSystemRoles=sccm_site_system_roles,
        )
        trace_node_with_properties("Computer", self.object_sid, display, props)
        return SCCMNode(kinds=[nk.COMPUTER, nk.BASE], properties=props)

    @property
    def edges(self):
        # Computer-only edges (none right now; MemberOf comes from group_membership.py;
        # cross-cutting edges live in models/derived/).
        return iter(())

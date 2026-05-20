"""SCCM_ClientDevice node model.

Reads from the ``adminservice_client_devices`` DLT table (one row per
``SMS_R_System`` resource returned by the AdminService REST API).
Yields one ``SCCM_ClientDevice`` node per row.

Unlike Collections / AdminUsers / SecurityRoles, client devices are NOT
site-scoped in the global id sense - they are physical hosts that exist
once across the hierarchy regardless of which site reports them. The id
is therefore ``GUID:<resource_guid>`` and no hierarchy rewrite is applied.
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
class SCCMClientDeviceProperties(SCCMNodeProperties):
    """Properties carried on every SCCM_ClientDevice node.

    Names mirror PS1's ConfigManBearPig output: ``primaryUser`` /
    ``primaryUserSID`` from ``SMS_CombinedDeviceResources.PrimaryUser``,
    ``currentLogonUser`` / ``currentLogonUserSID`` from
    ``SMS_CombinedDeviceResources.CurrentLogonUser``, ``ADLastLogonUser``
    / ``ADLastLogonUserSID`` / ``ADLastLogonUserDomain`` from
    ``SMS_R_System.LastLogonUserName`` (split on ``\\``), plus the
    bare ``userName`` / ``userDomainName`` decomposition of
    ``LastLogonUser``. ``SMSID`` mirrors PS1's ``"GUID:<guid>"`` form
    (same as the node id). ``resourceID`` is rewritten as
    ``"<id>@<site>"`` for cross-site duplicate retention.
    """

    resourceID: Optional[str] = field(default=None, metadata={"description": "ResourceID@SiteCode from SMS_R_System (PS1 format)"})
    machineName: Optional[str] = field(default=None, metadata={"description": "Name reported by SMS_R_System"})
    SMSID: Optional[str] = field(default=None, metadata={"description": "GUID:<smsGuid> identifier (PS1 form)"})
    smsGUID: Optional[str] = field(default=None, metadata={"description": "Raw SMSUniqueIdentifier"})
    isClient: Optional[bool] = field(default=None, metadata={"description": "Whether the resource is an active client"})
    clientVersion: Optional[str] = field(default=None, metadata={"description": "Reported ClientVersion"})
    ADDomainSID: Optional[str] = field(default=None, metadata={"description": "AD computer SID matched via ad_object_sid"})
    primaryUser: Optional[str] = field(default=None, metadata={"description": "DOMAIN\\sam of the primary user"})
    primaryUserSID: Optional[str] = field(default=None, metadata={"description": "AD SID of the primary user"})
    currentLogonUser: Optional[str] = field(default=None, metadata={"description": "DOMAIN\\sam of the user currently logged on"})
    currentLogonUserSID: Optional[str] = field(default=None, metadata={"description": "AD SID of the currently-logged-on user"})
    ADLastLogonUser: Optional[str] = field(default=None, metadata={"description": "Bare SAM of the last AD logon"})
    ADLastLogonUserSID: Optional[str] = field(default=None, metadata={"description": "AD SID of the last-logon user"})
    ADLastLogonUserDomain: Optional[str] = field(default=None, metadata={"description": "Domain prefix of the last-logon user"})
    userName: Optional[str] = field(default=None, metadata={"description": "Bare SAM (PS1's userName field — same as ADLastLogonUser)"})
    userDomainName: Optional[str] = field(default=None, metadata={"description": "Domain prefix (PS1's userDomainName)"})
    sourceSiteCode: Optional[str] = field(default=None, metadata={"description": "Site code that surfaced the device"})
    collectionIds: Optional[list[str]] = field(default=None, metadata={"description": "List of CollectionID@SiteCode strings the device is a member of (PS1 form)"})
    collectionNames: Optional[list[str]] = field(default=None, metadata={"description": "Display names of the same collections"})
    deviceOS: Optional[str] = field(default=None, metadata={"description": "OS name reported by SMS_CombinedDeviceResources"})
    deviceOSBuild: Optional[str] = field(default=None, metadata={"description": "OS build reported by SMS_CombinedDeviceResources"})
    lastActiveTime: Optional[str] = field(default=None, metadata={"description": "SMS_CombinedDeviceResources.LastActiveTime"})
    lastOnlineTime: Optional[str] = field(default=None, metadata={"description": "SMS_CombinedDeviceResources.LastOnlineTime"})
    lastOfflineTime: Optional[str] = field(default=None, metadata={"description": "SMS_CombinedDeviceResources.LastOfflineTime"})
    lastReportedMPServerName: Optional[str] = field(default=None, metadata={"description": "Management point that last reported this device"})
    lastReportedMPServerSID: Optional[str] = field(default=None, metadata={"description": "AD SID of the management point that last reported this device"})
    currentManagementPoint: Optional[str] = field(default=None, metadata={"description": "Currently assigned MP server FQDN"})
    currentManagementPointSID: Optional[str] = field(default=None, metadata={"description": "AD SID of the currently assigned MP server"})
    previousSMSID: Optional[str] = field(default=None, metadata={"description": "Previous SMSID prior to the most recent change"})
    previousSMSIDChangeDate: Optional[str] = field(default=None, metadata={"description": "Timestamp the SMSID last changed"})
    DNSHostName: Optional[str] = field(default=None, metadata={"description": "FullDomainName reported by the SCCM client at registration"})
    ADLastLogonTime: Optional[str] = field(default=None, metadata={"description": "AD last-logon timestamp surfaced by SMS_CombinedDeviceResources"})
    distinguishedName: Optional[str] = field(default=None, metadata={"description": "AD distinguishedName of the device's Computer account"})
    SCCMInfra: Optional[bool] = field(default=True, metadata={"description": "Marker that this is SCCM infrastructure"})
    domain: Optional[str] = field(default=None, metadata={"description": "AD domain"})


@app.asset(
    description="SCCM client device node",
    node=NodeDef(
        kind=nk.SCCM_CLIENT_DEVICE,
        description="SCCM client device discovered via the AdminService SMS_R_System / SMS_CombinedDeviceResources endpoint",
        icon="laptop",
        properties=SCCMClientDeviceProperties,
    ),
    edges=[],
)
class SCCMClientDevice(BaseAsset):
    """SCCM_ClientDevice asset - one row per client from ``adminservice_client_devices``."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    dlt_config: ClassVar[DltConfig] = {"return_validated_models": True}

    guid: str
    site_code: str
    machine_name: Optional[str] = None
    resource_id: Optional[int] = None
    is_client: Optional[bool] = None
    client_version: Optional[str] = None
    ad_object_sid: Optional[str] = None
    last_logon_user: Optional[str] = None
    primary_user: Optional[str] = None
    current_user: Optional[str] = None
    device_os: Optional[str] = None
    device_os_build: Optional[str] = None
    last_active_time: Optional[str] = None
    last_online_time: Optional[str] = None
    last_offline_time: Optional[str] = None
    last_reported_mp_server_name: Optional[str] = None
    previous_sms_id: Optional[str] = None
    previous_sms_id_change_date: Optional[str] = None
    current_management_point: Optional[str] = None
    dns_host_name: Optional[str] = None
    ad_last_logon_time: Optional[str] = None
    user_name: Optional[str] = None
    user_domain_name: Optional[str] = None
    domain: Optional[str] = None
    source: Optional[str] = "AdminService-SMS_CombinedDeviceResources"

    @property
    def as_node(self) -> SCCMNode:
        node_id = f"GUID:{self.guid}"
        display = (
            f"{(self.machine_name or '').upper()}@{self.site_code}"
            if self.machine_name
            else node_id
        )
        trace_node(nk.SCCM_CLIENT_DEVICE, node_id, display)

        def _split_user(s: Optional[str]) -> tuple[Optional[str], Optional[str]]:
            """Split ``DOMAIN\\sam`` into ``(domain, sam)``; ``(None, sam)``
            when no backslash is present; ``(None, None)`` for empty input."""
            if not s:
                return None, None
            if "\\" in s:
                d, u = s.split("\\", 1)
                return (d or None), (u or None)
            return None, s

        primary_dom, primary_sam = _split_user(self.primary_user)
        current_dom, current_sam = _split_user(self.current_user)
        last_dom, last_sam = _split_user(self.last_logon_user)
        # PS1 prefers the dedicated ``UserDomainName`` field over the
        # split derived from ``LastLogonUser``. Mirror that — fall back
        # to the split only when AdminService didn't surface a value.
        explicit_user_domain = (self.user_domain_name or "").strip() or None
        explicit_user_name = (self.user_name or "").strip() or last_sam
        last_dom = explicit_user_domain or last_dom
        last_sam = explicit_user_name

        def _user_sid(sam: Optional[str]) -> Optional[str]:
            if not sam:
                return None
            try:
                return self._lookup.user_by_sam(sam)
            except Exception:
                return None

        resource_id_with_site = (
            f"{self.resource_id}@{self.site_code}"
            if self.resource_id and self.site_code
            else (str(self.resource_id) if self.resource_id else None)
        )

        # ``distinguishedName`` — looked up from ``ldap_computers`` via
        # the device's AD object SID. PS1 sources it from a separate AD
        # resolver call against ``DistinguishedName`` of the matching
        # Computer object.
        dn: Optional[str] = None
        if self.ad_object_sid:
            try:
                client = self._lookup.client
                schema = self._lookup.schema
                row = client.execute(
                    f"SELECT distinguished_name FROM {schema}.ldap_computers "
                    f"WHERE object_sid = ? LIMIT 1",
                    [self.ad_object_sid],
                ).fetchone()
                if row and row[0]:
                    dn = row[0]
            except Exception:
                pass

        # Collection memberships — one row per (collection_id, site_code)
        # in ``adminservice_collection_members`` for this device's GUID.
        # PS1 emits ``collectionIds = ["SMS00001@PS1", "SMS00001@CAS", ...]``
        # and ``collectionNames = ["All Systems", "All Desktop and Server Clients", ...]``;
        # we mirror that by joining members against the collections table.
        collection_ids: Optional[list[str]] = None
        collection_names: Optional[list[str]] = None
        try:
            client = self._lookup.client
            schema = self._lookup.schema
            rows = client.execute(
                f"SELECT DISTINCT m.collection_id, m.site_code, c.name "
                f"FROM {schema}.adminservice_collection_members m "
                f"LEFT JOIN {schema}.adminservice_collections c "
                f"  ON c.collection_id = m.collection_id "
                f" AND c.site_code = m.site_code "
                f"WHERE m.guid = ? "
                f"ORDER BY m.collection_id, m.site_code",
                [self.guid],
            ).fetchall()
            if rows:
                collection_ids = [f"{cid}@{sc}" for cid, sc, _name in rows]
                # Collection names are typically the same across sites — dedup
                # by name while preserving order.
                seen_names: set[str] = set()
                names: list[str] = []
                for _cid, _sc, nm in rows:
                    if nm and nm not in seen_names:
                        seen_names.add(nm)
                        names.append(nm)
                collection_names = names or None
        except Exception:
            pass

        return SCCMNode(
            kinds=[nk.SCCM_CLIENT_DEVICE],
            properties=SCCMClientDeviceProperties(
                node_id=node_id,
                name=display,
                displayname=display,
                environmentid=self.domain or None,
                resourceID=resource_id_with_site,
                machineName=self.machine_name,
                SMSID=node_id,
                smsGUID=self.guid,
                isClient=self.is_client,
                clientVersion=self.client_version,
                ADDomainSID=self.ad_object_sid,
                primaryUser=self.primary_user or None,
                primaryUserSID=_user_sid(primary_sam),
                currentLogonUser=self.current_user or None,
                currentLogonUserSID=_user_sid(current_sam),
                ADLastLogonUser=last_sam,
                ADLastLogonUserSID=_user_sid(last_sam),
                ADLastLogonUserDomain=last_dom,
                userName=last_sam,
                userDomainName=last_dom,
                sourceSiteCode=self.site_code,
                siteCode=self.site_code,
                collectionIds=collection_ids,
                collectionNames=collection_names,
                deviceOS=self.device_os or None,
                deviceOSBuild=self.device_os_build or None,
                lastActiveTime=self.last_active_time or None,
                lastOnlineTime=self.last_online_time or None,
                lastOfflineTime=self.last_offline_time or None,
                lastReportedMPServerName=self.last_reported_mp_server_name or None,
                lastReportedMPServerSID=(
                    self._lookup.computer_sid_by_hostname(self.last_reported_mp_server_name)
                    if self.last_reported_mp_server_name
                    else None
                ),
                currentManagementPoint=self.current_management_point or None,
                currentManagementPointSID=(
                    self._lookup.computer_sid_by_hostname(self.current_management_point)
                    if self.current_management_point
                    else None
                ),
                previousSMSID=self.previous_sms_id or None,
                previousSMSIDChangeDate=self.previous_sms_id_change_date or None,
                DNSHostName=self.dns_host_name or None,
                ADLastLogonTime=self.ad_last_logon_time or None,
                distinguishedName=dn,
                SCCMInfra=True,
                collectionSource=[self.source] if self.source else None,
                domain=self.domain,
            ),
        )

    @property
    def edges(self):
        # Cross-cutting edges (SCCM_HasClient site->device, SameHostAs
        # device<->computer, SCCM_HasCurrentUser, etc.) live in
        # models/derived/* and come from SQL views in Phase 4.
        return iter(())

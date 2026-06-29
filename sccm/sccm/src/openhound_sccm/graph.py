"""Base OpenGraph node/edge dataclasses + shared helpers for the SCCM collector.

Concrete node models (models/*.py) build these in their `as_node`. `SCCMNode`
supplies the `id` directly (we already know the SID / site code), unlike the
framework's UUID-deriving base. `domain_environment_id` derives the AD-domain SID
used as `environmentid` for Base AD nodes (spec §2 "Root/environment node").
"""
import re
from dataclasses import dataclass, field

from openhound.core.models.entries_dataclass import EdgeProperties, Node, NodeProperties

# A domain SID is the `S-1-5-21-X-Y-Z` prefix; an account SID appends `-RID`.
_DOMAIN_SID = re.compile(r"^(S-1-5-21(?:-\d+){3})-\d+$")


def domain_environment_id(sid: str, fallback_domain_sid: str | None = None) -> str | None:
    """Return the AD-domain SID to use as `environmentid` for a Base AD node.

    - Normal account SID `S-1-5-21-X-Y-Z-RID` -> `S-1-5-21-X-Y-Z`.
    - Well-known/builtin SID (no `S-1-5-21` domain part, e.g. `S-1-5-32-544`,
      `S-1-5-11`) -> `fallback_domain_sid` (the domain SID known from the record
      that produced this principal; SharpHound-style per-domain qualification).
    - `None` if neither applies; caller drops the node and logs.
    """
    if not sid:
        return None
    m = _DOMAIN_SID.match(sid.upper())
    if m:
        return m.group(1)
    return fallback_domain_sid


# Edge kind -> the kind to give a synthesised stub when the edge's END id has no node.
# Only edges whose end is a user/group SID (or a device smsid) appear here; ambiguous
# ends (user OR group) get "Base". See Stage 2 graph-integrity decision (2026-06-23).
BACKFILL_END_KIND: dict[str, str] = {
    "SCCM_HasPrimaryUser": "User",
    "SCCM_HasCurrentUser": "User",
    "SCCM_HasADLastLogonUser": "User",
    "HasSession": "User",
    "MemberOf": "Group",
    "SCCM_HasMember": "Base",
    "SCCM_HasStoredAccount": "Base",
}


@dataclass
class SCCMEdgeProperties(EdgeProperties):
    # Property names mirror ConfigManBearPig.ps1 exactly so BloodHound entity panels
    # render the keys operators know from the original tool. `traversable`/`composed`
    # come from the framework EdgeProperties base and already match CMBP.
    collectionSource: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class SCCMNode(Node):
    """Concrete SCCM node: `id` is supplied directly (no UUID derivation)."""
    id: str = ""

    def __post_init__(self):
        # id is set by the caller; nothing to derive. (Node declares this abstract.)
        return


# All node-property field names below mirror ConfigManBearPig.ps1's exact casing (camelCase for
# LDAP-derived attributes like dNSHostName/samAccountName, PascalCase for SCCM-specific properties
# like SCCMSiteSystemRoles). The framework base fields name/displayname/environmentid/last_seen are
# left as-is. dataclasses.asdict() emits these field names verbatim as the OpenGraph JSON keys.
@dataclass
class ComputerProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    SCCMSiteSystemRoles: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=False, kw_only=True)
    SCCMResourceIDs: list[str] = field(default_factory=list, kw_only=True)
    SCCMClientDeviceIdentifier: str | None = field(default=None, kw_only=True)
    dNSHostName: str | None = field(default=None, kw_only=True)
    samAccountName: str | None = field(default=None, kw_only=True)
    distinguishedName: str | None = field(default=None, kw_only=True)
    SMBSigningRequired: bool | None = field(default=None, kw_only=True)
    SCCMHasClientRemoteControlSPN: bool = field(default=False, kw_only=True)
    networkBootServer: bool = field(default=False, kw_only=True)
    disableLoopbackCheck: bool | None = field(default=None, kw_only=True)
    restrictReceivingNtlmTraffic: str | None = field(default=None, kw_only=True)
    SCCMClientCertificateRequired: bool | None = field(default=None, kw_only=True)
    SCCMHostsContentLibrary: bool | None = field(default=None, kw_only=True)
    SCCMIsPXESupportEnabled: bool | None = field(default=None, kw_only=True)


@dataclass
class UserProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    SCCMResourceIDs: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=False, kw_only=True)
    storedInSCCMSite: str | None = field(default=None, kw_only=True)
    distinguishedName: str | None = field(default=None, kw_only=True)
    userPrincipalName: str | None = field(default=None, kw_only=True)


@dataclass
class GroupProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=False, kw_only=True)
    SCCMResourceIDs: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class SCCMSiteProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    siteCode: str | None = field(default=None, kw_only=True)
    parentSiteCode: str | None = field(default=None, kw_only=True)
    rootSiteCode: str | None = field(default=None, kw_only=True)
    siteType: str | None = field(default=None, kw_only=True)
    siteGUID: str | None = field(default=None, kw_only=True)
    siteServerName: str | None = field(default=None, kw_only=True)
    SQLServerName: str | None = field(default=None, kw_only=True)
    SQLDatabaseName: str | None = field(default=None, kw_only=True)
    version: str | None = field(default=None, kw_only=True)
    buildNumber: str | None = field(default=None, kw_only=True)
    installDir: str | None = field(default=None, kw_only=True)
    # Stage 3 C5 additions — CMBP parity.
    SQLServiceAccountName: str | None = field(default=None, kw_only=True)
    distinguishedName: str | None = field(default=None, kw_only=True)
    sourceForest: str | None = field(default=None, kw_only=True)
    adminUsers: list[str] = field(default_factory=list, kw_only=True)
    storedAccounts: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)
    # Site/SQL server identity (CMBP ps1:7052-7065, 3040). The *DomainSID fields hold the full
    # resolved computer/account SID (CMBP names them "DomainSID" but stores the whole object SID).
    siteServerFQDN: str | None = field(default=None, kw_only=True)
    siteServerDomainSID: str | None = field(default=None, kw_only=True)
    SQLServerFQDN: str | None = field(default=None, kw_only=True)
    SQLServerDomainSID: str | None = field(default=None, kw_only=True)
    SQLServiceAccountDomainSID: str | None = field(default=None, kw_only=True)
    SQLServicePort: str | None = field(default=None, kw_only=True)


@dataclass
class SCCMCollectionProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    collectionID: str | None = field(default=None, kw_only=True)
    collectionType: str | None = field(default=None, kw_only=True)   # "Other"/"User"/"Device"
    memberCount: int | None = field(default=None, kw_only=True)
    comment: str | None = field(default=None, kw_only=True)
    isBuiltIn: bool | None = field(default=None, kw_only=True)
    limitToCollectionID: str | None = field(default=None, kw_only=True)
    limitToCollectionName: str | None = field(default=None, kw_only=True)
    collectionVariablesCount: int | None = field(default=None, kw_only=True)
    rootSiteCode: str | None = field(default=None, kw_only=True)
    sourceSiteCode: str | None = field(default=None, kw_only=True)
    lastChangeTime: str | None = field(default=None, kw_only=True)
    lastMemberChangeTime: str | None = field(default=None, kw_only=True)
    members: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)


@dataclass
class SCCMAdminUserProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    adminID: str | None = field(default=None, kw_only=True)
    adminSid: str | None = field(default=None, kw_only=True)
    distinguishedName: str | None = field(default=None, kw_only=True)
    isGroup: bool | None = field(default=None, kw_only=True)
    accountType: int | None = field(default=None, kw_only=True)  # port-added (no CMBP key)
    rootSiteCode: str | None = field(default=None, kw_only=True)
    # Audit fields from ADMIN_COLUMNS (CMBP parity, Stage 3 C3). displayName is a distinct key from
    # the framework base `displayname` — CMBP sets both, so we mirror that.
    displayName: str | None = field(default=None, kw_only=True)
    sourceSiteCode: str | None = field(default=None, kw_only=True)
    createdBy: str | None = field(default=None, kw_only=True)
    createdDate: str | None = field(default=None, kw_only=True)
    lastModifiedBy: str | None = field(default=None, kw_only=True)
    lastModifiedDate: str | None = field(default=None, kw_only=True)
    # Assignment lists: raw role ids, resolved role node ids, resolved collection node ids.
    collectionIds: list[str] = field(default_factory=list, kw_only=True)
    roleIDs: list[str] = field(default_factory=list, kw_only=True)
    memberOf: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)


@dataclass
class SCCMSecurityRoleProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    roleID: str | None = field(default=None, kw_only=True)
    roleName: str | None = field(default=None, kw_only=True)
    roleDescription: str | None = field(default=None, kw_only=True)
    isBuiltIn: bool | None = field(default=None, kw_only=True)
    isSecAdminRole: bool | None = field(default=None, kw_only=True)
    copiedFromID: str | None = field(default=None, kw_only=True)
    numberOfAdmins: int | None = field(default=None, kw_only=True)
    operations: list[str] = field(default_factory=list, kw_only=True)
    rootSiteCode: str | None = field(default=None, kw_only=True)
    # Audit fields from ROLE_COLUMNS (CMBP parity, Stage 3 C2).
    siteCode: str | None = field(default=None, kw_only=True)
    createdBy: str | None = field(default=None, kw_only=True)
    createdDate: str | None = field(default=None, kw_only=True)
    lastModifiedBy: str | None = field(default=None, kw_only=True)
    lastModifiedDate: str | None = field(default=None, kw_only=True)
    # Members: upper(logon_name)@root for each admin assigned to this role.
    members: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=True, kw_only=True)


@dataclass
class SCCMClientDeviceProperties(NodeProperties):
    collectionSource: list[str] = field(default_factory=list, kw_only=True)
    SMSID: str | None = field(default=None, kw_only=True)
    resourceID: str | None = field(default=None, kw_only=True)
    siteCode: str | None = field(default=None, kw_only=True)
    deviceOS: str | None = field(default=None, kw_only=True)
    deviceOSBuild: str | None = field(default=None, kw_only=True)
    isVirtualMachine: bool | None = field(default=None, kw_only=True)
    coManaged: bool | None = field(default=None, kw_only=True)
    AADDeviceID: str | None = field(default=None, kw_only=True)
    AADTenantID: str | None = field(default=None, kw_only=True)
    lastReportedMPServerName: str | None = field(default=None, kw_only=True)
    primaryUser: str | None = field(default=None, kw_only=True)
    currentLogonUser: str | None = field(default=None, kw_only=True)
    ADLastLogonUser: str | None = field(default=None, kw_only=True)
    rootSiteCode: str | None = field(default=None, kw_only=True)
    possible: bool = field(default=False, kw_only=True)  # port-added (no CMBP key)
    ADDomainSID: str | None = field(default=None, kw_only=True)
    # Telemetry scalars — Stage 3 C4 (CMBP parity).
    ADLastLogonTime: str | None = field(default=None, kw_only=True)
    ADLastLogonUserDomain: str | None = field(default=None, kw_only=True)
    sourceSiteCode: str | None = field(default=None, kw_only=True)
    lastActiveTime: str | None = field(default=None, kw_only=True)
    lastOnlineTime: str | None = field(default=None, kw_only=True)
    lastOfflineTime: str | None = field(default=None, kw_only=True)
    # Resolved SID fields — Stage 3 C4 (CMBP ps1:7227/7232/7245/7248).
    primaryUserSID: str | None = field(default=None, kw_only=True)
    currentLogonUserSID: str | None = field(default=None, kw_only=True)
    ADLastLogonUserSID: str | None = field(default=None, kw_only=True)
    lastReportedMPServerSID: str | None = field(default=None, kw_only=True)
    # Collection membership lists — Stage 3 C4 (CMBP ps1:7228-7229).
    collectionIds: list[str] = field(default_factory=list, kw_only=True)
    collectionNames: list[str] = field(default_factory=list, kw_only=True)
    SCCMInfra: bool = field(default=False, kw_only=True)

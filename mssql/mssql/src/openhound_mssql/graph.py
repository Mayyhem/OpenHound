"""OpenGraph node/edge dataclasses for the MSSQL collector.

Convert serializes graph entries with `dataclasses.asdict`, so these use the
DATACLASS variants from `openhound.core.models.entries_dataclass` (NOT the
Pydantic ones). Each property dataclass declares MSSQLHound's EXACT original
property names verbatim (decision D11) — camelCase like `isMixedModeAuthEnabled`,
`SQLServer`, `ownerPrincipalID` — so they render in BloodHound entity panels and
the validators (which do no key remapping) accept them. OpenHound's framework
base `NodeProperties` fields (`name`, `displayname`, `environmentid`,
`last_seen`) are kept as-is; the MSSQL fields are layered on top.

All MSSQL-specific fields are declared `kw_only=True` with sensible defaults.
This is required because the base `NodeProperties` has required positional
fields (`name`/`displayname`/`environmentid`) followed by a defaulted kw-only
field; adding defaulted fields without `kw_only` would raise "non-default
argument follows default argument". Optional/conditional properties default to
`None` (or empty list) so convert can omit absent keys when emitting, matching
the Go node builders that only set present properties.

Attributes:
    MSSQLNode: Node subclass that derives `self.id` in `__post_init__`.
    MSSQLEdgeProperties: Edge-property dataclass with the full MSSQLHound
        documentation bag plus the injected typed props.
    ServerProperties / LoginProperties / ServerRoleProperties /
    DatabaseProperties / DatabaseUserProperties / DatabaseRoleProperties /
    ApplicationRoleProperties / ADProperties: one property dataclass per node
        kind (see spec §5).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from openhound.core.models.entries_dataclass import (
    EdgeProperties,
    Node,
    NodeProperties,
)


@dataclass
class MSSQLNode(Node):
    """OpenGraph node for an MSSQL/AD entity, keyed by its ObjectIdentifier.

    The framework `Node` declares `kinds` and `properties`; this subclass adds
    the entity's stable `id` (its MSSQLHound ObjectIdentifier) and, optionally,
    a BloodHound `icon`. `id` is supplied at construction and surfaced through
    `__post_init__` so it serializes into the OpenGraph node envelope.

    Attributes:
        object_identifier: The stable ObjectIdentifier; becomes `self.id`.
        icon: Optional font-awesome icon dict (None for AD nodes).
        id: The node id, declared as a (non-init) dataclass field so it is
            serialized by `dataclasses.asdict`; set in `__post_init__` from
            `object_identifier`.
    """

    object_identifier: str
    icon: dict | None = None
    id: str = field(init=False)

    def __post_init__(self) -> None:
        """Expose the supplied ObjectIdentifier as the node `id`."""
        self.id = self.object_identifier


@dataclass
class ServerProperties(NodeProperties):
    """Properties for an `MSSQL_Server` node (collector.go createServerNode).

    Attributes:
        hostname: Host name of the SQL Server machine.
        fqdn: Fully-qualified domain name of the host.
        sqlServerName: Original SQL Server name (short name or instance form).
        version: Full `@@VERSION` string.
        versionNumber: Numeric product version (e.g. "15.0.2000.5").
        edition: SQL Server edition.
        productLevel: Product level (e.g. "RTM", "SP1").
        isClustered: Whether the instance is clustered.
        port: TCP port the instance listens on.
        instanceName: Instance name (omitted for default instance).
        isMixedModeAuthEnabled: Whether mixed-mode auth is enabled.
        forceEncryption: ForceEncryption registry/EPA verdict (optional).
        strictEncryption: Strict (TDS 8.0) encryption verdict (optional).
        extendedProtection: Extended Protection / EPA verdict (optional).
        isVulnerableToCVE_2025_49758: CVE-2025-49758 vulnerability flag.
        CVE_2025_49758_updateName: Name of the patch that fixes the CVE.
        CVE_2025_49758_patchKB: KB number of the fixing patch.
        CVE_2025_49758_requiredVersion: Minimum patched version.
        servicePrincipalNames: SPNs registered for the instance.
        serviceAccount: First service account (NetBIOS prefix stripped).
        databases: Names of databases on the instance.
        linkedToServers: Names of linked servers configured here.
        isLinkedServerTarget: True if a linked server resolves back to here.
        hasLinksFromServers: OIDs of servers linking back to this server.
        domainPrincipalsWithSysadmin: OIDs of domain principals w/ sysadmin.
        domainPrincipalsWithControlServer: OIDs w/ effective CONTROL SERVER.
        domainPrincipalsWithSecurityadmin: OIDs w/ securityadmin.
        domainPrincipalsWithImpersonateAnyLogin: OIDs w/ IMPERSONATE ANY LOGIN.
        isAnyDomainPrincipalSysadmin: True if any domain principal is sysadmin.
    """

    hostname: str = field(default="", kw_only=True)
    fqdn: str = field(default="", kw_only=True)
    sqlServerName: str = field(default="", kw_only=True)
    version: str = field(default="", kw_only=True)
    versionNumber: str = field(default="", kw_only=True)
    edition: str = field(default="", kw_only=True)
    productLevel: str = field(default="", kw_only=True)
    isClustered: bool = field(default=False, kw_only=True)
    port: int = field(default=0, kw_only=True)
    instanceName: str | None = field(default=None, kw_only=True)
    isMixedModeAuthEnabled: bool = field(default=False, kw_only=True)
    forceEncryption: str | None = field(default=None, kw_only=True)
    strictEncryption: str | None = field(default=None, kw_only=True)
    extendedProtection: str | None = field(default=None, kw_only=True)
    # CVE-2025-49758 fields. The canonical key in the Go output uses hyphens
    # ("isVulnerableToCVE-2025-49758"); Python identifiers can't contain
    # hyphens, so these underscore names are remapped to the hyphenated keys at
    # emit time (convert/output adapter). Declared here so the panel/schema
    # carries them.
    isVulnerableToCVE_2025_49758: bool = field(default=False, kw_only=True)
    CVE_2025_49758_updateName: str | None = field(default=None, kw_only=True)
    CVE_2025_49758_patchKB: str | None = field(default=None, kw_only=True)
    CVE_2025_49758_requiredVersion: str | None = field(default=None, kw_only=True)
    servicePrincipalNames: list[str] = field(default_factory=list, kw_only=True)
    serviceAccount: str | None = field(default=None, kw_only=True)
    databases: list[str] = field(default_factory=list, kw_only=True)
    linkedToServers: list[str] = field(default_factory=list, kw_only=True)
    isLinkedServerTarget: bool = field(default=False, kw_only=True)
    hasLinksFromServers: list[str] = field(default_factory=list, kw_only=True)
    domainPrincipalsWithSysadmin: list[str] = field(default_factory=list, kw_only=True)
    domainPrincipalsWithControlServer: list[str] = field(
        default_factory=list, kw_only=True
    )
    domainPrincipalsWithSecurityadmin: list[str] = field(
        default_factory=list, kw_only=True
    )
    domainPrincipalsWithImpersonateAnyLogin: list[str] = field(
        default_factory=list, kw_only=True
    )
    isAnyDomainPrincipalSysadmin: bool = field(default=False, kw_only=True)


@dataclass
class LoginProperties(NodeProperties):
    """Properties for an `MSSQL_Login` node (createServerPrincipalNode default).

    Attributes:
        principalId: SQL principal_id of the login.
        createDate: Login create date (RFC3339).
        modifyDate: Login modify date (RFC3339).
        SQLServer: Display name of the owning SQL Server.
        type: type_desc (SQL_LOGIN / WINDOWS_LOGIN / WINDOWS_GROUP / ...).
        disabled: Whether the login is disabled.
        defaultDatabase: Default database name for the login.
        isActiveDirectoryPrincipal: Whether the login maps to an AD principal.
        activeDirectorySID: SID when the login is an AD principal (optional).
        activeDirectoryPrincipal: Resolved AD principal name (optional).
        databaseUsers: Database users mapped from this login.
        memberOfRoles: Names of server roles this login belongs to.
        explicitPermissions: Explicitly granted/denied server permissions.
    """

    principalId: int = field(default=0, kw_only=True)
    createDate: str = field(default="", kw_only=True)
    modifyDate: str = field(default="", kw_only=True)
    SQLServer: str = field(default="", kw_only=True)
    type: str = field(default="", kw_only=True)
    disabled: bool = field(default=False, kw_only=True)
    defaultDatabase: str = field(default="", kw_only=True)
    isActiveDirectoryPrincipal: bool = field(default=False, kw_only=True)
    activeDirectorySID: str | None = field(default=None, kw_only=True)
    activeDirectoryPrincipal: str | None = field(default=None, kw_only=True)
    databaseUsers: list[str] = field(default_factory=list, kw_only=True)
    memberOfRoles: list[str] = field(default_factory=list, kw_only=True)
    explicitPermissions: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class ServerRoleProperties(NodeProperties):
    """Properties for an `MSSQL_ServerRole` node (SERVER_ROLE branch).

    Attributes:
        principalId: SQL principal_id of the role.
        createDate: Role create date (RFC3339).
        modifyDate: Role modify date (RFC3339).
        SQLServer: Display name of the owning SQL Server.
        isFixedRole: Whether this is a fixed server role.
        members: Member principal names.
        memberOfRoles: Names of server roles this role belongs to.
        explicitPermissions: Explicitly granted/denied server permissions.
    """

    principalId: int = field(default=0, kw_only=True)
    createDate: str = field(default="", kw_only=True)
    modifyDate: str = field(default="", kw_only=True)
    SQLServer: str = field(default="", kw_only=True)
    isFixedRole: bool = field(default=False, kw_only=True)
    members: list[str] = field(default_factory=list, kw_only=True)
    memberOfRoles: list[str] = field(default_factory=list, kw_only=True)
    explicitPermissions: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class DatabaseProperties(NodeProperties):
    """Properties for an `MSSQL_Database` node (collector.go createDatabaseNode).

    Attributes:
        databaseId: SQL database_id.
        createDate: Database create date (RFC3339).
        compatibilityLevel: Compatibility level integer.
        isReadOnly: Whether the database is read-only.
        isTrustworthy: Whether the TRUSTWORTHY flag is set.
        isEncrypted: Whether the database is encrypted.
        SQLServer: Display name of the owning SQL Server.
        SQLServerID: ObjectIdentifier of the owning server.
        ownerLoginName: Owner login name (optional).
        ownerPrincipalID: Owner principal_id as a string (optional).
        OwnerObjectIdentifier: Owner principal's ObjectIdentifier (optional).
        collationName: Database collation (optional).
    """

    databaseId: int = field(default=0, kw_only=True)
    createDate: str = field(default="", kw_only=True)
    compatibilityLevel: int = field(default=0, kw_only=True)
    isReadOnly: bool = field(default=False, kw_only=True)
    isTrustworthy: bool = field(default=False, kw_only=True)
    isEncrypted: bool = field(default=False, kw_only=True)
    SQLServer: str = field(default="", kw_only=True)
    SQLServerID: str = field(default="", kw_only=True)
    ownerLoginName: str | None = field(default=None, kw_only=True)
    ownerPrincipalID: str | None = field(default=None, kw_only=True)
    OwnerObjectIdentifier: str | None = field(default=None, kw_only=True)
    collationName: str | None = field(default=None, kw_only=True)


@dataclass
class DatabaseUserProperties(NodeProperties):
    """Properties for an `MSSQL_DatabaseUser` node (database user branch).

    Note `name` carries the "Name@DatabaseName" form set by the Go builder.

    Attributes:
        principalId: SQL principal_id of the database user.
        createDate: User create date (RFC3339).
        modifyDate: User modify date (RFC3339).
        database: Database name the user lives in.
        SQLServer: Display name of the owning SQL Server.
        type: type_desc (SQL_USER / WINDOWS_USER / ...).
        defaultSchema: Default schema (optional).
        serverLogin: Mapped server login name (optional).
        memberOfRoles: Names of database roles the user belongs to.
        explicitPermissions: Explicitly granted/denied database permissions.
    """

    principalId: int = field(default=0, kw_only=True)
    createDate: str = field(default="", kw_only=True)
    modifyDate: str = field(default="", kw_only=True)
    database: str = field(default="", kw_only=True)
    SQLServer: str = field(default="", kw_only=True)
    type: str = field(default="", kw_only=True)
    defaultSchema: str | None = field(default=None, kw_only=True)
    serverLogin: str | None = field(default=None, kw_only=True)
    memberOfRoles: list[str] = field(default_factory=list, kw_only=True)
    explicitPermissions: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class DatabaseRoleProperties(NodeProperties):
    """Properties for an `MSSQL_DatabaseRole` node (DATABASE_ROLE branch).

    Attributes:
        principalId: SQL principal_id of the role.
        createDate: Role create date (RFC3339).
        modifyDate: Role modify date (RFC3339).
        database: Database name the role lives in.
        SQLServer: Display name of the owning SQL Server.
        isFixedRole: Whether this is a fixed database role.
        defaultSchema: Default schema (optional).
        members: Member principal names.
        memberOfRoles: Names of database roles this role belongs to.
        explicitPermissions: Explicitly granted/denied database permissions.
    """

    principalId: int = field(default=0, kw_only=True)
    createDate: str = field(default="", kw_only=True)
    modifyDate: str = field(default="", kw_only=True)
    database: str = field(default="", kw_only=True)
    SQLServer: str = field(default="", kw_only=True)
    isFixedRole: bool = field(default=False, kw_only=True)
    defaultSchema: str | None = field(default=None, kw_only=True)
    members: list[str] = field(default_factory=list, kw_only=True)
    memberOfRoles: list[str] = field(default_factory=list, kw_only=True)
    explicitPermissions: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class ApplicationRoleProperties(NodeProperties):
    """Properties for an `MSSQL_ApplicationRole` node (APPLICATION_ROLE branch).

    Attributes:
        principalId: SQL principal_id of the application role.
        createDate: Create date (RFC3339).
        modifyDate: Modify date (RFC3339).
        database: Database name the role lives in.
        SQLServer: Display name of the owning SQL Server.
        defaultSchema: Default schema (optional).
        memberOfRoles: Names of database roles this role belongs to.
        explicitPermissions: Explicitly granted/denied database permissions.
    """

    principalId: int = field(default=0, kw_only=True)
    createDate: str = field(default="", kw_only=True)
    modifyDate: str = field(default="", kw_only=True)
    database: str = field(default="", kw_only=True)
    SQLServer: str = field(default="", kw_only=True)
    defaultSchema: str | None = field(default=None, kw_only=True)
    memberOfRoles: list[str] = field(default_factory=list, kw_only=True)
    explicitPermissions: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class ADProperties(NodeProperties):
    """Properties for an AD node (`User`/`Group`/`Computer`, + `Base`).

    Covers all three AD node kinds; convert/output omits keys that are absent
    for a given kind (e.g. a local group only sets `name` +
    `isActiveDirectoryPrincipal`). Mirrors collector.go `createADNodes`.

    Attributes:
        SID: Object SID (optional; absent on bare local-group nodes).
        domain: Domain name (optional).
        isDomainPrincipal: Whether this is a domain (vs local) principal.
        SAMAccountName: sAMAccountName (optional; LDAP-enriched).
        isActiveDirectoryPrincipal: Set on local-group nodes.
        isEnabled: Whether the AD account is enabled (LDAP-enriched).
        distinguishedName: LDAP distinguished name (optional).
        userPrincipalName: userPrincipalName (optional).
        DNSHostName: DNS host name (optional; computer accounts).
    """

    SID: str | None = field(default=None, kw_only=True)
    domain: str | None = field(default=None, kw_only=True)
    isDomainPrincipal: bool | None = field(default=None, kw_only=True)
    SAMAccountName: str | None = field(default=None, kw_only=True)
    isActiveDirectoryPrincipal: bool | None = field(default=None, kw_only=True)
    isEnabled: bool | None = field(default=None, kw_only=True)
    distinguishedName: str | None = field(default=None, kw_only=True)
    userPrincipalName: str | None = field(default=None, kw_only=True)
    DNSHostName: str | None = field(default=None, kw_only=True)


@dataclass
class LinkedServerStubProperties(NodeProperties):
    """Properties for a FOREIGN linked-server stub ``MSSQL_Server`` node.

    A linked server pointing at a different host (e.g. ps1-db's ``CAS-DB`` link)
    gets a minimal stub server node so the LinkedTo/LinkedAsAdmin edge connects two
    server *nodes*. Go's stub (collector.go generateOutput linked-node loop) sets
    ONLY ``name`` + ``isLinkedServerTarget`` + ``hasLinksFromServers`` — it does NOT
    carry the full createServerNode property bag (no version/port/CVE/...), since
    the remote server was never collected. We mirror that minimal shape so the stub
    isn't polluted with empty/misleading defaults.

    Attributes:
        isLinkedServerTarget: Always True on a stub (it IS a link target).
        hasLinksFromServers: OIDs of the local servers that link to this target.
    """

    isLinkedServerTarget: bool = field(default=True, kw_only=True)
    hasLinksFromServers: list[str] = field(default_factory=list, kw_only=True)


@dataclass
class MSSQLEdgeProperties(EdgeProperties):
    """Edge properties: the MSSQLHound documentation bag + injected typed props.

    The framework base `EdgeProperties` supplies `composed` and `traversable`.
    This subclass adds the human-readable documentation strings emitted by the
    Go `GetEdgeProperties` generators (`general`/`windowsAbuse`/`linuxAbuse`/
    `opsec`/`references`/`composition`) plus `withGrant` (set when the source
    permission was GRANT_WITH_GRANT_OPTION) and the typed properties injected at
    construction for specific edge kinds (not produced by the generators):
    `ownerPrincipalID` on MSSQL_Owns; `credentialId` on the cred edges;
    `proxyId` on MSSQL_HasProxyCred. All are optional so convert can filter
    empties to match the Go output (which only sets non-empty keys).

    Attributes:
        general: General description of the relationship.
        windowsAbuse: Windows abuse guidance.
        linuxAbuse: Linux abuse guidance.
        opsec: OPSEC considerations.
        references: Reference links.
        composition: Composition Cypher (composition-set edges only).
        withGrant: True when granted WITH GRANT OPTION.
        ownerPrincipalID: Owner principal_id (MSSQL_Owns).
        credentialId: Credential id (MSSQL_HasMappedCred/HasDBScopedCred/
            HasProxyCred).
        proxyId: Proxy id (MSSQL_HasProxyCred).
    """

    general: str | None = field(default=None, kw_only=True)
    windowsAbuse: str | None = field(default=None, kw_only=True)
    linuxAbuse: str | None = field(default=None, kw_only=True)
    opsec: str | None = field(default=None, kw_only=True)
    references: str | None = field(default=None, kw_only=True)
    composition: str | None = field(default=None, kw_only=True)
    withGrant: bool | None = field(default=None, kw_only=True)
    ownerPrincipalID: str | None = field(default=None, kw_only=True)
    # credentialId / proxyId are emitted as STRINGS to match Go
    # (fmt.Sprintf("%d", …) in collector.go), not integers.
    credentialId: str | None = field(default=None, kw_only=True)
    proxyId: str | None = field(default=None, kw_only=True)
    # Linked-server (MSSQL_LinkedTo / MSSQL_LinkedAsAdmin) property bag, ported
    # verbatim from the Go edge property set (collector.go:3657-3671). Carrying
    # localLogin/remoteLogin per edge is also what keeps distinct login mappings
    # to the same target from collapsing under the streaming JSON dedup.
    localLogin: str | None = field(default=None, kw_only=True)
    remoteLogin: str | None = field(default=None, kw_only=True)
    remoteCurrentLogin: str | None = field(default=None, kw_only=True)
    dataSource: str | None = field(default=None, kw_only=True)
    path: str | None = field(default=None, kw_only=True)
    product: str | None = field(default=None, kw_only=True)
    provider: str | None = field(default=None, kw_only=True)
    dataAccess: bool | None = field(default=None, kw_only=True)
    rpcOut: bool | None = field(default=None, kw_only=True)
    usesImpersonation: bool | None = field(default=None, kw_only=True)
    remoteIsSysadmin: bool | None = field(default=None, kw_only=True)
    remoteIsSecurityAdmin: bool | None = field(default=None, kw_only=True)
    remoteHasControlServer: bool | None = field(default=None, kw_only=True)
    remoteHasImpersonateAnyLogin: bool | None = field(default=None, kw_only=True)
    remoteIsMixedMode: bool | None = field(default=None, kw_only=True)

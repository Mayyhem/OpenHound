"""Edge kind constants for the SCCM extension.

Mirrors the distinct edge kinds emitted by ConfigManBearPig.
"""

# Site replication topology
SCCM_ADMINS_REPLICATED_TO = "SCCM_AdminsReplicatedTo"

# Stage 2 edge kinds
SCCM_IS_MAPPED_TO = "SCCM_IsMappedTo"
SCCM_IS_ASSIGNED = "SCCM_IsAssigned"
SCCM_HAS_MEMBER = "SCCM_HasMember"
SCCM_HAS_CLIENT = "SCCM_HasClient"
SCCM_HAS_PRIMARY_USER = "SCCM_HasPrimaryUser"
SCCM_HAS_CURRENT_USER = "SCCM_HasCurrentUser"
SCCM_HAS_AD_LAST_LOGON_USER = "SCCM_HasADLastLogonUser"
SCCM_HAS_STORED_ACCOUNT = "SCCM_HasStoredAccount"
MEMBER_OF = "MemberOf"
HAS_SESSION = "HasSession"

# Stage 3 edge kinds (containment + RBAC fan-out)
SCCM_CONTAINS = "SCCM_Contains"
SCCM_FULL_ADMINISTRATOR = "SCCM_FullAdministrator"
SCCM_APPLICATION_AUTHOR = "SCCM_ApplicationAuthor"
SCCM_APPLICATION_ADMINISTRATOR = "SCCM_ApplicationAdministrator"
SCCM_COMPLIANCE_SETTINGS_MANAGER = "SCCM_ComplianceSettingsManager"
SCCM_OSD_MANAGER = "SCCM_OSDManager"
SCCM_OPERATIONS_ADMINISTRATOR = "SCCM_OperationsAdministrator"
SCCM_SECURITY_ADMINISTRATOR = "SCCM_SecurityAdministrator"
SCCM_ALL_PERMISSIONS = "SCCM_AllPermissions"
SCCM_ASSIGN_ALL_PERMISSIONS = "SCCM_AssignAllPermissions"

# Stage 4 edge kinds (host correlation + local-admin mesh)
SAME_HOST_AS = "SameHostAs"
LOCAL_ADMIN_REQUIRED = "LocalAdminRequired"

# CMBP traversable allow-list (ConfigManBearPig.ps1:2216-2249, uncommented entries only).
# Edges whose kind is in this set get properties.traversable = True. Includes future
# (Stage 3-6) kinds so later stages reuse this one source of truth.
TRAVERSABLE_EDGE_KINDS = frozenset({
    "AdminTo", "LocalAdminRequired",
    "CoerceAndRelayToAdminService", "CoerceAndRelayToMSSQL", "CoerceAndRelayNTLMtoSMB",
    "HasSession",
    "MSSQL_Contains", "MSSQL_ControlDB", "MSSQL_ControlServer", "MSSQL_ExecuteOnHost",
    "MSSQL_GetAdminTGS", "MSSQL_GetTGS", "MSSQL_HasLogin", "MSSQL_HostFor",
    "MSSQL_IsMappedTo", "MSSQL_MemberOf",
    "SameHostAs",
    "SCCM_AdminsReplicatedTo", "SCCM_AllPermissions", "SCCM_ApplicationAdministrator",
    "SCCM_AssignAllPermissions", "SCCM_Contains", "SCCM_FullAdministrator",
    "SCCM_HasADLastLogonUser", "SCCM_HasClient", "SCCM_HasCurrentUser",
    "SCCM_HasPrimaryUser", "SCCM_IsMappedTo",
})

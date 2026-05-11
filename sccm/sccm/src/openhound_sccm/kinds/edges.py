"""Edge kind constants for the SCCM extension.

Mirrors the edge kinds emitted by ConfigManBearPig (see sccm/ConfigManBearPig/python/lib/graph.py
TRAVERSABLE_EDGE_TYPES and lib/output.py SEED_EDGE_KINDS). Names are unprefixed because
the platform string itself already namespaces them (SCCM_*, MSSQL_*) — the kind written
to BloodHound is exactly the constant value here.

Note: ConfigManBearPig's seed list uses unprefixed names like ``CoerceAndRelayToAdminService``
in some places and ``SCCM_CoerceAndRelayToAdminService`` in others. The values below match
what the on-disk JSON actually carries, which is what the test runner reads. The seed-data
edge kinds list (lib/output.py SEED_EDGE_KINDS) is authoritative.
"""

# Generic / cross-source
MEMBER_OF = "MemberOf"  # AD group membership
HAS_SESSION = "HasSession"
SAME_HOST_AS = "SameHostAs"
LOCAL_ADMIN_REQUIRED = "LocalAdminRequired"

# Coerce-and-relay (CoerceAndRelaytoSMB is a known typo from the original; both forms emitted)
COERCE_AND_RELAY_TO_ADMIN_SERVICE = "CoerceAndRelayToAdminService"
COERCE_AND_RELAY_TO_MSSQL = "CoerceAndRelayToMSSQL"
COERCE_AND_RELAY_TO_SMB = "CoerceAndRelayToSMB"
COERCE_AND_RELAY_TO_SMB_LEGACY = "CoerceAndRelaytoSMB"  # PS-typo'd duplicate; preserved for parity

# MSSQL family
MSSQL_CONTAINS = "MSSQL_Contains"
MSSQL_CONTROL_DB = "MSSQL_ControlDB"
MSSQL_CONTROL_SERVER = "MSSQL_ControlServer"
MSSQL_EXECUTE_ON_HOST = "MSSQL_ExecuteOnHost"
MSSQL_GET_ADMIN_TGS = "MSSQL_GetAdminTGS"
MSSQL_GET_TGS = "MSSQL_GetTGS"
MSSQL_HAS_LOGIN = "MSSQL_HasLogin"
MSSQL_HOST_FOR = "MSSQL_HostFor"
MSSQL_IS_MAPPED_TO = "MSSQL_IsMappedTo"
MSSQL_LINKED_AS_ADMIN = "MSSQL_LinkedAsAdmin"
MSSQL_MEMBER_OF = "MSSQL_MemberOf"
MSSQL_SERVICE_ACCOUNT_FOR = "MSSQL_ServiceAccountFor"

# SCCM family
SCCM_ADMINS_REPLICATED_TO = "SCCM_AdminsReplicatedTo"
SCCM_ALL_PERMISSIONS = "SCCM_AllPermissions"
SCCM_APPLICATION_ADMINISTRATOR = "SCCM_ApplicationAdministrator"
SCCM_ASSIGN_ALL_PERMISSIONS = "SCCM_AssignAllPermissions"
SCCM_ASSIGN_SPECIFIC_PERMISSIONS = "SCCM_AssignSpecificPermissions"
SCCM_CONTAINS = "SCCM_Contains"
SCCM_FULL_ADMINISTRATOR = "SCCM_FullAdministrator"
SCCM_HAS_AD_LAST_LOGON_USER = "SCCM_HasADLastLogonUser"
SCCM_HAS_CLIENT = "SCCM_HasClient"
SCCM_HAS_COLLECTION_VAR = "SCCM_HasCollectionVar"
SCCM_HAS_CURRENT_USER = "SCCM_HasCurrentUser"
SCCM_HAS_MEMBER = "SCCM_HasMember"
SCCM_HAS_NETWORK_ACCESS_ACCOUNT = "SCCM_HasNetworkAccessAccount"
SCCM_HAS_PRIMARY_USER = "SCCM_HasPrimaryUser"
SCCM_HAS_STORED_ACCOUNT = "SCCM_HasStoredAccount"
SCCM_HAS_TASK_SEQUENCE = "SCCM_HasTaskSequence"
SCCM_IS_ASSIGNED = "SCCM_IsAssigned"
SCCM_IS_MAPPED_TO = "SCCM_IsMappedTo"
SCCM_OBTAIN_CERT_FOR = "SCCM_ObtainCertFor"

# Used for traversable detection in edge property emission (mirrors lib/graph.py TRAVERSABLE_EDGE_TYPES)
TRAVERSABLE_KINDS = frozenset({
    "AdminTo",
    COERCE_AND_RELAY_TO_ADMIN_SERVICE,
    COERCE_AND_RELAY_TO_MSSQL,
    COERCE_AND_RELAY_TO_SMB,
    COERCE_AND_RELAY_TO_SMB_LEGACY,
    HAS_SESSION,
    LOCAL_ADMIN_REQUIRED,
    SAME_HOST_AS,
    MSSQL_CONTAINS, MSSQL_CONTROL_DB, MSSQL_CONTROL_SERVER, MSSQL_EXECUTE_ON_HOST,
    MSSQL_GET_ADMIN_TGS, MSSQL_GET_TGS, MSSQL_HAS_LOGIN, MSSQL_HOST_FOR,
    MSSQL_IS_MAPPED_TO, MSSQL_LINKED_AS_ADMIN, MSSQL_MEMBER_OF, MSSQL_SERVICE_ACCOUNT_FOR,
    SCCM_ADMINS_REPLICATED_TO, SCCM_ALL_PERMISSIONS, SCCM_APPLICATION_ADMINISTRATOR,
    SCCM_ASSIGN_ALL_PERMISSIONS, SCCM_ASSIGN_SPECIFIC_PERMISSIONS, SCCM_CONTAINS,
    SCCM_FULL_ADMINISTRATOR, SCCM_HAS_AD_LAST_LOGON_USER, SCCM_HAS_CLIENT,
    SCCM_HAS_COLLECTION_VAR, SCCM_HAS_CURRENT_USER, SCCM_HAS_MEMBER,
    SCCM_HAS_NETWORK_ACCESS_ACCOUNT, SCCM_HAS_PRIMARY_USER, SCCM_HAS_STORED_ACCOUNT,
    SCCM_HAS_TASK_SEQUENCE, SCCM_IS_ASSIGNED, SCCM_IS_MAPPED_TO, SCCM_OBTAIN_CERT_FOR,
})

# Master list mirrors lib/output.py SEED_EDGE_KINDS — the seed_data.json edge kinds list.
# Includes the legacy typo'd lowercase form (``CoerceAndRelaytoSMB``) so the seed_data
# +1 contribution to the histogram matches the cmbp_seed baseline (which has 1
# CoerceAndRelaytoSMB edge from its own seed_data file).
SEED_EDGE_KINDS = (
    LOCAL_ADMIN_REQUIRED,
    COERCE_AND_RELAY_TO_ADMIN_SERVICE,
    COERCE_AND_RELAY_TO_MSSQL,
    COERCE_AND_RELAY_TO_SMB,
    COERCE_AND_RELAY_TO_SMB_LEGACY,
    HAS_SESSION,
    MSSQL_CONTAINS, MSSQL_CONTROL_DB, MSSQL_CONTROL_SERVER, MSSQL_EXECUTE_ON_HOST,
    MSSQL_GET_ADMIN_TGS, MSSQL_GET_TGS, MSSQL_HAS_LOGIN, MSSQL_HOST_FOR,
    MSSQL_IS_MAPPED_TO, MSSQL_LINKED_AS_ADMIN, MSSQL_MEMBER_OF, MSSQL_SERVICE_ACCOUNT_FOR,
    SAME_HOST_AS,
    SCCM_ADMINS_REPLICATED_TO, SCCM_ALL_PERMISSIONS, SCCM_APPLICATION_ADMINISTRATOR,
    SCCM_ASSIGN_ALL_PERMISSIONS, SCCM_ASSIGN_SPECIFIC_PERMISSIONS, SCCM_CONTAINS,
    SCCM_FULL_ADMINISTRATOR, SCCM_HAS_AD_LAST_LOGON_USER, SCCM_HAS_CLIENT,
    SCCM_HAS_CURRENT_USER, SCCM_HAS_MEMBER,
    SCCM_HAS_NETWORK_ACCESS_ACCOUNT, SCCM_HAS_PRIMARY_USER,
    SCCM_HAS_STORED_ACCOUNT, SCCM_IS_ASSIGNED, SCCM_IS_MAPPED_TO,
    # Note: SCCM_HasCollectionVar / SCCM_HasTaskSequence are intentionally
    # NOT in this list — the cmbp_seed baseline shows 0 for both kinds, so
    # we don't seed them either. The kind constants remain available for
    # real edge emission when CRED-* attack flows decrypt collection
    # variables / task sequences.
)

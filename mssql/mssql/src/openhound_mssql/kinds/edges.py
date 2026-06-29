"""Edge-kind string constants and traversability partitions for MSSQL.

All edge-kind strings are copied VERBATIM from MSSQLHound's Go output
(`internal/bloodhound/writer.go` `EdgeKinds`). Note that `HasSession` and the
BloodHound-native `MemberOf` partner edges have NO `MSSQL_` prefix; the MSSQL
membership edge is `MSSQL_MemberOf`.

The master set `ALL_EDGE_KINDS` is the set of edge kinds the collector can
actually produce: it is a superset of the 38 authoritative `knownEdgeTypes`
(from `integration_report_test.go`) plus the extra control/alter sub-kinds that
the per-edge generators emit (e.g. `MSSQL_ControlDB`, `MSSQL_ControlLogin`).
The two Go constants `MSSQL_CanExecuteOnServer` / `MSSQL_CanExecuteOnDB` are
deliberately excluded: they are defined in the Go struct but never emitted, are
absent from `knownEdgeTypes`, and have no property generator.

The three partitions below mirror the Go logic:
    - NON-TRAVERSABLE: exactly the kinds for which `edges.go IsTraversableEdge`
      returns false (the abstract permission edges).
    - POSSIBLE: the six kinds in `writer.go PossibleEdgeKinds` (traversable by
      default; `--disable-possible-edges` flips them to non-traversable).
    - TRAVERSABLE: every other producible kind (the offensive attack-path
      edges that are always traversable).
The three partitions are disjoint and together cover `ALL_EDGE_KINDS`.

Attributes:
    ALL_EDGE_KINDS: frozenset of every producible edge kind.
    TRAVERSABLE_EDGE_KINDS: always-traversable offensive edges.
    POSSIBLE_EDGE_KINDS: possible (best-effort) attack-path edges.
    NONTRAVERSABLE_EDGE_KINDS: abstract permission edges (default-included,
        disabled by `--disable-nontraversable-edges`).
"""

# --- Membership / structural -------------------------------------------------
MEMBER_OF = "MSSQL_MemberOf"
IS_MAPPED_TO = "MSSQL_IsMappedTo"
CONTAINS = "MSSQL_Contains"
OWNS = "MSSQL_Owns"
HAS_LOGIN = "MSSQL_HasLogin"

# --- Server-level control / impersonation -----------------------------------
CONTROL_SERVER = "MSSQL_ControlServer"
CONTROL_DB = "MSSQL_ControlDB"
CONTROL_DB_ROLE = "MSSQL_ControlDBRole"
CONTROL_DB_USER = "MSSQL_ControlDBUser"
CONTROL_LOGIN = "MSSQL_ControlLogin"
CONTROL_SERVER_ROLE = "MSSQL_ControlServerRole"
CONTROL = "MSSQL_Control"
IMPERSONATE = "MSSQL_Impersonate"
IMPERSONATE_ANY_LOGIN = "MSSQL_ImpersonateAnyLogin"
IMPERSONATE_DB_USER = "MSSQL_ImpersonateDBUser"
IMPERSONATE_LOGIN = "MSSQL_ImpersonateLogin"

# --- Alter / ownership -------------------------------------------------------
ALTER = "MSSQL_Alter"
ALTER_DB = "MSSQL_AlterDB"
ALTER_DB_ROLE = "MSSQL_AlterDBRole"
ALTER_SERVER_ROLE = "MSSQL_AlterServerRole"
ALTER_ANY_LOGIN = "MSSQL_AlterAnyLogin"
ALTER_ANY_SERVER_ROLE = "MSSQL_AlterAnyServerRole"
ALTER_ANY_ROLE = "MSSQL_AlterAnyRole"
ALTER_ANY_DB_ROLE = "MSSQL_AlterAnyDBRole"
ALTER_ANY_APP_ROLE = "MSSQL_AlterAnyAppRole"
CHANGE_OWNER = "MSSQL_ChangeOwner"
TAKE_OWNERSHIP = "MSSQL_TakeOwnership"
DB_TAKE_OWNERSHIP = "MSSQL_DBTakeOwnership"

# --- Membership / privilege grants ------------------------------------------
ADD_MEMBER = "MSSQL_AddMember"
CHANGE_PASSWORD = "MSSQL_ChangePassword"
GRANT_ANY_PERMISSION = "MSSQL_GrantAnyPermission"
GRANT_ANY_DB_PERMISSION = "MSSQL_GrantAnyDBPermission"

# --- Execution context -------------------------------------------------------
EXECUTE_AS = "MSSQL_ExecuteAs"
EXECUTE_AS_OWNER = "MSSQL_ExecuteAsOwner"
EXECUTE_ON_HOST = "MSSQL_ExecuteOnHost"

# --- Connection --------------------------------------------------------------
CONNECT = "MSSQL_Connect"
CONNECT_ANY_DATABASE = "MSSQL_ConnectAnyDatabase"

# --- Linked servers ----------------------------------------------------------
LINKED_TO = "MSSQL_LinkedTo"
LINKED_AS_ADMIN = "MSSQL_LinkedAsAdmin"

# --- Credentials / proxies ---------------------------------------------------
HAS_DB_SCOPED_CRED = "MSSQL_HasDBScopedCred"
HAS_MAPPED_CRED = "MSSQL_HasMappedCred"
HAS_PROXY_CRED = "MSSQL_HasProxyCred"

# --- Host / coercion / Kerberos ----------------------------------------------
SERVICE_ACCOUNT_FOR = "MSSQL_ServiceAccountFor"
HOST_FOR = "MSSQL_HostFor"
IS_TRUSTED_BY = "MSSQL_IsTrustedBy"
GET_TGS = "MSSQL_GetTGS"
GET_ADMIN_TGS = "MSSQL_GetAdminTGS"
COERCE_AND_RELAY_TO_MSSQL = "MSSQL_CoerceAndRelayToMSSQL"

# --- Non-MSSQL_ kinds (BloodHound-native) ------------------------------------
# Computer -> service-account Base node.
HAS_SESSION = "HasSession"

# Master set of every producible edge kind.
ALL_EDGE_KINDS = frozenset(
    {
        MEMBER_OF,
        IS_MAPPED_TO,
        CONTAINS,
        OWNS,
        HAS_LOGIN,
        CONTROL_SERVER,
        CONTROL_DB,
        CONTROL_DB_ROLE,
        CONTROL_DB_USER,
        CONTROL_LOGIN,
        CONTROL_SERVER_ROLE,
        CONTROL,
        IMPERSONATE,
        IMPERSONATE_ANY_LOGIN,
        IMPERSONATE_DB_USER,
        IMPERSONATE_LOGIN,
        ALTER,
        ALTER_DB,
        ALTER_DB_ROLE,
        ALTER_SERVER_ROLE,
        ALTER_ANY_LOGIN,
        ALTER_ANY_SERVER_ROLE,
        ALTER_ANY_ROLE,
        ALTER_ANY_DB_ROLE,
        ALTER_ANY_APP_ROLE,
        CHANGE_OWNER,
        TAKE_OWNERSHIP,
        DB_TAKE_OWNERSHIP,
        ADD_MEMBER,
        CHANGE_PASSWORD,
        GRANT_ANY_PERMISSION,
        GRANT_ANY_DB_PERMISSION,
        EXECUTE_AS,
        EXECUTE_AS_OWNER,
        EXECUTE_ON_HOST,
        CONNECT,
        CONNECT_ANY_DATABASE,
        LINKED_TO,
        LINKED_AS_ADMIN,
        HAS_DB_SCOPED_CRED,
        HAS_MAPPED_CRED,
        HAS_PROXY_CRED,
        SERVICE_ACCOUNT_FOR,
        HOST_FOR,
        IS_TRUSTED_BY,
        GET_TGS,
        GET_ADMIN_TGS,
        COERCE_AND_RELAY_TO_MSSQL,
        HAS_SESSION,
    }
)

# Possible (best-effort) attack-path edges. Mirrors writer.go PossibleEdgeKinds.
# Traversable by default; `--disable-possible-edges` flips them off and rewrites
# the schema's is_traversable flag.
POSSIBLE_EDGE_KINDS = frozenset(
    {
        LINKED_TO,
        IS_TRUSTED_BY,
        SERVICE_ACCOUNT_FOR,
        HAS_DB_SCOPED_CRED,
        HAS_MAPPED_CRED,
        HAS_PROXY_CRED,
    }
)

# Abstract permission edges that `edges.go IsTraversableEdge` returns false for.
# Default-included; `--disable-nontraversable-edges` suppresses them. This set
# is copied EXACTLY from the Go `IsTraversableEdge` switch — note that
# MSSQL_AlterAnyRole is NOT in that switch (so it is traversable in Go), which
# is why it is absent here even though spec §6 listed it.
NONTRAVERSABLE_EDGE_KINDS = frozenset(
    {
        ALTER,
        CONTROL,
        IMPERSONATE,
        ALTER_ANY_LOGIN,
        ALTER_ANY_SERVER_ROLE,
        ALTER_ANY_APP_ROLE,
        ALTER_ANY_DB_ROLE,
        CONNECT,
        CONNECT_ANY_DATABASE,
        TAKE_OWNERSHIP,
        ALTER_DB,
        ALTER_DB_ROLE,
        ALTER_SERVER_ROLE,
        IMPERSONATE_DB_USER,
        IMPERSONATE_LOGIN,
    }
)

# Always-traversable offensive edges: everything else the collector produces.
# Derived so the three partitions stay disjoint and exhaustive over the master
# set even as kinds are added.
TRAVERSABLE_EDGE_KINDS = frozenset(
    ALL_EDGE_KINDS - NONTRAVERSABLE_EDGE_KINDS - POSSIBLE_EDGE_KINDS
)

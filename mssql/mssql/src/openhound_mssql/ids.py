"""Stable ObjectIdentifier construction for MSSQL graph entities.

Pure functions that reproduce MSSQLHound's ID scheme exactly (Go
`internal/mssql/client.go` + `internal/collector/collector.go`), so the
emitted graph keys match the validator fixtures. ID formats:

    server         <computerSID-or-lowerhost>:<instance!=MSSQLSERVER else port>
    login/role     <name>@<serverOID>
    database       <serverOID>\\<dbName>
    db principal   <name>@<serverOID>\\<dbName>

No logging here: these are leaf string builders with no branches that can
fail; behaviour is fully covered by `tests/unit/test_ids.py`.
"""

from __future__ import annotations

# Default SQL Server instance name. A default instance is keyed by port; a
# named instance is keyed by its instance name (collector.go addServerToProcess).
DEFAULT_INSTANCE = "MSSQLSERVER"


def server_oid(
    computer_sid: str | None,
    hostname: str,
    instance: str | None,
    port: int,
) -> str:
    """Build the stable ObjectIdentifier for a SQL Server instance.

    Prefers the resolved computer SID; falls back to the lowercased hostname
    when no SID is known. A named (non-default) instance is keyed by instance
    name, otherwise by port. Mirrors collector.go `addServerToProcess`.

    Args:
        computer_sid: Resolved machine SID, or None/empty to fall back to host.
        hostname: Host name (lowercased when used as the key base).
        instance: SQL instance name; the default ("MSSQLSERVER") keys by port.
        port: TCP port, used when the instance is the default instance.

    Returns:
        The server ObjectIdentifier string.
    """
    base = computer_sid if computer_sid else hostname.lower()
    if instance and instance != DEFAULT_INSTANCE:
        return f"{base}:{instance}"
    return f"{base}:{port}"


def principal_oid(name: str, server_oid: str) -> str:
    """Build the ObjectIdentifier for a server-level principal (login/role).

    Args:
        name: Principal name (e.g. "sa", "sysadmin").
        server_oid: The owning server's ObjectIdentifier.

    Returns:
        "<name>@<serverOID>".
    """
    return f"{name}@{server_oid}"


def database_oid(server_oid: str, db_name: str) -> str:
    """Build the ObjectIdentifier for a database.

    Args:
        server_oid: The owning server's ObjectIdentifier.
        db_name: Database name (e.g. "msdb").

    Returns:
        "<serverOID>\\<dbName>".
    """
    return f"{server_oid}\\{db_name}"


def db_principal_oid(name: str, server_oid: str, db_name: str) -> str:
    """Build the ObjectIdentifier for a database-level principal.

    Covers database users, database roles, and application roles.

    Args:
        name: Principal name (e.g. "dbo", "public").
        server_oid: The owning server's ObjectIdentifier.
        db_name: Database name the principal lives in.

    Returns:
        "<name>@<serverOID>\\<dbName>".
    """
    return f"{name}@{server_oid}\\{db_name}"


def extract_db_id(principal_id: str) -> str:
    """Extract the database ObjectIdentifier from a database-principal ID.

    Splits on the first "@" and returns the part after it, matching Go
    `edges.go extractDBID`. If there is no "@", the input is returned
    unchanged (Go behaviour).

    Args:
        principal_id: A database-principal ObjectIdentifier
            ("<name>@<serverOID>\\<dbName>").

    Returns:
        The database ObjectIdentifier ("<serverOID>\\<dbName>"), or the input
        unchanged when it contains no "@".
    """
    name, sep, rest = principal_id.partition("@")
    if sep:
        return rest
    return principal_id


def rewrite_server_id(old: str, new: str, objs: list[dict]) -> None:
    """Re-key all IDs in-place after a server's OID changes (host -> SID).

    When a server is re-keyed from its hostname-based ID to its resolved
    SID-based ID, every principal/database/permission ID that embedded the old
    server OID must be rewritten. Mirrors collector.go `updateObjectIdentifiers`
    by string-replacing the two embedding patterns across all string values in
    the supplied dicts:

        "@<old>"  -> "@<new>"     (principals: Name@serverOID...)
        "<old>\\" -> "<new>\\"    (databases: serverOID\\DBName)

    Each replacement is applied at most once per value (Go uses Replace with
    count 1). Operates on a flat list of row dicts (the JSONL rows convert
    consumes); non-string values are left untouched.

    Args:
        old: The previous server ObjectIdentifier.
        new: The newly resolved server ObjectIdentifier.
        objs: List of row dicts to rewrite in place.
    """
    at_old, at_new = f"@{old}", f"@{new}"
    slash_old, slash_new = f"{old}\\", f"{new}\\"

    for obj in objs:
        for key, value in obj.items():
            if not isinstance(value, str):
                continue
            # Database IDs embed the server OID as a prefix: "<old>\DBName".
            if slash_old in value:
                value = value.replace(slash_old, slash_new, 1)
            # Principal IDs embed it after an "@": "Name@<old>" (optionally
            # "...@<old>\DBName" for db principals; the "@<old>" replace
            # covers both since the trailing "\DBName" is preserved).
            if at_old in value:
                value = value.replace(at_old, at_new, 1)
            obj[key] = value

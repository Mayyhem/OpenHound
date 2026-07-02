"""Shared helpers for the convert-stage node assets.

Every MSSQL_* node carries the same server-scoped context: the server's stable
ObjectIdentifier (used as the OpenGraph ``id`` of the server node and the
``environmentid`` of every other node) and the SQL Server display name. Both are
derived from the single raw ``servers`` row that ``collect`` produced, the same
way ``transforms.py`` derives ``server_oid`` in preproc — so the node ids the
convert stage emits match the ids embedded in the derived lookup tables
(principal maps, role closures, ...).

The derivation is cached on the injected :class:`MSSQLLookup` instance (one per
convert run) so each node asset that needs the server context does not re-scan
the ``servers`` table. ``self._lookup`` is the read-only preproc DuckDB.

Why this duplicates ``transforms._derive_server_oid``: the two stages cannot
share an instance — preproc builds DuckDB; convert reads it back in a separate
process. The logic is identical (``ids.server_oid`` / collector.go
``addServerToProcess``): both prefer the resolved computer SID (Stage 7a stamps
the ``computer_sid`` column onto the ``servers`` row at collect time) so the
server OID is SID-based, and both fall back to the lowercased machine name +
default port when no SID was resolved (non-domain host). Because the OID is
derived once here from the already-resolved SID, no ID is ever built before the
SID is known — Go's ``updateObjectIdentifiers`` re-key rewrite is unnecessary in
this pipeline (``ids.rewrite_server_id`` exists for completeness).
"""
from __future__ import annotations

import logging
from typing import Optional

from .. import ids

logger = logging.getLogger(__name__)

# Default SQL Server port. The raw ``servers`` row carries no port (collect never
# queries it), so a default instance is keyed by this. Matches
# ``transforms._DEFAULT_PORT``.
_DEFAULT_PORT = 1433

# Cache attribute names planted on the lookup instance for the single-server
# context. Underscore-prefixed so they can't collide with a real lookup method.
_OID_ATTR = "_mssql_server_oid_cache"
_NAME_ATTR = "_mssql_sql_server_name_cache"


def _first(row: dict, *names: str):
    """Return the first present (non-None) value among *names* (case variants)."""
    for name in names:
        value = row.get(name)
        if value is not None:
            return value
    return None


def _server_context(lookup) -> tuple[str, str]:
    """Compute (server_oid, sql_server_name) once per convert run, memoized.

    Reads the single raw ``servers`` row from the preproc DuckDB and derives the
    server ObjectIdentifier identically to ``transforms._derive_server_oid``
    (prefer computer SID — not collected yet, so ``None`` -> lowercased machine
    name; named instance keys by instance name, else by default port).

    The SQL Server *display* name is the ``sql_server_name_display`` column the
    collect stage stamped onto the row (``<fqdn>:<port>``, Go's SQLServerName
    format). This is the value used as the server node ``name`` and as the
    ``SQLServer`` property on EVERY other node (collector.go sets
    ``principal.SQLServerName = serverInfo.SQLServerName``). It is resolved at
    collect time (SPN / DNS / DEFAULT_DOMAIN) — convert never re-derives it from
    the tool host's domain.

    Returns ``("", "")`` when there is no ``servers`` row so a node asset can
    detect the empty case and drop the row rather than emit a malformed id.
    """
    cached_oid = getattr(lookup, _OID_ATTR, None)
    if cached_oid is not None:
        # Already derived this run — return the memoized pair.
        return cached_oid, getattr(lookup, _NAME_ATTR, "")

    row = next(iter(lookup.table_rows("servers")), None)
    if row is None:
        # No servers row: convert has nothing to anchor nodes to. Cache the empty
        # context so we only log this once.
        logger.warning("convert: no rows in servers table; node ids will be empty")
        setattr(lookup, _OID_ATTR, "")
        setattr(lookup, _NAME_ATTR, "")
        return "", ""

    # dlt snake_cases the collected camelCase keys (MachineName -> machine_name).
    machine = (
        _first(row, "machine_name", "MachineName", "machinename")
        or _first(row, "server_name", "ServerName", "servername")
        or ""
    )
    instance = _first(row, "instance_name", "InstanceName", "instancename") or ""
    # Stage 7a: prefer the resolved computer SID (stamped at collect time) so the
    # server OID is SID-based (<computerSID>:<port>), matching Go and transforms.
    computer_sid = _first(row, "computer_sid", "computersid") or None
    # MachineName can be HOST or HOST\INSTANCE; take the bare host for the key base.
    hostname = str(machine).split("\\", 1)[0] if machine else ""
    if not hostname:
        logger.warning("convert: servers row has no MachineName/ServerName; server_oid will be blank")
    server_oid = ids.server_oid(
        str(computer_sid) if computer_sid else None,
        hostname, str(instance) if instance else None, _DEFAULT_PORT,
    )

    # Display name: the collect-time-resolved <fqdn>:<port>. Fall back to fqdn,
    # then the server_oid, so it is always non-empty.
    display = (
        _first(row, "sql_server_name_display", "sql_server_name")
        or _first(row, "fqdn")
        or server_oid
    )
    logger.debug("convert: derived server_oid=%s sqlServerName=%s", server_oid, display)
    setattr(lookup, _OID_ATTR, server_oid)
    setattr(lookup, _NAME_ATTR, str(display))
    return server_oid, str(display)


def server_oid_for(lookup) -> str:
    """The server ObjectIdentifier for this convert run (cached)."""
    return _server_context(lookup)[0]


def sql_server_name_for(lookup) -> str:
    """The SQL Server display name for this convert run (cached)."""
    return _server_context(lookup)[1]


def as_bool(value) -> bool:
    """Coerce a raw DuckDB value (0/1, '0'/'1', true/false, bool) to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "t", "yes", "y")
    return False


def as_int(value, default: int = 0) -> int:
    """Coerce a raw value to int, returning *default* when blank/uncoercible."""
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def rfc3339(value) -> str:
    """Format a DuckDB date/datetime value as RFC3339, matching the Go output.

    The raw ``create_date`` / ``modify_date`` columns arrive as Python
    ``datetime``/``date`` (DuckDB native) or as strings. Go formats with
    ``time.RFC3339`` (``2006-01-02T15:04:05Z07:00``). We reproduce that: a naive
    datetime (no tzinfo — SQL Server catalog dates are UTC-naive) is rendered with
    a trailing ``Z``; a string is passed through. Empty/None -> "".
    """
    if value is None or value == "":
        return ""
    # datetime/date have isoformat(); strings are passed through verbatim.
    isoformat = getattr(value, "isoformat", None)
    if isoformat is None:
        return str(value)
    text = isoformat()
    # A naive datetime ("2024-01-02T03:04:05") gets a trailing Z to mark UTC,
    # matching Go's RFC3339 rendering of a UTC time. A date-only value
    # ("2024-01-02") is left as-is.
    if "T" in text and "+" not in text and not text.endswith("Z"):
        text += "Z"
    return text

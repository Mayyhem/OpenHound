"""DLT source for the MSSQL collector — one emit resource per raw table.

The collector *pushes* rows: a worker pool (run by ``main.py::_run_collection``
on a background thread) connects to each target and runs ``collect_server``,
which yields ``(table, row)`` pairs. DLT *pulls* rows: each ``@app.resource`` is
a generator the extract pass iterates. The push->pull gap is bridged by
:class:`openhound_collector_common.dlt.source_bridge.StreamBridge` — a registry
of bounded per-table queues. The worker pool ``put``s rows; the emit resources
below drain them (blocking until a shared ``DONE`` sentinel).

This mirrors the SCCM extension's ``source.py``, minus the multi-protocol
per-host phase machinery: MSSQL has a single per-target step (connect + run
``collect_server``), so there is no discovery pass and no recursive work queue
here — just the emit resources and a module-global handoff for the bridge the
producer installs before the extract pass.

``COLLECTED_TABLES`` is the exact set of table names ``collect_server`` yields
(spec §8 / ``collection/server.py``). One emit resource is registered per table.
"""
from __future__ import annotations

import logging

from openhound_collector_common.dlt.source_bridge import StreamBridge

from .main import app
from .models.raw_table import raw_table_asset

logger = logging.getLogger(__name__)


# The raw tables collect_server yields, in first-seen order (spec §8). Each gets
# one bounded queue and one emit resource. Keep this in lockstep with the
# ``yield ("<table>", ...)`` sites in collection/server.py.
COLLECTED_TABLES: tuple[str, ...] = (
    "servers",
    "service_accounts",
    "credentials",
    "proxy_accounts",
    "proxy_subsystems",
    "proxy_logins",
    "server_principals",
    "server_principal_credentials",
    "server_role_members",
    "server_permissions",
    "local_group_members",
    "databases",
    "database_principals",
    "database_principal_logins",
    "database_role_members",
    "database_permissions",
    "database_scoped_credentials",
    "linked_servers",
    # Stage 7a: collect-time AD SID/object resolutions (one row per resolved AD
    # object), the source for the AD node table built in preproc.
    "ad_resolved",
)


# ---------------------------------------------------------------------------
# Shared per-run bridge — planted by _run_collection() before the extract pass
# so the emit resources built inside source() drain the same queues the worker
# pool fills. Mirrors SCCM's module-global stream-registry handoff.
# ---------------------------------------------------------------------------
_bridge: StreamBridge | None = None


def set_bridge(bridge: StreamBridge | None) -> None:
    """Plant (or clear) the StreamBridge the next source() call will drain."""
    global _bridge
    _bridge = bridge


def get_bridge() -> StreamBridge | None:
    """Return the currently-installed StreamBridge (or None)."""
    return _bridge


@app.source(name="mssql", max_table_nesting=0)
def source():
    """Return one emit resource per collected table.

    Each emit resource drains its table's queue from the installed
    :class:`StreamBridge` via ``parallelized=True`` so every table streams in
    its own thread (a single-threaded extractor would deadlock on a momentarily
    empty queue — see source_bridge docs). ``_run_collection`` installs the
    bridge with :func:`set_bridge` just before running the extract pass.

    When no bridge is installed (e.g. ``convert`` re-imports the source as a
    no-op, or a misconfigured call), the emit resources still build but their
    ``drain_stream`` returns immediately — yielding nothing — so the source is
    always safe to call.
    """
    bridge = _bridge
    if bridge is None:
        # No producer installed: build a throwaway bridge over the canonical
        # table set so the source is still importable/callable and conformance
        # tests see the full resource set. Its queues are never fed, and the
        # emit generators yield nothing because drain_stream returns on a
        # missing/empty registry only after DONE — so we never start one here.
        # Use an empty-by-construction bridge whose drain returns immediately.
        logger.debug("source(): no StreamBridge installed; returning idle emit resources")
        bridge = _IdleBridge(COLLECTED_TABLES)

    return tuple(bridge.build_emit_resources(app.resource, raw_table_asset))


class _IdleBridge(StreamBridge):
    """A StreamBridge whose emit resources finish immediately (no producer).

    Used when ``source()`` is called without an installed bridge (convert's
    no-op re-import, or conformance tests): each emit resource yields nothing
    and returns at once instead of blocking forever on a ``DONE`` that will
    never arrive.
    """

    def drain_stream(self, table_name: str):  # noqa: D401 - see class docstring
        # No producer will ever push or broadcast DONE, so yield nothing.
        return iter(())


__all__ = ["COLLECTED_TABLES", "source", "set_bridge", "get_bridge"]

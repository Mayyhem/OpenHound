"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the wmi phase.
The shared :class:`SourceContext` cache is built once in ``source.py`` and
passed into each resource. All decorators register onto the same
``app`` instance created in ``main.py``.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import socket
import subprocess
from typing import Any, Iterable, Optional

import dlt

from ..clients.ad import ADClient, ADCredentials
from ..context import SourceContext
from ..main import app
from ..models.raw_table import raw_table_asset
from ..log_context import per_host_iter, per_pair_iter, with_log_context
from .mssql import _probe_mssql_epa

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase 3c — WMI / HTTP / SMB per-host enrichment.
# ---------------------------------------------------------------------------
# These resources enrich existing Computer / SCCM_ClientDevice nodes with
# additional properties (current user, PrimaryUser, SQL service account, MP
# / DP / SMS Provider role flags, SMB signing). They do NOT introduce new
# node kinds — Phase 4 SQL views consume the new tables to derive edges
# (HasSession, MSSQL_ServiceAccountFor, CoerceAndRelayToSMB, etc.).
#
# WMI uses impacket's DCOM bindings; HTTP shells out to ``curl.exe`` for the
# same Python-3.14 OPENSSL_Uplink reasons documented for AdminService (see
# Risk 8 in HANDOFF). SMB uses impacket's ``SMBConnection`` plus a bespoke
# raw SMB2 negotiate for signing detection.
#
# CMBP references:
#   - ``lib/collectors/wmi_collector.py``  (~1,549 LOC) - mostly mirrors
#     AdminService; here we only add the gap-filler queries (CCM_Client,
#     CCM_UsersSeenOnSystem, Win32_Service for the SQL service account).
#   - ``lib/collectors/http_collector.py`` (~560 LOC) - role fingerprinting.
#   - ``lib/collectors/smb_collector.py``  (~939 LOC) - share enum + SMB2
#     negotiate signing probe.
#
# CRED-2/3/5/6 attack flows are intentionally STUBBED here. Phase 4 secret
# policy edges cope with empty NAA / collection-secret tables.

# ---- WMI helper -----------------------------------------------------------

def _wmi_query(
    hostname: str,
    namespace: str,
    wql: str,
    domain: str,
    username: Optional[str],
    password: Optional[str],
) -> Optional[list[dict[str, Any]]]:
    """Run a single WQL query against ``hostname\\namespace`` and return rows.

    Returns ``None`` if the connection fails (port closed / auth denied / WMI
    namespace unavailable). Returns an empty list if the namespace responded
    but the query yielded no rows. Hosts the ``with`` boilerplate so callers
    don't have to manage DCOM lifecycle.

    Defers all impacket imports until first use - same OPENSSL_Uplink
    avoidance pattern used elsewhere.
    """
    # Fast TCP probe to skip dead hosts cheaply (DCOM uses 135).
    logger.verbose("Probing WMI on %s (port 135)", hostname)
    try:
        with socket.create_connection((hostname, 135), timeout=3):
            pass
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.verbose("wmi: %s:135 unreachable: %s", hostname, e)
        return None

    try:
        from impacket.dcerpc.v5.dcom import wmi as impacket_wmi
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.dtypes import NULL
    except ImportError:
        logger.warning("wmi: impacket DCOM bindings unavailable, skipping host %s", hostname)
        return None

    auth_domain, user = _split_user_domain(username, domain)
    if not user or not password:
        logger.debug("wmi: no explicit creds for %s, skipping (Negotiate not supported by impacket-DCOM)", hostname)
        return None

    dcom = None
    try:
        dcom = DCOMConnection(hostname, username=user, password=password, domain=auth_domain)
        iInterface = dcom.CoCreateInstanceEx(
            impacket_wmi.CLSID_WbemLevel1Login,
            impacket_wmi.IID_IWbemLevel1Login,
        )
        iWbemLevel1Login = impacket_wmi.IWbemLevel1Login(iInterface)
        services = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
        iWbemLevel1Login.RemRelease()
    except Exception as e:  # noqa: BLE001
        logger.verbose("wmi: connect to %s namespace %s failed: %s", hostname, namespace, e)
        if dcom is not None:
            try:
                dcom.disconnect()
            except Exception:
                pass
        return None

    rows: list[dict[str, Any]] = []
    try:
        enum = services.ExecQuery(wql)
    except Exception as e:  # noqa: BLE001
        logger.verbose("wmi: query failed on %s [%s]: %s", hostname, wql[:80], e)
        try:
            dcom.disconnect()
        except Exception:
            pass
        return None

    try:
        while True:
            try:
                objects = enum.Next(0xFFFFFFFF, 1)
            except Exception:
                break
            if not objects:
                break
            for obj in objects:
                try:
                    props = obj.getProperties()
                    rows.append({k: v.get("value") for k, v in props.items()})
                except Exception as e:  # noqa: BLE001
                    logger.debug("wmi: property parse failed on %s: %s", hostname, e)
    finally:
        try:
            dcom.disconnect()
        except Exception:
            pass
    return rows


def _adminservice_hosts_seen(ctx: "SourceContext") -> set[str]:
    """Return the set of hostnames for which AdminService already produced data.

    WMI fallback is only run for hosts whose AdminService payload was empty.
    """
    payloads = ctx.adminservice_payloads()
    seen: set[str] = set()
    for _provider, payload in payloads.items():
        for dev in payload.get("client_devices", []):
            host = (dev.get("hostname") or "").lower()
            if host:
                seen.add(host)
        for ss in payload.get("site_systems", []):
            host = (ss.get("hostname") or "").lower()
            if host:
                seen.add(host)
    return seen


@app.resource(name="wmi_clients", parallelized=False, columns=raw_table_asset("wmi_clients"))
@with_log_context(phase="WMI")
def wmi_clients(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Per-host CCM_Client properties via WMI fallback.

    Yields one row per AD computer that responds to a ``SELECT * FROM
    CCM_Client`` query in the ``root\\ccm`` namespace. Skipped silently for
    hosts where AdminService already returned a client-device row, since the
    WMI data is a strict subset.

    CMBP reference: ``wmi_collector.py`` (gap-filler client enumeration).
    """
    if not ctx.method_enabled("WMI"):
        logger.info("wmi_clients: disabled via --collection-methods")
        return
    seen = _adminservice_hosts_seen(ctx)
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        if hostname in seen:
            continue
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "wmi_clients") == "done":
            continue
        logger.info("Starting WMI collection on %s...", hostname)
        logger.info("Connecting to WMI namespace: root\\ccm on %s", hostname)
        rows = _wmi_query(
            hostname=hostname,
            namespace="root\\ccm",
            wql="SELECT ClientId, ClientVersion, AllowLocalAdminOverride FROM CCM_Client",
            domain=ctx.domain,
            username=ctx.username,
            password=ctx.password,
        )
        if not rows:
            logger.info("Could not connect to WMI namespace root\\ccm on %s", hostname)
        else:
            logger.info("Connected to WMI namespace")
            logger.info("Found %d CCM_Client rows on %s", len(rows), hostname)
            for r in rows:
                client_id = (r.get("ClientId") or "").strip()
                if not client_id:
                    continue
                yield {
                    "hostname": hostname,
                    "client_id": client_id,
                    "client_version": (r.get("ClientVersion") or "").strip(),
                    "allow_local_admin_override": bool(r.get("AllowLocalAdminOverride")),
                    "computer_sid": host.get("sid"),
                    "source": "WMI-CCM_Client",
                    "domain": ctx.domain,
                }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "wmi_clients")


@app.resource(name="wmi_users_seen", parallelized=False, columns=raw_table_asset("wmi_users_seen"))
@with_log_context(phase="WMI")
def wmi_users_seen(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per (host, user) pair from CCM_UsersSeenOnSystem.

    Drives Phase 4's ``SCCM_HasADLastLogonUser`` / ``SCCM_HasCurrentUser``
    edge generation. Only run for hosts where AdminService didn't already
    provide a primary/last-logon user.

    CMBP reference: ``wmi_collector.py::_get_combined_device_resources_via_wmi``.
    """
    if not ctx.method_enabled("WMI"):
        return
    seen = _adminservice_hosts_seen(ctx)
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        if hostname in seen:
            continue
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "wmi_users_seen") == "done":
            continue
        rows = _wmi_query(
            hostname=hostname,
            namespace="root\\ccm",
            wql="SELECT UserName, LastSeen FROM CCM_UsersSeenOnSystem",
            domain=ctx.domain,
            username=ctx.username,
            password=ctx.password,
        )
        if rows:
            for r in rows:
                user_name = (r.get("UserName") or "").strip()
                if not user_name:
                    continue
                yield {
                    "hostname": hostname,
                    "user_name": user_name,
                    "last_seen": r.get("LastSeen"),
                    "computer_sid": host.get("sid"),
                    "source": "WMI-CCM_UsersSeenOnSystem",
                    "domain": ctx.domain,
                }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "wmi_users_seen")


@app.resource(name="wmi_sql_service_accounts", parallelized=False, columns=raw_table_asset("wmi_sql_service_accounts"))
@with_log_context(phase="WMI")
def wmi_sql_service_accounts(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per SQL Server service account discovered via Win32_Service.

    Phase 4 uses this to materialise ``MSSQL_ServiceAccountFor``,
    ``MSSQL_GetTGS``, and ``HasSession`` edges.

    Only queries hosts that responded to the MSSQL EPA TDS PRELOGIN probe -
    most computers don't run a SQL service so the WMI call would be wasted.
    """
    if not ctx.method_enabled("WMI"):
        return

    # Probe each target for SQL Server (TCP/1433) then query Win32_Service
    # on confirmed SQL hosts. Combined into a single per-host loop so
    # mark_done fires for every host regardless of whether 1433 is open.
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "wmi_sql_service_accounts") == "done":
            continue
        epa = _probe_mssql_epa(hostname, 1433)
        if epa is not None:
            rows = _wmi_query(
                hostname=hostname,
                namespace="root\\cimv2",
                wql="SELECT Name, StartName, PathName FROM Win32_Service WHERE Name='MSSQLSERVER' OR Name LIKE 'MSSQL$%'",
                domain=ctx.domain,
                username=ctx.username,
                password=ctx.password,
            )
            if rows:
                for r in rows:
                    service_name = (r.get("Name") or "").strip()
                    start_name = (r.get("StartName") or "").strip()
                    if not service_name or not start_name:
                        continue
                    yield {
                        "hostname": hostname,
                        "service_name": service_name,
                        "service_account": start_name,
                        "path_name": (r.get("PathName") or "").strip(),
                        "computer_sid": host.get("sid"),
                        "source": "WMI-Win32_Service",
                        "domain": ctx.domain,
                    }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "wmi_sql_service_accounts")


# ---- HTTP fingerprinting (curl-based for TLS) -----------------------------

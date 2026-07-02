"""Per-target collection engine: the *producer* half of the push->pull bridge.

:func:`collect_targets` is the worker pool that ``main.py::_run_collection`` runs
on a background thread. For each resolved :class:`Target` it:

1. connects to the target with the run's credentials (``auth.connect``),
2. builds a best-effort :class:`WmiClient` (Windows + domain creds) for the
   service-account / local-group steps,
3. runs ``collect_server`` and pushes every yielded ``(table, row)`` onto the
   shared :class:`StreamBridge`.

A single target that fails to connect is logged and skipped — the run continues
and produces partial output (matching the Go binary, which never aborts the
whole run on one unreachable server). After every target is done the pool
broadcasts ``DONE`` so the emit resources can finish.

Concurrency: ``cfg.workers`` controls the pool. ``0`` (the default) means run
targets sequentially on this (the background) thread; ``N>0`` uses an N-thread
pool. The bridge's queues are bounded, so workers block on ``put`` when the
extract pass falls behind — flat memory regardless of how much each server
yields. Per-target log lines are tagged ``[target]`` via the shared log context.
"""
from __future__ import annotations

import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from openhound_collector_common.clients.wmi import WmiAuth, WmiClient
from openhound_collector_common.dlt.source_bridge import StreamBridge
from openhound_collector_common.logging import log_context

from ..auth import CollectionConfig, build_ldap_auth, connect
from .server import ServerContext, collect_server
from .targets import Target

logger = logging.getLogger(__name__)


def collect_targets(targets: list[Target], cfg: CollectionConfig, bridge: StreamBridge) -> None:
    """Run the per-target collection, pushing rows onto *bridge*, then broadcast DONE.

    Always broadcasts ``DONE`` in a ``finally`` so the emit resources unblock
    even if the whole pool raises — without that the extract pass would hang.

    When ``--collect-from-linked`` is set, the linked-server step records each
    discovered remote server's data source into a shared set; after every initial
    target is collected, those newly-discovered servers are queued and collected
    as new targets, repeating (cycle-safe via a visited set) until no new server
    is found. This is recursion of the *collection itself* (distinct from the
    server-side linked-server recursion, which only enumerates + probes links).
    """
    ad = _build_ad_client(cfg)
    # Shared mutable set the linked-server step fills with discovered data sources
    # (only allocated under --collect-from-linked; None disables the recording).
    discovered: Optional[set] = set() if cfg.collect_from_linked else None
    # Hosts already collected (initial targets + any queued link), so the
    # collect-from-linked queueing never re-collects a server (cycle safety).
    visited: set = {_target_key(t.host) for t in targets}
    try:
        if not targets:
            # Nothing to collect (e.g. SPN enum found no servers). The emit
            # resources still need DONE to finish cleanly.
            logger.warning("No targets to collect; producing empty output")
            return
        _collect_pass(targets, cfg, bridge, ad, discovered)

        # --collect-from-linked: queue newly-discovered linked servers and collect
        # from them too, until the discovery set adds nothing new (cycle-safe).
        if cfg.collect_from_linked and discovered is not None:
            _collect_from_linked(cfg, bridge, ad, discovered, visited)
    finally:
        # Signal end-of-stream to every emit resource exactly once.
        bridge.broadcast_done()
        # Release the shared LDAP connection (if any).
        _close_quietly(ad, "shared AD client")


def _collect_pass(targets: list[Target], cfg: CollectionConfig, bridge: StreamBridge,
                  ad, discovered: Optional[set]) -> None:
    """Collect one batch of targets (parallel or sequential per ``cfg.workers``)."""
    if cfg.workers and cfg.workers > 0:
        logger.info("Collecting %d target(s) with a %d-worker pool", len(targets), cfg.workers)
        _collect_parallel(targets, cfg, bridge, cfg.workers, ad, discovered)
    else:
        logger.info("Collecting %d target(s) sequentially (workers=0)", len(targets))
        for target in targets:
            _collect_one(target, cfg, bridge, ad, discovered)


def _collect_from_linked(cfg: CollectionConfig, bridge: StreamBridge, ad,
                         discovered: set, visited: set) -> None:
    """Queue + collect newly-discovered linked servers until none remain.

    Each round takes the discovered data sources not yet in *visited*, turns them
    into :class:`Target` objects, marks them visited, and collects them — which may
    discover further links. The visited set guarantees termination even with link
    cycles (A->B->A). Discovered data sources may be ``host``, ``host\\instance``,
    ``host,port``, or an Azure/RDS FQDN; the connection string is handed to the SQL
    client the same way an explicit ``-t`` target would be.
    """
    round_num = 0
    while True:
        pending = sorted(s for s in discovered if _target_key(s) not in visited)
        if not pending:
            # No new linked server discovered this round — done.
            logger.verbose("collect-from-linked: no new linked servers to queue")
            return
        round_num += 1
        for source in pending:
            visited.add(_target_key(source))
        queued = [Target(host=_data_source_host(s), connection_string=s) for s in pending]
        logger.info("collect-from-linked round %d: queuing %d discovered server(s): %s",
                    round_num, len(queued), ", ".join(pending))
        _collect_pass(queued, cfg, bridge, ad, discovered)


def _target_key(host_or_source: str) -> str:
    """Normalize a host / data-source string to a comparison key (lowercased host).

    Strips an instance (``HOST\\INSTANCE``) or ``host,port`` suffix so a server
    reached via different link spellings isn't collected twice.
    """
    key = (host_or_source or "").strip().lower()
    for sep in ("\\", ","):
        if sep in key:
            key = key.split(sep, 1)[0]
    return key


def _data_source_host(data_source: str) -> str:
    """Extract the bare host from a linked-server data source for :class:`Target`."""
    host = (data_source or "").strip()
    for sep in ("\\", ","):
        if sep in host:
            host = host.split(sep, 1)[0]
    return host


def _build_ad_client(cfg: CollectionConfig):
    """Build one shared :class:`AdClient` for collect-time SID/object resolution.

    Returns ``None`` (LDAP-backed steps skipped, OIDs fall back to the hostname)
    when no domain is configured — matching Go, which only resolves SIDs when a
    domain is set. The client is built even with ``--skip-ad-nodes`` because the
    *computer SID* resolution (which keys the server ObjectIdentifier) must still
    run; only the referenced-object resolution that feeds the AD nodes is skipped
    (in ``collect_server`` via ``ctx.ad`` being passed but the AD-node table being
    built empty in preproc). A construction error is non-fatal: log and run
    without AD enrichment (OIDs fall back to the hostname).
    """
    if not cfg.domain:
        logger.info("No --domain configured; skipping AD SID resolution (OIDs fall back to hostname)")
        return None
    try:
        from openhound_collector_common.clients.ad import AdClient

        return AdClient(domain=cfg.domain, dc=cfg.dc or None, auth=build_ldap_auth(cfg))
    except Exception as ex:  # noqa: BLE001 - AD enrichment is best-effort
        logger.warning("Could not build AD client for SID resolution: %s", ex)
        return None


def _collect_parallel(targets: list[Target], cfg: CollectionConfig,
                      bridge: StreamBridge, workers: int, ad, discovered=None) -> None:
    """Collect targets across an N-thread pool, isolating per-target failures."""
    # Cap the pool at the target count so we never spin idle threads.
    pool_size = min(workers, len(targets))
    with ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="mssql-collect") as pool:
        futures = {pool.submit(_collect_one, target, cfg, bridge, ad, discovered): target for target in targets}
        for future in futures:
            target = futures[future]
            try:
                future.result()
            except Exception as ex:  # noqa: BLE001 - one target must not abort the run
                # _collect_one already logs; this is the belt-and-suspenders guard
                # so a worker exception can't propagate and kill the pool.
                logger.error("Unhandled error collecting %s: %s", target.connection_string, ex)


def _collect_one(target: Target, cfg: CollectionConfig, bridge: StreamBridge, ad=None,
                 discovered=None) -> None:
    """Collect a single target: connect, build WMI, run collect_server, push rows.

    A connect failure (lockout-safe stop, unreachable host, lowpriv denied) logs
    and returns — the target contributes no rows but the run continues.

    *discovered* (when not None, i.e. ``--collect-from-linked``) is the shared set
    the linked-server step adds each discovered remote data source to, so the run
    can queue those servers as new targets.
    """
    connection_string = target.connection_string or target.host
    with log_context.target_context(connection_string):
        conn = None
        try:
            conn = connect(connection_string, cfg)
        except Exception as ex:  # noqa: BLE001 - connect failure is per-target, not fatal
            # Partial-output-from-SPN (Stage 3.1/7) is not wired yet; for now a
            # failed connect simply yields nothing for this target.
            logger.error("Failed to connect to %s: %s", connection_string, ex)
            return

        wmi = _build_wmi(target, cfg)
        try:
            # Pass the target's discovered SPNs so collect_server can resolve the
            # canonical FQDN from MSSQLSvc/<fqdn> (preferred over DNS / DEFAULT_DOMAIN),
            # and the resolved computer SID so the server ObjectIdentifier is keyed by
            # SID (Stage 7a) — matching Go's `<computerSID>:<port>` instead of the
            # hostname fallback. discovered_links is the shared collect-from-linked sink.
            ctx = ServerContext(
                target=connection_string, cfg=cfg, wmi=wmi,
                spns=list(getattr(target, "spns", []) or []),
                computer_sid=getattr(target, "object_sid", None),
                ad=ad,
                discovered_links=discovered,
            )
            row_count = 0
            for table_name, row in collect_server(conn, ctx):
                bridge.put(table_name, row)
                row_count += 1
            logger.info("Collected %d row(s) from %s", row_count, connection_string)
        except Exception as ex:  # noqa: BLE001 - a mid-collection error is per-target
            logger.error("Error during collection of %s: %s", connection_string, ex)
        finally:
            # Always release the SQL connection and the WMI/DCOM session.
            _close_quietly(conn, f"SQL connection to {connection_string}")
            _close_quietly(wmi, f"WMI client for {connection_string}")


def _build_wmi(target: Target, cfg: CollectionConfig) -> Optional[WmiClient]:
    """Build a best-effort WmiClient for the host's local-group / service steps.

    WMI (DCOM) needs domain credentials and is practically Windows-only here.
    Returns ``None`` when creds are missing or construction fails — ``collect_server``
    degrades gracefully (skips the WMI-backed steps and logs) when ``wmi`` is None.
    """
    # WMI needs a domain username + a secret. A bare SQL login or SSPI-only run
    # can't drive DCOM here, so skip it. A domain login is DOMAIN\user or user@domain.
    is_domain_login = bool(cfg.user) and ("\\" in cfg.user or "@" in cfg.user)
    if not is_domain_login:
        logger.verbose("No domain credentials for WMI on %s; skipping WMI-backed steps", target.host)
        return None
    if not (cfg.password or cfg.nt_hash or cfg.kerberos_ticket):
        logger.verbose("No WMI secret for %s; skipping WMI-backed steps", target.host)
        return None
    if sys.platform != "win32":
        # DCOM via impacket can work off-Windows, but the local-group resolution
        # path is exercised/validated on Windows only; keep it gated for now.
        logger.verbose("WMI gated to Windows; skipping on platform=%s", sys.platform)
        return None

    domain, _, user = cfg.user.partition("\\")
    if "@" in cfg.user:  # UPN form user@domain
        user, _, domain = cfg.user.partition("@")
    auth = WmiAuth(
        username=user,
        password=cfg.password,
        nt_hash=cfg.nt_hash,
        kerberos_ticket=cfg.kerberos_ticket,
        domain=domain or cfg.domain,
        kdc_host=cfg.dc,
    )
    try:
        return WmiClient(target.host, auth)
    except Exception as ex:  # noqa: BLE001 - WMI is best-effort; never fatal
        logger.warning("Could not build WMI client for %s: %s", target.host, ex)
        return None


def _close_quietly(resource, label: str) -> None:
    """Close *resource* (if it has a ``close``) without letting cleanup raise."""
    if resource is None:
        return
    closer = getattr(resource, "close", None)
    if closer is None:
        return
    try:
        closer()
    except Exception as ex:  # noqa: BLE001 - cleanup must never raise
        logger.debug("Error closing %s: %s", label, ex)


__all__ = ["collect_targets"]

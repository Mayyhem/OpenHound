"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the smb phase.
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
# _RegistryProbe wraps the SMB + RPC plumbing for remote registry reads;
# imported here so smb_signing_status can fall back to the
# ``RequireSecuritySignature`` REG_DWORD when its SMB negotiate probe
# fails on a host. ``_split_user_domain`` is the credentials parser
# used by ``_smb_list_shares``. Both used to be missing from this
# module; their absence raised ``NameError`` on the first host and
# wiped out every SMB-resource yield.
from .registry import _RegistryProbe, _split_user_domain

logger = logging.getLogger(__name__)


def _smb_check_signing(hostname: str, port: int = 445, timeout: float = 5.0) -> Optional[bool]:
    """Detect SMB signing-required via impacket SMB negotiate handshake.

    Returns ``True`` if signing is required, ``False`` if not, ``None`` if
    the probe failed. Uses impacket's ``SMBConnection`` to perform a full
    negotiate (handles SMB1->SMB3 upgrade automatically) — modern Windows
    boxes negotiate SMB 3.x and the raw SMB2 negotiate path in CMBP can
    miss the signing flag for them.
    """
    logger.verbose("Probing SMB signing on %s:%d", hostname, port)
    try:
        sock = socket.create_connection((hostname, port), timeout=timeout)
        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.verbose("smb_signing: %s:%d unreachable: %s", hostname, port, e)
        return None

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        logger.warning("smb_signing: impacket unavailable, skipping %s", hostname)
        return None

    try:
        conn = SMBConnection(hostname, hostname, timeout=int(timeout))
        try:
            # impacket exposes signing-required as ``isSigningRequired()``.
            signing_required = bool(conn.isSigningRequired())
            logger.verbose("SMB signing on %s: %s", hostname, "required" if signing_required else "not required")
            return signing_required
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception as e:  # noqa: BLE001
        logger.verbose("smb_signing: probe failed for %s: %s", hostname, e)
        return None


def _smb_list_shares(
    hostname: str,
    domain: str,
    username: Optional[str],
    password: Optional[str],
    timeout: int = 5,
) -> Optional[list[dict[str, str]]]:
    """List SMB shares on ``hostname``. Returns None on connect/auth failure.

    Direct port of ``smb_collector._enumerate_shares`` minus the GraphStore
    side-effects.
    """
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        logger.warning("smb: impacket unavailable, skipping share enumeration on %s", hostname)
        return None

    auth_domain, user = _split_user_domain(username, domain)

    logger.verbose("SMB login to %s as %s\\%s", hostname, auth_domain or "", user or "<anonymous>")
    try:
        conn = SMBConnection(hostname, hostname, timeout=timeout)
        if user and password:
            conn.login(user, password, auth_domain)
        else:
            try:
                conn.login("", "", auth_domain)
            except Exception:
                return None
    except Exception as e:  # noqa: BLE001
        logger.verbose("SMB login to %s failed: %s", hostname, e)
        return None
    logger.verbose("SMB login to %s succeeded; enumerating shares", hostname)

    rows: list[dict[str, str]] = []
    try:
        shares = conn.listShares()
        for share in shares:
            try:
                name = share["shi1_netname"][:-1]
            except Exception:
                name = str(getattr(share, "shi1_netname", "")).rstrip("\x00")
            try:
                comment = share["shi1_remark"][:-1]
            except Exception:
                comment = str(getattr(share, "shi1_remark", "")).rstrip("\x00")
            if isinstance(comment, bytes):
                comment = comment.decode("utf-8", errors="ignore")
            rows.append({"name": str(name), "comment": str(comment)})
    except Exception as e:  # noqa: BLE001
        logger.verbose("SMB listShares on %s failed: %s", hostname, e)
        rows = []
    finally:
        try:
            conn.logoff()
        except Exception:
            pass
    return rows


_SMB_SITE_SHARES = {"SMS_SITE", "SMS_DP$", "SCCMContentLib$", "REMINST"}


@app.resource(name="smb_site_servers", parallelized=False, columns=raw_table_asset("smb_site_servers"))
@with_log_context(phase="SMB")
def smb_site_servers(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per (hostname, role, site_code) discovered via SMB share enum.

    A site server presents an ``SMS_SITE`` or ``SMS_<sitecode>`` share with a
    ``"SMS Site <code>"`` comment. The site_code is parsed out of the
    comment when present.
    """
    if not ctx.method_enabled("SMB"):
        logger.info("smb_site_servers: disabled via --collection-methods")
        return
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "smb_site_servers") == "done":
            continue
        logger.info("Starting SMB collection on %s...", hostname)
        shares = ctx.smb_shares(hostname)
        if shares is None:
            logger.info("Could not enumerate shares on %s", hostname)
        else:
            logger.info("Enumerated %d shares on %s", len(shares), hostname)
            is_site_server = False
            site_code: Optional[str] = None
            for s in shares:
                name = s["name"] or ""
                comment = s["comment"] or ""
                m = re.match(r"^SMS_(\w{3})$", name)
                if name == "SMS_SITE" or m:
                    is_site_server = True
                    cm = re.search(r"SMS Site (\w{3})", comment)
                    if cm:
                        site_code = cm.group(1)
                    elif m:
                        site_code = m.group(1)
            if is_site_server:
                logger.info("Found site server for site: %s", site_code or "<unknown>")
                yield {
                    "hostname": hostname,
                    "role": "SMS Site Server",
                    "site_code": site_code or "",
                    "computer_sid": host.get("sid"),
                    "source": "SMB-SMS_SITE",
                    "domain": ctx.domain,
                }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "smb_site_servers")


@app.resource(name="smb_distribution_points", parallelized=False, columns=raw_table_asset("smb_distribution_points"))
@with_log_context(phase="SMB")
def smb_distribution_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per Distribution Point discovered via SMB share enum.

    DP indicators: ``SMS_DP$``, ``SCCMContentLib$``, ``REMINST`` (PXE).
    """
    if not ctx.method_enabled("SMB"):
        return
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "smb_distribution_points") == "done":
            continue
        shares = ctx.smb_shares(hostname)
        if shares is not None:
            share_names = {s.get("name", "") for s in shares}
            is_dp = bool(share_names & {"SMS_DP$", "SCCMContentLib$"})
            is_pxe = "REMINST" in share_names
            if is_dp or is_pxe:
                site_code = ""
                for s in shares:
                    cm = re.search(r"SMS Site (\w{3})", s.get("comment") or "")
                    if cm:
                        site_code = cm.group(1)
                        break
                yield {
                    "hostname": hostname,
                    "dp_role": "Distribution Point",
                    "is_pxe_enabled": is_pxe,
                    "hosts_content_library": "SCCMContentLib$" in share_names or "SMS_DP$" in share_names,
                    "site_code": site_code,
                    "computer_sid": host.get("sid"),
                    "source": "SMB-DP",
                    "domain": ctx.domain,
                }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "smb_distribution_points")


@app.resource(name="smb_signing_status", parallelized=False, columns=raw_table_asset("smb_signing_status"))
@with_log_context(phase="SMB")
def smb_signing_status(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per host indicating whether SMB signing is required.

    Critical for Phase 4's ``CoerceAndRelayToSMB`` derived-edge generation.
    A host with ``signing_required=False`` and which is *not* the relay
    initiator is a candidate for the relay attack.

    Two probes per host, in order:

      1. SMB negotiate handshake against TCP/445 (impacket
         ``SMBConnection.isSigningRequired``). Fast and always usable.
      2. Remote registry read of
         ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters
         ::RequireSecuritySignature`` REG_DWORD. CMBP collects this value
         in ``registry_collector._read_smb_signing`` and uses it whenever
         the SMB-negotiate path would have failed (e.g. for passive
         failover hosts where 445 is firewalled but RPC over 135/445 still
         works for registry). Without this fallback OH misses
         CoerceAndRelayToSMB candidates like ``ps1-psv`` (the PS1 passive
         site server).
    """
    if not ctx.method_enabled("SMB"):
        return
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "smb_signing_status") == "done":
            continue
        signing = _smb_check_signing(hostname)
        if signing is True:
            logger.info("SMB signing is REQUIRED on %s", hostname)
        elif signing is False:
            logger.info("SMB signing is NOT required on %s", hostname)
        source = "SMB-Negotiate"
        if signing is None:
            # Registry fallback (CMBP parity)
            with _RegistryProbe(hostname, ctx.domain, ctx.username, ctx.password) as probe:
                if probe is not None:
                    val = probe.read_dword(
                        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                        "RequireSecuritySignature",
                    )
                    if val is not None:
                        signing = val == 1
                        source = "RemoteRegistry-SMBSigning"
        if signing is not None:
            yield {
                "hostname": hostname,
                "signing_required": signing,
                "computer_sid": host.get("sid"),
                "source": source,
                "domain": ctx.domain,
            }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "smb_signing_status")


# ---------------------------------------------------------------------------
# Phase 10 fold-in into the LDAP-owned ``ldap_sites`` table.
# ---------------------------------------------------------------------------
# A Secondary site server is occasionally only discoverable via its SMB
# shares — no mSSMSSite object in the System Management container (low-priv
# users can't enumerate it), and no AdminService access for the calling user
# either. CMBP/PS1 still emit a SCCM_Site node for these via SMB share
# enumeration (the ``SMS_<code>`` / ``SMS_SITE`` / ``SCCMContentLib$`` /
# ``REMINST`` patterns); without that, low-priv ``SCCM_AdminsReplicatedTo``
# edges pointing at the Secondary have no endpoint node. This used to live
# inside ``ldap_sites`` as an in-line fold-in but ran SMB during Phase 1,
# breaking the documented phase order. It now runs in Phase 10 and writes
# back into the same ``ldap_sites`` DLT table.

@app.resource(name="ldap_sites_smb_extra", parallelized=False, table_name="ldap_sites", columns=raw_table_asset("ldap_sites_smb_extra"))
@with_log_context(phase="SMB", target_from_ctx_domain=True)
def ldap_sites_smb_extra(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Emit SCCM_Site rows for sites discoverable only via SMB shares.

    Iterates ``ctx.ldap_computer_hosts()`` gated by
    ``ctx.sccm_discovered_hosts()`` (so we only probe hosts CMBP would
    have included in its TargetManager — by Phase 10 the SCCM-discovered
    set folds in the AdminService channel as well, matching CMBP).
    SMB share enumeration is served from ``ctx.smb_shares(...)`` so the
    cache filled by the Phase 10 smb_* resources is reused.
    """
    if not ctx.method_enabled("SMB"):
        return
    if ctx._emitted_site_codes is None:
        ctx._emitted_site_codes = set()
    seen_codes = ctx._emitted_site_codes
    discovered = ctx.sccm_discovered_hosts()
    extra_count = 0
    try:
        for host in per_host_iter(ctx.target_hosts_snapshot()):
            hostname = host.get("hostname")
            if not hostname:
                continue
            if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "ldap_sites_smb_extra") == "done":
                continue
            host_low = hostname.lower()
            host_short = host_low.split(".", 1)[0]
            if host_low in discovered or host_short in discovered:
                shares = ctx.smb_shares(hostname)
                if shares:
                    discovered_code: Optional[str] = None
                    origin_share: Optional[str] = None
                    for s in shares:
                        name = s.get("name") or ""
                        comment = s.get("comment") or ""
                        m = re.match(r"^SMS_(\w{3})$", name)
                        if name == "SMS_SITE" or m:
                            cm = re.search(r"SMS Site (\w{3})", comment)
                            if cm:
                                discovered_code = cm.group(1)
                                origin_share = name
                                break
                            if m:
                                discovered_code = m.group(1)
                                origin_share = name
                                break
                        cm = re.search(r"SMS Site (\w{3})", comment)
                        if cm and name in ("SMS_DP$", "SCCMContentLib$", "REMINST"):
                            discovered_code = cm.group(1)
                            origin_share = name
                            break
                    if discovered_code and discovered_code.upper() not in seen_codes:
                        seen_codes.add(discovered_code.upper())
                        extra_count += 1
                        logger.info(
                            "Found SMB-only SCCM site %s via share %s on %s",
                            discovered_code,
                            origin_share,
                            hostname,
                        )
                        yield {
                            "site_code": discovered_code,
                            "site_guid": None,
                            "distinguished_name": None,
                            "source_forest": None,
                            "site_type": None,
                            "parent_site_code": None,
                            "display_name": None,
                            "site_server_name": None,
                            "sql_server_name": None,
                            "sql_database_name": None,
                            "sql_service_account_name": None,
                            "version": None,
                            "collection_source": [f"SMB-{origin_share}"] if origin_share else ["SMB"],
                        }
            if ctx.target_queue is not None:
                ctx.target_queue.mark_done(hostname, "ldap_sites_smb_extra")
    except Exception as e:  # noqa: BLE001
        logger.warning("ldap_sites_smb_extra failed: %s", e)
    if extra_count:
        logger.info("Emitted %d SMB-only site(s)", extra_count)


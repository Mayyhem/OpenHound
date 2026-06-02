"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the dns phase.
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
from ..log_context import with_log_context
from .local import _normalize_host

logger = logging.getLogger(__name__)


@app.resource(name="dns_management_points", parallelized=False, columns=raw_table_asset("dns_management_points"))
@with_log_context(phase="DNS", target_from_ctx_domain=True)
def dns_management_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield rows for management points discovered via SRV records.

    For each known site code, queries ``_mssms_mp_<sitecode>._tcp.<domain>``.
    Site codes come from the LDAP-discovered ``mSSMSSite`` objects (re-ran here
    against the same AD client; cheap) plus anything passed via
    ``-sc / --site-codes``. If neither LDAP nor the CLI flag yields a code,
    the resource skips — there is no hardcoded fallback list (it used to mirror
    CMBP's ``CAS/PS1/PS2/SEC/SS1`` greenfield guesses, which produced misleading
    SRV traffic against environments that have no SCCM deployment at all).

    CMBP reference: ``lib/collectors/dns_collector.py``.
    """
    if not ctx.method_enabled("DNS"):
        return
    logger.info("Starting DNS collection...")
    try:
        import dns.exception
        import dns.resolver
        has_dnspython = True
    except ImportError:
        logger.warning("dnspython library not available. Install with: uv add dnspython")
        has_dnspython = False

    # Discover site codes from LDAP (re-using the existing AD client). The
    # ldap_sites resource already runs in this same source, but resources don't
    # share state at collect time, so we re-query — it's a tiny lookup.
    site_codes: set[str] = set()
    try:
        for entry in ctx.ad.paged_search(
            search_filter="(objectClass=mSSMSSite)",
            base=ctx.system_management_dn,
            attributes=["mSSMSSiteCode"],
        ):
            sc = (entry.get("mSSMSSiteCode") or "").strip()
            if sc:
                site_codes.add(sc)
    except Exception as e:  # noqa: BLE001
        logger.debug("dns_management_points: LDAP site enumeration failed: %s", e)

    # CMBP `-sc / --site-codes` augments / overrides the auto-discovered set.
    # Accepts a CSV value OR a path to a file with one site code per line.
    if ctx.site_codes:
        cli_codes: set[str] = set()
        sc_val = ctx.site_codes.strip()
        if sc_val:
            try:
                from pathlib import Path as _Path
                p = _Path(sc_val)
                if p.exists() and p.is_file():
                    for line in p.read_text(encoding="utf-8").splitlines():
                        code = line.split("#", 1)[0].strip()
                        if code:
                            cli_codes.add(code.upper())
                else:
                    cli_codes.update(c.strip().upper() for c in sc_val.split(",") if c.strip())
            except OSError as exc:
                logger.warning("dns_management_points: --site-codes %s unreadable: %s", sc_val, exc)
        if cli_codes:
            logger.info("dns_management_points: using user-supplied site codes %s", sorted(cli_codes))
            site_codes = cli_codes

    if not site_codes:
        logger.warning(
            "dns_management_points: no site codes available "
            "(LDAP mSSMSSite search under %s returned 0; --site-codes / "
            "SOURCES__SCCM__SITE_CODES not set) — skipping DNS SRV probe. "
            "Pass --site-codes PS1,CAS,... to probe specific codes.",
            ctx.system_management_dn,
        )
        return

    if has_dnspython:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        if ctx.ad.creds.domain_controller:
            resolver.nameservers = [_resolve_v4(ctx.ad.creds.domain_controller) or ctx.ad.creds.domain_controller]

        for site_code in sorted(site_codes):
            srv_name = f"_mssms_mp_{site_code.lower()}._tcp.{ctx.domain}"
            logger.info("Querying SRV record: %s", srv_name)
            try:
                answers = resolver.resolve(srv_name, "SRV")
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.exception.Timeout,
            ) as e:
                logger.debug("dns_management_points: %s -> %s", srv_name, e.__class__.__name__)
                continue
            except Exception as e:  # noqa: BLE001
                logger.debug("dns_management_points: %s failed: %s", srv_name, e)
                continue

            for rdata in answers:
                target_host = _normalize_host(str(rdata.target).rstrip("."))
                if not target_host:
                    continue
                port = getattr(rdata, "port", None)
                logger.info("Found management point: %s:%s (site: %s)", target_host, port, site_code)
                yield {
                    "hostname": target_host,
                    "site_code": site_code,
                    "port": port,
                    "srv_name": srv_name,
                    "source": f"DNS-SRV-{site_code}",
                    "domain": ctx.domain,
                }
    else:
        # ADIDNS fallback via LDAP — searches dnsNode objects under MicrosoftDNS.
        # We just discover names; full record parsing is left for a richer
        # phase. Nothing emitted unless real records exist.
        for site_code in sorted(site_codes):
            search_filter = f"(&(objectClass=dnsNode)(name=_mssms_mp_{site_code.lower()}*))"
            base = f"DC={ctx.domain},CN=MicrosoftDNS,DC=DomainDnsZones,{ctx.ad.base_dn}"
            try:
                for entry in ctx.ad.paged_search(
                    search_filter=search_filter,
                    base=base,
                    attributes=["name"],
                ):
                    name = entry.get("name")
                    host = _normalize_host(name)
                    if host:
                        yield {
                            "hostname": host,
                            "site_code": site_code,
                            "port": None,
                            "srv_name": None,
                            "source": f"DNS-ADIDNS-{site_code}",
                            "domain": ctx.domain,
                        }
            except Exception as e:  # noqa: BLE001
                logger.debug("dns_management_points: ADIDNS for %s failed: %s", site_code, e)
    logger.info("DNS collection completed")


def _resolve_v4(host: str) -> Optional[str]:
    """Resolve a hostname to its first IPv4 address, or None."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return None


# ---- DHCP collector -------------------------------------------------------

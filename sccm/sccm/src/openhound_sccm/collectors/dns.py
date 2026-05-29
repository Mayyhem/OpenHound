"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the dns phase.
The shared :class:`SourceContext` cache is built once in ``source.py`` and
passed into each resource. All decorators register onto the same
``app`` instance created in ``main.py``.
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Any, Iterable, Optional


from ..context import SourceContext
from ..main import app
from ..models.raw_table import raw_table_asset
from ..log_context import with_log_context

logger = logging.getLogger(__name__)


@app.resource(name="dns_management_points", parallelized=False, columns=raw_table_asset("dns_management_points"))
@with_log_context(phase="DNS", target_from_ctx_domain=True)
def dns_management_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield rows for management points discovered via SRV records.

    For each known site code, queries ``_mssms_mp_<sitecode>._tcp.<domain>``.
    Site codes come from the LDAP-discovered ``mSSMSSite`` objects (re-ran here
    against the same AD client; cheap) plus anything passed via
    ``-sc / --site-codes``.
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

    # Site codes are needed to construct the SRV record names. We get them from the CLI options and/or LDAP
    site_codes = ctx.site_codes

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
        if ctx.dns_resolver:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [ctx.dns_resolver]
        else:
            resolver = dns.resolver.Resolver()
            if ctx.ad.creds.domain_controller:
                resolver.nameservers = [_resolve_v4(ctx.ad.creds.domain_controller) or ctx.ad.creds.domain_controller]
        resolver.timeout = 5
        resolver.lifetime = 10

        for site_code in sorted(site_codes):
            srv_name = f"_mssms_mp_{site_code.lower()}._tcp.{ctx.domain}"
            logger.info("Querying SRV record: %s", srv_name)
            try:
                answers = resolver.resolve(srv_name, "SRV")
            except dns.resolver.NXDOMAIN:
                logger.verbose(f"No SRV record found for {srv_name} (NXDOMAIN)")
                continue
            except dns.resolver.NoAnswer:
                logger.verbose(f"No SRV record found for {srv_name} (NoAnswer)")
                continue
            except dns.exception.Timeout:
                logger.warning(f"DNS query timed out for {srv_name}")
                continue
            except Exception as ex:
                logger.error(f"DNS query failed for {srv_name}: {ex}")
                continue

            for rdata in answers:
                target_host = str(rdata.target).rstrip(".")
                if not target_host:
                    logger.warning(f"Found management point with empty hostname for {srv_name}: {rdata}")
                    continue
                
                port = getattr(rdata, "port", None)

                target = ctx.register_target(
                    identifier=target_host,
                    source=f"DNS-SRV-{site_code}",
                    site_code=site_code
                )

                if target:
                    logger.info("Found management point: %s:%s (site: %s)", target_host, port, site_code)
                    yield target.ad_object
                else:
                    logger.warning(f"Failed to register target management point {target_host} from SRV record {srv_name}")

    else:
        # ADIDNS fallback via LDAP — searches dnsNode objects under MicrosoftDNS.
        # We just discover names; full record parsing is left for a richer
        # phase. Nothing emitted unless real records exist.
        target = None
        for site_code in sorted(site_codes):
            search_filter = f"(&(objectClass=dnsNode)(name=_mssms_mp_{site_code.lower()}*))"
            base = f"DC={ctx.domain},CN=MicrosoftDNS,DC=DomainDnsZones,{ctx.ad.base_dn}"
            try:
                for entry in ctx.ad.paged_search(
                    search_filter=search_filter,
                    base=base,
                    attributes=["*"],
                ):
                    name = _extract_srv_target(entry.get("dnsRecord"))
                    if name:

                        target = ctx.register_target(
                            identifier=name,
                            source=f"DNS-ADIDNS-{site_code}",
                            site_code=site_code
                        )

                        if target:
                            logger.info("Found management point via ADIDNS: %s (site: %s)", name, site_code)
                            yield target.ad_object
                        else:
                            logger.warning(f"Failed to register target for management point {name} from ADIDNS search in site {site_code}")

            except Exception as ex:
                logger.error("dns_management_points: ADIDNS for %s failed: %s", site_code, ex)
    logger.info("DNS collection completed")


def _extract_srv_target(dns_record: Any) -> Optional[str]:
    """Return the SRV target hostname from a raw dnsRecord attribute value.

    Accepts bytes, bytearray, or a list of those (ldap3 may return multiple
    values when a node has more than one record).  Returns the target of the
    first SRV record found, or None.
    """
    if dns_record is None:
        return None
    records = dns_record if isinstance(dns_record, list) else [dns_record]
    for record in records:
        if isinstance(record, str):
            record = record.encode("latin-1")
        if not isinstance(record, (bytes, bytearray)):
            continue
        hostname = _parse_dns_rpc_record_srv(record)
        if hostname:
            return hostname
    return None


# MS-DNSP 2.2.2.2.5 DNS_RPC_RECORD header layout (little-endian unless noted):
#   DataLength(2) Type(2) Version(1) Rank(1) Flags(2)
#   Serial(4) TtlSeconds(4, big-endian) Reserved(4, big-endian) TimeStamp(4)
_DNS_RPC_RECORD_HEADER = struct.Struct("<HH")  # DataLength, Type
_DNS_RPC_RECORD_HEADER_SIZE = 24
_DNS_TYPE_SRV = 33  # 0x0021


def _parse_dns_rpc_record_srv(data: bytes) -> Optional[str]:
    """Parse a DNS_RPC_RECORD blob and return the SRV target FQDN, or None."""
    if len(data) < _DNS_RPC_RECORD_HEADER_SIZE + 8:
        return None
    _, record_type = _DNS_RPC_RECORD_HEADER.unpack_from(data, 0)
    if record_type != _DNS_TYPE_SRV:
        return None
    # SRV rdata: Priority(2 LE) + Weight(2 LE) + Port(2 LE) + DNS_COUNT_NAME
    offset = _DNS_RPC_RECORD_HEADER_SIZE + 6
    # DNS_COUNT_NAME: cchNameLength(1) + labelCount(1) + wire-format labels
    if offset + 2 > len(data):
        return None
    name_length = data[offset]
    label_count = data[offset + 1]
    name_data = data[offset + 2: offset + 2 + name_length]
    if len(name_data) < name_length:
        return None
    labels: list[str] = []
    pos = 0
    for _ in range(label_count):
        if pos >= len(name_data):
            break
        llen = name_data[pos]
        pos += 1
        if llen == 0 or pos + llen > len(name_data):
            break
        try:
            labels.append(name_data[pos: pos + llen].decode("ascii"))
        except UnicodeDecodeError:
            return None
        pos += llen
    return ".".join(labels) if labels else None


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

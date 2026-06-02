"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the http phase.
The shared :class:`SourceContext` cache is built once in ``source.py`` and
passed into each resource. All decorators register onto the same
``app`` instance created in ``main.py``.
"""

from __future__ import annotations

import logging
import socket
import warnings
from typing import Any, Iterable, Optional

import dlt
import requests
from urllib3.exceptions import InsecureRequestWarning

from ..clients.ad import ADClient, ADCredentials
from ..context import SourceContext
from ..main import app
from ..models.raw_table import raw_table_asset
from ..log_context import per_host_iter, per_pair_iter, with_log_context

logger = logging.getLogger(__name__)

warnings.simplefilter("ignore", InsecureRequestWarning)


def _curl_probe(url: str, timeout: int = 5) -> Optional[dict[str, Any]]:
    """Unauthenticated HTTP probe used to detect SCCM role endpoints.

    Returns a dict ``{status, server, headers, body}`` for any HTTP response
    (including 200/401/403 — the latter two mean the path exists but needs
    auth). Returns ``None`` on TCP / TLS failure so callers can distinguish
    "no route" from "endpoint refused us".
    """
    logger.verbose("Testing endpoint: %s", url)
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        logger.verbose("http: probe failed for %s: %s", url, exc)
        return None

    headers = {k.lower(): v for k, v in resp.headers.items()}
    logger.verbose("    Received %s", resp.status_code)
    return {
        "status": resp.status_code,
        "server": headers.get("server"),
        "headers": headers,
        "body": resp.text,
    }


_HTTP_MP_PATHS = (
    # PS1 (ConfigManBearPig.ps1:8646) requests MPKEYINFORMATION first because
    # its XML response contains the MP's authoritative FQDN + SITECODE.
    # Parsing it lets us register new MPs (e.g. cross-forest or hosts whose
    # ldap_computers row was filtered out as disabled) before subsequent
    # phases iterate the target set.
    ("/SMS_MP/.sms_aut?MPKEYINFORMATION", "MPKEYINFORMATION"),
    ("/SMS_MP/.sms_aut?MPLOCATION", "MP_LOCATION"),
    ("/SMS_MP/.sms_aut?MPCERT", "MP_CERT"),
    ("/sms_mp/.sms_aut?mplist", "MPLIST"),
)
# Probed separately so we capture the 403 (PS1's signal that client
# certificates are required); see ``http_management_points`` for the
# emission rule.
_HTTP_MP_SMSTRC_PATH = "/SMS_MP/.sms_aut?SMSTRC"


def _parse_mp_xml(body: str, endpoint_desc: str) -> list[dict[str, Optional[str]]]:
    """Extract (fqdn, site_code) pairs from an MPKEYINFORMATION / MPLIST
    XML response. Returns ``[]`` on any parse failure.

    MPKEYINFORMATION shape::
        <MPKEYINFORMATION>
            <FQDN>ps1-mp.mayyhem.com</FQDN>
            <SITECODE>PS1</SITECODE>
            ...
        </MPKEYINFORMATION>

    MPLIST shape::
        <MPList>
            <MP><Name>fqdn1</Name><SiteCode>PS1</SiteCode></MP>
            <MP><Name>fqdn2</Name><SiteCode>PS1</SiteCode></MP>
        </MPList>

    We use stdlib ``xml.etree.ElementTree`` and tolerate any element
    capitalisation. PS1 parses these at
    ``ConfigManBearPig.ps1:8685`` (MPKEYINFORMATION) and ``:8724`` (MPLIST).
    """
    if not body:
        return []
    import xml.etree.ElementTree as ET
    out: list[dict[str, Optional[str]]] = []
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []

    def _find_child_text(elem, names_lc: set[str]) -> Optional[str]:
        for child in elem:
            tag = child.tag.split("}")[-1].lower()  # strip namespace if any
            if tag in names_lc and child.text:
                return child.text.strip()
        return None

    desc_upper = endpoint_desc.upper()
    if "MPKEYINFORMATION" in desc_upper:
        fqdn = _find_child_text(root, {"fqdn"})
        site = _find_child_text(root, {"sitecode"})
        if fqdn:
            out.append({"fqdn": fqdn.lower(), "site_code": site})
    elif "MPLIST" in desc_upper:
        for mp in root:
            tag = mp.tag.split("}")[-1].lower()
            if tag != "mp":
                continue
            fqdn = _find_child_text(mp, {"name", "fqdn"})
            site = _find_child_text(mp, {"sitecode", "site_code"})
            if fqdn:
                out.append({"fqdn": fqdn.lower(), "site_code": site})
    return out
_HTTP_DP_PATHS = (
    ("/SMS_DP_SMSPKG$/Datalib/", "DP_DATALIB"),
    ("/SMS_DP_SMSPKG$/", "DP_PKG"),
)
_HTTP_SMS_PROVIDER_PATHS = (
    ("/AdminService/wmi/", "ADMINSERVICE_WMI"),
)


@app.resource(name="http_management_points", parallelized=False, columns=raw_table_asset("http_management_points"))
@with_log_context(phase="HTTP")
def http_management_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per Management Point discovered via HTTP probing.

    Probes each host's ``/SMS_MP/.sms_aut?MPLOCATION`` etc. on HTTP and
    HTTPS. A 200/401/403 response indicates the path is served (the latter
    two mean the role exists but the request needs auth).

    CMBP reference: ``http_collector.py``.
    """
    if not ctx.method_enabled("HTTP"):
        logger.info("http_management_points: disabled via --collection-methods")
        return
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "http_management_points") == "done":
            continue
        logger.info("Starting HTTP collection on %s...", hostname)
        any_port_open = False
        for scheme in ("https", "http"):
            port = 443 if scheme == "https" else 80
            try:
                with socket.create_connection((hostname, port), timeout=3):
                    pass
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
            any_port_open = True
            for path, desc in _HTTP_MP_PATHS:
                url = f"{scheme}://{hostname}{path}"
                resp = _curl_probe(url)
                if not resp:
                    continue
                status = resp.get("status") or 0
                if status not in (200, 401, 403):
                    continue
                logger.info("Found %s (%s): %s", "Management Point", desc, url)
                yield {
                    "hostname": hostname,
                    "mp_url": url,
                    "scheme": scheme,
                    "path": path,
                    "status": status,
                    "server_header": resp.get("server"),
                    "endpoint_desc": desc,
                    "computer_sid": host.get("sid"),
                    "source": f"HTTP-{desc}",
                    "domain": ctx.domain,
                }
                # Parse the XML response (MPKEYINFORMATION / MPLIST) to
                # discover additional MPs and register them as probe
                # targets. PS1 does this at ConfigManBearPig.ps1:8685
                # (MPKEYINFORMATION) and :8724 (MPLIST) — newly-discovered
                # hosts are added via Add-DeviceToTargets and probed by
                # subsequent phases.
                if status == 200 and desc in ("MPKEYINFORMATION", "MPLIST"):
                    for parsed in _parse_mp_xml(resp.get("body") or "", desc):
                        new_fqdn = parsed.get("fqdn")
                        if not new_fqdn:
                            continue
                        ctx.register_target(
                            new_fqdn,
                            source=f"HTTP-{desc}",
                        )
                # First successful path on this scheme is enough; move on
                break
            # Separate probe for the SMSTRC endpoint — PS1 emits a 403
            # there as the signal that the MP requires client certs
            # (line 8671 of ConfigManBearPig.ps1). We yield a marker row
            # so the Computer model can surface ``SCCMClientCertificateRequired``.
            smstrc_url = f"{scheme}://{hostname}{_HTTP_MP_SMSTRC_PATH}"
            smstrc_resp = _curl_probe(smstrc_url)
            if smstrc_resp and (smstrc_resp.get("status") or 0) == 403:
                logger.info(
                    "Found Management Point (SMSTRC cert-required signal): %s",
                    smstrc_url,
                )
                yield {
                    "hostname": hostname,
                    "mp_url": smstrc_url,
                    "scheme": scheme,
                    "path": _HTTP_MP_SMSTRC_PATH,
                    "status": 403,
                    "server_header": smstrc_resp.get("server"),
                    "endpoint_desc": "MP_SMSTRC_CERT_REQUIRED",
                    "computer_sid": host.get("sid"),
                    "source": "HTTP-SMSTRC",
                    "domain": ctx.domain,
                }
        if not any_port_open:
            logger.info("HTTP/HTTPS ports not open on %s, skipping HTTP collection", hostname)
        logger.info("HTTP collection completed for %s", hostname)
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "http_management_points")


@app.resource(name="http_smsproviders", parallelized=False, columns=raw_table_asset("http_smsproviders"))
@with_log_context(phase="HTTP")
def http_smsproviders(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per SMS Provider role discovered via HTTPS AdminService probe.

    Hits ``https://<host>/AdminService/wmi/``. A 200/401/403 indicates the
    role is present even if creds aren't sufficient. Complements
    ``adminservice_admins`` which only fires when creds *are* sufficient.
    """
    if not ctx.method_enabled("HTTP"):
        return
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "http_smsproviders") == "done":
            continue
        port_open = False
        try:
            with socket.create_connection((hostname, 443), timeout=3):
                pass
            port_open = True
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        if port_open:
            for path, desc in _HTTP_SMS_PROVIDER_PATHS:
                url = f"https://{hostname}{path}"
                resp = _curl_probe(url)
                if not resp:
                    continue
                status = resp.get("status") or 0
                if status not in (200, 401, 403):
                    continue
                yield {
                    "hostname": hostname,
                    "provider_url": url,
                    "status": status,
                    "server_header": resp.get("server"),
                    "endpoint_desc": desc,
                    "computer_sid": host.get("sid"),
                    "source": f"HTTP-{desc}",
                    "domain": ctx.domain,
                }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "http_smsproviders")


@app.resource(name="http_distribution_points", parallelized=False, columns=raw_table_asset("http_distribution_points"))
@with_log_context(phase="HTTP")
def http_distribution_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per Distribution Point discovered via HTTP probing.

    Hits ``/SMS_DP_SMSPKG$/Datalib/`` and ``/SMS_DP_SMSPKG$/`` over both
    schemes.
    """
    if not ctx.method_enabled("HTTP"):
        return
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "http_distribution_points") == "done":
            continue
        for scheme in ("https", "http"):
            port = 443 if scheme == "https" else 80
            port_open = False
            try:
                with socket.create_connection((hostname, port), timeout=3):
                    pass
                port_open = True
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
            if not port_open:
                continue
            for path, desc in _HTTP_DP_PATHS:
                url = f"{scheme}://{hostname}{path}"
                resp = _curl_probe(url)
                if not resp:
                    continue
                status = resp.get("status") or 0
                if status not in (200, 401, 403):
                    continue
                yield {
                    "hostname": hostname,
                    "dp_url": url,
                    "scheme": scheme,
                    "path": path,
                    "status": status,
                    "server_header": resp.get("server"),
                    "endpoint_desc": desc,
                    "computer_sid": host.get("sid"),
                    "source": f"HTTP-{desc}",
                    "domain": ctx.domain,
                }
                break
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "http_distribution_points")


@app.resource(name="http_naa_secrets", parallelized=False, columns=raw_table_asset("http_naa_secrets"))
@with_log_context(phase="HTTP")
def http_naa_secrets(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """STUB: CRED-3 NAA secret extraction via authenticated MP HTTP API.

    Real flow requires the SCCMPolicyClient client-registration handshake
    (see ``clients/sccm.py``). Phase 4 secret-policy edges cope with the
    empty table; this resource is wired so the table appears when collected
    with secret extraction enabled in a future iteration.
    """
    return
    yield  # type: ignore[unreachable]


@app.resource(name="http_collection_secrets", parallelized=False, columns=raw_table_asset("http_collection_secrets"))
@with_log_context(phase="HTTP")
def http_collection_secrets(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """STUB: CRED-5 collection-variable secret extraction.

    Same pattern as ``http_naa_secrets`` — needs an authenticated client
    registration. Empty rows here; Phase 4 SQL views will produce zero
    secret-policy edges, which matches the lab baseline.
    """
    return
    yield  # type: ignore[unreachable]


# ---- SMB enumeration ------------------------------------------------------


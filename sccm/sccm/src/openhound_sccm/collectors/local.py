"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the local phase.
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

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase 2 once-phase resources: Local, DNS, DHCP
# ---------------------------------------------------------------------------
# These resources extend Computer-node properties via the ``sccm.targets`` SQL
# union in ``transforms.py``. They do NOT introduce new node kinds. Each row
# uses ``hostname`` as the host column (matching ``_build_targets``'s contract)
# plus a small fixed set of provenance fields. CRED-4 CIM-repository scraping
# from CMBP's ``local_collector.py`` is intentionally NOT ported — those are
# secret-emitting paths that belong to Phase 4 post-processing.


def _normalize_host(value: Any) -> Optional[str]:
    if not value:
        return None
    text = str(value).strip().lower()
    return text or None


# ---- Local collector ------------------------------------------------------

@app.resource(name="local_management_points", parallelized=False, columns=raw_table_asset("local_management_points"))
@with_log_context(phase="Local", target_from_ctx_domain=True)
def local_management_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield rows for management points discovered locally on the collector host.

    On Windows, reads the SCCM client registry (``HKLM\\SOFTWARE\\Microsoft\\SMS``)
    to pull the assigned site code and the management point hostnames the local
    client knows about. On non-Windows or with no SCCM client installed, yields
    nothing — this is the expected case for an LDAP-only domainadmin run.

    CMBP reference: ``lib/collectors/local_collector.py::_check_sccm_registry``.
    The CRED-4 CIM-repository scraping from the same module is *not* ported
    here — that path emits SCCM_Secret nodes which are a Phase 4 concern.
    """
    if not ctx.method_enabled("Local"):
        return
    logger.info("Starting Local collection...")
    if platform.system() != "Windows":
        logger.info("Local collection only supported on Windows (SCCM client detection)")
        logger.info("Skipping local collection on non-Windows platform")
        return

    ccm_dir = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "CCM")
    if not os.path.isdir(ccm_dir):
        logger.info("SCCM client not detected on local system")
        return
    logger.info("SCCM client detected (CCM directory exists)")

    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        logger.debug("local_management_points: winreg unavailable on this platform")
        return

    site_code: Optional[str] = None
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\SMS\Mobile Client",
        ) as key:
            site_code, _ = winreg.QueryValueEx(key, "AssignedSiteCode")
    except (FileNotFoundError, OSError) as e:
        logger.debug("local_management_points: AssignedSiteCode read failed: %s", e)

    if not site_code:
        # Without a site code we can't enumerate Sites\SMS:<site>; nothing to yield
        return
    logger.info("Local SCCM assigned site: %s", site_code)

    # The site server (assigned MP) hostname comes from
    # HKLM\SOFTWARE\Microsoft\SMS\Client\Sites\SMS:<site>
    mp_host: Optional[str] = None
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\SMS\Client\Sites",
        ) as key:
            mp_host, _ = winreg.QueryValueEx(key, f"SMS:{site_code}")
    except (FileNotFoundError, OSError) as e:
        logger.debug("local_management_points: SMS:%s read failed: %s", site_code, e)

    host = _normalize_host(mp_host)
    if not host:
        return
    logger.info("Local management point: %s", host)

    yield {
        "hostname": host,
        "mp_url": f"http://{host}",
        "site_code": site_code,
        "source": "Local-Registry",
        "domain": ctx.domain,
    }
    logger.info("Local collection completed")


@app.resource(name="local_distribution_points", parallelized=False, columns=raw_table_asset("local_distribution_points"))
@with_log_context(phase="Local", target_from_ctx_domain=True)
def local_distribution_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield rows for distribution points discovered via local SCCM client log scrape.

    SCCM client logs (``CCM\\Logs\\*.log``, ``CCMSetup\\Logs\\*.log``) frequently
    reference DP UNC and HTTP endpoints. Phase 1 already feeds Computer nodes from
    LDAP for any DP that's an AD computer; this resource just contributes provenance
    rows so ``sccm.targets`` records the discovery as ``Local-DP``.

    CMBP reference: ``lib/collectors/local_collector.py::_parse_sccm_logs``.
    """
    if not ctx.method_enabled("Local"):
        return
    if platform.system() != "Windows":
        return

    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    log_dirs = [
        os.path.join(system_root, "CCM", "Logs"),
        os.path.join(system_root, "CCMSetup", "Logs"),
    ]
    smscfg = os.path.join(system_root, "SMSCFG.ini")

    url_pattern = re.compile(r"https?://([a-zA-Z0-9\-\.]+(?:\.\w+)+)", re.IGNORECASE)
    unc_pattern = re.compile(r"\\\\([a-zA-Z0-9\-\.]+(?:\.\w+)+)\\", re.IGNORECASE)

    discovered: set[str] = set()
    domain_lower = ctx.domain.lower() if ctx.domain else ""

    def _parse(path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    for m in url_pattern.finditer(line):
                        discovered.add(m.group(1).lower())
                    for m in unc_pattern.finditer(line):
                        discovered.add(m.group(1).lower())
        except (PermissionError, OSError):
            pass

    for log_dir in log_dirs:
        if os.path.isdir(log_dir):
            try:
                for filename in os.listdir(log_dir):
                    if filename.endswith(".log"):
                        _parse(os.path.join(log_dir, filename))
            except PermissionError:
                continue
    if os.path.isfile(smscfg):
        _parse(smscfg)

    for host in sorted(discovered):
        # Only emit hosts that look like they belong to our domain — others are
        # internet endpoints and noise.
        if domain_lower and not host.endswith(f".{domain_lower}"):
            continue
        yield {
            "hostname": host,
            "source": "Local-LogParsing",
            "domain": ctx.domain,
        }


# ---- DNS collector --------------------------------------------------------

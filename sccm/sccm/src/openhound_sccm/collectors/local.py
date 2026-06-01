"""
This module hosts the ``@app.resource`` generators for the local phase.
The shared :class:`SourceContext` cache is built once in ``source.py`` and
passed into each resource. All decorators register onto the same
``app`` instance created in ``main.py``.
"""

from __future__ import annotations

import functools
import logging
import os
import platform
import re
from typing import Any, Iterable

from ..context import SourceContext
from ..main import app
from ..models.raw_table import raw_table_asset
from ..log_context import with_log_context

logger = logging.getLogger(__name__)


@functools.lru_cache(maxsize=1)
def _wmi_ccm():
    """Return the connected root\\CCM WMI service, or None if unavailable."""
    if platform.system() != "Windows":
        logger.info("Local collection only supported on Windows SCCM client devices")
        return None
    try:
        import win32com.client
        svc = win32com.client.Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\CCM")
        logger.info("Connected to WMI root\\CCM namespace, proceeding with local collection")
        return svc
    except Exception as ex:
        logger.error("Failed to connect to WMI root\\CCM namespace: %s", ex)
        logger.info("Skipping local collection since this host doesn't appear to be an SCCM client")
        return None


# ---- Local collector ------------------------------------------------------
@app.resource(name="local_wmi_sms_authority", parallelized=False, columns=raw_table_asset("local_wmi_sms_authority"))
@with_log_context(phase="Local", target_from_ctx_domain=True)
def local_wmi_sms_authority(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """
    Yield row for the current management point and cache site code discovered in SMS_Authority WMI class.
    """
    if not ctx.method_enabled("Local"):
        return
    svc = _wmi_ccm()
    if svc is None:
        return

    logger.info("Starting local collection...")
    logger.info("Querying SMS_Authority for current management point and site code...")

    try:
        for item in svc.ExecQuery("SELECT * FROM SMS_Authority"):
            mp = getattr(item, "CurrentManagementPoint", None)
            # Extract site code from Name property (format: "SMS:PS1")
            global site_code
            site_code = getattr(item, "Name", "").split(":")[-1] if ":" in getattr(item, "Name", "") else None

            if site_code and site_code not in ctx.site_codes:
                logger.info(f"Found new site code '{site_code}' in local WMI repository")
                ctx.site_codes.add(site_code)

            if mp:
                target = ctx.register_target(
                    identifier=mp,
                    source="Local-SMS_Authority",
                    site_code=site_code | None
                )

                if target:
                    logger.info(f"Found current management point: {target.ad_object.get('dNSHostName')} ({target.ad_object.get('object_sid')})")
                    yield target.ad_object
                else:
                    logger.warning(f"Failed to register target for current management point {mp} from SMS_Authority")

    except Exception as ex:
        logger.error("Error querying SMS_Authority: %s", ex)


@app.resource(name="local_wmi_sms_lookupmp", parallelized=False, columns=raw_table_asset("local_wmi_sms_lookupmp"))
@with_log_context(phase="Local", target_from_ctx_domain=True)
def local_wmi_sms_lookupmp(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """
    Yield row for other known management points discovered in SMS_LookupMP WMI class.
    """
    if not ctx.method_enabled("Local"):
        return
    svc = _wmi_ccm()
    if svc is None:
        return

    logger.info("Qeurying SMS_LookupMP for additional management points...")

    try:
        for item in svc.ExecQuery("SELECT * FROM SMS_LookupMP"):
            mp = getattr(item, "Name", None)

            if mp:
                target = ctx.register_target(
                    identifier=mp,
                    source="Local-SMS_LookupMP",
                    site_code=site_code
                )

                if target:
                    logger.info(f"Found management point: {target.ad_object.get('dNSHostName')} ({target.ad_object.get('object_sid')})")
                    yield target.ad_object
                else:
                    logger.warning(f"Failed to register target for management point {mp} from SMS_LookupMP")

    except Exception as ex:
        logger.error("Error querying SMS_LookupMP: %s", ex)


@app.resource(name="local_wmi_ccm_client", parallelized=False, columns=raw_table_asset("local_wmi_ccm_client"))
@with_log_context(phase="Local", target_from_ctx_domain=True)
def local_wmi_ccm_client(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """
    Yield row for SCCM client device identifiers discovered in CCM_Client WMI class.
    """
    if not ctx.method_enabled("Local"):
        return
    svc = _wmi_ccm()
    if svc is None:
        return

    logger.info("Qeurying SMS_LookupMP for additional management points...")

    try:
        for item in svc.ExecQuery("SELECT * FROM SMS_LookupMP"):
            mp = getattr(item, "Name", None)

            if mp:
                target = ctx.register_target(
                    identifier=mp,
                    source="Local-SMS_LookupMP",
                    site_code=site_code
                )

                if target:
                    logger.info(f"Found management point: {target.ad_object.get('dNSHostName')} ({target.ad_object.get('object_sid')})")
                    yield target.ad_object
                else:
                    logger.warning(f"Failed to register target for management point {mp} from SMS_LookupMP")

    except Exception as ex:
        logger.error("Error querying SMS_LookupMP: %s", ex)


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

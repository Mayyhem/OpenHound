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

    global current_mp_ad_obj, site_code

    logger.info("Starting local collection...")
    logger.info("Querying SMS_Authority for current management point and site code...")

    try:
        for item in svc.ExecQuery("SELECT * FROM SMS_Authority"):
            current_mp = getattr(item, "CurrentManagementPoint", None)
            # Extract site code from Name property (format: "SMS:PS1")
            site_code = getattr(item, "Name", "").split(":")[-1] if ":" in getattr(item, "Name", "") else None

            if site_code and site_code not in ctx.site_codes:
                logger.info(f"Found new site code '{site_code}' in local WMI repository")
                ctx.site_codes.add(site_code)

            if current_mp:
                target = ctx.register_target(
                    identifier=current_mp,
                    source="Local-SMS_Authority",
                    site_code=site_code if site_code else None
                )

                if target:
                    logger.info(f"Found current management point: {target.ad_object.get('dNSHostName')} ({target.ad_object.get('object_sid')})")
                    current_mp_ad_obj = target.ad_object

                    if target.is_new:
                        logger.info(f"Registered new target: {target.ad_object.get('dNSHostName')}")
                        yield target.ad_object
                    else:
                        logger.verbose(f"Skipping already registered target: {target.ad_object.get('dNSHostName')}")
                else:
                    logger.warning(f"Failed to register target for current management point {current_mp} from SMS_Authority")

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
                    site_code=site_code if site_code else None
                )

                if target:
                    logger.info(f"Found management point: {target.ad_object.get('dNSHostName')} ({target.ad_object.get('object_sid')})")

                    if target.is_new:
                        logger.info(f"Registered new target: {target.ad_object.get('dNSHostName')}")
                        yield target.ad_object
                    else:
                        logger.verbose(f"Skipping already registered target: {target.ad_object.get('dNSHostName')}")
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

    global this_computer_ad_obj

    logger.info("Querying CCM_Client for client information...")

    try:
        for item in svc.ExecQuery("SELECT * FROM CCM_Client"):
            client_id = getattr(item, "ClientId", None)
            client_id_change_date = getattr(item, "ClientIdChangeDate", None)
            previous_client_id = getattr(item, "PreviousClientId", None)

            # Get COMPUTERNAME and USERDNSDOMAIN to resolve in AD
            computer_name = os.environ.get("COMPUTERNAME", None)
            user_dns_domain = os.environ.get("USERDNSDOMAIN", None)
            name_to_resolve = f"{computer_name}.{user_dns_domain}" if user_dns_domain else computer_name

            if name_to_resolve:
                try:
                    # Just resolve, don't add local host to targets
                    this_computer_ad_obj = ctx.resolve_principal(name_to_resolve)
                except Exception as ex:
                    logger.error("Error resolving principal for %s: %s", name_to_resolve, ex)

            if client_id:
                log_suffix = ""
                if previous_client_id and previous_client_id != client_id:
                    log_suffix = f" (previous ID: {previous_client_id}"
                    if client_id_change_date:
                        log_suffix += f", changed on {client_id_change_date}"
                    log_suffix += ")"
                logger.info(f"Found client ID (SMSID) for {name_to_resolve}: {client_id} {log_suffix}")

                yield {
                    "ad_domain_sid": this_computer_ad_obj.get("object_sid") if this_computer_ad_obj else None,
                    "current_management_point": current_mp_ad_obj.get("dNSHostName") if current_mp_ad_obj else None,
                    "current_management_point_sid": current_mp_ad_obj.get("object_sid") if current_mp_ad_obj else None,
                    "distinguished_name": this_computer_ad_obj.get("distinguishedName") if this_computer_ad_obj else None,
                    "dns_host_name": this_computer_ad_obj.get("dNSHostName") if this_computer_ad_obj else None,
                    "name": this_computer_ad_obj.get("sAMAccountName") if this_computer_ad_obj else None,
                    "previous_smsid_change_date": client_id_change_date,
                    "previous_smsid": previous_client_id,
                    "site_code": site_code if site_code else None,
                    "smsid": client_id,
                    "source": "Local-CCM_Client",
                }
    except Exception as ex:
        logger.error("Error querying CCM_Client: %s", ex)


@app.resource(name="local_client_logs_targets", parallelized=False, columns=raw_table_asset("local_client_logs_targets"))
@with_log_context(phase="Local", target_from_ctx_domain=True)
def local_client_logs_targets(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield rows for management points and distribution points discovered via 
    local SCCM client log scrape.

    SCCM client logs (``CCM\\Logs\\*.log``, ``CCMSetup\\Logs\\*.log``) frequently
    reference MP and DP UNC and HTTP endpoints.
    """
    if not ctx.method_enabled("Local"):
        return
    if platform.system() != "Windows":
        return

    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    log_dirs = [
        os.path.join(system_root, "CCM", "Logs"),
        os.path.join(system_root, "ccmsetup", "Logs"),
    ]

    unc_pattern = re.compile(r"\\\\([a-zA-Z0-9\-_\s]{2,15}(?:\.[a-zA-Z0-9\-_\s]{1,64}){0,3})(\\[^\\\/:\*\?`\"<>\|;]{1,64})+(\\)?", re.IGNORECASE)
    url_pattern = re.compile(r"\w+://(?:[\w@][\w.:@]+@)?([\w][\w.-]*)", re.IGNORECASE)

    # Maps discovered hostname (lowercase) to its source type for targeted log messages.
    discovered: dict[str, str] = {}

    def _parse(path: str) -> None:
        file_name = os.path.basename(path)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    for m in unc_pattern.finditer(line):
                        unc_path = m.group(0).strip()
                        logger.verbose(f"Found UNC path in {file_name}: {unc_path}")
                        discovered.setdefault(m.group(1).lower(), "UNC path")
                    for m in url_pattern.finditer(line):
                        full_url = m.group(0).strip()
                        logger.verbose(f"Found URL in {file_name}: {full_url}")
                        discovered.setdefault(m.group(1).lower(), "URL")
        except Exception as ex:
            logger.error(f"Failed to search log file {path}: {ex}")

    for log_dir in log_dirs:
        if os.path.isdir(log_dir):
            try:
                for filename in os.listdir(log_dir):
                    if filename.endswith(".log"):
                        logger.verbose(f"Processing log file: {os.path.join(log_dir, filename)}")
                        _parse(os.path.join(log_dir, filename))
            except (Exception) as ex:
                logger.error(f"Failed to process log directory {log_dir}: {ex}")
                continue

    for host in sorted(discovered.keys()):
        # Skip localhost references and current machine
        if host in ("localhost", "127.0.0.1", this_computer_ad_obj.get("dNSHostName").lower() if this_computer_ad_obj else None, this_computer_ad_obj.get("sAMAccountName").lower() if this_computer_ad_obj else None):
            logger.debug(f"Skipping localhost reference found in client logs: {host}")
            continue

        resolved_ip = ctx.resolve_ip(host)

        if resolved_ip:
            # Check RFC1918 ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if (resolved_ip.startswith("10.") or
                (resolved_ip.startswith("172.") and 16 <= int(resolved_ip.split(".")[1]) <= 31) or
                resolved_ip.startswith("192.168.")):
                logger.info(f"Host resolved to RFC1918 IP address: {host} ({resolved_ip})")

                target = ctx.register_target(
                    identifier=host,
                    source="Local-ClientLogs",
                    site_code=site_code
                )

                if target:
                    logger.info(f"Found host in client logs: {target.ad_object.get('dNSHostName')} ({target.ad_object.get('object_sid')})")

                    if target.is_new:
                        logger.info(f"Registered new target: {target.ad_object.get('dNSHostName')}")
                        yield target.ad_object
                    else:
                        logger.verbose(f"Skipping already registered target: {target.ad_object.get('dNSHostName')}")
                else:
                    logger.warning(f"Failed to register target for host {host} found in client logs")
            else:
                logger.debug(f"Host found in client logs resolved to non-RFC1918 IP address, skipping: {host} ({resolved_ip})")
        else:
            logger.verbose(f"Failed to resolve hostname {host} from {discovered[host]}")
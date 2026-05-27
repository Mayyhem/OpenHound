"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the ldap phase.
The shared :class:`SourceContext` cache is built once in ``source.py`` and
passed into each resource. All decorators register onto the same
``app`` instance created in ``main.py``.
"""
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Iterable

from ..context import SourceContext
from ..log_context import with_log_context
from ..main import app
from ..models.raw_table import raw_table_asset
from ..models import SCCMSite

logger = logging.getLogger(__name__)


def _parse_mp_capabilities(capabilities_str: str, mp_site_code: str) -> dict:
    """Parse mSSMSCapabilities XML into structured fields.

    Returns a dict with keys: site_type, parent_site_code,
    command_line_site_code, root_site_code, fsp_hostnames.
    Returns safe defaults on parse failure or empty input.
    """
    # Default assumption — overwritten below if XML parses successfully
    result: dict = {
        "site_type": "Secondary Site",
        "parent_site_code": "Undetermined",
        "command_line_site_code": None,
        "root_site_code": None,
        "fsp_hostnames": [],
    }
    if not capabilities_str:
        return result
    try:
        # Clean unescaped ampersands before parsing
        clean = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;)", "&amp;", str(capabilities_str))
        root = ET.fromstring(clean)

        # Extract CommandLine site code
        # ClientOperationalSettings.CCM.CommandLine contains "SMSSITECODE=XYZ"
        ccm = root.find(".//CCM")
        if ccm is not None:
            cmd = ccm.get("CommandLine", "") or ""
            if not cmd:
                cl_elem = ccm.find("CommandLine")
                cmd = (cl_elem.text or "") if cl_elem is not None else (ccm.text or "")
            m = re.search(r"SMSSITECODE=([A-Z0-9]{3})", cmd, re.IGNORECASE)
            if m:
                result["command_line_site_code"] = m.group(1).upper()

        # Extract root site code — identifies the hierarchy root
        rs = root.find("RootSiteCode")
        if rs is None:
            rs = root.find(".//RootSiteCode")
        if rs is not None and rs.text:
            result["root_site_code"] = rs.text.strip().upper()

        # Extract fallback status point hostnames
        # Each FSPServer node names a host serving as an FSP for this site
        fsp_elem = root.find("FSP")
        if fsp_elem is None:
            fsp_elem = root.find(".//FSP")
        if fsp_elem is not None:
            result["fsp_hostnames"] = [
                s.text.strip()
                for s in fsp_elem.findall("FSPServer")
                if s.text and s.text.strip()
            ]

        # Determine site type from the relationship between this MP's site code,
        # the CommandLine site code, and the root site code
        mp_code = mp_site_code.upper() if mp_site_code else ""
        cmd_code = result["command_line_site_code"]
        root_code = result["root_site_code"]

        # Check if this MP's CommandLine site code matches the site we're analyzing
        if cmd_code and cmd_code == mp_code:
            # Primary Site: an MP exists whose CommandLine.SMSSITECODE equals
            # this site's code
            result["site_type"] = "Primary Site"
            # A different root site code indicates this Primary reports to a CAS
            result["parent_site_code"] = root_code if (root_code and root_code != mp_code) else "None"
        elif root_code and root_code == mp_code and cmd_code != mp_code:
            # Central Administration Site: an MP exists whose RootSiteCode equals
            # this site's code but CommandLine.SMSSITECODE points elsewhere
            result["site_type"] = "Central Administration Site"
            result["parent_site_code"] = "None"
        else:
            # Neither condition met — Secondary Site; parent is the root if known,
            # otherwise fall back to the CommandLine site code
            result["site_type"] = "Secondary Site"
            if root_code and root_code != mp_code:
                result["parent_site_code"] = root_code
            elif cmd_code and cmd_code != mp_code:
                result["parent_site_code"] = cmd_code

    except Exception as parse_err:
        logger.debug("mSSMSCapabilities parse failed for %s: %s", mp_site_code, parse_err)
    return result


_SITE_ATTRS = [
    "mSSMSSiteCode",
    "mSSMSHealthState",
    "mSSMSSourceForest",
    "objectClass",
    "distinguishedName",
    "name",
]

@app.resource(name="ldap_sites", parallelized=False, columns=SCCMSite)
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_sites(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """
    SCCM sites discovered via mSSMSSite objects in the System Management container.
    """
    if not ctx.method_enabled("LDAP"):
        return

    if ctx._emitted_site_codes is None:
        ctx._emitted_site_codes = set()
    seen_codes = ctx._emitted_site_codes
    site_count = 0

    logger.info("Collecting mSSMSSite objects in System Management container...")
    try:
        for entry in ctx.ad.paged_search(
            search_filter="(objectClass=mSSMSSite)",
            base=ctx.system_management_dn,
            attributes=_SITE_ATTRS,
        ):
            site_code = (entry.get("mSSMSSiteCode") or "").strip()
            if not site_code:
                continue

            # Parse health state for SiteGUID
            site_guid = None
            health = entry.get("mSSMSHealthState")
            if health:
                m = re.search(rf"{re.escape(site_code)}\.(\{{[^}}]+\}})", str(health))
                if m:
                    site_guid = m.group(1)

            seen_codes.add(site_code.upper())
            site_count += 1
            logger.info("Found site: %s", site_code)
            yield {
                "collection_source": ["LDAP-mSSMSSite"],
                "distinguished_name": entry.get("distinguishedName"),
                "parent_site_code": "Undetermined", # Will be determined by mSSMSManagementPoint
                "sccm_infra": True,
                "site_code": site_code,
                "site_guid": site_guid,
                "source_forest": entry.get("mSSMSSourceForest"),
            }
    except Exception as ex:
        logger.error("Failed to search System Management container: %s", ex)
        logger.warning("The System Management container may not exist or access is denied")
        return
    logger.info("Found %d mSSMSSite objects", site_count)


@app.resource(name="ldap_management_points_raw", parallelized=False, columns=raw_table_asset("ldap_management_points_raw"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_management_points_raw(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Management points, FSP hosts, and site classification from mSSMSManagementPoint.

    One row per mSSMSManagementPoint entry. Registers both the MP hostname and
    any FSP hostnames parsed from mSSMSCapabilities as collection targets.
    Preproc transforms derive site_types, computer_mp_roles, computer_fsp_roles,
    and computer_site_system_roles from this table.
    """
    if not ctx.method_enabled("LDAP"):
        return
    
    logger.info("Collecting mSSMSManagementPoint objects in System Management container...")
    mp_count = 0
    fsp_count = 0

    try:
        for entry in ctx.ad.paged_search(
            search_filter="(objectClass=mSSMSManagementPoint)",
            base=ctx.system_management_dn,
            attributes=["mSSMSSiteCode", "mSSMSCapabilities", "mSSMSMPName"],
        ):
            mp_hostname = entry.get("mSSMSMPName")
            mp_site_code = (entry.get("mSSMSSiteCode") or "").strip()
            mp_code_upper = mp_site_code.upper() if mp_site_code else None

            # Register the management point as a collection target so its
            # per-host resources run in subsequent passes
            if mp_hostname:
                if not mp_site_code:
                    logger.warning("mSSMSManagementPoint missing site code: %s", mp_hostname)
                mp_target = ctx.register_target(
                    mp_hostname,
                    site_code=mp_code_upper,
                    source="LDAP-mSSMSManagementPoint",
                )
                if mp_target and mp_target.is_new:
                    mp_sid = mp_target.ad_object.get("object_sid")
                    sid_suffix = f" ({mp_sid})" if mp_sid else ""
                    logger.info("Found management point in site %s: %s%s", mp_site_code, mp_hostname, sid_suffix)
                    mp_count += 1

            # Parse capabilities to determine site relationships and extract
            # FSP hostnames from the capabilities XML
            parsed = _parse_mp_capabilities(entry.get("mSSMSCapabilities") or "", mp_site_code)

            # Register each fallback status point as a collection target;
            # FSP hostnames come from FSPServer nodes inside the capabilities XML
            for fsp_hostname in parsed["fsp_hostnames"]:
                fsp_target = ctx.register_target(
                    fsp_hostname,
                    site_code=mp_code_upper,
                    source="LDAP-mSSMSManagementPoint",
                )
                if fsp_target and fsp_target.is_new:
                    fsp_sid = fsp_target.ad_object.get("object_sid")
                    sid_suffix = f" ({fsp_sid})" if fsp_sid else ""
                    logger.info("Found fallback status point in site %s: %s%s", mp_site_code, fsp_hostname, sid_suffix)
                    fsp_count += 1

            yield {
                "mp_hostname": mp_hostname,
                "site_code": mp_site_code,
                "site_type": parsed["site_type"],
                "parent_site_code": parsed["parent_site_code"],
                "command_line_site_code": parsed["command_line_site_code"],
                "root_site_code": parsed["root_site_code"],
                "fsp_hostnames": parsed["fsp_hostnames"],
            }
    except Exception as ex:
        logger.error("Failed to search System Management container: %s", ex)
        logger.warning("The System Management container may not exist or access is denied")

    logger.info("Found %d management points and %d fallback status points", mp_count, fsp_count)


@app.resource(name="ldap_cmrc_devices", parallelized=False, columns=raw_table_asset("ldap_cmrc_devices"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_cmrc_devices(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """
    Computers with the CmRcService SPN registered, indicating they have the SCCM client remote control service installed.
    One row per computer with the CmRcService SPN. Registers each computer as a collection target for subsequent passes.
    """
    if not ctx.method_enabled("LDAP"):
        return

    logger.info("Searching for computers with Remote Control SPN (CmRcService/*)...")

    try:
        rows = list(
            ctx.ad.paged_search(
                search_filter="(servicePrincipalName=CmRcService/*)",
                attributes = [
                    "dNSHostName", "distinguishedName", "objectClass", "servicePrincipalName", 
                    "objectSid", "cn", "name", "samAccountName"
                ]            
            )
        )
    except Exception as ex:
        logger.warning("CmRcService search failed: %s", ex)
        rows = []

    logger.info("Found %d computers with CmRcService SPN in %s", len(rows), ctx.domain)
    
    # Give this client device the first primary site code published to AD. This could 
    # very well be wrong in multi-site environments, but it should be in the same hierarchy, 
    # so it's better than nothing for offensive use case and will be replaced if privileged
    # collection is conducted later
    site_code = sorted(ctx._emitted_site_codes)[0] if ctx._emitted_site_codes else None

    for entry in rows:
        sid = entry.get("object_sid")
        if not sid:
            continue
        dns_host_name = (entry.get("dNSHostName") or "").lower() or None
        sam_account_name = (entry.get("sAMAccountName") or "").strip() or None
        name = entry.get("name") or None

        logger.verbose("Found computer with Remote Control SPN: %s (%s)", entry.get("dNSHostName"), sid)

        # Do NOT register the computer as a target. This could be any domain computer.

        yield {
            "object_sid": sid,
            "sam_account_name": sam_account_name,
            "name": name,
            "dns_host_name": dns_host_name,
            "domain": ctx.domain,
        }


@app.resource(name="ldap_network_boot_servers", parallelized=False, columns=raw_table_asset("ldap_network_boot_servers"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_network_boot_servers(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """
    Searches for connectionPoint objects with netbootserver attribute and 
    intellimirrorSCP objects, which are likely WDS/PXE-enabled distribution points.
    """
    if not ctx.method_enabled("LDAP"):
        return

    logger.info("Searching for network boot servers (PXE-enabled DPs)...")

    # Search for connectionPoint objects with netbootserver
    try:
        netbootserver_rows = list(
            ctx.ad.paged_search(
                search_filter="(&(objectClass=connectionPoint)(netbootserver=*))",
                attributes = ["distinguishedName","objectClass"]            
            )
        )
        logger.info("Found %d connectionPoint objects with netbootserver in %s", len(netbootserver_rows), ctx.domain)   
    except Exception as ex:
        logger.warning("netbootserver search failed: %s", ex)
        netbootserver_rows = []

    # Search for intellimirrorSCP objects
    try:
        intellimirror_rows = list(
            ctx.ad.paged_search(
                search_filter="(objectClass=intellimirrorSCP)",
                attributes = ["distinguishedName", "objectClass"]          
            )
        )
        logger.info("Found %d intellimirrorSCP objects in %s", len(intellimirror_rows), ctx.domain)
    except Exception as ex:
        logger.warning("intellimirrorSCP search failed: %s", ex)
        intellimirror_rows = []

    # Uniquify and combine results from both searches because there may be some overlap
    # They are list[dict[str, Any]] with key distinguishedName
    network_boot_servers = {entry["distinguishedName"]: entry for entry in (netbootserver_rows + intellimirror_rows)}.values()

    if not network_boot_servers:
        logger.info("No network boot server objects found in %s", ctx.domain)
        return

    for server in network_boot_servers: 
        dn = server.get("distinguishedName")
        obj_class = server.get("objectClass")

        if not dn:
            continue

        try:
            # Extract everything after the first comma to get parent DN (the computer object)
            parent_dn = dn.split(",", 1)[1] if "," in dn else None
            if not parent_dn:
                continue

            parent = ctx.resolve_principal(parent_dn)
            if not parent:
                continue

            dns_host_name = parent.get("dNSHostName")
            if not dns_host_name:
                logger.warning(f"Network boot server entry {dn} has no dNSHostName for its computer object")
                logger.debug(f"Parent object: {parent}")

            sid = parent.get("object_sid")
            if not sid:
                logger.warning(f"Network boot server entry {dn} has no SID for its computer object")
                logger.debug(f"Parent object: {parent}")

            if dns_host_name and sid:
                target = ctx.register_target(
                    identifier=sid,
                    site_code=None,
                    source=f"LDAP-{obj_class}",
                    ad_object=parent,
                )

                if target:
                    logger.info(f"Found network boot server: {dns_host_name} ({sid})")

                if target and target.ad_object:

                    raise Exception("Debugging target with AD object: %s", target.ad_object)
                
                    yield {
                        "object_sid": sid,
                        "dns_host_name": dns_host_name,
                        "name": parent.get("name"),
                        "sam_account_name": parent.get("sAMAccountName"),
                        "domain": ctx.domain,
                    }

        except Exception as ex:
            logger.warning(f"Failed to process network boot server {dn}: {ex}")
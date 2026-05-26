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
    except Exception as e:
        logger.error("Failed to search System Management container: %s", e)
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
    logger.info("Collecting mSSMSManagementPoint objects in System Management container...")
    mp_count = 0

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
                    logger.info("Found management point: %s (site: %s)", mp_hostname, mp_site_code)

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
                    logger.info("Found fallback status point: %s (site: %s)", fsp_hostname, mp_site_code)

            mp_count += 1
            # One flat row per entry; preproc transforms fan this into
            # site_types, computer_mp_roles, and computer_fsp_roles tables
            yield {
                "mp_hostname": mp_hostname,
                "site_code": mp_site_code,
                "site_type": parsed["site_type"],
                "parent_site_code": parsed["parent_site_code"],
                "command_line_site_code": parsed["command_line_site_code"],
                "root_site_code": parsed["root_site_code"],
                "fsp_hostnames": parsed["fsp_hostnames"],
            }
    except Exception as e:
        logger.error("Failed to search System Management container: %s", e)
        logger.warning("The System Management container may not exist or access is denied")

    logger.info("Found %d mSSMSManagementPoint objects", mp_count)
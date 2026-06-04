"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the ldap phase.
The shared :class:`SourceContext` cache is built once in ``source.py`` and
passed into each resource. All decorators register onto the same
``app`` instance created in ``main.py``.
"""
import logging
import re
import struct
import xml.etree.ElementTree as ET
from typing import Any, Iterable

from ..clients.ad import bytes_to_sid
from ..context import SourceContext
from ..log_context import with_log_context
from ..main import app
from ..models.raw_table import raw_table_asset
from ..models import SCCMSite

logger = logging.getLogger(__name__)


def _parse_mp_capabilities(capabilities_str: str, mp_site_code: str) -> dict:
    """Parse mSSMSCapabilities XML into structured fields.

    Returns a dict with keys: site_type, parent_site_code,
    command_line_site_code, root_site_code, fsp_hostname.
    Returns safe defaults on parse failure or empty input.
    """
    # Default assumption — overwritten below if XML parses successfully
    result: dict = {
        "site_type": "Secondary Site",
        "parent_site_code": "Undetermined",
        "command_line_site_code": None,
        "root_site_code": None,
        "fsp_hostname": None,
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

        # Extract the fallback status point hostname
        # An FSPServer node names a host serving as an FSP for this site. At
        # most one FSP is expected per MP; warn and keep the first if several.
        fsp_elem = root.find("FSP")
        if fsp_elem is None:
            fsp_elem = root.find(".//FSP")
        if fsp_elem is not None:
            fsp_hostnames = [
                s.text.strip()
                for s in fsp_elem.findall("FSPServer")
                if s.text and s.text.strip()
            ]
            if len(fsp_hostnames) > 1:
                logger.warning(
                    "Multiple FSPServer entries for site %s; using the first (%s)",
                    mp_site_code,
                    fsp_hostnames[0],
                )
            if fsp_hostnames:
                result["fsp_hostname"] = fsp_hostnames[0]

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
        logger.error("mSSMSCapabilities parse failed for %s: %s", mp_site_code, parse_err)
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

    if ctx.site_codes is None:
        ctx.site_codes = set()
    seen_codes = ctx.site_codes
    site_count = 0

    logger.info("Searching for mSSMSSite objects in System Management container...")
    try:
        results = list(
            ctx.ad.paged_search(
                search_filter="(objectClass=mSSMSSite)",
                base=ctx.system_management_dn,
                attributes=_SITE_ATTRS,
            )
        )
    except Exception as ex:
        logger.error("Failed to search System Management container: %s", ex)
        logger.warning("The System Management container may not exist or access is denied")
        results = []

    for entry in results:
        try:
            site_code = entry.get("mSSMSSiteCode").strip()
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
            logger.error("Failed to process mSSMSSite entry %s: %s", entry.get("mSSMSSiteCode"), ex)
            logger.debug(f"Search result: {entry}")

    logger.info("Found %d mSSMSSite objects", site_count)


@app.resource(name="ldap_management_points_raw", parallelized=False, columns=raw_table_asset("ldap_management_points_raw"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_management_points_raw(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Management points, FSP hosts, and site classification from mSSMSManagementPoint.

    One row per mSSMSManagementPoint entry. Registers both the MP hostname and
    the FSP hostname parsed from mSSMSCapabilities as collection targets.
    Preproc transforms derive site_types, computer_mp_roles, computer_fsp_roles,
    and computer_site_system_roles from this table.
    """
    if not ctx.method_enabled("LDAP"):
        return
    
    logger.info("Searching for mSSMSManagementPoint objects in System Management container...")
    mp_count = 0
    fsp_count = 0

    try:
        results = list(
            ctx.ad.paged_search(
                search_filter="(objectClass=mSSMSManagementPoint)",
                base=ctx.system_management_dn,
                attributes=["mSSMSSiteCode", "mSSMSCapabilities", "mSSMSMPName"],
            )
        )
    except Exception as ex:
        logger.error("Failed to search System Management container: %s", ex)
        logger.warning("The System Management container may not exist or access is denied")
        results = []

    logger.info("Found %d mSSMSManagementPoint objects", len(results))

    for entry in results:

        try:
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
                if mp_target:
                    mp_sid = mp_target.ad_object.get("object_sid")
                    sid_suffix = f" ({mp_sid})" if mp_sid else ""
                    logger.info("Found management point in site %s: %s%s", mp_site_code, mp_hostname, sid_suffix)
                    mp_count += 1
                else:
                    logger.warning(f"Failed to register target for management point {mp_hostname} from mSSMSManagementPoint entry")

            # Parse capabilities to determine site relationships and extract
            # FSP hostnames from the capabilities XML
            parsed = _parse_mp_capabilities(entry.get("mSSMSCapabilities") or "", mp_site_code)

            # Register the fallback status point as a collection target;
            # the FSP hostname comes from the FSPServer node inside the capabilities XML
            fsp_hostname = parsed["fsp_hostname"]
            if fsp_hostname:
                fsp_target = ctx.register_target(
                    fsp_hostname,
                    site_code=mp_code_upper,
                    source="LDAP-mSSMSManagementPoint",
                )
                if fsp_target:
                    fsp_sid = fsp_target.ad_object.get("object_sid")
                    sid_suffix = f" ({fsp_sid})" if fsp_sid else ""
                    logger.info("Found fallback status point in site %s: %s%s", mp_site_code, fsp_hostname, sid_suffix)
                    fsp_count += 1
                else:
                    logger.warning(f"Failed to register target for fallback status point {fsp_hostname} from mSSMSManagementPoint entry")

            yield {
                "mp_hostname": mp_hostname,
                "site_code": mp_site_code,
                "site_type": parsed["site_type"],
                "parent_site_code": parsed["parent_site_code"],
                "command_line_site_code": parsed["command_line_site_code"],
                "root_site_code": parsed["root_site_code"],
                "fsp_hostname": parsed["fsp_hostname"],
            }
        except Exception as ex:
            logger.error("Failed to process mSSMSManagementPoint entry %s: %s", entry.get("mSSMSMPName"), ex)
            logger.debug(f"Search result: {entry}")

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
        results = list(
            ctx.ad.paged_search(
                search_filter="(servicePrincipalName=CmRcService/*)",
                attributes = [
                    "dNSHostName", "distinguishedName", "objectClass", "servicePrincipalName", 
                    "objectSid", "cn", "name", "samAccountName"
                ]            
            )
        )
    except Exception as ex:
        logger.error("CmRcService search failed: %s", ex)
        results = []

    logger.info("Found %d computers with CmRcService SPN in %s", len(results), ctx.domain)
    
    # Give this client device the first primary site code published to AD. This could 
    # very well be wrong in multi-site environments, but it should be in the same hierarchy, 
    # so it's better than nothing for offensive use case and will be replaced if privileged
    # collection is conducted later
    site_code = sorted(ctx.site_codes)[0] if ctx.site_codes else None

    for entry in results:

        try:
            sid = entry.get("object_sid")
            dns_host_name = entry.get("dNSHostName")

            logger.verbose("Found computer with Remote Control SPN: %s (%s)", dns_host_name, sid)

            # Do NOT register the computer as a target. This could be any domain computer.

            yield {
                "object_sid": sid,
                "sam_account_name": entry.get("sAMAccountName"),
                "name": entry.get("name"),
                "dns_host_name": dns_host_name,
                "domain": ctx.domain,
                "site_code": site_code,
            }
        except Exception as ex:
            logger.error("Failed to process computer with Remote Control SPN %s: %s", entry.get("dNSHostName"), ex)
            logger.debug(f"Search result: {entry}")


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
        logger.error("netbootserver search failed: %s", ex)
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
        logger.error("intellimirrorSCP search failed: %s", ex)
        intellimirror_rows = []

    # Uniquify and combine results from both searches because there may be some overlap
    # They are list[dict[str, Any]] with key distinguishedName
    all_results = {entry["distinguishedName"]: entry for entry in (netbootserver_rows + intellimirror_rows)}.values()

    if not all_results:
        logger.info("No network boot server objects found in %s", ctx.domain)
        return

    for entry in all_results: 
        dn = entry.get("distinguishedName")
        obj_class = entry.get("objectClass", [])
        if isinstance(obj_class, str):
            obj_class = [obj_class]

        if not dn:
            logger.warning(f"Network boot server entry missing distinguishedName: {entry}")
            logger.debug(f"Search result: {entry}")
            continue

        try:
            # Extract everything after the first comma to get parent DN (the computer object)
            computer_dn = dn.split(",", 1)[1] if "," in dn else None
            if not computer_dn:
                continue

            target = ctx.register_target(
                identifier=computer_dn,
                source=f"LDAP-{obj_class}",
            )

            if target:
                logger.info(f"Found network boot server: {target.ad_object.get('dNSHostName')} ({target.ad_object.get('object_sid')})")
                yield target.ad_object
            else:
                logger.warning(f"Failed to register target for network boot server {computer_dn} from {obj_class} entry")

        except Exception as ex:
            logger.error(f"Failed to process network boot server {dn}: {ex}")
            logger.debug(f"Search result: {entry}")


@app.resource(name="ldap_pattern_matches", parallelized=False, columns=raw_table_asset("ldap_pattern_matches"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_pattern_matches(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """
    Searches the domain for computers whose names match
    SCCM-related patterns (sccm, mecm, mcm, memcm, configm, cfgm, sms).
    """
    if not ctx.method_enabled("LDAP"):
        return

    logger.info("Searching for computers with SCCM naming patterns...")

    search_patterns = ["sccm", "mecm", "mcm", "memcm", "configm", "cfgm", "sms"]

    # Build dynamic LDAP filter to search for any of the patterns in multiple attributes
    filter_parts = []
    for pattern in search_patterns:
        filter_parts.append(f"(samaccountname=*{pattern}*)")
        filter_parts.append(f"(description=*{pattern}*)")
        filter_parts.append(f"(name=*{pattern}*)")
        filter_parts.append(f"(cn=*{pattern}*)")
        filter_parts.append(f"(displayname=*{pattern}*)")
        filter_parts.append(f"(serviceprincipalname=*{pattern}*)")
        filter_parts.append(f"(dnshostname=*{pattern}*)")
        filter_parts.append(f"(description=*{pattern}*)")

    ldap_filter = f"(&(objectCategory=computer)(|{''.join(filter_parts)}))"

    try:
        results = list(
            ctx.ad.paged_search(
                search_filter=ldap_filter,
                attributes=[
                    "sAMAccountName", "description", "name", "displayName",
                    "servicePrincipalName", "dNSHostName", "objectClass", "objectSid",
                ],
            )
        )
    except Exception as ex:
        logger.error("SCCM naming pattern search failed: %s", ex)
        results = []

    if not results:
        logger.info("No computers with SCCM naming patterns found")
        return

    logger.info("Found %d computers with SCCM naming patterns in %s", len(results), ctx.domain)

    for computer in results:

        try:
            # Add to collection targets for subsequent collection phases
            target = ctx.register_target(
                identifier=computer.get("object_sid"),
                source=f"LDAP-NamePattern",
                ad_object=computer,
            )

            if target:
                logger.info(f"Found system with SCCM naming pattern: {target.ad_object.get('dNSHostName')} ({target.ad_object.get('object_sid')})")
                yield target.ad_object
            else:
                logger.warning(f"Failed to register target for computer with SCCM naming pattern {computer.get('name')} ({computer.get('object_sid')})")

        except Exception as ex:
            logger.error(f"Failed to process search result {computer.get('name')}: {ex}")
            logger.debug(f"Search result: {computer}")


@app.resource(name="ldap_system_management_dacl", parallelized=False, columns=raw_table_asset("ldap_system_management_dacl"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_system_management_dacl(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """
    Check ACLs on the System Management container.
    Looks for GenericAll (Full Control) permissions, which indicate site servers.
    """
    if not ctx.method_enabled("LDAP"):
        return

    logger.info("Checking permissions on System Management container...")

    # Query the container's nTSecurityDescriptor
    # Need to use SD_FLAGS control to request DACL (0x04)
    # SD_FLAGS OID: 1.2.840.113556.1.4.801
    # BER value: SEQUENCE { INTEGER 4 } = 30 03 02 01 04
    system_mgmt_dn = f"CN=System Management,CN=System,{ctx.ad.base_dn}"

    try:
        sd_control = ("1.2.840.113556.1.4.801", True, bytes([0x30, 0x03, 0x02, 0x01, 0x04]))
        results = list(
            ctx.ad.paged_search(
            search_filter="(objectClass=container)",
            base=system_mgmt_dn,
            attributes=["nTSecurityDescriptor"],
            controls=[sd_control],
            )
        )
    except Exception as e:
        logger.error(f"Failed to read System Management container ACLs: {e}")
        return

    if not results:
        logger.warning("Could not read System Management container ACLs")
        return

    sd_bytes = results[0].get("nTSecurityDescriptor")
    if not sd_bytes or not isinstance(sd_bytes, bytes):
        logger.warning("nTSecurityDescriptor not returned as bytes")
        logger.debug(f"nTSecurityDescriptor: {sd_bytes}")
        return

    # Parse security descriptor and extract GenericAll ACEs
    try:
        generic_all_sids = _parse_sd_generic_all(sd_bytes)
    except Exception as ex:
        logger.error(f"Failed to parse System Management container ACLs: {ex}")
        return
    
    if not generic_all_sids:
        logger.warning("No GenericAll permissions found on System Management container")
        return

    for sid_str in generic_all_sids:
        ad_obj = None

        try:
            # Resolve SID to AD object
            ad_obj = ctx.resolve_principal(sid_str)
            if not ad_obj:
                logger.warning(f"Could not resolve GenericAll principal '{sid_str}' to domain object")
                continue

            sam = ad_obj.get("sAMAccountName")

            obj_class = ad_obj.get("objectClass", [])
            if isinstance(obj_class, str):
                obj_class = [obj_class]

            # Determine object type
            obj_type = "unknown"
            if "computer" in [c.lower() for c in obj_class]:
                obj_type = "computer"

                # Add as collection target
                target = ctx.register_target(
                    identifier=ad_obj.get("dNSHostName"),
                    source="LDAP-GenericAllSystemManagement",
                    ad_object=ad_obj,
                )

                if not target:
                    logger.warning(f"Failed to register target for {ad_obj.get('dNSHostName')} with GenericAll on System Management container")

            elif "user" in [c.lower() for c in obj_class]:
                obj_type = "user"
            elif "group" in [c.lower() for c in obj_class]:
                obj_type = "group"
            logger.info(f"Found {obj_type} with GenericAll on System Management container: {sam} ({sid_str})")

            yield ad_obj

        except Exception as ex:
            logger.error(f"Failed to process GenericAll principal {sid_str}: {ex}")


def _parse_sd_generic_all(sd_bytes: bytes) -> list[str]:
    """
    Parse a Windows SECURITY_DESCRIPTOR binary blob and return SIDs with GenericAll.

    In Active Directory, GenericAll maps to 0x000F01FF (Full Control) rather than
    the raw Windows GENERIC_ALL bit (0x10000000). The .NET ActiveDirectoryRights
    enum GenericAll = 0x000F01FF. We check for both, plus any mask that includes
    all the AD-specific rights.

    Structure reference:
    - SECURITY_DESCRIPTOR header (20 bytes for self-relative)
    - DACL at OffsetDacl
    - ACL header (8 bytes): revision, padding, size, ace_count, padding
    - Each ACE: AceType(1), AceFlags(1), AceSize(2), ACCESS_MASK(4), SID(variable)
    - ACCESS_ALLOWED_OBJECT_ACE (type 0x05) has extra: Flags(4), optional ObjectType(16),
      optional InheritedObjectType(16) before the SID
    """
    if len(sd_bytes) < 20:
        return []

    # Parse SECURITY_DESCRIPTOR header
    revision = sd_bytes[0]
    control = struct.unpack_from("<H", sd_bytes, 2)[0]
    offset_dacl = struct.unpack_from("<I", sd_bytes, 16)[0]

    if offset_dacl == 0 or offset_dacl >= len(sd_bytes):
        return []

    # Parse ACL header at offset_dacl
    acl_size = struct.unpack_from("<H", sd_bytes, offset_dacl + 2)[0]
    ace_count = struct.unpack_from("<H", sd_bytes, offset_dacl + 4)[0]

    results = []
    pos = offset_dacl + 8  # Skip ACL header

    # AD GenericAll = 0x000F01FF (DS Full Control)
    # Also check raw GENERIC_ALL = 0x10000000 in case it wasn't mapped
    AD_GENERIC_ALL = 0x000F01FF
    GENERIC_ALL = 0x10000000
    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05

    for _ in range(ace_count):
        if pos + 4 > len(sd_bytes):
            break

        ace_type = sd_bytes[pos]
        ace_flags = sd_bytes[pos + 1]
        ace_size = struct.unpack_from("<H", sd_bytes, pos + 2)[0]

        if ace_size < 4 or pos + ace_size > len(sd_bytes):
            break

        if pos + 8 > len(sd_bytes):
            pos += ace_size
            continue

        access_mask = struct.unpack_from("<I", sd_bytes, pos + 4)[0]
        is_generic_all = (access_mask & GENERIC_ALL) or (access_mask & AD_GENERIC_ALL) == AD_GENERIC_ALL

        if is_generic_all:
            sid_data = None

            if ace_type == ACCESS_ALLOWED_ACE_TYPE:
                # ACCESS_ALLOWED_ACE: header(4) + mask(4) + SID
                sid_data = sd_bytes[pos + 8:pos + ace_size]

            elif ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                # ACCESS_ALLOWED_OBJECT_ACE: header(4) + mask(4) + flags(4) +
                #   [ObjectType(16)] + [InheritedObjectType(16)] + SID
                if pos + 12 <= len(sd_bytes):
                    obj_flags = struct.unpack_from("<I", sd_bytes, pos + 8)[0]
                    sid_start = pos + 12
                    if obj_flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                        sid_start += 16
                    if obj_flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                        sid_start += 16
                    sid_data = sd_bytes[sid_start:pos + ace_size]

            if sid_data:
                sid_str = bytes_to_sid(sid_data)
                if sid_str:
                    results.append(sid_str)

        pos += ace_size

    return results
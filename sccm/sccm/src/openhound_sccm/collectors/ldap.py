"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the ldap phase.
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
from ..models import Computer, Group, GroupMembership, SCCMSite, User

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LDAP resources (Phase 1 thin slice)
# ---------------------------------------------------------------------------

_COMPUTER_ATTRS = [
    "objectSid",
    "objectGUID",
    "sAMAccountName",
    "name",
    "distinguishedName",
    "dNSHostName",
    "operatingSystem",
    "operatingSystemVersion",
    "userAccountControl",
    "servicePrincipalName",
    "memberOf",
    "primaryGroupID",
]


@app.resource(name="ldap_computers", parallelized=False, columns=Computer)
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_computers(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """All computer accounts in the domain (one row per AD computer)."""
    logger.info("Searching for all computer objects...")
    count = 0
    for entry in ctx.ad.paged_search(
        search_filter="(&(objectCategory=computer)(objectClass=computer))",
        attributes=_COMPUTER_ATTRS,
    ):
        count += 1
        yield _normalize_computer(entry, ctx.domain)
    logger.info("Found %d computer objects", count)


_USER_ATTRS = [
    "objectSid",
    "objectGUID",
    "sAMAccountName",
    "userPrincipalName",
    "name",
    "displayName",
    "distinguishedName",
    "userAccountControl",
    "memberOf",
    "primaryGroupID",
    "servicePrincipalName",
]


@app.resource(name="ldap_users", parallelized=False, columns=User)
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_users(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """All user accounts in the domain (one row per AD user)."""
    logger.info("Searching for all user objects...")
    count = 0
    for entry in ctx.ad.paged_search(
        search_filter="(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))",
        attributes=_USER_ATTRS,
    ):
        count += 1
        yield _normalize_user(entry, ctx.domain)
    logger.info("Found %d user objects", count)


_GROUP_ATTRS = [
    "objectSid",
    "objectGUID",
    "sAMAccountName",
    "name",
    "distinguishedName",
    "groupType",
    "member",
]


@app.resource(name="ldap_groups", parallelized=False, columns=Group)
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_groups(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """All groups in the domain (one row per AD group).

    Also synthesises a row for the well-known Authenticated Users
    pseudo-group (``S-1-5-11``). LDAP doesn't expose it as a regular
    ``group`` object but every CoerceAndRelay edge in the SCCM model
    starts from it, so a Group node has to exist for the edges to be
    valid in the BloodHound graph. CMBP synthesises this node too.
    """
    logger.info("Searching for all group objects...")
    count = 0
    for entry in ctx.ad.paged_search(
        search_filter="(objectClass=group)",
        attributes=_GROUP_ATTRS,
    ):
        count += 1
        yield _normalize_group(entry, ctx.domain)
    logger.info("Found %d group objects", count)

    # PS1 uses lowercase domain prefix on the Authenticated Users
    # synthesised node id (e.g. "mayyhem.com-S-1-5-11"). Match that so
    # CoerceAndRelay edges from auth users line up across PS1 / CMBP / OH.
    domain_lower = (ctx.domain or "").lower()
    if domain_lower:
        yield {
            "object_sid": f"{domain_lower}-S-1-5-11",
            "object_guid": None,
            "sam_account_name": "Authenticated Users",
            "name": "Authenticated Users",
            "distinguished_name": None,
            "group_type": None,
            "member": [],
            "domain": ctx.domain,
        }


@app.resource(name="ldap_group_memberships", parallelized=False, columns=GroupMembership)
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_group_memberships(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """One row per (group, member-DN) pair.

    Re-runs the same LDAP search as ``ldap_groups`` (groups are small relative to
    the AD index; the second pass costs ~30ms in the test domain) and emits a flat
    membership row for each ``member`` value. Originally written as a DLT
    transformer chained off ``ldap_groups`` but DLT's pipe operator wasn't
    producing a separate destination table for the chained output here, so we
    implement the membership table as a top-level resource. The cost is one extra
    paged search; the benefit is a guaranteed-separate JSONL the convert phase can
    read.
    """
    for entry in ctx.ad.paged_search(
        search_filter="(objectClass=group)",
        attributes=_GROUP_ATTRS,
    ):
        members = entry.get("member") or []
        if isinstance(members, str):
            members = [members]
        group_sid = entry.get("object_sid") or ""
        group_name = entry.get("sAMAccountName") or entry.get("name") or ""
        for member_dn in members:
            if not isinstance(member_dn, str) or not member_dn:
                continue
            yield {
                "group_sid": group_sid,
                "group_name": group_name,
                "member_dn": member_dn,
            }


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
    """SCCM sites discovered via mSSMSSite objects in the System Management container.

    Also folds in any sites returned by ``wmi/SMS_Site`` from the AdminService
    payload — CMBP creates a SCCM_Site per row from both ``ldap_sites`` AND
    SMS_Site (e.g. a Secondary site that is hierarchy-discovered via the
    SMS Provider but not registered in the System Management container).

    Each yielded row is enriched with AdminService data (display name, site
    server name, SQL server / database / service-account names, version) from
    the merged SMS_Site + SMS_SCI_SiteDefinition + SMS_SCI_SysResUse payloads
    so the SCCM_Site node carries the CMBP-equivalent denormalised property
    surface for BloodHound queries.
    """
    # Phase 1 (LDAP) — emit pure LDAP-discovered sites only. AdminService
    # enrichment (display name, site server, SQL host/db, SQL service account,
    # version, site type, parent site code) is deferred to convert time via
    # lookup methods on ``SCCMSite.as_node`` that read the
    # ``adminservice_sites`` / ``adminservice_site_definitions`` tables Phase
    # 7 writes. AdminService-only sites (those in SMS_Site but not in
    # mSSMSSite / mSSMSManagementPoint) are emitted by the
    # ``ldap_sites_admin_extra`` resource in Phase 7 — which writes to the
    # same ``ldap_sites`` DLT table via ``table_name=``. Keeping ldap_sites
    # LDAP-only is what makes the documented phase order
    # (LDAP → Local → DNS → DHCP → Registry → MSSQL → AdminService → WMI →
    # HTTP → SMB) actually hold at runtime — see context.py
    # ``sccm_discovered_hosts`` for the matching gate change.
    # ``ctx._emitted_site_codes`` is the cross-resource dedup set shared
    # with the Phase 7 (``ldap_sites_admin_extra``) and Phase 10
    # (``ldap_sites_smb_extra``) writers to the same DLT table.
    if ctx._emitted_site_codes is None:
        ctx._emitted_site_codes = set()
    seen_codes = ctx._emitted_site_codes
    site_count = 0

    logger.info("Searching for mSSMSSite objects in System Management container...")
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
            logger.info("Found SCCM site: %s", site_code)
            yield {
                "collection_source": ["LDAP-mSSMSSite"],
                "display_name": None,
                "distinguished_name": entry.get("distinguishedName"),
                "site_code": site_code,
                "site_guid": site_guid,
                "source_forest": entry.get("mSSMSSourceForest"),
                "parent_site_code": None,
                "site_server_name": None,
                "site_type": None,
                "sql_server_name": None,
                "sql_database_name": None,
                "sql_service_account_name": None,
                "version": None,
            }
    except Exception as e:
        logger.error("Failed to search System Management container: %s", e)
        logger.warning("The System Management container may not exist or access is denied")
    logger.info("Found %d mSSMSSite objects", site_count)

    # mSSMSManagementPoint fold-in: each Site (CAS, Primary, Secondary) has a
    # corresponding MP record under the System Management container. We emit
    # SCCM_Site rows for any site discovered via its MP that wasn't already
    # seen via mSSMSSite. Classification (siteType / parent) lives in the
    # ``ldap_mp_site_classifications`` resource and is folded in at convert
    # time via transforms.py.
    try:
        for entry in ctx.ad.paged_search(
            search_filter="(objectClass=mSSMSManagementPoint)",
            base=ctx.system_management_dn,
            attributes=["mSSMSSiteCode"],
        ):
            mp_site_code = (entry.get("mSSMSSiteCode") or "").strip()
            if not mp_site_code or mp_site_code.upper() in seen_codes:
                continue
            seen_codes.add(mp_site_code.upper())
            yield {
                "site_code": mp_site_code,
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
                "collection_source": ["LDAP-mSSMSManagementPoint"],
            }
    except Exception as e:
        logger.warning("ldap_sites mp fold-in failed: %s", e)

    # AdminService-only and SMB-only site discovery used to live here as
    # fold-ins, but they did out-of-phase work (HTTP / SMB during Phase 1).
    # Both are now their own resources that write back into this same
    # ``ldap_sites`` DLT table via ``table_name="ldap_sites"`` at their
    # proper phases — see ``ldap_sites_admin_extra`` (Phase 7) and
    # ``ldap_sites_smb_extra`` (Phase 10). The shared site-code dedup is
    # handled there against the rows this resource has already written.


@app.resource(name="ldap_mp_site_classifications", parallelized=False, columns=raw_table_asset("ldap_mp_site_classifications"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_mp_site_classifications(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Per-site (siteType, parent_site_code) classification derived from
    each ``mSSMSManagementPoint`` object's ``mSSMSCapabilities`` XML.

    Mirrors CMBP's ``ldap_collector::_collect_management_points`` parse:

      * commandLineSiteCode == mp_site_code AND rootSiteCode != mp -> Primary, parent=root
      * rootSiteCode == mp_site_code AND commandLine != mp         -> CAS, parent=None
      * (default)                                                  -> Secondary,
            parent = rootSiteCode (which is the parent Primary), or
                     commandLineSiteCode if rootSiteCode is missing

    The transforms read this table at preproc to set ``site_types`` even
    when AdminService is unavailable (low-priv users), closing the
    ``SCCM_AdminsReplicatedTo`` gap for Secondary sites.
    """
    logger.info("Searching for mSSMSManagementPoint objects...")
    mp_count = 0
    try:
        import xml.etree.ElementTree as ET
        for entry in ctx.ad.paged_search(
            search_filter="(objectClass=mSSMSManagementPoint)",
            base=ctx.system_management_dn,
            attributes=["mSSMSSiteCode", "mSSMSCapabilities", "mSSMSMPName"],
        ):
            mp_site_code = (entry.get("mSSMSSiteCode") or "").strip()
            if not mp_site_code:
                continue
            mp_count += 1
            mp_code_upper = mp_site_code.upper()
            capabilities_str = entry.get("mSSMSCapabilities")
            command_line_site_code: Optional[str] = None
            root_site_code: Optional[str] = None
            if capabilities_str:
                try:
                    clean_xml = re.sub(
                        r"&(?!amp;|lt;|gt;|quot;|apos;)", "&amp;", str(capabilities_str)
                    )
                    root = ET.fromstring(clean_xml)
                    ccm = root.find(".//CCM")
                    if ccm is not None:
                        cmd = ccm.get("CommandLine", "") or ""
                        if not cmd:
                            cl_elem = ccm.find("CommandLine")
                            cmd = (cl_elem.text or "") if cl_elem is not None else (ccm.text or "")
                        cmd_match = re.search(r"SMSSITECODE=([A-Z0-9]{3})", cmd, re.IGNORECASE)
                        if cmd_match:
                            command_line_site_code = cmd_match.group(1).upper()
                    rs = root.find("RootSiteCode")
                    if rs is None:
                        rs = root.find(".//RootSiteCode")
                    if rs is not None and rs.text:
                        root_site_code = rs.text.strip().upper()
                except Exception as parse_err:
                    logger.debug(
                        "mSSMSCapabilities parse failed for %s: %s", mp_site_code, parse_err
                    )

            site_type: str
            parent: Optional[str] = None
            if command_line_site_code == mp_code_upper:
                site_type = "Primary"
                if root_site_code and root_site_code != mp_code_upper:
                    parent = root_site_code
            elif root_site_code == mp_code_upper and command_line_site_code != mp_code_upper:
                site_type = "CAS"
            else:
                site_type = "Secondary"
                if root_site_code and root_site_code != mp_code_upper:
                    parent = root_site_code
                elif command_line_site_code and command_line_site_code != mp_code_upper:
                    parent = command_line_site_code

            yield {
                "site_code": mp_site_code,
                "site_type": site_type,
                "parent_site_code": parent,
                "command_line_site_code": command_line_site_code,
                "root_site_code": root_site_code,
            }
    except Exception as e:
        logger.warning("ldap_mp_site_classifications resource failed: %s", e)
    logger.info("Found %d mSSMSManagementPoint objects", mp_count)


@app.resource(name="ldap_cmrc_devices", parallelized=False, columns=raw_table_asset("ldap_cmrc_devices"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_cmrc_devices(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Lookup table for AD computers carrying a ``CmRcService/*`` SPN.

    Mirrors PS1's LDAP once-phase search at
    ``ConfigManBearPig.ps1:3216-3289``. The CmRcService SPN is registered by
    the SCCM client agent at install time, so its presence on a Computer
    indicates the box was (or is) an SCCM client. Phase 7 reads this table
    (via ``ctx.cmrc_spn_matches()``) to synthesise SCCM_ClientDevice rows
    in ``adminservice_client_devices`` for hosts that AdminService didn't
    surface.

    Emitting the search as a standalone LDAP-phase resource (rather than
    burying it inside ``adminservice_client_devices``) keeps the network
    call associated with its true phase in logs and lets a caller who
    runs only ``-m LDAP`` still discover the SPN-marked hosts.
    """
    if not ctx.method_enabled("LDAP"):
        return
    matches = ctx.cmrc_spn_matches()
    domain = ctx.domain
    for entry in matches:
        sid = entry.get("object_sid") or entry.get("objectSid")
        if isinstance(sid, (bytes, memoryview)):
            try:
                from ..clients.ad import bytes_to_sid as _b2s
                sid = _b2s(sid)
            except Exception:
                sid = None
        if not sid:
            continue
        dns = (entry.get("dNSHostName") or "").lower() or None
        sam = (entry.get("sAMAccountName") or "").strip() or None
        name = entry.get("name") or None
        # Register as a probe target — mirrors PS1's ``Add-DeviceToTargets
        # -Source LDAP-CmRcService`` at ConfigManBearPig.ps1:3261. Subsequent
        # per-host phases (Registry / MSSQL / WMI / HTTP / SMB) will pick
        # this host up via ``target_hosts_snapshot()``.
        ctx.register_target(
            dns or (sam.rstrip("$") if sam else None),
            sid=str(sid), sam=sam, name=name,
            source="LDAP-CmRcService",
        )
        yield {
            "object_sid": str(sid),
            "sam_account_name": sam,
            "name": name,
            "dns_host_name": dns,
            "domain": domain,
        }


@app.resource(name="ldap_network_boot_servers", parallelized=False, columns=raw_table_asset("ldap_network_boot_servers"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_network_boot_servers(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Network-boot (PXE) servers discovered via two AD object patterns.

    Mirrors PS1's LDAP once-phase search at
    ``ConfigManBearPig.ps1:3291-3378``:

    * ``(&(objectclass=connectionPoint)(netbootserver=*))`` — modern
      WDS / SCCM PXE registration; the parent object is the SCCM DP.
    * ``(objectclass=intellimirrorSCP)`` — legacy RIS / WDS SCP, same parent
      mapping.

    For each match we strip the leading RDN to get the parent DN (the
    Computer), so a row in this table can be joined on
    ``ldap_computers.distinguished_name`` at convert time. Phase 4 then
    sets the Computer's ``networkBootServer`` to True from this signal
    AND adds the host to the per-host probe set so subsequent phases see
    it. PS1 emits these even when the SCCM client (and therefore the
    SMB SCCMContentLib$ share probe) isn't reachable — running
    ``-m LDAP`` alone should still surface them.
    """
    if not ctx.method_enabled("LDAP"):
        return
    domain = ctx.domain
    logger.info("Searching for network boot servers (PXE-enabled DPs)...")
    seen_parent_dns: set[str] = set()

    def _emit(entry: dict[str, Any], object_class: str) -> Iterable[dict[str, Any]]:
        dn = entry.get("distinguishedName") or ""
        if not dn or "," not in dn:
            return
        # Strip the first RDN (the connectionPoint / intellimirrorSCP itself)
        # to get the parent computer's DN.
        parent_dn = dn.split(",", 1)[1].strip()
        if not parent_dn or parent_dn in seen_parent_dns:
            return
        seen_parent_dns.add(parent_dn)
        yield {
            "parent_dn": parent_dn,
            "object_class": object_class,
            "source": f"LDAP-{object_class}",
            "domain": domain,
        }

    try:
        for entry in ctx.ad.paged_search(
            search_filter="(&(objectclass=connectionPoint)(netbootserver=*))",
            attributes=["distinguishedName"],
        ):
            yield from _emit(entry, "connectionPoint")
    except Exception as exc:  # noqa: BLE001
        logger.warning("ldap connectionPoint search failed: %s", exc)
    try:
        for entry in ctx.ad.paged_search(
            search_filter="(objectclass=intellimirrorSCP)",
            attributes=["distinguishedName"],
        ):
            yield from _emit(entry, "intellimirrorSCP")
    except Exception as exc:  # noqa: BLE001
        logger.warning("ldap intellimirrorSCP search failed: %s", exc)
    logger.info("Found %d network boot server object(s)", len(seen_parent_dns))


@app.resource(name="ldap_system_management_acl", parallelized=False, columns=raw_table_asset("ldap_system_management_acl"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_system_management_acl(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Principals with ``GenericAll`` rights on the System Management container.

    Mirrors PS1's ``Get-Acl AD:\\<SystemManagementDN>`` walk at
    ``ConfigManBearPig.ps1:3454-3517``. PS1 emits the matched principals
    as Computer / User / Group nodes with
    ``collectionSource=["LDAP-GenericAllSystemManagement"]`` and adds any
    Computer principals to the collection-target set.

    Reading the DACL through LDAP requires the ``nTSecurityDescriptor``
    attribute with the ``LDAP_SERVER_SD_FLAGS_OID`` control set so the DC
    returns the discretionary ACL even for non-domainadmin readers.
    ldap3 surfaces both via the ``SDFlagsControl`` extension.
    """
    if not ctx.method_enabled("LDAP"):
        return
    logger.info("Checking permissions on System Management container...")
    try:
        conn = ctx.ad.bind()
    except Exception as exc:  # noqa: BLE001
        logger.warning("ldap_system_management_acl: bind failed: %s", exc)
        return

    from ldap3.protocol.microsoft import security_descriptor_control
    sd_control = security_descriptor_control(sdflags=0x04)  # DACL only

    try:
        conn.search(
            search_base=ctx.system_management_dn,
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes=["nTSecurityDescriptor"],
            controls=sd_control,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("ldap_system_management_acl: SD read failed: %s", exc)
        return
    if not conn.entries:
        logger.info("System Management container not found or empty SD")
        return

    raw_sd = conn.entries[0]["nTSecurityDescriptor"].raw_values
    if not raw_sd:
        return

    # Parse using impacket — it's already an OH transitive dep via the SMB /
    # WMI probes. ldap3 doesn't ship a SD/ACE parser of its own.
    try:
        from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
    except ImportError:
        logger.warning("ldap_system_management_acl: impacket SD parser unavailable")
        return

    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(raw_sd[0])

    # GenericAll = 0x000F01FF (DS_CONTROL_ACCESS | all directory rights). PS1
    # checks ``$_.ActiveDirectoryRights -eq "GenericAll"`` which evaluates
    # against the same bitmask. ACE type 0x00 is ACCESS_ALLOWED.
    GENERIC_ALL = 0x000F01FF
    ACCESS_ALLOWED_ACE_TYPE = 0x00

    domain = ctx.domain
    seen_sids: set[str] = set()
    count = 0
    for ace in sd["Dacl"]["Data"]:
        if ace["AceType"] != ACCESS_ALLOWED_ACE_TYPE:
            continue
        mask = ace["Ace"]["Mask"]["Mask"]
        if mask != GENERIC_ALL:
            continue
        sid_obj = ace["Ace"]["Sid"]
        try:
            sid_str = sid_obj.formatCanonical()
        except Exception:
            continue
        # Skip BUILTIN / NT AUTHORITY (S-1-5-18, etc.) — matches PS1's
        # ``-notlike "NT AUTHORITY\\*"`` filter at line 3462.
        if sid_str.startswith("S-1-5-") and sid_str.count("-") < 5:
            # short SIDs like S-1-5-18, S-1-5-32-544 — built-in / system
            # principals; PS1 skips them. We allow domain SIDs through
            # because those have 7+ components.
            if sid_str.startswith("S-1-5-32-") or sid_str in ("S-1-5-18", "S-1-5-19", "S-1-5-20"):
                continue
        if sid_str in seen_sids:
            continue
        seen_sids.add(sid_str)
        count += 1
        yield {
            "principal_sid": sid_str,
            "ace_mask": int(mask),
            "source": "LDAP-GenericAllSystemManagement",
            "domain": domain,
        }
    logger.info("Found %d principal(s) with GenericAll on System Management container", count)


@app.resource(name="ldap_sms_providers", parallelized=False, columns=raw_table_asset("ldap_sms_providers"))
@with_log_context(phase="LDAP", target_from_ctx_domain=True)
def ldap_sms_providers(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Computers that host the SMS Provider role (lookup table — no node emitted).

    Discovered via the ``intellimirrorSCP`` and ``connectionPoint`` SPN patterns plus
    the ``ServiceConnectionPoint`` objectClass under each SCCM site DN. Phase 1 emits
    rows from a simple sAMAccountName naming pattern (``*-sms``, ``*-pss``); Phase 3
    enriches via the AdminService discovery.

    Intentionally has no ``columns=`` (i.e. no Pydantic validator/asset). If the
    Computer asset were attached, the convert phase would map ``Computer`` to this
    table instead of ``ldap_computers`` (DLT framework limitation: one asset class
    maps to exactly one source table). The SMS-provider rows already appear in
    ``ldap_computers`` via the broader LDAP query; this resource only feeds
    ``transforms.py`` (``assign_all_permissions_edges`` etc).
    """
    logger.info("Searching for SMS Provider hosts (sAMAccountName ends in -pss / -sms)...")
    seen_sids: set[str] = set()
    count = 0
    for entry in ctx.ad.paged_search(
        search_filter="(&(objectCategory=computer)(|(samAccountName=*-pss$)(samAccountName=*-sms$)))",
        attributes=_COMPUTER_ATTRS,
    ):
        sid = entry.get("object_sid")
        if not sid or sid in seen_sids:
            continue
        seen_sids.add(sid)
        count += 1
        yield _normalize_computer(entry, ctx.domain, source_tag="LDAP-SMSProvider")
    logger.info("Found %d SMS Provider host(s)", count)


# ---------------------------------------------------------------------------
# Normalisers — flatten ldap3-shaped dicts into the schema expected by models.
# ---------------------------------------------------------------------------

def _list_or_none(value) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _account_disabled(uac: Any) -> bool | None:
    if uac is None:
        return None
    try:
        return bool(int(uac) & 0x2)
    except (TypeError, ValueError):
        return None


def _normalize_computer(entry: dict[str, Any], domain: str, *, source_tag: str = "LDAP") -> dict[str, Any]:
    sam = entry.get("sAMAccountName") or ""
    return {
        "object_sid": entry.get("object_sid") or "",
        "object_guid": entry.get("object_guid"),
        "sam_account_name": sam,
        "name": entry.get("name") or sam.rstrip("$"),
        "distinguished_name": entry.get("distinguishedName"),
        "dns_host_name": (entry.get("dNSHostName") or "").lower() or None,
        "operating_system": entry.get("operatingSystem"),
        "operating_system_version": entry.get("operatingSystemVersion"),
        "enabled": (False if _account_disabled(entry.get("userAccountControl")) else True),
        "service_principal_names": _list_or_none(entry.get("servicePrincipalName")),
        "member_of_dns": _list_or_none(entry.get("memberOf")),
        "primary_group_id": entry.get("primaryGroupID"),
        "source": source_tag,
        "domain": domain,
    }


def _normalize_user(entry: dict[str, Any], domain: str) -> dict[str, Any]:
    sam = entry.get("sAMAccountName") or ""
    return {
        "object_sid": entry.get("object_sid") or "",
        "object_guid": entry.get("object_guid"),
        "sam_account_name": sam,
        "user_principal_name": entry.get("userPrincipalName"),
        "name": entry.get("name") or sam,
        "display_name": entry.get("displayName"),
        "distinguished_name": entry.get("distinguishedName"),
        "enabled": (False if _account_disabled(entry.get("userAccountControl")) else True),
        "member_of_dns": _list_or_none(entry.get("memberOf")),
        "primary_group_id": entry.get("primaryGroupID"),
        "service_principal_names": _list_or_none(entry.get("servicePrincipalName")),
        "domain": domain,
    }


def _normalize_group(entry: dict[str, Any], domain: str) -> dict[str, Any]:
    sam = entry.get("sAMAccountName") or ""
    return {
        "object_sid": entry.get("object_sid") or "",
        "object_guid": entry.get("object_guid"),
        "sam_account_name": sam,
        "name": entry.get("name") or sam,
        "distinguished_name": entry.get("distinguishedName"),
        "group_type": entry.get("groupType"),
        "member": _list_or_none(entry.get("member")) or [],
        "domain": domain,
    }


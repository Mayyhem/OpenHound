"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the adminservice phase.
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
from ..log_context import per_pair_iter, with_log_context
from ..models import SCCMAdminUser, SCCMClientDevice, SCCMCollection, SCCMSecurityRole

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase 3b — AdminService REST API enumeration.
# ---------------------------------------------------------------------------
# The AdminService runs on the SMS Provider role over HTTPS / 443 and is the
# richest data source in the whole collector. The original CMBP implementation
# is `lib/collectors/adminservice_collector.py` (~1,399 LOC); we port the
# nine WMI-shaped queries faithfully but split them into separate DLT
# resources so each lands in its own JSONL.
#
# Pattern: each `adminservice_*` resource calls `ctx.adminservice_payloads()`
# which lazily fetches every reachable SMS Provider's data exactly once per
# source run, then yields the corresponding slice. Errors per host are
# swallowed with a logged INFO so a single offline provider doesn't fail the
# whole collection.
#
# CMBP reference URLs (under /AdminService/):
#   wmi/SMS_Identification               -> site code for this provider
#   wmi/SMS_Site                         -> all sites in the hierarchy
#   wmi/SMS_SCI_SiteDefinition           -> SQL/site server detail per site
#   wmi/SMS_Admin                        -> admin users / groups
#   wmi/SMS_Collection                   -> collections
#   wmi/SMS_FullCollectionMembership     -> per-collection members
#   wmi/SMS_Role                         -> security roles
#   wmi/SMS_R_System                     -> client devices / AD-mapped systems
#   wmi/SMS_CombinedDeviceResources      -> richer client device view
#   wmi/SMS_TaskSequencePackage          -> task sequence policies
#   wmi/SMS_CollectionVariable           -> per-collection variables
#   wmi/SMS_SCI_SysResUse                -> site system roles per host

def _normalize_role_member_admin(item: dict[str, Any]) -> str:
    """Extract a normalized ``DOMAIN\\sam`` admin logon from an SMS_Admin row."""
    return ((item.get("LogonName") or "").strip())


def _collect_adminservice_data(
    hostname: str,
    username: Optional[str],
    password: Optional[str],
) -> Optional[dict[str, Any]]:
    """Run the full AdminService enumeration against ``hostname`` and return
    a dict of lists keyed by resource name. Returns ``None`` if the host is
    unreachable or the initial site-code probe fails (i.e. neither
    ``SMS_Identification`` nor ``SMS_Site`` returns anything).

    Each list entry is a dict already shaped for the matching DLT resource
    schema. The shaping happens inline (one short helper would be more
    DRY but at the cost of clarity given how different the WMI rows are).
    """
    from ..clients.adminservice import AdminServiceClient

    logger.info("Starting AdminService collection on %s...", hostname)
    base_url = f"https://{hostname}/AdminService"
    client = AdminServiceClient(
        base_url=base_url,
        username=username,
        password=password,
        timeout=20,
    )

    if not client.host_reachable(443, timeout=3.0):
        logger.info("HTTPS port 443 not open on %s, skipping AdminService collection", hostname)
        return None
    logger.info("Connecting to AdminService on %s/", base_url)

    # Step 1: SMS_Identification gives this provider's site code.
    logger.info("Getting SMS Provider site code via SMS_Identification...")
    site_code = None
    ident = client.get("wmi/SMS_Identification")
    if ident:
        for entry in ident.get("value", []):
            sc = entry.get("ThisSiteCode")
            if sc:
                site_code = sc
                break

    # Step 2: SMS_Site gives every site in the hierarchy. Even if SMS_Identification
    # failed we may still pull a usable site_code from here.
    logger.info("Getting sites via AdminService...")
    sites_payload = client.get_paginated("wmi/SMS_Site") or []
    if sites_payload:
        logger.info("Retrieved %d SMS Sites", len(sites_payload))
    if not site_code and sites_payload:
        for entry in sites_payload:
            if entry.get("SiteCode"):
                site_code = entry["SiteCode"]
                break

    if not site_code:
        logger.info("Could not determine site code for %s", hostname)
        return None

    logger.info("Site code: %s", site_code)
    logger.info("Collecting from site: %s", site_code)

    logger.verbose("Querying SMS_SCI_SiteDefinition")
    site_definitions = client.get_paginated("wmi/SMS_SCI_SiteDefinition") or []
    logger.verbose("Retrieved %d SMS_SCI_SiteDefinition rows", len(site_definitions))

    logger.info("Discovering admin users and security roles...")
    logger.verbose("Querying SMS_Admin")
    admins_raw = client.get_paginated("wmi/SMS_Admin") or []
    logger.info("Found %d admin users", len(admins_raw))
    logger.verbose("Querying SMS_Collection")
    collections_raw = client.get_paginated("wmi/SMS_Collection") or []
    logger.info("Found %d collections", len(collections_raw))
    logger.verbose("Querying SMS_FullCollectionMembership")
    collection_members_raw = client.get_paginated("wmi/SMS_FullCollectionMembership") or []
    logger.verbose("Retrieved %d collection-membership rows", len(collection_members_raw))
    logger.verbose("Querying SMS_Role")
    roles_raw = client.get_paginated("wmi/SMS_Role") or []
    logger.info("Found %d security roles", len(roles_raw))
    logger.verbose("Querying SMS_R_System")
    sms_r_system_raw = client.get_paginated("wmi/SMS_R_System") or []
    logger.verbose("Retrieved %d SMS_R_System rows", len(sms_r_system_raw))
    # SMS_CombinedDeviceResources defaults to a small projection. PS1 (line
    # 7166 of ConfigManBearPig.ps1) requests a wide $select; mirror it so
    # the device property bag can carry ADLastLogonTime, lastOfflineTime,
    # lastOnlineTime, primaryUser, currentLogonUser, deviceOS,
    # userDomainName, etc.
    combined_devices_raw = client.get_paginated(
        "wmi/SMS_CombinedDeviceResources",
        extra_params={
            "$select": (
                "AADDeviceID,AADTenantID,ADLastLogonTime,CNAccessMP,"
                "CNLastOfflineTime,CNLastOnlineTime,CoManaged,"
                "CurrentLogonUser,DeviceOS,DeviceOSBuild,IsClient,"
                "IsObsolete,IsVirtualMachine,LastActiveTime,LastMPServerName,"
                "Name,PrimaryUser,ResourceID,SiteCode,SMSID,"
                "UserName,UserDomainName,ClientVersion"
            )
        },
    ) or []
    # SMS_R_User: like SMS_R_System but for AD users, with SecurityGroupName
    # giving each user's group memberships. CMBP feeds these to MemberOf
    # edges (User -> Group); see adminservice_collector._get_sms_r_user.
    sms_r_user_raw = client.get_paginated(
        "wmi/SMS_R_User",
        extra_params={
            "$select": (
                "DistinguishedName,FullDomainName,FullUserName,Name,ResourceID,"
                "SecurityGroupName,SID,UniqueUserName,UserName,UserPrincipalName"
            )
        },
    ) or []

    # The next two are best-effort - SCCM versions vary on availability.
    task_sequences_raw = client.get_paginated("wmi/SMS_TaskSequencePackage") or []
    collection_vars_raw = client.get_paginated("wmi/SMS_CollectionVariable") or []
    site_systems_raw = client.get_paginated("wmi/SMS_SCI_SysResUse") or []
    # SMS_SCI_Reserved: per-site stored accounts (NAA, push install, etc.).
    # CMBP feeds these to ``SCCM_HasStoredAccount`` edges from SCCM_Site
    # to the resolved User node.
    logger.info("Getting stored accounts...")
    reserved_accounts_raw = client.get_paginated("wmi/SMS_SCI_Reserved") or []
    if reserved_accounts_raw:
        logger.info("Found %d stored account entries", len(reserved_accounts_raw))
    else:
        logger.info("No stored accounts found")

    # ----- Normalise into per-resource row lists -----

    # adminservice_admins: one row per SMS_Admin entry
    admins: list[dict[str, Any]] = []
    role_members: list[dict[str, Any]] = []
    for item in admins_raw:
        logon = _normalize_role_member_admin(item)
        if not logon:
            continue
        roles = item.get("RoleNames") or []
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",") if r.strip()]
        colls = item.get("CollectionNames") or []
        if isinstance(colls, str):
            colls = [c.strip() for c in colls.split(",") if c.strip()]

        scope_names = item.get("CategoryNames") or []
        if isinstance(scope_names, str):
            scope_names = [s.strip() for s in scope_names.split(",") if s.strip()]
        is_all_instances = bool(scope_names) and (
            "All Systems" in scope_names or "All" in scope_names
        )

        admins.append({
            "logon_name": logon,
            "site_code": site_code,
            "admin_id": item.get("AdminID"),
            "admin_sid": item.get("AdminSid") or "",
            "display_name": item.get("DisplayName") or "",
            "is_group": (item.get("AccountType") == 1),
            "is_all_instances": is_all_instances,
            "source_site_code": item.get("SourceSite") or site_code,
            "role_names": roles,
            "collection_names": colls,
            # PS1 surfaces these audit fields on the SCCM_AdminUser node.
            # ``SMS_Admin.LastModifiedBy`` is a ``DOMAIN\sam`` string and
            # ``LastModifiedDate`` is an ISO timestamp.
            "last_modified_by": item.get("LastModifiedBy") or "",
            "last_modified_date": item.get("LastModifiedDate") or "",
        })

        # adminservice_role_members: one row per (admin, role, scope-collection) tuple.
        # SMS_Admin's RoleNames + CollectionNames are parallel-ish lists; we
        # cross them so Phase 4 can join scope vs role independently. The
        # CategoryNames+RoleNames "All Systems" case represents a Full Admin
        # with global scope - emitted with scope_collection_id = "SMS00001".
        scope_collection_ids: list[str] = []
        if is_all_instances:
            scope_collection_ids = ["SMS00001"]  # All Systems
        # Match collection name -> id from the collections list when available.
        coll_name_to_id = {
            (c.get("Name") or "").strip(): (c.get("CollectionID") or "").strip()
            for c in collections_raw
        }
        for cname in colls:
            cid = coll_name_to_id.get(cname.strip())
            if cid:
                scope_collection_ids.append(cid)

        # If we couldn't resolve any specific scope, emit one role-member row
        # per role with a NULL scope so the relation is still recorded.
        if not scope_collection_ids:
            scope_collection_ids = [""]

        # Match role name -> id from the roles list.
        role_name_to_id = {
            (r.get("RoleName") or "").strip(): (r.get("RoleID") or "").strip()
            for r in roles_raw
        }
        for rname in roles:
            rid = role_name_to_id.get(rname.strip(), "")
            for cid in scope_collection_ids:
                role_members.append({
                    "admin_logon_name": logon,
                    "site_code": site_code,
                    "role_id": rid,
                    "role_name": rname,
                    "scope_collection_id": cid,
                    "scope_is_all": is_all_instances,
                })

    # adminservice_collections
    collections: list[dict[str, Any]] = []
    for item in collections_raw:
        cid = (item.get("CollectionID") or "").strip()
        if not cid:
            continue
        collections.append({
            "collection_id": cid,
            "site_code": site_code,
            "name": item.get("Name") or "",
            "collection_type": item.get("CollectionType"),
            "member_count": item.get("MemberCount"),
            "limiting_collection_id": item.get("LimitToCollectionID") or "",
            # PS1 emits these extra fields on every SCCM_Collection node;
            # they're all standard SMS_Collection columns. ``IsBuiltIn`` is
            # the bool flag for default collections (All Systems, All Users,
            # etc.). ``LastChangeTime`` / ``LastMemberChangeTime`` are ISO
            # timestamps. ``CollectionVariablesCount`` is the count of
            # variables defined on the collection (also exposed via the
            # separate ``adminservice_collection_variables`` resource).
            "comment": item.get("Comment") or "",
            "is_built_in": bool(item.get("IsBuiltIn") or False),
            "last_change_time": item.get("LastChangeTime") or "",
            "last_member_change_time": item.get("LastMemberChangeTime") or "",
            "collection_variables_count": item.get("CollectionVariablesCount"),
        })

    # adminservice_collection_members
    collection_members: list[dict[str, Any]] = []
    for item in collection_members_raw:
        cid = (item.get("CollectionID") or "").strip()
        rid = item.get("ResourceID") if item.get("ResourceID") is not None else item.get("ResourceId")
        if not cid or rid is None:
            continue
        sms_id = (item.get("SMSID") or "").strip()
        if sms_id and sms_id.upper().startswith("GUID:"):
            guid = sms_id.split(":", 1)[1]
        else:
            guid = sms_id
        # ``raw_site_code`` preserves the raw SiteCode field exactly as it
        # arrived from the SMS_FullCollectionMembership row (could be empty
        # for user / user-group collections — CMBP groups these with a
        # bare ``<id>@`` node id). ``site_code`` falls back to the
        # AdminService host's site_code so SQL views that join on it (e.g.
        # ``has_member_edges`` / ``client_user_edges``) keep working.
        raw_site_code = item.get("SiteCode") or ""
        member_site_code = raw_site_code or site_code
        collection_members.append({
            "site_code": member_site_code,
            "raw_site_code": raw_site_code,
            "collection_id": cid,
            "resource_id": rid,
            "guid": guid,
            "machine_name": item.get("Name") or "",
        })

    # adminservice_security_roles
    security_roles: list[dict[str, Any]] = []
    for item in roles_raw:
        rid = (item.get("RoleID") or "").strip()
        if not rid:
            continue
        security_roles.append({
            "role_id": rid,
            "site_code": site_code,
            "role_name": item.get("RoleName") or "",
            "description": item.get("RoleDescription") or "",
            # PS1 surfaces these audit + provenance fields on the
            # SCCM_SecurityRole node. ``CopiedFromID`` records the parent
            # role when an admin clones a built-in role to customise it.
            "copied_from_id": item.get("CopiedFromID") or "",
            "created_by": item.get("CreatedBy") or "",
            "created_date": item.get("CreatedDate") or "",
            "last_modified_by": item.get("LastModifiedBy") or "",
            "last_modified_date": item.get("LastModifiedDate") or "",
        })

    # adminservice_client_devices: prefer SMS_CombinedDeviceResources for the
    # rich (LastLogonUser/PrimaryUser/CurrentLogonUser) view, fall back to
    # SMS_R_System for the AD-side mapping.
    client_devices: list[dict[str, Any]] = []
    seen_guids: set[str] = set()
    for item in combined_devices_raw:
        is_client = bool(item.get("IsClient"))
        is_obsolete = bool(item.get("IsObsolete"))
        if not is_client or is_obsolete:
            continue
        sms_guid = (item.get("SMSID") or "").strip()
        if sms_guid.upper().startswith("GUID:"):
            sms_guid = sms_guid.split(":", 1)[1]
        if not sms_guid:
            continue
        if sms_guid in seen_guids:
            continue
        seen_guids.add(sms_guid)
        machine_name = (item.get("Name") or "").strip()
        # Per-device hostname (lowercase) — kept in a local that doesn't
        # shadow the function-parameter ``hostname`` (which is the SMS
        # Provider host and is read again by the closing log line / by
        # downstream callers that want the provider context).
        device_hostname = machine_name.lower() if machine_name else ""
        client_devices.append({
            "guid": sms_guid,
            "site_code": item.get("SiteCode") or site_code,
            "machine_name": machine_name,
            "resource_id": item.get("ResourceID") if item.get("ResourceID") is not None else item.get("ResourceId"),
            "is_client": is_client,
            "client_version": item.get("ClientVersion") or "",
            "ad_object_sid": "",  # filled in from SMS_R_System below
            # PS1 maps ``UserName`` to the device's last-logon-user;
            # ``LastLogonUser`` isn't in the AdminService projection PS1
            # requests. We mirror that here — keep ``last_logon_user``
            # populated so the ``SCCM_HasADLastLogonUser`` edges still
            # fire downstream.
            "last_logon_user": item.get("LastLogonUser") or item.get("UserName") or "",
            "primary_user": item.get("PrimaryUser") or "",
            "current_user": item.get("CurrentLogonUser") or "",
            # Additional PS1-aligned fields from SMS_CombinedDeviceResources.
            # ``DeviceOS`` and ``DeviceOSBuild`` map to PS1's
            # ``deviceOS`` / ``deviceOSBuild``. The various
            # ``Last*Time`` fields are used as-is.
            "device_os": item.get("DeviceOS") or item.get("OperatingSystemNameAndVersion") or "",
            "device_os_build": item.get("DeviceOSBuild") or item.get("Build") or "",
            "last_active_time": item.get("LastActiveTime") or "",
            "last_online_time": (
                item.get("CNLastOnlineTime") or item.get("LastOnlineTime") or ""
            ),
            "last_offline_time": (
                item.get("CNLastOfflineTime") or item.get("LastOfflineTime") or ""
            ),
            "last_reported_mp_server_name": (
                item.get("LastMPServerName")
                or item.get("LastReportedMPServerName")
                or ""
            ),
            # PS1 surfaces the previous SMSID + change date when a device
            # has been re-imaged or reinstalled.
            "previous_sms_id": item.get("PreviousSMSID") or "",
            "previous_sms_id_change_date": item.get("PreviousSMSIDChangeDate") or "",
            # The "currently assigned management point" — PS1 maps this
            # from ``CNAccessMP`` (the cloud-native client's currently-
            # reachable MP), falling back to ``LastMPServerName`` so the
            # property is never empty for an actively-reporting device.
            "current_management_point": (
                item.get("CNAccessMP")
                or item.get("CurrentManagementPoint")
                or item.get("ResidentMPServerName")
                or item.get("LastMPServerName")
                or item.get("LastReportedMPServerName")
                or ""
            ),
            # AD last-logon time on the device, surfaced via
            # ``SMS_CombinedDeviceResources.ADLastLogonTime``.
            "ad_last_logon_time": item.get("ADLastLogonTime") or "",
            # User name / domain split — PS1 reads these from
            # ``UserName`` + ``UserDomainName`` rather than parsing
            # ``LastLogonUser``. ``last_logon_user`` already carries the
            # bare SAM but we now also expose the domain prefix.
            "user_name": item.get("UserName") or "",
            "user_domain_name": item.get("UserDomainName") or "",
            "hostname": device_hostname,
        })

    # Walk SMS_R_System for the AD SID linkage on each device.
    rs_by_resource_id: dict[int, dict[str, Any]] = {}
    for item in sms_r_system_raw:
        rid = item.get("ResourceID") if item.get("ResourceID") is not None else item.get("ResourceId")
        if rid is None:
            continue
        rs_by_resource_id[rid] = item

    for dev in client_devices:
        rid = dev.get("resource_id")
        if rid is None:
            continue
        rs = rs_by_resource_id.get(rid)
        if not rs:
            continue
        sid = rs.get("SID") or rs.get("ObjectGUID") or ""
        if isinstance(sid, list):
            sid = sid[0] if sid else ""
        if isinstance(sid, str) and sid.startswith("S-"):
            dev["ad_object_sid"] = sid
        # PS1's ``DNSHostName`` on SCCM_ClientDevice is the FQDN of the
        # device. ``SMS_R_System`` stores it as the netbios name + the
        # full domain name in separate fields; we glue them.
        netbios = rs.get("NetbiosName") or rs.get("Name") or ""
        if isinstance(netbios, list):
            netbios = netbios[0] if netbios else ""
        full_domain = rs.get("FullDomainName") or ""
        if isinstance(full_domain, list):
            full_domain = full_domain[0] if full_domain else ""
        if netbios and full_domain:
            dev["dns_host_name"] = f"{netbios}.{full_domain}".lower()
        elif netbios:
            dev["dns_host_name"] = str(netbios).lower()

    # adminservice_task_sequences
    task_sequences: list[dict[str, Any]] = []
    for item in task_sequences_raw:
        pkg_id = (item.get("PackageID") or "").strip()
        if not pkg_id:
            continue
        task_sequences.append({
            "package_id": pkg_id,
            "site_code": site_code,
            "name": item.get("Name") or "",
            "description": item.get("Description") or "",
        })

    # adminservice_collection_variables
    collection_variables: list[dict[str, Any]] = []
    for item in collection_vars_raw:
        cid = (item.get("CollectionID") or "").strip()
        var_name = (item.get("Name") or "").strip()
        if not cid or not var_name:
            continue
        collection_variables.append({
            "site_code": site_code,
            "collection_id": cid,
            "name": var_name,
            "value": item.get("Value") or "",
            "is_masked": bool(item.get("IsMasked")),
        })

    # adminservice_r_system_security_groups: one row per (computer_name,
    # security_group_name) pair from SMS_R_System. CMBP uses these to emit
    # Computer -> Group MemberOf edges via the AD resolver in
    # ``adminservice_collector._get_sms_r_system`` (lines 698-731). Phase 6
    # consumes this in the ``r_system_member_of_edges`` SQL view to fill
    # the MemberOf gap (33 -> 68) at convert time.
    r_system_security_groups: list[dict[str, Any]] = []
    for item in sms_r_system_raw:
        machine = (item.get("Name") or "").strip()
        # SMS_R_System uses "ResourceId" (capital R, lower D) — not "ResourceID".
        resource_id = item.get("ResourceId") or item.get("ResourceID")
        groups = item.get("SecurityGroupName") or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",") if g.strip()]
        if not machine:
            continue
        # Emit a row even when SecurityGroupName is empty so the Computer
        # model can still pick up the SMS_R_System ResourceID for hosts
        # that are AD-pushed but not in any SCCM security group (PS1
        # behaviour at ConfigManBearPig.ps1:7363).
        if not groups:
            r_system_security_groups.append({
                "machine_name": machine,
                "site_code": site_code,
                "security_group_name": None,
                "resource_id": resource_id,
            })
            continue
        for grp in groups:
            grp = (grp or "").strip()
            if not grp:
                continue
            r_system_security_groups.append({
                "machine_name": machine,
                "site_code": site_code,
                "security_group_name": grp,
                "resource_id": resource_id,
            })

    # adminservice_r_user_security_groups: one row per (user_sid /
    # user_name, security_group_name) pair from SMS_R_User. CMBP uses
    # these to emit User -> Group MemberOf edges; see
    # ``adminservice_collector._get_sms_r_user`` (lines 757-870).
    # Phase 6's ``r_user_member_of_edges`` SQL view consumes this.
    r_user_security_groups: list[dict[str, Any]] = []
    for item in sms_r_user_raw:
        sid_value = item.get("SID")
        if isinstance(sid_value, list):
            sid_value = sid_value[0] if sid_value else None
        if not sid_value:
            continue
        full_name = (item.get("FullUserName") or item.get("UniqueUserName") or item.get("Name") or "").strip()
        sam = (item.get("UserName") or "").strip()
        resource_id = item.get("ResourceID") if item.get("ResourceID") is not None else item.get("ResourceId")
        groups = item.get("SecurityGroupName") or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",") if g.strip()]
        if not groups:
            continue
        for grp in groups:
            grp = (grp or "").strip()
            if not grp:
                continue
            r_user_security_groups.append({
                "user_sid": sid_value,
                "user_name": full_name or sam,
                "user_sam_account_name": sam,
                "site_code": site_code,
                "security_group_name": grp,
                "resource_id": resource_id,
            })

    # adminservice_site_systems
    site_systems: list[dict[str, Any]] = []
    for item in site_systems_raw:
        server_name = (item.get("ServerName") or "").strip()
        role_name = (item.get("RoleName") or "").strip()
        role_site = item.get("SiteCode") or site_code
        if not server_name or not role_name:
            # Fall back to NetworkOSPath which is sometimes the only field set.
            net_path = (item.get("NetworkOSPath") or "").lstrip("\\").strip()
            if net_path and not server_name:
                server_name = net_path
        if not server_name or not role_name:
            continue

        # CMBP extracts the SQL Server service account from the Props sub-list:
        # PropertyName == "SQL Server Service Logon Account", account in Value2
        # (lib/collectors/adminservice_collector.py:1267-1272). This is the
        # ONLY data source for service-account info that survives without
        # Win32_Service WMI access (lowpriv/roanalyst can't read Win32_Service).
        # We carry it on the SMS SQL Server role row so the gettgs SQL view
        # can fall back to it when wmi_sql_service_accounts is empty.
        service_account: Optional[str] = None
        props_list = item.get("Props", [])
        if isinstance(props_list, list):
            for prop in props_list:
                if not isinstance(prop, dict):
                    continue
                if prop.get("PropertyName") == "SQL Server Service Logon Account":
                    val2 = (prop.get("Value2") or "").strip()
                    if val2:
                        service_account = val2
                        break

        site_systems.append({
            "hostname": server_name.lower(),
            "role": role_name,
            "site_code": role_site,
            "computer_sid": None,  # resolved at convert time via ldap_computers
            "service_account": service_account,  # only set on SMS SQL Server rows
        })

    # adminservice_reserved_accounts: one row per SMS_SCI_Reserved entry that
    # carries an actual ``UserName`` (CMBP skips entries with no UserName).
    # Each row's ``account_username`` is a ``DOMAIN\sam`` string we resolve
    # against ``ldap_users`` at preproc time to materialise the
    # ``SCCM_HasStoredAccount`` edge.
    reserved_accounts: list[dict[str, Any]] = []
    for item in reserved_accounts_raw:
        username = (item.get("UserName") or "").strip()
        if not username:
            continue
        reserved_accounts.append({
            "account_username": username,
            "item_name": (item.get("ItemName") or "").strip(),
            "item_type": (item.get("ItemType") or "").strip(),
            "site_code": (item.get("SiteCode") or site_code).strip() or site_code,
        })

    logger.info("AdminService collection completed for %s", hostname)
    return {
        "site_code": site_code,
        "sites": sites_payload,
        "site_definitions": site_definitions,
        "admins": admins,
        "role_members": role_members,
        "collections": collections,
        "collection_members": collection_members,
        "security_roles": security_roles,
        "client_devices": client_devices,
        "task_sequences": task_sequences,
        "collection_variables": collection_variables,
        "site_systems": site_systems,
        "r_system_security_groups": r_system_security_groups,
        "r_user_security_groups": r_user_security_groups,
        "reserved_accounts": reserved_accounts,
    }


@app.resource(name="adminservice_admins", parallelized=False, columns=SCCMAdminUser)
@with_log_context(phase="AdminService")
def adminservice_admins(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_Admin entry per reachable SMS Provider.

    Yields the dict shape consumed by ``models/sccm_admin_user.py``. Multiple
    SMS Providers in a hierarchy will produce overlapping rows (CAS sees
    every Primary's admins) — that's expected; convert-side dedup happens
    by id.
    """
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_admins") == "done":
            continue
        for row in payload.get("admins", []):
            yield {**row, "domain": domain}
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_admins")


@app.resource(name="adminservice_collections", parallelized=False, columns=SCCMCollection)
@with_log_context(phase="AdminService")
def adminservice_collections(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_Collection entry per reachable SMS Provider, plus
    one phantom-suffix row per CollectionID whose first
    SMS_FullCollectionMembership member carries an empty SiteCode (CMBP
    creates a bare ``<id>@`` node for these — typically user / user-group
    collections — by grouping memberships and using
    ``members[0].SiteCode or ''``).
    """
    domain = ctx.domain
    # Track phantom collections: emit one stub row per (CollectionID) where
    # the first observed member has empty raw SiteCode and we have NOT yet
    # emitted that phantom for that ID.
    phantom_emitted: set[str] = set()

    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_collections") == "done":
            continue
        # Real SMS_Collection entries
        for row in payload.get("collections", []):
            yield {**row, "domain": domain}

        # Phantom rows from SMS_FullCollectionMembership when the first
        # group-member's raw SiteCode is empty. CMBP groups by
        # CollectionID and uses ``members[0].SiteCode`` as the suffix —
        # if that's empty (typical for user-collection types), the node
        # is created with id ``<cid>@``.
        first_raw_by_cid: dict[str, str] = {}
        for row in payload.get("collection_members", []) or []:
            cid = (row.get("collection_id") or "").strip()
            if not cid:
                continue
            if cid in first_raw_by_cid:
                continue
            first_raw_by_cid[cid] = (row.get("raw_site_code") or "").strip()

        for cid, raw_sc in first_raw_by_cid.items():
            if raw_sc:
                # First member already has a real site code — CMBP would
                # produce <cid>@<raw_sc>, then post-processing renames it
                # to the hierarchy root. This is exactly what
                # ``SCCMCollection`` already produces from the
                # ``adminservice_collections`` SMS_Collection row, so
                # nothing more to do here.
                continue
            if cid in phantom_emitted:
                continue
            phantom_emitted.add(cid)
            yield {
                "collection_id": cid,
                "site_code": "",  # bare ``<cid>@`` node id
                "name": None,
                "collection_type": None,
                "member_count": None,
                "limiting_collection_id": None,
                "domain": domain,
                "source": "AdminService-SMS_FullCollectionMembership",
            }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_collections")


@app.resource(name="adminservice_collection_members", parallelized=False, columns=raw_table_asset("adminservice_collection_members"))
@with_log_context(phase="AdminService")
def adminservice_collection_members(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_FullCollectionMembership entry per reachable SMS Provider.

    Lookup table only — no Pydantic asset. Phase 4 SQL views consume this for
    SCCM_HasMember edges (collection -> client device).
    """
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_collection_members") == "done":
            continue
        for row in payload.get("collection_members", []):
            yield {**row, "domain": domain}
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_collection_members")


@app.resource(name="adminservice_security_roles", parallelized=False, columns=SCCMSecurityRole)
@with_log_context(phase="AdminService")
def adminservice_security_roles(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_Role entry per reachable SMS Provider."""
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_security_roles") == "done":
            continue
        for row in payload.get("security_roles", []):
            yield {**row, "domain": domain}
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_security_roles")


@app.resource(name="adminservice_role_members", parallelized=False, columns=raw_table_asset("adminservice_role_members"))
@with_log_context(phase="AdminService")
def adminservice_role_members(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (admin, role, scope-collection) tuple.

    Lookup table only — no Pydantic asset. Phase 4 SQL views consume this to
    materialise SCCM_FullAdministrator / SCCM_ApplicationAdministrator /
    SCCM_AssignSpecificPermissions derived edges via the
    ``role_assignment_edges`` view.
    """
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_role_members") == "done":
            continue
        for row in payload.get("role_members", []):
            yield {**row, "domain": domain}
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_role_members")


@app.resource(name="adminservice_client_devices", parallelized=False, columns=SCCMClientDevice)
@with_log_context(phase="AdminService")
def adminservice_client_devices(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (de-duped) SCCM client device.

    Two sources combine:

    1. ``SMS_CombinedDeviceResources`` / ``SMS_R_System`` from AdminService
       (the rich, authoritative source — only available to SCCM admins).
    2. LDAP computers carrying the ``CmRcService`` SPN — that SPN is
       registered by the SCCM client agent during installation, so its
       presence on a Computer is a strong signal that the box is an SCCM
       client. CMBP emits a synthesised ``SCCM_ClientDevice`` for every
       such Computer (regardless of AdminService access) so users who
       can't reach AdminService still see the SCCM-managed estate.

    The synthesised rows are skipped when AdminService already supplied
    a row whose ``ad_object_sid`` matches the LDAP Computer SID, so the
    two sources never double-emit the same device.
    """
    domain = ctx.domain
    sid_to_admin_guid: dict[str, str] = {}
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_client_devices") == "done":
            continue
        for row in payload.get("client_devices", []):
            sid = (row.get("ad_object_sid") or "").upper()
            if sid and row.get("guid"):
                sid_to_admin_guid.setdefault(sid, row["guid"])
            yield {**row, "domain": domain}
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_client_devices")

    # Synthesise ClientDevice rows for every LDAP computer carrying the
    # CmRcService SPN. When the SID already has an AdminService device,
    # we re-use the AdminService GUID so the two rows merge at node-emit
    # time but each row still contributes its own SCCM_HasClient edge in
    # the SQL view (matching CMBP, which emits separate edges per
    # discovery path even though the underlying device is one node).
    yield from _synthesised_cmrc_client_devices(ctx, domain, sid_to_admin_guid)


def _synthesised_cmrc_client_devices(
    ctx: "SourceContext",
    domain: str,
    sid_to_admin_guid: dict[str, str],
) -> Iterable[dict[str, Any]]:
    """LDAP-only fallback: emit a SCCM_ClientDevice for every Computer
    whose ``servicePrincipalName`` includes ``CmRcService/...``.

    PS1 (ConfigManBearPig.ps1 line 3269) gates this synthesis on
    ``-not $DisablePossibleEdges`` — the CmRcService SPN is a heuristic
    signal that "the box was once an SCCM client", and PS1 considers
    that too speculative to emit when the caller asks for confirmed-
    only edges. Mirror that gate here so OpenHound and PS1 agree under
    ``--disable-possible-edges``.

    Matches CMBP's ``_collect_cmrc_service_spns`` behaviour: takes the
    first primary site code found via ``mSSMSSite`` (or the first site
    of any kind, falling back to ``UNKNOWN`` if none) and uses
    ``uuid.uuid5(SID, site_code)`` for a deterministic per-(sid, site)
    GUID — CMBP uses a fresh ``uuid.uuid4()`` per run; we make ours
    stable so the same ZIP is reproducible across collects.
    """
    import uuid

    # PS1 line 3269: ``if (-not $DisablePossibleEdges)``. The SPN-based
    # heuristic is a "possible" client signal that PS1 suppresses under
    # ``-DisablePossibleEdges``; suppress here too so OpenHound matches
    # PS1 intent.
    if ctx.disable_possible_edges:
        return

    site_code = _primary_site_code_from_ldap(ctx)
    if not site_code:
        # No SCCM site at all — synthesised devices wouldn't have
        # anywhere to attach to.
        return

    cmrc_namespace = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")  # URL namespace; arbitrary fixed namespace
    # The LDAP CmRcService SPN search has been moved to ``SourceContext.
    # cmrc_spn_matches()`` (which is driven by the ``ldap_cmrc_devices``
    # resource in collectors/ldap.py) so the network call is bracketed
    # with ``phase_context("LDAP")`` and logged correctly in the LDAP
    # phase. Here we just consume the cached result; if LDAP collection
    # was disabled or the search failed, the cache returns ``[]``.
    cmrc_results = ctx.cmrc_spn_matches()
    if not cmrc_results:
        return
    for entry in cmrc_results:
        sid = _coerce_sid(entry.get("object_sid") or entry.get("objectSid"))
        if not sid:
            continue
        sam = (entry.get("sAMAccountName") or "").rstrip("$")
        name = entry.get("name") or sam
        machine_name = (sam or name or "").upper()
        if not machine_name:
            continue
        # Re-use the AdminService GUID for this SID if available so the
        # two rows merge at node-emit time. Otherwise synthesise a new
        # deterministic UUID.
        device_guid = sid_to_admin_guid.get(sid.upper()) or str(
            uuid.uuid5(cmrc_namespace, f"{sid}|{site_code}")
        )
        yield {
            "guid": device_guid,
            "site_code": site_code,
            "machine_name": machine_name,
            "resource_id": None,
            "is_client": True,
            "client_version": None,
            "ad_object_sid": sid,
            "last_logon_user": None,
            "primary_user": None,
            "current_user": None,
            "domain": domain,
            "source": "LDAP-CmRcService",
        }


def _primary_site_code_from_ldap(ctx: "SourceContext") -> Optional[str]:
    """First primary site code from ``mSSMSSite`` System Management container.

    Mirrors CMBP's ``_get_first_primary_site_published_to_ad``: takes the
    first site whose ``mSSMSAssignmentSiteCode`` is non-empty, falling
    back to the first one we see if no primary is flagged.
    """
    try:
        results = list(
            ctx.ad.paged_search(
                search_filter="(objectClass=mSSMSSite)",
                attributes=["mSSMSSiteCode", "mSSMSAssignmentSiteCode", "cn", "name"],
            )
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("ldap mSSMSSite search failed: %s", exc)
        return None
    primary_codes: list[str] = []
    any_codes: list[str] = []
    for entry in results:
        site_code = entry.get("mSSMSSiteCode") or entry.get("cn") or entry.get("name")
        if isinstance(site_code, list):
            site_code = site_code[0] if site_code else None
        if not site_code:
            continue
        any_codes.append(site_code)
        if entry.get("mSSMSAssignmentSiteCode"):
            primary_codes.append(site_code)
    if primary_codes:
        return primary_codes[0]
    if any_codes:
        return any_codes[0]
    return None


def _coerce_sid(sid_value: Any) -> Optional[str]:
    if sid_value is None:
        return None
    if isinstance(sid_value, list):
        sid_value = sid_value[0] if sid_value else None
        if sid_value is None:
            return None
    if isinstance(sid_value, bytes):
        try:
            from impacket.ldap.ldaptypes import LDAP_SID
            sid = LDAP_SID()
            sid.fromString(sid_value)
            return sid.formatCanonical()
        except Exception:  # noqa: BLE001
            return None
    return str(sid_value)


@app.resource(name="adminservice_task_sequences", parallelized=False, columns=raw_table_asset("adminservice_task_sequences"))
@with_log_context(phase="AdminService")
def adminservice_task_sequences(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_TaskSequencePackage entry. Phase 4 wires these into
    SCCM_HasTaskSequence edges + SCCM_Secret nodes."""
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_task_sequences") == "done":
            continue
        for row in payload.get("task_sequences", []):
            yield {**row, "domain": domain}
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_task_sequences")


@app.resource(name="adminservice_collection_variables", parallelized=False, columns=raw_table_asset("adminservice_collection_variables"))
@with_log_context(phase="AdminService")
def adminservice_collection_variables(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_CollectionVariable entry. Phase 4 emits
    SCCM_HasCollectionVar edges and SCCM_Secret nodes for ``IsMasked=True``
    rows."""
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_collection_variables") == "done":
            continue
        for row in payload.get("collection_variables", []):
            yield {**row, "domain": domain}
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_collection_variables")


@app.resource(name="adminservice_r_system_security_groups", parallelized=False, columns=raw_table_asset("adminservice_r_system_security_groups"))
@with_log_context(phase="AdminService")
def adminservice_r_system_security_groups(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (computer_name, security_group_name) pair from SMS_R_System.

    Lookup table only — Phase 6 SQL view ``r_system_member_of_edges``
    consumes this to emit Computer -> Group MemberOf edges that LDAP-side
    enumeration may have missed (e.g. members enumerated via WMI but not
    present in the LDAP ``member`` multi-valued attribute).
    """
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_r_system_security_groups") == "done":
            continue
        for row in payload.get("r_system_security_groups", []):
            yield {**row, "domain": domain}
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_r_system_security_groups")


@app.resource(name="adminservice_r_user_security_groups", parallelized=False, columns=raw_table_asset("adminservice_r_user_security_groups"))
@with_log_context(phase="AdminService")
def adminservice_r_user_security_groups(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (user_sid, security_group_name) pair from SMS_R_User.

    Lookup table only — Phase 6 SQL view ``r_user_member_of_edges``
    consumes this to emit User -> Group MemberOf edges that LDAP-side
    group enumeration didn't surface (e.g. nested-group memberships via
    SCCM's user-collection sync, or foreign-domain users discovered by
    SMS_R_User but not the LDAP ``member`` walk).
    """
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_r_user_security_groups") == "done":
            continue
        for row in payload.get("r_user_security_groups", []):
            yield {**row, "domain": domain}
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_r_user_security_groups")


@app.resource(name="adminservice_site_systems", parallelized=False, columns=raw_table_asset("adminservice_site_systems"))
@with_log_context(phase="AdminService")
def adminservice_site_systems(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (hostname, role, site_code) tuple from SMS_SCI_SysResUse.
    Phase 4's ``LocalAdminRequired`` SQL view consumes this so that
    co-located site systems get the correct admin-required edges from the
    primary site server."""
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_site_systems") == "done":
            continue
        for row in payload.get("site_systems", []):
            yield {**row, "domain": domain}
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_site_systems")


@app.resource(name="adminservice_sites", parallelized=False, columns=raw_table_asset("adminservice_sites"))
@with_log_context(phase="AdminService")
def adminservice_sites(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per ``SMS_Site`` entry from the AdminService payload.

    Materialised so ``transforms.py`` can compute multi-source provenance
    for edges and nodes that PS1 tags with ``AdminService-SMS_Sites``. The
    ``ldap_sites`` fold-in reads the same payload at collect time for site
    enrichment; this resource exposes it for SQL joins at convert time.
    Fields are normalised to snake_case so the SQL is portable across
    different SMS_Site shapes.
    """
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_sites") == "done":
            continue
        for row in payload.get("sites", []):
            site_code = (row.get("SiteCode") or "").strip()
            if not site_code:
                continue
            server = (row.get("SiteServerName") or row.get("ServerName") or "").strip()
            yield {
                "site_code": site_code,
                "site_name": row.get("SiteName") or "",
                "server_name": server.lower() if server else "",
                "version": str(row.get("Version") or "") or None,
                "site_type": row.get("Type"),
                "reporting_site_code": (row.get("ReportingSiteCode") or "").strip() or None,
                "install_dir": (row.get("InstallDir") or "").strip() or None,
                "domain": domain,
            }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_sites")


@app.resource(name="adminservice_site_definitions", parallelized=False, columns=raw_table_asset("adminservice_site_definitions"))
@with_log_context(phase="AdminService")
def adminservice_site_definitions(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per ``SMS_SCI_SiteDefinition`` entry from the AdminService payload.

    Materialised so ``transforms.py`` can compute multi-source provenance for
    MSSQL_Server and SCCM_Site nodes — PS1 attaches ``AdminService-SMS_SCI_SiteDefinition``
    to every edge whose underlying host appears in this set.
    """
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_site_definitions") == "done":
            continue
        for row in payload.get("site_definitions", []):
            site_code = (row.get("SiteCode") or "").strip()
            if not site_code:
                continue
            sql_server = (row.get("SQLServerName") or "").strip()
            yield {
                "site_code": site_code,
                "site_name": row.get("SiteName") or "",
                "sql_server_name": sql_server.lower() if sql_server else "",
                "sql_database_name": (row.get("SQLDatabaseName") or "").strip() or None,
                "reporting_site_code": (row.get("ReportingSiteCode") or "").strip() or None,
                "domain": domain,
            }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_site_definitions")


@app.resource(name="adminservice_reserved_accounts", parallelized=False, columns=raw_table_asset("adminservice_reserved_accounts"))
@with_log_context(phase="AdminService")
def adminservice_reserved_accounts(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_SCI_Reserved entry that carries a ``UserName``.

    SMS_SCI_Reserved is the SCCM site-control-image table holding stored
    account credentials (Network Access Accounts, push install accounts,
    content access accounts, etc.). CMBP emits a ``SCCM_HasStoredAccount``
    edge from the ``SCCM_Site`` to each resolved User, plus a
    ``storedInSCCMSite`` property on the User node. We materialise
    one row per (site_code, account_username) here and the SQL view
    ``has_stored_account_edges`` joins against ``ldap_users`` to resolve
    the SID at preproc time.
    """
    domain = ctx.domain
    for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
        if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "adminservice_reserved_accounts") == "done":
            continue
        for row in payload.get("reserved_accounts", []):
            yield {**row, "domain": domain}
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(_host, "adminservice_reserved_accounts")


# ---------------------------------------------------------------------------
# Phase 7 fold-in into the LDAP-owned ``ldap_sites`` table.
# ---------------------------------------------------------------------------
# Some SCCM hierarchies (Secondary sites in particular) appear in the SMS
# Provider's SMS_Site / SMS_SCI_SiteDefinition tables without ever showing
# up in the System Management container's mSSMSSite / mSSMSManagementPoint
# objects (low-privileged collectors can't enumerate the container even when
# the site itself is reachable). CMBP/PS1 still emit a SCCM_Site node for
# those — we used to do it via an in-line fold-in inside ``ldap_sites`` at
# Phase 1, but that triggered Phase 7 HTTP work during Phase 1 and broke the
# documented phase order. Now the fold-in lives here, in Phase 7, and writes
# back into the same ``ldap_sites`` DLT table (``table_name="ldap_sites"``)
# so the ``SCCMSite`` asset binding picks the rows up alongside the LDAP
# rows. Dedup happens against ``ctx._emitted_site_codes``, which
# ``ldap_sites`` populated during Phase 1.

@app.resource(name="ldap_sites_admin_extra", parallelized=False, table_name="ldap_sites", columns=raw_table_asset("ldap_sites_admin_extra"))
@with_log_context(phase="AdminService")
def ldap_sites_admin_extra(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Emit SCCM_Site rows for sites surfaced only via AdminService.

    Writes into the ``ldap_sites`` DLT table so the ``SCCMSite`` asset
    binding consumes these alongside the Phase 1 rows. The site's
    AdminService-derived enrichment fields (display name, site server,
    SQL host/db, version, type, parent) are not baked in here — they're
    resolved at convert time via the ``*_for_site`` lookup methods on
    ``SCCMLookup``, which read the dedicated ``adminservice_sites`` /
    ``adminservice_site_definitions`` / ``adminservice_site_systems``
    tables.
    """
    if ctx._emitted_site_codes is None:
        ctx._emitted_site_codes = set()
    seen_codes = ctx._emitted_site_codes
    extra_count = 0
    try:
        for _host, payload in per_pair_iter(ctx.adminservice_payloads().items()):
            if ctx.target_queue is not None and ctx.target_queue.get_status(_host, "ldap_sites_admin_extra") == "done":
                continue
            # SMS_Site rows
            for entry in payload.get("sites", []) or []:
                site_code = (entry.get("SiteCode") or "").strip()
                if not site_code or site_code.upper() in seen_codes:
                    continue
                seen_codes.add(site_code.upper())
                extra_count += 1
                logger.info("Found AdminService-only SCCM site: %s", site_code)
                yield {
                    "site_code": site_code,
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
                    "collection_source": ["AdminService-SMS_Sites"],
                }
            # SMS_SCI_SiteDefinition rows (covers sites that appear only in
            # the site-definition table — primarily Secondary sites visible
            # to the SMS Provider but not in SMS_Site for the calling user).
            for entry in payload.get("site_definitions", []) or []:
                site_code = (entry.get("SiteCode") or "").strip()
                if not site_code or site_code.upper() in seen_codes:
                    continue
                seen_codes.add(site_code.upper())
                extra_count += 1
                logger.info("Found AdminService-only SCCM site (SiteDefinition): %s", site_code)
                yield {
                    "site_code": site_code,
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
                    "collection_source": ["AdminService-SMS_SCI_SiteDefinition"],
                }
            if ctx.target_queue is not None:
                ctx.target_queue.mark_done(_host, "ldap_sites_admin_extra")
    except Exception as e:  # noqa: BLE001
        logger.warning("ldap_sites_admin_extra failed: %s", e)
    if extra_count:
        logger.info("Emitted %d AdminService-only site(s)", extra_count)


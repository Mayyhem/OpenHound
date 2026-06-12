"""AdminService collect-only per-host collector.

Ports ConfigManBearPig.ps1's Invoke-AdminServiceCollection: queries the SCCM
AdminService REST API over Negotiate (the shared HttpClient) and yields raw
JSONL rows. No AD resolution or graph building — that is a deferred convert
stage. Collection order matches the PS1 exactly.
"""
import json
import logging
from typing import Any, Iterable, Iterator, Optional

from ..clients.http import ErrorClass, HttpClient
from ..clients.http_auth import AuthMode
from ..context import SourceContext
from ..log_context import with_log_context
from .sms_rows import (
    _prop,
    _row,
    odata_select,
    ADMIN_COLUMNS,
    COLLECTION_COLUMNS,
    COLLECTION_MEMBER_COLUMNS,
    DEVICE_COLUMNS,
    ROLE_COLUMNS,
    RSYSTEM_COLUMNS,
    RUSER_COLUMNS,
    SITE_COLUMNS,
    SITEDEF_COLUMNS,
    SYSRES_COLUMNS,
)

logger = logging.getLogger(__name__)

_BATCH = 1000


def _get_value(client, path: str) -> Optional[list]:
    """GET an AdminService path; return its JSON ``value`` list, or None on failure."""
    result = client.get(path)
    if result.error_class is ErrorClass.CONNECT_FAILURE:
        logger.verbose("AdminService GET %s failed to connect: %s", path, result.error_message)
        return None
    if result.error_class is not ErrorClass.RESPONSE:
        logger.warning("AdminService GET %s failed: %s", path, result.error_class.value)
        return None
    if result.status_code != 200:
        logger.warning("AdminService GET %s returned HTTP %s", path, result.status_code)
        return None
    try:
        data = json.loads(result.content or b"")
    except Exception as ex:  # noqa: BLE001 - malformed body
        logger.warning("AdminService GET %s returned invalid JSON: %s", path, ex)
        return None
    value = data.get("value")
    if value is None:
        logger.warning("AdminService GET %s response had no 'value' array", path)
        return None
    return value


def _paginate(client, path: str) -> Iterator[dict]:
    """Yield rows across ``$top``/``$skip`` pages until a short (final) page."""
    skip = 0
    while True:
        sep = "&" if "?" in path else "?"
        value = _get_value(client, f"{path}{sep}$top={_BATCH}&$skip={skip}")
        if not value:
            return
        for row in value:
            yield row
        if len(value) < _BATCH:
            return
        skip += _BATCH


def _identification(client) -> Optional[str]:
    """Gate: this SMS provider's site code, or None if not a reachable provider."""
    path = "AdminService/wmi/SMS_Identification?$select=ThisSiteCode,ThisSiteName"
    logger.verbose("Collecting this SMS Provider's site from %s", path)
    value = _get_value(client, path)
    if not value:
        # Issues logged by _get_value
        return None
    # Always the first item
    site_code = value[0].get("ThisSiteCode")
    if not site_code:
        logger.warning("No site identification returned from query")
        return None
    logger.info("Identified this SMS Provider's site: %s (%s)", site_code, value[0].get("ThisSiteName"))
    return site_code


# --- collection helpers (PS1 order) ---------------------------------------

def _sites(client, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_Site"
    query = f"?{odata_select(SITE_COLUMNS)}"
    logger.verbose("Collecting all sites from %s", path)
    value = _get_value(client, path + query)
    if value is None:
        # Issues logged by _get_value
        return
    logger.info("Collected %d sites", len(value))
    for site in value:
        yield "adminservice_sites", _row("AdminService-SMS_Site", site_code, site)
        target_site_code = site.get("SiteCode")
        if target_site_code:
            logger.verbose("  %s", target_site_code)
            logger.debug("    %s", site)
            yield from _site_definition(client, target_site_code, ctx)
        else:
            logger.warning("Site record missing SiteCode: %s", site)


def _site_definition(client, target_site: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_SCI_SiteDefinition"
    query = f"?$filter=SiteCode eq '{target_site}'&{odata_select(SITEDEF_COLUMNS)}"
    logger.verbose("Collecting site definition for site %s from %s", target_site, path)
    value = _get_value(client, path + query)
    if not value:
        # Issues logged by _get_value
        return
    for sdef in value:
        props = sdef.get("Props")
        logger.debug("Site definition for site %s: %s", target_site, sdef)

        site_server_name = sdef.get("SiteServerName")
        sql_server_fqdn = _prop(props, "SQLServerFQDN", "Value1")
        sql_service_port = _prop(props, "SQLServicePort", "Value")
    
        yield "adminservice_site_definitions", _row(
            "AdminService-SMS_SCI_SiteDefinition", target_site, sdef, drop={"Props"},
            extra={
                "site_guid": _prop(props, "siteGUID", "Value1"),
                "sql_server_fqdn": sql_server_fqdn,
                "sql_service_port": sql_service_port,
            },
        )

        # Create a computer row for the site server, with a role of "SMS Site Server"
        if site_server_name:
            logger.verbose("Found site server for site %s: %s", target_site, site_server_name)
            
            # Don't add targets during privileged collection, we don't need them
            site_server_ad_object = ctx.resolve_principal(site_server_name)
            if site_server_ad_object:
                row = {
                    **(site_server_ad_object or {}),
                    "source": "AdminService-SiteDefinition",
                    "sccm_infra": True,
                    "sccm_site_system_roles": "SMS Site Server@" + target_site if target_site else "SMS Site Server",
                }
                row.setdefault("name", site_server_name)
                yield "adminservice_site_definitions_computers", row
            else:
                logger.warning("Failed to resolve site server %s to AD object", site_server_name)

        # Create a computer row for the site database server, with a role of "SMS SQL Server"
        if sql_server_fqdn:
            logger.verbose("Found SQL server for site %s: %s", target_site, sql_server_fqdn)

            # Don't add targets during privileged collection, we don't need them
            sql_server_ad_object = ctx.resolve_principal(sql_server_fqdn)
            if sql_server_ad_object:
                row = {
                    **(sql_server_ad_object or {}),
                    "source": "AdminService-SiteDefinition",
                    "sccm_infra": True,
                    "sccm_site_system_roles": "SMS SQL Server@" + target_site if target_site else "SMS SQL Server",
                }
                row.setdefault("name", sql_server_fqdn)
                yield "adminservice_site_definitions_computers", row
            else:
                logger.warning("Failed to resolve SQL server %s to AD object", sql_server_fqdn)


def _reserved_accounts(client, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_SCI_Reserved"
    logger.verbose("Collecting stored accounts from %s", path)
    value = _get_value(client, path)
    if value is None:
        # Issues logged by _get_value
        return
    logger.info("Collected %d stored accounts", len(value))

    for account in value:
        logger.verbose("  %s (site: %s)", account.get("UserName"), account.get("SiteCode"))
        logger.debug("    %s", account)
        account_ad_object = ctx.resolve_principal(account.get("UserName"))
        if account_ad_object:
            row = {
                **(account_ad_object or {}),
                "source": "AdminService-SMS_SCI_Reserved",
                "sccm_infra": True,
                **account,
            }
            row.setdefault("name", account.get("UserName"))
            yield "adminservice_reserved_accounts", row
        else:
            logger.warning("Failed to resolve stored account %s to AD object", account.get("UserName"))


def _client_devices(client, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_CombinedDeviceResources"
    query = f"?{odata_select(DEVICE_COLUMNS)}"
    logger.verbose("Collecting client devices from %s", path)
    count = 0
    for device in _paginate(client, path + query):
        # Skip non-clients and obsolete records (stale reinstalls).
        if device.get("IsClient") is False or device.get("IsObsolete") is True:
            logger.debug("Skipping device %s (IsClient=%s, IsObsolete=%s)", device.get("DistinguishedName") or device.get("Name"),
                         device.get("IsClient"), device.get("IsObsolete"))
            continue
        logger.debug("Found client device: %s", device)
        # Resolving these would take too long, so we'll just add Computer nodes with the SID from the corresponding row in the adminservice_r_system table during the convert stage
        count += 1
        yield "adminservice_client_devices", _row(
            "AdminService-SMS_CombinedDeviceResources", site_code, device)
    logger.info("Collected %d client devices", count)


def _r_system(client, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_R_System"
    query = f"?{odata_select(RSYSTEM_COLUMNS)}"
    logger.verbose("Collecting systems and groups from %s", path)
    count = 0
    for system in _paginate(client, path + query):
        logger.debug("Found system: %s", system)
        # Resolving these would take too long, so we'll just add Computer nodes with the SID from this table during the convert stage
        count += 1
        yield "adminservice_r_system", _row(
            "AdminService-SMS_R_System", site_code, system)
    logger.info("Collected %d system and security group records", count)


def _r_user(client, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_R_User"
    query = f"?{odata_select(RUSER_COLUMNS)}"
    logger.verbose("Collecting users and groups from %s", path)
    count = 0
    for user in _paginate(client, path + query):
        logger.debug("Found user: %s", user)
        # Resolving these would take too long, so we'll just add User nodes with the SID from this table during the convert stage
        count += 1
        yield "adminservice_r_user", _row(
            "AdminService-SMS_R_User", site_code, user)
    logger.info("Collected %d user and security group records", count)


def _collections(client, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_Collection"
    query = f"?{odata_select(COLLECTION_COLUMNS)}"
    logger.verbose("Collecting device and user collections from %s", path)
    count = 0
    for collection in _paginate(client, path + query):
        # Put name in parentheses if present
        logger.debug("Found collection: %s", collection)
        count += 1
        yield "adminservice_collections", _row("AdminService-SMS_Collection", site_code, collection)
    logger.info("Collected %d device and user collections", count)


def _collection_members(client, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_FullCollectionMembership"
    query = f"?{odata_select(COLLECTION_MEMBER_COLUMNS)}"
    logger.verbose("Collecting collection memberships from %s", path)
    count = 0
    for member in _paginate(client, path + query):
        logger.debug("Found collection membership: %s", member)
        count += 1
        yield "adminservice_collection_members", _row(
            "AdminService-SMS_FullCollectionMembership", site_code, member)
    logger.info("Collected %d collection memberships", count)


def _security_roles(client, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_Role"
    logger.verbose("Collecting security roles from %s", path)
    count = 0
    for role in _paginate(client, path):
        # Only include _KEEP fields in debug logs
        logger.debug("Found security role: %s", {k: v for k, v in role.items() if k in ROLE_COLUMNS or k.startswith("@")})
        count += 1
        yield "adminservice_security_roles", _row(
            "AdminService-SMS_Role", site_code, role, keep=ROLE_COLUMNS)
    logger.info("Collected %d security roles", count)


def _admins(client, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_Admin"
    logger.verbose("Collecting admin users and groups from %s", path)
    count = 0
    for admin in _paginate(client, path):
        # Only include _KEEP fields in debug logs
        logger.debug("Found admin user/group: %s", {k: v for k, v in admin.items() if k in ADMIN_COLUMNS or k.startswith("@")})
        count += 1
        yield "adminservice_admins", _row(
            "AdminService-SMS_Admin", site_code, admin, keep=ADMIN_COLUMNS)
    logger.info("Collected %d admin users and groups", count)


def _site_systems(client, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_SCI_SysResUse"
    logger.verbose("Collecting site system roles from %s", path)
    count = 0
    for system in _paginate(client, path):
        props = system.get("Props")
        # Only include _KEEP fields in debug logs to avoid logging encrypted cert fields
        logger.debug("Found site system role: %s", {k: v for k, v in system.items() if k in SYSRES_COLUMNS or k.startswith("@")})
        count += 1
        yield "adminservice_site_systems", _row(
            "AdminService-SMS_SCI_SysResUse", site_code, system, keep=SYSRES_COLUMNS,
            extra={"sql_server_service_logon_account":
                   _prop(props, "SQL Server Service Logon Account", "Value2")},
        )
    logger.info("Collected %d site system roles", count)


# --- orchestrator ----------------------------------------------------------

_COLLECTIONS = (
    _sites,
    _reserved_accounts,
    _client_devices,
    _r_system,
    _r_user,
    _collections,
    _collection_members,
    _security_roles,
    _admins,
    _site_systems,
)


@with_log_context(phase="AdminService")
def collect_adminservice(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield raw AdminService rows for one target, or nothing if it isn't a
    reachable SMS provider (the SMS_Identification gate fails)."""
    if not ctx.method_enabled("AdminService"):
        return

    logger.info("Starting AdminService collection on %s...", target)
    client = HttpClient.from_context(ctx, target , auth=AuthMode.NEGOTIATE)
    try:
        site_code = _identification(client)
        if site_code is None:
            logger.info("%s is not a reachable AdminService provider; skipping", target)
            return
        # Reached the SMS Provider: mark this host collected via AdminService so the
        # WMI fallback phase (should_run_phase) skips it. Mirrors PS1 setting
        # CollectionTargets[$target]["Collected"]/["Method"] after identification.
        entry = ctx.target_hosts_by_hostname.get(target.lower())
        if entry is not None:
            entry.completed_phases.add("AdminService")
            logger.verbose("Marked AdminService complete on %s (site %s)", target, site_code)
        else:
            logger.debug("No TargetEntry for %s; WMI-fallback gating unavailable", target)
        for collection in _COLLECTIONS:
            try:
                yield from collection(client, site_code, ctx)
            except Exception as ex:  # noqa: BLE001 - one collection failing must not abort the rest
                logger.warning("AdminService %s failed on %s: %s", collection.__name__, target, ex)
        logger.info("AdminService collection completed for %s (site %s)", target, site_code)
    except Exception as ex:  # noqa: BLE001 - never crash the per-host worker
        logger.error("AdminService collection failed for %s: %s", target, ex)
    finally:
        client.close()

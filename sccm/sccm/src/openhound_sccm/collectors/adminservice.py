"""AdminService collect-only per-host collector.

Ports ConfigManBearPig.ps1's Invoke-AdminServiceCollection: queries the SCCM
AdminService REST API over Negotiate (the shared HttpClient) and yields raw
JSONL rows. No AD resolution or graph building — that is a deferred convert
stage. Collection order matches the PS1 exactly; the two collections the PS1
does not gather (collection variables, task sequences) are appended last.
"""
import json
import logging
import re
from typing import Any, Iterable, Iterator, Optional

from ..clients.http import ErrorClass, HttpClient
from ..clients.http_auth import AuthMode
from ..context import SourceContext
from ..log_context import with_log_context

logger = logging.getLogger(__name__)

_BATCH = 1000

# Acronym-aware camelCase/PascalCase -> snake_case (AADDeviceID -> aad_device_id).
_SNAKE_1 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_SNAKE_2 = re.compile(r"([a-z0-9])([A-Z])")


def _snake(name: str) -> str:
    return _SNAKE_2.sub(r"\1_\2", _SNAKE_1.sub(r"\1_\2", name)).lower()


def _get_value(client, path: str) -> Optional[list]:
    """GET an AdminService path; return its JSON ``value`` list, or None on failure."""
    result = client.get(path)
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


def _prop(props: Optional[list], name: str, field: str = "Value1") -> Any:
    """Return one SMS Props value (by PropertyName), or None."""
    for p in props or []:
        if p.get("PropertyName") == name:
            return p.get(field)
    return None


def _row(source: str, site_code: Optional[str], obj: dict, *,
         keep: Optional[set] = None, drop: Optional[set] = None,
         extra: Optional[dict] = None) -> dict:
    """Build a raw row: snake-cased API fields + source + source_site_code.

    ``keep`` (original field names) whitelists columns for no-$select endpoints;
    ``drop`` excludes flattened blobs (e.g. Props); ``extra`` adds derived values.
    OData metadata keys (``@...``) are always dropped.
    """
    row: dict[str, Any] = {"source": source, "source_site_code": site_code}
    drop = drop or set()
    for k, v in obj.items():
        if k.startswith("@") or k in drop:
            continue
        if keep is not None and k not in keep:
            continue
        row[_snake(k)] = v
    if extra:
        row.update(extra)
    return row


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


# --- $select / keep column sets -------------------------------------------

_SITE_SELECT = ("$select=BuildNumber,InstallDir,ReportingSiteCode,ServerName,"
                "SiteCode,SiteName,Status,Type,Version")
_SITEDEF_SELECT = ("$select=ParentSiteCode,SiteCode,SiteName,SiteServerDomain,"
                   "SiteServerName,SiteType,SQLDatabaseName,SQLServerName,Props")
_DEVICE_SELECT = ("$select=AADDeviceID,AADTenantID,ADLastLogonTime,CNAccessMP,CNLastOfflineTime,"
                  "CNLastOnlineTime,CoManaged,CurrentLogonUser,DeviceOS,DeviceOSBuild,IsClient,"
                  "IsObsolete,IsVirtualMachine,LastActiveTime,LastMPServerName,Name,PrimaryUser,"
                  "ResourceID,SiteCode,SMSID,UserName,UserDomainName")
_RSYSTEM_SELECT = "$select=Client,Name,Obsolete,ResourceID,SID,SMSUniqueIdentifier,SecurityGroupName,SystemRoles"
_RUSER_SELECT = ("$select=AADTenantID,AADUserID,DistinguishedName,FullDomainName,FullUserName,Name,"
                 "ResourceID,SecurityGroupName,SID,UniqueUserName,UserName,UserPrincipalName")
_COLLECTION_SELECT = ("$select=CollectionID,CollectionType,CollectionVariablesCount,Comment,"
                      "IsBuiltIn,LastChangeTime,LastMemberChangeTime,LimitToCollectionID,"
                      "LimitToCollectionName,MemberCount,Name")
# SMS_Role / SMS_Admin / SMS_SCI_SysResUse reject $select on lazy
# columns, so fetch all columns and whitelist the ones we want.
_ROLE_KEEP = {"CopiedFromID", "CreatedBy", "CreatedDate", "IsBuiltIn", "IsSecAdminRole",
              "LastModifiedBy", "LastModifiedDate", "NumberOfAdmins", "Operations", "RoleID",
              "RoleName", "RoleDescription", "SourceSite"}
_ADMIN_KEEP = {"AccountType", "AdminID", "AdminSid", "CategoryNames", "CollectionNames", "CreatedBy",
               "CreatedDate", "DisplayName", "DistinguishedName", "IsGroup", "LastModifiedBy",
               "LastModifiedDate", "LogonName", "RoleNames", "Roles", "SourceSite"}
_SYSRES_KEEP = {"NetworkOSPath", "SiteCode", "RoleName", "Type"}


# --- collection helpers (PS1 order) ---------------------------------------

def _sites(client, site_code: str) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_Site"
    query = f"?{_SITE_SELECT}"
    logger.verbose("Collecting all sites from %s", path)
    value = _get_value(client, path + query)
    if value is None:
        # Issues logged by _get_value
        return
    logger.info("Collected %d sites", len(value))
    for site in value:
        yield "adminservice_sites", _row("AdminService-SMS_Site", site_code, site)
        sc = site.get("SiteCode")
        if sc:
            logger.verbose("  %s", sc)
            logger.debug("    %s", site)
            yield from _site_definition(client, site_code, sc)
        else:
            logger.warning("Site record missing SiteCode: %s", site)


def _site_definition(client, site_code: str, target_site: str) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_SCI_SiteDefinition"
    query = f"?$filter=SiteCode eq '{target_site}'&{_SITEDEF_SELECT}"
    logger.verbose("Collecting site definition for site %s from %s", target_site, path)
    value = _get_value(client, path + query)
    if not value:
        # Issues logged by _get_value
        return
    for sdef in value:
        props = sdef.get("Props")
        logger.debug("Site definition for site %s: %s", target_site, sdef)
        yield "adminservice_site_definitions", _row(
            "AdminService-SMS_SCI_SiteDefinition", site_code, sdef, drop={"Props"},
            extra={
                "site_guid": _prop(props, "siteGUID", "Value1"),
                "sql_server_fqdn": _prop(props, "SQLServerFQDN", "Value1"),
                "sql_service_port": _prop(props, "SQLServicePort", "Value"),
            },
        )


def _reserved_accounts(client, site_code: str) -> Iterator[tuple[str, dict]]:
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
        yield "adminservice_reserved_accounts", _row("AdminService-SMS_SCI_Reserved", site_code, account)


def _client_devices(client, site_code: str) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_CombinedDeviceResources"
    query = f"?{_DEVICE_SELECT}"
    logger.verbose("Collecting client devices from %s", path)
    count = 0
    for device in _paginate(client, path + query):
        # Skip non-clients and obsolete records (stale reinstalls).
        if device.get("IsClient") is False or device.get("IsObsolete") is True:
            logger.debug("Skipping device %s (IsClient=%s, IsObsolete=%s)", device.get("DistinguishedName") or device.get("Name"),
                         device.get("IsClient"), device.get("IsObsolete"))
            continue
        logger.debug("Found client device: %s", device)
        count += 1
        yield "adminservice_client_devices", _row(
            "AdminService-SMS_CombinedDeviceResources", site_code, device)
    logger.info("Collected %d client devices", count)


def _r_system(client, site_code: str) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_R_System"
    query = f"?{_RSYSTEM_SELECT}"
    logger.verbose("Collecting systems and groups from %s", path)
    count = 0
    for system in _paginate(client, path + query):
        logger.debug("Found system: %s", system)
        count += 1
        yield "adminservice_r_system", _row(
            "AdminService-SMS_R_System", site_code, system)
    logger.info("Collected %d system and security group records", count)


def _r_user(client, site_code: str) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_R_User"
    query = f"?{_RUSER_SELECT}"
    logger.verbose("Collecting users and groups from %s", path)
    count = 0
    for user in _paginate(client, path + query):
        logger.debug("Found user: %s", user)
        count += 1
        yield "adminservice_r_user", _row(
            "AdminService-SMS_R_User", site_code, user)
    logger.info("Collected %d user and security group records", count)


def _collections(client, site_code: str) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_Collection"
    query = f"?{_COLLECTION_SELECT}"
    logger.verbose("Collecting device and user collections from %s", path)
    count = 0
    for collection in _paginate(client, path + query):
        # Put name in parentheses if present
        logger.debug("Found collection: %s", collection)
        count += 1
        yield "adminservice_collections", _row("AdminService-SMS_Collection", site_code, collection)
    logger.info("Collected %d device and user collections", count)


def _collection_members(client, site_code: str) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_FullCollectionMembership"
    query = "?$select=CollectionID,ResourceID,SiteCode"
    logger.verbose("Collecting collection memberships from %s", path)
    count = 0
    for member in _paginate(client, path + query):
        logger.debug("Found collection membership: %s", member)
        count += 1
        yield "adminservice_collection_members", _row(
            "AdminService-SMS_FullCollectionMembership", site_code, member)
    logger.info("Collected %d collection memberships", count)


def _security_roles(client, site_code: str) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_Role"
    logger.verbose("Collecting security roles from %s", path)
    count = 0
    for role in _paginate(client, path):
        # Only include _KEEP fields in debug logs
        logger.debug("Found security role: %s", {k: v for k, v in role.items() if k in _ROLE_KEEP or k.startswith("@")})
        count += 1
        yield "adminservice_security_roles", _row(
            "AdminService-SMS_Role", site_code, role, keep=_ROLE_KEEP)
    logger.info("Collected %d security roles", count)


def _admins(client, site_code: str) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_Admin"
    logger.verbose("Collecting admin users and groups from %s", path)
    count = 0
    for admin in _paginate(client, path):
        # Only include _KEEP fields in debug logs
        logger.debug("Found admin user/group: %s", {k: v for k, v in admin.items() if k in _ADMIN_KEEP or k.startswith("@")})
        count += 1
        yield "adminservice_admins", _row(
            "AdminService-SMS_Admin", site_code, admin, keep=_ADMIN_KEEP)
    logger.info("Collected %d admin users and groups", count)


def _site_systems(client, site_code: str) -> Iterator[tuple[str, dict]]:
    path = "/AdminService/wmi/SMS_SCI_SysResUse"
    logger.verbose("Collecting site system roles from %s", path)
    count = 0
    for system in _paginate(client, path):
        props = system.get("Props")
        # Only include _KEEP fields in debug logs to avoid logging encrypted cert fields
        logger.debug("Found site system role: %s", {k: v for k, v in system.items() if k in _SYSRES_KEEP or k.startswith("@")})
        count += 1
        yield "adminservice_site_systems", _row(
            "AdminService-SMS_SCI_SysResUse", site_code, system, keep=_SYSRES_KEEP,
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
        for collection in _COLLECTIONS:
            try:
                yield from collection(client, site_code)
            except Exception as ex:  # noqa: BLE001 - one collection failing must not abort the rest
                logger.warning("AdminService %s failed on %s: %s", collection.__name__, target, ex)
        logger.info("AdminService collection completed for %s (site %s)", target, site_code)
    except Exception as ex:  # noqa: BLE001 - never crash the per-host worker
        logger.error("AdminService collection failed for %s: %s", target, ex)
    finally:
        client.close()

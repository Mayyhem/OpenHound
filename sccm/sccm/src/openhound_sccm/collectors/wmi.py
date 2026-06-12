"""WMI collect-only per-host collector: the AdminService fallback.

Mirrors ``collectors/adminservice.py`` one-to-one — the same ten collections in
the same order — but reads the SMS Provider's ``root\\SMS\\site_<code>`` WMI
namespace over DCOM/WMI (``clients/wmi.WmiClient``) instead of the AdminService
REST API. It runs only when AdminService could not be reached on the host; the engine's
``per_host_phases.should_run_phase`` enforces that via ``TargetEntry.completed_phases``.

Row shaping is identical to AdminService: the shared ``sms_rows`` atoms snake-case
and whitelist the same columns, so ``wmi_*`` rows line up with their
``adminservice_*`` counterparts. The only difference is transport and the
``WMI-*`` source labels / ``wmi_*`` table names.
"""
import logging
from typing import Any, Iterable, Iterator

from ..clients.wmi import WmiClient
from ..context import SourceContext
from ..log_context import with_log_context
from .sms_rows import (
    _prop,
    _row,
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


# --- collection helpers (PS1 / AdminService order) ------------------------

def _sites(client: WmiClient, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting all sites via WMI (SMS_Site)")
    rows = client.query("SMS_Site", columns=SITE_COLUMNS)
    if rows is None:
        # Issues logged by WmiClient.query
        return
    logger.info("Collected %d sites via WMI", len(rows))
    for site in rows:
        yield "wmi_sites", _row("WMI-SMS_Site", site_code, site)
        target_site_code = site.get("SiteCode")
        if target_site_code:
            logger.verbose("  %s", target_site_code)
            logger.debug("    %s", site)
            yield from _site_definition(client, target_site_code, ctx)
        else:
            logger.warning("Site record missing SiteCode: %s", site)


def _site_definition(client: WmiClient, target_site: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting site definition for site %s via WMI (SMS_SCI_SiteDefinition)", target_site)
    rows = client.query("SMS_SCI_SiteDefinition", columns=SITEDEF_COLUMNS, where=f"SiteCode = '{target_site}'")
    if not rows:
        # Issues logged by WmiClient.query
        return
    for sdef in rows:
        props = sdef.get("Props")
        logger.debug("Site definition for site %s: %s", target_site, sdef)

        site_server_name = sdef.get("SiteServerName")
        sql_server_fqdn = _prop(props, "SQLServerFQDN", "Value1")
        sql_service_port = _prop(props, "SQLServicePort", "Value")

        yield "wmi_site_definitions", _row(
            "WMI-SMS_SCI_SiteDefinition", target_site, sdef, drop={"Props"},
            extra={
                "site_guid": _prop(props, "siteGUID", "Value1"),
                "sql_server_fqdn": sql_server_fqdn,
                "sql_service_port": sql_service_port,
            },
        )

        # Create a computer row for the site server, with a role of "SMS Site Server"
        if site_server_name:
            logger.verbose("Found site server for site %s: %s", target_site, site_server_name)
            site_server_ad_object = ctx.resolve_principal(site_server_name)
            if site_server_ad_object:
                row = {
                    **(site_server_ad_object or {}),
                    "source": "WMI-SiteDefinition",
                    "sccm_infra": True,
                    "sccm_site_system_roles": "SMS Site Server@" + target_site if target_site else "SMS Site Server",
                }
                row.setdefault("name", site_server_name)
                yield "wmi_site_definitions_computers", row
            else:
                logger.warning("Failed to resolve site server %s to AD object", site_server_name)

        # Create a computer row for the site database server, with a role of "SMS SQL Server"
        if sql_server_fqdn:
            logger.verbose("Found SQL server for site %s: %s", target_site, sql_server_fqdn)
            sql_server_ad_object = ctx.resolve_principal(sql_server_fqdn)
            if sql_server_ad_object:
                row = {
                    **(sql_server_ad_object or {}),
                    "source": "WMI-SiteDefinition",
                    "sccm_infra": True,
                    "sccm_site_system_roles": "SMS SQL Server@" + target_site if target_site else "SMS SQL Server",
                }
                row.setdefault("name", sql_server_fqdn)
                yield "wmi_site_definitions_computers", row
            else:
                logger.warning("Failed to resolve SQL server %s to AD object", sql_server_fqdn)


def _reserved_accounts(client: WmiClient, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting stored accounts via WMI (SMS_SCI_Reserved)")
    rows = client.query("SMS_SCI_Reserved")
    if rows is None:
        # Issues logged by WmiClient.query
        return
    logger.info("Collected %d stored accounts via WMI", len(rows))

    for account in rows:
        logger.verbose("  %s (site: %s)", account.get("UserName"), account.get("SiteCode"))
        logger.debug("    %s", account)
        account_ad_object = ctx.resolve_principal(account.get("UserName"))
        if account_ad_object:
            row = {
                **(account_ad_object or {}),
                "source": "WMI-SMS_SCI_Reserved",
                "sccm_infra": True,
                **account,
            }
            row.setdefault("name", account.get("UserName"))
            yield "wmi_reserved_accounts", row
        else:
            logger.warning("Failed to resolve stored account %s to AD object", account.get("UserName"))


def _client_devices(client: WmiClient, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting client devices via WMI (SMS_CombinedDeviceResources)")
    rows = client.query("SMS_CombinedDeviceResources", columns=DEVICE_COLUMNS)
    if rows is None:
        return
    count = 0
    for device in rows:
        # Skip non-clients and obsolete records (stale reinstalls).
        if device.get("IsClient") is False or device.get("IsObsolete") is True:
            logger.debug("Skipping device %s (IsClient=%s, IsObsolete=%s)",
                         device.get("DistinguishedName") or device.get("Name"),
                         device.get("IsClient"), device.get("IsObsolete"))
            continue
        logger.debug("Found client device: %s", device)
        count += 1
        yield "wmi_client_devices", _row("WMI-SMS_CombinedDeviceResources", site_code, device)
    logger.info("Collected %d client devices via WMI", count)


def _r_system(client: WmiClient, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting systems and groups via WMI (SMS_R_System)")
    rows = client.query("SMS_R_System", columns=RSYSTEM_COLUMNS)
    if rows is None:
        return
    count = 0
    for system in rows:
        logger.debug("Found system: %s", system)
        count += 1
        yield "wmi_r_system", _row("WMI-SMS_R_System", site_code, system)
    logger.info("Collected %d system and security group records via WMI", count)


def _r_user(client: WmiClient, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting users and groups via WMI (SMS_R_User)")
    rows = client.query("SMS_R_User", columns=RUSER_COLUMNS)
    if rows is None:
        return
    count = 0
    for user in rows:
        logger.debug("Found user: %s", user)
        count += 1
        yield "wmi_r_user", _row("WMI-SMS_R_User", site_code, user)
    logger.info("Collected %d user and security group records via WMI", count)


def _collections(client: WmiClient, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting device and user collections via WMI (SMS_Collection)")
    rows = client.query("SMS_Collection", columns=COLLECTION_COLUMNS)
    if rows is None:
        return
    count = 0
    for collection in rows:
        logger.debug("Found collection: %s", collection)
        count += 1
        yield "wmi_collections", _row("WMI-SMS_Collection", site_code, collection)
    logger.info("Collected %d device and user collections via WMI", count)


def _collection_members(client: WmiClient, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting collection memberships via WMI (SMS_FullCollectionMembership)")
    rows = client.query("SMS_FullCollectionMembership", columns=COLLECTION_MEMBER_COLUMNS)
    if rows is None:
        return
    count = 0
    for member in rows:
        logger.debug("Found collection membership: %s", member)
        count += 1
        yield "wmi_collection_members", _row("WMI-SMS_FullCollectionMembership", site_code, member)
    logger.info("Collected %d collection memberships via WMI", count)


def _security_roles(client: WmiClient, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting security roles via WMI (SMS_Role)")
    rows = client.query("SMS_Role")
    if rows is None:
        return
    count = 0
    for role in rows:
        # Only include _KEEP fields in debug logs
        logger.debug("Found security role: %s", {k: v for k, v in role.items() if k in ROLE_COLUMNS})
        count += 1
        yield "wmi_security_roles", _row("WMI-SMS_Role", site_code, role, keep=ROLE_COLUMNS)
    logger.info("Collected %d security roles via WMI", count)


def _admins(client: WmiClient, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting admin users and groups via WMI (SMS_Admin)")
    rows = client.query("SMS_Admin")
    if rows is None:
        return
    count = 0
    for admin in rows:
        # Only include _KEEP fields in debug logs
        logger.debug("Found admin user/group: %s", {k: v for k, v in admin.items() if k in ADMIN_COLUMNS})
        count += 1
        yield "wmi_admins", _row("WMI-SMS_Admin", site_code, admin, keep=ADMIN_COLUMNS)
    logger.info("Collected %d admin users and groups via WMI", count)


def _site_systems(client: WmiClient, site_code: str, ctx: SourceContext) -> Iterator[tuple[str, dict]]:
    logger.verbose("Collecting site system roles via WMI (SMS_SCI_SysResUse)")
    rows = client.query("SMS_SCI_SysResUse")
    if rows is None:
        return
    count = 0
    for system in rows:
        props = system.get("Props")
        # Only include _KEEP fields in debug logs to avoid logging encrypted cert fields
        logger.debug("Found site system role: %s", {k: v for k, v in system.items() if k in SYSRES_COLUMNS})
        count += 1
        yield "wmi_site_systems", _row(
            "WMI-SMS_SCI_SysResUse", site_code, system, keep=SYSRES_COLUMNS,
            extra={"sql_server_service_logon_account":
                   _prop(props, "SQL Server Service Logon Account", "Value2")},
        )
    logger.info("Collected %d site system roles via WMI", count)


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


@with_log_context(phase="WMI")
def collect_wmi(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield raw WMI rows for one target, or nothing if it isn't a reachable SMS
    Provider (the SMS_ProviderLocation identification gate fails).

    Runs only when AdminService did not already reach this host — enforced by
    ``per_host_phases.should_run_phase`` reading ``TargetEntry.completed_phases``.
    """
    if not ctx.method_enabled("WMI"):
        return

    logger.info("Starting WMI collection on %s...", target)
    client = WmiClient.from_context(ctx, target)
    try:
        site_code = client.identify()
        if site_code is None:
            logger.info("%s is not a reachable SMS Provider over WMI; skipping", target)
            return
        for collection in _COLLECTIONS:
            try:
                yield from collection(client, site_code, ctx)
            except Exception as ex:  # noqa: BLE001 - one collection failing must not abort the rest
                logger.warning("WMI %s failed on %s: %s", collection.__name__, target, ex)
        # Mark this host collected via WMI (parity with AdminService's marker).
        entry = ctx.target_hosts_by_hostname.get(target.lower())
        if entry is not None:
            entry.completed_phases.add("WMI")
        logger.info("WMI collection completed for %s (site %s)", target, site_code)
    except Exception as ex:  # noqa: BLE001 - never crash the per-host worker
        logger.error("WMI collection failed for %s: %s", target, ex)
    finally:
        client.close()

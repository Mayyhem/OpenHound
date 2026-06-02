"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the derived phase.
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
from ..log_context import per_host_iter, per_pair_iter, with_log_context
from ..models import DerivedEdges, DerivedNode

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase 4 — derived-edges trigger.
# ---------------------------------------------------------------------------
#
# The 11 derived edge SQL views materialised in ``transforms.py`` are read at
# convert time by ``models/derived/aggregator.py::DerivedEdges``. That model
# only fires when its bound DLT resource yields at least one row, so we add a
# tiny trigger resource that emits a single sentinel row at collect time. The
# row's value doesn't matter — the model opens its own DuckDB connection via
# ``self._lookup.client``.
#
# Yielding a single row also keeps ``Converter.run``'s
# ``source_object.resources.values()`` discovery happy: it binds DerivedEdges
# to the ``derived_edges`` table by matching ``columns=DerivedEdges``.

@app.resource(name="derived_edges", parallelized=False, columns=DerivedEdges)
@with_log_context(phase="Derived", target_from_ctx_domain=True)
def derived_edges(_ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One sentinel row to trigger the DerivedEdges aggregator at convert time."""
    yield {"trigger": "derived_edges"}


# ---------------------------------------------------------------------------
# Phase 6 — derived MSSQL principal nodes (synthesised at collect time).
# ---------------------------------------------------------------------------
#
# The Phase 4 ``mssql_sysadmin_edges`` SQL view emits edge endpoints for
# MSSQL_Login / MSSQL_DatabaseUser / MSSQL_DatabaseRole / MSSQL_ServerRole /
# MSSQL_Database principals that don't have their own collected tables. Until
# this resource existed those nodes were stub-on-first-reference inside
# BloodHound — graphically valid but property-poor.
#
# We replicate the same fan-out logic in Python here, using the cached
# ``ctx.adminservice_payloads()`` (site_systems) plus ``ctx.ldap_computer_hosts()``
# (computer SID/SAM) — the same inputs the SQL view consumes. Each yielded row
# carries one synthesised node and is bound to the ``DerivedNode`` model.

_SECONDARY_ROLES = {"sms site server", "sms provider", "sms sql server", "sms management point", "sms distribution point"}


def _classify_site_type(roles: set[str]) -> str:
    """Match the ``sccm.site_types`` view heuristic.

    CAS         = SiteServer + Provider + no MP
    Primary     = SiteServer + Provider + MP
    Secondary   = SiteServer + MP + no Provider
    Other       = anything else
    """
    has_ss = "sms site server" in roles
    has_mp = "sms management point" in roles
    has_prov = "sms provider" in roles
    if has_ss and has_prov and not has_mp:
        return "CAS"
    if has_ss and has_prov and has_mp:
        return "Primary"
    if has_ss and has_mp and not has_prov:
        return "Secondary"
    return "Other"


@app.resource(name="derived_nodes", parallelized=False, columns=DerivedNode)
@with_log_context(phase="Derived", target_from_ctx_domain=True)
def derived_nodes(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per synthesised MSSQL principal node.

    Mirrors the SQL view ``sccm.mssql_sysadmin_edges`` but in Python so the
    rows can be written to JSONL at collect time and consumed by the
    ``DerivedNode`` model at convert time.

    The fan-out for each (sysadmin Computer, site DB Computer) tuple at the
    same site emits five node kinds:

      * MSSQL_Login        ``<DOMAIN>\\<sam>@<dbhost>:1433``
      * MSSQL_DatabaseUser ``<DOMAIN>\\<sam>@<dbhost>:1433\\CM_<site>``
      * MSSQL_Database     ``<dbhost>:1433\\CM_<site>``
      * MSSQL_ServerRole   ``sysadmin@<dbhost>:1433`` (one per server)
      * MSSQL_DatabaseRole ``db_owner@<dbhost>:1433\\CM_<site>`` (one per db)

    Per-server / per-database role nodes are deduped so we emit one
    ``sysadmin@server`` and one ``db_owner@server\\db`` regardless of how
    many sysadmin computers are present.
    """
    payloads = ctx.adminservice_payloads()
    if not payloads:
        return

    # Build site -> set(role) mapping for the site_types classification.
    site_roles: dict[str, set[str]] = {}
    site_systems_rows: list[dict[str, Any]] = []
    for payload in payloads.values():
        for ss in payload.get("site_systems", []):
            site = (ss.get("site_code") or "").strip()
            role = (ss.get("role") or "").strip().lower()
            host = (ss.get("hostname") or "").strip().lower()
            if not site or not role or not host:
                continue
            site_roles.setdefault(site, set()).add(role)
            site_systems_rows.append({"site": site, "role": role, "hostname": host})

    site_types = {site: _classify_site_type(roles) for site, roles in site_roles.items()}

    # Index ldap_computer_hosts by hostname / sam for fast lookup.
    ldap_by_host: dict[str, dict[str, Any]] = {}
    ldap_by_sam: dict[str, dict[str, Any]] = {}
    for h in per_host_iter(ctx.ldap_computer_hosts()):
        host = (h.get("hostname") or "").lower()
        sam = (h.get("sam") or "").rstrip("$").lower()
        if host:
            ldap_by_host[host] = h
        if sam:
            ldap_by_sam[sam] = h

    def _resolve_computer(hostname: str) -> Optional[dict[str, Any]]:
        """Mirror the SQL JOIN on dns_host_name / sam / name."""
        h = (hostname or "").lower()
        if not h:
            return None
        if h in ldap_by_host:
            return ldap_by_host[h]
        short = h.split(".", 1)[0]
        if short in ldap_by_sam:
            return ldap_by_sam[short]
        return None

    # Site DBs (one per site, role = SMS SQL Server)
    site_dbs: dict[str, str] = {}
    for ss in site_systems_rows:
        if ss["role"] == "sms sql server":
            site_dbs.setdefault(ss["site"], ss["hostname"])

    # Sysadmins (Site Server + SMS Provider on non-Secondary sites)
    sysadmins: list[tuple[str, str, dict[str, Any]]] = []  # (site, hostname, ldap_row)
    for ss in site_systems_rows:
        site = ss["site"]
        if site_types.get(site) == "Secondary":
            continue
        if ss["role"] not in ("sms site server", "sms provider"):
            continue
        ldap_row = _resolve_computer(ss["hostname"])
        if not ldap_row or not ldap_row.get("sid"):
            continue
        sysadmins.append((site, ss["hostname"], ldap_row))

    # Track emitted MSSQL nodes so the same (server, site, login) tuple
    # appearing multiple times in the sysadmin fan-out only yields once.
    emitted_servers: set[str] = set()
    emitted_logins: set[str] = set()
    emitted_db_users: set[str] = set()
    emitted_databases: set[str] = set()
    emitted_server_roles: set[str] = set()
    emitted_db_roles: set[str] = set()

    domain_short = (ctx.domain or "").split(".")[0].lower()

    # ---- Per-(server,site) structural fan-out -----------------------------
    # For every primary site (CAS or Primary) that has an 'SMS SQL Server'
    # role row, emit the MSSQL_Database / MSSQL_ServerRole sysadmin /
    # MSSQL_DatabaseRole db_owner nodes that anchor the per-server
    # structural edges built by
    # ``transforms._build_mssql_server_hierarchy_edges``.
    #
    # PS1 (ConfigManBearPig.ps1 line 6330) explicitly skips Secondary sites
    # for this hierarchy emission. CMBP-python's mirror check at
    # mssql_collector.py:373 has a typo that compares against
    # ``"Secondary Site"`` while CMBP's site_type is the integer 1 (the
    # parallel patch in this session fixes both ends of that comparison).
    # PS1 only emits the MSSQL_Database / MSSQL_DatabaseRole hierarchy
    # when the site DB host is backed by a
    # RemoteRegistry-MultisiteComponentServers entry (line 6336-6342 of
    # ConfigManBearPig.ps1). When ``--disable-possible-edges`` is set we
    # mirror that gate, so a low-privilege caller that can't read the
    # site server's registry sees the same shape PS1 and CMBP-python
    # emit (MSSQL_Server is still synthesised so its incoming HostFor /
    # ExecuteOnHost edges have a valid endpoint, but the database
    # hierarchy beneath it is not).
    require_registry_confirmation = bool(ctx.disable_possible_edges)
    confirmed_db_hosts = (
        ctx.registry_confirmed_db_hosts() if require_registry_confirmation else set()
    )

    for site, db_host in site_dbs.items():
        if not db_host:
            continue
        if site_types.get(site) == "Secondary":
            continue
        emit_database_hierarchy = (
            not require_registry_confirmation
            or db_host.lower() in confirmed_db_hosts
        )
        # PS1 builds MSSQL_Server / Database / ServerRole / DatabaseRole
        # IDs around the **computer SID** of the SQL host, not its FQDN.
        # Resolve the SQL host to its AD computer SID; skip if we can't
        # find the AD object (matches PS1's implicit requirement that
        # the SQL host has an AD record).
        db_ldap = _resolve_computer(db_host)
        if not db_ldap or not db_ldap.get("sid"):
            continue
        db_sid = db_ldap["sid"]
        server_id = f"{db_sid}:1433"
        database_id = f"{server_id}\\CM_{site}"
        sysadmin_role_id = f"sysadmin@{server_id}"
        db_owner_role_id = f"db_owner@{database_id}"

        # MSSQL_Server node (one per host:1433). PS1/CMBP both emit these
        # as the anchor for every MSSQL_* edge that points at the SQL
        # instance (HostFor, ExecuteOnHost, Contains->sysadmin, etc.).
        if server_id not in emitted_servers:
            emitted_servers.add(server_id)
            yield {
                "kind": "MSSQL_Server",
                "node_id": server_id,
                "name": server_id,
                "displayname": server_id,
                "server": db_host,
                "site_code": site,
                "domain": ctx.domain,
                "sccm_infra": True,
            }

        if emit_database_hierarchy and database_id not in emitted_databases:
            emitted_databases.add(database_id)
            yield {
                "kind": "MSSQL_Database",
                "node_id": database_id,
                "name": f"CM_{site}",
                "displayname": f"CM_{site}",
                "server": db_host,
                "database": f"CM_{site}",
                "site_code": site,
                "domain": ctx.domain,
                "sccm_infra": True,
            }

        if sysadmin_role_id not in emitted_server_roles:
            emitted_server_roles.add(sysadmin_role_id)
            yield {
                "kind": "MSSQL_ServerRole",
                "node_id": sysadmin_role_id,
                "name": "sysadmin",
                "displayname": "sysadmin",
                "server": db_host,
                "site_code": site,
                "domain": ctx.domain,
                "is_fixed_role": True,
                "sccm_infra": True,
            }

        if emit_database_hierarchy and db_owner_role_id not in emitted_db_roles:
            emitted_db_roles.add(db_owner_role_id)
            yield {
                "kind": "MSSQL_DatabaseRole",
                "node_id": db_owner_role_id,
                "name": "db_owner",
                "displayname": "db_owner",
                "server": db_host,
                "database": f"CM_{site}",
                "site_code": site,
                "domain": ctx.domain,
                "is_fixed_role": True,
                "sccm_infra": True,
            }

    for site, _sa_host, sa in sysadmins:
        db_host = site_dbs.get(site)
        if not db_host or db_host == _sa_host:
            continue
        # PS1 uses the AD-stored ``sAMAccountName`` verbatim for the login
        # name (e.g. ``mayyhem\CAS-PSS$`` — uppercase, trailing ``$``).
        # ``ctx.ldap_computer_hosts()`` strips the ``$`` for downstream
        # lookups; computer-account logins need it back. Use the raw
        # ``name`` (CN) attribute when present — it preserves casing
        # — and add the trailing ``$`` since these are always computer
        # accounts.
        sam = sa.get("sam") or ""
        if not sam:
            continue
        # Prefer the canonical CN casing when available so we get
        # ``CAS-PSS$`` rather than ``cas-pss$``.
        sam_display = sa.get("name") or sam
        login_str = f"{domain_short}\\{sam_display}$"
        db_ldap = _resolve_computer(db_host)
        if not db_ldap or not db_ldap.get("sid"):
            continue
        db_sid = db_ldap["sid"]
        server_id = f"{db_sid}:1433"
        database_id = f"{server_id}\\CM_{site}"
        login_id = f"{login_str}@{server_id}"
        db_user_id = f"{login_str}@{database_id}"
        sysadmin_role_id = f"sysadmin@{server_id}"
        db_owner_role_id = f"db_owner@{database_id}"

        # PS1 ties MSSQL_Database / MSSQL_DatabaseRole emission to a
        # successful RemoteRegistry probe of the site DB host. Mirror
        # that here so the sysadmin fan-out doesn't re-emit them when
        # the per-server loop above (which has the same gate) already
        # decided to skip.
        emit_database_hierarchy = (
            not require_registry_confirmation
            or db_host.lower() in confirmed_db_hosts
        )

        # MSSQL_Login. PS1's ``loginType`` is always ``Windows`` for these
        # synthesised logins because every sysadmin in the fan-out is a
        # Windows-authenticated AD computer account (MAYYHEM\<MACHINE>$).
        if login_id not in emitted_logins:
            emitted_logins.add(login_id)
            yield {
                "kind": "MSSQL_Login",
                "node_id": login_id,
                "name": login_id,
                "displayname": login_str,
                "server": db_host,
                "login": login_str,
                "login_type": "Windows",
                "site_code": site,
                "domain": ctx.domain,
                "sccm_infra": True,
                "member_of_roles": ["sysadmin"],
            }

        # MSSQL_DatabaseUser depends on the MSSQL_Database node. When the
        # registry-confirmation gate hides the database we skip the user
        # too, so CMBP-python (which uses the same gate after the matching
        # fix in post_processing.py) and OpenHound stay in lockstep.
        if emit_database_hierarchy and db_user_id not in emitted_db_users:
            emitted_db_users.add(db_user_id)
            yield {
                "kind": "MSSQL_DatabaseUser",
                "node_id": db_user_id,
                "name": db_user_id,
                "displayname": login_str,
                "server": db_host,
                "database": f"CM_{site}",
                "login": login_str,
                "site_code": site,
                "domain": ctx.domain,
                "sccm_infra": True,
                "member_of_roles": ["db_owner"],
            }

        # MSSQL_Database (one per (server, db))
        if emit_database_hierarchy and database_id not in emitted_databases:
            emitted_databases.add(database_id)
            yield {
                "kind": "MSSQL_Database",
                "node_id": database_id,
                "name": f"CM_{site}",
                "displayname": f"CM_{site}",
                "server": db_host,
                "database": f"CM_{site}",
                "site_code": site,
                "domain": ctx.domain,
                "sccm_infra": True,
            }

        # MSSQL_ServerRole sysadmin (one per server)
        if sysadmin_role_id not in emitted_server_roles:
            emitted_server_roles.add(sysadmin_role_id)
            yield {
                "kind": "MSSQL_ServerRole",
                "node_id": sysadmin_role_id,
                "name": "sysadmin",
                "displayname": "sysadmin",
                "server": db_host,
                "site_code": site,
                "domain": ctx.domain,
                "is_fixed_role": True,
                "sccm_infra": True,
            }

        # MSSQL_DatabaseRole db_owner (one per database)
        if emit_database_hierarchy and db_owner_role_id not in emitted_db_roles:
            emitted_db_roles.add(db_owner_role_id)
            yield {
                "kind": "MSSQL_DatabaseRole",
                "node_id": db_owner_role_id,
                "name": "db_owner",
                "displayname": "db_owner",
                "server": db_host,
                "database": f"CM_{site}",
                "site_code": site,
                "domain": ctx.domain,
                "is_fixed_role": True,
                "sccm_infra": True,
            }


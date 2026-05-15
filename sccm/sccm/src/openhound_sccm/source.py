"""DLT source / resources / transformers for the OpenHound SCCM extension.

Each ``@app.resource`` writes one DLT table (named after the resource) into
``output/sccm/<table>/`` as JSONL during the collect phase. Models read those
tables back in convert.

Phase 1 (LDAP thin slice):
    ldap_sites, ldap_computers, ldap_users, ldap_groups,
    ldap_sms_providers, ldap_group_memberships

Phase 2 (Local / DNS / DHCP once-phases):
    local_management_points, local_distribution_points,
    dns_management_points,
    dhcp_pxe_dps

Per-host transformer chains (RemoteRegistry, MSSQL, AdminService, WMI, HTTP, SMB)
are not yet implemented — they will be added in Phase 3, chained off the parent
resources via DLT's pipe operator.

Credentials are read from ``[sources.sccm]`` in ``.dlt/secrets.toml`` or from
the equivalent ``SOURCES__SCCM__*`` environment variables.

Schema notes
------------
Field naming convention: snake_case. Models normalise to camelCase via aliases
when emitting properties so OpenGraph output matches CMBP byte-for-byte.

The ``transforms.py::_build_targets`` SQL union expects these once-phase tables
to expose the host as the ``hostname`` column:
    local_management_points, local_distribution_points,
    dns_management_points, dhcp_pxe_dps
The resources below honour that contract.

LDAP attributes that flow into multiple downstream tables (e.g. computer SIDs that
appear as Computer nodes AND as group members) are collected once and joined in
``transforms.py`` SQL — not duplicated across resources.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Any, Iterable, Optional

import dlt

from .clients.ad import ADClient, ADCredentials
from .context import SourceContext
from .main import app
from .models import (
    Computer,
    DerivedEdges,
    DerivedNode,
    Group,
    GroupMembership,
    MSSQLServer,
    SCCMAdminUser,
    SCCMClientDevice,
    SCCMCollection,
    SCCMSecurityRole,
    SCCMSite,
    User,
)

logger = logging.getLogger(__name__)





# Pull each resource function into this module's namespace. Importing the
# collector modules also triggers their ``@app.resource(...)`` decorators,
# which register each resource on ``app``. The ``source()`` factory below
# calls these by their bare names.
from .collectors.adminservice import (  # noqa: E402
    adminservice_admins,
    adminservice_client_devices,
    adminservice_collection_members,
    adminservice_collection_variables,
    adminservice_collections,
    adminservice_r_system_security_groups,
    adminservice_r_user_security_groups,
    adminservice_reserved_accounts,
    adminservice_role_members,
    adminservice_security_roles,
    adminservice_site_definitions,
    adminservice_site_systems,
    adminservice_sites,
    adminservice_task_sequences,
    ldap_sites_admin_extra,
)
from .collectors.derived import derived_edges, derived_nodes  # noqa: E402
from .collectors.dhcp import dhcp_pxe_dps  # noqa: E402
from .collectors.dns import dns_management_points  # noqa: E402
from .collectors.http import (  # noqa: E402
    http_collection_secrets,
    http_distribution_points,
    http_management_points,
    http_naa_secrets,
    http_smsproviders,
)
from .collectors.ldap import (  # noqa: E402
    ldap_computers,
    ldap_group_memberships,
    ldap_groups,
    ldap_mp_site_classifications,
    ldap_sites,
    ldap_sms_providers,
    ldap_users,
)
from .collectors.local import (  # noqa: E402
    local_distribution_points,
    local_management_points,
)
from .collectors.mssql import mssql_epa_flags  # noqa: E402
from .collectors.registry import (  # noqa: E402
    registry_current_users,
    registry_sccm_components,
    registry_sccm_databases,
)
from .collectors.smb import (  # noqa: E402
    ldap_sites_smb_extra,
    smb_distribution_points,
    smb_signing_status,
    smb_site_servers,
)
from .collectors.wmi import (  # noqa: E402
    wmi_clients,
    wmi_sql_service_accounts,
    wmi_users_seen,
)


# ---------------------------------------------------------------------------
# Source assembly
# ---------------------------------------------------------------------------

@app.source(name="sccm", max_table_nesting=0)
def source(
    # ---- Connection (CMBP -d/-dc/-u/-p) — dlt-bound from SOURCES__SCCM__* env vars ----
    domain: str = dlt.config.value,
    domain_controller: str | None = dlt.config.value,
    username: str | None = dlt.secrets.value,
    password: str | None = dlt.secrets.value,
):
    """Build the LDAP-driven SCCM data source.

    The four parameters above bind via dlt's config/secrets system (so the
    `SOURCES__SCCM__{DOMAIN,DOMAIN_CONTROLLER,USERNAME,PASSWORD}` env vars
    are read automatically). Every other CMBP-equivalent flag is read from
    ``os.environ`` inside the body via the ``_env*`` helpers — declaring
    them as dlt-bound parameters causes dlt to eagerly coerce them from
    config providers in ways that produce confusing runtime errors (e.g.
    a missing or unset env value tripping bool/int coercion). Keeping the
    dlt-bound surface to the four credentials matches the pre-CLI-port
    factory shape and lets the CMBP-style flags on
    ``openhound collect|preprocess|convert sccm`` drive everything else
    via the env vars they set in ``main.py``.
    """

    # Defaults for every CMBP-equivalent flag the source factory honours.
    # ``_env*`` helpers below override these from the matching env var.
    # Note: ``use_ssl`` / ``start_tls`` / ``ldap_signing`` / ``ldap_channel_binding``
    # are intentionally absent — the LDAP transport + hardening combo is
    # auto-detected by ``ADClient.bind()`` in a lockout-safe way (see
    # ``clients/ad.py``). ``LDAP_PORT`` survives only as an explicit pin
    # for the rare case where 636/389 isn't appropriate.
    ldap_port: int | None = None
    collection_methods: str = "All"
    computers: str | None = None
    computer_file: str | None = None
    sms_provider: str | None = None
    site_codes: str | None = None
    disable_possible_edges: bool = False
    enable_bad_opsec: bool = False
    threads: int = 1
    show_cleartext_passwords: bool = False
    machine_name: str | None = None
    machine_pass: str | None = None
    client_name: str | None = None
    create_machine_account: str | None = None
    use_altauth: bool = False
    registration_sleep: int = 10
    socks_proxy: str | None = None

    def _env(name: str, fallback):
        v = os.environ.get(name)
        return v if v not in (None, "") else fallback

    def _env_bool(name: str, fallback: bool) -> bool:
        v = os.environ.get(name)
        if v is None or v == "":
            return fallback
        return v.lower() in ("1", "true", "yes", "on")

    def _env_int(name: str, fallback: int) -> int:
        v = os.environ.get(name)
        if v is None or v == "":
            return fallback
        try:
            return int(v)
        except ValueError:
            return fallback

    # Preserve None when no env var is set so ADClient auto-detects the
    # transport (LDAPS 636 → StartTLS 389 → LDAP 389 with NTLM sign/seal).
    _ldap_port_env = os.environ.get("SOURCES__SCCM__LDAP_PORT")
    if _ldap_port_env not in (None, ""):
        try:
            ldap_port = int(_ldap_port_env)
        except ValueError:
            pass
    collection_methods = _env("SOURCES__SCCM__COLLECTION_METHODS", collection_methods) or "All"
    computers = _env("SOURCES__SCCM__COMPUTERS", computers)
    computer_file = _env("SOURCES__SCCM__COMPUTER_FILE", computer_file)
    sms_provider = _env("SOURCES__SCCM__SMS_PROVIDER", sms_provider)
    site_codes = _env("SOURCES__SCCM__SITE_CODES", site_codes)
    disable_possible_edges = _env_bool("SOURCES__SCCM__DISABLE_POSSIBLE_EDGES", disable_possible_edges)
    enable_bad_opsec = _env_bool("SOURCES__SCCM__ENABLE_BAD_OPSEC", enable_bad_opsec)
    threads = _env_int("SOURCES__SCCM__THREADS", threads)
    show_cleartext_passwords = _env_bool("SOURCES__SCCM__SHOW_CLEARTEXT_PASSWORDS", show_cleartext_passwords)
    machine_name = _env("SOURCES__SCCM__MACHINE_NAME", machine_name)
    machine_pass = _env("SOURCES__SCCM__MACHINE_PASS", machine_pass)
    client_name = _env("SOURCES__SCCM__CLIENT_NAME", client_name)
    create_machine_account = _env("SOURCES__SCCM__CREATE_MACHINE_ACCOUNT", create_machine_account)
    use_altauth = _env_bool("SOURCES__SCCM__USE_ALTAUTH", use_altauth)
    registration_sleep = _env_int("SOURCES__SCCM__REGISTRATION_SLEEP", registration_sleep)
    socks_proxy = _env("SOURCES__SCCM__SOCKS_PROXY", socks_proxy)

    creds = ADCredentials(
        domain=domain,
        domain_controller=domain_controller,
        username=username,
        password=password,
        port=ldap_port,
    )
    ctx = SourceContext(
        ad=ADClient(creds),
        domain=domain,
        username=username,
        password=password,
        collection_methods=collection_methods or "All",
        computers=computers,
        computer_file=computer_file,
        sms_provider=sms_provider,
        site_codes=site_codes,
        disable_possible_edges=bool(disable_possible_edges),
        enable_bad_opsec=bool(enable_bad_opsec),
        threads=int(threads) if threads else 1,
        show_cleartext_passwords=bool(show_cleartext_passwords),
        machine_name=machine_name,
        machine_pass=machine_pass,
        client_name=client_name,
        create_machine_account=create_machine_account,
        use_altauth=bool(use_altauth),
        registration_sleep=int(registration_sleep) if registration_sleep else 10,
        socks_proxy=socks_proxy,
    )

    return (
        # Phase 1 — LDAP once-phases
        ldap_sites(ctx),
        ldap_mp_site_classifications(ctx),
        ldap_computers(ctx),
        ldap_users(ctx),
        ldap_groups(ctx),
        ldap_group_memberships(ctx),
        ldap_sms_providers(ctx),
        # Phase 2 — Local / DNS / DHCP once-phases. Each runs locally on the
        # collector machine (no per-host fan-out) and contributes provenance
        # rows to ``sccm.targets`` via the SQL union in ``transforms.py``.
        local_management_points(ctx),
        local_distribution_points(ctx),
        dns_management_points(ctx),
        dhcp_pxe_dps(ctx),
        # Phase 3a — Per-host RemoteRegistry + MSSQL probes. Each iterates the
        # cached ``ctx.ldap_computer_hosts()`` list. Hosts that don't permit
        # remote registry / aren't listening on TCP 1433 are silently skipped.
        registry_sccm_components(ctx),
        registry_sccm_databases(ctx),
        registry_current_users(ctx),
        mssql_epa_flags(ctx),
        # Phase 3b — AdminService REST API. Each resource shares a per-host
        # cache built lazily by ``ctx.adminservice_payloads()``.
        adminservice_admins(ctx),
        adminservice_collections(ctx),
        adminservice_collection_members(ctx),
        adminservice_security_roles(ctx),
        adminservice_role_members(ctx),
        adminservice_client_devices(ctx),
        adminservice_task_sequences(ctx),
        adminservice_collection_variables(ctx),
        adminservice_site_systems(ctx),
        adminservice_sites(ctx),
        adminservice_site_definitions(ctx),
        adminservice_r_system_security_groups(ctx),
        adminservice_r_user_security_groups(ctx),
        adminservice_reserved_accounts(ctx),
        # Phase 7 fold-in: emit SCCM_Site rows for sites that surfaced only
        # via AdminService (no mSSMSSite / mSSMSManagementPoint). Writes
        # into the same ``ldap_sites`` DLT table; deduped against
        # ``ctx._emitted_site_codes`` populated by the Phase 1 resource.
        ldap_sites_admin_extra(ctx),
        # Phase 3c — WMI / HTTP / SMB per-host enrichment. WMI is a fallback
        # for hosts where AdminService didn't return a row; HTTP / SMB tag
        # role + signing flags consumed by Phase 4 SQL views.
        wmi_clients(ctx),
        wmi_users_seen(ctx),
        wmi_sql_service_accounts(ctx),
        http_management_points(ctx),
        http_smsproviders(ctx),
        http_distribution_points(ctx),
        http_naa_secrets(ctx),
        http_collection_secrets(ctx),
        smb_site_servers(ctx),
        smb_distribution_points(ctx),
        smb_signing_status(ctx),
        # Phase 10 fold-in: emit SCCM_Site rows for sites surfaced only via
        # SMB share enumeration (low-priv users on Secondary site servers).
        # Writes into the same ``ldap_sites`` DLT table; deduped against
        # ``ctx._emitted_site_codes``.
        ldap_sites_smb_extra(ctx),
        # Phase 4 — derived-edges trigger. One sentinel row that fires the
        # DerivedEdges aggregator model in convert.
        derived_edges(ctx),
        # Phase 6 — synthesised MSSQL principal nodes (Login / DatabaseUser /
        # DatabaseRole / ServerRole / Database) referenced by the
        # ``mssql_sysadmin_edges`` fan-out. Mirrors the SQL view in Python so
        # the rows can be persisted to JSONL at collect time.
        derived_nodes(ctx),
    )

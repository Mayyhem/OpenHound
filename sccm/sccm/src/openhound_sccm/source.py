import logging
import pathlib
import queue as _queue

import dlt

from .clients.ad import ADClient, ADCredentials
from .context import SourceContext
from .main import app
from .models.raw_table import raw_table_asset
from .per_host_phases import PER_HOST_PHASES, all_table_names
from .phased_pipeline.streams import DONE

from .collectors.ldap import (
    ldap_management_points_raw,
    ldap_sites,
    ldap_cmrc_devices,
    ldap_network_boot_servers,
    ldap_pattern_matches,
    ldap_system_management_dacl,
)

from .collectors.dns import dns_management_points

from .collectors.local import (
    local_wmi_sms_authority,
    local_wmi_sms_lookupmp,
    local_wmi_ccm_client,
    local_client_logs_targets,
)

logger = logging.getLogger(__name__)


def _parse_csv_option(value: str | None) -> set[str]:
    """Return a stripped set of tokens from a comma-separated CLI value."""
    return {token for raw in (value or "").split(",") if (token := raw.strip())}


# ---------------------------------------------------------------------------
# Shared per-run state — planted by collect_sccm() before each pipeline.run()
# so the SourceContext created inside source() carries the same instances.
# ---------------------------------------------------------------------------
_shared_queue = None
_shared_ad_cache = None
_shared_discovered_domains = None


def set_shared_queue(work_queue) -> None:
    """Plant (or clear) the shared phased_pipeline.WorkQueue for the next source() call."""
    global _shared_queue
    _shared_queue = work_queue


def set_shared_ad_cache(cache) -> None:
    """Plant (or clear) the shared AD resolution cache for the next source() call."""
    global _shared_ad_cache
    _shared_ad_cache = cache


def set_shared_discovered_domains(domains) -> None:
    """Plant (or clear) the shared discovered-domains set for the next source() call."""
    global _shared_discovered_domains
    _shared_discovered_domains = domains


# ---------------------------------------------------------------------------
# Per-table stream registry. The per-host engine (run by collect_sccm on a
# background thread) pushes rows onto these bounded queues; the emit resources
# below drain them. collect_sccm installs the mapping via set_table_queues()
# just before running the emit pass, mirroring the _shared_* pattern above.
# ---------------------------------------------------------------------------
_table_queues: dict[str, _queue.Queue] | None = None


def set_table_queues(mapping: dict[str, _queue.Queue]) -> None:
    """Plant the per-table stream mapping the emit resources will drain."""
    global _table_queues
    _table_queues = mapping


def get_table_queues() -> dict[str, _queue.Queue] | None:
    """Return the currently-installed per-table stream mapping (or None)."""
    return _table_queues


def clear_table_queues() -> None:
    """Forget the per-table stream mapping after the emit pass finishes."""
    global _table_queues
    _table_queues = None


def _drain_stream(table_name: str):
    """Yield rows from one per-table stream until the shared DONE marker.

    Used by the emit resources. A blocking get() means an empty stream is a
    *wait*, not an end — the resource stops only on DONE, which is broadcast to
    every stream once per-host collection reaches quiescence.
    """
    streams = get_table_queues()
    if streams is None:
        return
    stream = streams[table_name]
    while True:
        item = stream.get()
        if item is DONE:
            return
        yield item


def _make_emit_resource(table_name: str):
    """Build one DLT resource that streams a single per-host table to disk.

    Each carries ``columns=raw_table_asset(table_name)`` so convert can map the
    table to a model and the conformance tests are satisfied. A real collector's
    follow-up may replace the placeholder model with a typed one.
    """

    @app.resource(name=table_name, parallelized=False, columns=raw_table_asset(table_name))
    def _emit():
        yield from _drain_stream(table_name)

    return _emit


# One emit resource per per-host table, registered once at import time.
_EMIT_RESOURCES = tuple(_make_emit_resource(table) for table in all_table_names(PER_HOST_PHASES))


@app.source(name="sccm", max_table_nesting=0)
def source(
    # These are populated by main.py from the CLI options and secrets, then passed into the SourceContext
    # Connection
    domain: str = dlt.config.value,
    domain_controller: str | None = dlt.config.value,
    username: str | None = dlt.secrets.value,
    password: str | None = dlt.secrets.value,
    ldap_port: int | None = dlt.config.value,
    # Collection
    collection_methods: str | None = dlt.config.value,
    computers: str | None = dlt.config.value,
    computer_file: str | None = dlt.config.value,
    sms_provider: str | None = dlt.config.value,
    site_codes: str | None = dlt.config.value,
    # Behavior
    disable_possible_edges: bool | None = dlt.config.value,
    enable_bad_opsec: bool | None = dlt.config.value,
    threads: int | None = dlt.config.value,
    show_cleartext_passwords: bool | None = dlt.config.value,
    # CRED-2
    machine_name: str | None = dlt.config.value,
    machine_pass: str | None = dlt.secrets.value,
    client_name: str | None = dlt.config.value,
    create_machine_account: str | None = dlt.config.value,
    use_altauth: bool | None = dlt.config.value,
    registration_sleep: int | None = dlt.config.value,
    # Network
    socks_proxy: str | None = dlt.config.value,
    # DNS
    dns_resolver: str | None = dlt.config.value,
):
    # Normalize to handle None values and set defaults
    collection_methods = collection_methods or "All"
    disable_possible_edges = bool(disable_possible_edges)
    enable_bad_opsec = bool(enable_bad_opsec)
    threads = threads if threads is not None else 1
    show_cleartext_passwords = bool(show_cleartext_passwords)
    use_altauth = bool(use_altauth)
    registration_sleep = registration_sleep if registration_sleep is not None else 10

    # Parse allowed targets from --computers and --computer-file.
    # Both FQDN and short-name forms are added so Test-AllowedTarget matching
    # works regardless of how a discovered host is later presented.
    allowed = _parse_csv_option(computers)
    for name in list(allowed):
        if "." in name:
            allowed.add(name.split(".")[0])
    if computer_file:
        p = pathlib.Path(computer_file)
        if p.exists():
            for line in p.read_text().splitlines():
                name = line.strip().lower()
                if name:
                    allowed.add(name)
                    if "." in name:
                        allowed.add(name.split(".")[0])

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
        allowed_targets=frozenset(allowed),
        work_queue=_shared_queue,
        ad_resolution_cache=_shared_ad_cache if _shared_ad_cache is not None else {},
        discovered_domains=_shared_discovered_domains if _shared_discovered_domains is not None else set(),
        site_codes=_parse_csv_option(site_codes) or None,
        dns_resolver=dns_resolver,
    )

    # Discovery (once) resources seed the work queue via register_target. The
    # per-host phases are NOT DLT-scheduled here; they run in collect_sccm's
    # worker pool and stream their rows through the emit resources below. Both
    # sets are returned; collect_sccm selects each stage with with_resources().
    return (
        ldap_sites(ctx),
        ldap_management_points_raw(ctx),
        ldap_cmrc_devices(ctx),
        ldap_network_boot_servers(ctx),
        ldap_pattern_matches(ctx),
        ldap_system_management_dacl(ctx),
        dns_management_points(ctx),
        local_wmi_sms_authority(ctx),
        local_wmi_sms_lookupmp(ctx),
        local_wmi_ccm_client(ctx),
        local_client_logs_targets(ctx),
        *(emit() for emit in _EMIT_RESOURCES),
    )

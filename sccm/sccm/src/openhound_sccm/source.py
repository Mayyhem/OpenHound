import dlt
import logging
import pathlib

from .clients.ad import ADClient, ADCredentials
from .context import SourceContext
from .main import app

from .collectors.ldap import (
    ldap_management_points_raw,
    ldap_sites,
    ldap_cmrc_devices,
    ldap_network_boot_servers,
    ldap_pattern_matches,
    ldap_system_management_dacl,
)

from .collectors.dns import dns_management_points

logger = logging.getLogger(__name__)


def _parse_csv_option(value: str | None) -> set[str]:
    """Return a stripped set of tokens from a comma-separated CLI value."""
    return {token for raw in (value or "").split(",") if (token := raw.strip())}

# ---------------------------------------------------------------------------
# Shared target queue — set by collect_sccm() before each pipeline.run() call
# so that the SourceContext created inside source() carries the same queue
# instance across multiple passes.
# ---------------------------------------------------------------------------
_shared_queue = None
_shared_ad_cache = None
_shared_discovered_domains = None

def set_shared_queue(queue) -> None:
    """Plant (or clear) the shared TargetQueue for the next source() call."""
    global _shared_queue
    _shared_queue = queue

def set_shared_ad_cache(cache) -> None:
    """Plant (or clear) the shared AD resolution cache for the next source() call."""
    global _shared_ad_cache
    _shared_ad_cache = cache

def set_shared_discovered_domains(domains) -> None:
    """Plant (or clear) the shared discovered-domains set for the next source() call."""
    global _shared_discovered_domains
    _shared_discovered_domains = domains

# Names of every per-host resource. collect_sccm() passes this to
# source().with_resources() for subsequent queue-loop passes
PER_HOST_RESOURCE_NAMES: tuple[str, ...] = (
    "registry_sccm_components",
)

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
        target_queue=_shared_queue,
        ad_resolution_cache=_shared_ad_cache if _shared_ad_cache is not None else {},
        discovered_domains=_shared_discovered_domains if _shared_discovered_domains is not None else set(),
        site_codes=_parse_csv_option(site_codes) or None,
        dns_resolver=dns_resolver,
    )

    return (
        ldap_sites(ctx),
        ldap_management_points_raw(ctx),
        ldap_cmrc_devices(ctx),
        ldap_network_boot_servers(ctx),
        ldap_pattern_matches(ctx),
        ldap_system_management_dacl(ctx),
        dns_management_points(ctx),
    )

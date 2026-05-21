import dlt

from .clients.ad import ADClient, ADCredentials
from .context import SourceContext
from .main import app

from .collectors.ldap import (
    ldap_sites,
)


@app.source(name="sccm", max_table_nesting=0)
def source(
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
):
    # Normalize to handle None values and set defaults
    collection_methods = collection_methods or "All"
    disable_possible_edges = bool(disable_possible_edges)
    enable_bad_opsec = bool(enable_bad_opsec)
    threads = threads if threads is not None else 1
    show_cleartext_passwords = bool(show_cleartext_passwords)
    use_altauth = bool(use_altauth)
    registration_sleep = registration_sleep if registration_sleep is not None else 10

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
    )
    
    return (
        ldap_sites(ctx),
    )

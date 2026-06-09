"""
Checks MSSQL database servers for:
- Extended Protection for Authentication (EPA) settings via NTLM probing
- Site database MSSQL server nodes and relationships
- sysadmin login detection
- Service account detection
"""
import logging
from typing import Any, Iterable

from ..clients.mssql_epa import test_epa
from ..context import SourceContext
from ..log_context import with_log_context

logger = logging.getLogger(__name__)


def _check_port(hostname: str, port: int, timeout: float = 3.0) -> bool:
    """Check if TCP port is open on the target host."""
    import socket
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError) as ex:
        logger.debug("%s:%d unreachable: %s", hostname, port, ex)
        return False


@with_log_context(phase="MSSQL")
def collect_mssql(target: str, ctx: SourceContext) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield one row per MSSQL host that responds to probing on TCP/1433.

    EPA detection is performed via NTLM login probes (explicit credentials or
    current-user SSPI). EPA enforcement drives the CoerceAndRelayToMSSQL derived
    edges, so hosts not listening on 1433 silently yield no row.
    """
    if not ctx.method_enabled("MSSQL"):
        return

    logger.info("Starting MSSQL collection on %s", target)

    # Query AD for SPNs to help EPA detection select the correct service binding.
    spns = ctx.ad.get_spns(target)

    # Split port or instance name from SPN if present (format is MSSQLSvc/hostname:port or MSSQLSvc/hostname\instance).
    port = 1433  # Default MSSQL port
    if spns:
        # Get the MSSQLSvc SPN for the target host, if present
        spn = next((s for s in spns if s.startswith("MSSQLSvc/")), None)
        if spn:
            if ":" in spn:
                _, port_str = spn.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    logger.warning("Invalid port in SPN %s: %s", spn, port_str)
            elif "\\" in spn:
                # Instance name is present, but we can't determine the port without connecting to the SQL Browser service, so default to 1433.
                logger.info("SPN %s contains instance name but no port, defaulting to 1433", spn)
        else:
            logger.verbose("No MSSQLSvc SPN found for %s, defaulting to port 1433", target)
    else:
        logger.verbose("No SPNs found for %s, defaulting to port 1433", target)
        
    if not _check_port(target, port):
        logger.info("MSSQL port %d is not open, skipping", port)
        return

    logger.info("MSSQL port %d is open", port)

    # Probe EPA enforcement using the credential ladder (explicit creds -> SSPI -> skip).
    epa_result = test_epa(
        target=target,
        port=port,
        remote_name=target,
        domain=ctx.domain,
        username=ctx.username,
        password=ctx.password,
        nt_hash=ctx.nt_hash,
        spns=spns,
    )

    force_encryption = None
    extended_protection = None
    strict_encryption = None
    if epa_result:
        force_encryption = epa_result.force_encryption
        extended_protection = epa_result.extended_protection
        strict_encryption = epa_result.strict_encryption

    target_entry = ctx.target_hosts_by_hostname.get(target.lower())

    yield "mssql_servers", {
        "source": "MSSQL-ScanForEPA",
        "force_encryption": force_encryption,
        "extended_protection": extended_protection,
        "strict_encryption": strict_encryption,
        "name": target_entry.ad_object.get("name") if target_entry and target_entry.ad_object else target,
        "domain_computer_sid": target_entry.ad_object.get("object_sid") if target_entry and target_entry.ad_object else None,
        "port": port,
    }

    logger.info("MSSQL collection completed for %s:%d", target, port)

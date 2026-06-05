import logging
import socket
import time
from typing import Iterable, Any, Optional

from ..clients.smb_sso import connect_smb
from ..context import SourceContext, TargetEntry
from ..log_context import with_log_context
from ..main import app

logger = logging.getLogger(__name__)

# Try to import impacket for remote registry
try:
    from impacket.dcerpc.v5 import rrp, transport
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


# Registry key paths for SCCM
SCCM_REG_KEYS = {
    # Readable by any authenticated AD user with SMB access to the host
    "triggers": r"SOFTWARE\Microsoft\SMS\Triggers",
    "component_servers": r"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Component Servers",
    "multisite_component_servers": r"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers",
    "current_user": r"SOFTWARE\Microsoft\SMS\CurrentUser",
}


# RemoteRegistry is trigger-started on modern Windows: the first \winreg pipe
# open wakes the service but races against it actually listening, so the first
# bind often returns STATUS_PIPE_NOT_AVAILABLE. Retry briefly to let the service
# finish starting -- this mirrors what the native OpenRemoteBaseKey client (used
# by the original PowerShell) does internally.
WINREG_BIND_RETRIES = 3
WINREG_BIND_RETRY_DELAY = 1.5


class _RegistryProbe:
    """Lightweight remote-registry helper used by the registry resources.

    Wraps an SMB connection + a winreg DCE/RPC binding.
    """

    def __init__(self, hostname: str, domain: str, username: Optional[str], password: Optional[str]) -> None:
        self.hostname = hostname
        self.domain = domain
        self.username = username
        self.password = password
        self.smb = None
        self.dce = None
        self.root_key = None

    def __enter__(self) -> Optional["_RegistryProbe"]:
        # Fast TCP probe to avoid 30-second SMB timeouts on dead hosts.
        logger.verbose("Probing Remote Registry on %s (port 445)", self.hostname)
        try:
            with socket.create_connection((self.hostname, 445), timeout=3):
                pass
        except (socket.timeout, ConnectionRefusedError, OSError) as ex:
            logger.verbose("SMB/445 not reachable on %s: %s", self.hostname, ex)
            return None

        try:
            from impacket.dcerpc.v5 import rrp, transport
            from impacket.nt_errors import STATUS_PIPE_NOT_AVAILABLE
            from impacket.smbconnection import SessionError
        except ImportError:
            logger.warning("impacket not installed; skipping host %s", self.hostname)
            return None

        smb = connect_smb(self.hostname, self.domain, self.username, self.password)
        if smb is None:
            return None
        self.smb = smb

        # Bind to the \winreg pipe, retrying only the trigger-start race. On any
        # exit we leave self.smb set so __exit__ performs exactly one logoff --
        # logging off here too would delete the session twice and raise a
        # spurious STATUS_USER_SESSION_DELETED.
        for attempt in range(1, WINREG_BIND_RETRIES + 1):
            try:
                rpc = transport.SMBTransport(smb.getRemoteHost(), filename=r"\winreg", smb_connection=smb)
                rpc.connect()
                dce = rpc.get_dce_rpc()
                dce.connect()
                dce.bind(rrp.MSRPC_UUID_RRP)
                resp = rrp.hOpenLocalMachine(dce)
                self.dce = dce
                self.root_key = resp["phKey"]
                logger.verbose("Remote Registry bind to %s succeeded on attempt %d", self.hostname, attempt)
                return self
            except SessionError as ex:
                # STATUS_PIPE_NOT_AVAILABLE means RemoteRegistry is still starting
                # (our open was the trigger); wait and retry. Other SMB errors
                # (access denied, service disabled, etc.) are not transient.
                if ex.getErrorCode() == STATUS_PIPE_NOT_AVAILABLE and attempt < WINREG_BIND_RETRIES:
                    logger.verbose(
                        "winreg pipe not listening yet on %s (attempt %d/%d); RemoteRegistry still starting, retrying in %.1fs",
                        self.hostname, attempt, WINREG_BIND_RETRIES, WINREG_BIND_RETRY_DELAY,
                    )
                    time.sleep(WINREG_BIND_RETRY_DELAY)
                    continue
                logger.verbose("winreg bind on %s failed: %s", self.hostname, ex)
                return None
            except Exception as ex:  # noqa: BLE001
                # Most common cause: RemoteRegistry service not running, or no perm.
                logger.verbose("winreg bind on %s failed: %s", self.hostname, ex)
                return None

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            if self.dce is not None:
                logger.verbose("Disconnecting Remote Registry on %s", self.hostname)
                self.dce.disconnect()
        except Exception as ex:
            logger.error("Failed to disconnect DCE/RPC on %s: %s", self.hostname, ex)
            pass
        try:
            if self.smb is not None:
                logger.verbose("Logging off SMB on %s", self.hostname)
                self.smb.logoff()
        except Exception as ex:
            logger.error("Failed to log off SMB on %s: %s", self.hostname, ex)
            pass

    # ----- read helpers ------------------------------------------------------

    def read_value(self, key_path: str, value_name: str) -> Optional[str]:
        from impacket.dcerpc.v5 import rrp
        logger.verbose("Reading value %s under %s", value_name, key_path)
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                _, value = rrp.hBaseRegQueryValue(self.dce, sub, value_name)
                if isinstance(value, bytes):
                    value = value.decode("utf-16-le", errors="replace")
                return str(value).rstrip("\x00").strip()
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except Exception as ex:
            logger.error("Failed to read registry value %s under %s on %s: %s", value_name, key_path, self.hostname, ex)
            return None

    def read_dword(self, key_path: str, value_name: str) -> Optional[int]:
        from impacket.dcerpc.v5 import rrp
        logger.verbose("Reading DWORD value %s under %s on %s", value_name, key_path, self.hostname)
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                _, value = rrp.hBaseRegQueryValue(self.dce, sub, value_name)
                if isinstance(value, int):
                    return value
                if isinstance(value, bytes) and len(value) >= 4:
                    import struct
                    return struct.unpack("<I", value[:4])[0]
                return int(value) if value else None
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except Exception as ex:
            logger.error("Failed to read DWORD value %s under %s on %s: %s", value_name, key_path, self.hostname, ex)
            return None

    def enum_keys(self, key_path: str) -> Optional[list[str]]:
        from impacket.dcerpc.v5 import rrp
        logger.verbose("Enumerating subkeys under %s", key_path)
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                names: list[str] = []
                i = 0
                while True:
                    try:
                        resp = rrp.hBaseRegEnumKey(self.dce, sub, i)
                    except Exception:
                        break  # ERROR_NO_MORE_ITEMS: normal end of enumeration
                    # lpNameOut is an RRP_UNICODE_STRING wrapper; the subkey name is
                    # its Data field. Calling str() on the wrapper itself raises
                    # "__str__ returned non-string (type bytes)". Mirrors read_values().
                    name_field = resp["lpNameOut"]
                    try:
                        name = name_field["Data"]
                    except (KeyError, TypeError):
                        name = name_field
                    if isinstance(name, bytes):
                        name = name.decode("utf-16-le", errors="replace")
                    names.append(str(name).rstrip("\x00").strip())
                    i += 1
                return names
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except Exception as ex:
            logger.verbose("Failed to enumerate subkeys under %s: %s", key_path, ex)
            return None

    def read_values(self, key_path: str) -> Optional[list[tuple[str, str]]]:
        """Return a list of ``(value_name, value_data)`` pairs under *key_path*.

        Used for keys where the *names* are unknown — e.g. SCCM's
        ``SMS\\CurrentUser`` key, which uses arbitrary value names whose
        contents are SIDs. Returns ``None`` if the key can't be opened;
        an empty list if the key exists but has no values.

        ``hBaseRegEnumValue`` returns ``lpType`` + a list-of-byte ``lpData``
        buffer; impacket's ``unpackValue(type, data)`` decodes both REG_SZ
        and REG_MULTI_SZ to a Python str. impacket's NDR layer auto-unwraps
        ``lpValueNameOut`` to the value name as a plain Python str, so we use
        it directly.
        """
        from impacket.dcerpc.v5 import rrp
        logger.verbose("Enumerating values under %s", key_path)
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                out: list[tuple[str, str]] = []
                i = 0
                while True:
                    try:
                        resp = rrp.hBaseRegEnumValue(self.dce, sub, i)
                    except Exception:
                        break  # ERROR_NO_MORE_ITEMS: normal end of enumeration
                    # impacket's NDR auto-unwraps lpValueNameOut to a Python str (the
                    # field carries a 'Data' subfield), so name_field["Data"] raises
                    # TypeError -- the str itself is the value name. Mirrors enum_keys().
                    name_field = resp["lpValueNameOut"]
                    try:
                        raw_name = name_field["Data"]
                    except (KeyError, TypeError):
                        raw_name = name_field
                    if isinstance(raw_name, bytes):
                        raw_name = raw_name.decode("utf-16-le", errors="replace")
                    name = str(raw_name).rstrip("\x00").strip()
                    # Decode the value data via impacket's helper, which
                    # handles the byte-array-of-byte-structures shape and
                    # type-specific decoding (REG_SZ → str, REG_DWORD → int).
                    try:
                        value_type = resp["lpType"]
                        raw_data = resp["lpData"]
                        decoded = rrp.unpackValue(value_type, raw_data)
                    except Exception as ex:
                        logger.error("Failed to decode value %r at index %d under %s: %s", name, i, key_path, ex)
                        decoded = ""
                    if isinstance(decoded, bytes):
                        decoded = decoded.decode("utf-16-le", errors="replace")
                    data = str(decoded).rstrip("\x00").strip()
                    out.append((name, data))
                    i += 1
                return out
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except Exception as ex:
            logger.error("Failed to open registry key %s: %s", key_path, ex)
            return None


@with_log_context(phase="RemoteRegistry")
def collect_registry(target: str, ctx: "SourceContext") -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield one row per (host, role) discovered via remote registry.

    For each host with SMB/445 + RemoteRegistry reachable, reads SCCM_REG_KEYS.

    A successful read (even if the keys are empty) implies this host is the
    SCCM site server.
    """
    if not ctx.method_enabled("RemoteRegistry"):
        return

    logger.info("Starting Remote Registry collection on %s...", target)

    with _RegistryProbe(target, ctx.domain, ctx.username, ctx.password) as probe:
        if probe is None:
            logger.info("Could not connect to %s for registry queries", target)
        else:

            # SOFTWARE\Microsoft\SMS\CurrentUser - first because it exists on other site system roles, not just site servers.
            # The logged-in user's domain SID is the data of the value named "UserSID".
            # Select it by name (not by enumeration position) so the sibling "Session"
            # DWORD can never be mistaken for the SID — the order in which the registry
            # hands back the two values is not guaranteed.
            logger.verbose("Querying %s for logged-in user's domain SID", SCCM_REG_KEYS["current_user"])
            values = probe.read_values(SCCM_REG_KEYS["current_user"])

            current_user_sid = None
            if values is None:
                # read_values returns None only when the key can't be opened.
                logger.error("Error querying %s on %s", SCCM_REG_KEYS["current_user"], target)
            else:
                current_user_sid = next(
                    (data for name, data in values if name.lower() == "usersid" and data),
                    None,
                )
                if not current_user_sid:
                    # Key present but no logged-in user recorded — not an error.
                    logger.info("No UserSID value under %s on %s", SCCM_REG_KEYS["current_user"], target)

            if current_user_sid:
                logger.verbose("Found CurrentUser SID %s on %s; resolving principal", current_user_sid, target)
                current_user_ad_object = ctx.resolve_principal(current_user_sid)
                if current_user_ad_object:
                    logger.info("Found current user: %s (%s)", current_user_ad_object.get("sAMAccountName"), current_user_sid)
                    row = {
                        **(current_user_ad_object or {}),
                        "source": "RemoteRegistry-CurrentUser",
                    }
                    row.setdefault("object_sid", current_user_sid)
                    yield "users", row
                else:
                    logger.warning("Failed to resolve current user SID: %s", current_user_sid)


            # HKLM\SOFTWARE\Microsoft\SMS\Triggers
            logger.verbose("Querying %s for SCCM site code", SCCM_REG_KEYS["triggers"])
            subkeys = probe.enum_keys(SCCM_REG_KEYS["triggers"])
            if subkeys and len(subkeys) > 1:
                logger.warning("Multiple site codes found under %s: %s", SCCM_REG_KEYS["triggers"], subkeys)
            site_code = subkeys[0] if subkeys else None
            if site_code:
                logger.info("Found SCCM site code: %s", site_code)
                yield "sccm_sites", {
                    "source": "RemoteRegistry-Triggers",
                    "site_code": site_code,
                }
            else:
                logger.info("%s does not exist or no site code subkey found, skipping remaining Remote Registry checks", SCCM_REG_KEYS["triggers"])
                return


            # HKLM\SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Component Servers
            logger.verbose("Querying %s for SCCM component servers", SCCM_REG_KEYS["component_servers"])
            subkeys = probe.enum_keys(SCCM_REG_KEYS["component_servers"])

            if subkeys:
                # Now we know this target is a site server
                # Spread every resolved AD attribute (dNSHostName, name,
                # sAMAccountName, object_sid, cn, ...) into the row, then
                # layer the registry-derived fields on top. AD `name`
                # flows through from ad_object; fall back to the raw
                # server name only when AD resolution failed (ad_object
                # is None or lacks a name).
                logger.info("Found %s, this target is a site server", SCCM_REG_KEYS["component_servers"])
                target_entry = ctx.target_hosts_by_hostname[target]
                row = {
                    **(target_entry.ad_object or {}),
                    "source": "RemoteRegistry-ComponentServers",
                    "sccm_infra": True,
                    "sccm_site_system_roles": "SMS Site Server@" + site_code if site_code else "SMS Site Server",
                }
                row.setdefault("name", target)
                yield "computers", row

                for i, server in enumerate(subkeys):
                    logger.info("Found component server #%d: %s", i + 1, server)

                    new_target = ctx.register_target(
                        identifier=server,
                        source="RemoteRegistry-ComponentServers",
                    )

                    if new_target:
                        row = {
                            **(new_target.ad_object or {}),
                            "source": "RemoteRegistry-ComponentServers",
                            "sccm_infra": True,
                            "sccm_site_system_roles": "SMS Component Server@" + site_code if site_code else "SMS Component Server",
                        }
                        row.setdefault("name", server)
                        yield "computers", row
                    # No else: register_target logs why it skipped (filtered host
                    # or empty name), so a None return isn't a failure here.
            else:
                logger.verbose("No component servers found under %s", SCCM_REG_KEYS["component_servers"])
            

            # HKLM\SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers
            logger.verbose("Querying %s for SCCM multisite component servers", SCCM_REG_KEYS["multisite_component_servers"])
            subkeys = probe.enum_keys(SCCM_REG_KEYS["multisite_component_servers"])

            if subkeys is None:
                # Key absent: nothing to record
                logger.verbose("No Multisite Component Servers key on %s", target)
            elif len(subkeys) == 0:
                # Key present but empty: the site database is local to this site
                # server, so this host carries both the SQL Server and Site Server
                # roles.
                logger.info("Site database is local to the site server: %s", target)
                target_entry = ctx.target_hosts_by_hostname[target]
                row = {
                    **(target_entry.ad_object or {}),
                    "source": "RemoteRegistry-MultisiteComponentServers",
                    "sccm_infra": True,
                    "sccm_site_system_roles": [
                        "SMS SQL Server@" + site_code if site_code else "SMS SQL Server",
                        "SMS Site Server@" + site_code if site_code else "SMS Site Server",
                    ],
                }
                row.setdefault("name", target)
                yield "computers", row
            else:
                # One or more remote site database servers, each a SQL Server
                if len(subkeys) == 1:
                    logger.info("Found single remote site database server: %s", subkeys[0])
                else:
                    logger.info("Found clustered remote site database servers: %s", ", ".join(subkeys))

                for server in subkeys:
                    new_target = ctx.register_target(
                        identifier=server,
                        source="RemoteRegistry-MultisiteComponentServers",
                    )
                    if new_target:
                        row = {
                            **(new_target.ad_object or {}),
                            "source": "RemoteRegistry-MultisiteComponentServers",
                            "sccm_infra": True,
                            "sccm_site_system_roles": ["SMS SQL Server@" + site_code if site_code else "SMS SQL Server"],
                        }
                        row.setdefault("name", server)
                        yield "computers", row
                    # No else: register_target logs why it skipped (filtered host
                    # or empty name), so a None return isn't a failure here.

    logger.info("Remote Registry collection completed for %s", target)


def collect_mssql_registry(probe: _RegistryProbe) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield one row per SQL instance discovered via remote registry.
    """
    logger.info("Starting MSSQL registry collection on %s...", probe.hostname)

    # Try multiple default registry paths for MSSQL instances
    # These correspond to SQL Server versions: 2012+ (v11+) use MSSQL versions
    reg_paths = [
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2022
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2019
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2017
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2016
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2014
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",  # SQL 2012
        r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL.1\MSSQLServer\SuperSocketNetLib",              # Older versions / default fallback
        r"SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib"                                # Legacy path
    ]

    force_encryption = None
    extended_protection = None
    reg_path_found = None
    restrict_receiving_ntlm_traffic = None
    disable_loopback_check = None

    # Try each registry path until one succeeds
    for reg_path in reg_paths:
    # just open the path to see if it exists
        reg_path
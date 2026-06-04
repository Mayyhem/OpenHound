import logging
import socket
from typing import Iterable, Any, Optional

from ..clients.smb_sso import connect_smb
from ..context import SourceContext
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
    "multisite_components": r"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers",
    "current_user": r"SOFTWARE\Microsoft\SMS\CurrentUser",
}


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
        except ImportError:
            logger.warning("impacket not installed; skipping host %s", self.hostname)
            return None

        smb = connect_smb(self.hostname, self.domain, self.username, self.password)
        if smb is None:
            return None
        self.smb = smb

        try:
            rpc = transport.SMBTransport(smb.getRemoteHost(), filename=r"\winreg", smb_connection=smb)
            rpc.connect()
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)
            resp = rrp.hOpenLocalMachine(dce)
            self.dce = dce
            self.root_key = resp["phKey"]
            logger.verbose("Remote Registry bind to %s succeeded", self.hostname)
            return self
        except Exception as ex:  # noqa: BLE001
            # Most common cause: RemoteRegistry service not running, or no perm.
            logger.verbose("winreg bind on %s failed: %s", self.hostname, ex)
            try:
                smb.logoff()
            except Exception:
                pass
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
            logger.error("Failed to enumerate subkeys under %s: %s", key_path, ex)
            return None

    def read_values(self, key_path: str) -> Optional[list[tuple[str, str]]]:
        """Return a list of ``(value_name, value_data)`` pairs under *key_path*.

        Used for keys where the *names* are unknown — e.g. SCCM's
        ``SMS\\CurrentUser`` key, which uses arbitrary value names whose
        contents are SIDs. Returns ``None`` if the key can't be opened;
        an empty list if the key exists but has no values.

        ``hBaseRegEnumValue`` returns ``lpType`` + a list-of-byte ``lpData``
        buffer; impacket's ``unpackValue(type, data)`` decodes both REG_SZ
        and REG_MULTI_SZ to a Python str. The wire ``lpValueNameOut`` is
        an RRP_UNICODE_STRING whose ``Data`` field is a Python string —
        not raw bytes — so we extract that directly.
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
                    except Exception as ex:
                        logger.error("No more values at index %d under %s: %s", i, key_path, ex)
                        break
                    # Extract the Unicode value name from the RRP_UNICODE_STRING wrapper.
                    name_field = resp["lpValueNameOut"]
                    try:
                        raw_name = name_field["Data"]
                    except (KeyError, TypeError) as ex:
                        logger.error("Unexpected format for value name at index %d under %s: %s", i, key_path, ex)
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
    SCCM site server. Hosts without the SCCM key tree silently yield nothing.
    """
    if not ctx.method_enabled("RemoteRegistry"):
        return

    logger.info("Starting Remote Registry collection on %s...", target)

    with _RegistryProbe(target, ctx.domain, ctx.username, ctx.password) as probe:
        if probe is None:
            logger.info("Could not connect to %s for registry queries", target)
        else:
            # HKLM\SOFTWARE\Microsoft\SMS\Triggers
            logger.info("Querying %s for SCCM site code", SCCM_REG_KEYS["triggers"])
            subkeys = probe.enum_keys(SCCM_REG_KEYS["triggers"])
            site_code = subkeys[0] if subkeys else None
            if site_code:
                logger.info("Found SCCM site code: %s", site_code)
                yield "sccm_sites", {
                    "site_code": site_code,
                    "source": "RemoteRegistry-Triggers",
                }
            else:
                logger.warning("Triggers key exists, but no site code subkey found under %s", SCCM_REG_KEYS["triggers"])
    logger.info("Remote Registry collection completed for %s", target)
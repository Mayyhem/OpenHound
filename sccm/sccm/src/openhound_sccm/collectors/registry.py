"""SCCM collectors split out from ``source.py``.

This module hosts the ``@app.resource`` generators for the registry phase.
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
from ..models.raw_table import raw_table_asset
from ..log_context import per_host_iter, per_pair_iter, with_log_context

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Phase 3a — Per-host RemoteRegistry + MSSQL probes.
# ---------------------------------------------------------------------------
# These resources iterate ``ctx.ldap_computer_hosts()`` and probe each host
# directly. RemoteRegistry uses impacket's RPC-over-SMB to read SCCM
# configuration from HKLM; MSSQL sends a TDS PRELOGIN packet to TCP/1433 to
# detect Extended Protection for Authentication.
#
# CMBP references:
#   - ``lib/collectors/registry_collector.py``     (~752 LOC)
#   - ``lib/collectors/mssql_collector.py``        (~621 LOC)
#
# Phase 3a does NOT do authenticated MSSQL introspection — that requires a
# pymssql / impacket-mssql round-trip with credentials and is best done in
# Phase 3b alongside AdminService. The login/database/role/etc. resources
# below currently yield empty so the convert phase doesn't crash if the
# JSONL is missing.

# -- Registry ----------------------------------------------------------------

_SCCM_REG_KEYS = {
    "triggers": r"SOFTWARE\Microsoft\SMS\Identification",
    "component_servers": r"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Component Servers",
    "multisite_components": r"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers",
    # The SCCM client agent writes the logged-on user's SID to
    # ``SOFTWARE\Microsoft\SMS\CurrentUser`` — readable by any
    # authenticated AD user with SMB access to the host. The generic
    # ``LogonUI\LastLoggedOnSAMUser`` value is ACL-restricted to local
    # admins, which is why earlier versions of this collector missed
    # all of PS1's HasSession edges for low-privileged callers.
    "current_user": r"SOFTWARE\Microsoft\SMS\CurrentUser",
}


def _split_user_domain(username: Optional[str], default_domain: str) -> tuple[str, str]:
    """Split a ``DOMAIN\\user`` or ``user@domain`` into ``(domain, user)``.

    Falls back to the first component of the configured AD ``domain`` when no
    explicit prefix is present.
    """
    if not username:
        return default_domain.split(".")[0], ""
    if "\\" in username:
        d, u = username.split("\\", 1)
        return d, u
    if "@" in username:
        u, d = username.split("@", 1)
        return d, u
    return default_domain.split(".")[0], username


class _RegistryProbe:
    """Lightweight remote-registry helper used by the Phase 3a registry resources.

    Wraps an SMB connection + a winreg DCE/RPC binding. ``read_value`` /
    ``read_dword`` / ``enum_keys`` are slimmed-down versions of the helpers
    in ``lib/collectors/registry_collector.py`` — same APIs, same error model
    (return None on failure), no GraphStore writes.
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
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.verbose("registry: SMB/445 not reachable on %s: %s", self.hostname, e)
            return None

        try:
            from impacket.dcerpc.v5 import rrp, transport
            from impacket.smbconnection import SMBConnection
        except ImportError:
            logger.warning("registry: impacket not installed; skipping host %s", self.hostname)
            return None

        d, u = _split_user_domain(self.username, self.domain)
        try:
            smb = SMBConnection(self.hostname, self.hostname, timeout=5)
            if u and self.password:
                smb.login(u, self.password, d)
            else:
                # Current Kerberos session — best-effort
                smb.login("", "", d)
            self.smb = smb
        except Exception as e:  # noqa: BLE001
            logger.verbose("registry: SMB login to %s failed: %s", self.hostname, e)
            return None

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
        except Exception as e:  # noqa: BLE001
            # Most common cause: RemoteRegistry service not running, or no perm.
            logger.verbose("registry: winreg bind on %s failed: %s", self.hostname, e)
            try:
                smb.logoff()
            except Exception:
                pass
            return None

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            if self.dce is not None:
                self.dce.disconnect()
        except Exception:
            pass
        try:
            if self.smb is not None:
                self.smb.logoff()
        except Exception:
            pass

    # ----- read helpers ------------------------------------------------------

    def read_value(self, key_path: str, value_name: str) -> Optional[str]:
        from impacket.dcerpc.v5 import rrp
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                _, value = rrp.hBaseRegQueryValue(self.dce, sub, value_name)
                if isinstance(value, bytes):
                    value = value.decode("utf-16-le", errors="replace")
                return str(value).rstrip("\x00").strip()
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except Exception:
            return None

    def read_dword(self, key_path: str, value_name: str) -> Optional[int]:
        from impacket.dcerpc.v5 import rrp
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
        except Exception:
            return None

    def enum_keys(self, key_path: str) -> Optional[list[str]]:
        from impacket.dcerpc.v5 import rrp
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                names: list[str] = []
                i = 0
                while True:
                    try:
                        resp = rrp.hBaseRegEnumKey(self.dce, sub, i)
                        name = resp["lpNameOut"]
                        if isinstance(name, bytes):
                            name = name.decode("utf-16-le", errors="replace")
                        names.append(str(name).rstrip("\x00").strip())
                        i += 1
                    except Exception:
                        break
                return names
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except Exception:
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
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                out: list[tuple[str, str]] = []
                i = 0
                while True:
                    try:
                        resp = rrp.hBaseRegEnumValue(self.dce, sub, i)
                    except Exception:
                        break
                    # Extract the Unicode value name from the RRP_UNICODE_STRING wrapper.
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
                    except Exception:
                        decoded = ""
                    if isinstance(decoded, bytes):
                        decoded = decoded.decode("utf-16-le", errors="replace")
                    data = str(decoded).rstrip("\x00").strip()
                    out.append((name, data))
                    i += 1
                return out
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except Exception:
            return None


@app.resource(name="registry_sccm_components", parallelized=False, columns=raw_table_asset("registry_sccm_components"))
@with_log_context(phase="RemoteRegistry")
def registry_sccm_components(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per (host, role) discovered via remote registry.

    For each host with SMB/445 + RemoteRegistry reachable, reads:
    - ``HKLM\\SOFTWARE\\Microsoft\\SMS\\Identification::Site Code`` to record
      the site code the host is part of (role = ``"Site System"``).
    - The ``Component Servers`` subkey — each subkey name is the FQDN of a
      site system server (passive site server, SCP, MP, DP, SUP). One row
      per FQDN with role = ``"SMS Component Server"``.

    A successful read (even if the keys are empty) implies this host is the
    SCCM site server. Hosts without the SCCM key tree silently yield nothing.
    """
    if not ctx.method_enabled("RemoteRegistry"):
        return
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "registry_sccm_components") == "done":
            continue
        logger.info("Starting Remote Registry collection on %s...", hostname)
        with _RegistryProbe(hostname, ctx.domain, ctx.username, ctx.password) as probe:
            if probe is None:
                logger.info("Could not connect to %s for registry queries", hostname)
            else:
                site_code = probe.read_value(_SCCM_REG_KEYS["triggers"], "Site Code")
                if site_code:
                    logger.info("Found SCCM site code in registry: %s", site_code)
                    yield {
                        "hostname": hostname,
                        "site_code": site_code,
                        "role": "SMS Site Server",
                        "computer_sid": host.get("sid"),
                        "source": "RemoteRegistry-Identification",
                        "domain": ctx.domain,
                    }
                    components = probe.enum_keys(_SCCM_REG_KEYS["component_servers"]) or []
                    if components:
                        logger.info("Read component servers: %s", components)
                    for fqdn in components:
                        if not fqdn:
                            continue
                        yield {
                            "hostname": fqdn.lower(),
                            "site_code": site_code,
                            "role": "SMS Component Server",
                            "computer_sid": None,
                            "source": "RemoteRegistry-ComponentServer",
                            "domain": ctx.domain,
                        }
        logger.info("Remote Registry collection completed for %s", hostname)
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "registry_sccm_components")


@app.resource(name="registry_sccm_databases", parallelized=False, columns=raw_table_asset("registry_sccm_databases"))
@with_log_context(phase="RemoteRegistry")
def registry_sccm_databases(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per (site_code, db_hostname) discovered via remote registry.

    Reads the ``SMS_SITE_COMPONENT_MANAGER\\Multisite Component Servers``
    subkey on each reachable host. Empty subkey = local DB (we do not emit a
    row in that case; the registry path doesn't reveal a remote DB host).
    Populated subkey = the listed FQDN(s) are SQL servers hosting the site DB.
    """
    if not ctx.method_enabled("RemoteRegistry"):
        return
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "registry_sccm_databases") == "done":
            continue
        with _RegistryProbe(hostname, ctx.domain, ctx.username, ctx.password) as probe:
            if probe is not None:
                site_code = probe.read_value(_SCCM_REG_KEYS["triggers"], "Site Code")
                if site_code:
                    multisite = probe.enum_keys(_SCCM_REG_KEYS["multisite_components"]) or []
                    for db_fqdn in multisite:
                        if not db_fqdn:
                            continue
                        db_lower = db_fqdn.lower()
                        # Mark this host as registry-confirmed so the later
                        # ``derived_nodes`` resource can decide whether to
                        # synthesise the MSSQL_Database / MSSQL_DatabaseRole
                        # nodes when ``--disable-possible-edges`` is set.
                        ctx.note_registry_confirmed_db_host(db_lower)
                        yield {
                            "hostname": db_lower,
                            "site_code": site_code,
                            "site_server": hostname,
                            "source": "RemoteRegistry-MultisiteComponentServers",
                            "domain": ctx.domain,
                        }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "registry_sccm_databases")


@app.resource(name="registry_current_users", parallelized=False, columns=raw_table_asset("registry_current_users"))
@with_log_context(phase="RemoteRegistry")
def registry_current_users(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per (host, currently-logged-on-user-SID) from the registry.

    Reads ``HKLM\\SOFTWARE\\Microsoft\\SMS\\CurrentUser`` — an SCCM
    client-agent-managed key whose value *names* are arbitrary and
    whose value *contents* are user SIDs. PS1's resolution rule
    (ConfigManBearPig.ps1 lines 5000-5012):

      * 0 values → no user
      * 1 value  → use it
      * 2 values → use index 1 (PS1's pick, kept verbatim)
      * else     → warn and skip

    Yielded ``user_name`` is the SID; convert-time SID resolution is
    handled by the consuming model.

    Gated on :meth:`SourceContext.sccm_discovered_hosts` — CMBP's per-host
    registry walk only iterates the ``TargetManager`` host list (hosts
    surfaced by LDAP-mSSMSManagementPoint / LDAP naming pattern / SMS
    Provider sAMAccountName / AdminService SMS_Site / SMS_SCI_*). Without
    this gate OH walks the full LDAP computer set and reads the DC's
    registry, surfacing a phantom ``DC -> domainadmin`` HasSession edge
    that CMBP never produces.
    """
    if not ctx.method_enabled("RemoteRegistry"):
        return
    discovered = ctx.sccm_discovered_hosts()
    for host in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host["hostname"]
        # Same canonicalisation as ``mssql_epa_flags``: the discovered set
        # carries lowercase short-host AND lowercase fqdn forms.
        short = (hostname or "").split(".", 1)[0].lower()
        fqdn = (hostname or "").lower()
        if discovered and short not in discovered and fqdn not in discovered:
            continue
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "registry_current_users") == "done":
            continue
        with _RegistryProbe(hostname, ctx.domain, ctx.username, ctx.password) as probe:
            if probe is not None:
                entries = probe.read_values(_SCCM_REG_KEYS["current_user"])
                if entries:
                    # SMS\CurrentUser usually carries two values: ``UserSID`` (the
                    # logged-on SID) and ``Session`` (the WTS session id). PS1
                    # picks index 1 from the hashtable, which depends on Windows
                    # GetValueNames() enumeration order. To stay deterministic
                    # across hosts, find whichever value looks like a real SID
                    # ("S-1-...") and use that. Falls back to PS1's original
                    # heuristic (single-value → take it) when no SID-looking
                    # value is present.
                    sid_like = [data for _name, data in entries if data and data.startswith("S-1-")]
                    if sid_like:
                        user_sid: Optional[str] = sid_like[0]
                    else:
                        non_empty = [data for _name, data in entries if data]
                        if len(non_empty) == 1:
                            user_sid = non_empty[0]
                        else:
                            logger.warning(
                                "registry: no SID-shaped value under SMS\\CurrentUser on %s (%d entries)",
                                hostname,
                                len(entries),
                            )
                            user_sid = None
                    if user_sid:
                        yield {
                            "hostname": hostname,
                            "user_name": user_sid,
                            "computer_sid": host.get("sid"),
                            "source": "RemoteRegistry-CurrentUser",
                            "domain": ctx.domain,
                        }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "registry_current_users")


# -- MSSQL SQL-server registry probe (ForceEncryption / ExtendedProtection) --

_MSSQL_REG_PATHS = [
    # PS1 ConfigManBearPig.ps1 lines 2820-2829 — versioned paths for every
    # SQL Server release back to SQL 2012, plus the legacy default path.
    r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",
    r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",
    r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL14.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",
    r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",
    r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL12.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",
    r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL11.MSSQLSERVER\MSSQLServer\SuperSocketNetLib",
    r"SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL.1\MSSQLServer\SuperSocketNetLib",
    r"SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib",
]


@app.resource(name="registry_mssql_settings", parallelized=False, columns=raw_table_asset("registry_mssql_settings"))
@with_log_context(phase="RemoteRegistry")
def registry_mssql_settings(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield SQL-host registry settings — ``force_encryption``,
    ``extended_protection``, plus the LSA flags PS1 emits alongside
    them (``disable_loopback_check``, ``restrict_receiving_ntlm_traffic``).

    Mirrors PS1's ``Get-MssqlEpaSettingsViaRemoteRegistry`` (lines
    2810-2961). The LSA flags are technically general-OS settings, but
    PS1 only emits them on SQL hosts (the function only runs per SQL
    host), so we match that scope here.
    """
    if not ctx.method_enabled("RemoteRegistry"):
        return
    discovered = ctx.sccm_discovered_hosts()
    seen: set[str] = set()
    for host_row in per_host_iter(ctx.target_hosts_snapshot()):
        hostname = host_row["hostname"]
        short = (hostname or "").split(".", 1)[0].lower()
        fqdn = (hostname or "").lower()
        if discovered and short not in discovered and fqdn not in discovered:
            continue
        if fqdn in seen:
            continue
        seen.add(fqdn)
        if ctx.target_queue is not None and ctx.target_queue.get_status(hostname, "registry_mssql_settings") == "done":
            continue
        with _RegistryProbe(hostname, ctx.domain, ctx.username, ctx.password) as probe:
            if probe is not None:
                force_encryption = None
                extended_protection = None
                for path in _MSSQL_REG_PATHS:
                    fe_raw = probe.read_dword(path, "ForceEncryption")
                    if fe_raw is None:
                        continue
                    force_encryption = "Yes" if fe_raw == 1 else "No"
                    ep_raw = probe.read_dword(path, "ExtendedProtection")
                    if ep_raw == 0:
                        extended_protection = "Off"
                    elif ep_raw == 1:
                        extended_protection = "Allowed"
                    elif ep_raw == 2:
                        extended_protection = "Required"
                    break
                if force_encryption is not None:
                    # ``DisableLoopbackCheck`` at HKLM\SYSTEM\CurrentControlSet\Control\Lsa.
                    # PS1 maps 0 → "Enabled" (the loopback check is ON, the value
                    # is "disabled" in the sense of the override flag), 1 → "Disabled".
                    # Default when missing is "Enabled".
                    disable_loopback_check = "Enabled"
                    lb_raw = probe.read_dword(
                        r"SYSTEM\CurrentControlSet\Control\Lsa", "DisableLoopbackCheck"
                    )
                    if lb_raw == 1:
                        disable_loopback_check = "Disabled"
                    elif lb_raw not in (None, 0):
                        disable_loopback_check = f"Unknown ({lb_raw})"

                    # ``RestrictReceivingNtlmTraffic`` at
                    # HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0. PS1 maps
                    # 0 → "Off", 1 → "Deny_All", 2 → "Deny_Inbound_Explicit".
                    # Default when missing is "Off".
                    restrict_ntlm = "Off"
                    ntlm_raw = probe.read_dword(
                        r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
                        "RestrictReceivingNtlmTraffic",
                    )
                    if ntlm_raw == 1:
                        restrict_ntlm = "Deny_All"
                    elif ntlm_raw == 2:
                        restrict_ntlm = "Deny_Inbound_Explicit"
                    elif ntlm_raw not in (None, 0):
                        restrict_ntlm = f"Unknown ({ntlm_raw})"

                    yield {
                        "hostname": fqdn,
                        "force_encryption": force_encryption,
                        "extended_protection": extended_protection,
                        "disable_loopback_check": disable_loopback_check,
                        "restrict_receiving_ntlm_traffic": restrict_ntlm,
                        "source": "RemoteRegistry-MssqlSettings",
                        "domain": ctx.domain,
                    }
        if ctx.target_queue is not None:
            ctx.target_queue.mark_done(hostname, "registry_mssql_settings")


# -- MSSQL EPA prelogin probe ------------------------------------------------

_TDS_PRELOGIN_VERSION = 0x00
_TDS_PRELOGIN_ENCRYPTION = 0x01
_TDS_PRELOGIN_INSTOPT = 0x02
_TDS_PRELOGIN_THREADID = 0x03
_TDS_PRELOGIN_MARS = 0x04
_TDS_PRELOGIN_TERMINATOR = 0xFF


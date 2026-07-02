"""MSSQL auth/EPA wiring on top of the shared ``openhound_collector_common`` client.

This is the thin MSSQL-specific adapter (plan Stage 2, Tasks 2.1 + 2.2). It does
three things and nothing more:

1. :class:`CollectionConfig` reads the ``SOURCES__MSSQL__*`` env vars that
   ``main.py`` sets from the CLI flags, into one plain dataclass.
2. :func:`build_auth` / :func:`build_ldap_auth` translate that config into the
   shared client's :class:`~openhound_collector_common.clients.mssql.Auth` (SQL
   path) and :class:`~openhound_collector_common.clients.ad.LdapAuth` (LDAP path).
3. :func:`connect` / :func:`detect_epa` are one-line wrappers that hand the built
   auth to the shared client. The connection-strategy waterfall, the
   stop-on-auth-error lockout safety, the TLS-1.2 EPA cap, and the EPA probe
   matrix all live in the shared client — this layer only *selects the mode and
   SPN*, per the design spec (§2.1 / §9).

Auth-mode priority (matches the Go binary and the shared client docs): pass-the-
ticket (Kerberos only) → pass-the-hash → password → current-user SSPI. SSPI is
gated behind ``sys.platform == "win32"``. The EPA "Allowed/Required" ambiguity
that arises under SSPI is preserved verbatim by the shared client (we do not
collapse it here).
"""
from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from typing import Optional

from openhound_collector_common.clients.ad import LdapAuth
from openhound_collector_common.clients.auth import split_user_domain
from openhound_collector_common.logging import log_context  # noqa: F401  (registers logger.verbose)
from openhound_collector_common.clients.mssql import (
    Auth,
    MssqlConnection,
    default_spn,
    detect_epa as _shared_detect_epa,
    parse_target,
)

logger = logging.getLogger(__name__)


def _env(name: str) -> Optional[str]:
    """Read a ``SOURCES__MSSQL__<name>`` env var, treating blank as unset."""
    value = os.environ.get(f"SOURCES__MSSQL__{name}")
    if value is not None and value.strip() == "":
        # main.py drops blanks, but be defensive: a blank string is "unset".
        return None
    return value


def _env_bool(name: str) -> bool:
    """Read a boolean ``SOURCES__MSSQL__<name>`` toggle (``"true"`` => True)."""
    value = _env(name)
    return bool(value) and value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    """Read an int ``SOURCES__MSSQL__<name>``; fall back to *default* on garbage."""
    value = _env(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning("SOURCES__MSSQL__%s=%r is not an int; using default %d", name, value, default)
        return default


@dataclass
class CollectionConfig:
    """All MSSQL collection settings, read from ``SOURCES__MSSQL__*`` env vars.

    ``main.py`` maps every CLI flag to one of these env vars before the source
    factory runs (CLI wins). :meth:`from_env` rebuilds this dataclass from them so
    the collection code never touches ``os.environ`` directly.
    """

    # --- SQL authentication ---
    user: Optional[str] = None
    password: Optional[str] = None
    nt_hash: Optional[str] = None
    kerberos_ticket: Optional[str] = None  # base64 .kirbi / KRB-CRED
    # --- LDAP/AD authentication (SPN discovery, SID resolution, EPA) ---
    ldap_user: Optional[str] = None
    ldap_password: Optional[str] = None
    ldap_nt_hash: Optional[str] = None
    ldap_kerberos_ticket: Optional[str] = None
    # --- connection / discovery ---
    targets: Optional[str] = None
    domain: str = ""
    dc: Optional[str] = None
    dns_resolver: Optional[str] = None
    proxy: Optional[str] = None
    # --- collection toggles ---
    scan_all_computers: bool = False
    scan_all_computer_ports: str = "1433"
    skip_private_address: bool = False
    domain_enum_only: bool = False
    skip_linked_servers: bool = False
    collect_from_linked: bool = False
    skip_ad_nodes: bool = False
    disable_nontraversable_edges: bool = False
    disable_possible_edges: bool = False
    skip_ip_dedupe: bool = False
    # --- performance ---
    linked_timeout: int = 300
    port_check_timeout: int = 2
    memory_threshold: int = 90
    workers: int = 0
    # --- output ---
    temp_dir: Optional[str] = None
    log_per_target: bool = False

    @classmethod
    def from_env(cls) -> "CollectionConfig":
        """Build the config from the ``SOURCES__MSSQL__*`` environment."""
        cfg = cls(
            user=_env("USER"),
            password=_env("PASSWORD"),
            nt_hash=_env("NT_HASH"),
            kerberos_ticket=_env("KERBEROS_TICKET"),
            ldap_user=_env("LDAP_USER"),
            ldap_password=_env("LDAP_PASSWORD"),
            ldap_nt_hash=_env("LDAP_NT_HASH"),
            ldap_kerberos_ticket=_env("LDAP_KERBEROS_TICKET"),
            targets=_env("TARGETS"),
            domain=_env("DOMAIN") or "",
            dc=_env("DC"),
            dns_resolver=_env("DNS_RESOLVER"),
            proxy=_env("PROXY"),
            scan_all_computers=_env_bool("SCAN_ALL_COMPUTERS"),
            scan_all_computer_ports=_env("SCAN_ALL_COMPUTER_PORTS") or "1433",
            skip_private_address=_env_bool("SKIP_PRIVATE_ADDRESS"),
            domain_enum_only=_env_bool("DOMAIN_ENUM_ONLY"),
            skip_linked_servers=_env_bool("SKIP_LINKED_SERVERS"),
            collect_from_linked=_env_bool("COLLECT_FROM_LINKED"),
            skip_ad_nodes=_env_bool("SKIP_AD_NODES"),
            disable_nontraversable_edges=_env_bool("DISABLE_NONTRAVERSABLE_EDGES"),
            disable_possible_edges=_env_bool("DISABLE_POSSIBLE_EDGES"),
            skip_ip_dedupe=_env_bool("SKIP_IP_DEDUPE"),
            linked_timeout=_env_int("LINKED_TIMEOUT", 300),
            port_check_timeout=_env_int("PORT_CHECK_TIMEOUT", 2),
            memory_threshold=_env_int("MEMORY_THRESHOLD", 90),
            workers=_env_int("WORKERS", 0),
            temp_dir=_env("TEMP_DIR"),
            log_per_target=_env_bool("LOG_PER_TARGET"),
        )
        logger.debug("Loaded CollectionConfig from env (user=%s, targets=%s, domain=%s, workers=%d)",
                     cfg.user, cfg.targets, cfg.domain, cfg.workers)
        return cfg


def _domain_for(username: Optional[str], cfg: CollectionConfig) -> str:
    """Return the AD domain for *username*, preferring an embedded ``DOMAIN\\``/``@``.

    A bare login (no domain in the name) falls back to ``cfg.domain``. An empty
    string means "no domain" -> a plain SQL login.
    """
    if not username:
        return ""
    domain, _user = split_user_domain(username, cfg.domain)
    return domain


def _sam_for(username: Optional[str], cfg: CollectionConfig) -> str:
    """Return just the sAMAccountName from ``DOMAIN\\user``/``user@domain``/bare."""
    if not username:
        return ""
    _domain, user = split_user_domain(username, cfg.domain)
    return user


def build_auth(cfg: CollectionConfig, *, spn: Optional[str] = None) -> Auth:
    """Build the SQL :class:`Auth` from *cfg*.

    Mode selection mirrors the Go binary's priority and the shared client's
    ``_login`` dispatch: pass-the-ticket → pass-the-hash → password → SSPI.

    * ``--ticket`` set                  -> pass-the-ticket (Kerberos only).
    * ``--nt-hash`` set                 -> pass-the-hash (domain NTLMv2).
    * ``--user`` + ``--password`` set   -> password auth. A domain in the user
      name (``DOMAIN\\u`` / ``u@domain``) or ``--domain`` makes it domain NTLMv2
      (+EPA channel binding); a bare ``user`` is a plain SQL login.
    * nothing set                       -> current-user SSPI (Windows only).
    """
    domain = _domain_for(cfg.user, cfg)
    sam = _sam_for(cfg.user, cfg)

    if cfg.kerberos_ticket:
        # Pass-the-ticket: Kerberos only, no NTLM fallback (design D12).
        logger.verbose("SQL auth: pass-the-ticket (Kerberos) for %s\\%s", domain, sam)
        return Auth(username=sam, kerberos_ticket=cfg.kerberos_ticket,
                    domain=domain, spn=spn, kdc_host=cfg.dc)
    if cfg.nt_hash:
        # Pass-the-hash: domain NTLMv2 with the supplied NT hash.
        logger.verbose("SQL auth: pass-the-hash for %s\\%s", domain, sam)
        return Auth(username=sam, nt_hash=cfg.nt_hash, domain=domain, spn=spn, kdc_host=cfg.dc)
    if cfg.user and cfg.password is not None:
        # Password auth. Domain-shaped login => domain NTLMv2 (+EPA); else SQL login.
        if domain:
            logger.verbose("SQL auth: domain NTLMv2 (+EPA) for %s\\%s", domain, sam)
        else:
            logger.verbose("SQL auth: SQL login as %s", sam)
        return Auth(username=sam, password=cfg.password, domain=domain, spn=spn, kdc_host=cfg.dc)

    # No explicit credentials: current-user SSPI (Windows SSO). Gate to Windows.
    if sys.platform != "win32":
        logger.error("SQL auth: no credentials supplied and SSPI is Windows-only (platform=%s)", sys.platform)
        raise RuntimeError(
            "no SQL credentials supplied; current-user SSPI requires Windows. "
            "Pass --user/--password (or --nt-hash / --ticket)."
        )
    logger.verbose("SQL auth: current-user SSPI (Windows SSO)")
    return Auth(use_sspi=True, domain=domain, spn=spn, kdc_host=cfg.dc)


def build_ldap_auth(cfg: CollectionConfig) -> LdapAuth:
    """Build the LDAP :class:`LdapAuth` from *cfg*.

    Uses the ``--ldap-*`` credentials when supplied; otherwise falls back to the
    SQL credentials when they're domain-shaped (matches the Go binary, which
    reuses domain SQL creds for LDAP when LDAP creds are unset). A bare SQL login
    (no domain) is NOT reused — that would be a SQL-only account with no AD bind.
    """
    # Prefer explicit LDAP creds.
    if cfg.ldap_kerberos_ticket:
        logger.verbose("LDAP auth: pass-the-ticket (Kerberos)")
        return LdapAuth(username=cfg.ldap_user, kerberos_ticket=cfg.ldap_kerberos_ticket)
    if cfg.ldap_nt_hash:
        logger.verbose("LDAP auth: pass-the-hash")
        return LdapAuth(username=cfg.ldap_user, nt_hash=cfg.ldap_nt_hash)
    if cfg.ldap_user and cfg.ldap_password is not None:
        logger.verbose("LDAP auth: explicit LDAP password for %s", cfg.ldap_user)
        return LdapAuth(username=cfg.ldap_user, password=cfg.ldap_password)

    # Fall back to SQL creds when they carry a domain (domain-shaped).
    if _domain_for(cfg.user, cfg):
        if cfg.kerberos_ticket:
            logger.verbose("LDAP auth: falling back to SQL pass-the-ticket")
            return LdapAuth(username=cfg.user, kerberos_ticket=cfg.kerberos_ticket)
        if cfg.nt_hash:
            logger.verbose("LDAP auth: falling back to SQL pass-the-hash")
            return LdapAuth(username=cfg.user, nt_hash=cfg.nt_hash)
        if cfg.password is not None:
            logger.verbose("LDAP auth: falling back to SQL domain password for %s", cfg.user)
            return LdapAuth(username=cfg.user, password=cfg.password)

    # Nothing usable: current-user SSPI (Windows) or anonymous, decided by AdClient.
    logger.verbose("LDAP auth: no explicit creds; deferring to current-user SSPI/anonymous")
    return LdapAuth()


def spn_for_target(target: str) -> str:
    """Derive the conventional ``MSSQLSvc/<host>:<port>`` SPN for *target*."""
    parsed = parse_target(target)
    return default_spn(parsed.host, parsed.port)


def connect(target: str, cfg: CollectionConfig, *, timeout: int = 15) -> MssqlConnection:
    """Open an authenticated :class:`MssqlConnection` to *target* using *cfg*.

    The SPN is pinned to the target's host so EPA channel binding and Kerberos
    request the right service. The shared client owns the strategy waterfall and
    stops on auth errors (lockout safety).
    """
    spn = spn_for_target(target)
    auth = build_auth(cfg, spn=spn)
    logger.info("Connecting to %s (SPN %s)", target, spn)
    return MssqlConnection().connect(target, auth, timeout=timeout)


def detect_epa(target: str, cfg: CollectionConfig, *, timeout: int = 15) -> dict:
    """Run EPA detection against *target* using the LDAP/domain credentials.

    Returns the shared client's verdict dict
    (``forceEncryption`` / ``extendedProtection`` / ``strictEncryption`` + extras).
    EPA probing needs domain NTLM credentials, so we build an :class:`Auth` from
    the LDAP creds (falling back to SQL domain creds). When only a bare SQL login
    or SSPI is available, EPA is attempted with whatever Windows auth we can form;
    a non-domain SQL login cannot probe EPA and the shared client raises.
    """
    ldap = build_ldap_auth(cfg)
    spn = spn_for_target(target)

    # Translate the LdapAuth (or SSPI) into the shared client's Auth for probing.
    if ldap.kerberos_ticket:
        logger.verbose("EPA on %s: probing with Kerberos ticket", target)
        domain = _domain_for(ldap.username, cfg)
        auth = Auth(username=_sam_for(ldap.username, cfg), kerberos_ticket=ldap.kerberos_ticket,
                    domain=domain, spn=spn, kdc_host=cfg.dc)
    elif ldap.nt_hash:
        logger.verbose("EPA on %s: probing with pass-the-hash", target)
        domain = _domain_for(ldap.username, cfg)
        auth = Auth(username=_sam_for(ldap.username, cfg), nt_hash=ldap.nt_hash,
                    domain=domain, spn=spn, kdc_host=cfg.dc)
    elif ldap.username and ldap.password is not None:
        domain = _domain_for(ldap.username, cfg)
        logger.verbose("EPA on %s: probing with domain password for %s\\%s",
                       target, domain, _sam_for(ldap.username, cfg))
        auth = Auth(username=_sam_for(ldap.username, cfg), password=ldap.password,
                    domain=domain, spn=spn, kdc_host=cfg.dc)
    elif sys.platform == "win32":
        logger.verbose("EPA on %s: probing with current-user SSPI", target)
        auth = Auth(use_sspi=True, domain=cfg.domain, spn=spn, kdc_host=cfg.dc)
    else:
        # No domain creds and no SSPI -> EPA cannot be probed.
        logger.warning("EPA on %s: no domain credentials available; skipping EPA probe", target)
        raise RuntimeError("EPA detection requires domain credentials (or Windows SSPI)")

    return _shared_detect_epa(target, auth, timeout=timeout)


__all__ = [
    "CollectionConfig",
    "build_auth",
    "build_ldap_auth",
    "connect",
    "detect_epa",
    "spn_for_target",
]

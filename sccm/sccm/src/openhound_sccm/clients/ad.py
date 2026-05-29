"""LDAP / Active Directory client for SCCM data collection.

A focused subset of `sccm/ConfigManBearPig/python/lib/ad_resolver.py` covering only
what the OpenHound `source.py` needs at collect time. We do **not** vendor the full
550-LOC original verbatim — most of its surface (cache management, name resolution
via NTAccount fallback chains, group membership traversal) is convert-time
post-processing that has moved to ``transforms.py`` SQL views and ``lookup.py``.

What stays here:
  - `ADClient.bind()` — opens an authenticated ldap3 connection, auto-detecting
    the right transport + signing/CBT combo (no CLI knobs, no lockouts).
  - `ADClient.paged_search(filter, attributes, base=None)` — uses ldap3's paged search,
    yields each entry's attributes as a flat dict; binary SIDs/GUIDs are decoded.
  - `bytes_to_sid(b)` and `bytes_to_guid(b)` — public helpers used by source.py.

Auto-detection is lockout-safe: only AD's ``data 52e`` family of LDAP result-49
sub-codes (bad/locked/expired/disabled credentials) increment ``badPwdCount``.
Protocol-level rejections — ``strongerAuthRequired`` (result 8), CBT mismatch
(``data 80090346``), TLS handshake / connect failures — are returned *before*
the password is validated, so retrying with a different transport profile after
one of those does not advance the lockout counter. ``bind()`` therefore tries
each profile in order, propagating immediately on a credential-class failure
and continuing only on protocol/transport errors.
"""

from __future__ import annotations

import importlib
import ipaddress
import logging
import socket
import struct
import sys

from dataclasses import dataclass
from typing import Any, Iterable

from ldap3 import (
    ALL,
    AUTO_BIND_NO_TLS,
    AUTO_BIND_NONE,
    AUTO_BIND_TLS_BEFORE_BIND,
    KERBEROS,
    NTLM,
    SASL,
    SUBTREE,
    Connection,
    Server,
)
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.core.results import RESULT_SUCCESS

# ENCRYPT / TLS_CHANNEL_BINDING were added in ldap3 2.10.2rc4. Newer DCs that
# enforce LDAP signing or channel binding need these constants. We try-import
# so the file still loads against older ldap3 if a venv is mid-upgrade — the
# fallback strings won't actually let signing / CBT *work* on those older
# versions (Connection rejects the kwargs), but the import won't crash so
# callers that don't request signing / CBT continue to function.
try:
    from ldap3 import ENCRYPT, TLS_CHANNEL_BINDING
except ImportError:  # pragma: no cover - belt & braces for older ldap3
    ENCRYPT = "ENCRYPT"
    TLS_CHANNEL_BINDING = "TLS_CHANNEL_BINDING"


# Integrated auth (SASL GSSAPI / Kerberos) requires the OS Kerberos backend.
# ldap3 picks ``gssapi`` on POSIX and ``winkerberos`` on Windows; both are
# optional installs. We try-import both up-front so ``bind()`` can skip the
# Kerberos profile cleanly when no backend is available, rather than crashing
# inside ldap3's SASL state machine.
def _integrated_auth_available() -> bool:
    try:
        importlib.import_module("gssapi")
        return True
    except ImportError:
        pass
    try:
        importlib.import_module("winkerberos")
        return True
    except ImportError:
        pass
    return False


_INTEGRATED_AUTH_AVAILABLE = _integrated_auth_available()


def _current_user_ntlm_available() -> bool:
    if sys.platform != "win32":
        return False
    try:
        importlib.import_module("sspi")
        importlib.import_module("sspicon")
        importlib.import_module("win32security")
        return True
    except ImportError:
        return False


_CURRENT_USER_NTLM_AVAILABLE = _current_user_ntlm_available()

logger = logging.getLogger(__name__)


def _is_ip_address(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
        return True
    except ValueError:
        return False


def _ip_address_text(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def _reverse_dns_hostname(value: str | None) -> str | None:
    ip_text = _ip_address_text(value)
    if ip_text is None:
        return None

    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip_text)
    except OSError as exc:
        logger.debug("Reverse DNS lookup for %s failed: %s", ip_text, exc)
        return None

    for candidate in (hostname, *aliases):
        candidate = candidate.strip().rstrip(".")
        if candidate and not _is_ip_address(candidate):
            return candidate
    return None


class _SSPICurrentUserNtlmClient:
    """ldap3 NTLM client shim backed by the current Windows SSPI credentials."""

    def __init__(self) -> None:
        import sspi

        self._auth = sspi.ClientAuth("NTLM")
        self._challenge: bytes | None = None

    @staticmethod
    def _buffer_bytes(sec_buffer) -> bytes:
        if not sec_buffer or len(sec_buffer) == 0:
            return b""
        return bytes(sec_buffer[0].Buffer or b"")

    def create_negotiate_message(self) -> bytes:
        _, sec_buffer = self._auth.authorize(None)
        return self._buffer_bytes(sec_buffer)

    def parse_challenge_message(self, message: bytes) -> bool:
        self._challenge = bytes(message)
        return True

    def create_authenticate_message(self) -> bytes:
        if self._challenge is None:
            return b""
        _, sec_buffer = self._auth.authorize(self._challenge)
        return self._buffer_bytes(sec_buffer)

    def seal(self, message: bytes) -> bytes:
        encrypted, trailer = self._auth.encrypt(message)
        return trailer + encrypted

    def unseal(self, sealed_message: bytes) -> bytes:
        import sspicon

        sizes = self._auth.ctxt.QueryContextAttributes(sspicon.SECPKG_ATTR_SIZES)
        trailer_size = int(sizes["SecurityTrailer"])
        trailer = sealed_message[:trailer_size]
        encrypted = sealed_message[trailer_size:]
        return self._auth.decrypt(encrypted, trailer)


# ---------------------------------------------------------------------------
# Bind-error classification. AD returns LDAP result code 49 (invalidCredentials)
# with an embedded ``data XXXX`` substring identifying the reason. Only the
# credential-class codes below increment ``badPwdCount`` (the lockout counter);
# treating any of them as "retry with a different transport profile" risks
# locking the account out across our attempt chain, so we propagate immediately.
# Everything else (strongerAuthRequired, CBT mismatch, TLS issues) is returned
# before the password is validated and is safe to retry.
# ---------------------------------------------------------------------------

# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-status_codes
# 52e  ERROR_LOGON_FAILURE        — bad password (only this increments badPwdCount)
# 532  ERROR_PASSWORD_EXPIRED
# 533  ERROR_ACCOUNT_DISABLED
# 701  ERROR_ACCOUNT_EXPIRED
# 773  ERROR_PASSWORD_MUST_CHANGE
# 775  ERROR_ACCOUNT_LOCKED_OUT  — already locked; don't keep poking it
_CREDENTIAL_FAILURE_SUBCODES = {"52e", "532", "533", "701", "773", "775"}


def _bind_error_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}".lower()


def _is_credential_failure(exc: BaseException) -> bool:
    """Stop-the-chain check: True for any bind error tied to the credential
    itself (bad password, locked, expired, disabled). Returning True here
    means "do not retry against another transport — we'd just rack up
    badPwdCount increments without changing the outcome."
    """
    text = _bind_error_text(exc)
    if "invalidcredentials" not in text:
        return False
    return any(f"data {code}" in text for code in _CREDENTIAL_FAILURE_SUBCODES)


def _is_stronger_auth_required(exc: BaseException) -> bool:
    """True when the DC rejected the bind because signing/sealing is required
    (LDAP result code 8). Safe to retry with hardened transport."""
    text = _bind_error_text(exc)
    return (
        "strongerauthrequired" in text
        or "stronger auth" in text
        or "stronger authentication" in text
        or "sign or seal" in text
    )


def bytes_to_sid(value: bytes | str | None) -> str | None:
    """Convert a binary objectSid (8+ bytes) into S-1-5-21-... string form.

    ldap3 sometimes returns SIDs already as strings; pass-through in that case.
    """
    if value is None:
        return None
    if isinstance(value, str):
        if value.startswith("S-1-"):
            return value
        # Some servers return the binary as a base64 or hex string — best effort decode
        return value
    if not isinstance(value, (bytes, bytearray)) or len(value) < 8:
        return None
    revision = value[0]
    sub_authority_count = value[1]
    identifier_authority = int.from_bytes(value[2:8], "big")
    sub_authorities = []
    for i in range(sub_authority_count):
        offset = 8 + i * 4
        sub_authorities.append(struct.unpack("<I", value[offset:offset + 4])[0])
    parts = [str(revision), str(identifier_authority)] + [str(sa) for sa in sub_authorities]
    return "S-" + "-".join(parts)


def bytes_to_guid(value: bytes | str | None) -> str | None:
    """Convert a binary objectGUID (16 bytes) into the canonical 8-4-4-4-12 string."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if not isinstance(value, (bytes, bytearray)) or len(value) != 16:
        return None
    # objectGUID is little-endian for the first three groups
    return "{}-{}-{}-{}-{}".format(
        value[0:4][::-1].hex(),
        value[4:6][::-1].hex(),
        value[6:8][::-1].hex(),
        value[8:10].hex(),
        value[10:16].hex(),
    )


@dataclass
class ADCredentials:
    domain: str
    domain_controller: str | None = None
    username: str | None = None
    password: str | None = None
    # Optional port override. ``None`` lets ``ADClient.bind()`` auto-detect the
    # transport (LDAPS 636 → StartTLS 389 → LDAP 389+sign/seal). Setting a
    # value pins the port and narrows the attempt chain accordingly: 636/3269
    # → LDAPS; everything else → LDAP (with NTLM sign/seal when creds are
    # supplied, falling back to plain LDAP only as a last resort).
    port: int | None = None


# Attempt profile for ADClient.bind(). Each entry encodes a (transport,
# hardening, auth_mode) tuple; bind() walks them in order until one binds
# successfully or until a credential-class failure stops the chain.
#
# auth_mode controls the SASL/bind mechanism:
#   "ntlm"        — NTLM bind with explicit username/password. Required for
#                   session_security (sign/seal) and CBT.
#   "kerberos"    — SASL GSSAPI / Kerberos using the OS credential cache
#                   (winkerberos on Windows, gssapi on POSIX). No explicit
#                   creds; uses the current user's TGT. CBT is supplied by
#                   ldap3's SASL Kerberos path when on TLS.
#   "sspi_ntlm"   — NTLM using the current Windows logon session via SSPI.
#                   No explicit username/password; useful when Kerberos cannot
#                   build an LDAP SPN, such as --dc <IP> with no reverse DNS.
#   "anonymous"   — Last-ditch fallback. AD blocks every meaningful search
#                   from anonymous so we only emit this profile when nothing
#                   else is possible (and we log a clear warning).
@dataclass(frozen=True)
class _BindAttempt:
    label: str
    use_ssl: bool
    port: int
    start_tls: bool
    session_security: bool  # NTLM sign+seal — requires NTLM credentials
    channel_binding: bool   # TLS CBT — requires TLS + NTLM credentials
    auth_mode: str = "ntlm"


class ADClient:
    """Thin ldap3 wrapper used by OpenHound source resources.

    Auto-detects the LDAP transport and security envelope at ``bind()`` time:
    LDAPS:636 + CBT → StartTLS:389 + CBT → LDAP:389 + NTLM sign/seal. The walk
    is lockout-safe — see the module docstring and ``_is_credential_failure``.
    """

    def __init__(self, credentials: ADCredentials):
        self.creds = credentials
        self.base_dn = ",".join(f"DC={part}" for part in credentials.domain.split("."))
        self._conn: Connection | None = None

    # ------------------------------------------------------------------ bind --

    def bind(self) -> Connection:
        if self._conn is not None and self._conn.bound:
            return self._conn

        attempts, host = self._prepare_attempts_and_host(self._build_attempt_plan())
        self._log_credential_summary(attempts)

        last_exc: BaseException | None = None
        for attempt in attempts:
            try:
                self._conn = self._open_connection(host=host, attempt=attempt)
                logger.info(
                    "LDAP connected: %s:%d (auth=%s, profile=%s, principal=%s)",
                    host,
                    attempt.port,
                    attempt.auth_mode,
                    attempt.label,
                    self._principal_label(attempt.auth_mode),
                )
                return self._conn
            except LDAPException as exc:
                if _is_credential_failure(exc):
                    # Bad / locked / expired / disabled credentials. Falling
                    # through to another transport would just keep advancing
                    # badPwdCount without ever succeeding.
                    raise
                last_exc = exc
                logger.debug(
                    "LDAP bind via %s failed (%s); trying next profile",
                    attempt.label,
                    exc,
                )
                continue
            except OSError as exc:
                # socket.gaierror, ConnectionRefused, TLS handshake — port
                # closed, DNS miss, or cert problem. No auth was attempted;
                # safe to fall through.
                last_exc = exc
                logger.debug(
                    "LDAP transport to %s:%d (%s) failed: %s; trying next profile",
                    host,
                    attempt.port,
                    attempt.label,
                    exc,
                )
                continue
            except Exception as ex:
                if attempt.auth_mode == "kerberos":
                    last_exc = exc
                    logger.debug(
                        "LDAP bind via %s failed (%s); trying next profile",
                        attempt.label,
                        ex,
                    )
                    continue
                raise

        if last_exc:
            raise last_exc
        raise RuntimeError("LDAP connection failed before bind was attempted")

    def _principal_label(self, auth_mode: str) -> str:
        if auth_mode == "ntlm":
            return self.creds.username or "<ntlm-no-user>"
        if auth_mode == "kerberos":
            # ldap3 / winkerberos read the principal from the OS Kerberos
            # cache (Windows LSA / klist). Looking up which principal that
            # actually is would require querying SSPI; surface "current user"
            # as the human-readable hint and rely on `klist` for diagnostics.
            return "current OS user (Kerberos TGT)"
        if auth_mode == "sspi_ntlm":
            return "current OS user (NTLM SSPI)"
        return "anonymous"

    def _log_credential_summary(self, attempts: list[_BindAttempt]) -> None:
        """Announce which auth mode the upcoming bind attempts will use.

        We log this before the first attempt so that operators reading the
        log can immediately see whether NTLM, Kerberos, or anonymous is in
        play — important because each has different failure modes (NTLM:
        wrong password → lockout; Kerberos: missing TGT → bind fails; anon:
        bind succeeds but every search returns ``operationsError``).
        """
        modes = {a.auth_mode for a in attempts}
        if modes == {"anonymous"}:
            if not _INTEGRATED_AUTH_AVAILABLE:
                logger.warning(
                    "LDAP auth: no credentials supplied and no Kerberos "
                    "backend is installed (winkerberos on Windows, gssapi "
                    "on POSIX) — falling back to anonymous bind. AD rejects "
                    "every meaningful search from anonymous binds. Install "
                    "winkerberos (`uv add winkerberos`) or pass --username "
                    "and --password."
                )
            else:
                # We shouldn't actually hit this branch — when integrated
                # auth is available we always emit a Kerberos profile — but
                # keep the warning as a safety net in case the planning rules
                # change in the future.
                logger.warning(
                    "LDAP auth: falling back to anonymous bind. Searches "
                    "will fail with `operationsError` until credentials or "
                    "a valid Kerberos TGT are available."
                )
            return
        if "kerberos" in modes:
            if self.creds.username and not self.creds.password:
                logger.info(
                    "LDAP auth: integrated (Kerberos via OS cred cache). "
                    "Configured username '%s' has no password — ignoring it "
                    "and using the current OS user's TGT instead.%s",
                    self.creds.username,
                    (
                        " Current-user NTLM via Windows SSPI is available "
                        "as a fallback."
                        if "sspi_ntlm" in modes
                        else " Set --password / SOURCES__SCCM__PASSWORD "
                        "to force NTLM with that account."
                    ),
                )
            else:
                logger.info(
                    "LDAP auth: integrated (Kerberos via OS cred cache; "
                    "principal taken from the current user's TGT).%s",
                    (
                        " Current-user NTLM via Windows SSPI is available "
                        "as a fallback."
                        if "sspi_ntlm" in modes
                        else ""
                    ),
                )
        elif "sspi_ntlm" in modes:
            logger.info(
                "LDAP auth: integrated NTLM via Windows SSPI "
                "(principal taken from the current OS logon session)."
            )
        elif "ntlm" in modes:
            logger.info("LDAP auth: NTLM as %s", self.creds.username)

    def _prepare_attempts_and_host(
        self,
        attempts: list[_BindAttempt],
    ) -> tuple[list[_BindAttempt], str]:
        host = self.creds.domain_controller or self.creds.domain
        modes = {a.auth_mode for a in attempts}
        if "kerberos" not in modes or not _is_ip_address(self.creds.domain_controller):
            return attempts, host

        rdns_hostname = _reverse_dns_hostname(self.creds.domain_controller)
        if rdns_hostname:
            logger.info(
                "LDAP auth: reverse DNS resolved Kerberos DC IP '%s' to "
                "'%s'; using that hostname so SSPI can build the LDAP service "
                "principal name.",
                self.creds.domain_controller,
                rdns_hostname,
            )
            return attempts, rdns_hostname

        if "sspi_ntlm" in modes:
            attempts = [a for a in attempts if a.auth_mode != "kerberos"]
            logger.info(
                "LDAP auth: --dc '%s' is an IP address and reverse DNS did "
                "not return a hostname; skipping Kerberos and using "
                "current-user NTLM via Windows SSPI.",
                self.creds.domain_controller,
            )
            return attempts, host

        logger.warning(
            "LDAP auth: integrated Kerberos is using domain controller '%s', "
            "which is an IP address, and reverse DNS did not return a hostname. "
            "Kerberos/SSPI needs a DC hostname to build the LDAP service "
            "principal name (ldap/<dc-host>); IP addresses commonly fail with "
            "`InitializeSecurityContext: The specified target is unknown or "
            "unreachable`. Fix by omitting --dc so OpenHound resolves a DC "
            "with DNS SRV, or set --dc to the DC FQDN or NetBIOS/NBNS name. "
            "To connect by IP, set --password / SOURCES__SCCM__PASSWORD to "
            "force NTLM.",
            self.creds.domain_controller,
        )
        return attempts, host

    def _bind_host_for_attempts(self, attempts: list[_BindAttempt]) -> str:
        _, host = self._prepare_attempts_and_host(attempts)
        return host

    # ------------------------------------------------------------- planning --

    def _build_attempt_plan(self) -> list[_BindAttempt]:
        """Build the ordered list of bind attempts.

        Picks between four auth modes:
          * NTLM (when explicit ``username`` + ``password`` are set)
          * Kerberos (when no creds and the OS Kerberos backend is importable
            — winkerberos on Windows, gssapi on POSIX). Uses the current user's
            TGT / cred cache; perfect for domain-joined collectors.
          * SSPI NTLM (when no explicit password and Windows SSPI is available).
            Uses the current Windows logon session without handling a password.
          * Anonymous (last resort, when neither of the above applies; AD
            rejects every meaningful search so this is logged loudly).

        Per-mode profile order:
          NTLM      : LDAPS:636+CBT → StartTLS:389+CBT → LDAP:389+sign/seal
          Kerb      : LDAPS:636+CBT → LDAP:389
          SSPI NTLM : LDAPS:636 → StartTLS:389 → LDAP:389+sign/seal
          Anon      : LDAPS:636 → LDAP:389

        With ``creds.port`` set, narrows the chain to that port (636/3269 →
        LDAPS, anything else → LDAP). Same auth-mode selection rules apply.
        """
        has_ntlm = self._has_explicit_ntlm_credentials()
        # When the user only sets a username (no password — common when an
        # env file partially fills SOURCES__SCCM__USERNAME), the NTLM bind
        # path is unreachable. Fall back to integrated auth so the current
        # OS user's Kerberos TGT is used; the configured username is logged
        # as a hint but doesn't drive Kerberos (TGT identity comes from the
        # cred cache, not from an explicit arg).
        has_kerberos = (not has_ntlm) and _INTEGRATED_AUTH_AVAILABLE
        has_current_user_ntlm = (not has_ntlm) and _CURRENT_USER_NTLM_AVAILABLE
        pinned = self.creds.port

        if has_ntlm:
            auth_modes = [("ntlm", "NTLM")]
        else:
            auth_modes: list[tuple[str, str]] = []
            if has_kerberos:
                auth_modes.append(("kerberos", "Kerberos"))
            if has_current_user_ntlm:
                auth_modes.append(("sspi_ntlm", "SSPI-NTLM"))
            if not auth_modes:
                auth_modes.append(("anonymous", "anonymous"))

        def _cbt_capable(auth_mode: str) -> bool:
            # Explicit NTLM can build ldap3 CBTs from the password-derived
            # session key; Kerberos CBT is handled inside ldap3's GSSAPI path.
            # The pywin32 SSPI helper used for current-user NTLM does not expose
            # the channel-binding input buffer we would need here.
            return auth_mode in ("ntlm", "kerberos")

        def _ldaps(auth_mode: str, transport_label: str, port: int) -> _BindAttempt:
            cbt_capable = _cbt_capable(auth_mode)
            return _BindAttempt(
                label=f"LDAPS+CBT+{transport_label}" if cbt_capable else f"LDAPS+{transport_label}",
                use_ssl=True,
                port=port,
                start_tls=False,
                session_security=False,
                channel_binding=cbt_capable,
                auth_mode=auth_mode,
            )

        def _starttls(auth_mode: str, transport_label: str, port: int) -> _BindAttempt:
            cbt_capable = _cbt_capable(auth_mode)
            return _BindAttempt(
                label=f"StartTLS+CBT+{transport_label}" if cbt_capable else f"StartTLS+{transport_label}",
                use_ssl=False,
                port=port,
                start_tls=True,
                session_security=False,
                channel_binding=cbt_capable,
                auth_mode=auth_mode,
            )

        def _ldap_signed(auth_mode: str, transport_label: str, port: int) -> _BindAttempt:
            return _BindAttempt(
                label=f"LDAP+sign/seal+{transport_label}",
                use_ssl=False,
                port=port,
                start_tls=False,
                session_security=True,
                channel_binding=False,
                auth_mode=auth_mode,
            )

        def _ldap_plain(auth_mode: str, transport_label: str, port: int) -> _BindAttempt:
            return _BindAttempt(
                label=f"LDAP+{transport_label}",
                use_ssl=False,
                port=port,
                start_tls=False,
                session_security=False,
                channel_binding=False,
                auth_mode=auth_mode,
            )

        if pinned is not None:
            if pinned in (636, 3269):
                return [
                    _ldaps(auth_mode, transport_label, pinned)
                    for auth_mode, transport_label in auth_modes
                ]
            attempts: list[_BindAttempt] = []
            for auth_mode, transport_label in auth_modes:
                if auth_mode in ("ntlm", "sspi_ntlm"):
                    attempts.append(_ldap_signed(auth_mode, transport_label, pinned))
                    attempts.append(_ldap_plain(auth_mode, transport_label, pinned))
                else:
                    attempts.append(_ldap_plain(auth_mode, transport_label, pinned))
            return attempts

        attempts = []
        for auth_mode, transport_label in auth_modes:
            attempts.append(_ldaps(auth_mode, transport_label, 636))
            if auth_mode in ("ntlm", "sspi_ntlm"):
                attempts.append(_starttls(auth_mode, transport_label, 389))
                attempts.append(_ldap_signed(auth_mode, transport_label, 389))
            else:
                attempts.append(_ldap_plain(auth_mode, transport_label, 389))
        return attempts

    # ---------------------------------------------------------------- helpers --

    def _open_connection(
        self,
        *,
        host: str,
        attempt: _BindAttempt,
    ) -> Connection:
        """Open and bind one Connection with the requested security settings."""
        server = Server(
            host,
            port=attempt.port,
            use_ssl=attempt.use_ssl,
            get_info=ALL,
            connect_timeout=5,
        )

        kwargs: dict[str, Any] = {
            "auto_bind": AUTO_BIND_TLS_BEFORE_BIND if attempt.start_tls else AUTO_BIND_NO_TLS,
            "read_only": True,
            "receive_timeout": 30,
        }
        if attempt.auth_mode == "sspi_ntlm":
            return self._open_current_user_ntlm_connection(server=server, attempt=attempt)
        if attempt.auth_mode == "ntlm":
            kwargs.update(
                {
                    "user": self.creds.username,
                    "password": self.creds.password,
                    "authentication": NTLM,
                }
            )
        elif attempt.auth_mode == "kerberos":
            kwargs.update(
                {
                    "authentication": SASL,
                    "sasl_mechanism": KERBEROS,
                }
            )
        # "anonymous" → leave authentication unset (ldap3 default is ANONYMOUS).
        # ldap3 SASL Kerberos handles CBT internally via the OS GSSAPI/winkerberos
        # backend, so the explicit `channel_binding` kwarg is only relevant for
        # NTLM binds.
        if attempt.session_security:
            kwargs["session_security"] = ENCRYPT
        if attempt.channel_binding and attempt.auth_mode == "ntlm":
            kwargs["channel_binding"] = TLS_CHANNEL_BINDING

        try:
            return Connection(server, **kwargs)
        except TypeError as exc:
            # Older ldap3 versions don't accept session_security /
            # channel_binding kwargs. The dependency floor in pyproject.toml
            # avoids this in practice; the explicit message just makes the
            # failure mode actionable for anyone running an older venv.
            if attempt.session_security or attempt.channel_binding:
                raise RuntimeError(
                    "LDAP signing / channel binding requires ldap3 with "
                    "session_security and channel_binding support. "
                    "Upgrade ldap3 to >=2.10.2rc4."
                ) from exc
            raise

    def _open_current_user_ntlm_connection(
        self,
        *,
        server: Server,
        attempt: _BindAttempt,
    ) -> Connection:
        conn = Connection(
            server,
            auto_bind=AUTO_BIND_NONE,
            authentication=NTLM,
            read_only=True,
            receive_timeout=30,
            session_security=ENCRYPT if attempt.session_security else None,
        )
        conn.open(read_server_info=False)
        if attempt.start_tls and not conn.start_tls(read_server_info=False):
            error = "StartTLS before current-user NTLM bind failed"
            if conn.last_error:
                error = f"{error}: {conn.last_error}"
            conn.unbind()
            raise LDAPBindError(error)

        self._bind_current_user_ntlm(conn)
        conn.refresh_server_info()
        return conn

    def _bind_current_user_ntlm(self, conn: Connection, controls=None) -> None:
        from ldap3.operation.bind import bind_operation

        conn.last_error = None
        with conn.connection_lock:
            if conn.sasl_in_progress:
                return
            conn.sasl_in_progress = True
            try:
                conn.ntlm_client = _SSPICurrentUserNtlmClient()

                request = bind_operation(conn.version, "SICILY_PACKAGE_DISCOVERY", conn.ntlm_client)
                response = conn.post_send_single_response(conn.send("bindRequest", request, controls))
                result = response[0] if conn.strategy.sync else conn.get_response(response)[1]
                packages = (result.get("server_creds") or b"").decode("ascii", errors="ignore").split(";")
                if "NTLM" not in packages:
                    raise LDAPBindError("DC did not advertise the NTLM Sicily package")

                request = bind_operation(conn.version, "SICILY_NEGOTIATE_NTLM", conn.ntlm_client)
                response = conn.post_send_single_response(conn.send("bindRequest", request, controls))
                result = response[0] if conn.strategy.sync else conn.get_response(response)[1]

                if result and result.get("result") == RESULT_SUCCESS:
                    request = bind_operation(
                        conn.version,
                        "SICILY_RESPONSE_NTLM",
                        conn.ntlm_client,
                        result.get("server_creds"),
                    )
                    response = conn.post_send_single_response(conn.send("bindRequest", request, controls))
                    result = response[0] if conn.strategy.sync else conn.get_response(response)[1]

                conn.result = result
                conn.bound = bool(result and result.get("result") == RESULT_SUCCESS)
                if not conn.bound:
                    description = result.get("description") if result else None
                    message = result.get("message") if result else None
                    conn.last_error = description or message or "current-user NTLM bind failed"
                    raise LDAPBindError(conn.last_error)
            except LDAPException:
                raise
            except Exception as ex:
                raise LDAPBindError(f"current-user NTLM via Windows SSPI failed: {ex}") from ex
            finally:
                conn.sasl_in_progress = False

    def _has_explicit_ntlm_credentials(self) -> bool:
        return bool(self.creds.username and self.creds.password)

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.unbind()
            except Exception:
                pass
            self._conn = None

    # -------------------------------------------------------------------

    def paged_search(
        self,
        search_filter: str,
        attributes: list[str],
        base: str | None = None,
        scope: str = SUBTREE,
        controls: list[str] | None = None,
        size_limit: int = 0,
    ) -> Iterable[dict[str, Any]]:
        """Yield each matching entry as a dict of {attr_name: value}.

        `attributes` is a positive list — `*` is permitted for "all". SIDs/GUIDs are
        decoded to strings if present; arrays come through as Python lists.

        Per-search progress goes to DEBUG (one line per search at start, one at
        end with the entry count); each LDAP search would otherwise flood INFO.
        Use ``-v`` for source-level summaries, ``--debug`` to see every search.
        """
        conn = self.bind()
        base_dn = base or self.base_dn
        # Promoted to VERBOSE so ``-vv`` shows the same per-query trace PS1's
        # AD resolver emits at ``[Verbose]`` for each ADSISearcher / DirectorySearcher
        # attempt. ``--debug`` still gets the same line.
        logger.verbose("LDAP search: base=%s filter=%s", base_dn, search_filter)
        total = 0
        page = 0
        try:
            cookie = None
            while True:
                conn.search(
                    search_base=base_dn,
                    search_filter=search_filter,
                    search_scope=scope,
                    attributes=attributes,
                    paged_size=500,
                    paged_cookie=cookie,
                    controls=controls
                )
                # LDAP server-side error surfaces in `conn.result['description']`
                # without raising — e.g. ``noSuchObject`` for a missing
                # ``CN=System Management`` container. Surface those so the
                # caller doesn't see a silent 0-result.
                result = conn.result or {}
                desc = result.get("description")
                if desc and desc.lower() not in ("success", "sizelimitexceeded"):
                    logger.warning(
                        "LDAP search returned %s (base=%s filter=%s): %s",
                        desc,
                        base_dn,
                        search_filter,
                        result.get("message") or "",
                    )
                    break
                page += 1
                page_count = len(conn.entries)
                total += page_count
                for entry in conn.entries:
                    yield self._entry_to_dict(entry)
                # ldap3 paged-cookie extraction
                cookie = (
                    result.get("controls", {})
                    .get("1.2.840.113556.1.4.319", {})
                    .get("value", {})
                    .get("cookie")
                )
                if not cookie:
                    break
        except LDAPException as e:
            logger.warning("LDAP search failed (filter=%s, base=%s): %s", search_filter, base_dn, e)
        finally:
            logger.verbose(
                "LDAP search complete: base=%s filter=%s entries=%d pages=%d",
                base_dn,
                search_filter,
                total,
                page,
            )

    # Attributes whose values are always opaque binary blobs and must not be
    # UTF-8-decoded (doing so corrupts them via errors="replace" substitution).
    _BINARY_ATTRS = frozenset({"ntsecuritydescriptor", "dnsrecord"})

    @staticmethod
    def _entry_to_dict(entry) -> dict[str, Any]:
        """Convert an ldap3 Entry into a plain dict, decoding binary SIDs/GUIDs."""
        out: dict[str, Any] = {"distinguishedName": str(entry.entry_dn)}
        for attr_name in entry.entry_attributes:
            raw = entry[attr_name].raw_values
            if not raw:
                out[attr_name] = None
                continue
            if attr_name.lower() == "objectsid":
                out["object_sid"] = bytes_to_sid(raw[0])
                continue
            if attr_name.lower() == "objectguid":
                out["object_guid"] = bytes_to_guid(raw[0])
                continue
            if attr_name.lower() in ADClient._BINARY_ATTRS:
                v = raw[0]
                if isinstance(v, str):
                    v = v.encode("latin-1")
                out[attr_name] = v
                continue
            values = []
            for v in raw:
                if isinstance(v, (bytes, bytearray)):
                    try:
                        values.append(v.decode("utf-8", errors="replace"))
                    except Exception:
                        values.append(v.hex())
                else:
                    values.append(v)
            out[attr_name] = values if len(values) > 1 else values[0]
        return out

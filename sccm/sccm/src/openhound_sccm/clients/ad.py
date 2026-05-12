"""LDAP / Active Directory client for SCCM data collection.

A focused subset of `sccm/ConfigManBearPig/python/lib/ad_resolver.py` covering only
what the OpenHound `source.py` needs at collect time. We do **not** vendor the full
550-LOC original verbatim — most of its surface (cache management, name resolution
via NTAccount fallback chains, group membership traversal) is convert-time
post-processing that has moved to ``transforms.py`` SQL views and ``lookup.py``.

What stays here:
  - `ADClient.bind()` — opens an authenticated ldap3 connection.
  - `ADClient.paged_search(filter, attributes, base=None)` — uses ldap3's paged search,
    yields each entry's attributes as a flat dict; binary SIDs/GUIDs are decoded.
  - `bytes_to_sid(b)` and `bytes_to_guid(b)` — public helpers used by source.py.

If full ad_resolver feature parity is needed later (e.g. for runtime SID->name
translation that's not derivable from a single LDAP record), revisit by either
vendoring the rest of ad_resolver.py or adding ConfigManBearPig as a path-dep.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Any, Iterable

from ldap3 import (
    ALL,
    AUTO_BIND_NO_TLS,
    AUTO_BIND_TLS_BEFORE_BIND,
    NTLM,
    SUBTREE,
    Connection,
    Server,
)
from ldap3.core.exceptions import LDAPException

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

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LDAP security mode normalisation. CMBP's ``-ls / --ldap-signing`` and
# ``-cb / --ldap-channel-binding`` flags accept ``auto`` / ``required`` /
# ``disabled`` plus a handful of legacy aliases (true/yes/on for required,
# false/no/off for disabled). Centralising the coercion makes the bind
# logic readable.
# ---------------------------------------------------------------------------

_LDAP_SECURITY_ALIASES: dict[str, str] = {
    "auto": "auto",
    "default": "auto",
    "true": "required",
    "yes": "required",
    "y": "required",
    "1": "required",
    "on": "required",
    "required": "required",
    "require": "required",
    "enabled": "required",
    "enable": "required",
    "false": "disabled",
    "no": "disabled",
    "n": "disabled",
    "0": "disabled",
    "off": "disabled",
    "disabled": "disabled",
    "disable": "disabled",
}


def _normalize_ldap_security_mode(
    value: str | bool | None,
    *,
    name: str,
    default: str = "auto",
) -> str:
    """Coerce ``value`` to one of ``auto`` / ``required`` / ``disabled``."""
    if value is None:
        return default
    if isinstance(value, bool):
        return "required" if value else "disabled"
    mode = _LDAP_SECURITY_ALIASES.get(str(value).strip().lower())
    if not mode:
        raise ValueError(f"{name} must be one of: auto, required, disabled")
    return mode


def _is_stronger_auth_required(exc: BaseException) -> bool:
    """Detect AD DC ``strongerAuthRequired`` bind rejections (signing required)."""
    text = f"{type(exc).__name__}: {exc}".lower()
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
    use_ssl: bool = False
    port: int | None = None
    # CMBP-style LDAP transport hardening knobs. ``start_tls`` upgrades a plain
    # LDAP connection to TLS before binding. ``ldap_signing`` controls NTLM
    # sign-and-seal; ``ldap_channel_binding`` controls TLS channel binding
    # tokens. Each accepts ``auto`` / ``required`` / ``disabled``.
    start_tls: bool = False
    ldap_signing: str = "auto"
    ldap_channel_binding: str = "auto"


class ADClient:
    """Thin ldap3 wrapper used by OpenHound source resources.

    Uses a single bound connection. Callers iterate `paged_search` for each LDAP
    query they need; results come back as plain dicts, with binary SIDs/GUIDs
    pre-decoded into strings.
    """

    def __init__(self, credentials: ADCredentials):
        if credentials.use_ssl and credentials.start_tls:
            raise ValueError("Use either LDAPS or LDAP StartTLS, not both.")
        self.creds = credentials
        self.base_dn = ",".join(f"DC={part}" for part in credentials.domain.split("."))
        # Normalise the security-mode strings once so every bind call sees
        # canonical ``auto``/``required``/``disabled`` values.
        self._signing_mode = _normalize_ldap_security_mode(
            credentials.ldap_signing, name="ldap_signing"
        )
        self._cbt_mode = _normalize_ldap_security_mode(
            credentials.ldap_channel_binding, name="ldap_channel_binding"
        )
        self._conn: Connection | None = None

    # ------------------------------------------------------------------ bind --

    def bind(self) -> Connection:
        if self._conn is not None and self._conn.bound:
            return self._conn

        host = self.creds.domain_controller or self.creds.domain
        port = self.creds.port or (636 if self.creds.use_ssl else 389)
        channel_binding = self._should_use_channel_binding()

        # Try without NTLM sign-and-seal first when the policy is ``auto``;
        # retry with signing on after a ``strongerAuthRequired`` rejection.
        # ``required`` skips straight to signing-on; ``disabled`` never
        # enables it.
        attempts = [False]
        if self._should_require_session_security():
            attempts = [True]
        elif self._can_retry_with_session_security():
            attempts.append(True)

        last_exc: LDAPException | None = None
        for use_session_security in attempts:
            try:
                conn = self._open_connection(
                    host=host,
                    port=port,
                    use_session_security=use_session_security,
                    use_channel_binding=channel_binding,
                )
                self._conn = conn
                logger.info(
                    "LDAP connected: %s:%d (user=%s, transport=%s, session_security=%s, channel_binding=%s)",
                    host,
                    port,
                    self.creds.username or "<kerberos>",
                    self._transport_label(),
                    "encrypt" if use_session_security else "off",
                    "on" if channel_binding else "off",
                )
                return conn
            except LDAPException as exc:
                last_exc = exc
                if not use_session_security and _is_stronger_auth_required(exc):
                    logger.warning(
                        "LDAP bind to %s:%d requires signing/sealing; retrying with NTLM session security",
                        host,
                        port,
                    )
                    continue
                raise

        if last_exc:
            raise last_exc
        raise RuntimeError("LDAP connection failed before bind was attempted")

    # ---------------------------------------------------------------- helpers --

    def _open_connection(
        self,
        *,
        host: str,
        port: int,
        use_session_security: bool,
        use_channel_binding: bool,
    ) -> Connection:
        """Open and bind one Connection with the requested security settings."""
        if use_session_security and not self._has_explicit_ntlm_credentials():
            raise ValueError(
                "LDAP signing/sealing without LDAPS or StartTLS requires explicit NTLM credentials."
            )

        server = Server(
            host,
            port=port,
            use_ssl=self.creds.use_ssl,
            get_info=ALL,
            connect_timeout=5,
        )

        kwargs: dict[str, Any] = {
            "auto_bind": AUTO_BIND_TLS_BEFORE_BIND if self.creds.start_tls else AUTO_BIND_NO_TLS,
            "read_only": True,
            "receive_timeout": 30,
        }
        if self.creds.username and self.creds.password:
            kwargs.update(
                {
                    "user": self.creds.username,
                    "password": self.creds.password,
                    "authentication": NTLM,
                }
            )
        if use_session_security:
            kwargs["session_security"] = ENCRYPT
        if use_channel_binding:
            kwargs["channel_binding"] = TLS_CHANNEL_BINDING

        try:
            return Connection(server, **kwargs)
        except TypeError as exc:
            # Older ldap3 versions don't accept session_security /
            # channel_binding kwargs. The dependency floor in pyproject.toml
            # avoids this in practice; the explicit message just makes the
            # failure mode actionable for anyone running an older venv.
            if use_session_security or use_channel_binding:
                raise RuntimeError(
                    "LDAP signing / channel binding requires ldap3 with "
                    "session_security and channel_binding support. "
                    "Upgrade ldap3 to >=2.10.2rc4."
                ) from exc
            raise

    def _has_explicit_ntlm_credentials(self) -> bool:
        return bool(self.creds.username and self.creds.password)

    def _should_require_session_security(self) -> bool:
        if self.creds.use_ssl or self.creds.start_tls:
            # Over TLS the wire is already encrypted; NTLM sign-and-seal
            # would be redundant and ldap3 rejects the combination.
            return False
        return self._signing_mode == "required"

    def _can_retry_with_session_security(self) -> bool:
        return (
            self._signing_mode == "auto"
            and not self.creds.use_ssl
            and not self.creds.start_tls
            and self._has_explicit_ntlm_credentials()
        )

    def _should_use_channel_binding(self) -> bool:
        if self._cbt_mode == "disabled":
            return False
        if not (self.creds.use_ssl or self.creds.start_tls):
            if self._cbt_mode == "required":
                raise ValueError("LDAP channel binding requires LDAPS or LDAP StartTLS.")
            return False
        if not self._has_explicit_ntlm_credentials():
            if self._cbt_mode == "required":
                raise ValueError("LDAP channel binding requires explicit NTLM credentials.")
            return False
        return True

    def _transport_label(self) -> str:
        if self.creds.use_ssl:
            return "LDAPS"
        if self.creds.start_tls:
            return "StartTLS"
        return "LDAP"

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
        size_limit: int = 0,
    ) -> Iterable[dict[str, Any]]:
        """Yield each matching entry as a dict of {attr_name: value}.

        `attributes` is a positive list — `*` is permitted for "all". SIDs/GUIDs are
        decoded to strings if present; arrays come through as Python lists.
        """
        conn = self.bind()
        base_dn = base or self.base_dn
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
                )
                for entry in conn.entries:
                    yield self._entry_to_dict(entry)
                # ldap3 paged-cookie extraction
                cookie = (
                    conn.result.get("controls", {})
                    .get("1.2.840.113556.1.4.319", {})
                    .get("value", {})
                    .get("cookie")
                )
                if not cookie:
                    break
        except LDAPException as e:
            logger.warning("LDAP search failed (filter=%s, base=%s): %s", search_filter, base_dn, e)

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

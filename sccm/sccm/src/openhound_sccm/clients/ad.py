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
    NTLM,
    SUBTREE,
    Connection,
    Server,
)
from ldap3.core.exceptions import LDAPException

logger = logging.getLogger(__name__)


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


class ADClient:
    """Thin ldap3 wrapper used by OpenHound source resources.

    Uses a single bound connection. Callers iterate `paged_search` for each LDAP
    query they need; results come back as plain dicts, with binary SIDs/GUIDs
    pre-decoded into strings.
    """

    def __init__(self, credentials: ADCredentials):
        self.creds = credentials
        self.base_dn = ",".join(f"DC={part}" for part in credentials.domain.split("."))
        self._conn: Connection | None = None

    def bind(self) -> Connection:
        if self._conn is not None and self._conn.bound:
            return self._conn
        host = self.creds.domain_controller or self.creds.domain
        port = self.creds.port or (636 if self.creds.use_ssl else 389)
        server = Server(host, port=port, use_ssl=self.creds.use_ssl, get_info=ALL, connect_timeout=5)
        if self.creds.username and self.creds.password:
            self._conn = Connection(
                server,
                user=self.creds.username,
                password=self.creds.password,
                authentication=NTLM,
                auto_bind=True,
                read_only=True,
                receive_timeout=30,
            )
        else:
            # Current Kerberos session (domain-joined)
            self._conn = Connection(server, auto_bind=True, read_only=True, receive_timeout=30)
        logger.info("LDAP connected: %s:%d (user=%s)", host, port, self.creds.username or "<kerberos>")
        return self._conn

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

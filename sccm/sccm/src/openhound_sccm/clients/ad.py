"""LDAP / Active Directory client for SCCM data collection.

SCCM's :class:`ADClient` is now a thin subclass of the shared
:class:`openhound_collector_common.clients.ad.AdClient`. The shared client
contributes the entire **lockout-safe** transport/bind waterfall (LDAPS:636+CBT →
StartTLS:389+CBT → LDAP:389+sign/seal, with Kerberos / current-user SSPI-NTLM /
anonymous fallbacks), the paged-search loop, and the SID/GUID decoders — all
originally proven here and generalized into the shared library (which the MSSQL
collector also consumes). This subclass keeps only the SCCM-specific surface:

  * constructed from SCCM's :class:`ADCredentials` (username+password or
    integrated auth only — SCCM does not pass an NT hash / Kerberos ticket to
    LDAP), mapped onto the shared ``LdapAuth``;
  * :meth:`_entry_to_dict` emits **snake_case** keys (``dns_host_name`` …) so
    dlt's table loader doesn't mangle camelCase, and preserves opaque binary
    attributes (``ntSecurityDescriptor`` / ``dnsRecord``) as raw bytes;
  * :meth:`get_spns` — servicePrincipalName lookup by hostname.

Lockout-safety (inherited): only AD's ``data 52e`` family of result-49 sub-codes
(bad/locked/expired/disabled credentials) increments ``badPwdCount``. Protocol-
level rejections — ``strongerAuthRequired`` (result 8), CBT mismatch
(``data 80090346``), TLS handshake / connect failures — are returned *before* the
password is validated, so retrying with a different transport profile after one
of those does not advance the lockout counter. The shared ``bind`` propagates
immediately on a credential-class failure (see ``_is_credential_failure``) and
falls through only on protocol/transport errors.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from openhound_collector_common.clients.ad import (
    AdClient,
    LdapAuth,
    bytes_to_guid,
    bytes_to_sid,
)

logger = logging.getLogger(__name__)


@dataclass
class ADCredentials:
    domain: str
    domain_controller: str | None = None
    username: str | None = None
    password: str | None = None
    # Optional port override. ``None`` lets ``bind()`` auto-detect the transport
    # (LDAPS 636 → StartTLS 389 → LDAP 389+sign/seal). Setting a value pins the
    # port and narrows the attempt chain: 636/3269 → LDAPS; anything else → LDAP
    # (with NTLM sign/seal when creds are supplied, plain LDAP only as a last
    # resort).
    port: int | None = None


class ADClient(AdClient):
    """SCCM LDAP client: the shared lockout-safe ``AdClient`` waterfall plus
    SCCM's snake_case entry mapping and ``get_spns``. See the module docstring."""

    # dlt table columns are snake_case, so entry dicts use snake_case keys rather
    # than the shared client's camelCase. objectSid/objectGuid are decoded
    # separately (binary), so they're intentionally absent from this map.
    _ATTR_KEY_MAP: dict[str, str] = {
        "distinguishedname": "distinguished_name",
        "dnshostname": "dns_host_name",
        "samaccountname": "sam_account_name",
        "userprincipalname": "user_principal_name",
        "objectclass": "object_class",
    }
    # Attributes whose values are always opaque binary blobs and must NOT be
    # UTF-8-decoded (doing so corrupts them via errors="replace" substitution).
    _BINARY_ATTRS = frozenset({"ntsecuritydescriptor", "dnsrecord"})

    def __init__(self, credentials: ADCredentials):
        # Kept for callers that read ``ctx.ad.creds`` (clients/http.py,
        # collectors/dns.py read ``creds.domain_controller``).
        self.creds = credentials
        # SCCM binds LDAP with username+password or integrated auth only (no
        # LDAP pass-the-hash / pass-the-ticket), so only these LdapAuth fields
        # are populated; the shared waterfall handles the rest.
        super().__init__(
            domain=credentials.domain,
            dc=credentials.domain_controller,
            auth=LdapAuth(
                username=credentials.username,
                password=credentials.password,
            ),
            port=credentials.port,
        )

    @staticmethod
    def _entry_to_dict(entry) -> dict[str, Any]:
        """Convert an ldap3 Entry into a plain dict, decoding binary SIDs/GUIDs.

        All output keys are clean snake_case so dlt's table-loading step does not
        mangle them (e.g. ``dNSHostName`` → ``d_ns_host_name``). LDAP query
        attribute names (the wire protocol) are left unchanged in search calls.
        """
        # distinguishedName always comes from entry.entry_dn; normalise the key
        # here so every other attribute goes through the same mapping path.
        out: dict[str, Any] = {"distinguished_name": str(entry.entry_dn)}
        for attr_name in entry.entry_attributes:
            raw = entry[attr_name].raw_values
            if not raw:
                # Use the mapped key if available, else the raw name.
                out_key = ADClient._ATTR_KEY_MAP.get(attr_name.lower(), attr_name)
                out[out_key] = None
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
                # Binary attrs like ntsecuritydescriptor have no camelCase alias,
                # so the raw attr_name is already acceptable here.
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
            out_key = ADClient._ATTR_KEY_MAP.get(attr_name.lower(), attr_name)
            out[out_key] = values if len(values) > 1 else values[0]
        return out

    def get_spns(self, dns_hostname: str) -> list[str]:
        """Query the servicePrincipalName attribute of a computer object by its
        hostname. Returns a list of SPNs or an empty list on miss/failure."""
        try:
            logger.info("Querying SPNs for %s", dns_hostname)
            results = list(
                self.paged_search(
                    search_filter=f"(dNSHostName={dns_hostname})",
                    attributes=["servicePrincipalName"],
                )
            )
            if results and "servicePrincipalName" in results[0]:
                return results[0]["servicePrincipalName"]
            logger.debug("No SPNs found for %s", dns_hostname)
        except Exception as ex:
            logger.error("Failed to query SPN for %s: %s", dns_hostname, ex)
        return []

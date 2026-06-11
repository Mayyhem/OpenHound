"""Negotiate auth engine for the SCCM HTTP client.

Mints the ``Authorization: Negotiate <base64>`` tokens for the
``WWW-Authenticate: Negotiate`` dance used by the AdminService REST API:

  * **Kerberos** (impacket) from a password, an NT hash (used as the RC4 key),
    or a base64 KRB-CRED (``.kirbi``) ticket — pass-the-ticket.
  * **NTLM** (impacket) from a password or NT hash.
  * **Current-user SSPI** (pywin32) for passwordless Windows single sign-on.

Mirrors the structure of ``clients/smb_sso.py`` (capability gate + per-handshake
client objects). ``choose_auth`` is the pure ladder selector (unit-tested with
no network); the negotiator classes are the live seams, validated end-to-end
against a real AdminService during development.

Each negotiator exposes ``step(server_token) -> (token_bytes, done)``: the
client base64-encodes ``token_bytes`` into the ``Negotiate`` header, and feeds
any server continuation token (NTLM's second leg) back into ``step``.

The explicit-Kerberos AP-REQ deliberately omits ``GSS_C_DCE_STYLE`` from the
GSS checksum flags: http.sys / IIS HTTP Negotiate rejects DCE-style tokens with
a 401 (only RPC-style endpoints such as WinRM accept them). Validated live.
"""
from __future__ import annotations

import base64
import datetime
import enum
import importlib
import ipaddress
import logging
import struct
import sys
from typing import Any, Optional

from .. import log_context  # noqa: F401  (registers logger.verbose on logging.Logger)

from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, TGS_REP, Authenticator, seq_set
from impacket.krb5.ccache import CCache
from impacket.krb5.gssapi import (
    CheckSumField,
    GSS_C_INTEG_FLAG,
    GSS_C_MUTUAL_FLAG,
    GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG,
    KRB5_AP_REQ,
)
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT
from impacket.krb5.types import KerberosTime, Principal, Ticket
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3
from impacket.spnego import (
    ASN1_AID,
    ASN1_OID,
    SPNEGO_NegTokenInit,
    SPNEGO_NegTokenResp,
    TypesMech,
    asn1encode,
)
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

logger = logging.getLogger(__name__)

# The conventional empty LM hash, prepended to a bare NT hash so impacket
# receives the LMHASH:NTHASH form it expects (identical to mssql_epa.py).
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"

# GSS checksum flags for the explicit-Kerberos authenticator. Matches impacket's
# getKerberosType1 set MINUS GSS_C_DCE_STYLE (and GSS_C_CONF, unnecessary here):
# http.sys/IIS HTTP Negotiate rejects DCE-style tokens. Validated live against a
# real AdminService (DCE-style -> 401; this set -> accepted).
_GSS_HTTP_FLAGS = GSS_C_INTEG_FLAG | GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG | GSS_C_MUTUAL_FLAG


class AuthMode(enum.Enum):
    """Caller's choice of whether the Negotiate ladder runs at all."""
    NEGOTIATE = "negotiate"   # run the auth ladder
    NONE = "none"             # never send Authorization (HTTP role-probe)


def _sspi_negotiate_available() -> bool:
    """True only on Windows with the pywin32 SSPI modules importable.

    Mirrors smb_sso._sspi_negotiate_available / ad._current_user_ntlm_available.
    """
    if sys.platform != "win32":
        return False
    try:
        importlib.import_module("sspi")
        importlib.import_module("sspicon")
        return True
    except ImportError:
        return False


sspi_negotiate_available = _sspi_negotiate_available  # public alias


def is_ip(host: str) -> bool:
    """True when *host* is a bare IP literal (so no HTTP SPN can be formed)."""
    try:
        ipaddress.ip_address(host.strip().strip("[]"))
        return True
    except ValueError:
        return False


def http_spn(host: str) -> str:
    """The Kerberos service principal name for an HTTP/HTTPS endpoint."""
    return f"HTTP/{host}"


def format_hashes(nt_hash: Optional[str]) -> Optional[str]:
    """Normalize an NT hash to impacket's LMHASH:NTHASH form (or None)."""
    if not nt_hash:
        return None
    if ":" in nt_hash:
        return nt_hash
    return f"{EMPTY_LM_HASH}:{nt_hash}"


def split_user_domain(username: str, default_domain: str) -> tuple[str, str]:
    """Split ``DOMAIN\\user`` or ``user@domain`` into ``(domain, user)``."""
    if "\\" in username:
        domain, user = username.split("\\", 1)
        return domain, user
    if "@" in username:
        user, domain = username.split("@", 1)
        return domain, user
    return default_domain, username


def choose_auth(
    *,
    username: Optional[str],
    password: Optional[str],
    nt_hash: Optional[str],
    ticket: Optional[str],
    target_host: str,
    sspi_available: bool,
) -> list[str]:
    """Resolve the ordered auth rungs to attempt for a NEGOTIATE-mode request.

    Precedence (explicit creds win, then current-user SSPI, then anonymous):
      1. ticket                       -> ["kerberos"]            (no NTLM fallback)
      2. username + (password|hash)   -> ["kerberos","ntlm"]    (kerberos skipped
                                          when target is a bare IP -> ["ntlm"])
      3. sspi_available               -> ["sspi"]
      4. otherwise                    -> ["anonymous"]
    """
    if ticket:
        logger.debug("HTTP auth: pass-the-ticket (Kerberos only) for %s", target_host)
        return ["kerberos"]
    if username and (password or nt_hash):
        if is_ip(target_host):
            logger.verbose(
                "HTTP auth: %s is a bare IP; skipping Kerberos (no SPN), using NTLM only",
                target_host,
            )
            return ["ntlm"]
        logger.debug("HTTP auth: explicit creds -> Kerberos, NTLM fallback for %s", target_host)
        return ["kerberos", "ntlm"]
    if sspi_available:
        logger.debug("HTTP auth: current-user SSPI Negotiate for %s", target_host)
        return ["sspi"]
    logger.verbose("HTTP auth: no creds and no SSPI; anonymous for %s", target_host)
    return ["anonymous"]


# --- SPNEGO helpers ---------------------------------------------------------


def _spnego_init(mech, mech_token: bytes) -> bytes:
    """Wrap a mechanism token in an SPNEGO NegTokenInit advertising *mech*."""
    blob = SPNEGO_NegTokenInit()
    blob["MechTypes"] = [mech]
    blob["MechToken"] = mech_token
    return blob.getData()


def _spnego_resp(mech_token: bytes) -> bytes:
    """Wrap a continuation mechanism token in an SPNEGO NegTokenResp."""
    blob = SPNEGO_NegTokenResp()
    blob["ResponseToken"] = mech_token
    return blob.getData()


def _unwrap_spnego_response(server_token: bytes) -> bytes:
    """Extract the inner mechanism token from a server SPNEGO NegTokenResp."""
    return SPNEGO_NegTokenResp(server_token)["ResponseToken"]


# --- Negotiators ------------------------------------------------------------


class SspiNegotiator:
    """Current-user SSPI Negotiate; mirrors smb_sso._SSPINegotiateClient."""

    def __init__(self, *, target_host: str) -> None:
        import sspi  # Windows-only; imported lazily so the module loads anywhere
        self._auth = sspi.ClientAuth("Negotiate", targetspn=http_spn(target_host))

    def step(self, server_token: Optional[bytes]) -> tuple[bytes, bool]:
        error, buffers = self._auth.authorize(server_token if server_token else None)
        token = bytes(buffers[0].Buffer) if buffers else b""
        # pywin32: error == 0 (SEC_E_OK) means the handshake is complete; the
        # caller still inspects the HTTP status (a non-401 ends the loop even
        # when SSPI reports SEC_I_CONTINUE_NEEDED for the optional mutual leg).
        return token, error == 0


class NtlmNegotiator:
    """Two-leg NTLM (type1 -> server challenge -> type3) via impacket, SPNEGO-wrapped."""

    _MECH = TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"]

    def __init__(self, *, domain: str, username: str, password: Optional[str],
                 nt_hash: Optional[str]) -> None:
        self._domain = domain
        self._username = username
        self._password = password or ""
        self._lm = ""
        self._nt = ""
        hashes = format_hashes(nt_hash)
        if hashes:
            self._lm, self._nt = hashes.split(":")
        self._type1: Any = None  # impacket NTLMSSP type-1 (untyped), set on first step

    def step(self, server_token: Optional[bytes]) -> tuple[bytes, bool]:
        if server_token is None:
            self._type1 = getNTLMSSPType1(domain=self._domain)
            return _spnego_init(self._MECH, self._type1.getData()), False
        challenge = _unwrap_spnego_response(server_token)
        type3, _session_key = getNTLMSSPType3(
            self._type1, challenge, self._username, self._password,
            self._domain, self._lm, self._nt,
        )
        return _spnego_resp(type3.getData()), True


class KerberosNegotiator:
    """One-shot Kerberos AP-REQ over SPNEGO via impacket.

    Sources a service ticket for ``HTTP/<host>`` from one of:
      * a base64 KRB-CRED (``.kirbi``) ticket — a direct service ticket if it
        matches the SPN, otherwise a TGT used to request one (pass-the-ticket);
      * a password / NT hash — a fresh TGT then a service ticket from the KDC.

    Decodes the ticket eagerly so a malformed blob fails fast with ValueError.
    """

    _MS_KRB5 = TypesMech["MS KRB5 - Microsoft Kerberos 5"]
    _KRB5 = TypesMech["KRB5 - Kerberos 5"]

    def __init__(self, *, target_host: str, realm: str, username: Optional[str],
                 password: Optional[str], nt_hash: Optional[str],
                 ticket: Optional[str], kdc_host: Optional[str]) -> None:
        self._target_host = target_host
        self._spn = http_spn(target_host)
        self._realm = realm.upper()
        self._username = username
        self._password = password or ""
        self._lm = ""
        self._nt = ""
        hashes = format_hashes(nt_hash)
        if hashes:
            self._lm, self._nt = hashes.split(":")
        self._kdc_host = kdc_host
        # Cached (tgs_rep_bytes, cipher, session_key): fetched once, then reused so
        # each request rebuilds only the cheap AP-REQ — no repeat KDC round-trip.
        self._service: Optional[tuple] = None
        self._ccache: Optional[CCache] = None
        if ticket:
            try:
                self._ccache = CCache()
                self._ccache.fromKRBCRED(base64.b64decode(ticket, validate=True))
            except Exception as exc:  # malformed base64 / not a KRB-CRED
                raise ValueError(f"--ticket is not a valid base64 KRB-CRED (.kirbi): {exc}") from exc

    def step(self, server_token: Optional[bytes]) -> tuple[bytes, bool]:
        if self._service is None:
            # First call: one KDC exchange (TGT+TGS, or load from the ticket).
            # Cached for this negotiator's lifetime so later requests skip the KDC.
            self._service = self._service_ticket()
        return self._build_blob(*self._service), True

    def _service_ticket(self):
        """Return ``(tgs_rep_bytes, cipher, session_key)`` for the HTTP SPN."""
        if self._ccache is not None:
            direct = self._ccache.getCredential(self._spn)
            if direct is not None:
                logger.verbose("HTTP Kerberos: using service ticket for %s from ticket", self._spn)
                d = direct.toTGS(self._spn)
                return d["KDC_REP"], d["cipher"], d["sessionKey"]
            tgt_cred = self._ccache.getCredential(f"krbtgt/{self._realm}")
            if tgt_cred is None and self._ccache.credentials:
                tgt_cred = self._ccache.credentials[0]
            if tgt_cred is None:
                raise ValueError("ticket contains no usable TGT or service ticket")
            logger.verbose("HTTP Kerberos: requesting %s using TGT from ticket", self._spn)
            tgt = tgt_cred.toTGT()
            tgs, cipher, _, sk = getKerberosTGS(
                Principal(self._spn, type=constants.PrincipalNameType.NT_SRV_INST.value),
                self._realm, self._kdc_host, tgt["KDC_REP"], tgt["cipher"], tgt["sessionKey"],
            )
            return tgs, cipher, sk

        logger.verbose("HTTP Kerberos: requesting TGT+TGS for %s from KDC %s", self._spn, self._kdc_host)
        client = Principal(self._username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, _, sk = getKerberosTGT(
            client, self._password, self._realm, self._lm, self._nt, b"", self._kdc_host,
        )
        tgs, cipher, _, sk = getKerberosTGS(
            Principal(self._spn, type=constants.PrincipalNameType.NT_SRV_INST.value),
            self._realm, self._kdc_host, tgt, cipher, sk,
        )
        return tgs, cipher, sk

    def _build_blob(self, tgs_bytes: bytes, cipher, session_key) -> bytes:
        """Assemble the AP-REQ and wrap it in an SPNEGO NegTokenInit."""
        tgs_rep = decoder.decode(tgs_bytes, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs_rep["ticket"])
        client_name = Principal()
        client_name.from_asn1(tgs_rep, "crealm", "cname")

        ap_req = AP_REQ()
        ap_req["pvno"] = 5
        ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req["ap-options"] = constants.encodeFlags([constants.APOptions.mutual_required.value])
        seq_set(ap_req, "ticket", ticket.to_asn1)

        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = str(tgs_rep["crealm"])
        seq_set(authenticator, "cname", client_name.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)
        authenticator["cksum"] = noValue
        authenticator["cksum"]["cksumtype"] = 0x8003
        chk = CheckSumField()
        chk["Lgth"] = 16
        chk["Flags"] = _GSS_HTTP_FLAGS
        authenticator["cksum"]["checksum"] = chk.getData()
        authenticator["seq-number"] = 0

        encrypted = cipher.encrypt(session_key, 11, encoder.encode(authenticator), None)
        ap_req["authenticator"] = noValue
        ap_req["authenticator"]["etype"] = cipher.enctype
        ap_req["authenticator"]["cipher"] = encrypted

        mech_token = struct.pack("B", ASN1_AID) + asn1encode(
            struct.pack("B", ASN1_OID) + asn1encode(self._KRB5)
            + KRB5_AP_REQ + encoder.encode(ap_req))
        return _spnego_init(self._MS_KRB5, mech_token)

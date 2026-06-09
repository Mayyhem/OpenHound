"""MSSQL Extended Protection for Authentication (EPA) network probing.

Ports MSSQLHound's ``TestEPA`` (internal/mssql/client.go) to Python. EPA
enforcement cannot be read passively from a PRELOGIN; it is inferred by
attempting NTLM logins while deliberately corrupting or omitting the channel
binding token (encrypted/strict connections) or the service principal name
(unencrypted connections) and observing which the server rejects with an
"untrusted domain" error.

``determine_epa`` is the pure decision tree over per-probe outcomes. The live
probers (impacket explicit-credential and Windows SSPI integrated auth) plug in
behind the same ``probe(mode)`` seam.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional

from impacket import ntlm, tds

logger = logging.getLogger(__name__)

# MS-TDS PRELOGIN encryption byte values. Mirror impacket.tds.TDS_ENCRYPT_*
# (stable protocol constants) so the decision tree carries no impacket import.
ENCRYPT_OFF = 0
ENCRYPT_ON = 1
ENCRYPT_NOT_SUP = 2
ENCRYPT_REQ = 3
ENCRYPT_STRICT = 8

# Default SQL Server service class for the correct/baseline service binding.
DEFAULT_SERVICE_CLASS = "MSSQLSvc"

# The conventional "empty" LM hash, prepended to a bare NT hash for pass-the-hash
# so impacket receives the ``LMHASH:NTHASH`` form it expects.
EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"

# A fixed 16-byte garbage channel binding token. A server enforcing channel
# binding rejects it; one that ignores bindings accepts it. Identical bytes to
# MSSQLHound (ntlm_auth.go) and RelayInformer for cross-tool consistency.
BOGUS_CBT = b"\xc0\x91\x30\xd2\xc4\xc3\xd4\xc7\x51\x5a\xb4\x52\xdf\x08\xaf\xfd"

# "untrusted domain" rejection text -> an EPA binding check failed.
_UNTRUSTED_DOMAIN_TEXT = "the login is from an untrusted domain"
# A plain login failure -> bindings were accepted; credentials/db were not.
_LOGIN_FAILED_TEXT = "login failed for"


@dataclass
class ProbeOutcome:
    """Classified result of one EPA login attempt.

    Attributes:
        success: True when the login reached LOGINACK (authenticated).
        is_untrusted_domain: True when the server rejected the login with
            "the login is from an untrusted domain" — the signal that an EPA
            binding check failed.
        is_login_failed: True for a plain "Login failed for" rejection, which
            still proves the credentials/bindings were accepted far enough to
            count as a valid prereq response.
        encryption_flag: The PRELOGIN encryption byte the server returned.
        is_strict: True when the connection used TDS 8.0 strict encryption.
        error_message: Raw server error text, for logging.
    """

    success: bool = False
    is_untrusted_domain: bool = False
    is_login_failed: bool = False
    encryption_flag: int = ENCRYPT_OFF
    is_strict: bool = False
    error_message: str = ""


@dataclass
class EPAResult:
    """Outcome of the full EPA enforcement determination.

    Attributes:
        extended_protection: "Off", "Allowed", "Required", or "Unknown".
        force_encryption: True when the server requires TLS for all connections.
        strict_encryption: True when the server uses TDS 8.0 strict encryption.
        encryption_flag: The PRELOGIN encryption byte observed.
        unmodified_success: True when the baseline (correct-bindings) login
            succeeded.
    """

    extended_protection: str
    force_encryption: bool = False
    strict_encryption: bool = False
    encryption_flag: int = ENCRYPT_OFF
    unmodified_success: bool = False


class EPAPrereqError(Exception):
    """Raised when the baseline login neither succeeds nor cleanly fails login.

    Without a valid baseline response we cannot trust the manipulated-binding
    responses, so EPA enforcement is indeterminable.
    """


def determine_epa(probe: Callable[[str], ProbeOutcome], auth_method: Optional[str] = None) -> EPAResult:
    """Determine EPA enforcement by running manipulated-binding login probes.

    ``probe(mode)`` performs one login attempt for ``mode`` in {"normal",
    "bogus_cbt", "missing_cbt", "bogus_service", "missing_service"} and returns
    a classified ``ProbeOutcome``. ``auth_method`` (optional) is the auth strategy
    ("sspi" or "explicit") for handling SSPI-specific indistinguishability.
    """
    normal = probe("normal")

    # Prereq: the baseline (correct-bindings) login must either authenticate or
    # fail with a plain "login failed". Any other response (untrusted domain,
    # unexpected error) means we cannot trust the manipulated-binding probes.
    if not normal.success and not normal.is_login_failed:
        raise EPAPrereqError(
            f"EPA prereq check failed: unexpected baseline response: {normal.error_message}"
            if normal.error_message
            else "EPA prereq check failed: credentials rejected (untrusted domain)"
        )

    if normal.is_strict or normal.encryption_flag == ENCRYPT_REQ:
        # Encrypted connection -> probe channel binding enforcement.
        ep = _classify_binding(probe, "bogus_cbt", "missing_cbt", auth_method)
    elif normal.encryption_flag in (ENCRYPT_OFF, ENCRYPT_ON):
        # Unencrypted connection -> probe service (SPN) binding enforcement.
        ep = _classify_binding(probe, "bogus_service", "missing_service", auth_method)
    else:
        # ENCRYPT_NOT_SUP or any unexpected flag: no usable binding to probe.
        ep = "Unknown"

    return EPAResult(
        extended_protection=ep,
        force_encryption=normal.is_strict or normal.encryption_flag == ENCRYPT_REQ,
        strict_encryption=normal.is_strict,
        encryption_flag=normal.encryption_flag,
        unmodified_success=normal.success,
    )


def _classify_binding(
    probe: Callable[[str], ProbeOutcome], bogus_mode: str, missing_mode: str, auth_method: Optional[str] = None
) -> str:
    """Map a bogus-then-missing binding probe pair to Off/Allowed/Required.

    A server that accepts a *bogus* binding is not enforcing EPA at all (Off).
    A server that rejects the bogus binding is checking it; whether it also
    rejects a *missing* binding distinguishes Required from Allowed.

    When using SSPI (Windows integrated auth), both bogus and missing are
    rejected if EPA is enforced at all, because SSPI always includes the
    AV pairs (Windows builds the NTLM token). In this indistinguishable case,
    report the literal "Allowed/Required" so the uncertainty is preserved
    for downstream consumers.
    """
    bogus = probe(bogus_mode)
    if not bogus.is_untrusted_domain:
        return "Off"
    missing = probe(missing_mode)
    if missing.is_untrusted_domain:
        # Both bogus and missing are rejected.
        if auth_method == "sspi":
            # SSPI cannot distinguish Allowed from Required because Windows
            # always includes the AV pairs. Surface the ambiguity verbatim.
            return "Allowed/Required"
        return "Required"
    return "Allowed"


def _mode_login_params(mode: str, service_class: str = DEFAULT_SERVICE_CLASS) -> dict:
    """Map an EPA probe mode to ``_MSSQLEPA.login`` keyword arguments.

    ``cbt_value`` semantics (passed to impacket's channel binding handling):
      None -> compute the correct token from the live TLS channel (or empty if
              the connection is unencrypted); ``BOGUS_CBT`` -> wrong token;
      ``b""`` -> omit the channel binding AV pair entirely.
    ``service`` is the SPN service class impacket prefixes to the server's host.
    ``strip_target_service`` omits the target-name AV pair entirely.
    """
    if mode == "normal":
        return {"cbt_value": None, "service": service_class, "strip_target_service": False}
    if mode == "bogus_cbt":
        return {"cbt_value": BOGUS_CBT, "service": service_class, "strip_target_service": False}
    if mode == "missing_cbt":
        return {"cbt_value": b"", "service": service_class, "strip_target_service": False}
    if mode == "bogus_service":
        return {"cbt_value": None, "service": "cifs", "strip_target_service": False}
    if mode == "missing_service":
        return {"cbt_value": None, "service": "", "strip_target_service": True}
    raise ValueError(f"unknown EPA probe mode: {mode!r}")


def _classify_error_text(text: str) -> ProbeOutcome:
    """Classify a server error string into an unauthenticated ``ProbeOutcome``."""
    lowered = text.lower()
    return ProbeOutcome(
        is_untrusted_domain=_UNTRUSTED_DOMAIN_TEXT in lowered,
        is_login_failed=_LOGIN_FAILED_TEXT in lowered,
        error_message=text,
    )


# --- Live impacket prober (explicit-credential / pass-the-hash) --------------


class _MSSQLEPA(tds.MSSQL):
    """impacket MSSQL client with EPA-probe control over the NTLM Type3 bindings.

    Reuses impacket 0.13.1's ``_negotiate_encryption`` (which transparently
    handles TDS 8.0 strict) and adds control over the channel binding token, the
    service SPN class, and whether the target-name AV pair is sent at all.
    ``login`` is a near-verbatim copy of ``tds.MSSQL.login`` with those three
    knobs added, recording the EPA-relevant encryption flag and strict status.
    """

    #: PRELOGIN encryption flag observed during the last login (ENCRYPT_STRICT
    #: when the connection upgraded to TDS 8.0 strict).
    epa_encryption_flag: int = ENCRYPT_OFF
    #: Whether the last login used TDS 8.0 strict encryption.
    epa_is_strict: bool = False

    def getErrorMessages(self) -> str:
        """Join all TDS error tokens from the last reply into one string."""
        if not self.replies:
            return ""
        messages = []
        for token_list in self.replies.values():
            for token in token_list:
                if token["TokenType"] == tds.TDS_ERROR_TOKEN:
                    messages.append(
                        "(%s) %s"
                        % (
                            token["ServerName"].decode("utf-16le"),
                            token["MsgText"].decode("utf-16le"),
                        )
                    )
        return " ".join(messages)

    def login(
        self,
        database,
        username,
        password="",
        domain="",
        hashes=None,
        cbt_value: Optional[bytes] = None,
        service: str = DEFAULT_SERVICE_CLASS,
        strip_target_service: bool = False,
    ) -> bool:
        """Attempt a Windows-auth login with EPA bindings under our control.

        ``cbt_value``: None -> correct token from the TLS channel (or empty when
        unencrypted); ``BOGUS_CBT`` -> wrong token; ``b""`` -> omit the channel
        binding AV pair. ``service`` is the SPN class impacket prefixes to the
        server host. ``strip_target_service`` omits the target-name AV pair.
        """
        if hashes is not None:
            lmhash_hex, nthash_hex = hashes.split(":")
            lmhash = bytes.fromhex(lmhash_hex)
            nthash = bytes.fromhex(nthash_hex)
        else:
            # Empty strings (not bytes) — impacket's ``NTOWFv2`` keys on
            # ``hash != ''`` (str compare). Passing ``b""`` would be ``!= ''``
            # in Python 3 and trick impacket into HMACing with empty bytes
            # instead of deriving the NT hash from ``password``, producing a
            # bogus NTProofStr the server rejects as "untrusted domain".
            lmhash = ""
            nthash = ""

        resp = self._negotiate_encryption()
        self.epa_is_strict = bool(self.tds8)
        self.epa_encryption_flag = ENCRYPT_STRICT if self.tds8 else resp["Encryption"]

        self.version = ntlm.VERSION()
        (
            self.version["ProductMajorVersion"],
            self.version["ProductMinorVersion"],
            self.version["ProductBuild"],
        ) = (10, 0, 20348)

        login = tds.TDS_LOGIN()
        login["TDSVersion"] = self._get_default_login7_tds_version()
        self._set_session_login7_tds_version(login["TDSVersion"])
        login["HostName"] = self.workstation_id.encode("utf-16le")
        login["AppName"] = self.application_name.encode("utf-16le")
        login["ServerName"] = self.remoteName.encode("utf-16le")
        login["CltIntName"] = login["AppName"]
        login["ClientPID"] = 1234
        login["PacketSize"] = self.packetSize
        if database is not None:
            login["Database"] = database.encode("utf-16le")
        login["OptionFlags2"] = tds.TDS_INIT_LANG_FATAL | tds.TDS_ODBC_ON | tds.TDS_INTEGRATED_SECURITY_ON

        auth = ntlm.getNTLMSSPType1("", "", use_ntlmv2=True, version=self.version)
        login["SSPI"] = auth.getData()
        login["Length"] = len(login.getData())

        self.sendTDS(tds.TDS_LOGIN7, login.getData())
        # ENCRYPT_OFF: only the LOGIN7 packet is encrypted; drop TLS afterward.
        if not self.tds8 and resp["Encryption"] == ENCRYPT_OFF:
            self.tlsSocket = None

        tds_resp = self.recvTDS()
        server_challenge = tds_resp["Data"][3:]

        # Resolve the channel binding token per the requested probe mode.
        if self._has_active_tls_channel_binding():
            channel_binding_value = (
                self.generate_cbt_from_tls_unique() if cbt_value is None else cbt_value
            )
        else:
            channel_binding_value = b"" if cbt_value is None else cbt_value

        original_test_case = ntlm.TEST_CASE
        if strip_target_service:
            ntlm.TEST_CASE = True
        try:
            type3, exported_session_key = ntlm.getNTLMSSPType3(
                auth,
                server_challenge,
                username,
                password,
                domain,
                lmhash,
                nthash,
                service=service,
                use_ntlmv2=True,
                channel_binding_value=channel_binding_value,
                version=self.version,
            )
            # Compute the MIC over the three NTLM messages.
            type3["MIC"] = b"\x00" * 16
            new_mic = ntlm.hmac_md5(
                exported_session_key,
                auth.getData()
                + ntlm.NTLMAuthChallenge(server_challenge).getData()
                + type3.getData(),
            )
            type3["MIC"] = new_mic
        finally:
            ntlm.TEST_CASE = original_test_case

        self.sendTDS(tds.TDS_SSPI, type3.getData())
        tds_resp = self.recvTDS()
        self.replies = self.parseReply(tds_resp["Data"])
        return tds.TDS_LOGINACK_TOKEN in self.replies

    def login_sspi(self, *, target_spn: Optional[str], cbt_mode: str) -> bool:
        """Attempt a current-user (integrated) Windows-auth login via SSPI.

        Windows builds the NTLM tokens (and the MIC) for the logged-in user; we
        only steer the EPA bindings: ``target_spn`` becomes the service binding
        (``None`` omits it), and ``cbt_mode`` in {"correct", "bogus", "missing"}
        controls the channel binding token. NTLM is forced (not Negotiate) so the
        AV-pair-based EPA mechanism applies.
        """
        import sspi
        import sspicon
        import win32security

        resp = self._negotiate_encryption()
        self.epa_is_strict = bool(self.tds8)
        self.epa_encryption_flag = ENCRYPT_STRICT if self.tds8 else resp["Encryption"]

        # ISC_REQ_INTEGRITY drives NTLM signing/MIC negotiation; no confidentiality
        # (the TDS/TLS layer handles encryption).
        auth = sspi.ClientAuth(
            "NTLM",
            targetspn=target_spn or None,
            scflags=sspicon.ISC_REQ_INTEGRITY | sspicon.ISC_REQ_CONNECTION,
        )
        _, out_buffers = auth.authorize(None)
        type1 = bytes(out_buffers[0].Buffer)

        login = tds.TDS_LOGIN()
        login["TDSVersion"] = self._get_default_login7_tds_version()
        self._set_session_login7_tds_version(login["TDSVersion"])
        login["HostName"] = self.workstation_id.encode("utf-16le")
        login["AppName"] = self.application_name.encode("utf-16le")
        login["ServerName"] = self.remoteName.encode("utf-16le")
        login["CltIntName"] = login["AppName"]
        login["ClientPID"] = 1234
        login["PacketSize"] = self.packetSize
        login["OptionFlags2"] = tds.TDS_INIT_LANG_FATAL | tds.TDS_ODBC_ON | tds.TDS_INTEGRATED_SECURITY_ON
        login["SSPI"] = type1
        login["Length"] = len(login.getData())

        self.sendTDS(tds.TDS_LOGIN7, login.getData())
        if not self.tds8 and resp["Encryption"] == ENCRYPT_OFF:
            self.tlsSocket = None

        tds_resp = self.recvTDS()
        server_challenge = tds_resp["Data"][3:]

        sec_buffer_in = win32security.PySecBufferDescType()
        token_buf = win32security.PySecBufferType(
            auth.pkg_info["MaxToken"], sspicon.SECBUFFER_TOKEN
        )
        token_buf.Buffer = bytes(server_challenge)
        sec_buffer_in.append(token_buf)

        bindings = self._resolve_sspi_channel_binding(cbt_mode)
        if bindings is not None:
            cbt_buf = win32security.PySecBufferType(
                len(bindings), sspicon.SECBUFFER_CHANNEL_BINDINGS
            )
            cbt_buf.Buffer = bindings
            sec_buffer_in.append(cbt_buf)

        _, out_buffers = auth.authorize(sec_buffer_in)
        type3 = bytes(out_buffers[0].Buffer)

        self.sendTDS(tds.TDS_SSPI, type3)
        tds_resp = self.recvTDS()
        self.replies = self.parseReply(tds_resp["Data"])
        return tds.TDS_LOGINACK_TOKEN in self.replies

    def _resolve_sspi_channel_binding(self, cbt_mode: str) -> Optional[bytes]:
        """Return SEC_CHANNEL_BINDINGS bytes for ``cbt_mode`` (or None to omit).

        "missing" omits the buffer; an unencrypted connection has no tls-unique,
        so there is nothing to bind regardless of mode.
        """
        if cbt_mode == "missing" or not getattr(self, "tls_unique", None):
            return None
        if cbt_mode == "bogus":
            return _sec_channel_bindings(_BOGUS_TLS_UNIQUE)
        return _sec_channel_bindings(self.tls_unique)


# 16 bytes of garbage tls-unique material, used to forge a wrong SEC_CHANNEL_BINDINGS
# so Windows emits a channel binding hash the server will reject when it enforces EPA.
_BOGUS_TLS_UNIQUE = b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00"


def _sec_channel_bindings(tls_unique: bytes) -> bytes:
    """Build a Windows ``SEC_CHANNEL_BINDINGS`` struct for the given tls-unique.

    Layout: eight little-endian ULONGs (initiator/acceptor addr type+len+offset,
    application-data len+offset) followed by the application data. Windows hashes
    this into the NTLM ``MsvAvChannelBindings`` AV pair; the server recomputes the
    same value from its TLS channel, so the application data must match impacket's
    ``generate_cbt_from_tls_unique`` form (``b"tls-unique:" + tls_unique``).
    """
    import struct

    app_data = b"tls-unique:" + tls_unique
    header = struct.pack("<8L", 0, 0, 0, 0, 0, 0, len(app_data), 32)
    return header + app_data


def impacket_prober(
    *,
    target: str,
    port: int,
    remote_name: str,
    domain: str,
    username: str,
    password: Optional[str],
    hashes: Optional[str],
    service_class: str = DEFAULT_SERVICE_CLASS,
) -> Callable[[str], ProbeOutcome]:
    """Return a ``probe(mode)`` that runs one explicit-credential EPA login.

    A fresh connection is made per probe (matching the reference) so connection
    state never leaks between modes.
    """

    def probe(mode: str) -> ProbeOutcome:
        params = _mode_login_params(mode, service_class)
        client = _MSSQLEPA(target, port, remote_name)
        return _run_login_probe(
            client,
            mode,
            target,
            lambda: client.login(
                database=None,
                username=username,
                password=password or "",
                domain=domain,
                hashes=hashes,
                **params,
            ),
        )

    return probe


def sspi_prober(
    *,
    target: str,
    port: int,
    remote_name: str,
    correct_spn: str,
) -> Callable[[str], ProbeOutcome]:
    """Return a ``probe(mode)`` that runs one current-user SSPI (integrated) login.

    ``correct_spn`` is the full service SPN (e.g. ``MSSQLSvc/host.fqdn:1433``).
    Channel-binding modes keep that SPN and vary the binding token; service modes
    keep the correct binding and vary the SPN (``cifs/host`` / omitted).
    """
    host = correct_spn.split("/", 1)[1].split(":", 1)[0] if "/" in correct_spn else remote_name
    mode_spec = {
        "normal": (correct_spn, "correct"),
        "bogus_cbt": (correct_spn, "bogus"),
        "missing_cbt": (correct_spn, "missing"),
        "bogus_service": (f"cifs/{host}", "correct"),
        "missing_service": (None, "correct"),
    }

    def probe(mode: str) -> ProbeOutcome:
        target_spn, cbt_mode = mode_spec[mode]
        client = _MSSQLEPA(target, port, remote_name)
        return _run_login_probe(
            client,
            mode,
            target,
            lambda: client.login_sspi(target_spn=target_spn, cbt_mode=cbt_mode),
        )

    return probe


def _run_login_probe(
    client: "_MSSQLEPA",
    mode: str,
    target: str,
    login_call: Callable[[], bool],
) -> ProbeOutcome:
    """Connect, run one login attempt, classify the outcome, and disconnect.

    Shared by both probers; only ``login_call`` differs between explicit-cred and
    SSPI auth. Any exception is reported as an unauthenticated "other" outcome so
    a single failed probe never aborts the whole determination.
    """
    try:
        client.connect()
        authenticated = login_call()
        enc, strict = client.epa_encryption_flag, client.epa_is_strict
        if authenticated:
            logger.debug("EPA probe %s on %s: success", mode, target)
            return ProbeOutcome(success=True, encryption_flag=enc, is_strict=strict)
        outcome = _classify_error_text(client.getErrorMessages())
        outcome.encryption_flag = enc
        outcome.is_strict = strict
        logger.debug("EPA probe %s on %s: %s", mode, target, outcome.error_message)
        return outcome
    except Exception as ex:  # noqa: BLE001 - any failure classifies as 'other'
        logger.debug("EPA probe %s on %s raised: %s", mode, target, ex)
        return ProbeOutcome(
            error_message=str(ex),
            encryption_flag=getattr(client, "epa_encryption_flag", ENCRYPT_OFF),
            is_strict=getattr(client, "epa_is_strict", False),
        )
    finally:
        try:
            client.disconnect()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass


# --- Orchestration (auth ladder + SPN selection) ----------------------------


def _select_mssql_spn(spns: Optional[list], host: str, port: int) -> str:
    """Pick the registered ``MSSQLSvc`` SPN, or derive ``MSSQLSvc/host:port``."""
    for spn in spns or []:
        if spn.lower().startswith(DEFAULT_SERVICE_CLASS.lower() + "/"):
            return spn
    return f"{DEFAULT_SERVICE_CLASS}/{host}:{port}"


def _format_hashes(nt_hash: Optional[str]) -> Optional[str]:
    """Normalize an NT hash to impacket's ``LMHASH:NTHASH`` form (or None)."""
    if not nt_hash:
        return None
    if ":" in nt_hash:
        return nt_hash
    return f"{EMPTY_LM_HASH}:{nt_hash}"


def _choose_auth(
    *,
    username: Optional[str],
    password: Optional[str],
    nt_hash: Optional[str],
    sspi_available: bool,
) -> str:
    """Resolve the auth ladder to "explicit", "sspi", or "skip"."""
    if username and (password or nt_hash):
        return "explicit"
    if sspi_available:
        return "sspi"
    return "skip"


def _sspi_available() -> bool:
    """True only on Windows with the pywin32 SSPI modules importable."""
    import sys

    if sys.platform != "win32":
        return False
    try:
        import sspi  # noqa: F401
        import sspicon  # noqa: F401
        import win32security  # noqa: F401

        return True
    except ImportError:
        return False


def _split_user_domain(username: str, default_domain: str) -> tuple[str, str]:
    """Split ``DOMAIN\\user`` or ``user@domain`` into ``(domain, user)``."""
    if "\\" in username:
        domain, user = username.split("\\", 1)
        return domain, user
    if "@" in username:
        user, domain = username.split("@", 1)
        return domain, user
    return default_domain, username


def test_epa(
    *,
    target: str,
    port: int = 1433,
    remote_name: Optional[str] = None,
    domain: str = "",
    username: Optional[str] = None,
    password: Optional[str] = None,
    nt_hash: Optional[str] = None,
    spns: Optional[list] = None,
) -> Optional[EPAResult]:
    """Determine EPA enforcement for one SQL Server, selecting the auth method.

    Auth ladder: explicit credentials (password or NT hash) -> current-user SSPI
    integrated auth -> skip (returns None). ``spns`` is the host's AD SPN list,
    used to pick the registered ``MSSQLSvc`` SPN. Raises ``EPAPrereqError`` when
    the baseline login fails to establish a trustworthy result.
    """
    remote_name = remote_name or target
    correct_spn = _select_mssql_spn(spns, remote_name, port)
    service_class = correct_spn.split("/", 1)[0]

    choice = _choose_auth(
        username=username, password=password, nt_hash=nt_hash, sspi_available=_sspi_available()
    )
    if choice == "explicit":
        # _choose_auth returns "explicit" only when username is non-empty.
        assert username is not None
        auth_domain, sam = _split_user_domain(username, domain)
        logger.info("EPA testing %s via explicit credentials for %s\\%s", target, auth_domain, sam)
        prober = impacket_prober(
            target=target,
            port=port,
            remote_name=remote_name,
            domain=auth_domain,
            username=sam,
            password=password,
            hashes=_format_hashes(nt_hash),
            service_class=service_class,
        )
        return determine_epa(prober, auth_method="explicit")
    elif choice == "sspi":
        logger.info("EPA testing %s via current-user SSPI (NTLM) integrated auth", target)
        prober = sspi_prober(
            target=target, port=port, remote_name=remote_name, correct_spn=correct_spn
        )
        return determine_epa(prober, auth_method="sspi")
    else:
        logger.warning("EPA testing %s skipped: no credentials and SSPI unavailable", target)
        return None


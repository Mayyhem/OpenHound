"""Transport-only WMI client: per-target DCOM/WMI connection + credential ladder.

``WmiClient`` plays the role ``clients/http.HttpClient`` plays for HTTP: it owns a
per-target connection and a credential ladder, and streams normalized rows for a
WQL query. It is service-agnostic — the caller supplies the WMI *namespace* and
class (e.g. ``root\\SMS\\site_<code>`` for the SCCM SMS Provider, ``root\\cimv2``
for stock WMI); nothing here knows about SCCM.

Auth reuses ``http_auth.choose_auth`` for credential *precedence*, then realizes
each rung over a WMI transport:

  * ``ticket`` / ``kerberos`` / ``ntlm`` -> impacket DCOM (incl. pass-the-hash,
    pass-the-ticket); cross-platform.
  * ``sspi``     -> pywin32 WMI as the current Windows user; Windows-only.
  * ``anonymous``-> skipped (DCOM always requires authentication).

The first rung whose ``execquery`` runs the caller's initial query without raising
wins and is cached; later queries reuse it. Rows stream: each is yielded as it is
pulled off the WMI enumerator.
"""
from __future__ import annotations

import base64
import logging
from typing import Any, Iterator, Optional

from .. import log_context  # noqa: F401  (registers logger.verbose on logging.Logger)
from . import http_auth
from .http_auth import format_hashes, split_user_domain

logger = logging.getLogger(__name__)


def _build_wql(class_name: str, columns: Optional[tuple] = None, where: Optional[str] = None) -> str:
    """Render a WQL query. ``columns=None`` selects all (``SELECT *``)."""
    select = ",".join(columns) if columns else "*"
    wql = f"SELECT {select} FROM {class_name}"
    if where:
        wql += f" WHERE {where}"
    return wql


# --- row normalization ----------------------------------------------------
# Both backends normalize a WMI instance to a plain ``{Name: value}`` dict so
# the shared ``sms_rows._row``/``_prop`` helpers can shape rows identically to
# AdminService. Embedded objects (e.g. an SMS_SCI_* ``Props`` array) recurse to
# nested dicts/lists, matching the JSON the AdminService REST API returns.

def _normalize(props: Any) -> dict:
    """impacket ``IWbemClassObject.getProperties()`` -> ``{Name: value}``."""
    out: dict[str, Any] = {}
    for name in props:
        out[name] = _unwrap(props[name].get("value"))
    return out


def _unwrap(value: Any) -> Any:
    if isinstance(value, list):
        return [_unwrap(v) for v in value]
    # A directly-returned WMI object exposes getProperties(); recurse into it.
    if hasattr(value, "getProperties"):
        return _normalize(value.getProperties())
    # An embedded WMI object (e.g. an SMS Props element) comes back as an
    # impacket ENCODING_UNIT whose ObjectBlock must be parsed to expose its
    # {name: {value: ...}} map. The top-level IWbemClassObject does this in its
    # __init__; embedded ones are left unparsed, so do it here.
    embedded = _embedded_props(value)
    if embedded is not None:
        return _normalize(embedded)
    return value


def _embedded_props(value: Any):
    """Return an embedded impacket ENCODING_UNIT's property map, or None."""
    try:
        object_block = value["ObjectBlock"]
    except (TypeError, KeyError, IndexError):
        return None
    parse = getattr(object_block, "parseObject", None)
    if parse is None:
        return None
    try:
        parse()
    except Exception:  # noqa: BLE001 - undecodable embedded object: leave it raw
        return None
    if object_block.ctCurrent is None:
        return None
    return object_block.ctCurrent["properties"]


def _normalize_swbem(obj: Any) -> dict:
    """pywin32 SWbemObject -> ``{Name: value}``."""
    out: dict[str, Any] = {}
    for prop in obj.Properties_:
        out[prop.Name] = _unwrap_swbem(prop.Value)
    return out


def _unwrap_swbem(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return [_unwrap_swbem(v) for v in value]
    # Embedded SWbemObjects expose Properties_; recurse into them.
    if hasattr(value, "Properties_"):
        return _normalize_swbem(value)
    return value


# --- backends -------------------------------------------------------------

class _ImpacketBackend:
    """WMI over impacket DCOM: explicit creds, pass-the-hash, pass-the-ticket.

    impacket breaks if a second ``IWbemLevel1Login`` is issued over one
    ``DCOMConnection`` -- the second namespace's queries fail with a bind-context
    rejection (validated live against ps1-sms). So each WMI namespace gets its
    own ``DCOMConnection``. The collector touches two namespaces total
    (``root\\SMS`` for identification, ``root\\SMS\\site_<code>`` for every
    collection), so this is at most two connections per host.
    """

    def __init__(self, target: str, *, domain: str, username: str, password: str,
                 lmhash: str, nthash: str, do_kerberos: bool, kdc_host: Optional[str],
                 tgt: Any = None, tgs: Any = None) -> None:
        self._target = target
        self._domain = domain
        self._username = username
        self._password = password
        self._lmhash = lmhash
        self._nthash = nthash
        self._do_kerberos = do_kerberos
        self._kdc_host = kdc_host
        self._tgt = tgt
        self._tgs = tgs
        # namespace -> (DCOMConnection, IWbemServices), one connection per namespace
        self._conns: dict[str, tuple] = {}

    def connect(self) -> None:
        # Connections are opened lazily per namespace in _services_for(); the
        # auth ladder still fails fast because identify() issues its first query
        # immediately after connect(), and a bad-credential DCOMConnection raises
        # then. Nothing to do eagerly here.
        return

    def _services_for(self, namespace: str):
        if namespace not in self._conns:
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            from impacket.dcerpc.v5.dcom import wmi
            from impacket.dcerpc.v5.dtypes import NULL
            dcom = DCOMConnection(
                self._target, self._username, self._password, self._domain,
                self._lmhash, self._nthash, "", self._tgt, self._tgs,
                oxidResolver=True, doKerberos=self._do_kerberos, kdcHost=self._kdc_host,
            )
            iinterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            login = wmi.IWbemLevel1Login(iinterface)
            svc = login.NTLMLogin(f"\\\\{self._target}\\{namespace}", NULL, NULL)
            login.RemRelease()
            self._conns[namespace] = (dcom, svc)
        return self._conns[namespace][1]

    def execquery(self, namespace: str, wql: str):
        """Establish the namespace connection (raising on auth failure) and return
        the WMI enumerator for *wql*. The auth ladder treats a raised exception
        here as the signal that this credential rung is unusable."""
        return self._services_for(namespace).ExecQuery(wql)

    def stream(self, enum) -> Iterator[dict]:
        """Yield normalized rows off a WMI enumerator until S_FALSE ends it."""
        try:
            while True:
                try:
                    obj = enum.Next(0xFFFFFFFF, 1)[0]
                except Exception as ex:  # noqa: BLE001 - S_FALSE marks end of enumeration
                    if "S_FALSE" in str(ex):
                        break
                    raise
                yield _normalize(obj.getProperties())
        finally:
            enum.RemRelease()

    def close(self) -> None:
        for dcom, _svc in self._conns.values():
            try:
                dcom.disconnect()
            except Exception as ex:  # noqa: BLE001 - best-effort teardown
                logger.debug("DCOM disconnect from %s failed: %s", self._target, ex)
        self._conns.clear()


class _PyWin32Backend:
    """WMI over pywin32 as the current Windows user (the SSPI ladder rung)."""

    def __init__(self, target: str) -> None:
        self._target = target
        self._locator: Any = None
        self._services: dict[str, Any] = {}

    def connect(self) -> None:
        import win32com.client
        self._locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")

    def _services_for(self, namespace: str):
        if namespace not in self._services:
            # No user/password -> ConnectServer authenticates as the current user.
            self._services[namespace] = self._locator.ConnectServer(self._target, namespace)
        return self._services[namespace]

    def execquery(self, namespace: str, wql: str):
        return self._services_for(namespace).ExecQuery(wql)

    def stream(self, objset) -> Iterator[dict]:
        for o in objset:
            yield _normalize_swbem(o)

    def close(self) -> None:
        # pywin32 COM objects release on garbage collection; nothing to do.
        self._services.clear()


# --- client ---------------------------------------------------------------

class WmiClient:
    """Per-target WMI client mirroring ``HttpClient`` for the SMS Provider."""

    def __init__(self, *, target: str, domain: str, username: Optional[str] = None,
                 password: Optional[str] = None, nt_hash: Optional[str] = None,
                 kerberos_ticket: Optional[str] = None, kdc_host: Optional[str] = None) -> None:
        self._target = target
        self._domain = domain or ""
        self._username = username
        self._password = password
        self._nt_hash = nt_hash
        self._kerberos_ticket = kerberos_ticket
        self._kdc_host = kdc_host
        self._backend: Any = None       # the rung that connected, cached

    @classmethod
    def from_context(cls, ctx, target: str) -> "WmiClient":
        """Build a client for *target*, reading credentials from a SourceContext.

        The KDC defaults to the already-resolved domain controller, matching
        ``HttpClient.from_context``.
        """
        kdc = None
        creds = getattr(getattr(ctx, "ad", None), "creds", None)
        if creds is not None:
            kdc = getattr(creds, "domain_controller", None)
        return cls(
            target=target,
            domain=getattr(ctx, "domain", "") or "",
            username=getattr(ctx, "username", None),
            password=getattr(ctx, "password", None),
            nt_hash=getattr(ctx, "nt_hash", None),
            kerberos_ticket=getattr(ctx, "kerberos_ticket", None),
            kdc_host=kdc,
        )

    # ----- auth ladder ----------------------------------------------------

    def _build_backend(self, rung: str):
        """Construct the WMI backend for a chosen ladder rung (None for anonymous)."""
        _, sam = split_user_domain(self._username or "", self._domain)
        if rung == "sspi":
            return _PyWin32Backend(self._target)
        if rung == "ntlm":
            ad_domain, _ = split_user_domain(self._username or "", self._domain)
            lm, nt = (format_hashes(self._nt_hash) or ":").split(":")
            return _ImpacketBackend(
                self._target, domain=ad_domain, username=sam, password=self._password or "",
                lmhash=lm, nthash=nt, do_kerberos=False, kdc_host=self._kdc_host,
            )
        if rung == "kerberos":
            lm, nt = (format_hashes(self._nt_hash) or ":").split(":")
            tgt = tgs = None
            if self._kerberos_ticket:
                ticket_user, tgt, tgs = self._load_ticket()
                # Pass-the-ticket may supply no -u; impacket still needs a client
                # principal for the AP-REQ, so derive it from the ticket's cname.
                if not sam:
                    sam = ticket_user
            return _ImpacketBackend(
                # doKerberos treats `domain` as the realm, so pass the full DNS domain.
                self._target, domain=self._domain, username=sam, password=self._password or "",
                lmhash=lm, nthash=nt, do_kerberos=True, kdc_host=self._kdc_host, tgt=tgt, tgs=tgs,
            )
        return None  # anonymous

    def _load_ticket(self):
        """Load a base64 KRB-CRED (.kirbi) into ``(username, TGT, TGS)`` for impacket.

        The client principal is read from the ticket so pass-the-ticket works
        even when no ``-u`` was supplied.
        """
        from impacket.krb5.ccache import CCache
        ccache = CCache()
        ccache.fromKRBCRED(base64.b64decode(self._kerberos_ticket, validate=True))
        if not ccache.credentials:
            raise ValueError("--ticket contains no usable credentials")
        cred = ccache.credentials[0]
        username = cred["client"].prettyPrint().decode("utf-8", "replace").split("@")[0]
        # impacket's DCOMConnection requests the DCOM service ticket from the TGT.
        tgt = cred.toTGT()
        return username, tgt, None

    def query(self, namespace: str, class_name: str, *, columns: Optional[tuple] = None,
              where: Optional[str] = None) -> Iterator[dict]:
        """Run a WQL query against *namespace*, streaming normalized rows.

        The first query runs the auth ladder (this query is the probe) and caches
        the winning backend; later queries reuse it. Yields nothing (and logs) if
        the ladder is exhausted or the query fails.
        """
        wql = _build_wql(class_name, columns, where)
        try:
            logger.verbose("WMI query on %s (%s): %s", self._target, namespace, wql)
            raw = self._open(namespace, wql)
        except Exception as ex:  # noqa: BLE001 - one class failing must not abort the rest
            logger.warning("WMI query %s on %s failed: %s", class_name, self._target, ex)
            return
        if raw is None:
            return  # ladder exhausted (logged in _open)
        yield from self._backend.stream(raw)

    def _open(self, namespace: str, wql: str):
        """Return a WMI enumerator for (namespace, wql).

        On the first call the auth ladder runs, using this query as the rung
        probe; the first rung whose ``execquery`` returns without raising wins and
        is cached. Returns None if every rung is exhausted.
        """
        if self._backend is not None:
            return self._backend.execquery(namespace, wql)
        plan = http_auth.choose_auth(
            username=self._username, password=self._password, nt_hash=self._nt_hash,
            ticket=self._kerberos_ticket, target_host=self._target,
            sspi_available=http_auth.sspi_negotiate_available(),
        )
        for rung in plan:
            backend = self._build_backend(rung)
            if backend is None:
                logger.info("WMI on %s: skipping anonymous rung (DCOM requires authentication)", self._target)
                continue
            try:
                logger.verbose("WMI auth attempt on %s via %s", self._target, rung)
                backend.connect()
                raw = backend.execquery(namespace, wql)
            except Exception as ex:  # noqa: BLE001 - this rung failed; try the next
                logger.verbose("WMI %s rung failed on %s: %s", rung, self._target, ex)
                backend.close()
                continue
            logger.info("WMI authenticated on %s via %s", self._target, rung)
            self._backend = backend
            return raw
        logger.info("WMI auth ladder exhausted on %s (%s)", self._target, plan)
        return None

    def close(self) -> None:
        if self._backend is not None:
            self._backend.close()

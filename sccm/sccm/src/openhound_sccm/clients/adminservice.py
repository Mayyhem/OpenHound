"""SCCM AdminService REST client (pure Python).

Uses ``requests`` plus a small ``HttpNegotiateAuth`` handler built on
``pyspnego`` for SPNEGO/Negotiate auth with explicit credentials. With a
username/password supplied at construction time, pyspnego selects Kerberos
under SPNEGO so each call authenticates as the configured user — no
dependence on the host process's session ticket and no need for
``runas /netonly`` to differentiate users.

Channel Bindings (RFC 5929 ``tls-server-end-point``) are computed from the
server certificate when the connection is HTTPS, so the client works
against IIS sites that enforce Extended Protection (EPA).
"""

from __future__ import annotations

import base64
import logging
import socket
import warnings
from typing import Any, Optional
from urllib.parse import urlparse

import requests
import spnego
import spnego.channel_bindings
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from requests.auth import AuthBase
from urllib3.exceptions import InsecureRequestWarning
from urllib3.response import HTTPResponse

logger = logging.getLogger(__name__)


class HttpNegotiateAuth(AuthBase):
    """Requests auth handler that drives SPNEGO/Negotiate with explicit creds.

    With ``(username, password)``, pyspnego negotiates Kerberos under SPNEGO
    when the server supports it, giving true per-user differentiation.
    Channel Binding Tokens (RFC 5929 ``tls-server-end-point``) are computed
    from the server certificate when the connection is HTTPS, so the
    handler works against IIS sites that enforce Extended Protection.
    """

    _MAX_ROUNDS = 8

    def __init__(
        self,
        username: Optional[str],
        password: Optional[str],
        send_cbt: bool = True,
    ) -> None:
        self.username = username
        self.password = password
        self.send_cbt = send_cbt

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        request.headers["Connection"] = "Keep-Alive"
        request.register_hook("response", self._response_hook)
        return request

    def _response_hook(
        self,
        response: requests.Response,
        **kwargs: Any,
    ) -> requests.Response:
        if response.status_code != 401:
            return response
        if "negotiate" not in response.headers.get("www-authenticate", "").lower():
            return response
        return self._negotiate(response, kwargs)

    def _negotiate(
        self,
        response: requests.Response,
        kwargs: dict[str, Any],
    ) -> requests.Response:
        cbt = None
        if self.send_cbt:
            cert_hash = _server_cert_hash(response)
            if cert_hash is not None:
                cbt = spnego.channel_bindings.GssChannelBindings(
                    application_data=b"tls-server-end-point:" + cert_hash
                )

        target_hostname = urlparse(response.url).hostname or ""
        try:
            client = spnego.client(
                self.username,
                self.password,
                protocol="negotiate",
                channel_bindings=cbt,
                hostname=target_hostname,
                service="HTTP",
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("adminservice spnego.client init failed: %s", exc)
            return response

        response.content
        response.raw.release_conn()

        in_token: Optional[bytes] = None
        request = response.request.copy()
        connection = response.connection
        send_kwargs = dict(kwargs, stream=False)
        prior = response

        for _ in range(self._MAX_ROUNDS):
            try:
                out_token = client.step(in_token)
            except Exception as exc:  # noqa: BLE001
                logger.debug("adminservice spnego step failed: %s", exc)
                return prior
            if not out_token:
                return prior

            request.headers["Authorization"] = (
                "Negotiate " + base64.b64encode(out_token).decode("ascii")
            )
            try:
                next_response = connection.send(request, **send_kwargs)
            except requests.RequestException as exc:
                logger.debug("adminservice negotiate send failed: %s", exc)
                return prior

            if next_response.status_code != 401:
                final_token = _extract_token(
                    next_response.headers.get("www-authenticate")
                )
                if final_token is not None:
                    try:
                        client.step(final_token)
                    except Exception as exc:  # noqa: BLE001
                        logger.debug(
                            "adminservice spnego mutual-auth check failed: %s", exc
                        )
                next_response.history.append(prior)
                return next_response

            challenge_token = _extract_token(
                next_response.headers.get("www-authenticate")
            )
            next_response.content
            next_response.raw.release_conn()
            if challenge_token is None:
                next_response.history.append(prior)
                return next_response

            cookie = next_response.headers.get("set-cookie")
            request = next_response.request.copy()
            if cookie:
                request.headers["Cookie"] = cookie
            in_token = challenge_token
            prior = next_response

        return prior


def _extract_token(header_value: Optional[str]) -> Optional[bytes]:
    if not header_value:
        return None
    for part in header_value.split(","):
        part = part.strip()
        if part.lower().startswith("negotiate"):
            _, _, value = part.partition(" ")
            value = value.strip()
            if not value:
                return None
            try:
                return base64.b64decode(value)
            except Exception:  # noqa: BLE001
                return None
    return None


def _server_cert_hash(response: requests.Response) -> Optional[bytes]:
    raw_response = response.raw
    if not isinstance(raw_response, HTTPResponse):
        return None
    sock_obj = getattr(getattr(getattr(raw_response, "_fp", None), "fp", None), "raw", None)
    sock_obj = getattr(sock_obj, "_sock", None) if sock_obj is not None else None
    if sock_obj is None:
        return None
    try:
        cert_der = sock_obj.getpeercert(True)
    except (AttributeError, OSError):
        return None
    if not cert_der:
        return None
    return _certificate_hash(cert_der)


def _certificate_hash(cert_der: bytes) -> Optional[bytes]:
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    try:
        hash_algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        hash_algorithm = None
    if not hash_algorithm or hash_algorithm.name in ("md5", "sha1"):
        digest = hashes.Hash(hashes.SHA256(), default_backend())
    else:
        digest = hashes.Hash(hash_algorithm, default_backend())
    digest.update(cert_der)
    return digest.finalize()


class AdminServiceClient:
    """Pure-Python client for the SCCM Administration Service REST API."""

    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = False,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        parsed = urlparse(self.base_url)
        self._host: str = parsed.hostname or ""
        self._port: int = parsed.port or (443 if parsed.scheme == "https" else 80)

        if not verify_ssl:
            warnings.simplefilter("ignore", InsecureRequestWarning)

        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})
        self._session.verify = verify_ssl
        self._session.auth = HttpNegotiateAuth(username, password)

    def host_reachable(self, port: Optional[int] = None, timeout: float = 3.0) -> bool:
        host = self._host
        port = port or self._port
        if not host:
            return False
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def get(
        self,
        endpoint: str,
        params: Optional[dict] = None,
    ) -> Optional[dict[str, Any]]:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        request_params: Optional[dict] = None

        if params:
            # OData ``$``-prefixed parameters are stitched in raw so the
            # literal ``$`` isn't escaped to ``%24`` (the AdminService 400s
            # on percent-encoded ``$``).
            odata_pairs = [(k, v) for k, v in params.items() if k.startswith("$")]
            other = {k: v for k, v in params.items() if not k.startswith("$")}
            if odata_pairs:
                separator = "&" if "?" in url else "?"
                url = url + separator + "&".join(f"{k}={v}" for k, v in odata_pairs)
            request_params = other or None

        try:
            response = self._session.get(
                url,
                params=request_params,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            logger.debug("adminservice request failed for %s: %s", url, exc)
            return None

        status_code = response.status_code
        if status_code == 401:
            logger.warning("adminservice 401 (auth) on %s", url)
            return None
        if status_code == 403:
            logger.warning("adminservice 403 (forbidden) on %s", url)
            return None
        if status_code == 404:
            logger.debug("adminservice 404 on %s", url)
            return None
        if status_code >= 400:
            logger.debug("adminservice HTTP %s on %s", status_code, url)
            return None

        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            logger.debug("adminservice JSON decode failed on %s: %s", url, exc)
            return None

    def get_paginated(
        self,
        endpoint: str,
        top: int = 1000,
        extra_params: Optional[dict] = None,
    ) -> list[dict[str, Any]]:
        all_results: list[dict[str, Any]] = []
        skip = 0
        while True:
            params: dict[str, Any] = {"$top": top, "$skip": skip}
            if extra_params:
                params.update(extra_params)
            response = self.get(endpoint, params=params)
            if not response:
                break
            items = response.get("value", [])
            if not items:
                break
            all_results.extend(items)
            logger.debug(
                "adminservice fetched %d items from %s (total: %d)",
                len(items), endpoint, len(all_results),
            )
            if len(items) < top:
                break
            skip += top
        return all_results

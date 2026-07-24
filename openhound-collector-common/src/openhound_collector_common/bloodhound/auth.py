"""HTTP request signing for the BloodHound CE API.

Two schemes, matching BloodHound CE and the Go MSSQLHound client:
* HMAC-SHA256 — a three-step keyed chain over method+URI, the request hour, and
  the body. Used when both a token ID and secret key are supplied.
* Bearer — a JWT in the Authorization header. Used when only a token is supplied.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
from typing import Callable, Optional, Union


class HMACAuth:
    """Sign requests with BloodHound CE's chained HMAC-SHA256 scheme.

    OperationKey = HMAC(token_key, method+uri); DateKey = HMAC(OperationKey,
    hour); Signature = HMAC(DateKey, body). The RequestDate we send and the hour
    we sign are derived from the same instant, so the server (which truncates the
    RequestDate it receives to the hour) recomputes an identical signature.
    """

    def __init__(self, token_id: str, token_key: str,
                 now_func: Optional[Callable[[], datetime.datetime]] = None) -> None:
        self.token_id = token_id
        self.token_key = token_key
        # Injectable clock for deterministic tests; defaults to UTC now.
        self._now = now_func or (lambda: datetime.datetime.now(datetime.timezone.utc))

    def headers(self, method: str, path: str, body: Optional[bytes]) -> dict[str, str]:
        digester = hmac.new(self.token_key.encode(), None, hashlib.sha256)
        digester.update(f"{method}{path}".encode())

        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        request_date = self._now().astimezone().isoformat("T")
        # BH CE truncates to the hour ("YYYY-MM-DDTHH" = first 13 chars).
        digester.update(request_date[:13].encode())

        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        if body:
            digester.update(body)

        signature = base64.b64encode(digester.digest()).decode()
        return {
            "Authorization": f"bhesignature {self.token_id}",
            "RequestDate": request_date,
            "Signature": signature,
        }


class BearerAuth:
    """Sign requests with a JWT Bearer token (the simpler BH CE scheme)."""

    def __init__(self, token: str) -> None:
        self.token = token

    def headers(self, method: str, path: str, body: Optional[bytes]) -> dict[str, str]:
        # method/path/body unused — a Bearer header is request-independent.
        return {"Authorization": f"Bearer {self.token}"}


Authenticator = Union[HMACAuth, BearerAuth]

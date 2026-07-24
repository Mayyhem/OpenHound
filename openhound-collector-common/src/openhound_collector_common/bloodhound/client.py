"""Retrying HTTP client for the BloodHound CE upload + extensions APIs.

Ports MSSQLHound/internal/uploader/client.go. Endpoints:
  POST /api/v2/file-upload/start      -> start a results job, returns its id
  POST /api/v2/file-upload/{id}       -> upload one file (json or zip)
  POST /api/v2/file-upload/{id}/end   -> signal the job is complete
  PUT  /api/v2/extensions             -> register custom node/edge schema
Transient failures (HTTP 429 / 5xx) are retried with exponential backoff. The
`send`/`sleep` callables are injectable so tests run offline with no real waits.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Callable, Optional

import requests

from .auth import Authenticator

logger = logging.getLogger(__name__)

_START_PATH = "/api/v2/file-upload/start"
_FILE_PATH = "/api/v2/file-upload/{job_id}"
_END_PATH = "/api/v2/file-upload/{job_id}/end"
_EXTENSIONS_PATH = "/api/v2/extensions"

_OK_STATUSES = frozenset({200, 201, 202, 204})


class BloodHoundHTTPError(Exception):
    """A BloodHound API call failed (non-success status or exhausted retries)."""

    def __init__(self, operation: str, code: int, reason: str) -> None:
        self.operation = operation
        self.code = code
        self.reason = reason
        super().__init__(f"{operation} failed (HTTP {code}): {reason[:300]}")


def _default_send(method, url, headers, data, timeout):
    return requests.request(method=method, url=url, headers=headers, data=data, timeout=timeout)


class BloodHoundClient:
    def __init__(
        self,
        base_url: str,
        auth: Authenticator,
        *,
        max_retries: int = 3,
        retry_delay: float = 2.0,
        timeout: float = 60.0,
        send: Optional[Callable] = None,
        sleep: Optional[Callable[[float], None]] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = auth
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        self._send = send or _default_send
        self._sleep = sleep or time.sleep

    def _request(self, method: str, path: str, body: Optional[bytes], content_type: str, operation: str):
        url = self.base_url + path
        delay = self.retry_delay
        last_reason = ""
        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                logger.debug("%s: retry %d/%d after %.1fs", operation, attempt, self.max_retries, delay)
                self._sleep(delay)
                delay *= 2
            headers = {"Content-Type": content_type, **self.auth.headers(method, path, body)}
            try:
                resp = self._send(method, url, headers, body, self.timeout)
            except requests.RequestException as exc:
                # Network-level failure — retry until the budget is spent.
                last_reason = str(exc)
                logger.warning("%s: request error (%s)", operation, exc)
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                last_reason = getattr(resp, "text", "") or f"HTTP {resp.status_code}"
                logger.warning("%s: transient HTTP %d", operation, resp.status_code)
                continue
            if resp.status_code not in _OK_STATUSES:
                # Non-transient failure — do not retry; surface immediately.
                raise BloodHoundHTTPError(operation, resp.status_code, getattr(resp, "text", "") or "")
            return resp
        raise BloodHoundHTTPError(operation, 0, f"exhausted {self.max_retries + 1} attempts: {last_reason}")

    def start_upload(self) -> str:
        resp = self._request("POST", _START_PATH, b"{}", "application/json", "start upload")
        try:
            data = resp.json() or {}
            job_id = (data.get("data") or {}).get("id")
        except (ValueError, AttributeError) as exc:
            raise BloodHoundHTTPError("start upload", resp.status_code, f"unparseable response body: {exc}") from exc
        if not job_id:
            raise BloodHoundHTTPError("start upload", resp.status_code, "empty job id in response")
        return str(job_id)

    def upload_file(self, job_id: str, file_path: Path) -> None:
        body = Path(file_path).read_bytes()
        content_type = "application/zip" if Path(file_path).suffix.lower() == ".zip" else "application/json"
        self._request("POST", _FILE_PATH.format(job_id=job_id), body, content_type,
                      f"upload file {Path(file_path).name}")

    def end_upload(self, job_id: str) -> None:
        self._request("POST", _END_PATH.format(job_id=job_id), b"{}", "application/json", "end upload")

    def upload_schema(self, data: bytes) -> None:
        self._request("PUT", _EXTENSIONS_PATH, data, "application/json", "upload schema")

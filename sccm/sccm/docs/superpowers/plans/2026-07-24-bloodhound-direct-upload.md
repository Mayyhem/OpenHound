# BloodHound CE Direct Upload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **This repo forbids agent git commits** — every task ends at a *green checkpoint* (targeted tests pass, stop for the owner to review + commit), not a `git commit`.

**Ticket:** ope-8c44

**Goal:** Add direct upload of the OpenHound graph to BloodHound CE — schema (custom node/edge kinds) and results (a zip of the OpenGraph files) — driven from the SCCM collector's `collect` (`--run-all`) and `convert` commands, built on a reusable uploader in `openhound-collector-common`.

**Architecture:** Port the Go MSSQLHound upload flow ([`MSSQLHound/internal/uploader`](../../../../MSSQLHound/internal/uploader), [`internal/bloodhound/writer.go`](../../../../MSSQLHound/internal/bloodhound/writer.go)) into a new, framework-agnostic `bloodhound/` subpackage of `openhound-collector-common`: a small HTTP client (`PUT /api/v2/extensions` for schema; `POST /api/v2/file-upload/{start,{id},end}` job flow for results; HMAC or Bearer auth; retry on 429/5xx with exponential backoff), a zip bundler, and a schema-mutation helper. SCCM supplies its two schema files (`schema.json` + `schema_MSSQL.json`) and calls one shared `run_upload(...)` orchestration from both CLI commands. `convert sccm` must be **hand-registered** on the framework's `convert` Typer group (the `@app.convert` decorator exposes no seam for extra flags), mirroring how `collect sccm` is already hand-registered.

**Tech Stack:** Python 3.13+, Typer (CLI), `requests` (HTTP), stdlib `hmac`/`hashlib`/`zipfile`/`json`, pytest. No changes to OpenHound core.

## Global Constraints

Copy these verbatim into every task's mental checklist:

- **Locked decisions (from the design grill, 2026-07-24):**
  - **D1 — API surface:** Port the Go flow. Schema → `PUT /api/v2/extensions`. Results → `POST /api/v2/file-upload/start` → `POST /api/v2/file-upload/{id}` (one file per POST, `application/zip` or `application/json` by extension) → `POST /api/v2/file-upload/{id}/end`. Auth: HMAC (`token-id` + `token-key`) if both present, else Bearer (`token-id` only). Retry 3× on HTTP 429/5xx with exponential backoff (2s, doubling).
  - **D2 — Code location:** Reusable uploader lives in `openhound-collector-common`. Wire into the **SCCM collector only** for now; MSSQL/future collectors adopt later.
  - **D3 — CLI placement:** Upload flags live on **both** `collect sccm` and `convert sccm`. `collect --run-all -B …` uploads end-to-end; `convert -B …` uploads what convert produced.
  - **D4 — Results payload:** a **zip** of the convert output JSON files. **No `seed_data.json`** (the `PUT /api/v2/extensions` schema already registers every kind).
  - **D5 — Schemas uploaded:** **both** `sccm/sccm/schema.json` (namespace `SCCM`) and `sccm/sccm/schema_MSSQL.json` (namespace `MSSQL`), because the SCCM collector emits `MSSQL_*` edges/nodes whose kinds live in the MSSQL schema.
  - **D6 — Upload-only / standalone:** `--upload-dir <graph_dir>` uploads existing OpenGraph files without collecting/converting. `--skip-collection` (Go semantics) = push schema only, no collection.
  - **D7 — `--disable-possible-edges`:** before `PUT`, flip `is_traversable` → `false` for the "possible" relationship kinds in each schema (SCCM: the two coerce-and-relay kinds; MSSQL: the Go `PossibleEdgeKinds` set). Port of `SchemaJSONWithDisabledPossibleEdges`.
- **Flag names (verbatim, mirror the Go tool):** `-B/--bloodhound <token-id>:<token_key>@<url>`, `--bloodhound-url` (env `BLOODHOUND_URL`), `--token-id` (env `BLOODHOUND_TOKEN_ID`), `--token-key` (env `BLOODHOUND_TOKEN_KEY`), `--upload-schema-only`, `--upload-results-only` (mutually exclusive), `--skip-collection`, `--upload-dir`.
- **No OpenHound core edits.** Only `openhound-collector-common/` and `sccm/sccm/` (shared-lib changes are owner-gated — approved for this task — and must re-validate both extensions).
- **No git commits by the agent.** End each task green; the owner commits.
- **Logging:** every `if/else` and `try/except` gets an appropriately-levelled log (error/warning/info/verbose/debug) unless truly needless (then a comment). Secrets (`token-key`) must never be logged.
- **Tests** live under each package's `tests/` dir. Validate with the package venv: shared lib → `cd openhound-collector-common && uv run pytest tests/<file> -v`; SCCM → `cd sccm/sccm && uv run pytest tests/<file> -v`. Do not run the full suite.
- **Docs are code-truth.** Update the SCCM README (Quick Start, CLI, examples) and ARCHITECTURE.md when behavior changes; keep TICKETS-BY-STATUS.md current.

---

## File Structure

**New — shared library (`openhound-collector-common/src/openhound_collector_common/bloodhound/`):**
- `__init__.py` — public exports.
- `auth.py` — `HMACAuth`, `BearerAuth`: produce request-signing headers.
- `client.py` — `BloodHoundClient`: retrying HTTP + the four endpoints.
- `uploader.py` — `BloodHoundUploader`, `UploadSummary`, `build_uploader(...)`, `resolve_credentials(...)`, `parse_bloodhound_shorthand(...)`.
- `zip_bundle.py` — `bundle_graph_dir(...)`.
- `schema.py` — `disable_possible_edges(...)`.

**New — shared library tests (`openhound-collector-common/tests/`):**
- `test_bloodhound_auth.py`, `test_bloodhound_client.py`, `test_bloodhound_uploader.py`, `test_bloodhound_zip.py`, `test_bloodhound_schema.py`.

**New — SCCM (`sccm/sccm/src/openhound_sccm/`):**
- `bloodhound_schemas.py` — load + mutate SCCM's two schema files.
- `bloodhound_upload.py` — `run_upload(...)`: the single orchestration both commands call.

**New — SCCM tests (`sccm/sccm/tests/`):**
- `bloodhound_schemas_test.py`, `bloodhound_upload_test.py`, `bloodhound_cli_test.py`.

**Modified:**
- `openhound-collector-common/pyproject.toml` — add `requests` dependency.
- `sccm/sccm/src/openhound_sccm/main.py` — upload flags on `collect_sccm`; hand-register `convert sccm` with upload flags; set `app.converter` manually.
- `sccm/sccm/README.md`, `sccm/sccm/ARCHITECTURE.md`, `TICKETS-BY-STATUS.md`.

---

## Interfaces (the contract every task shares)

```python
# openhound_collector_common.bloodhound

class HMACAuth:
    def __init__(self, token_id: str, token_key: str, now_func: Callable[[], datetime] | None = None): ...
    def headers(self, method: str, path: str, body: bytes | None) -> dict[str, str]: ...

class BearerAuth:
    def __init__(self, token: str): ...
    def headers(self, method: str, path: str, body: bytes | None) -> dict[str, str]: ...

Authenticator = HMACAuth | BearerAuth

class BloodHoundClient:
    def __init__(self, base_url: str, auth: Authenticator, *,
                 max_retries: int = 3, retry_delay: float = 2.0, timeout: float = 60.0,
                 send: Callable | None = None, sleep: Callable[[float], None] | None = None): ...
    def start_upload(self) -> str: ...                     # POST /api/v2/file-upload/start -> job id
    def upload_file(self, job_id: str, file_path: Path) -> None:  # POST /api/v2/file-upload/{id}
    def end_upload(self, job_id: str) -> None:             # POST /api/v2/file-upload/{id}/end
    def upload_schema(self, data: bytes) -> None:          # PUT /api/v2/extensions

@dataclass
class UploadSummary:
    files_uploaded: int = 0
    files_failed: int = 0
    schemas_uploaded: int = 0
    errors: list[str] = field(default_factory=list)
    @property
    def ok(self) -> bool: ...

class BloodHoundUploader:
    def __init__(self, client: BloodHoundClient, logger: logging.Logger | None = None): ...
    def upload_schemas(self, schemas: Sequence[bytes]) -> UploadSummary: ...
    def upload_files(self, files: Sequence[Path]) -> UploadSummary: ...

def parse_bloodhound_shorthand(value: str) -> tuple[str, str, str]: ...   # "<id>:<key>@<url>" -> (id, key, url)
def resolve_credentials(bloodhound: str | None, url: str | None,
                        token_id: str | None, token_key: str | None,
                        env: Mapping[str, str] | None = None
                        ) -> tuple[str | None, str | None, str | None]: ...  # (url, token_id, token_key)
def build_uploader(url: str | None, token_id: str | None, token_key: str | None,
                   logger: logging.Logger | None = None,
                   client_kwargs: dict | None = None) -> BloodHoundUploader | None: ...

def bundle_graph_dir(graph_dir: Path, out_zip: Path) -> Path | None: ...    # zip *.json; None if no files
def disable_possible_edges(schema_bytes: bytes, possible_kinds: Iterable[str]) -> bytes: ...
```

```python
# openhound_sccm.bloodhound_schemas
SCCM_POSSIBLE_EDGE_KINDS: tuple[str, ...]     # SCCM coerce-and-relay kinds
MSSQL_POSSIBLE_EDGE_KINDS: tuple[str, ...]    # Go PossibleEdgeKinds, MSSQL_-prefixed
def load_sccm_schemas(disable_possible: bool) -> list[bytes]: ...   # [SCCM schema, MSSQL schema], mutated if asked

# openhound_sccm.bloodhound_upload
def run_upload(*, uploader: BloodHoundUploader, schemas: list[bytes],
               results_dir: Path | None, work_dir: Path,
               upload_schema: bool, upload_results: bool,
               logger: logging.Logger) -> UploadSummary: ...
```

---

### Task 1: Request signing (`auth.py`)

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/bloodhound/__init__.py`
- Create: `openhound-collector-common/src/openhound_collector_common/bloodhound/auth.py`
- Test: `openhound-collector-common/tests/test_bloodhound_auth.py`

**Interfaces:**
- Produces: `HMACAuth`, `BearerAuth`, `Authenticator` (used by `client.py` in Task 2).

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_bloodhound_auth.py
import base64
import datetime
import hashlib
import hmac

from openhound_collector_common.bloodhound.auth import BearerAuth, HMACAuth


def _fixed_now():
    # Fixed instant so the signature is deterministic.
    return datetime.datetime(2026, 7, 24, 15, 30, 0, tzinfo=datetime.timezone.utc)


def test_hmac_headers_match_bloodhound_chain():
    auth = HMACAuth("id-123", "secret-key", now_func=_fixed_now)
    headers = auth.headers("POST", "/api/v2/file-upload/start", b"{}")

    # Recompute the three-step BH CE HMAC chain independently.
    d = hmac.new(b"secret-key", None, hashlib.sha256)
    d.update(b"POST/api/v2/file-upload/start")
    d = hmac.new(d.digest(), None, hashlib.sha256)
    request_date = _fixed_now().astimezone().isoformat("T")
    d.update(request_date[:13].encode())
    d = hmac.new(d.digest(), None, hashlib.sha256)
    d.update(b"{}")
    expected_sig = base64.b64encode(d.digest()).decode()

    assert headers["Authorization"] == "bhesignature id-123"
    assert headers["Signature"] == expected_sig
    assert headers["RequestDate"] == request_date


def test_hmac_none_body_signs_empty():
    auth = HMACAuth("id", "key", now_func=_fixed_now)
    with_none = auth.headers("GET", "/x", None)
    with_empty = auth.headers("GET", "/x", b"")
    assert with_none["Signature"] == with_empty["Signature"]


def test_bearer_headers():
    headers = BearerAuth("jwt-token").headers("GET", "/api/v2/x", None)
    assert headers["Authorization"] == "Bearer jwt-token"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_auth.py -v`
Expected: FAIL — `ModuleNotFoundError: openhound_collector_common.bloodhound.auth`

- [ ] **Step 3: Write minimal implementation**

```python
# openhound-collector-common/src/openhound_collector_common/bloodhound/__init__.py
"""Reusable BloodHound CE upload client for OpenHound collectors.

Ports the Go MSSQLHound upload flow (schema via PUT /api/v2/extensions, results
via the /api/v2/file-upload job API) as framework-agnostic, pure-Python building
blocks. No `openhound` or `dlt` imports — collectors wire these into their CLI.
"""
```

```python
# openhound-collector-common/src/openhound_collector_common/bloodhound/auth.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_auth.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Green checkpoint** — tests pass; stop for owner review (no commit).

---

### Task 2: Retrying HTTP client (`client.py`)

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/bloodhound/client.py`
- Test: `openhound-collector-common/tests/test_bloodhound_client.py`

**Interfaces:**
- Consumes: `Authenticator` (Task 1).
- Produces: `BloodHoundClient`, `BloodHoundHTTPError` (used by `uploader.py`, Task 3).

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_bloodhound_client.py
from pathlib import Path

import pytest

from openhound_collector_common.bloodhound.auth import HMACAuth
from openhound_collector_common.bloodhound.client import (
    BloodHoundClient,
    BloodHoundHTTPError,
)


class FakeResponse:
    def __init__(self, status_code, *, json_body=None, text=""):
        self.status_code = status_code
        self._json = json_body
        self.text = text

    def json(self):
        return self._json


def make_client(responses):
    """Client whose transport returns queued FakeResponses; records calls."""
    calls = []
    queue = list(responses)

    def send(method, url, headers, data, timeout):
        calls.append({"method": method, "url": url, "headers": headers, "data": data})
        return queue.pop(0)

    client = BloodHoundClient(
        "https://bh.example",
        HMACAuth("id", "key"),
        send=send,
        sleep=lambda _s: None,  # no real backoff in tests
    )
    return client, calls


def test_start_upload_returns_job_id():
    client, calls = make_client([FakeResponse(201, json_body={"data": {"id": 42}})])
    assert client.start_upload() == "42"
    assert calls[0]["method"] == "POST"
    assert calls[0]["url"] == "https://bh.example/api/v2/file-upload/start"


def test_retry_on_500_then_success():
    client, calls = make_client([FakeResponse(500, text="boom"),
                                 FakeResponse(201, json_body={"data": {"id": 7}})])
    assert client.start_upload() == "7"
    assert len(calls) == 2  # retried once


def test_gives_up_after_max_retries():
    client, _ = make_client([FakeResponse(503)] * 4)  # 1 try + 3 retries
    with pytest.raises(BloodHoundHTTPError):
        client.start_upload()


def test_upload_file_sets_zip_content_type(tmp_path):
    z = tmp_path / "graph.zip"
    z.write_bytes(b"PK\x03\x04zip")
    client, calls = make_client([FakeResponse(202)])
    client.upload_file("9", z)
    assert calls[0]["url"].endswith("/api/v2/file-upload/9")
    assert calls[0]["headers"]["Content-Type"] == "application/zip"
    assert calls[0]["data"] == b"PK\x03\x04zip"


def test_upload_schema_uses_put_extensions():
    client, calls = make_client([FakeResponse(200)])
    client.upload_schema(b'{"schema": {}}')
    assert calls[0]["method"] == "PUT"
    assert calls[0]["url"].endswith("/api/v2/extensions")
    assert calls[0]["headers"]["Content-Type"] == "application/json"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_client.py -v`
Expected: FAIL — `ModuleNotFoundError: ...bloodhound.client`

- [ ] **Step 3: Write minimal implementation**

```python
# openhound-collector-common/src/openhound_collector_common/bloodhound/client.py
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
        job_id = (resp.json() or {}).get("data", {}).get("id")
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_client.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Green checkpoint** — stop for review.

---

### Task 3: Uploader orchestration + credential resolution (`uploader.py`)

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/bloodhound/uploader.py`
- Test: `openhound-collector-common/tests/test_bloodhound_uploader.py`

**Interfaces:**
- Consumes: `BloodHoundClient`, `BloodHoundHTTPError` (Task 2); `HMACAuth`, `BearerAuth` (Task 1).
- Produces: `BloodHoundUploader`, `UploadSummary`, `parse_bloodhound_shorthand`, `resolve_credentials`, `build_uploader` (used by SCCM Tasks 8–10).

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_bloodhound_uploader.py
from pathlib import Path

import pytest

from openhound_collector_common.bloodhound.client import BloodHoundHTTPError
from openhound_collector_common.bloodhound.uploader import (
    BloodHoundUploader,
    UploadSummary,
    build_uploader,
    parse_bloodhound_shorthand,
    resolve_credentials,
)


class FakeClient:
    def __init__(self, fail_file=False):
        self.schemas = []
        self.files = []
        self.started = 0
        self.ended = 0
        self._fail_file = fail_file

    def upload_schema(self, data):
        self.schemas.append(data)

    def start_upload(self):
        self.started += 1
        return "job-1"

    def upload_file(self, job_id, path):
        if self._fail_file:
            raise BloodHoundHTTPError("upload file", 400, "bad")
        self.files.append((job_id, Path(path).name))

    def end_upload(self, job_id):
        self.ended += 1


def test_parse_shorthand():
    assert parse_bloodhound_shorthand("id:key@https://bh.example") == (
        "id", "key", "https://bh.example")


def test_parse_shorthand_rejects_missing_at():
    with pytest.raises(ValueError):
        parse_bloodhound_shorthand("idkeynourl")


def test_resolve_credentials_shorthand_wins_over_env():
    url, tid, tkey = resolve_credentials(
        "id:key@https://a", None, None, None,
        env={"BLOODHOUND_URL": "https://b", "BLOODHOUND_TOKEN_ID": "x"})
    assert (url, tid, tkey) == ("https://a", "id", "key")


def test_resolve_credentials_env_fallback():
    url, tid, tkey = resolve_credentials(
        None, None, None, None,
        env={"BLOODHOUND_URL": "https://b", "BLOODHOUND_TOKEN_ID": "x",
             "BLOODHOUND_TOKEN_KEY": "y"})
    assert (url, tid, tkey) == ("https://b", "x", "y")


def test_build_uploader_none_without_url():
    assert build_uploader(None, "id", "key") is None


def test_build_uploader_hmac_and_bearer():
    assert build_uploader("https://bh", "id", "key") is not None   # HMAC
    assert build_uploader("https://bh", "jwt", None) is not None   # Bearer
    assert build_uploader("https://bh", None, None) is None        # no creds


def test_upload_schemas_counts():
    c = FakeClient()
    summary = BloodHoundUploader(c).upload_schemas([b"{}", b"{}"])
    assert summary.schemas_uploaded == 2
    assert summary.ok


def test_upload_files_job_lifecycle():
    c = FakeClient()
    summary = BloodHoundUploader(c).upload_files([Path("a.zip")])
    assert c.started == 1 and c.ended == 1
    assert summary.files_uploaded == 1 and summary.ok


def test_upload_files_records_failure_but_still_ends_job():
    c = FakeClient(fail_file=True)
    summary = BloodHoundUploader(c).upload_files([Path("a.zip")])
    assert summary.files_failed == 1 and not summary.ok
    assert c.ended == 1  # job closed even on failure
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_uploader.py -v`
Expected: FAIL — `ModuleNotFoundError: ...bloodhound.uploader`

- [ ] **Step 3: Write minimal implementation**

```python
# openhound-collector-common/src/openhound_collector_common/bloodhound/uploader.py
"""High-level BloodHound CE upload orchestration + credential plumbing.

`BloodHoundUploader` turns the low-level client into two operations: push a list
of schema blobs, and upload a list of files under one job. `resolve_credentials`
merges the Go-style flags (`-B` shorthand, discrete flags, env vars) into one
(url, token_id, token_key) triple, and `build_uploader` picks HMAC vs Bearer.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .auth import BearerAuth, HMACAuth
from .client import BloodHoundClient, BloodHoundHTTPError

logger = logging.getLogger(__name__)


@dataclass
class UploadSummary:
    """Aggregate outcome of an upload run."""

    files_uploaded: int = 0
    files_failed: int = 0
    schemas_uploaded: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.files_failed == 0 and not self.errors

    def merge(self, other: "UploadSummary") -> "UploadSummary":
        self.files_uploaded += other.files_uploaded
        self.files_failed += other.files_failed
        self.schemas_uploaded += other.schemas_uploaded
        self.errors.extend(other.errors)
        return self


class BloodHoundUploader:
    def __init__(self, client: BloodHoundClient, logger_: Optional[logging.Logger] = None) -> None:
        self.client = client
        self.log = logger_ or logger

    def upload_schemas(self, schemas: Sequence[bytes]) -> UploadSummary:
        summary = UploadSummary()
        for i, data in enumerate(schemas):
            try:
                self.client.upload_schema(data)
                summary.schemas_uploaded += 1
                self.log.info("Uploaded schema %d/%d to BloodHound", i + 1, len(schemas))
            except BloodHoundHTTPError as exc:
                summary.errors.append(f"schema {i + 1}: {exc}")
                self.log.warning("Schema upload %d/%d failed: %s", i + 1, len(schemas), exc)
        return summary

    def upload_files(self, files: Sequence[Path]) -> UploadSummary:
        summary = UploadSummary()
        if not files:
            self.log.debug("No result files to upload; skipping job")
            return summary
        try:
            job_id = self.client.start_upload()
        except BloodHoundHTTPError as exc:
            summary.files_failed = len(files)
            summary.errors.append(f"start upload: {exc}")
            self.log.warning("Failed to start upload job: %s", exc)
            return summary
        self.log.info("Uploading %d file(s) to BloodHound (job %s)", len(files), job_id)
        for f in files:
            try:
                self.client.upload_file(job_id, f)
                summary.files_uploaded += 1
                self.log.info("Uploaded %s", Path(f).name)
            except BloodHoundHTTPError as exc:
                summary.files_failed += 1
                summary.errors.append(f"{Path(f).name}: {exc}")
                self.log.warning("Failed to upload %s: %s", Path(f).name, exc)
        try:
            self.client.end_upload(job_id)
        except BloodHoundHTTPError as exc:
            # The files may already be queued server-side; log but don't fail hard.
            summary.errors.append(f"end upload: {exc}")
            self.log.warning("Failed to end upload job %s: %s", job_id, exc)
        return summary


def parse_bloodhound_shorthand(value: str) -> tuple[str, str, str]:
    """Parse `-B` `<token-id>:<token_key>@<url>` into (token_id, token_key, url).

    Splits on the LAST `@` so a URL containing `@` (unusual, but a userinfo URL
    could) does not break the credentials split; the key is everything between
    the first `:` and that `@`.
    """
    at = value.rfind("@")
    if at < 0:
        raise ValueError("-B format must be <token-id>:<token_key>@<bloodhound_url>")
    creds, url = value[:at], value[at + 1:]
    colon = creds.find(":")
    if colon < 0:
        raise ValueError("-B format must be <token-id>:<token_key>@<bloodhound_url>")
    return creds[:colon], creds[colon + 1:], url


def resolve_credentials(
    bloodhound: Optional[str],
    url: Optional[str],
    token_id: Optional[str],
    token_key: Optional[str],
    env: Optional[Mapping[str, str]] = None,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Merge -B shorthand, discrete flags, and env vars into (url, id, key).

    Precedence: -B shorthand > discrete flag > env var. Returns Nones when a
    value is absent so the caller can decide whether upload was requested at all.
    """
    import os

    env = env if env is not None else os.environ
    if bloodhound:
        b_id, b_key, b_url = parse_bloodhound_shorthand(bloodhound)
        return b_url, b_id, b_key
    return (
        url or env.get("BLOODHOUND_URL") or None,
        token_id or env.get("BLOODHOUND_TOKEN_ID") or None,
        token_key or env.get("BLOODHOUND_TOKEN_KEY") or None,
    )


def build_uploader(
    url: Optional[str],
    token_id: Optional[str],
    token_key: Optional[str],
    logger_: Optional[logging.Logger] = None,
    client_kwargs: Optional[dict] = None,
) -> Optional[BloodHoundUploader]:
    """Build an uploader, or None if upload was not (fully) configured.

    Requires a URL. HMAC when both token id + key are present; Bearer when only
    an id/token is present; None otherwise.
    """
    log = logger_ or logger
    if not url:
        return None
    if token_id and token_key:
        auth = HMACAuth(token_id, token_key)
    elif token_id:
        # Only an id given: treat it as a JWT Bearer token (mirrors the Go tool).
        auth = BearerAuth(token_id)
    else:
        log.warning("BloodHound URL given without a token id/key; cannot upload")
        return None
    client = BloodHoundClient(url, auth, **(client_kwargs or {}))
    return BloodHoundUploader(client, log)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_uploader.py -v`
Expected: PASS (9 passed)

- [ ] **Step 5: Green checkpoint** — stop for review.

---

### Task 4: Zip bundler (`zip_bundle.py`)

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/bloodhound/zip_bundle.py`
- Test: `openhound-collector-common/tests/test_bloodhound_zip.py`

**Interfaces:**
- Produces: `bundle_graph_dir(graph_dir, out_zip) -> Path | None` (used by SCCM Task 8).

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_bloodhound_zip.py
import zipfile
from pathlib import Path

from openhound_collector_common.bloodhound.zip_bundle import bundle_graph_dir


def test_bundles_only_json_files(tmp_path):
    gdir = tmp_path / "graph"
    gdir.mkdir()
    (gdir / "sccm_nodes-1.json").write_text('{"graph": {}}')
    (gdir / "sccm_edges-1.json").write_text('{"graph": {}}')
    (gdir / "notes.txt").write_text("ignore me")

    out = bundle_graph_dir(gdir, tmp_path / "out.zip")
    assert out is not None and out.exists()
    with zipfile.ZipFile(out) as zf:
        names = sorted(zf.namelist())
    assert names == ["sccm_edges-1.json", "sccm_nodes-1.json"]


def test_returns_none_when_no_json(tmp_path):
    gdir = tmp_path / "graph"
    gdir.mkdir()
    (gdir / "notes.txt").write_text("x")
    assert bundle_graph_dir(gdir, tmp_path / "out.zip") is None


def test_returns_none_when_dir_missing(tmp_path):
    assert bundle_graph_dir(tmp_path / "nope", tmp_path / "out.zip") is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_zip.py -v`
Expected: FAIL — `ModuleNotFoundError: ...bloodhound.zip_bundle`

- [ ] **Step 3: Write minimal implementation**

```python
# openhound-collector-common/src/openhound_collector_common/bloodhound/zip_bundle.py
"""Bundle a directory of OpenGraph JSON files into a single zip for upload.

BloodHound CE's file-upload API accepts a zip of OpenGraph JSON files. We zip
every top-level `*.json` in the convert output dir (flat, basenames only). No
`seed_data.json` is added — the schema PUT already registers every kind.
"""
from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def bundle_graph_dir(graph_dir: Path, out_zip: Path) -> Optional[Path]:
    """Zip the `*.json` files in *graph_dir* into *out_zip*.

    Returns the zip path, or None if the directory is missing or has no JSON
    files (nothing to upload).
    """
    graph_dir = Path(graph_dir)
    if not graph_dir.is_dir():
        logger.warning("Graph directory does not exist, nothing to bundle: %s", graph_dir)
        return None

    json_files = sorted(graph_dir.glob("*.json"))
    if not json_files:
        logger.warning("No OpenGraph .json files found in %s; nothing to upload", graph_dir)
        return None

    out_zip = Path(out_zip)
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in json_files:
            zf.write(f, arcname=f.name)
    logger.info("Bundled %d OpenGraph file(s) into %s", len(json_files), out_zip)
    return out_zip
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_zip.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Green checkpoint** — stop for review.

---

### Task 5: Schema possible-edge mutation (`schema.py`)

**Files:**
- Create: `openhound-collector-common/src/openhound_collector_common/bloodhound/schema.py`
- Test: `openhound-collector-common/tests/test_bloodhound_schema.py`

**Interfaces:**
- Produces: `disable_possible_edges(schema_bytes, possible_kinds) -> bytes` (used by SCCM Task 7).

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_bloodhound_schema.py
import json

from openhound_collector_common.bloodhound.schema import disable_possible_edges


def _schema():
    return json.dumps({
        "schema": {"name": "SCCM"},
        "relationship_kinds": [
            {"name": "SCCM_CoerceAndRelayToSMB", "is_traversable": True},
            {"name": "SCCM_Contains", "is_traversable": True},
        ],
    }).encode()


def test_flips_only_named_kinds():
    out = json.loads(disable_possible_edges(_schema(), ["SCCM_CoerceAndRelayToSMB"]))
    by_name = {r["name"]: r["is_traversable"] for r in out["relationship_kinds"]}
    assert by_name["SCCM_CoerceAndRelayToSMB"] is False
    assert by_name["SCCM_Contains"] is True


def test_no_kinds_is_identity_shape():
    out = json.loads(disable_possible_edges(_schema(), []))
    assert all(r["is_traversable"] for r in out["relationship_kinds"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_schema.py -v`
Expected: FAIL — `ModuleNotFoundError: ...bloodhound.schema`

- [ ] **Step 3: Write minimal implementation**

```python
# openhound-collector-common/src/openhound_collector_common/bloodhound/schema.py
"""Mutate a BloodHound extensions schema before upload.

Port of MSSQLHound's `SchemaJSONWithDisabledPossibleEdges`: given a schema JSON
blob and a set of "possible" relationship kind names, set their `is_traversable`
to false so `--disable-possible-edges` and the uploaded schema agree.
"""
from __future__ import annotations

import json
import logging
from typing import Iterable

logger = logging.getLogger(__name__)


def disable_possible_edges(schema_bytes: bytes, possible_kinds: Iterable[str]) -> bytes:
    """Return *schema_bytes* with the named relationship kinds non-traversable."""
    schema = json.loads(schema_bytes)
    disabled = set(possible_kinds)
    flipped = 0
    for rel in schema.get("relationship_kinds", []):
        if rel.get("name") in disabled:
            rel["is_traversable"] = False
            flipped += 1
    logger.debug("disable_possible_edges: set %d relationship kind(s) non-traversable", flipped)
    return json.dumps(schema, indent=2).encode()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_schema.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Green checkpoint** — stop for review.

---

### Task 6: Package exports + `requests` dependency

**Files:**
- Modify: `openhound-collector-common/src/openhound_collector_common/bloodhound/__init__.py`
- Modify: `openhound-collector-common/pyproject.toml:15-34` (dependencies list)
- Test: `openhound-collector-common/tests/test_bloodhound_exports.py`

**Interfaces:**
- Produces: the public `openhound_collector_common.bloodhound` API used by SCCM.

- [ ] **Step 1: Write the failing test**

```python
# openhound-collector-common/tests/test_bloodhound_exports.py
def test_public_api_importable():
    from openhound_collector_common.bloodhound import (
        BloodHoundClient,
        BloodHoundHTTPError,
        BloodHoundUploader,
        UploadSummary,
        bundle_graph_dir,
        build_uploader,
        disable_possible_edges,
        resolve_credentials,
    )

    assert build_uploader(None, None, None) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_exports.py -v`
Expected: FAIL — `ImportError` (names not exported yet)

- [ ] **Step 3: Write the implementation**

Append to `openhound-collector-common/src/openhound_collector_common/bloodhound/__init__.py`:

```python
from .client import BloodHoundClient, BloodHoundHTTPError
from .schema import disable_possible_edges
from .uploader import (
    BloodHoundUploader,
    UploadSummary,
    build_uploader,
    parse_bloodhound_shorthand,
    resolve_credentials,
)
from .zip_bundle import bundle_graph_dir

__all__ = [
    "BloodHoundClient",
    "BloodHoundHTTPError",
    "BloodHoundUploader",
    "UploadSummary",
    "build_uploader",
    "bundle_graph_dir",
    "disable_possible_edges",
    "parse_bloodhound_shorthand",
    "resolve_credentials",
]
```

Add `requests` to `openhound-collector-common/pyproject.toml` dependencies (after the `cryptography` line, before the platform-gated `pywin32`):

```toml
    # HTTP client for the BloodHound CE upload + extensions APIs (bloodhound/client.py).
    "requests>=2.31.0",
```

- [ ] **Step 4: Sync the environment, then run the test**

Run: `cd openhound-collector-common && uv sync && uv run pytest tests/test_bloodhound_exports.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Run the whole bloodhound suite (shared-lib re-validation)**

Run: `cd openhound-collector-common && uv run pytest tests/test_bloodhound_*.py -v`
Expected: PASS (all bloodhound tests green)

- [ ] **Step 6: Green checkpoint** — stop for review. The shared lib now provides a complete, tested uploader. SCCM wiring follows.

---

### Task 7: SCCM schema loading (`bloodhound_schemas.py`)

**Files:**
- Create: `sccm/sccm/src/openhound_sccm/bloodhound_schemas.py`
- Test: `sccm/sccm/tests/bloodhound_schemas_test.py`

**Interfaces:**
- Consumes: `disable_possible_edges` (Task 5).
- Produces: `load_sccm_schemas(disable_possible: bool) -> list[bytes]`, `SCCM_POSSIBLE_EDGE_KINDS`, `MSSQL_POSSIBLE_EDGE_KINDS` (used by Task 8).

**Notes:** The two schema files live at the SCCM package root — `sccm/sccm/schema.json` and `sccm/sccm/schema_MSSQL.json`. From `src/openhound_sccm/bloodhound_schemas.py`, that root is `Path(__file__).resolve().parents[2]`. `SCCM_POSSIBLE_EDGE_KINDS` are the two Stage-6 coerce-and-relay kinds that carry `is_traversable: true` in `schema.json`. `MSSQL_POSSIBLE_EDGE_KINDS` mirrors the Go `PossibleEdgeKinds` list ([writer.go:22-29](../../../../MSSQLHound/internal/bloodhound/writer.go#L22-L29)).

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/bloodhound_schemas_test.py
import json

from openhound_sccm.bloodhound_schemas import (
    MSSQL_POSSIBLE_EDGE_KINDS,
    SCCM_POSSIBLE_EDGE_KINDS,
    load_sccm_schemas,
)


def test_loads_both_schemas_by_namespace():
    schemas = load_sccm_schemas(disable_possible=False)
    namespaces = {json.loads(s)["schema"]["namespace"] for s in schemas}
    assert namespaces == {"SCCM", "MSSQL"}


def test_disable_possible_flips_sccm_and_mssql_kinds():
    schemas = load_sccm_schemas(disable_possible=True)
    rels = {}
    for s in schemas:
        for r in json.loads(s)["relationship_kinds"]:
            rels[r["name"]] = r["is_traversable"]
    for kind in SCCM_POSSIBLE_EDGE_KINDS + MSSQL_POSSIBLE_EDGE_KINDS:
        # Only assert kinds actually present in the shipped schemas.
        if kind in rels:
            assert rels[kind] is False, f"{kind} should be non-traversable"


def test_default_leaves_possible_edges_traversable():
    schemas = load_sccm_schemas(disable_possible=False)
    rels = {}
    for s in schemas:
        for r in json.loads(s)["relationship_kinds"]:
            rels[r["name"]] = r["is_traversable"]
    assert rels.get("SCCM_CoerceAndRelayToSMB") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sccm/sccm && uv run pytest tests/bloodhound_schemas_test.py -v`
Expected: FAIL — `ModuleNotFoundError: openhound_sccm.bloodhound_schemas`

- [ ] **Step 3: Write minimal implementation**

```python
# sccm/sccm/src/openhound_sccm/bloodhound_schemas.py
"""Load the SCCM collector's BloodHound extensions schemas for upload.

The SCCM collector emits both SCCM_* kinds (schema.json) and MSSQL_* kinds
(schema_MSSQL.json) — see kinds/edges.py — so a direct upload registers BOTH so
every emitted edge/node renders. `--disable-possible-edges` flips the uncertain
("possible") relationship kinds to non-traversable in each schema before upload,
mirroring MSSQLHound's SchemaJSONWithDisabledPossibleEdges.
"""
from __future__ import annotations

import logging
from pathlib import Path

from openhound_collector_common.bloodhound import disable_possible_edges

logger = logging.getLogger(__name__)

# Package root holding the two hand-maintained schema files.
_SCHEMA_ROOT = Path(__file__).resolve().parents[2]
_SCCM_SCHEMA = _SCHEMA_ROOT / "schema.json"
_MSSQL_SCHEMA = _SCHEMA_ROOT / "schema_MSSQL.json"

# SCCM's Stage-6 coerce-and-relay edges are the collector's "possible" edges.
SCCM_POSSIBLE_EDGE_KINDS: tuple[str, ...] = (
    "SCCM_CoerceAndRelayToAdminService",
    "SCCM_CoerceAndRelayToSMB",
)

# MSSQL "possible" edges — verbatim from Go writer.go PossibleEdgeKinds.
MSSQL_POSSIBLE_EDGE_KINDS: tuple[str, ...] = (
    "MSSQL_LinkedTo",
    "MSSQL_IsTrustedBy",
    "MSSQL_ServiceAccountFor",
    "MSSQL_HasDBScopedCred",
    "MSSQL_HasMappedCred",
    "MSSQL_HasProxyCred",
)


def load_sccm_schemas(disable_possible: bool) -> list[bytes]:
    """Return [SCCM schema, MSSQL schema] as JSON bytes, mutated if requested."""
    schemas: list[bytes] = []
    for path, possible in ((_SCCM_SCHEMA, SCCM_POSSIBLE_EDGE_KINDS),
                           (_MSSQL_SCHEMA, MSSQL_POSSIBLE_EDGE_KINDS)):
        if not path.exists():
            # A missing schema file is a packaging error — surface it loudly.
            logger.error("BloodHound schema file missing: %s", path)
            raise FileNotFoundError(path)
        data = path.read_bytes()
        if disable_possible:
            data = disable_possible_edges(data, possible)
            logger.debug("Loaded schema %s (possible edges disabled)", path.name)
        else:
            logger.debug("Loaded schema %s", path.name)
        schemas.append(data)
    return schemas
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sccm/sccm && uv run pytest tests/bloodhound_schemas_test.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Green checkpoint** — stop for review.

---

### Task 8: SCCM upload orchestration (`bloodhound_upload.py`)

**Files:**
- Create: `sccm/sccm/src/openhound_sccm/bloodhound_upload.py`
- Test: `sccm/sccm/tests/bloodhound_upload_test.py`

**Interfaces:**
- Consumes: `BloodHoundUploader`, `UploadSummary` (Task 3), `bundle_graph_dir` (Task 4).
- Produces: `run_upload(*, uploader, schemas, results_dir, work_dir, upload_schema, upload_results, logger) -> UploadSummary` (used by both CLI commands, Tasks 9–10).

**Notes:** This is the single dispatch both commands call, so schema/results logic lives in one place. It zips `results_dir` into `work_dir/sccm-bloodhound-upload.zip` only when results are wanted and a dir is given.

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/bloodhound_upload_test.py
import logging
from pathlib import Path

from openhound_collector_common.bloodhound import UploadSummary
from openhound_sccm.bloodhound_upload import run_upload


class FakeUploader:
    def __init__(self):
        self.schema_calls = []
        self.file_calls = []

    def upload_schemas(self, schemas):
        self.schema_calls.append(list(schemas))
        return UploadSummary(schemas_uploaded=len(schemas))

    def upload_files(self, files):
        self.file_calls.append([Path(f).name for f in files])
        return UploadSummary(files_uploaded=len(files))


def _graph(tmp_path):
    g = tmp_path / "graph"
    g.mkdir()
    (g / "sccm_nodes-1.json").write_text('{"graph": {}}')
    return g


def test_uploads_schema_and_results(tmp_path):
    up = FakeUploader()
    summary = run_upload(
        uploader=up, schemas=[b"{}", b"{}"], results_dir=_graph(tmp_path),
        work_dir=tmp_path, upload_schema=True, upload_results=True,
        logger=logging.getLogger("t"))
    assert up.schema_calls == [[b"{}", b"{}"]]
    assert up.file_calls and up.file_calls[0][0].endswith(".zip")
    assert summary.schemas_uploaded == 2 and summary.files_uploaded == 1


def test_schema_only_skips_results(tmp_path):
    up = FakeUploader()
    run_upload(uploader=up, schemas=[b"{}"], results_dir=_graph(tmp_path),
               work_dir=tmp_path, upload_schema=True, upload_results=False,
               logger=logging.getLogger("t"))
    assert up.schema_calls and not up.file_calls


def test_results_only_skips_schema(tmp_path):
    up = FakeUploader()
    run_upload(uploader=up, schemas=[b"{}"], results_dir=_graph(tmp_path),
               work_dir=tmp_path, upload_schema=False, upload_results=True,
               logger=logging.getLogger("t"))
    assert not up.schema_calls and up.file_calls


def test_results_requested_but_no_dir_is_noop_for_files(tmp_path):
    up = FakeUploader()
    summary = run_upload(uploader=up, schemas=[b"{}"], results_dir=None,
                         work_dir=tmp_path, upload_schema=True, upload_results=True,
                         logger=logging.getLogger("t"))
    assert up.schema_calls and not up.file_calls
    assert summary.schemas_uploaded == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sccm/sccm && uv run pytest tests/bloodhound_upload_test.py -v`
Expected: FAIL — `ModuleNotFoundError: openhound_sccm.bloodhound_upload`

- [ ] **Step 3: Write minimal implementation**

```python
# sccm/sccm/src/openhound_sccm/bloodhound_upload.py
"""Dispatch a BloodHound CE upload for the SCCM collector.

One entry point (`run_upload`) shared by `collect --run-all` and `convert`, so
the schema/results decision logic lives in exactly one place. Schemas are pushed
first (they register the kinds); results are the convert output dir zipped into
one archive and uploaded under a single job.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from openhound_collector_common.bloodhound import (
    BloodHoundUploader,
    UploadSummary,
    bundle_graph_dir,
)

_ZIP_NAME = "sccm-bloodhound-upload.zip"


def run_upload(
    *,
    uploader: BloodHoundUploader,
    schemas: list[bytes],
    results_dir: Optional[Path],
    work_dir: Path,
    upload_schema: bool,
    upload_results: bool,
    logger: logging.Logger,
) -> UploadSummary:
    """Push schema and/or results to BloodHound; return a combined summary."""
    summary = UploadSummary()

    if upload_schema:
        logger.info("Uploading %d schema(s) to BloodHound...", len(schemas))
        summary.merge(uploader.upload_schemas(schemas))
    else:
        logger.debug("Schema upload skipped (--upload-results-only)")

    if upload_results:
        if results_dir is None:
            # Nothing converted / no dir to upload — schema-only effectively.
            logger.warning(
                "Results upload requested but no graph directory is available; "
                "run with --run-all or pass --upload-dir. Skipping results.")
        else:
            zip_path = bundle_graph_dir(results_dir, Path(work_dir) / _ZIP_NAME)
            if zip_path is None:
                logger.warning("No OpenGraph files to upload in %s", results_dir)
            else:
                logger.info("Uploading results zip to BloodHound...")
                summary.merge(uploader.upload_files([zip_path]))
    else:
        logger.debug("Results upload skipped (--upload-schema-only)")

    if summary.ok:
        logger.info("BloodHound upload complete: %d schema(s), %d file(s)",
                    summary.schemas_uploaded, summary.files_uploaded)
    else:
        logger.warning("BloodHound upload finished with problems: %s", "; ".join(summary.errors))
    return summary
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd sccm/sccm && uv run pytest tests/bloodhound_upload_test.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Green checkpoint** — stop for review.

---

### Task 9: Wire upload flags into `collect sccm`

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py` — `collect_sccm` signature (add BloodHound Upload panel, ~after line 1075) and body (early `--skip-collection` path near line 1077; post-`--run-all` upload near line 1248).
- Test: `sccm/sccm/tests/bloodhound_cli_test.py`

**Interfaces:**
- Consumes: `resolve_credentials`, `build_uploader` (Task 3); `load_sccm_schemas` (Task 7); `run_upload` (Task 8).
- Produces: an internal helper `_dispatch_bloodhound_upload(...)` reused by Task 10.

**Notes:** Add a small module-level helper so both commands share the "resolve creds → build uploader → validate flags → run_upload" flow. `--skip-collection` must short-circuit *before* the collection body. Without `--run-all` and without `--upload-dir`, there is no graph, so results are skipped (schema still uploads if requested).

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/bloodhound_cli_test.py
import logging
from pathlib import Path

import pytest

import openhound_sccm.main as main


class RecordingUploader:
    last = None

    def __init__(self):
        RecordingUploader.last = self
        self.schema_calls = []
        self.file_calls = []

    def upload_schemas(self, schemas):
        from openhound_collector_common.bloodhound import UploadSummary
        self.schema_calls.append(list(schemas))
        return UploadSummary(schemas_uploaded=len(schemas))

    def upload_files(self, files):
        from openhound_collector_common.bloodhound import UploadSummary
        self.file_calls.append([Path(f).name for f in files])
        return UploadSummary(files_uploaded=len(files))


def test_upload_mutual_exclusion_raises():
    with pytest.raises(main.typer.BadParameter):
        main._resolve_upload_mode(upload_schema_only=True, upload_results_only=True)


def test_resolve_upload_mode_defaults_to_both():
    assert main._resolve_upload_mode(False, False) == (True, True)
    assert main._resolve_upload_mode(True, False) == (True, False)
    assert main._resolve_upload_mode(False, True) == (False, True)


def test_dispatch_uploads_schema_only_for_skip_collection(monkeypatch, tmp_path):
    # build_uploader returns our recording fake regardless of creds.
    monkeypatch.setattr(main, "build_uploader",
                        lambda *a, **k: RecordingUploader())
    main._dispatch_bloodhound_upload(
        url="https://bh", token_id="i", token_key="k",
        disable_possible=False, results_dir=None, work_dir=tmp_path,
        upload_schema=True, upload_results=True, logger=logging.getLogger("t"))
    up = RecordingUploader.last
    assert up.schema_calls and not up.file_calls  # no results_dir -> schema only
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sccm/sccm && uv run pytest tests/bloodhound_cli_test.py -v`
Expected: FAIL — `AttributeError: module 'openhound_sccm.main' has no attribute '_resolve_upload_mode'`

- [ ] **Step 3: Add the shared helpers to `main.py`**

Add near the other collect helpers (e.g. after `_apply_env_overrides`), importing at module top:

```python
# main.py — new imports (top of file, with the other openhound_sccm imports)
from openhound_collector_common.bloodhound import build_uploader, resolve_credentials
from .bloodhound_schemas import load_sccm_schemas
from .bloodhound_upload import run_upload
```

```python
# main.py — new module-level helpers

def _resolve_upload_mode(upload_schema_only: bool, upload_results_only: bool) -> tuple[bool, bool]:
    """Map the two upload-only switches to (upload_schema, upload_results).

    Default is both. The two switches are mutually exclusive.
    """
    if upload_schema_only and upload_results_only:
        raise typer.BadParameter(
            "--upload-schema-only and --upload-results-only are mutually exclusive.",
            param_hint="--upload-results-only",
        )
    if upload_schema_only:
        return True, False
    if upload_results_only:
        return False, True
    return True, True


def _dispatch_bloodhound_upload(
    *,
    url: Optional[str],
    token_id: Optional[str],
    token_key: Optional[str],
    disable_possible: bool,
    results_dir: "Optional[pathlib.Path]",
    work_dir: pathlib.Path,
    upload_schema: bool,
    upload_results: bool,
    logger: logging.Logger,
) -> None:
    """Build the uploader and push schema/results. No-op if not configured."""
    uploader = build_uploader(url, token_id, token_key, logger_=logger)
    if uploader is None:
        logger.debug("BloodHound upload not configured; skipping")
        return
    schemas = load_sccm_schemas(disable_possible) if upload_schema else []
    run_upload(
        uploader=uploader, schemas=schemas, results_dir=results_dir,
        work_dir=work_dir, upload_schema=upload_schema, upload_results=upload_results,
        logger=logger,
    )
```

- [ ] **Step 4: Run the helper tests to verify they pass**

Run: `cd sccm/sccm && uv run pytest tests/bloodhound_cli_test.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Add the CLI flags + body wiring to `collect_sccm`**

Add a `BloodHound Upload` panel to the `collect_sccm` signature (after the `--debug` option near line 1075):

```python
    # ---- BloodHound Upload ----
    bloodhound: Optional[str] = typer.Option(None, "-B", "--bloodhound", rich_help_panel="BloodHound Upload", help="BloodHound CE credentials shorthand: <token-id>:<token_key>@<url> (uploads both schema and results)."),
    bloodhound_url: Optional[str] = typer.Option(None, "--bloodhound-url", rich_help_panel="BloodHound Upload", help="BloodHound CE instance URL (env: BLOODHOUND_URL)."),
    token_id: Optional[str] = typer.Option(None, "--token-id", rich_help_panel="BloodHound Upload", help="BloodHound API token ID (env: BLOODHOUND_TOKEN_ID)."),
    token_key: Optional[str] = typer.Option(None, "--token-key", rich_help_panel="BloodHound Upload", help="BloodHound API token key (env: BLOODHOUND_TOKEN_KEY)."),
    upload_schema_only: bool = typer.Option(False, "--upload-schema-only", rich_help_panel="BloodHound Upload", help="Only upload schema definitions (skip results)."),
    upload_results_only: bool = typer.Option(False, "--upload-results-only", rich_help_panel="BloodHound Upload", help="Only upload collection results (skip schema)."),
    skip_collection: bool = typer.Option(False, "--skip-collection", rich_help_panel="BloodHound Upload", help="Skip collection; with -B, push the schema only (or upload --upload-dir results)."),
    upload_dir: Optional[pathlib.Path] = typer.Option(None, "--upload-dir", rich_help_panel="BloodHound Upload", help="Upload existing OpenGraph files from this directory instead of collecting/converting."),
```

Insert the early upload-only short-circuit at the very start of the `collect_sccm` body (right after `_apply_log_level(verbose, debug, silent)`, ~line 1077):

```python
    # Resolve BloodHound creds up front so both the skip-collection and the
    # --run-all paths use the same values. `upload_mode` also validates the
    # mutually-exclusive switches early (before any collection work).
    bh_url, bh_token_id, bh_token_key = resolve_credentials(
        bloodhound, bloodhound_url, token_id, token_key)
    upload_schema, upload_results = _resolve_upload_mode(upload_schema_only, upload_results_only)

    # --skip-collection: do no collection. With creds, push schema (and, if
    # --upload-dir is given, those existing results). Mirrors the Go tool.
    if skip_collection:
        logger.info("--skip-collection set: skipping collection.")
        _dispatch_bloodhound_upload(
            url=bh_url, token_id=bh_token_id, token_key=bh_token_key,
            disable_possible=disable_possible, results_dir=upload_dir,
            work_dir=output_path, upload_schema=upload_schema,
            upload_results=upload_results and upload_dir is not None,
            logger=logger,
        )
        return None
```

Extend the post-`--run-all` block (after `_log_all_output_locations(...)`, ~line 1248) to upload, and add an else-branch so `-B` without `--run-all` still pushes schema:

```python
        # Direct BloodHound upload of the graph convert just produced (or an
        # explicit --upload-dir). results_dir is None-safe inside run_upload.
        _dispatch_bloodhound_upload(
            url=bh_url, token_id=bh_token_id, token_key=bh_token_key,
            disable_possible=disable_possible,
            results_dir=upload_dir or _paths.graph_out,
            work_dir=output_path, upload_schema=upload_schema,
            upload_results=upload_results, logger=logger,
        )
```

And in the existing `else:` (line ~1267, `--run-all not set`) add, before the debug log:

```python
        # Even without --run-all there is no graph to upload, but the operator
        # may still want the schema (or an explicit --upload-dir) pushed.
        if bh_url:
            _dispatch_bloodhound_upload(
                url=bh_url, token_id=bh_token_id, token_key=bh_token_key,
                disable_possible=disable_possible, results_dir=upload_dir,
                work_dir=output_path, upload_schema=upload_schema,
                upload_results=upload_results and upload_dir is not None,
                logger=logger,
            )
```

- [ ] **Step 6: Verify the CLI help renders the new panel (no crash)**

Run: `cd sccm/sccm && uv run openhound collect sccm --help`
Expected: a `BloodHound Upload` panel listing `-B/--bloodhound`, `--bloodhound-url`, `--token-id`, `--token-key`, `--upload-schema-only`, `--upload-results-only`, `--skip-collection`, `--upload-dir`.

- [ ] **Step 7: Run the CLI option-panel + upload tests**

Run: `cd sccm/sccm && uv run pytest tests/bloodhound_cli_test.py tests/test_cli_option_panels.py -v`
Expected: PASS

- [ ] **Step 8: Green checkpoint** — stop for review.

---

### Task 10: Hand-register `convert sccm` with upload flags

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/main.py` — replace the `@app.convert(lookup=SCCMLookup)` registration (~line 1684) with a hand-registered command on the framework's `convert` Typer group + a manual `app.converter` assignment.
- Test: `sccm/sccm/tests/bloodhound_cli_test.py` (extend).

**Interfaces:**
- Consumes: `_dispatch_bloodhound_upload`, `_resolve_upload_mode`, `resolve_credentials` (Task 9); the existing convert hook body.
- Produces: `convert sccm` CLI command with the upload flags; `app.converter` still callable by `run_end_to_end`.

**Notes:** The framework's `@app.convert` decorator both sets `app.converter` (the in-process callable `run_end_to_end` uses) and auto-registers a fixed-signature `convert sccm` CLI command. To add flags we take over both: keep the convert *hook* body as `_sccm_convert_hook(ctx)`, define a small `_run_convert(...)` (replicating the framework's ~10-line body) assigned to `app.converter`, and hand-register the CLI wrapper on `_convert_typer`. This is a documented divergence (ARCHITECTURE.md, Task 11). **Do not** keep the `@app.convert` decorator — that would double-register the command name.

- [ ] **Step 1: Write the failing test**

```python
# add to sccm/sccm/tests/bloodhound_cli_test.py
def test_app_converter_is_callable_after_handregister():
    # run_end_to_end depends on app.converter being set to an in-process callable.
    assert callable(main.app.converter)


def test_convert_command_registered_with_upload_flags():
    # The hand-registered command must expose the BloodHound flags.
    names = {c.name for c in main._convert_typer.registered_commands}
    assert "sccm" in names
    sccm_cmd = next(c for c in main._convert_typer.registered_commands if c.name == "sccm")
    params = {p for p in sccm_cmd.callback.__annotations__}
    assert {"bloodhound", "upload_dir", "skip_collection"} <= params
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd sccm/sccm && uv run pytest tests/bloodhound_cli_test.py -k convert -v`
Expected: FAIL — `AttributeError: module 'openhound_sccm.main' has no attribute '_convert_typer'`

- [ ] **Step 3: Rewrite the convert registration in `main.py`**

Add the import at the top (with the collect import at line 16):

```python
from openhound.cli.convert import convert as _convert_typer  # noqa: E402
```

Add these framework imports (used by the manual `_run_convert`):

```python
import duckdb
from openhound.core.app import DEFAULT_LOOKUP_FILE
from openhound.core.convert import Converter, Method
from openhound.core.progress import Progress
```

Replace the current `@app.convert(lookup=SCCMLookup)` decorator + `def convert(ctx)` (~line 1684) with the hook body kept as a plain function and the two registrations:

```python
def _sccm_convert_hook(ctx: ConvertContext):
    """Emit the SCCM graph by reading the preproc DuckDB directly (Convert-Read-DB).

    (Body unchanged from the previous @app.convert function — copy it verbatim.)
    """
    # ... existing convert body: emit_graph_from_duckdb(...) then return noop source ...


def _run_convert(
    input_path: pathlib.Path,
    output_path: pathlib.Path,
    lookup_file: pathlib.Path = DEFAULT_LOOKUP_FILE,
    progress: Progress = Progress.tqdm,
    method: Method = Method.write,
):
    """In-process convert callable — mirrors the framework's run_convert closure.

    Assigned to app.converter so run_end_to_end (the --run-all chain) works, and
    called by the hand-registered CLI command below.
    """
    client = duckdb.connect(str(lookup_file), read_only=True)
    lookup_session = SCCMLookup(client)
    if isinstance(progress, str):
        progress = Progress(progress)
    converter = Converter(
        name=app.name, source_kind=app.source_kind, input_path=input_path,
        output_path=output_path, lookup=lookup_session, progress=progress, method=method,
    )
    source_method, extra_context = _sccm_convert_hook(
        ConvertContext(input_path=input_path, output_path=output_path,
                       lookup=lookup_session, pipeline=converter)
    )
    return converter.run(source_method, graph_resources=app.assets, extra_context=extra_context)


# run_end_to_end (via --run-all) calls app.converter directly; set it manually
# since we bypass the @app.convert decorator to add the upload flag surface.
app.converter = _run_convert


@_convert_typer.command(name="sccm", help="Convert collected SCCM data to OpenGraph; optionally upload to BloodHound CE.")
def convert_sccm(
    input_path: InputPath,
    output_path: OutputPath,
    lookup_file: pathlib.Path = typer.Option(DEFAULT_LOOKUP_FILE, "--lookup-file", help="DuckDB lookup file path."),
    progress: ProgressOption = typer.Option(ProgressOption.off, help="Progress backend."),
    disable_possible_edges: bool = typer.Option(False, "--disable-possible-edges", help="Disable uncertain/possible edges (also flips them non-traversable in the uploaded schema)."),
    # ---- BloodHound Upload (identical surface to collect) ----
    bloodhound: Optional[str] = typer.Option(None, "-B", "--bloodhound", rich_help_panel="BloodHound Upload", help="BloodHound CE credentials shorthand: <token-id>:<token_key>@<url>."),
    bloodhound_url: Optional[str] = typer.Option(None, "--bloodhound-url", rich_help_panel="BloodHound Upload", help="BloodHound CE instance URL (env: BLOODHOUND_URL)."),
    token_id: Optional[str] = typer.Option(None, "--token-id", rich_help_panel="BloodHound Upload", help="BloodHound API token ID (env: BLOODHOUND_TOKEN_ID)."),
    token_key: Optional[str] = typer.Option(None, "--token-key", rich_help_panel="BloodHound Upload", help="BloodHound API token key (env: BLOODHOUND_TOKEN_KEY)."),
    upload_schema_only: bool = typer.Option(False, "--upload-schema-only", rich_help_panel="BloodHound Upload", help="Only upload schema definitions."),
    upload_results_only: bool = typer.Option(False, "--upload-results-only", rich_help_panel="BloodHound Upload", help="Only upload results."),
    upload_dir: Optional[pathlib.Path] = typer.Option(None, "--upload-dir", rich_help_panel="BloodHound Upload", help="Upload existing OpenGraph files from this dir instead of converting."),
) -> None:
    _apply_log_level(verbose=False, debug=False, silent=False)
    bh_url, bh_token_id, bh_token_key = resolve_credentials(bloodhound, bloodhound_url, token_id, token_key)
    upload_schema, upload_results = _resolve_upload_mode(upload_schema_only, upload_results_only)

    if upload_dir is not None:
        # Standalone re-upload: skip convert, push the given graph dir.
        logger.info("--upload-dir set: uploading existing graph, skipping convert.")
        results_dir = upload_dir
    else:
        # Normal path: run the convert, then upload what it produced.
        _run_convert(input_path=input_path, output_path=output_path,
                     lookup_file=lookup_file, progress=_resolve_progress(progress),
                     method=Method.write)
        results_dir = output_path

    _dispatch_bloodhound_upload(
        url=bh_url, token_id=bh_token_id, token_key=bh_token_key,
        disable_possible=disable_possible_edges, results_dir=results_dir,
        work_dir=output_path, upload_schema=upload_schema, upload_results=upload_results,
        logger=logger,
    )
```

> **Implementer note:** copy the *existing* convert body into `_sccm_convert_hook` verbatim (it currently lives in the `@app.convert`-decorated `convert(ctx)` function around line 1684). Confirm `SCCMLookup`, `InputPath`, `OutputPath`, `ProgressOption`, and `_resolve_progress` are already imported/defined in `main.py` (they are used by the existing collect/convert code); if `InputPath` is not imported, add `from openhound.core.app import InputPath`.

- [ ] **Step 4: Run the convert-registration tests**

Run: `cd sccm/sccm && uv run pytest tests/bloodhound_cli_test.py -v`
Expected: PASS (all, including the two new convert tests)

- [ ] **Step 5: Verify convert still works end-to-end against a cached bucket**

Run (uses an existing preprocessed lookup + dataset dir if present, else skip):
`cd sccm/sccm && uv run openhound convert sccm ./output/sccm ./output/graph --lookup-file ./output/lookup.duckdb`
Expected: writes `sccm_nodes-*.json` / `sccm_edges-*.json` to `./output/graph` exactly as before (no upload without `-B`).

- [ ] **Step 6: Verify `--run-all` still chains (app.converter wiring intact)**

Run: `cd sccm/sccm && uv run pytest tests/convert_integration_test.py -v`
Expected: PASS (convert output unchanged; the manual `app.converter` matches the old decorator behavior).

- [ ] **Step 7: Green checkpoint** — stop for review. Both commands now upload.

---

### Task 11: Documentation, architecture, and ticket close-out

**Files:**
- Modify: `sccm/sccm/README.md` — Quick Start step 5, a new "BloodHound Upload" subsection under Command Line Options, copy-paste examples for the mayyhem.com lab.
- Modify: `sccm/sccm/ARCHITECTURE.md` — new divergence section + changelog entry.
- Modify: `TICKETS-BY-STATUS.md` — reflect ope-8c44.
- Command: `gtk` status + note on ope-8c44.

**Notes:** Docs are code-truth. Only document what Tasks 1–10 actually implemented.

- [ ] **Step 1: Rewrite README Quick Start step 5**

Replace the current step 5 with a direct-upload example and keep the manual path as an alternative:

```markdown
### 5. Upload to BloodHound

One command — collect, build the graph, and upload schema + results to BloodHound CE:

```powershell
uv run openhound collect sccm .\out -d mayyhem.com --dc dc.mayyhem.com `
  -u "MAYYHEM\domainadmin" -p "Passw0rd!" --run-all `
  -B "<token-id>:<token-key>@https://bloodhound.mayyhem.com"
```

Re-upload an existing run without recollecting:

```powershell
uv run openhound convert sccm .\out\sccm .\out\graph --lookup-file .\out\lookup.duckdb `
  -B "<token-id>:<token-key>@https://bloodhound.mayyhem.com"
```

Push only the schema (registers the SCCM_* and MSSQL_* kinds/icons), no data:

```powershell
uv run openhound collect sccm .\out --skip-collection --upload-schema-only `
  -B "<token-id>:<token-key>@https://bloodhound.mayyhem.com"
```
```

- [ ] **Step 2: Add a "BloodHound Upload" subsection to Command Line Options**

Document each flag (verbatim names from the Global Constraints), the env vars (`BLOODHOUND_URL`, `BLOODHOUND_TOKEN_ID`, `BLOODHOUND_TOKEN_KEY`), that both schemas upload, and that `--disable-possible-edges` also flips those kinds non-traversable in the uploaded schema. Note the endpoints used (`PUT /api/v2/extensions`, `POST /api/v2/file-upload/*`) and that the upload uses local DNS (not the `--proxy` tunnel).

- [ ] **Step 3: Add the ARCHITECTURE.md divergence section + changelog**

Add a section documenting: (a) direct upload as a new capability built on `openhound-collector-common/bloodhound`, and (b) the `convert sccm` hand-registration (why: `@app.convert` exposes no flag seam; how: manual `app.converter` + `_convert_typer.command`; the same seam pattern as `collect`). Add a dated changelog row.

- [ ] **Step 4: Update TICKETS-BY-STATUS.md and annotate the ticket**

Run:
```bash
gtk add-note ope-8c44 "Implemented: shared bloodhound uploader in openhound-collector-common (auth/client/uploader/zip/schema); SCCM collect+convert wired (-B/--bloodhound, env vars, --upload-schema-only/--upload-results-only, --skip-collection, --upload-dir); uploads schema.json + schema_MSSQL.json with --disable-possible-edges mutation; convert hand-registered. Offline tests green. Live lab validation vs bloodhound.mayyhem.com pending."
```
Then edit `TICKETS-BY-STATUS.md` to list ope-8c44 under the appropriate status (in_progress until live-validated).

- [ ] **Step 5: Full re-validation of both extensions (shared-lib change gate)**

Run the targeted suites that exercise the shared lib and SCCM wiring:
```bash
cd openhound-collector-common && uv run pytest tests/test_bloodhound_*.py -v
cd sccm/sccm && uv run pytest tests/bloodhound_schemas_test.py tests/bloodhound_upload_test.py tests/bloodhound_cli_test.py tests/convert_integration_test.py -v
```
Expected: all PASS. (Per the shared-lib gate, the MSSQL extension must still import cleanly: `cd mssql/mssql && uv run python -c "import openhound_mssql.main"`.)

- [ ] **Step 6: Green checkpoint** — stop for owner review + live-lab validation vs `bloodhound.mayyhem.com`.

---

## Live Validation (owner, post-merge)

Not an automated task — the offline tests use fakes. After review, validate against the lab:

1. Create a BloodHound CE API token (token id + key).
2. `uv run openhound collect sccm .\out -d mayyhem.com --dc dc.mayyhem.com -u "MAYYHEM\domainadmin" -p "Passw0rd!" --run-all -B "<id>:<key>@https://bloodhound.mayyhem.com" -v`
3. Confirm in BH CE: the SCCM_* and MSSQL_* kinds render with icons; nodes/edges from the run are present; `--disable-possible-edges` hides the coerce-and-relay traversals.
4. Confirm `--skip-collection --upload-schema-only` registers kinds with no data, and `convert … -B` re-uploads without recollecting.

## Self-Review Notes

- **Spec coverage:** D1 (Task 2 endpoints + Task 1 auth + Task 2 retry), D2 (Tasks 1–6 in shared lib; Tasks 7–10 SCCM-only), D3 (Task 9 collect + Task 10 convert), D4 (Task 4 zip, no seed_data), D5 (Task 7 loads both schemas), D6 (Task 9 `--skip-collection`/`--upload-dir`, Task 10 `--upload-dir`), D7 (Task 5 mutation + Task 7 kind sets). All covered.
- **Type consistency:** `build_uploader`/`resolve_credentials`/`UploadSummary`/`run_upload`/`load_sccm_schemas` signatures match between the Interfaces block and every task that uses them.
- **Divergence flagged:** `convert sccm` hand-registration (Task 10) is the one non-obvious structural change; documented in Task 11.

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
        try:
            for f in files:
                try:
                    self.client.upload_file(job_id, f)
                    summary.files_uploaded += 1
                    self.log.info("Uploaded %s", Path(f).name)
                except (BloodHoundHTTPError, OSError) as exc:
                    summary.files_failed += 1
                    summary.errors.append(f"{Path(f).name}: {exc}")
                    self.log.warning("Failed to upload %s: %s", Path(f).name, exc)
        finally:
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

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
    def __init__(self, fail_file=False, fail_file_oserror=False):
        self.schemas = []
        self.files = []
        self.started = 0
        self.ended = 0
        self._fail_file = fail_file
        self._fail_file_oserror = fail_file_oserror

    def upload_schema(self, data):
        self.schemas.append(data)

    def start_upload(self):
        self.started += 1
        return "job-1"

    def upload_file(self, job_id, path):
        if self._fail_file_oserror:
            raise FileNotFoundError(f"File not found: {path}")
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


def test_upload_files_handles_oserror_and_still_ends_job():
    c = FakeClient(fail_file_oserror=True)
    summary = BloodHoundUploader(c).upload_files([Path("a.zip")])
    assert summary.files_failed == 1 and not summary.ok
    assert c.ended == 1  # job closed even on file read error
    # Verify no exception propagated out of upload_files
    assert len(summary.errors) == 1
    assert "a.zip" in summary.errors[0]

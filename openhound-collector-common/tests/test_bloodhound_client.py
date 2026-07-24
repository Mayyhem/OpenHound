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


class FakeResponseBadJSON(FakeResponse):
    """FakeResponse that raises ValueError when json() is called."""
    def json(self):
        raise ValueError("Invalid JSON")


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


def test_no_retry_on_401():
    client, calls = make_client([FakeResponse(401, text="unauthorized")])
    with pytest.raises(BloodHoundHTTPError):
        client.start_upload()
    assert len(calls) == 1  # raised immediately, no retry


def test_malformed_json_graceful_failure():
    """200 with invalid JSON body raises BloodHoundHTTPError, not ValueError."""
    client, calls = make_client([FakeResponseBadJSON(200)])
    with pytest.raises(BloodHoundHTTPError) as exc_info:
        client.start_upload()
    assert "unparseable response body" in str(exc_info.value)


def test_null_data_field_graceful_failure():
    """200 with {"data": null} raises BloodHoundHTTPError for empty job id."""
    client, calls = make_client([FakeResponse(200, json_body={"data": None})])
    with pytest.raises(BloodHoundHTTPError) as exc_info:
        client.start_upload()
    assert "empty job id" in str(exc_info.value)


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

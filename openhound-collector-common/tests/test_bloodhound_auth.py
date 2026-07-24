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

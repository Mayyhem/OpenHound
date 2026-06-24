# Task A1: Stamp host SID onto the RemoteRegistry current-user row

**Why:** `HasSession` (Computer→User) needs the host computer SID; today the `remoteregistry_users` current-user row carries only the *user's* SID. See `sccm/sccm/src/openhound_sccm/collectors/registry.py` lines ~471-483 (`get_current_user`).

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/collectors/registry.py`
- Create (test): `sccm/sccm/src/openhound_sccm/collectors/registry_current_user_test.py`

**Interfaces — Produces:** `remoteregistry_users` rows gain `host_object_sid: str | None` (the probed host's AD computer SID).

## Step 1: Write the failing test

```python
# src/openhound_sccm/collectors/registry_current_user_test.py
import types
from openhound_sccm.collectors import registry


class _FakeProbe:
    hostname = "host1.lab"
    def read_values(self, _key):
        return [("UserSID", "S-1-5-21-1-2-3-1106"), ("Session", 1)]


def _fake_ctx():
    host_obj = {"name": "HOST1", "object_sid": "S-1-5-21-1-2-3-1104"}
    user_obj = {"sam_account_name": "alice", "object_sid": "S-1-5-21-1-2-3-1106"}
    ctx = types.SimpleNamespace()
    ctx.resolve_principal = lambda sid: dict(user_obj)
    ctx.target_hosts_by_hostname = {"host1.lab": types.SimpleNamespace(ad_object=host_obj)}
    return ctx


def test_current_user_row_has_host_object_sid():
    rows = list(registry.get_current_user(_FakeProbe(), _fake_ctx()))
    assert len(rows) == 1
    table, row = rows[0]
    assert table == "remoteregistry_users"
    assert row["object_sid"] == "S-1-5-21-1-2-3-1106"        # the logged-on user
    assert row["host_object_sid"] == "S-1-5-21-1-2-3-1104"   # the host it logged onto
```

## Step 2: Run — expect failure (`KeyError: 'host_object_sid'`).

## Step 3: Implement

In `get_current_user`, look up the host entry and add `host_object_sid` to the row (mirroring `get_ntlm_settings`/`get_mssql_settings`, which already do `ctx.target_hosts_by_hostname[probe.hostname]`):

```python
        if current_user_ad_object:
            logger.info("Found current user: %s (%s)", current_user_ad_object.get("sam_account_name"), current_user_sid)
            target_entry = ctx.target_hosts_by_hostname.get(probe.hostname)
            host_sid = target_entry.ad_object.get("object_sid") if (target_entry and target_entry.ad_object) else None
            if host_sid is None:
                # No resolved host AD object — HasSession can't be built for this row downstream; keep the row but log.
                logger.warning("Current-user row for %s has no host object_sid; HasSession will be dropped downstream", probe.hostname)
            row = {
                **(current_user_ad_object or {}),
                "source": "RemoteRegistry-CurrentUser",
                "host_object_sid": host_sid,
            }
            row.setdefault("object_sid", current_user_sid)
            yield "remoteregistry_users", row
```

> Note: the real `get_current_user` uses `ctx.target_hosts_by_hostname[probe.hostname]` directly elsewhere; `.get(...)` is used here so a missing entry logs+continues rather than KeyError. Match the surrounding code's style and keep the existing `current_user_sid`/`read_values` logic intact.

## Step 4: Run — expect PASS.

## Step 5: Checkpoint — `git add` (stage only, NO commit):
`git add sccm/sccm/src/openhound_sccm/collectors/registry.py sccm/sccm/src/openhound_sccm/collectors/registry_current_user_test.py`

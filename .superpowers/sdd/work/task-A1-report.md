# Task A1 Report: Stamp host SID onto RemoteRegistry current-user row

## Status
DONE

## Files Changed

### Modified
- `sccm/sccm/src/openhound_sccm/collectors/registry.py`
  - In `get_current_user` (lines ~474-483), after the existing `logger.info` call, added a lookup via `ctx.target_hosts_by_hostname.get(probe.hostname)` to retrieve the host's AD object and extract its `object_sid` as `host_sid`.
  - Added `"host_object_sid": host_sid` to the yielded row dict.
  - Added a `logger.warning` when `host_sid` is `None` (no resolved host AD object), noting that `HasSession` will be dropped downstream.
  - Used `.get()` on the dict rather than direct bracket access, consistent with the brief's guidance for graceful missing-entry handling.

### Created
- `sccm/sccm/src/openhound_sccm/collectors/registry_current_user_test.py`
  - Single test `test_current_user_row_has_host_object_sid` using `_FakeProbe` (returns `UserSID` + `Session` values) and `_fake_ctx` (simulates both a resolved user AD object and a host entry with `object_sid`).
  - Asserts: one row yielded, table name is `remoteregistry_users`, `object_sid` is the user SID, `host_object_sid` is the host SID.

## Test Command and Output

```
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/collectors/registry_current_user_test.py -v
```

### Before implementation (Step 2 — expected failure):
```
FAILED sccm/sccm/src/openhound_sccm/collectors/registry_current_user_test.py::test_current_user_row_has_host_object_sid
KeyError: 'host_object_sid'
1 failed in 4.63s
```

### After implementation (Step 4 — expected pass):
```
PASSED sccm/sccm/src/openhound_sccm/collectors/registry_current_user_test.py::test_current_user_row_has_host_object_sid
1 passed in 1.62s
```

## Deviations from Brief
None. Implementation matches the brief's code block exactly. Style matches surrounding code in `registry.py` (same pattern as `get_ntlm_settings`/`get_mssql_settings` which use `ctx.target_hosts_by_hostname[probe.hostname]` directly for non-None cases).

## Concerns
None.

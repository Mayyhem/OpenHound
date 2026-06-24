# Task C1 Report

## Files Changed

- `sccm/sccm/src/openhound_sccm/transforms.py` — added `_resource_to_sid`, `_device_by_resourceid`, `_collection_by_name`, `_role_by_name` builder functions; added 6 new `(label, select)` entries to `_principal_by_name`'s `sources` list (unique_user_name, full_user_name, user_principal_name × adminservice/wmi); wired all 4 lookup builders into `transforms()` after `_node_client_device` and before `_graph_edges_init`.
- `sccm/sccm/src/openhound_sccm/transforms_lookups_test.py` — created; tests `test_lookups_built` and `test_principal_by_name_resolves_unique_user_name`.

## Test Command + Output

```
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest .../transforms_lookups_test.py .../transforms_principal_test.py -v
```

```
collected 5 items
transforms_lookups_test.py::test_lookups_built PASSED
transforms_lookups_test.py::test_principal_by_name_resolves_unique_user_name PASSED
transforms_principal_test.py::test_principal_by_name_unions_and_uppercases PASSED
transforms_principal_test.py::test_root_site_code_resolves_to_cas PASSED
transforms_principal_test.py::test_principal_by_name_includes_user_groups PASSED
5 passed in 1.57s
```

## Deviations

None. Implementation matches spec verbatim.

## Concerns

None.

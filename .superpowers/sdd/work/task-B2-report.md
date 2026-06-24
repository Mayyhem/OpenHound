# Task B2 Report: `node_security_role` + `SCCMSecurityRole`

## Status: DONE

## Files changed
- **Created** `sccm/sccm/src/openhound_sccm/node_security_role_test.py` — transform test
- **Created** `sccm/sccm/src/openhound_sccm/models/sccm_security_role_test.py` — model tests
- **Created** `sccm/sccm/src/openhound_sccm/models/sccm_security_role.py` — `SCCMSecurityRole` model
- **Modified** `sccm/sccm/src/openhound_sccm/graph.py` — added `SCCMSecurityRoleProperties`
- **Modified** `sccm/sccm/src/openhound_sccm/transforms.py` — added `_node_security_role`; called from `transforms()` after `_node_collection`
- **Modified** `sccm/sccm/src/openhound_sccm/models/__init__.py` — exported `SCCMSecurityRole`
- **Modified** `sccm/sccm/src/openhound_sccm/main.py` — imported `SCCMSecurityRole`; added `("node_security_role", SCCMSecurityRole)` to `NODE_SPECS`

## Test run
```
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project .../sccm/sccm pytest .../node_security_role_test.py .../models/sccm_security_role_test.py -v
3 passed in 0.42s
```

## Deviations
None. Code transcribed verbatim from brief; no SQL/type errors encountered on the `operations` column.

## Concerns
None.

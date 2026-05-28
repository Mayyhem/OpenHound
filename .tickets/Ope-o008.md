---
id: Ope-o008
status: open
deps: []
links: []
created: 2026-05-28T13:28:30Z
type: task
priority: 1
assignee: Mayyhem
tags: [sccm, audit, relay, smb]
---
# Verify CoerceAndRelayToSMB Lifecycle (Collection to Postprocessing)

Audit whether intermediate CoerceAndRelayToSMB data survives through to postprocessing or is dropped before the transform phase. coerce_and_relay_edges is listed in transforms.py comments but no SQL definition exists. smb_signing_status feeds the relay feasibility check but the full data path has not been validated.

## Design

Trace full data path: SMB signing status collection -> JSONL storage -> preproc table -> transform SQL -> edge emission. Confirm smb_signing_status is in preproc_table_map in main.py. Implement the coerce_and_relay_edges SQL transform in transforms.py. Verify transform runs after all SMB collection completes. Add row count logging at each stage.

## Acceptance Criteria

coerce_and_relay_edges SQL transform is implemented and correct. End-to-end test confirms edges appear when SMB signing is disabled on a site server. No data silently dropped between collection and postprocessing.


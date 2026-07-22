---
id: Ope-8wi2
status: open
deps: []
links: []
created: 2026-05-28T13:31:15Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, bloodhound, output]
---

# Upload Directly to BloodHound

Wire up the SCCM extension output to the existing BloodHound upload destinations in OpenHound core. OpenHound core already implements BloodHound CE and BHE upload destinations but the SCCM extension only writes to local files. The app = OpenHound(sccm) instance supports registering additional destinations.

## Design

Add --bloodhound-url, --bloodhound-token (CE) and --bhe-url, --bhe-token (Enterprise) CLI flags to main.py. When provided, register the BloodHound upload destination with the DLT pipeline after conversion. Respect existing BloodHound client in /src/openhound/core/clients/bloodhound.py. Add --no-local-output flag to suppress local JSON write when uploading directly.

## Acceptance Criteria

--bloodhound-url and --bloodhound-token causes graph to be uploaded to BH CE after conversion. --bhe-url/--bhe-token targets BHE ingest API. Upload errors are reported without crashing (data still saved locally unless --no-local-output).

## Notes

**2026-07-22T16:24:34Z**

CLI panel reserved (2026-07-22): during the collect-sccm --help reorg, the operator asked for a 'BloodHound Upload' rich_help_panel. It was NOT added yet because there are no upload flags. When this ticket is implemented, add the upload flag(s) to collect_sccm() (or a dedicated 'openhound upload' path) with rich_help_panel='BloodHound Upload' so they render as their own titled section in --help. Sibling reorg note: options are grouped into Authentication/Collection/Performance/Output/Logging panels via rich_help_panel; follow that pattern.

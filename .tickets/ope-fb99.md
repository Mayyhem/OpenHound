---
id: ope-fb99
status: open
deps: []
links: [ope-c141, ope-c0c0, ope-6b93]
created: 2026-07-23T19:20:16Z
type: task
priority: 2
tags: [sccm, graph]
---

# Emit missing SCCM node/edge properties (ClientDevice extras, Site.siteSystemRoles, IsMappedTo.SCCMInfra) to CMBP parity

A --compare-to-zip diff (OpenHound vs CMBP baseline) found SCCM-specific properties present in CMBP output but not emitted by the OpenHound collector. Emit all of these (CMBP-exact casing): (1) SCCM_ClientDevice: currentManagementPoint, currentManagementPointSID, previousSMSID, previousSMSIDChangeDate, userName, userDomainName, lastReportedMPServerSID (and DNSHostName/distinguishedName if resolvable). (2) SCCM_Site: siteSystemRoles. (3) SCCM_IsMappedTo edge: SCCMInfra property. Determine each source from ConfigManBearPig.ps1 (AdminService/WMI SMS_R_System / SMS_CombinedDeviceResources fields for the client-device extras; site-definition/SysResUse for siteSystemRoles) and plumb through preproc/convert to the node/edge property dataclasses. Update README node/edge reference + ARCHITECTURE. Part of the same CMBP-parity effort as the AD-property ticket; needs brainstorm/spec/plan.

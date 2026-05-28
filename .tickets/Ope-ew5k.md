---
id: Ope-ew5k
status: open
deps: []
links: []
created: 2026-05-28T13:27:40Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, collection, wmi]
---
# WMI Collection

Implement WMI-based collection for client devices, logged-on users, and SQL service accounts. Three WMI-sourced preproc tables are defined but have no collector: wmi_clients, wmi_users_seen, wmi_sql_service_accounts.

## Design

Create collectors/wmi.py. Use impacket or wmi library for remote WMI queries (respect --socks-proxy). Query root\ccm:SMS_Client for client GUID/version/site, root\cimv2:Win32_LoggedOnUser for active users, root\cimv2:Win32_Service WHERE Name LIKE MSSQL% for SQL service accounts. Gate on ctx.method_enabled(WMI). Register resources in source.py Phase 3.

## Acceptance Criteria

With --collection-methods WMI, collector queries each target host and yields wmi_clients, wmi_users_seen, wmi_sql_service_accounts records. Data flows into preproc tables and populates graph edges.


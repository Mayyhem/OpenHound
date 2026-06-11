---
id: ope-b7b2
status: open
deps: []
links: [ope-272e]
created: 2026-06-09T20:50:25Z
type: task
priority: 3
tags: [sccm, auth, pth, ptt, credentials, deferred]
---

# Wire --nt-hash / --ticket into LDAP, SMB, RemoteRegistry, MSSQL auth paths

DEFERRED. The HTTP-client work (ope-d57d) introduces the global --nt-hash and --ticket CLI flags + SourceContext.kerberos_ticket, but initially only the HTTP client consumes them. This ticket threads those same credentials into the OTHER already-implemented auth paths so pass-the-hash and pass-the-ticket work uniformly across all protocols: LDAP (clients/ad.py ADCredentials + bind: NTLM pass-the-hash and Kerberos pass-the-ticket), SMB/RemoteRegistry (clients/smb_sso.py connect_smb: explicit NTLM-hash login + Kerberos ticket path), MSSQL (clients/mssql_epa.py: nt_hash already supported, add ticket). Relates to / subsumes ope-272e (LDAP PtH placeholder).

---
id: ope-272e
status: open
deps: []
links: [ope-b7b2]
created: 2026-06-08T20:57:57Z
type: task
priority: 3
assignee: cthompson
tags: [sccm, ldap, pth, placeholder]
---

# LDAP pass-the-hash (--nt-hash) support — placeholder

Placeholder: add pass-the-hash (NT hash) support to the LDAP/AD client auth path (ADCredentials + ad.py SSPI/NTLM bind), mirroring the nt_hash support added for MSSQL EPA in ope-c8cc. Lets operators authenticate LDAP with DOMAIN/user + NT hash instead of a cleartext password. Scope/design TBD.

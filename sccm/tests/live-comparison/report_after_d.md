# Unit-test comparison: live ConfigManBearPig.ps1 vs OpenHound SCCM collector

Both runs used the **same** `Invoke-ConfigManBearPigUnitTests.ps1` kit and the identical `$ExpectedEdges` list, collected with **All methods + `-DisablePossibleEdges`**. Test cases are aligned by position (the kit runs the list in a fixed order).

- **CMBP console:** `C:\Users\domainadmin\Desktop\OpenHound\sccm\tests\live-comparison\results\live_run.log`
- **OpenHound console:** `C:\Users\domainadmin\Desktop\OpenHound\sccm\tests\live-comparison\results\openhound_d_run.log`

## Top-line

| Metric | CMBP (live) | OpenHound |
|---|---|---|
| Total nodes | 171 | 239 |
| Total edges | 455 | 411 |
| Tests PASSED | 53 | 55 |
| Tests FAILED | 7 | 5 |
| Tests SKIPPED | 1 | 1 |
| Result lines parsed | 61 | 61 |

## Divergences

- **Regressions (CMBP PASS → OpenHound not PASS): 2**
- OpenHound-only passes (CMBP not PASS → OpenHound PASS): 4
- Both FAIL: 3
- Agree PASS: 51

### Regressions — present/correct in CMBP, missing/wrong in OpenHound

| # | Kind | Description | CMBP | OpenHound |
|---|---|---|---|---|
| 58 | `SCCM_IsAssigned` | The domainadmin SCCM admin user is assigned the Full Administrator security role in the... | PASS | FAIL (wrong count) |
| 59 | `SCCM_IsMappedTo` | The domainadmin user is mapped to an SCCM admin user in the CAS primary site (plus one ... | PASS | FAIL (wrong count) |

### OpenHound-only passes — investigate whether these are real or false positives

| # | Kind | Description | CMBP | OpenHound |
|---|---|---|---|---|
| 28 | `MSSQL_Contains` | The MSSQL servers (cas-db, ps1-db, and ps1-psv) contain the sysadmin server role | FAIL (wrong count) | PASS |
| 30 | `MSSQL_ControlServer` | The sysadmin MSSQL server role controls the server instance on cas-db, ps1-db, and ps1-psv | FAIL (wrong count) | PASS |
| 31 | `MSSQL_ExecuteOnHost` | The MSSQL servers (cas-db, ps1-db, and ps1-psv) can execute commands on their hosts | FAIL (wrong count) | PASS |
| 35 | `MSSQL_HostFor` | The MSSQL server computers (cas-db, ps1-db, and ps1-psv) host the MSSQL server instances | FAIL (wrong count) | PASS |

### Failing in both

| # | Kind | Description | CMBP | OpenHound |
|---|---|---|---|---|
| 17 | `CoerceAndRelayToSMB` | Authenticated Users group can coerce and relay authentication to the SMB service on the... | FAIL (not found) | FAIL (not found) |
| 52 | `SCCM_FullAdministrator` | The domainadmin SCCM admin user has the Full Administrator security role over all clien... | FAIL (wrong count) | FAIL (wrong count) |
| 55 | `SCCM_HasCurrentUser` | The PS1 client device has domainuser as the current logged on user (requires manual add... | FAIL (not found) | FAIL (not found) |

## Per-edge-kind rollup (PASS / FAIL / SKIP)

| Kind | CMBP P/F/S | OpenHound P/F/S |
|---|---|---|
| `CoerceAndRelayToAdminService` | 1/0/0 | 1/0/0 |
| `CoerceAndRelayToMSSQL` | 4/0/0 | 4/0/0 |
| `CoerceAndRelayToSMB` | 3/1/0 | 3/1/0 |
| `HasSession` | 2/0/0 | 2/0/0 |
| `LocalAdminRequired` | 9/0/0 | 9/0/0 |
| `MSSQL_Contains` | 8/1/0 | 9/0/0 |
| `MSSQL_ControlDB` | 1/0/0 | 1/0/0 |
| `MSSQL_ControlServer` | 0/1/0 | 1/0/0 |
| `MSSQL_ExecuteOnHost` | 0/1/0 | 1/0/0 |
| `MSSQL_GetAdminTGS` | 1/0/0 | 1/0/0 |
| `MSSQL_GetTGS` | 1/0/0 | 1/0/0 |
| `MSSQL_HasLogin` | 1/0/0 | 1/0/0 |
| `MSSQL_HostFor` | 0/1/0 | 1/0/0 |
| `MSSQL_IsMappedTo` | 1/0/0 | 1/0/0 |
| `MSSQL_MemberOf` | 2/0/0 | 2/0/0 |
| `MSSQL_ServiceAccountFor` | 1/0/0 | 1/0/0 |
| `SCCM_AdminsReplicatedTo` | 3/0/0 | 3/0/0 |
| `SCCM_AllPermissions` | 1/0/0 | 1/0/0 |
| `SCCM_AssignAllPermissions` | 2/0/0 | 2/0/0 |
| `SCCM_AssignSpecificPermissions` | 0/0/1 | 0/0/1 |
| `SCCM_Contains` | 3/0/0 | 3/0/0 |
| `SCCM_FullAdministrator` | 0/1/0 | 0/1/0 |
| `SCCM_HasADLastLogonUser` | 1/0/0 | 1/0/0 |
| `SCCM_HasClient` | 1/0/0 | 1/0/0 |
| `SCCM_HasCurrentUser` | 0/1/0 | 0/1/0 |
| `SCCM_HasMember` | 1/0/0 | 1/0/0 |
| `SCCM_HasPrimaryUser` | 1/0/0 | 1/0/0 |
| `SCCM_IsAssigned` | 1/0/0 | 0/1/0 |
| `SCCM_IsMappedTo` | 2/0/0 | 1/1/0 |
| `SameHostAs` | 2/0/0 | 2/0/0 |

## Edge-type histogram (raw edges emitted, by kind)

| Kind | CMBP | OpenHound |
|---|---|---|
| `CoerceAndRelayToAdminService` | 2 | 1 |
| `CoerceAndRelayToMSSQL` | 5 | 4 |
| `CoerceAndRelayToSMB` | 5 | 4 |
| `HasSession` | 9 | 8 |
| `LocalAdminRequired` | 13 | 14 |
| `MSSQL_Contains` | 15 | 17 |
| `MSSQL_ControlDB` | 3 | 3 |
| `MSSQL_ControlServer` | 3 | 3 |
| `MSSQL_ExecuteOnHost` | 3 | 3 |
| `MSSQL_GetAdminTGS` | 3 | 2 |
| `MSSQL_GetTGS` | 5 | 4 |
| `MSSQL_HasLogin` | 5 | 4 |
| `MSSQL_HostFor` | 3 | 3 |
| `MSSQL_IsMappedTo` | 5 | 4 |
| `MSSQL_LinkedAsAdmin` | 1 | 0 |
| `MSSQL_MemberOf` | 9 | 8 |
| `MSSQL_ServiceAccountFor` | 3 | 2 |
| `MemberOf` | 70 | 79 |
| `SCCM_AdminsReplicatedTo` | 4 | 3 |
| `SCCM_AllPermissions` | 3 | 2 |
| `SCCM_ApplicationAdministrator` | 20 | 19 |
| `SCCM_AssignAllPermissions` | 11 | 10 |
| `SCCM_AssignSpecificPermissions` | 1 | 0 |
| `SCCM_Contains` | 61 | 60 |
| `SCCM_FullAdministrator` | 20 | 19 |
| `SCCM_HasADLastLogonUser` | 15 | 14 |
| `SCCM_HasClient` | 39 | 19 |
| `SCCM_HasCurrentUser` | 7 | 6 |
| `SCCM_HasMember` | 41 | 43 |
| `SCCM_HasNetworkAccessAccount` | 1 | 0 |
| `SCCM_HasPrimaryUser` | 2 | 1 |
| `SCCM_HasStoredAccount` | 3 | 2 |
| `SCCM_IsAssigned` | 19 | 9 |
| `SCCM_IsMappedTo` | 7 | 3 |
| `SameHostAs` | 39 | 38 |

## Full per-test comparison

| # | Kind | Description | CMBP | OpenHound | Flag |
|---|---|---|---|---|---|
| 0 | `LocalAdminRequired` | The CAS primary site server has local administrator rights on the C... | PASS | PASS |  |
| 1 | `LocalAdminRequired` | The CAS primary site server has local administrator rights on the s... | PASS | PASS |  |
| 2 | `LocalAdminRequired` | The PS1 primary site server has local administrator rights on the s... | PASS | PASS |  |
| 3 | `LocalAdminRequired` | The PS1 primary site server has local administrator rights on the S... | PASS | PASS |  |
| 4 | `LocalAdminRequired` | The PS1 primary site server has local administrator rights on the m... | PASS | PASS |  |
| 5 | `LocalAdminRequired` | The PS1 primary site server has local administrator rights on the d... | PASS | PASS |  |
| 6 | `LocalAdminRequired` | The PS1 primary site server has local administrator rights on the p... | PASS | PASS |  |
| 7 | `LocalAdminRequired` | The PS1 passive site server has local administrator rights on the p... | PASS | PASS |  |
| 8 | `LocalAdminRequired` | The PS2 primary site server does not have local administrator right... | PASS (correctly absent) | PASS (correctly absent) |  |
| 9 | `CoerceAndRelayToAdminService` | Authenticated Users group can coerce the PS1 primary site server an... | PASS | PASS |  |
| 10 | `CoerceAndRelayToMSSQL` | Authenticated Users group can coerce and relay authentication to th... | PASS | PASS |  |
| 11 | `CoerceAndRelayToMSSQL` | Authenticated Users group can coerce and relay authentication to th... | PASS | PASS |  |
| 12 | `CoerceAndRelayToMSSQL` | Authenticated Users group can coerce and relay authentication to th... | PASS | PASS |  |
| 13 | `CoerceAndRelayToMSSQL` | Authenticated Users group can coerce and relay authentication to th... | PASS | PASS |  |
| 14 | `CoerceAndRelayToSMB` | Authenticated Users group can coerce and relay authentication to th... | PASS | PASS |  |
| 15 | `CoerceAndRelayToSMB` | Authenticated Users group can coerce and relay authentication to th... | PASS | PASS |  |
| 16 | `CoerceAndRelayToSMB` | Authenticated Users group can coerce and relay authentication to th... | PASS | PASS |  |
| 17 | `CoerceAndRelayToSMB` | Authenticated Users group can coerce and relay authentication to th... | FAIL (not found) | FAIL (not found) | both FAIL |
| 18 | `HasSession` | The MSSQL service account has an active session on the CAS site dat... | PASS | PASS |  |
| 19 | `HasSession` | The MSSQL service account has an active session on the PS1 site dat... | PASS | PASS |  |
| 20 | `MSSQL_Contains` | The CAS site database MSSQL server contains the CM_<SiteCode> database | PASS | PASS |  |
| 21 | `MSSQL_Contains` | The CAS site database MSSQL server contains the CAS-PSS$ login | PASS | PASS |  |
| 22 | `MSSQL_Contains` | The CAS site database contains the db_owner database role | PASS | PASS |  |
| 23 | `MSSQL_Contains` | The CAS site database contains the CAS-PSS$ user | PASS | PASS |  |
| 24 | `MSSQL_Contains` | The PS1 site database MSSQL server contains the CM_<SiteCode> database | PASS | PASS |  |
| 25 | `MSSQL_Contains` | The PS1 site database MSSQL server contains the PS1-PSS$ login | PASS | PASS |  |
| 26 | `MSSQL_Contains` | The PS1 site database contains the db_owner database role | PASS | PASS |  |
| 27 | `MSSQL_Contains` | The PS1 site database contains the PS1-PSS$ user | PASS | PASS |  |
| 28 | `MSSQL_Contains` | The MSSQL servers (cas-db, ps1-db, and ps1-psv) contain the sysadmi... | FAIL (wrong count) | PASS | ⚠️ OH-only pass |
| 29 | `MSSQL_ControlDB` | The db_owner MSSQL database role controls the site database on cas-... | PASS | PASS |  |
| 30 | `MSSQL_ControlServer` | The sysadmin MSSQL server role controls the server instance on cas-... | FAIL (wrong count) | PASS | ⚠️ OH-only pass |
| 31 | `MSSQL_ExecuteOnHost` | The MSSQL servers (cas-db, ps1-db, and ps1-psv) can execute command... | FAIL (wrong count) | PASS | ⚠️ OH-only pass |
| 32 | `MSSQL_GetAdminTGS` | The site database MSSQL service account can request a TGS for any d... | PASS | PASS |  |
| 33 | `MSSQL_GetTGS` | The site database MSSQL service account can request a TGS for any d... | PASS | PASS |  |
| 34 | `MSSQL_HasLogin` | The primary and passive site server and SMS Provider computers have... | PASS | PASS |  |
| 35 | `MSSQL_HostFor` | The MSSQL server computers (cas-db, ps1-db, and ps1-psv) host the M... | FAIL (wrong count) | PASS | ⚠️ OH-only pass |
| 36 | `MSSQL_IsMappedTo` | The primary and passive site server and SMS Provider MSSQL server l... | PASS | PASS |  |
| 37 | `MSSQL_MemberOf` | The primary and passive site server and SMS Provider MSSQL database... | PASS | PASS |  |
| 38 | `MSSQL_MemberOf` | The primary and passive site server and SMS Provider MSSQL server l... | PASS | PASS |  |
| 39 | `MSSQL_ServiceAccountFor` | The site database MSSQL service account is the service account for ... | PASS | PASS |  |
| 40 | `SameHostAs` | The PS1 client device is the same host as the domain joined compute... | PASS | PASS |  |
| 41 | `SameHostAs` | The PS1 client device is the same host as the domain joined compute... | PASS | PASS |  |
| 42 | `SCCM_AdminsReplicatedTo` | The PS1 primary site has the same admins as the CAS primary site | PASS | PASS |  |
| 43 | `SCCM_AdminsReplicatedTo` | The PS1 primary site has the same admins as the CAS primary site (b... | PASS | PASS |  |
| 44 | `SCCM_AdminsReplicatedTo` | Admin users in secondary sites are NOT replicated to primary sites ... | PASS (correctly absent) | PASS (correctly absent) |  |
| 45 | `SCCM_AllPermissions` | The Full Administrator with all collections has all permissions to ... | PASS | PASS |  |
| 46 | `SCCM_AssignAllPermissions` | Domain computers hosting the SMS Provider role (CAS-PSS, PS1-PSS, P... | PASS | PASS |  |
| 47 | `SCCM_AssignAllPermissions` | SCCM primary site databases (CAS-DB\CM_CAS and PS1-DB\CM_PS1) can a... | PASS | PASS |  |
| 48 | `SCCM_AssignSpecificPermissions` | no Source/Target/Properties specified | SKIPPED (coverage placeholder) | SKIPPED (coverage placeholder) |  |
| 49 | `SCCM_Contains` | The CAS and PS1 primary sites contain an SCCM admin user | PASS | PASS |  |
| 50 | `SCCM_Contains` | The CAS and PS1 primary sites contain the Full Administrator securi... | PASS | PASS |  |
| 51 | `SCCM_Contains` | The CAS and PS1 primary sites contain the SMS00001 collection | PASS | PASS |  |
| 52 | `SCCM_FullAdministrator` | The domainadmin SCCM admin user has the Full Administrator security... | FAIL (wrong count) | FAIL (wrong count) | both FAIL |
| 53 | `SCCM_HasADLastLogonUser` | The PS1 client device has domainuser as the last logged on user in ... | PASS | PASS |  |
| 54 | `SCCM_HasClient` | PS1-DEV is a client of the PS1 site | PASS | PASS |  |
| 55 | `SCCM_HasCurrentUser` | The PS1 client device has domainuser as the current logged on user ... | FAIL (not found) | FAIL (not found) | both FAIL |
| 56 | `SCCM_HasMember` | The SMS00001 collection contains the PS1 client device | PASS | PASS |  |
| 57 | `SCCM_HasPrimaryUser` | The PS1 client device has domainuser as the primary user | PASS | PASS |  |
| 58 | `SCCM_IsAssigned` | The domainadmin SCCM admin user is assigned the Full Administrator ... | PASS | FAIL (wrong count) | ❌ REGRESSION |
| 59 | `SCCM_IsMappedTo` | The domainadmin user is mapped to an SCCM admin user in the CAS pri... | PASS | FAIL (wrong count) | ❌ REGRESSION |
| 60 | `SCCM_IsMappedTo` | The domainuser user is NOT mapped to an SCCM admin user in any prim... | PASS (correctly absent) | PASS (correctly absent) |  |

## Node-level: ClientDevice memberOf normalization check

- CMBP: not reported
- OpenHound: not reported

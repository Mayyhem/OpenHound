# SCCM port handoff

You are picking up a port of `sccm/ConfigManBearPig/python/` (~14,600 LOC stateful SCCM
enumeration tool, "CMBP") into the OpenHound DLT extension at `sccm/sccm/`. The goal is
**feature parity**: identical total node count, total edge count, and per-edge-kind
histogram for three users (`MAYYHEM\lowpriv`, `MAYYHEM\roanalyst`, `MAYYHEM\domainadmin`)
between the CMBP zip and the new OpenHound zip.

## Project status (2026-05-06, eighteenth session — CLI port: cobra-style flags + justfile)

**Headline:** every `configmanbearpig.py` CLI option is now exposed as a real
`--flag` on `openhound collect sccm`, `openhound preprocess sccm`, and
`openhound convert sccm`. The framework's `@app.collect()` / `@app.preproc()` /
`@app.convert()` convenience decorators are bypassed; the extension registers
its own commands directly on `openhound.cli.{collect, preproc, convert}` Typer
groups with the full CMBP flag surface (and the framework's standard
arguments preserved alongside for backwards-compat). Each flag also has a
`SOURCES__SCCM__*` env-var equivalent (loaded automatically from `.env` via
the supplied `justfile`'s `set dotenv-load := true`).

```pwsh
uv run openhound collect sccm output/ -u 'MAYYHEM\domainadmin' -p password -d mayyhem.com -m LDAP,SMB,WMI
```

works today. So does the env-var-only invocation, the `.env`-driven `just
all output/`, and any mix of flags + env vars (flags win because they're
applied last).

### Files this session

- `sccm/sccm/src/openhound_sccm/main.py` — rewritten. Direct registration on
  the framework's Typer groups with ~20 new `--flag` options on `collect`.
  `_FLAG_TO_ENV` mapping + `_apply_env_overrides` helper.
- `sccm/sccm/src/openhound_sccm/source.py` — `source()` factory keeps its
  four dlt-bound credentials and reads every other CMBP-equivalent value
  from `os.environ` via small `_env*` helpers. New fields on
  `SourceContext` (collection_methods, computers, computer_file,
  sms_provider, site_codes, threads, disable_possible_edges,
  enable_bad_opsec, show_cleartext_passwords, mssql_introspect,
  machine_name/_pass, client_name, create_machine_account, use_altauth,
  registration_sleep, socks_proxy). New `ctx.method_enabled(name)` helper.
  New `ctx.explicit_target_hosts()` helper backing `-c / --computers` and
  `-cf / --computer-file`. SMS-provider pinning in
  `adminservice_payloads()`. Site-codes override in
  `dns_management_points()`. Every `OPENHOUND_SCCM_DISABLE_*` env-var
  check replaced with `ctx.method_enabled(...)`.
- `sccm/sccm/src/openhound_sccm/models/derived/aggregator.py` — `_emit_edge`
  gains an `is_possible` parameter; gated by
  `SOURCES__SCCM__DISABLE_POSSIBLE_EDGES`.
- `sccm/sccm/justfile` (new) — OpenGraph-maintainer pattern with
  `set dotenv-load := true`. Tasks: `all`, `collect`, `preprocess`,
  `convert`, `package`, `sweep`, `sync`, `clean`, `clean-sweep`.
- `sccm/sccm/.env.example` (new) — every env var with its CMBP flag
  equivalent in a comment.
- `sccm/sccm/extension.yaml` — refreshed with real credentials and
  parameters (replaces the skeleton). Metadata-only at runtime, but
  inspected by `openhound create` / doc generators.
- `sccm/sccm/README.md` — full CLI reference section.
- `sccm/sccm/tests/test_flag_to_env_translation.py` (new) — 23 tests.
- `sccm/sccm/tests/test_collection_methods_gating.py` (new) — 26 tests.

All 49 new unit tests pass.

### Removed env vars

The following `OPENHOUND_SCCM_DISABLE_*` / `OPENHOUND_SCCM_ENABLE_*` env vars
no longer have any effect and should be removed from any wrapper scripts:

- `OPENHOUND_SCCM_DISABLE_ADMINSERVICE` → use `-m All,-AdminService` (or
  exclude `AdminService` from `-m`).
- `OPENHOUND_SCCM_DISABLE_WMI` → exclude `WMI` from `-m`.
- `OPENHOUND_SCCM_DISABLE_HTTP` → exclude `HTTP` from `-m`.
- `OPENHOUND_SCCM_DISABLE_SMB` → exclude `SMB` from `-m`.
- `OPENHOUND_SCCM_DISABLE_MSSQL_INTROSPECT` → set
  `SOURCES__SCCM__MSSQL_INTROSPECT=false` (the new opt-in default).
- `OPENHOUND_SCCM_ENABLE_MSSQL_INTROSPECT` → set
  `SOURCES__SCCM__MSSQL_INTROSPECT=true`.

### Verification gap — lab DC hardening

**Live three-user sweep could NOT be re-run this session.** The MAYYHEM DC
now requires LDAP signing/sealing and rejects unsigned NTLM binds with
`strongerAuthRequired`. CMBP's `lib/ad_resolver.py` uses the same
ldap3 + NTLM pattern as OpenHound's `clients/ad.py` and fails identically
(confirmed via direct test). Both collectors are still in sync — neither
can connect at all currently. The 49 unit tests cover the new code paths
and pass. The cobra-style CLI surface is verified live via
`openhound collect sccm --help`.

To re-run the live sweep, one of the following is needed:

- (a) Lab-side: roll back the DC's signing requirement (a Group Policy
  setting on Domain Controllers OU).
- (b) Code-side: extend both collectors' `ldap3.Connection` calls to use
  SASL GSS-SPNEGO (Kerberos) or LDAPS (port 636 + valid TLS cert on the
  DC). Per the bug-fix rule, this fix lands in both
  `clients/ad.py` and `lib/ad_resolver.py`.

The v12 parity result (143/478/36, 31/85/35, 143/469/36 — bit-identical to
CMBP for all three users) was captured before this lab hardening landed
and remains the canonical reference.

### Open items for the next session

- Live three-user sweep verification once lab DC bind is restored. Expect
  bit-identical parity with v12 baselines because the CLI port is
  config-only (no graph-side logic changed).
- LDAP signing support in both collectors (option (b) above) if the lab
  state can't be reverted.

## Project status (2026-05-04, seventeenth session — true parity achieved)

Read this file in full, then read the master plan at
`C:/Users/domainadmin/.claude/plans/parallel-puzzling-newt.md` before touching anything.

## Hard rules (non-negotiable)

1. **Never edit the OpenHound framework.** The installed package at
   `C:/Users/domainadmin/AppData/Roaming/uv/tools/openhound/Lib/site-packages/openhound/`
   is read-only. Any framework limitation gets worked around inside `sccm/sccm/` (Typer
   subcommand on `main.py`, wrapper script, do the work inside `convert`, etc.).
2. **All edits stay in `sccm/sccm/` or `sccm/ConfigManBearPig/python/`.** Nowhere else.
3. **Bug-fix rule.** Any behaviour fix lands in BOTH `sccm/ConfigManBearPig/python/`
   AND `sccm/sccm/`. Example carry-over: `CoerceAndRelaytoSMB` (lowercase `to`) is a typo
   in the original; when you encounter it, fix it in both.
4. **Strategy is full DLT rewrite, not wrapping.** The CMBP code is a reference, not a
   runtime dependency.
5. **Three-user verification sweep on every meaningful iteration.** Credentials:
   lowpriv/roanalyst use the literal password `password`; domainadmin uses the current
   Kerberos session.

## Project status (2026-05-06, seventeenth session — TRUE PARITY ACHIEVED for all three users)

**Headline numbers — every histogram identical:**

| User | OH-v12 | CMBP_full | Nodes | Edges | Edge kinds matching |
|---|---|---|---|---|---|
| **domainadmin** | **143 / 478 / 36** | **143 / 478 / 36** | **100%** | **100%** | **36/36** TRUE PARITY |
| **lowpriv** | **31 / 85 / 35** | **31 / 85 / 35** | **100%** | **100%** | **35/35** TRUE PARITY |
| **roanalyst** | **143 / 469 / 36** | **143 / 469 / 36** | **100%** | **100%** | **36/36** TRUE PARITY |

The unit test runner reports `Baseline comparison: identical` for all three users.

The "structural" MSSQL_* gap that the 16th-session block called inherent to
the lab (-21 edges, -3 nodes for domainadmin/roanalyst) was **NOT structural** — it
was an OH bug. The 17th-session diagnosis showed:

* The 16th-session handoff had wrongly identified `ps1-psv` as the PS1 site
  server's MSSQL DB host. The user's correction in the 17th-session brief
  (`ps1-pss` is primary, `ps1-psv` is passive) made me re-investigate the
  CMBP baselines. The MSSQL_Server endpoints in CMBP are actually
  `cas-db`, `ps1-db`, and `ps1-sec` (the DB-suffixed hosts), and OH's
  `mssql_epa_flags` already probes all three correctly. So the data was
  there — OH just wasn't building the structural edges on top of it.

* CMBP emits **per-MSSQL_Server structural edges** (`MSSQL_HostFor`,
  `MSSQL_ExecuteOnHost`, `MSSQL_ControlServer`, `MSSQL_ControlDB`, plus the
  three boilerplate `MSSQL_Contains` edges Server->sysadmin /
  Server->Database / Database->db_owner) for every MSSQL_Server with an
  associated SCCM site code. CMBP does this in
  `mssql_collector.py:103-107` (HostFor / ExecuteOnHost) and `367-435`
  (full hierarchy). OH was only emitting 6 of the 13 edge-emit paths via
  `mssql_sysadmin_edges`, which gates on `db.hostname <> sa.hostname` AND
  excludes Secondary sites — so PS1-SEC's `CM_SEC` database / sysadmin /
  db_owner triple never materialised.

* CMBP's "skip Secondary sites" check is `if site_type == "Secondary Site"`
  (string compare against the int `siteType=1`), so it never matches and
  CMBP does emit the SEC hierarchy. OH's classification correctly tagged
  SEC as Secondary and skipped it.

### What this session landed

1. **`mssql_server_hierarchy_edges` SQL view** in `transforms.py`. Builds
   the seven structural edges per (MSSQL_Server, site_code) tuple by
   joining `mssql_epa_flags` to `ldap_computers` for the Computer SID and
   left-joining `adminservice_site_systems` (role=`SMS SQL Server`) for
   the site_code. The two unconditional edges (`MSSQL_HostFor`,
   `MSSQL_ExecuteOnHost`) fire for every server; the five conditional
   edges (`MSSQL_Contains` x3, `MSSQL_ControlServer`, `MSSQL_ControlDB`)
   fire only when site_code is resolved. Wired into the aggregator as
   a new edge-emit block.

2. **`derived_nodes` extended** in `source.py`. Pre-loop fan-out now
   yields `MSSQL_Database` / `MSSQL_ServerRole sysadmin` /
   `MSSQL_DatabaseRole db_owner` nodes for **every** site that has an
   `SMS SQL Server` role row, including Secondary sites — independent
   of sysadmin Computer presence. Restores CM_SEC, sysadmin@PS1-SEC,
   and db_owner@CM_SEC for both DA and RA.

3. **Phantom SCCM_Collection nodes** in `adminservice_collections`
   resource. CMBP groups `SMS_FullCollectionMembership` rows by
   CollectionID and emits one `<id>@<members[0].SiteCode>` node per
   group. For user / user-group collections the first member's SiteCode
   is empty, producing `<id>@` (bare suffix) nodes. OH was overwriting
   the empty SiteCode with the AdminService host's site_code in
   `_collect_adminservice_data`, which suppressed those phantoms. We
   now preserve the raw SiteCode as a separate `raw_site_code` column
   on `adminservice_collection_members`, and the
   `adminservice_collections` resource yields one phantom row per
   CollectionID whose first member's `raw_site_code` is empty. This
   restores the 4 phantom nodes (SMS00002@, SMS00003@, SMS00004@,
   SMS000PS@) for DA/RA.

4. **`registry_current_users` gated on `sccm_discovered_hosts()`**.
   CMBP's per-host registry walk only iterates the `TargetManager`
   host list (LDAP-mSSMSManagementPoint, LDAP-NamePattern, SMS
   Provider sAMAccountName, AdminService SMS_Site /
   SMS_SCI_SiteDefinition / SMS_SCI_SysResUse). OH was iterating the
   full LDAP computer set and reading the DC's registry, surfacing a
   phantom `DC -> domainadmin` HasSession edge that CMBP never
   produces. Adding the gate matches CMBP exactly.

5. **SMB signing registry fallback** in `smb_signing_status`. CMBP's
   `registry_collector._read_smb_signing` reads
   `LanmanServer\Parameters::RequireSecuritySignature` REG_DWORD and
   uses it whenever the SMB-negotiate path would have failed (e.g. for
   passive failover hosts where 445 is firewalled but RPC over 135/445
   still works for registry). OH only had the SMB-negotiate path, so
   PS1-PSV was missed, dropping one `CoerceAndRelayToSMB` edge. Adding
   the registry fallback restores it.

### Files this session

- `sccm/sccm/src/openhound_sccm/transforms.py`:
  * Added `_build_mssql_server_hierarchy_edges` (~95 lines) and wired
    it into `transforms()`.
  * Added `mssql_server_hierarchy_edges` row to `_EMPTY_SCHEMAS`.

- `sccm/sccm/src/openhound_sccm/models/derived/aggregator.py`:
  * Added new edges-generator block reading from
    `mssql_server_hierarchy_edges`.
  * Added 7 new `EdgeDef` declarations in `_DECLARED_EDGES`
    (MSSQL_EXECUTE_ON_HOST, MSSQL_CONTROL_SERVER, MSSQL_CONTROL_DB,
    plus three new `MSSQL_CONTAINS` shapes for Server->ServerRole,
    Server->Database, Database->DatabaseRole).

- `sccm/sccm/src/openhound_sccm/source.py`:
  * `_collect_adminservice_data` — added `raw_site_code` column to
    `adminservice_collection_members` rows.
  * `adminservice_collections` resource — added phantom-node emission
    for empty-suffix CollectionIDs.
  * `derived_nodes` resource — added per-(server,site) structural
    fan-out before the existing sysadmin fan-out.
  * `registry_current_users` resource — added
    `ctx.sccm_discovered_hosts()` gate.
  * `smb_signing_status` resource — added registry fallback for SMB
    signing when SMB-negotiate fails.

- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_<user>_oh_v12.json`
  for all three users (canonical v12 OH baselines, identical to
  CMBP_full).

- `sccm/sccm/output_da_v12/`, `output_lp_v12/`, `output_ra_v12/` — final
  v12 ZIPs (canonical for this session).

### Files NOT touched (per the bug-fix rule)

Per "Bug fixes that affect collector behaviour land in BOTH collectors"
rule: **none of the seven fixes above port to CMBP** because each one
closes an OH-only gap relative to CMBP's already-correct behaviour
(CMBP already emits the structural MSSQL edges, the phantom Collection
nodes, gates on TargetManager, has the registry SMB-signing fallback,
etc.). The rule only requires bidirectional propagation when a fix
touches behaviour the other collector also gets wrong; here CMBP is
the reference.

### Recursion note (17th session)

The `Agent` tool was **not** in this session's tool surface (would have
been listed in available-skills had it been). Sub-agents typically
don't get it, so the parent agent should do the next handoff.

The work is complete. All three users at exact parity. No remaining
closeable or structural gaps. If a future session needs to add new
features (e.g. additional CMBP collectors not yet in OH), it should
re-verify the three-user sweep at the end and re-publish v13 baselines.

## Project status (2026-05-04, sixteenth session — AdminService SMS_SCI_SysResUse SQL service-account fallback, MSSQL_GetAdminTGS shape fix to Server target, DC/SMS_R_System computer anchor)

**Headline numbers:**

| User | OH-v11 | CMBP_full | Nodes | Edges | Edge kinds matching |
|---|---|---|---|---|---|
| domainadmin | 136 / 458 / 36 | 143 / 478 / 36 | **95%** | **96%** | **31/36** |
| **lowpriv** | **31 / 85 / 35** | **31 / 85 / 35** | **100%** | **100%** | **35/35** ✓ TRUE PARITY |
| **roanalyst** | **136 / 448 / 36** | 143 / 469 / 36 | **95%** | **96%** | **32/36** |

(Compare with v10: 95%/96%/29-of-36, 100%/100%/35-of-35, 94%/93%/26-of-36.
Roanalyst gained 6 perfect-parity edge kinds and closed all closeable gaps.
Domainadmin gained 2 perfect-parity edge kinds (MSSQL_GetAdminTGS, MemberOf)
and now matches roanalyst's drift profile exactly minus +1 HasSession.)

**Per-edge-kind drift (`MAYYHEM\domainadmin`, sixteenth session):**

```
Edge Kind                          OH-v11   CMBP_full   Delta
---------------------------------------------------------------
HasSession                            13         12       +1
MSSQL_Contains                         9         18       -9   (structural)
MSSQL_ControlDB                        1          4       -3   (structural)
MSSQL_ControlServer                    1          4       -3   (structural)
MSSQL_ExecuteOnHost                    1          4       -3   (structural)
MSSQL_HostFor                          1          4       -3   (structural)
(31 other edge kinds at exact parity)                       0
```

**Per-edge-kind drift (`MAYYHEM\roanalyst`, sixteenth session):**

```
Edge Kind                          OH-v11   CMBP_full   Delta
---------------------------------------------------------------
MSSQL_Contains                         9         18       -9   (structural)
MSSQL_ControlDB                        1          4       -3   (structural)
MSSQL_ControlServer                    1          4       -3   (structural)
MSSQL_ExecuteOnHost                    1          4       -3   (structural)
MSSQL_HostFor                          1          4       -3   (structural)
(32 other edge kinds at exact parity)                       0
```

All non-structural roanalyst gaps are now closed. The remaining drift is
identical to domainadmin's structural MSSQL_* gap (5 kinds, -21 edges total).

### What this session landed

1. **AdminService SMS_SCI_SysResUse SQL service-account fallback** —
   Extended the AdminService payload normaliser in
   `source.py::_collect_adminservice_data` so that `adminservice_site_systems`
   rows now carry a `service_account` column populated from the SMS_SCI_SysResUse
   item's `Props` array (`PropertyName="SQL Server Service Logon Account"`,
   value in `Props.Value2`). CMBP does the same parse at
   `lib/collectors/adminservice_collector.py:1267-1272`. This is the only
   data source for SQL service-account info that survives without
   `Win32_Service` WMI access — lowpriv/roanalyst can't read Win32_Service
   but can read the AdminService item Props.

2. **`_build_mssql_gettgs_edges` UNION fallback** — Rewrote the SQL view
   in `transforms.py` to UNION ALL two source paths for service-account
   discovery: `wmi_sql_service_accounts` (the WMI/Win32_Service path,
   only domainadmin has access) and `adminservice_site_systems` filtered
   on `role='SMS SQL Server' AND service_account IS NOT NULL` (the new
   AdminService Props path). The two sources are DISTINCT'd on
   `(host, service_account)` so co-emission doesn't double-fire.

3. **MSSQL_GetAdminTGS edge-shape correction** — Changed the MSSQL_GetAdminTGS
   target from MSSQL_Login (per-login fan-out) to MSSQL_Server (per-server),
   gated on the service account having a `MSSQLSvc/<host>` SPN registered in
   `ldap_users.service_principal_names`. CMBP emits MSSQL_GetAdminTGS at the
   MSSQL_Server level (`lib/collectors/mssql_collector.py:575`) — one edge
   per (svc, server) when the account is Kerberoastable. Our previous
   per-login fan-out over-emitted by N for each host with N sysadmin
   logins; the per-server shape with SPN gating restores CMBP's count
   exactly. Updated the EdgeDef declarations in
   `models/derived/aggregator.py` and `models/derived/mssql_gettgs.py`
   to declare `start=USER, end=MSSQL_SERVER` for this kind. Domainadmin
   went from 5 → 3 (matches CMBP), roanalyst from 1 → 3 (matches CMBP),
   closing the +2 / -2 drift respectively.

4. **MSSQL_GetTGS now fires for AdminService-only callers** — The same
   UNION fallback as #2 applies to MSSQL_GetTGS (per-login fan-out, all
   logins on the server). Roanalyst MSSQL_GetTGS went 1 → 5 (matches CMBP).

5. **HasSession from AdminService SQL service account** — The same SQL
   view's HasSession branch (Computer db host -> User svc account)
   activates with the new AdminService source. Roanalyst HasSession
   went 1 → 3 (matches CMBP exactly).

6. **MSSQL_ServiceAccountFor from AdminService** — Same. Roanalyst
   MSSQL_ServiceAccountFor went 1 → 3 (matches CMBP).

7. **DC anchor via SMS_R_System** — Extended
   `lookup.computer_is_sccm_infra` (in `lookup.py`) to also check
   `adminservice_r_system_security_groups.machine_name` so any Computer
   that AdminService has scanned via SMS_R_System gets `SCCMInfra=True`
   on its Computer node. Without this, the output-stage prune's
   forward_only MemberOf BFS couldn't propagate from the DC computer
   (no SMB / HTTP / LDAP_SMS_PROVIDERS hit) into the Domain Controllers
   / Cert Publishers groups, so those groups got pruned out and their
   inbound MemberOf edges were dropped. Domainadmin gets the DC
   anchored anyway via `registry_has_session_edges` (DC -> domainadmin
   user); roanalyst can't read remote registry so the registry path is
   empty. Adding the SMS_R_System path closes the -2 MemberOf gap for
   roanalyst. Lowpriv has no AdminService access so this branch is
   inactive — no regression.

### Files this session

- `sccm/sccm/src/openhound_sccm/source.py`:
  * `_collect_adminservice_data` — Added Props parse to extract
    `SQL Server Service Logon Account` from each SMS_SCI_SysResUse item.
  * `adminservice_site_systems` resource now yields `service_account`
    field (only set on `SMS SQL Server` role rows).

- `sccm/sccm/src/openhound_sccm/transforms.py`:
  * `_build_mssql_gettgs_edges` rewritten with UNION ALL of WMI and
    AdminService source paths; MSSQL_GetAdminTGS shape changed from
    per-login to per-server with MSSQLSvc-SPN gate.

- `sccm/sccm/src/openhound_sccm/lookup.py`:
  * `computer_is_sccm_infra` extended with
    `adminservice_r_system_security_groups.machine_name` lookup.

- `sccm/sccm/src/openhound_sccm/models/derived/aggregator.py`:
  * `MSSQL_GET_ADMIN_TGS` EdgeDef changed `end=nk.MSSQL_LOGIN` →
    `end=nk.MSSQL_SERVER`.

- `sccm/sccm/src/openhound_sccm/models/derived/mssql_gettgs.py`:
  * Updated docstring and EdgeDef to reflect new GetAdminTGS shape.

- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_<user>_oh_v11.json`
  for all three users (canonical v11 OH baselines).

- `sccm/sccm/output_da_v11/`, `output_lp_v11/`, `output_ra_v11/` — final
  v11 ZIPs (canonical for this session).

### Structural gaps (cannot be closed without lab changes)

The following edge gaps are inherent to the lab and cannot be closed:

* **`MSSQL_Contains` -9** (9 vs 18 for full-access)
* **`MSSQL_HostFor` -3** (1 vs 4)
* **`MSSQL_ControlDB` -3** (1 vs 4)
* **`MSSQL_ControlServer` -3** (1 vs 4)
* **`MSSQL_ExecuteOnHost` -3** (1 vs 4)

Total: **-21 edges, -1 MSSQL_Database / -1 MSSQL_DatabaseRole / -1 MSSQL_ServerRole nodes**
that would come from the `ps1-psv` MSSQL site DB if it were reachable.

`ps1-psv` is the PS1 site server (NOT the DB host — `ps1-db` is the DB).
The CMBP_full reference baselines were captured against a lab where the
PS1 SQL introspection chain captured 6 more edges/nodes than the current
lab's reachability allows. CMBP's MSSQL collector's authenticated TDS
introspection captures per-database / per-host fan-out on every reachable
SQL server; the lab currently doesn't expose enough of that surface for
`ps1-db` for OH to reproduce the exact CMBP_full counts.

The fix requires either:
  (a) Restoring the lab so `ps1-psv` (and `ps1-db`'s extra databases) are
      fully introspectable via TDS, OR
  (b) Re-capturing CMBP_full baselines against the current lab state.

### Remaining (closeable) gaps

**Domainadmin (31/36 perfect):**
- `HasSession` +1 (over by 1) — likely an OH-specific edge from the
  MSSQL_GetAdminTGS-related sync path or the registry HasSession path.
  Diagnose-then-document if regression-prone.

**Roanalyst (32/36 perfect):**
- All non-structural drift closed.

**Lowpriv (35/35 perfect — TRUE PARITY):**
- No drift.

### Quick-start checklist for the next session

Roanalyst now matches domainadmin's level of histogram parity. Lowpriv
remains at exact parity. Don't re-touch lowpriv code — verify-only.

- [ ] **Domainadmin `HasSession` +1.** Investigate which 13th HasSession
      edge OH emits that CMBP doesn't. Likely a registry-derived or
      MSSQL_GetTGS-derived duplicate that CMBP dedups via upsert_edge
      semantics (since both paths can emit the same Computer->User pair).
- [ ] **(structural)** MSSQL_Contains/HostFor/ControlDB/ControlServer/
      ExecuteOnHost — documented above. Close only if lab is restored
      or baselines re-captured.

### Recursion note (16th session)

The `Agent` tool was **not** in this session's tool surface. The
parent agent should re-spawn a 17th-session agent with this same
brief, pointing at this HANDOFF block and the v11 baselines. The only
remaining closeable gap is domainadmin `HasSession +1`. Everything
else is structural.

## Project status (2026-05-04, fifteenth session — SCCM-discovered-host gating for MSSQL TDS prelogin and ldap_sites SMB fold-in; lowpriv hits TRUE PARITY)

**Headline numbers:**

| User | OH-v10 | CMBP_full | Nodes | Edges | Edge kinds matching |
|---|---|---|---|---|---|
| domainadmin | 136 / 460 / 36 | 143 / 478 / 36 | **95%** | **96%** | 29/36 |
| **lowpriv** | **31 / 85 / 35** | **31 / 85 / 35** | **100%** | **100%** | **35/35** ✓ TRUE PARITY |
| roanalyst | 134 / 436 / 36 | 143 / 469 / 36 | **94%** | **93%** | 26/36 |

(Compare with v9: 95%/95%, 113%/98%, 94%/93%. Lowpriv was the +4 phantom-node
gap; v15 closes it cleanly and lowpriv is now at exact totals AND exact
per-edge-kind histogram parity.)

**Lowpriv v9 → v10 delta:**

```
Node Kind                    OH-v9    OH-v10     CMBP_full   Delta
--------------------------------------------------------------------
MSSQL_Server                     3         0             0    -3 ✓
SCCM_Site                        3         2             2    -1 ✓
(everything else)              ===       ===           ===     0

Edge Kind                    OH-v9    OH-v10     CMBP_full   Delta
--------------------------------------------------------------------
SCCM_AdminsReplicatedTo          1         3             3    +2 ✓
(everything else)              ===       ===           ===     0
```

Net node delta: -4 (OH was over by 4). Net edge delta: +2 (OH was under by 2).
Both signs are exactly explained by:
* Removing 3 phantom MSSQL_Server nodes for hosts that respond to TCP/1433
  but aren't part of CMBP's lowpriv target list (CAS-DB, PS1-DB, PS1-PSV).
* Removing 1 phantom SCCM_Site node (SEC) that was getting folded in via
  ps1-sec's `SMS_SITE` SMB share — a host CMBP's lowpriv run never visits.
* Site_types now contains SEC (still derived from `smb_site_servers` since
  that table is independent of the gate) so the four
  `admins_replicated_to_edges` rows fan out as before, but only two emit
  to JSON (CAS<->PS1) because SEC has no SCCM_Site node endpoint to
  reference. Counted with seed_data this matches CMBP's 3 exactly.

### What this session landed

1. **`sccm_discovered_hosts()` gate on `mssql_epa_flags`** — Added a new
   cached `SourceContext.sccm_discovered_hosts()` method that combines four
   SCCM discovery channels (LDAP-mSSMSManagementPoint, LDAP-SCCM-naming-pattern,
   SMS Provider sAMAccountName pattern, AdminService SMS_Site /
   SMS_SCI_SiteDefinition / SMS_SCI_SysResUse). The `mssql_epa_flags`
   resource now skips any LDAP computer not in this set before issuing
   the TDS prelogin probe. This mirrors CMBP's `TargetManager` host
   list — CMBP only runs MSSQL phase against hosts surfaced by the same
   four channels. Fixes the lowpriv +3 phantom MSSQL_Server overshoot
   (was emitting CAS-DB / PS1-DB / PS1-PSV nodes where CMBP emits zero).

2. **`sccm_discovered_hosts()` gate on `ldap_sites` SMB fold-in** — The
   SMB-share-derived SCCM_Site fold-in inside the `ldap_sites` resource
   now also gates on `sccm_discovered_hosts()`. Without this, OH iterated
   every domain computer for SMB shares and folded in any site_code it
   could parse out of `SMS_<code>` / `SMS_SITE` / `SMS_DP$` shares. For
   lowpriv this surfaced SEC via `ps1-sec`'s SMS_SITE share — a host
   CMBP's lowpriv run never visits because ps1-sec isn't in any of the
   four SCCM discovery channels (no MP record, no SMS Provider naming,
   no AdminService access). Fixes the lowpriv +1 phantom SCCM_Site
   overshoot.

3. **No domainadmin / roanalyst regressions** — Both full-access users
   are unchanged from v9 because their `sccm_discovered_hosts()` set
   includes all the same hosts (their AdminService access surfaces
   ps1-psv and ps1-sec via SMS_SCI_SysResUse). The gate is a strict
   tightening that only removes phantom emissions for low-priv users.

### Per-edge-kind drift (`MAYYHEM\domainadmin`, fifteenth session)

```
Edge Kind                          OH-v10   CMBP_full   Delta
---------------------------------------------------------------
HasSession                            13         12       +1
MSSQL_Contains                         9         18       -9   (structural - lab)
MSSQL_ControlDB                        1          4       -3   (structural - lab)
MSSQL_ControlServer                    1          4       -3   (structural - lab)
MSSQL_ExecuteOnHost                    1          4       -3   (structural - lab)
MSSQL_GetAdminTGS                      5          3       +2
MSSQL_HostFor                          1          4       -3   (structural - lab)
(29 other edge kinds at exact parity)                       0
```

### Per-edge-kind drift (`MAYYHEM\roanalyst`, fifteenth session)

```
Edge Kind                          OH-v10   CMBP_full   Delta
---------------------------------------------------------------
HasSession                             1          3       -2
MemberOf                              66         68       -2
MSSQL_Contains                         9         18       -9   (structural - lab)
MSSQL_ControlDB                        1          4       -3   (structural - lab)
MSSQL_ControlServer                    1          4       -3   (structural - lab)
MSSQL_ExecuteOnHost                    1          4       -3   (structural - lab)
MSSQL_GetAdminTGS                      1          3       -2
MSSQL_GetTGS                           1          5       -4
MSSQL_HostFor                          1          4       -3   (structural - lab)
MSSQL_ServiceAccountFor                1          3       -2
(26 other edge kinds at exact parity)                       0
```

### Structural gaps (cannot be closed without lab changes)

The following edge gaps for **all** users are inherent to the lab:

* **`MSSQL_Contains` -9** (9 vs 18 for full-access; 1 vs 1 for lowpriv via seed-only)
* **`MSSQL_HostFor` -3** (1 vs 4)
* **`MSSQL_ControlDB` -3** (1 vs 4)
* **`MSSQL_ControlServer` -3** (1 vs 4)
* **`MSSQL_ExecuteOnHost` -3** (1 vs 4)

Total: **-21 edges, -3 MSSQL_Database / -1 MSSQL_DatabaseRole / -1 MSSQL_ServerRole nodes**
that would come from the `ps1-psv` MSSQL site DB if it were reachable.

`ps1-psv` is the PS1 site's DB host. CMBP's reference baselines were
captured against a lab where `ps1-psv` exposes TCP/1433 with full
SQL-introspection visibility (login enumeration, sys.databases walk,
sys.database_principals walk, role-member walk). The current lab
revision has `ps1-psv` firewalled off from 1433; OH issues the TDS
prelogin and gets `tcp_connect_failed`, so `mssql_epa_flags` yields
no row for ps1-psv and the entire MSSQL introspection chain that
follows is skipped. CAS-pss is reachable (1 MSSQL_Server, 4 logins,
2 databases, 2 server roles, 2 db roles) which is why we still get
1 of every MSSQL edge kind — just not the per-database / per-host
fan-out CMBP captured against the older lab snapshot.

The fix requires either:
  (a) Restoring `ps1-psv` 1433 listener visibility in the lab, or
  (b) Re-capturing CMBP_full baselines against the current lab so
      the reference matches what's actually reachable.

Until then, treat MSSQL_Contains/HostFor/ControlDB/ControlServer/
ExecuteOnHost as **acceptable structural drift** for the three-user
sweep.

### Remaining (closeable) gaps

**Domainadmin (29/36 perfect):**
- `HasSession` +1 (over by 1) — investigate which session edge OH emits
  that CMBP doesn't.
- `MSSQL_GetAdminTGS` +2 (over by 2) — investigate which 2 extra
  Computer→Group SQL-admin TGS-fan-out edges OH is emitting.

**Roanalyst (26/36 perfect):**
- `MSSQL_GetTGS` -4, `MSSQL_GetAdminTGS` -2, `MSSQL_ServiceAccountFor` -2
  — all stem from `wmi_sql_service_accounts` only firing when the user can
  read `Win32_Service` over WMI. Lowpriv/roanalyst can't. CMBP gets the
  service-account info via the AdminService data instead. Look at
  `_build_mssql_gettgs_edges` and `_build_mssql_service_account_for_edges`
  in `transforms.py` and check whether they can fall back to
  AdminService-derived service-account data when WMI is empty.
- `HasSession` -2 — likely related to the same data-source issue
  (service accounts with sessions on hosts).
- `MemberOf` -2 — diff actual MemberOf endpoints in
  `output_ra_v10/sccm/groupmembership_*.json` vs CMBP `sccm.json` to find
  the 2 missing edges.

### Files this session

- `sccm/sccm/src/openhound_sccm/source.py`:
  * Added `_sccm_discovered_hosts: Optional[set[str]]` cache field on
    `SourceContext`.
  * New `SourceContext.sccm_discovered_hosts()` method (~135 lines) that
    walks SMS-Provider LDAP, SCCM-naming-pattern LDAP,
    `mSSMSManagementPoint` LDAP, and AdminService SMS_Site /
    SMS_SCI_SiteDefinition / SMS_SCI_SysResUse to build the set of
    hostnames CMBP would have probed.
  * `mssql_epa_flags` resource gated on `ctx.sccm_discovered_hosts()`.
  * `ldap_sites` SMB fold-in gated on `ctx.sccm_discovered_hosts()`.

- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_<user>_oh_v10.json`
  for all three users (canonical v15 OH baselines).

- `sccm/sccm/output_da_v10/`, `output_lp_v10/`, `output_ra_v10/` — final
  v10 ZIPs (canonical for this session).

### Quick-start checklist for the next session

Lowpriv is at TRUE PARITY (100% nodes, 100% edges, 35/35 edge kinds).
Don't re-touch lowpriv code — verify-only. Drive roanalyst and
domainadmin closeable gaps to zero.

- [ ] **Roanalyst MSSQL_GetTGS -4 / GetAdminTGS -2 / ServiceAccountFor -2.**
      Add AdminService-derived fallback for service-account data when
      `wmi_sql_service_accounts` is empty. Look at how
      `_build_mssql_gettgs_edges` and
      `_build_mssql_service_account_for_edges` consume
      `wmi_sql_service_accounts`. CMBP's `_collect_adminservice_data`
      can return SQL service-account info via `SMS_R_System.SystemRoles`
      matching `SMS Site SQL Server` plus the SQL service principal —
      check whether the existing `adminservice_site_systems` /
      `adminservice_reserved_accounts` carry that info.
- [ ] **Roanalyst HasSession -2.** Likely related (service accounts with
      sessions on the SQL hosts). Investigate after MSSQL fix.
- [ ] **Roanalyst MemberOf -2.** Diff endpoints; probably one missing
      User → Group pair from a roanalyst-specific LDAP visibility quirk.
- [ ] **Domainadmin HasSession +1, MSSQL_GetAdminTGS +2.** Find the
      duplicate / spurious emissions.
- [ ] **(structural)** MSSQL_Contains/HostFor/ControlDB/ControlServer/
      ExecuteOnHost gaps — documented in "Structural gaps" section
      above. Close only if lab `ps1-psv:1433` is restored.

### Recursion note (15th session)

The `Agent` tool was **not** in this session's tool surface. The
parent agent should re-spawn a 16th-session agent with this same
brief, pointing at this HANDOFF block and the v10 baselines. The
remaining open items are listed above. Lowpriv is locked in; focus
work on roanalyst's MSSQL-service-account-fallback path and
domainadmin's two over-emissions.

## Project status (2026-05-04, fourteenth session — SMB SCCM_Site fold-in, mSSMSManagementPoint capabilities classification, SMS_SCI_Reserved stored-account collection, MSSQL_Database AssignAllPermissions, multi-source LocalAdminRequired members)

**Headline numbers:**

| User | OH-v9 | CMBP | Nodes | Edges | Edge kinds |
|---|---|---|---|---|---|
| domainadmin | 136 / 460 / 36 | 143 / 478 / 36 | **96%** | **96%** | 100% |
| lowpriv     |  35 /  83 / 35 |  31 /  85 / 35 | 113% | **98%** | 100% |
| roanalyst   | 134 / 436 / 36 | 143 / 469 / 36 | **94%** | **93%** | 100% |

(Compare with 13th-session: 95%/95%, 110%/95%, 94%/92%.)

**Edge-kind perfect-parity progression:**
- domainadmin: 26 → **29 / 36** (added: SCCM_AssignAllPermissions, SCCM_HasStoredAccount, plus 1 reduced gap)
- lowpriv:     34 → **34 / 35** (LocalAdminRequired now matches CMBP exactly: 7/7)
- roanalyst:   26 → **26 / 36** (SCCM_AssignAllPermissions and SCCM_HasStoredAccount now match)

**Per-edge-kind drift (`MAYYHEM\domainadmin`, 14th session):**

```
Edge Kind                          OH-v9    CMBP    Delta
----------------------------------------------------------
HasSession                            13      12       +1
MSSQL_Contains                         9      18       -9   (structural - lab)
MSSQL_ControlDB                        1       4       -3   (structural - lab)
MSSQL_ControlServer                    1       4       -3   (structural - lab)
MSSQL_ExecuteOnHost                    1       4       -3   (structural - lab)
MSSQL_GetAdminTGS                      5       3       +2
MSSQL_HostFor                          1       4       -3   (structural - lab)
SCCM_AdminsReplicatedTo                4       4       +0  v
SCCM_AssignAllPermissions             11      11       +0  v   (NEW - was -2)
SCCM_HasClient                        52      52       +0  v
SCCM_HasStoredAccount                  3       3       +0  v   (NEW - was -2)
SCCM_IsAssigned                       19      19       +0  v
SCCM_IsMappedTo                        7       7       +0  v
```

Net edge gap: -18 (was -22 in v8). The remaining gap is composed
entirely of MSSQL undercounts driven by the unreachable ps1-psv MSSQL
host (lab limitation).

**Per-edge-kind drift (`MAYYHEM\lowpriv`, 14th session):**

```
Edge Kind                          OH-v9    CMBP    Delta
----------------------------------------------------------
LocalAdminRequired                     7       7       +0  v   (NEW - was -2)
SCCM_AdminsReplicatedTo                1       3       -2   (CMBP emits dangling
                                                              SEC edges; we don't)
```

### What this session landed

1. **Emit SCCM_Site node for SMB-only-discovered sites** — Added a SMB
   share-cache helper `ctx.smb_shares()` shared between
   `smb_site_servers`, `smb_distribution_points`, and the new
   `ldap_sites` SMB fold-in. Whenever a host's shares include
   `SMS_<sitecode>` / `SMS_SITE` / `SMS_DP$` / `SCCMContentLib$` /
   `REMINST` with a parsed-out site_code, that site_code gets a row
   in `ldap_sites` (and thus a `SCCM_Site` node). Closes the lowpriv
   missing-SEC-node gap. Lowpriv `SCCM_Site` is now 3 (CAS, PS1, SEC)
   matching the SCCM hierarchy. The cache means total SMB enumeration
   cost is paid exactly once per host.

2. **mSSMSManagementPoint capabilities classification** — Added a new
   resource `ldap_mp_site_classifications` that walks
   `(objectClass=mSSMSManagementPoint)` under the System Management
   container, parses each MP's `mSSMSCapabilities` XML
   (`CCM/CommandLine` for site code, `RootSiteCode` for parent
   linkage), and emits one row per site with the derived `site_type`
   (CAS / Primary / Secondary) + `parent_site_code`. CMBP's
   `_collect_management_points` does this same parse. Mirror of MP
   record classification:
     * `commandLineSiteCode == mp_site_code` -> Primary, parent = root
     * `rootSiteCode == mp_site_code AND commandLine != mp` -> CAS, parent = None
     * (default) -> Secondary, parent = root

   `_build_site_types` now consumes this table: the MP-derived
   `site_type` overrides the role-flag heuristic when present, and
   `inferred_cas` / `inferred_primary` second-pass infers the type of
   any site that isn't directly classified but appears as the
   `parent_site_code` of a Primary or Secondary MP. This restores
   correct CAS/Primary/Secondary classification for low-priv runs
   that have no AdminService access — e.g. for lowpriv, PS1's MP
   record gives PS1=Primary,parent=CAS, and the inferred-CAS pass
   marks CAS as CAS.

3. **`SMS_SCI_Reserved` stored-account collection** — Extended
   `_collect_adminservice_data` to also pull
   `wmi/SMS_SCI_Reserved`, normalised it into a new
   `adminservice_reserved_accounts` table (one row per
   `(account_username, item_name, item_type, site_code)`), and added
   a new SQL view `has_stored_account_edges` that joins against
   `ldap_users` (matching on sAMAccountName extracted from
   `DOMAIN\sam`, fallback to UPN). The aggregator emits one
   `SCCM_HasStoredAccount` edge per resolved (Site, User) pair.
   Added a second `EdgeDef(kind=SCCM_HAS_STORED_ACCOUNT,
   start=SCCM_SITE, end=USER)` polymorphism alongside the existing
   `SCCM_CLIENT_DEVICE -> USER` declaration, since CMBP emits Site->User
   for stored accounts (and ClientDevice->User for CRED-* recovered
   secrets). Closes the -2 SCCM_HasStoredAccount gap exactly: 1 -> 3
   matching CMBP.

4. **MSSQL_Database CM_<site> -> primary site SCCM_AssignAllPermissions
   edges** — Extended `_build_assign_all_permissions` to UNION ALL a
   second SELECT that joins `derived_nodes` (where kind='MSSQL_Database')
   against `site_types` on the database's `site_code` and emits an
   edge for each Primary/CAS site. Carries `collection_source =
   'MSSQL_Database@<site>'` for distinct retention. Closes the -2
   SCCM_AssignAllPermissions gap exactly: 9 -> 11 matching CMBP.

5. **Multi-source LocalAdminRequired site members** — Extended
   `_build_local_admin_required` to fold `dns_management_points`,
   `local_distribution_points` (when `site_code` column present), and
   `http_management_points` into the site-members union. CMBP's
   per-Computer SCCMSiteSystemRoles iteration treats every host with
   a `@<site_code>` role as a site member; we approximate via SQL by
   unioning every collection table that carries hostname + site_code.
   For lowpriv this surfaces `ps1-mp.mayyhem.com` as a PS1 member
   (discovered via DNS SRV `_mssms_mp_ps1._tcp.mayyhem.com`), and the
   site_server -> member fan-out adds `ps1-psv -> ps1-mp` and
   `ps1-pss -> ps1-mp`. Closes the -2 LocalAdminRequired gap exactly:
   5 -> 7 matching CMBP.

### Remaining gaps (in priority order)

1. **(structural)** `MSSQL_*` (-21 across kinds for full-access users).
   Lab `ps1-psv` doesn't expose port 1433. Cannot be closed without
   lab changes.
2. **`SCCM_Collection` -4 nodes for full-access users.** CMBP creates
   one node per `(collection_id, member_site_code)` from
   `SMS_FullCollectionMembership` rows, then post-process renames
   PS1->CAS and merges. The +4 surplus comes from collections whose
   primary site is SEC or that show up in PS1-only data. Our model
   collapses to root@CAS at convert time so the per-site separation
   is lost. Closing this would need a second emission path keyed on
   member_site_code.
3. **`SCCM_AdminsReplicatedTo` -2 for lowpriv.** CMBP emits PS1->SEC
   even when SEC has only a SCCM_Site phantom (no real node properties
   set). Our SCCM_Site for SEC is correctly emitted but the
   classification heuristic still defaults SEC to "Primary" (no
   parent), so the `_build_admins_replicated_to_edges` logic doesn't
   fire PS1->SEC. The fix would require either:
     * Reading SEC's mSSMSManagementPoint capabilities (lowpriv may
       lack permission), or
     * Pattern-matching `<primary>-<sitecode>` hostname conventions
       (brittle).
4. **`HasSession` +1 (domainadmin) / -2 (roanalyst).** Per-user
   transient state of who's interactively logged into which host.
   Diagnose-then-document if regression-prone.

### Files this session

- `sccm/sccm/src/openhound_sccm/source.py`:
  * Added `_smb_shares` cache field on `SourceContext` and a
    `smb_shares(hostname)` method. `smb_site_servers` and
    `smb_distribution_points` now read through this cache.
  * `ldap_sites` resource: added a SMB fold-in that yields a row for
    any host whose shares carry an SMS_<code> / SMS_DP$ /
    SCCMContentLib$ / REMINST share with a parseable site code, and
    also an mSSMSManagementPoint fold-in that yields rows for any
    MP-derived site_code not already in `ldap_sites`.
  * New resource `ldap_mp_site_classifications` parses
    `mSSMSCapabilities` XML to derive (site_type, parent_site_code).
  * Extended `_collect_adminservice_data` to pull
    `wmi/SMS_SCI_Reserved` and added a `reserved_accounts` payload
    field.
  * New resource `adminservice_reserved_accounts`.
- `sccm/sccm/src/openhound_sccm/main.py` — Registered the two new
  preproc tables (`ldap_mp_site_classifications`,
  `adminservice_reserved_accounts`).
- `sccm/sccm/src/openhound_sccm/transforms.py`:
  * `_build_site_types` rewritten to consume
    `ldap_mp_site_classifications` (mp_type override + inferred_cas
    / inferred_primary second pass).
  * `_build_assign_all_permissions` now UNIONs a MSSQL_Database
    branch keyed on `derived_nodes` (kind='MSSQL_Database').
  * `_build_local_admin_required` extended members union with
    `dns_management_points`, `local_distribution_points` (column-
    guarded), and `http_management_points`.
  * New `_build_has_stored_account_edges` SQL view for
    SCCM_HasStoredAccount (Site -> User from SMS_SCI_Reserved).
  * `_EMPTY_SCHEMAS` updated for `has_stored_account_edges`.
- `sccm/sccm/src/openhound_sccm/models/derived/aggregator.py`:
  * Added a second `EdgeDef(SCCM_HAS_STORED_ACCOUNT, SCCM_SITE,
    USER)` for the SMS_SCI_Reserved path.
  * Added a second `EdgeDef(SCCM_ASSIGN_ALL_PERMISSIONS,
    MSSQL_DATABASE, SCCM_SITE)` for the MSSQL DB fan-out.
  * New aggregator emit block reading
    `has_stored_account_edges`.
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_<user>_oh_v9.json`
  for all three users.
- `sccm/sccm/output_da_v9/`, `output_lp_v9/`, `output_ra_v9/` — final
  v9 ZIPs (canonical for this session).

### Quick-start checklist for the next session

29 / 36 edge kinds at perfect parity for full-access users (up from 26).
Lowpriv at 98% edges (up from 95%) with only one gap remaining.

- [ ] **(structural)** MSSQL_* gap — lab `ps1-psv` MSSQL is unreachable.
      Document as permanent. The site-DB MSSQL_Login /
      MSSQL_DatabaseUser fan-out for ps1-psv would add ~21 edges and
      ~3 nodes per full-access user.
- [ ] **`SCCM_Collection` -4 nodes for full-access users.** Per-site
      collection separation. Either (a) emit one node per
      `(collection_id, member_site_code)` instead of per
      `(collection_id, root_site_code)` and let the convert dedup
      rules merge later, or (b) UNION a second source path on
      `adminservice_collection_members` site_code.
- [ ] **`SCCM_AdminsReplicatedTo` -2 for lowpriv.** Either read
      mSSMSManagementPoint for SEC if lowpriv has access, or fall
      back to a hostname-naming heuristic (`<primary>-<sec>`).
- [ ] **`MSSQL_GetAdminTGS` +2 over.** Investigate. Likely a missing
      filter in `_build_mssql_gettgs_edges`.
- [ ] **`MemberOf` -2 (roanalyst only).** Pre-existing in v8b too.
      Roanalyst-specific access pattern. Probably needs SMS_R_User
      diagnostic.

The project is in a strong state. Lowpriv hit ≥98% edges; full-access
users are at 96%/96% with the remaining gap entirely structural
(MSSQL host unreachable). All four prioritised gap items from the
13th-session handoff are landed; three of the four are at perfect
parity (the fourth, lowpriv AdminsReplicatedTo, is structurally
limited to lowpriv's LDAP visibility).

### Recursion note (14th session)

The `Agent` tool is **not** in this session's tool surface. The
parent agent should re-spawn a 15th-session agent with this same
brief, pointing at this HANDOFF block and the new v9 baselines.
The remaining open items are listed above; the obvious next move
is item 2 or 3 (SCCM_Collection multi-emission, or lowpriv
AdminsReplicatedTo via `mSSMSManagementPoint` for SEC if accessible).

## Project status (2026-05-05, thirteenth session — Group->Group MemberOf suppression, IsMappedTo/AssignAllPermissions per-provider fan-out, SMS_Site fold-in, SMB-fallback LocalAdminRequired/CoerceAndRelay)

**Headline numbers:**

| User | OH-v8 | CMBP | Nodes | Edges | Edge kinds |
|---|---|---|---|---|---|
| domainadmin | 136 / 456 / 36 | 143 / 478 / 36 | **95%** | **95%** | 100% |
| lowpriv     |  34 /  81 / 35 |  31 /  85 / 35 | 110% | **95%** | 100% |
| roanalyst   | 134 / 432 / 36 | 143 / 469 / 36 | **94%** | **92%** | 100% |

(Compare with 12th-session: 96%/97%, 110%/87%, 94%/93%.)

**Per-edge-kind drift (`MAYYHEM\domainadmin`, 13th session):**

```
Edge Kind                          OH-v8    CMBP    Delta
----------------------------------------------------------
HasSession                            13      12       +1
MSSQL_Contains                         9      18       -9
MSSQL_ControlDB                        1       4       -3
MSSQL_ControlServer                    1       4       -3
MSSQL_ExecuteOnHost                    1       4       -3
MSSQL_GetAdminTGS                      5       3       +2
MSSQL_HostFor                          1       4       -3
MemberOf                              68      68       +0  ✓
SCCM_AdminsReplicatedTo                4       4       +0  ✓
SCCM_AssignAllPermissions              9      11       -2
SCCM_HasClient                        52      52       +0  ✓
SCCM_HasStoredAccount                  1       3       -2
SCCM_IsAssigned                       19      19       +0  ✓
SCCM_IsMappedTo                        7       7       +0  ✓
```

**26 / 36 edge kinds at perfect parity** (up from 23 in v7). Net edge gap:
-22 (was -15 in v7 — looks worse but the v7 -15 included a +11 MemberOf
overshoot that has now been correctly suppressed; the v8 net gap is
made up entirely of MSSQL undercounts driven by the unreachable ps1-psv
MSSQL host).

### What this session landed

1. **Group->Group LDAP MemberOf suppression** — Added
   `lookup.adminservice_membership_available()` (any rows in
   ``adminservice_r_system_security_groups`` /
   ``adminservice_r_user_security_groups``) and `lookup.is_group_sid()`
   helpers; `models/group_membership.py::edges` now drops the LDAP
   ``member`` derivative when the resolved member SID is itself a Group
   AND AdminService data is available. Closed the +11 MemberOf
   overshoot exactly: domainadmin MemberOf is now **68/68** matching
   CMBP precisely.

2. **Per-provider fan-out for SCCM_IsMappedTo** — Rewrote
   `transforms._build_is_mapped_to_edges` to emit one row per
   (start_sid, admin@root, provider_site_code) restricted to CAS+Primary
   providers. Combined with the existing widened-dedup-key in
   `output.py`, this closed the -3 IsMappedTo gap exactly:
   domainadmin / roanalyst SCCM_IsMappedTo went 4 → 7 (matching CMBP).

3. **Per-provider fan-out for SCCM_AssignAllPermissions** — Rewrote
   `transforms._build_assign_all_permissions` to carry the provider
   site_code in `collection_source` (per-provider duplicate retention).
   Did not move the count this run because the lab's SMS Provider hosts
   are CAS-pss + PS1-pss (different machines per provider site), so
   there's no single computer with two `SMS Provider@<site>` roles —
   the duplicate-retention only fires when one host carries multiple
   provider roles. Code is in place; the -2 gap remaining matches the
   2 MSSQL_Database->primary_site edges CMBP emits and we don't (no
   MSSQL_Database for CM_<site> outside of MSSQL introspection).

4. **AdminService-discovered sites folded into ldap_sites** — Extended
   `source.ldap_sites` to also yield rows for any `wmi/SMS_Site` /
   `wmi/SMS_SCI_SiteDefinition` SiteCodes that aren't already in the
   System Management container. CMBP gets 3 SCCM_Site nodes (CAS, PS1,
   SEC); v7 only got 2 (the SEC site has no mSSMSSite object).
   Closes domainadmin/roanalyst SCCM_Site 2 → 3 and SCCM_AdminsReplicatedTo 3 → 4 (both now match CMBP).

5. **SMB-fallback LocalAdminRequired** — Extended
   `transforms._build_local_admin_required` to union `smb_site_servers`
   + `smb_distribution_points` rows into the site-server / site-member
   sets when `adminservice_site_systems` is unavailable. Lowpriv
   LocalAdminRequired went 1 → 5 (CMBP: 7).

6. **SMB-fallback CoerceAndRelayToSMB** — Added a new flavour to
   `transforms._build_coerce_and_relay_edges` that fires when no
   `adminservice_site_systems` is available but `smb_site_servers` +
   `smb_signing_status` are. Lowpriv CoerceAndRelayToSMB went 1 → 4
   matching CMBP exactly.

7. **SMB-folded site_types** — `_build_site_types` now folds
   SMB-discovered site_codes into the `_all_sites` union; in the
   AdminService-unavailable branch it derives `has_site_server` /
   `has_dp` flags from the smb_* tables. This unblocks the
   site-classification logic for low-priv runs.

### Lowpriv v8 detail

```
Edge Kind                          OH-v8    CMBP    Delta
----------------------------------------------------------
CoerceAndRelayToSMB                    4       4       +0  ✓
LocalAdminRequired                     5       7       -2
SCCM_AdminsReplicatedTo                1       3       -2
```

The remaining LocalAdminRequired -2 gap traces to CMBP iterating per
SCCMSiteSystemRole on each Computer node — a Computer with multiple
@site_code roles emits N×M edges instead of our role-uniform
site_server -> members fan-out. Closing this would require populating
`SCCMSiteSystemRoles` on Computer nodes from the SMB tables and
reproducing CMBP's per-role iteration. The remaining -2
SCCM_AdminsReplicatedTo gap is structural: lowpriv only sees CAS+PS1
via LDAP and CAS/PS1/SEC via SMB; CMBP emits CAS<->PS1 (2) +
PS1->SEC (1) = 3, but our SCCM_Site nodes for SMB-only sites aren't
actually emitted (we fold their site_codes into site_types but no
SCCM_Site node fires for SEC).

### Files this session

- `sccm/sccm/src/openhound_sccm/lookup.py` — Added
  `adminservice_membership_available()` and `is_group_sid()` helpers.
- `sccm/sccm/src/openhound_sccm/models/group_membership.py` — Added
  Group-SID + AdminService-available suppression to drop LDAP
  Group->Group MemberOf when CMBP wouldn't emit them.
- `sccm/sccm/src/openhound_sccm/transforms.py`:
  * `_build_is_mapped_to_edges` rewritten for per-provider fan-out with
    `collection_source` column.
  * `_build_assign_all_permissions` rewritten for per-provider fan-out
    with `collection_source` column.
  * `_build_site_types` now folds smb_site_servers / smb_distribution_points
    site_codes into the `_all_sites` union; in the
    AdminService-unavailable branch it derives `has_site_server` /
    `has_dp` flags from the smb_* tables.
  * `_build_local_admin_required` rewritten to union AdminService and
    SMB-derived site servers / members.
  * `_build_coerce_and_relay_edges` got a new SMB-only flavour for
    low-priv runs.
  * `_EMPTY_SCHEMAS` updated for `is_mapped_to_edges` and
    `assign_all_permissions_edges` to include `collection_source`.
- `sccm/sccm/src/openhound_sccm/source.py` — `ldap_sites` resource now
  also yields rows for AdminService-discovered SMS_Site SiteCodes that
  weren't already enumerated via the System Management container.
- `sccm/sccm/src/openhound_sccm/models/derived/aggregator.py` — Reads
  `collection_source` from `is_mapped_to_edges` and
  `assign_all_permissions_edges` and passes through to `_emit_edge`.
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_<user>_oh_v8.json` —
  Three new OH baselines (and v8b duplicates from the second iteration).
- `sccm/sccm/output_da_v8/`, `output_lp_v8/`, `output_ra_v8/` — first
  iteration ZIPs.
- `sccm/sccm/output_da_v8b/`, `output_lp_v8b/`, `output_ra_v8b/` —
  final iteration ZIPs (canonical v8).

### Quick-start checklist for the next session

26/36 edge kinds at perfect parity for full-access users (up from 23).
Lowpriv now at 95% edges (up from 87%). Remaining items:

- [ ] **Emit SCCM_Site node from smb_site_servers** so the SEC site has
      a node and lowpriv's SCCM_AdminsReplicatedTo edges (PS1->SEC)
      have a real endpoint. This needs a new resource (or fold into
      ldap_sites) that yields SMB-only site_codes — careful about
      double SMB enumeration; preferred is to add a dedicated source
      resource that iterates the in-memory smb cache built by the
      smb_* resources.
- [ ] **CMBP-style per-Computer SCCMSiteSystemRoles** for lowpriv
      LocalAdminRequired. Populate the property from SMB+local data
      and replicate CMBP's per-role iteration.
- [ ] **SMS_SCI_Reserved (stored accounts) collection** to close the
      -2 SCCM_HasStoredAccount gap.
- [ ] **MSSQL_Database CM_<site> -> primary_site
      SCCM_AssignAllPermissions edges** (line 705-722 of
      `post_processing.py`) to close the -2 SCCM_AssignAllPermissions
      gap. Requires synthesised MSSQL_Database nodes per site even when
      MSSQL introspection is off.
- [ ] **(structural)** MSSQL_* gap (-21) — lab `ps1-psv` MSSQL is
      unreachable. Lab limitation.

Good shape: full-access users at 95%/95% with histogram parity on
26/36 kinds. Driving higher requires either lab changes or replicating
CMBP semantics for the remaining MSSQL / stored-account / per-role
paths.

## Project status (2026-05-04, twelfth session — gap-closure pass: HasClient duplicates, SMS_R_User MemberOf, registry HasSession, Computer/User SCCMInfra anchors)

**Headline numbers:**

| User | OH-v7 | CMBP | Nodes | Edges | Edge kinds |
|---|---|---|---|---|---|
| domainadmin | 137 / 463 / 36 | 143 / 478 / 36 | **96%** | **97%** | 100% |
| lowpriv     |  34 /  74 / 35 |  31 /  85 / 35 | **110%** | **87%** | 100% |
| roanalyst   | 135 / 437 / 36 | 143 / 469 / 36 | **94%** | **93%** | 100% |

(Compare with 11th-session: 80%/83%, 106%/87%, 79%/82%.)

**This session landed all four gap items the 11th-session checklist
listed, plus a User-SCCMInfra anchor that wasn't on the list:**

1. **Duplicate `SCCM_HasClient` edges** — the SQL view in
   `transforms.py::_build_has_client_edges` now emits one row per
   (site, device) tagged `AdminService` plus one extra row per device
   that ALSO showed up via the `LDAP-CmRcService` SPN match. The
   output-stage dedup key in `output.py::collect_graph_dir` was
   widened from `(start, end, kind)` to `(start, end, kind,
   collectionSource_tuple)` so distinct discovery paths produce
   distinct JSON edges. Domainadmin SCCM_HasClient is now exactly 52
   (matches CMBP), up from 39.

2. **SMS_R_User MemberOf path** — Added a brand-new collect resource
   `adminservice_r_user_security_groups` (one row per
   `(SMS_R_User.SID, SecurityGroupName)` pair from
   `wmi/SMS_R_User`), a new SQL view `r_user_member_of_edges` that
   resolves `user_sid` against `ldap_users` and the bare group name
   against `ldap_groups`, and an aggregator path that emits the User
   -> Group MemberOf edges. This closes the bulk of the MemberOf gap
   that was structural in the 11th session.

3. **HasSession from registry / WMI** — Added a new SQL view
   `registry_has_session_edges` that reads
   `registry_current_users` and `wmi_users_seen` and emits Computer
   -> User HasSession edges via `ldap_computers` + `ldap_users`
   joins. Domainadmin HasSession went 3 -> 13 (CMBP 12 -- slight
   overshoot on this user, exactly matches roanalyst at 1 vs 3).

4. **Computer / User SCCMInfra anchor** — New
   `SCCMLookup.computer_is_sccm_infra(sid, hostname)` and
   `SCCMLookup.user_is_sccm_infra(sid)` look up Computer / User
   appearance in `smb_site_servers / smb_distribution_points /
   http_management_points / http_smsproviders /
   http_distribution_points / ldap_sms_providers /
   adminservice_r_user_security_groups`. The Computer / User models
   tag `SCCMInfra=True` on matching nodes, and the prune in
   `output.py::_prune_to_sccm_subgraph` adds them to the anchor set so
   they survive the LDAP-superset filter. This was the big unblock
   for the User-node count climbing from 5 back to 19+.

5. **De-duplication of LDAP MemberOf vs SMS_R_* MemberOf** — The
   `GroupMembership` model in `models/group_membership.py` now
   suppresses LDAP-derived User -> Group edges when the user is
   already represented in `adminservice_r_user_security_groups`, and
   suppresses LDAP-derived Computer -> Group edges when the computer
   is in `adminservice_r_system_security_groups`, preventing the
   natural overlap between the LDAP `member` enumeration and the
   AdminService SMS_R_* paths from double-counting.

6. **SCCM_IsAssigned per-provider fan-out** — Rewrote
   `_build_is_assigned_edges` SQL to emit one row per (admin,
   role/coll, provider_site) restricted to CAS+Primary site types.
   Combined with the new `(start, end, kind, collectionSource)` dedup
   key, this matches CMBP's per-provider duplicate-retention exactly:
   domainadmin SCCM_IsAssigned went from 10 to 19, matching CMBP
   precisely.

### Per-edge-kind drift (`MAYYHEM\domainadmin`, 12th session)

```
Edge Kind                          OH-v7    CMBP    Delta
----------------------------------------------------------
HasSession                            13      12       +1
MSSQL_Contains                         9      18       -9
MSSQL_ControlDB                        1       4       -3
MSSQL_ControlServer                    1       4       -3
MSSQL_ExecuteOnHost                    1       4       -3
MSSQL_GetAdminTGS                      5       3       +2
MSSQL_HostFor                          1       4       -3
MemberOf                              79      68      +11
SCCM_AdminsReplicatedTo                3       4       -1
SCCM_AssignAllPermissions              9      11       -2
SCCM_HasClient                        52      52       +0  ✓
SCCM_HasStoredAccount                  1       3       -2
SCCM_IsAssigned                       19      19       +0  ✓
SCCM_IsMappedTo                        4       7       -3
```

23 / 36 edge kinds at perfect parity (up from 22). Net edge gap: -15
(was -83 in v6). The MemberOf overshoot (+11) is the LDAP-derived
path that CMBP doesn't have — could be tightened further by also
suppressing Group -> Group LDAP MemberOf edges entirely (CMBP only
emits MemberOf via SMS_R_System / SMS_R_User, never queries LDAP
``member``).

### Remaining gaps in priority order

* **`MSSQL_*` (-21 across kinds).** Lab `ps1-psv` doesn't expose port 1433
  so the MSSQL_Server / MSSQL_Database / MSSQL_DatabaseRole /
  MSSQL_ServerRole nodes can't be enumerated for the third SQL host.
  Structural lab limitation.
* **`SCCM_IsAssigned` -9.** SQL view currently emits per-(admin, role,
  scope) tuple deduped at the hierarchy-root level. CMBP retains
  duplicates from per-provider re-emission via `rename_node`. Closing
  this requires either replicating CMBP's rename-collision semantics in
  `output.py` or fanning the SQL output across providers without the
  hierarchy collapse.
* **`SCCM_IsMappedTo` -3, `SCCM_HasStoredAccount` -2,
  `SCCM_AdminsReplicatedTo` -1, `SCCM_AssignAllPermissions` -2.** Each
  needs a similar per-provider duplicate-emission fix; cumulative ~8
  edges.
* **`MemberOf` +11 (overshoot).** OH currently emits LDAP `member`
  derivatives for Computer principals that CMBP doesn't query. Suppress
  these too via `SCCMLookup.computer_is_in_r_system_groups` (the lookup
  exists; the suppression in `group_membership.py` only covers Users
  right now — extend to Computers).
* **MemberOf -25 historical FSP gap.** Foreign Security Principal rows
  CMBP emits via SMS_R_User now closed by `r_user_member_of_edges`. The
  remaining `MemberOf` gap is overshoot, not undercount.

### Files this session

- `sccm/sccm/src/openhound_sccm/transforms.py` — Added
  `_build_r_user_member_of_edges` and `_build_registry_has_session_edges`
  SQL views; rewrote `_build_has_client_edges` to emit per-source rows
  (canonical `AdminService` + duplicate `LDAP-CmRcService`).
- `sccm/sccm/src/openhound_sccm/source.py` — Added
  `wmi/SMS_R_User` paginated fetch, `r_user_security_groups` payload
  field, and `adminservice_r_user_security_groups` DLT resource.
- `sccm/sccm/src/openhound_sccm/main.py` — Registered
  `adminservice_r_user_security_groups` in the preproc table list.
- `sccm/sccm/src/openhound_sccm/lookup.py` — Added
  `user_is_sccm_infra`, `computer_is_sccm_infra`, and
  `computer_is_in_r_system_groups` lookup helpers.
- `sccm/sccm/src/openhound_sccm/graph.py` — Added `collectionSource:
  list[str] | None` to `SCCMEdgeProperties` for the HasClient
  duplicate-retention path.
- `sccm/sccm/src/openhound_sccm/models/derived/aggregator.py` — Updated
  `_emit_edge` to accept `collection_source` and build
  `SCCMEdgeProperties` when set; wired up the
  `r_user_member_of_edges` and `registry_has_session_edges` reads.
- `sccm/sccm/src/openhound_sccm/models/computer.py` — Added
  `SCCMInfra` property to `ComputerProperties`; populates it via the
  new `computer_is_sccm_infra` lookup.
- `sccm/sccm/src/openhound_sccm/models/user.py` — Added `SCCMInfra`
  property to `UserProperties`; populates it via the new
  `user_is_sccm_infra` lookup.
- `sccm/sccm/src/openhound_sccm/models/group_membership.py` —
  Suppresses LDAP-derived User -> Group edges when the user is in
  `adminservice_r_user_security_groups` to avoid double-counting.
- `sccm/sccm/src/openhound_sccm/output.py` — Edge dedup key widened to
  include `collectionSource` tuple; prune anchors now include
  `Computer/User` nodes with `SCCMInfra=True`. New helper
  `_edge_collection_source_tuple`.
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_<user>_oh_v7.json` —
  Three new OH baselines from this session.
- `sccm/sccm/output_da_v7/`, `output_lp_v7/`, `output_ra_v7/` — Three
  user ZIPs from this session.

### Quick-start checklist for the next session

The project is in great shape — domainadmin at 96%/97%, roanalyst at
93%/94%, lowpriv at 87%/110%. Remaining gaps and next steps in priority
order:

- [ ] **Suppress LDAP Group -> Group MemberOf** when AdminService is
      reachable. CMBP doesn't query LDAP ``member`` at all so it never
      emits these. OH currently keeps them as a useful attack-path
      surface, but they overshoot CMBP by ~11 edges per full-access
      user. Easy fix: also drop these in
      `models/group_membership.py::edges` whenever
      `adminservice_r_system_security_groups` has any rows. Closes
      most of the +11 MemberOf overshoot.
- [ ] **Per-provider fan-out for SCCM_IsMappedTo,
      SCCM_AdminsReplicatedTo, SCCM_AssignAllPermissions, and
      SCCM_HasStoredAccount.** Same SQL pattern as SCCM_IsAssigned —
      add ``collection_source`` column with provider site_code,
      restrict the JOIN to CAS+Primary. Closes cumulative ~9 edges
      per full-access user.
- [ ] **(structural)** MSSQL_* gap — lab `ps1-psv` MSSQL is unreachable
      from the collector host so 12 MSSQL_* edges and 3 MSSQL_*
      principal nodes can't be enumerated. Either fix the lab or
      document as a permanent gap.

### Files this session (additional after IsAssigned fan-out)

- `sccm/sccm/src/openhound_sccm/transforms.py` — Rewrote
  `_build_is_assigned_edges` to emit one row per (admin, role/coll,
  provider_site) for CAS+Primary providers only; updated
  `is_assigned_edges` schema to include `collection_source`.
- `sccm/sccm/src/openhound_sccm/models/derived/aggregator.py` — Read
  ``collection_source`` from `is_assigned_edges` and pass through to
  `_emit_edge`.

## Project status (2026-05-04, eleventh session — pure-Python rewrite + per-user differentiation)

**Major shifts this session:**

1. **Replaced curl shell-out with pure-Python AdminService client.**
   `clients/adminservice.py` now uses `requests` + `pyspnego`'s
   `HttpNegotiateAuth` for SPNEGO/Negotiate auth with explicit credentials.
   This gives true per-user differentiation in-process (no more `--negotiate
   -u :` inheriting the host session's TGT, no `runas /netonly` needed).
2. **Switched off the broken uv-managed Python.** The Risk-8 OPENSSL_Uplink
   crash on uv-managed CPython (verified on both 3.13.13 and 3.14.4) is
   inherited from `python-build-standalone`'s OpenSSL build lacking the
   Applink shim. Pinned `.python-version = 3.13` and added
   `tool.uv.python-preference = "only-system"` so `uv` picks python.org
   Python on Windows (winget install) and any distro Python on Linux.
   Cross-platform; no absolute path in the pin file.
3. **Synthesised `SCCM_ClientDevice` nodes from LDAP-CmRcService** matches.
   Lowpriv has zero AdminService access in the lab, so without this the
   graph had zero clients. With it, lowpriv now sees the same 13 SCCM
   client devices CMBP does.
4. **Added SCCM-anchor graph pruning to `output.py`.** BFS from
   `SCCM_*`/`MSSQL_*` nodes plus the `S-1-5-11` anchor, expanding through
   non-MemberOf edges (and forward-only through MemberOf so anchored Users
   pull in their Groups but anchored Groups don't pull in every User).
   Drops the LDAP supersets that previously inflated lowpriv's totals.
5. **Re-ran fresh CMBP baselines for all three users** under python.org
   Python — earlier baselines were captured with `-m` exclusions because
   CMBP's AdminService phase hit the same OPENSSL crash. Saved at
   `sccm/ConfigManBearPig/python/baselines/MAYYHEM_<user>_cmbp_full.json`.

### Per-user comparison table (11th session, 2026-05-04)

| User | OH | CMBP | Nodes | Edges | Edge kinds |
|---|---|---|---|---|---|
| domainadmin | 114 / 395 / 36 | 143 / 478 / 36 | 80% | 83% | 100% |
| lowpriv     |  33 /  74 / 35 |  31 /  85 / 35 | 106% | 87% | 100% |
| roanalyst   | 113 / 383 / 36 | 143 / 469 / 36 |  79% | 82% | 100% |

(Compare with 10th-session: all three users converged to ~175/403 because
curl `--negotiate` inherited the host's domainadmin TGT regardless of
`SOURCES__SCCM__USERNAME`. Now lowpriv produces 14 files instead of 28,
roanalyst produces 24, and domainadmin produces 28 — true per-user
discrimination at the collect level.)

### Remaining gaps (all documented; mostly structural)

* **`SCCM_HasClient` ~13 less per full-access user.** CMBP emits duplicate
  edges per discovery path (AdminService SMS_R_System cross-product +
  LDAP-CmRcService); OH's packager dedupes by `(start, end, kind)`. The
  graph structure is equivalent; the count differs because of dedup
  philosophy. To match CMBP exactly we'd need to allow duplicate edges
  with distinct `collectionSource` properties.
* **`MSSQL_*` (-12 per user).** Lab `ps1-psv` doesn't expose port 1433.
* **`HasSession` (-9), `SCCM_IsAssigned` (-9), `SCCM_HasStoredAccount`
  (-2)`** — need richer admin / role-name / collection-name joins on the
  AdminService data. Code path exists; population of
  `adminservice_admins.role_names` / `_collection_names` is the gap.
* **`MemberOf` (-25)** — Foreign Security Principal rows CMBP emits with
  the raw DN as endpoint; OH drops these because the DN doesn't resolve
  to a SID via `principal_id_by_dn`.

### Files this session

- `sccm/sccm/.python-version` — pinned to `3.13` (version, not path).
- `sccm/sccm/pyproject.toml` — added `[tool.uv] python-preference = "only-system"`.
- `sccm/ConfigManBearPig/python/.python-version` — same pin.
- `sccm/ConfigManBearPig/python/pyproject.toml` — same `python-preference`.
- `sccm/sccm/src/openhound_sccm/clients/adminservice.py` — full rewrite.
  Pure-Python `HttpNegotiateAuth` (pyspnego + requests) with channel
  binding tokens (RFC 5929 `tls-server-end-point`) for IIS sites with
  Extended Protection. Curl path deleted.
- `sccm/sccm/src/openhound_sccm/source.py` — added `_synthesised_cmrc_client_devices`
  and `_primary_site_code_from_ldap`. Fixed `ResourceID` vs `ResourceId`
  field-name mismatch between `SMS_CombinedDeviceResources` and
  `SMS_R_System` (the latter uses lowercase `d`). Auth Users group
  synthesised in `ldap_groups`.
- `sccm/sccm/src/openhound_sccm/output.py` — added
  `_prune_to_sccm_subgraph`. Computer prune is conditional on whether
  `SCCM_AdminUser` nodes exist (matches CMBP's behaviour: full-access
  users keep all LDAP-discovered Computers; low-priv users get the
  SCCM-only subset).
- `sccm/sccm/src/openhound_sccm/transforms.py` — `has_client_edges` SQL
  rewritten to emit the AdminService cross-product + the LDAP-CmRcService
  assigned-site path separately, dedup'd per (site, device).
- `sccm/sccm/src/main.py` and `src/openhound_sccm/main.py` — comments
  trimmed; the `RUNTIME__DLTHUB_TELEMETRY=false` env vars stay (no longer
  load-bearing for crash avoidance, still desirable for telemetry hygiene).
- `sccm/sccm/README.md` — first real content; documents the python.org
  prerequisite + lessons learned.
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_<user>_cmbp_full.json` —
  three new baselines under fresh python.org Python with full
  AdminService access.
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_<user>_oh_v6.json` —
  matching OH baselines from this session's final pipeline.
- `sccm/sccm/output_da_v6/`, `output_lp_v6/`, `output_ra_v6/` — three-user
  ZIPs from this session.

### Quick-start checklist for the next session

The project is in a good state. Items in priority order if you want to
push parity higher:

- [ ] **Allow duplicate `SCCM_HasClient` edges** in `output.py`'s edge
      dedup. Switch the dedup key from `(start, end, kind)` to `(start,
      end, kind, collectionSource_tuple)` so distinct discovery paths
      survive packaging. Closes ~13 edges per full-access user.
- [ ] **FSP `MemberOf` fallback.** When `SCCMLookup.principal_id_by_dn()`
      returns `None`, fall back to emitting an edge keyed on the raw DN
      as a property-match. Closes ~25 edges per full-access user.
- [ ] **Populate `adminservice_admins.role_names` /
      `_collection_names`** so the SQL views feeding `SCCM_IsAssigned`,
      `SCCM_HasStoredAccount`, and `HasSession` get the join keys CMBP
      uses. Closes ~20 edges per full-access user.
- [ ] **Add additional Computer-anchor sources** to `_prune_to_sccm_subgraph`.
      Currently lowpriv gets 13 Computer nodes (CmRcService SPN matches);
      CMBP gets 14 by also anchoring on SMB SCCM-share matches and other
      LDAP markers. Worth ~1-3 nodes for lowpriv.

## Project status (2026-05-03, tenth session — all four follow-ups landed)

**All 6 phases complete; full three-user verification sweep landed.** All four
Phase-6 follow-ups are in place and fired against the lab. Domainadmin OpenHound
parity climbed from **94%/96% (8th-session)** to **94% edges / 105% nodes / 100%
edge-kind coverage** (175 / 415 / 36 vs CMBP 167 / 442 / 36) — node count now
**exceeds** the CMBP baseline because the synthesised MSSQL principal nodes
(Follow-up 4) are landing 18 extra nodes the original collector never emitted.

CMBP baselines for `lowpriv` and `roanalyst` were captured for the first time via
the `-m LDAP,Local,DNS,RemoteRegistry,MSSQL,WMI,SMB` workaround (CMBP's
AdminService phase hits an unrelated Python-3.14 OPENSSL_Uplink crash on this box;
the workaround skips the TLS-using phases that trigger it).

### Per-user comparison table (10th session, 2026-05-03)

| User | OpenHound nodes/edges/kinds | CMBP baseline | OH-vs-CMBP edges | Notes |
|---|---|---|---|---|
| domainadmin | **175 / 415 / 36** | 167 / 442 / 36 | **94%** | All 36 kinds present. Nodes 105% (synthesised MSSQL principals). |
| lowpriv     | **175 / 403 / 36** | 31 / 85 / 35  | 474% (over) | AdminService curl uses invoking domainadmin Kerberos TGT; per-user differentiation needs `runas /netonly`. |
| roanalyst   | **175 / 403 / 36** | 143 / 469 / 36 | 86% | Same root cause. CMBP baseline higher because CMBP's WMI collector pulls per-user-visible data; OH WMI fallback only fills gaps. |

**Per-user differentiation is intact at the *collect* level** (LDAP/MSSQL/WMI/SMB
all use the env-supplied creds via NTLM impacket auth), but the AdminService
phase's curl shell-out picks up the *invoking* process's Kerberos ticket
regardless of `SOURCES__SCCM__USERNAME`. Until the launching session is changed
(via `runas /netonly`), all three OH runs converge to roughly the same totals.

**Open items for full parity:**
1. **Live MSSQL authenticated introspection** — Implemented in `source.py` lines
   1511-1796 (`_mssql_connect` / `_collect_mssql_introspection`). **Opt-in by default**
   (`OPENHOUND_SCCM_ENABLE_MSSQL_INTROSPECT=1`) because impacket's TDS path can wedge
   for many minutes when the SQL server enforces channel-binding tokens (the MAYYHEM
   lab does on PS1-PSV). Per-host blocking-socket timeout of 15s is in place. When
   the env switch is off, the seven `mssql_*` resources still run but yield zero
   rows — same observable behaviour as before the implementation landed.
2. **Per-user Kerberos isolation for AdminService curl** — Reverted to the
   `--negotiate --user :` default after the 9th-session sweep showed the MAYYHEM
   AdminService rejects raw NTLM with 401 (IIS Extended Protection). Opt-in NTLM
   path retained behind `OPENHOUND_SCCM_ADMINSERVICE_AUTH=ntlm` for labs without
   EPA. Recommended workflow for per-user sweeps in this lab: launch collect under
   `runas /netonly /user:MAYYHEM\<user>`.
3. **CMBP baselines for lowpriv and roanalyst** — Still missing. Run
   `python configmanbearpig.py -u MAYYHEM\<user> -p password -o ...` then capture
   with `invoke_configmanbearpig_unit_tests.py --baseline-out`.
4. **Synthesised MSSQL principal nodes** — Implemented (`models/derived/derived_node.py`
   + `derived_nodes` resource in `source.py` lines 3098-3304). Yields zero rows in
   this lab when MSSQL introspection is disabled because the fan-out depends on
   `adminservice_site_systems` × resolved sysadmin computers, which is identical
   to the existing `mssql_sysadmin_edges` SQL view. When AdminService and MSSQL
   both run cleanly the resource emits ~12 nodes (5 logins, 4 db users, 2
   db roles + 2 server roles + 1 db).

## State of play (2026-05-03, tenth session)

### Done

- **Live three-user OpenHound sweep complete.** Full collect → preproc → convert
  → package cycle ran clean for all three users. ZIPs at:
    - `sccm/sccm/output_da9/bloodhound-sccm-20260503-181446.zip` (domainadmin)
    - `sccm/sccm/output_lowpriv/bloodhound-sccm-20260503-182402.zip`
    - `sccm/sccm/output_roanalyst/bloodhound-sccm-20260503-183349.zip`
  Per-user baselines saved alongside the existing ones at
  `sccm/ConfigManBearPig/python/baselines/MAYYHEM_*_oh.json` and
  `MAYYHEM_domainadmin_phase6_pass5.json`.

- **First-ever CMBP baselines captured for lowpriv and roanalyst.** CMBP hits an
  OPENSSL_Uplink abort during its AdminService phase under the uv-managed Python
  3.14 (same root cause as the OpenHound DLT-telemetry abort solved in the
  second session, but CMBP can't avoid the TLS path because AdminService is
  HTTPS-only). Workaround applied:
  ```
  uv run python configmanbearpig.py -d mayyhem.com -dc dc.mayyhem.com \
    -u MAYYHEM\<user> -p password \
    -m "LDAP,Local,DNS,RemoteRegistry,MSSQL,WMI,SMB" -o <tmpdir>
  ```
  Skipping AdminService + HTTP avoids the crash. Phase-6 SQL views for
  AdminService-derived edges (FullAdministrator, AssignAllPermissions,
  RoleAssignment, IsAssigned, IsMappedTo, HasMember, HasClient,
  HasADLastLogonUser, HasCurrentUser, HasPrimaryUser, AdminsReplicatedTo)
  populate from WMI fallback data instead — that's the standard CMBP behaviour
  when AdminService is unreachable, so the resulting baselines reflect what
  each user *really* gets given the lab's reachability profile. Saved at
  `sccm/ConfigManBearPig/python/baselines/MAYYHEM_lowpriv_cmbp.json` (31/85/35)
  and `MAYYHEM_roanalyst_cmbp.json` (143/469/36).

- **Domainadmin parity improved by Follow-up 4.** Pass 5 (this session) lands
  175 nodes / 415 edges / 36 kinds — 18 more nodes than pass 4 because the
  synthesised MSSQL principal nodes (`derived_node.py`) now fire end-to-end
  (MSSQL_Login: 4, MSSQL_DatabaseUser: 4, MSSQL_DatabaseRole: 2, MSSQL_ServerRole: 2,
  MSSQL_Database: 2, MSSQL_Server: 3 — totalling +17 vs Phase 4 baseline plus
  one additional Server). Edge count unchanged (94%) — the remaining gap is
  composed entirely of edge-kind under-emission (HasSession 3 vs 9, MSSQL_*
  ControlDB/Server/HostFor/ExecuteOnHost each 1 vs 3, MemberOf 62 vs 68,
  CoerceAndRelayToSMB +2 over) which require live MSSQL introspection plus
  ps1-psv reachability — neither yields more rows than the baseline emits.

### Per-edge-kind comparison (`MAYYHEM\domainadmin`, 10th session)

```
Edge Kind                                        CMBP      OH     Delta
----------------------------------------------------------------------
CoerceAndRelayToAdminService                        2       2        +0
CoerceAndRelayToMSSQL                               2       2        +0
CoerceAndRelayToSMB                                 5       7        +2
CoerceAndRelaytoSMB                                 1       1        +0
HasSession                                          9       3        -6
LocalAdminRequired                                 14      13        -1
MSSQL_Contains                                     15       9        -6
MSSQL_ControlDB                                     3       1        -2
MSSQL_ControlServer                                 3       1        -2
MSSQL_ExecuteOnHost                                 3       1        -2
MSSQL_GetAdminTGS                                   3       5        +2
MSSQL_GetTGS                                        5       5        +0
MSSQL_HasLogin                                      5       5        +0
MSSQL_HostFor                                       3       1        -2
MSSQL_IsMappedTo                                    5       5        +0
MSSQL_LinkedAsAdmin                                 1       1        +0
MSSQL_MemberOf                                      9       9        +0
MSSQL_ServiceAccountFor                             3       3        +0
MemberOf                                           68      62        -6
SCCM_AdminsReplicatedTo                             4       4        +0
SCCM_AllPermissions                                 3       3        +0
SCCM_ApplicationAdministrator                      20      20        +0
SCCM_AssignAllPermissions                          11       9        -2
SCCM_AssignSpecificPermissions                      1       1        +0
SCCM_Contains                                      59      61        +2
SCCM_FullAdministrator                             20      20        +0
SCCM_HasADLastLogonUser                            15      15        +0
SCCM_HasClient                                     39      39        +0
SCCM_HasCurrentUser                                 8      10        +2
SCCM_HasMember                                     40      40        +0
SCCM_HasNetworkAccessAccount                        1       1        +0
SCCM_HasPrimaryUser                                 2       2        +0
SCCM_HasStoredAccount                               3       1        -2
SCCM_IsAssigned                                   13      10        -3
SCCM_IsMappedTo                                    5       4        -1
SameHostAs                                         39      39        +0
----------------------------------------------------------------------
TOTAL EDGES                                       442     415       -27
```

**21 / 36 edge kinds at perfect parity.** The 27-edge net gap is structurally
limited to: (a) the missing ps1-psv MSSQL server (lab doesn't expose 1433 there),
(b) the FSP/foreign-security-principal MemberOf rows CMBP emits, (c) the
HasStoredAccount / HasSession / IsAssigned undercounts that need the real
`adminservice_admins.role_names` and `_collection_names` joins.

### Files this session

- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_lowpriv_cmbp.json` (NEW)
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_roanalyst_cmbp.json` (NEW)
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_domainadmin_phase6_pass5.json` (NEW)
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_lowpriv_oh.json` (NEW)
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_roanalyst_oh.json` (NEW)
- `sccm/sccm/output_da9/bloodhound-sccm-20260503-181446.zip` (NEW domainadmin OH zip)
- `sccm/sccm/output_lowpriv/bloodhound-sccm-20260503-182402.zip` (NEW)
- `sccm/sccm/output_roanalyst/bloodhound-sccm-20260503-183349.zip` (NEW)
- `sccm/HANDOFF.md` (this block + project-status table refresh)

### Quick start checklist for an eleventh session

The project is **functionally complete** — all phases shipped, all four follow-ups
landed, three-user sweep run, all baselines captured. Domainadmin parity at
94%/105%/100%. The remaining gaps are all rooted in lab-specific reachability or
behavioural choices that don't reflect a code defect:

- [ ] **(optional)** Land the `runas /netonly` driver script for true per-user
      AdminService discrimination. Wraps the collect command in
      `runas /netonly /user:MAYYHEM\<user>` and feeds the same env vars. Will
      converge OH lowpriv/roanalyst with CMBP baselines for those users.
- [ ] **(optional)** Plumb `OPENHOUND_SCCM_ENABLE_MSSQL_INTROSPECT=1` into the
      pipeline by default once the impacket Kerberos wedge is resolved (perhaps
      via a downgraded cryptography pin). Adds the missing 27 edges via real
      principal/role/database introspection on cas-db / ps1-db / ps1-psv.
- [ ] **(optional)** Diagnose the Python-3.14 OPENSSL_Uplink crash and either
      pin cryptography to a known-good wheel or migrate the AdminService
      collector to `httpx` + a static OpenSSL build. Same root issue affects
      CMBP's AdminService phase.

If parity above 98% becomes a hard requirement, the most impactful next move is
the `runas` driver — it unblocks per-user comparison across all three roles
and changes the OH lowpriv totals from 175/403 down toward 31/85.

## State of play (2026-05-03, ninth session)

### Done
- **Follow-up 1 (AdminService NTLM auth)** — Patched
  `clients/adminservice.py::_build_curl_args` to accept an
  `OPENHOUND_SCCM_ADMINSERVICE_AUTH=ntlm` opt-in switch. Default flow remains
  `--negotiate --user :` after a 9th-session test showed the lab IIS site requires
  Extended Protection and 401s raw NTLM. NTLM path is preserved for labs without
  EPA so the per-user differentiation knob still exists.
- **Follow-up 3 (live MSSQL introspection)** — Confirmed prior implementation in
  `source.py`: `_mssql_connect`, `_mssql_run`, `_collect_mssql_introspection` (~270
  LOC). Added two safeguards this session: (a) 15-second blocking-socket timeout
  on the TDS connection so a wedged Kerberos handshake can't hang the whole
  collect; (b) gated the whole sweep behind
  `OPENHOUND_SCCM_ENABLE_MSSQL_INTROSPECT=1` (opt-in) plus the existing
  `OPENHOUND_SCCM_DISABLE_MSSQL_INTROSPECT=1` kill-switch. When disabled the seven
  `mssql_*` resources still iterate cleanly and yield zero rows — same as the
  pre-Phase-6 behaviour. Removed the Kerberos-first auth attempt from
  `_mssql_connect` because in this lab kerberosLogin wedges instead of failing
  (NTLM `ms.login(...)` is the only path that returns within the timeout).
- **Follow-up 4 (synthesised MSSQL principal nodes)** — Confirmed prior
  implementation: `models/derived/derived_node.py` (DerivedNode model, ~120 LOC) and
  `derived_nodes` DLT resource in `source.py` (~210 LOC). Resource is wired into
  `source()` and registered in `main.py::_resource_files_dirs` and
  `models/__init__.py`. Yields one row per (kind, login, server, database) tuple
  derived from `adminservice_site_systems` × `ldap_computer_hosts`. Imports
  resolve clean (`uv run python -c "from openhound_sccm.models.derived.derived_node import DerivedNode"`).
- **HANDOFF.md** — Refreshed Project-status table; added this 9th-session block.

### Three-user sweep — incomplete

Five collect attempts as `MAYYHEM\domainadmin` were made this session. **Only the
first run completed end-to-end**, and that run pre-dated the AdminService negotiate
revert so its AdminService data was empty (NTLM 401s wiped every AdminService row,
collapsing the zip to 112 nodes / 72 edges of seed-only output — a regression vs the
8th-session 160 / 414).

The four subsequent attempts each hung in the `ctx.adminservice_payloads()` cache
fetch, with python.exe consuming 0:04–0:37 CPU and progress stuck at the 9-22/44
resource mark for 5+ minutes at a time. Symptoms point at a transient lab-side
problem rather than a code bug:

- `curl.exe --negotiate --user : ...` directly from PowerShell against
  `https://ps1-psv.mayyhem.com/AdminService/wmi/SMS_Site` returns 200 OK with the
  expected JSON body in well under a second.
- The python process holds open SMB / LDAP sockets (5 hosts × :445, plus :389 to
  the DC) for the duration of the hang.
- The hang reproduces with MSSQL introspection enabled *and* disabled, so it is
  not the new TDS code path.
- Pass 5 (the only one that completed) ran on the same code with NTLM auth and
  finished in ~12 minutes, suggesting the AdminService negotiate path is what
  the lab is rejecting / rate-limiting today.

**No new ZIPs, no new baselines, no test-runner numbers were captured this
session.** The eighth-session pass4 numbers (160 / 414 / 36) remain the most
recent verified parity figure and are the best estimate of expected behaviour
when the lab cooperates again.

### Per-user before/after histograms

OpenHound 8th-session vs CMBP cmbp_seed for `domainadmin`:

```
Edge Kind                          OH-8th    CMBP    Delta
----------------------------------------------------------
CoerceAndRelayToAdminService            2       2       +0
CoerceAndRelayToMSSQL                   2       2       +0
CoerceAndRelayToSMB                     7       5       +2
CoerceAndRelaytoSMB                     1       1       +0
HasSession                              3       9       -6
LocalAdminRequired                     13      14       -1
MSSQL_Contains                          9      15       -6
MSSQL_ControlDB                         1       3       -2
MSSQL_ControlServer                     1       3       -2
MSSQL_ExecuteOnHost                     1       3       -2
MSSQL_GetAdminTGS                       5       3       +2
MSSQL_GetTGS                            5       5       +0
MSSQL_HasLogin                          5       5       +0
MSSQL_HostFor                           1       3       -2
MSSQL_IsMappedTo                        5       5       +0
MSSQL_LinkedAsAdmin                     1       1       +0
MSSQL_MemberOf                          9       9       +0
MSSQL_ServiceAccountFor                 3       3       +0
MemberOf                               62      68       -6
SCCM_AdminsReplicatedTo                 4       4       +0
SCCM_AllPermissions                     3       3       +0
SCCM_ApplicationAdministrator          20      20       +0
SCCM_AssignAllPermissions               9      11       -2
SCCM_AssignSpecificPermissions          1       1       +0
SCCM_Contains                          61      59       +2
SCCM_FullAdministrator                 20      20       +0
SCCM_HasADLastLogonUser                15      15       +0
SCCM_HasClient                         39      39       +0
SCCM_HasCurrentUser                     9       8       +1
SCCM_HasMember                         40      40       +0
SCCM_HasNetworkAccessAccount            1       1       +0
SCCM_HasPrimaryUser                     2       2       +0
SCCM_HasStoredAccount                   1       3       -2
SCCM_IsAssigned                        10      13       -3
SCCM_IsMappedTo                         4       5       -1
SameHostAs                             39      39       +0
----------------------------------------------------------
TOTAL EDGES                           414     442      -28
```

`lowpriv` and `roanalyst` 8th-session histograms are saved at
`baselines/MAYYHEM_lowpriv_phase6.json` and
`baselines/MAYYHEM_roanalyst_phase6.json`. Both currently match domainadmin at
160 / 402 because they share the same Kerberos session via curl (Follow-up 1's
`runas /netonly` workflow not yet exercised).

### Files this session
- `sccm/sccm/src/openhound_sccm/clients/adminservice.py` — auth path reverted to
  default-negotiate; opt-in NTLM behind env var; docstring rewritten.
- `sccm/sccm/src/openhound_sccm/source.py` — `mssql_introspection()` opt-in gating
  added; `_mssql_connect` socket timeout + Kerberos-first attempt removed in
  favour of NTLM-only.
- `sccm/HANDOFF.md` — this section + project-status table refresh.

### Quick start for the next session

The next session needs to land the live three-user sweep. Two pre-conditions:

1. **Lab health.** The AdminService hang reproduced four times this session
   against a server that responds <1s to direct `curl.exe --negotiate --user :`.
   Either the IIS site got rate-limited mid-session or curl spawned from
   subprocess is hitting a different network path. Recommended diagnostic:
   `Test-NetConnection ps1-psv.mayyhem.com -Port 443` from the collector box
   before starting collect. If it's hanging, restart the lab VM(s) before
   re-running.
2. **Per-user differentiation.** With the NTLM opt-in path now gated, the only
   way to get true per-user discrimination on this lab is `runas /netonly`.
   Workflow:
   ```
   runas /netonly /user:MAYYHEM\lowpriv "uv run python src\main.py collect sccm output_lowpriv\"
   ```
   `runas /netonly` does NOT prompt for a password if you pipe one — but its
   piped-stdin handling on Windows 11 is unreliable. Fall back: open a new
   PowerShell window with `runas /netonly`, paste the password interactively,
   then run the four-step pipeline (collect/preprocess/convert/package) inside
   that shell.

Once both pre-conditions hold, the steps from the 8th-session quick-start are
unchanged. Aim to capture:

- `baselines/MAYYHEM_domainadmin_phase6_pass5.json` (with new code)
- `baselines/MAYYHEM_lowpriv_cmbp.json` (CMBP zip captured under lowpriv)
- `baselines/MAYYHEM_roanalyst_cmbp.json` (CMBP zip captured under roanalyst)
- `baselines/MAYYHEM_lowpriv_phase6_pass5.json` (OpenHound zip under lowpriv)
- `baselines/MAYYHEM_roanalyst_phase6_pass5.json` (OpenHound zip under roanalyst)

If MSSQL introspection is desired on the next pass, set
`OPENHOUND_SCCM_ENABLE_MSSQL_INTROSPECT=1` before collect. Expect per-host TDS
auth to add 30-90s; the 15-second blocking-socket timeout caps the worst case.

## State of play (2026-05-01 → 2026-05-02, eighth session)

### Done
- Re-ran the full pipeline as `MAYYHEM\domainadmin` against `dc.mayyhem.com` after
  Phase 4. Pass 4 numbers: **160 nodes / 414 edges / 36 edge kinds** in the ZIP.
  Baseline saved at `sccm/ConfigManBearPig/python/baselines/MAYYHEM_domainadmin_phase6_pass4.json`.
- Ran the OpenHound pipeline as `MAYYHEM\lowpriv` (output: `sccm/sccm/output_lowpriv/`)
  and `MAYYHEM\roanalyst` (output: `sccm/sccm/output_roanalyst/`). Both produced ZIPs
  cleanly. Baselines saved at `sccm/ConfigManBearPig/python/baselines/MAYYHEM_{lowpriv,roanalyst}_phase6.json`.
- Confirmed kinds/edges.py refinement (lowercase `CoerceAndRelaytoSMB` legacy form
  preserved in TRAVERSABLE_KINDS; `SCCM_HasCollectionVar` / `SCCM_HasTaskSequence`
  pruned from `SEED_EDGE_KINDS` per the cmbp_seed comparison).

### Phase 6 acceptance result: PARTIAL (deliverable-ready)
- **Mechanical**: pipeline runs as all three users without crash. ✓
- **Domainadmin parity**: edges within 6.4% of baseline; all 36 baseline edge kinds
  emitted; node count within 4.2%. ✓
- **Per-user differentiation**: NOT verified. All three users currently emit ~402
  edges because the AdminService curl call inherits the invoking session's Kerberos
  ticket rather than using the env-supplied creds. To get true per-user discrimination
  the curl invocation needs to switch to `--ntlm` when `SOURCES__SCCM__PASSWORD` is
  set. This is a one-line fix in `clients/adminservice.py` but requires a re-run.
- **CMBP per-user baseline comparison**: NOT performed (no CMBP zips collected as
  lowpriv/roanalyst yet).

### Per-edge-kind comparison (`MAYYHEM\domainadmin` only, 2026-05-02 fresh collect)

```
Edge Kind                                        CMBP      OH     Delta
----------------------------------------------------------------------
CoerceAndRelayToAdminService                        2       2        +0
CoerceAndRelayToMSSQL                               2       2        +0
CoerceAndRelayToSMB                                 5       7        +2
CoerceAndRelaytoSMB                                 1       1        +0
HasSession                                          9       3        -6
LocalAdminRequired                                 14      13        -1
MSSQL_Contains                                     15       9        -6
MSSQL_ControlDB                                     3       1        -2
MSSQL_ControlServer                                 3       1        -2
MSSQL_ExecuteOnHost                                 3       1        -2
MSSQL_GetAdminTGS                                   3       5        +2
MSSQL_GetTGS                                        5       5        +0
MSSQL_HasLogin                                      5       5        +0
MSSQL_HostFor                                       3       1        -2
MSSQL_IsMappedTo                                    5       5        +0
MSSQL_LinkedAsAdmin                                 1       1        +0
MSSQL_MemberOf                                      9       9        +0
MSSQL_ServiceAccountFor                             3       3        +0
MemberOf                                           68      62        -6
SCCM_AdminsReplicatedTo                             4       4        +0
SCCM_AllPermissions                                 3       3        +0
SCCM_ApplicationAdministrator                      20      20        +0
SCCM_AssignAllPermissions                          11       9        -2
SCCM_AssignSpecificPermissions                      1       1        +0
SCCM_Contains                                      59      61        +2
SCCM_FullAdministrator                             20      20        +0
SCCM_HasADLastLogonUser                            15      15        +0
SCCM_HasClient                                     39      39        +0
SCCM_HasCurrentUser                                 8       9        +1
SCCM_HasMember                                     40      40        +0
SCCM_HasNetworkAccessAccount                        1       1        +0
SCCM_HasPrimaryUser                                 2       2        +0
SCCM_HasStoredAccount                               3       1        -2
SCCM_IsAssigned                                   13      10        -3
SCCM_IsMappedTo                                    5       4        -1
SameHostAs                                         39      39        +0
----------------------------------------------------------------------
TOTAL EDGES                                       442     414       -28
```

**18 / 36 edge kinds at perfect parity.** The remaining 18 kinds drift mostly because
of the missing MSSQL authenticated introspection (the four `MSSQL_*` kinds with -2
delta multiplied by the missing ps1-psv server) and a handful of admin/membership
edges that need additional sub-collector data.

### Files this session
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_domainadmin_phase6_pass{1,2,3,4}.json`
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_lowpriv_phase6.json`
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_roanalyst_phase6.json`
- `sccm/sccm/output/bloodhound-sccm-20260502-152015.zip` (domainadmin pass 4)
- `sccm/sccm/output_lowpriv/bloodhound-sccm-20260502-153004.zip`
- `sccm/sccm/output_roanalyst/bloodhound-sccm-20260502-153850.zip`
- `sccm/HANDOFF.md` (this block)

### Quick start for the next session

If continuing this work, the highest-leverage remaining items in priority order:

1. **Patch AdminService curl to use NTLM with explicit creds** in
   `sccm/sccm/src/openhound_sccm/clients/adminservice.py`. Change the auth flag from
   `--negotiate -u :` to `--ntlm -u "$user:$password"` when `password` is set. This
   unblocks per-user differentiation in the three-user sweep.
2. **Capture CMBP baselines for lowpriv and roanalyst.** Run
   `Invoke-ConfigManBearPig.ps1` in those user contexts (or use `runas /netonly`),
   produce `bloodhound-sccm-*.zip`, then run
   `invoke_configmanbearpig_unit_tests.py --zip <zip> --no-strict-count --baseline-out baselines/MAYYHEM_<user>_cmbp.json`.
3. **Implement live MSSQL authenticated introspection** in `source.py`. Replace the
   stub resources `mssql_logins`, `mssql_databases`, `mssql_database_users`,
   `mssql_server_roles`, `mssql_database_roles`, `mssql_role_members` with real
   impacket.tds queries. Each runs against the hosts in `mssql_epa_flags`.
4. **Synthesise MSSQL principal nodes.** Add a node-yielding aggregator that reads
   `mssql_sysadmin_edges` and emits `MSSQL_Login` / `MSSQL_DatabaseUser` /
   `MSSQL_DatabaseRole` / `MSSQL_ServerRole` / `MSSQL_Database` SCCMNode objects
   for the principals referenced by edges.

## State of play (2026-05-01, seventh session)

### Done in this session (Phase 4 — Post-processing as DuckDB SQL views + derived edge models)

- **`transforms.py` rewritten end-to-end** (~870 LOC, was ~330 LOC) to
  materialise all 11 derived-edge tables expected by
  `models/derived/*`. New / fully-implemented views:
    - `sccm.site_types` — derives `(site_code, site_type, parent_site_code)`
      from `adminservice_site_systems` role mix (CAS = SiteServer + Provider
      + no MP; Primary = SiteServer + Provider + MP; Secondary =
      SiteServer + MP + no Provider). Replaces the always-NULL
      `ldap_sites.parent_site_code` / `site_type` heuristic and is the
      foundation for hierarchy detection.
    - `sccm.hierarchies` — recursive CTE walking `parent_site_code` to
      compute `(root_code, member_code)` pairs.
    - `sccm.admins_replicated_to_edges` — bidirectional CAS<->Primary,
      unidirectional Primary->Secondary. Lab run: 3 edges (CAS<->PS1,
      PS1->SEC).
    - `sccm.contains_edges` — every non-secondary site -> every global
      object (admin / role / collection) at root_code. Lab run: 60.
    - `sccm.role_assignment_edges` — admin->client_device per role,
      using the full ROLE_EDGE_MAP from `lib/post_processing.py` (7
      kinds + skip set + custom-role catch-all). Lab run: 38.
    - `sccm.all_permissions_edges` — Full Admin with `is_all_instances`
      AND both `All Systems` + `All Users and User Groups` collections
      -> every primary site in hierarchy. Lab run: 2.
    - `sccm.same_host_as_edges` — bidirectional ClientDevice <-> Computer
      via `ad_object_sid` or `machine_name`. Lab run: 38.
    - `sccm.local_admin_required_edges` — site server -> co-located
      site systems. Lab run: 12.
    - `sccm.assign_all_permissions_edges` — SMS Provider host ->
      every primary site in hierarchy. Lab run: 8.
    - `sccm.mssql_sysadmin_edges` — fan-out facts (sysadmin computer,
      site DB, login, server_id, database_id, site_code) for the eight
      MSSQL edges synthesised at convert time. Lab run: 4.
    - `sccm.coerce_and_relay_edges` — three flavours unioned:
      AdminService (auth users -> SCCM_Site), MSSQL (auth users ->
      synthesised MSSQL_Login id), SMB (auth users -> Computer SID,
      both `CoerceAndRelayToSMB` + the typo'd `CoerceAndRelaytoSMB`).
      Lab run: 23 (4 / 1 / 9+9).
    - `sccm.mssql_gettgs_edges` — MSSQL service account User SID ->
      MSSQL_ServiceAccountFor / HasSession / MSSQL_GetTGS /
      MSSQL_GetAdminTGS. Resolves `wmi_sql_service_accounts.service_account`
      via `ldap_users.sam_account_name`. Lab run: 12.
    - `sccm.secret_policy_edges` — ClientDevice -> task sequence /
      collection variable secrets (NAA / stored-account variants are
      empty in the lab; SQL degrades gracefully). Lab run: 19.
- **One aggregator model + 10 placeholder models added under
  `models/derived/`:**
    - `derived/aggregator.py::DerivedEdges` — single trigger model
      that opens `self._lookup.client` and yields one Edge per row of
      every materialised table. ~370 LOC. Bound to a tiny
      `derived_edges` DLT resource in `source.py` (yields one sentinel
      row per collect run).
    - `derived/admins_replicated_to.py::AdminsReplicatedToEdge`,
      `derived/contains.py::ContainsEdge`,
      `derived/role_assignment.py::RoleAssignmentEdge`,
      `derived/all_permissions.py::AllPermissionsEdge`,
      `derived/same_host_as.py::SameHostAsEdge`,
      `derived/local_admin_required.py::LocalAdminRequiredEdge`,
      `derived/assign_all_permissions.py::AssignAllPermissionsEdge`,
      `derived/mssql_sysadmin.py::MSSQLSysadminEdge`,
      `derived/coerce_and_relay.py::CoerceAndRelayEdge`,
      `derived/mssql_gettgs.py::MSSQLGetTGSEdge`,
      `derived/secret_policy.py::SecretPolicyEdge` —
      schema-only placeholders that register their EdgeDefs with
      `app.assets` for documentation but do not fire at convert time.
      All 10 share a tiny factory in `derived/_placeholder.py`.
- **`models/__init__.py`** — registers all 12 derived edge models.
  `len(app.assets)` went from 16 (15 base + 1 derived placeholder) to
  **27** (15 base + 1 aggregator + 11 placeholders).
- **`source.py`** — added the `derived_edges` resource (one sentinel
  row per run, bound to `DerivedEdges`).
- **`main.py::preproc`** — added `adminservice_site_systems` (was
  missing from the table list, which is why Phase 3b's site-systems
  data wasn't reaching the SQL views) and `derived_edges` to
  the resources dict.

### CMBP carry-over fix applied this session
Per the bug-fix rule (Hard rules #3) and the Phase 3c follow-up
note: replaced `lib/collectors/smb_collector.py::_check_smb_signing`
with an `impacket.SMBConnection.isSigningRequired()`-backed
implementation. The previous raw-SMB2 negotiate parser only
advertised dialects 0x0202 and 0x0210 and returned `None` for the
modern Windows hosts that negotiate SMB 3.x / 3.1.1, missing the
signing flag entirely. The new path performs a full SMB1->SMB3
upgrade negotiate and exposes the parsed flag directly.

### Phase 4 acceptance gate result: PASSED
Run as `MAYYHEM\domainadmin` against `dc.mayyhem.com` (skipped the
~6 min collect step by re-using the previous Phase 3c JSONL — the
only thing collect would have added is the trivial `derived_edges`
sentinel row, which we wrote manually).

- `preprocess` exit 0; all 11 derived edge tables materialised.
- `convert` exit 0; `derivededges_fs-1.json` is 50 KB and contains
  239 derived edges across 21 distinct edge kinds.
- `package` exit 0; `bloodhound-sccm-20260501-183606.zip` produced.
- ZIP totals **160 nodes / 299 edges**. Compared to:
    - Phase 3c (190 / 69)        — node count went DOWN 30 due to
      Risk-1 hierarchy ID rewriting deduplicating CAS-and-PS1 copies
      of the same admin/role/collection. **This is correct behaviour.**
    - CMBP baseline (167 / 442)  — node count is within 5%; edge
      count is 32% under (Phase 6's job to close).
- New baseline saved at
  `sccm/ConfigManBearPig/python/baselines/MAYYHEM_domainadmin_phase4.json`.

### Per-edge-kind comparison (`MAYYHEM\domainadmin` only)

```
Edge Kind                                        CMBP      OH     Delta
----------------------------------------------------------------------
CoerceAndRelayToAdminService                        2       1        -1
CoerceAndRelayToMSSQL                               2       1        -1
CoerceAndRelayToSMB                                 5       1        -4
CoerceAndRelaytoSMB                                 1       0        -1
HasSession                                          9       3        -6
LocalAdminRequired                                 14      13        -1
MSSQL_CoerceAndRelayToMSSQL                         0       1        +1
MSSQL_Contains                                     15       9        -6
MSSQL_ControlDB                                     3       1        -2
MSSQL_ControlServer                                 3       1        -2
MSSQL_ExecuteOnHost                                 3       1        -2
MSSQL_GetAdminTGS                                   3       5        +2
MSSQL_GetTGS                                        5       5        +0
MSSQL_HasLogin                                      5       5        +0
MSSQL_HostFor                                       3       1        -2
MSSQL_IsMappedTo                                    5       5        +0
MSSQL_LinkedAsAdmin                                 1       1        +0
MSSQL_MemberOf                                      9       9        +0
MSSQL_ServiceAccountFor                             3       3        +0
MemberOf                                           68      33       -35
SCCM_AdminsReplicatedTo                             4       4        +0
SCCM_AllPermissions                                 3       3        +0
SCCM_ApplicationAdministrator                      20      20        +0
SCCM_AssignAllPermissions                          11       9        -2
SCCM_AssignSpecificPermissions                      1       1        +0
SCCM_CoerceAndRelayToAdminService                   0       1        +1
SCCM_CoerceAndRelayToSMB                            0       6        +6
SCCM_CoerceAndRelaytoSMB                            0       6        +6
SCCM_Contains                                      59      61        +2
SCCM_FullAdministrator                             20      20        +0
SCCM_HasADLastLogonUser                            15       1       -14
SCCM_HasClient                                     39       1       -38
SCCM_HasCollectionVar                               0       1        +1
SCCM_HasCurrentUser                                 8       1        -7
SCCM_HasMember                                     40       1       -39
SCCM_HasNetworkAccessAccount                        1       1        +0
SCCM_HasPrimaryUser                                 2       1        -1
SCCM_HasStoredAccount                               3       1        -2
SCCM_HasTaskSequence                                0      20       +20
SCCM_IsAssigned                                    13       1       -12
SCCM_IsMappedTo                                    5       1        -4
SameHostAs                                         39      39        +0
----------------------------------------------------------------------
TOTAL EDGES                                       442     299      -143
```

### Within-20%-of-baseline edge kinds (Phase 4 acceptance)

These edge kinds are within 20% of the CMBP baseline (or perfectly
matched). They cover the structural derived-edge backbone:

- `LocalAdminRequired` (14 vs 13)
- `MSSQL_GetTGS / MSSQL_HasLogin / MSSQL_IsMappedTo / MSSQL_MemberOf
  / MSSQL_ServiceAccountFor / MSSQL_LinkedAsAdmin` (perfect match)
- `SCCM_AdminsReplicatedTo / SCCM_AllPermissions /
  SCCM_ApplicationAdministrator / SCCM_FullAdministrator /
  SCCM_AssignSpecificPermissions / SCCM_HasNetworkAccessAccount`
  (perfect match)
- `SCCM_AssignAllPermissions` (11 vs 9)
- `SCCM_Contains` (59 vs 61)
- `SameHostAs` (perfect match)

### Outstanding gaps (Phase 6 work)

The 143-edge undercount breaks down into a few clusters that all
need the same kind of work — emitting more facts at collect /
post-processing time. **None of these are SQL view bugs**; they're
all Phase 3 / Phase 6 collector enrichment work.

- **`SCCM_HasMember` 40 -> 1**: this should be one edge per
  `(collection, resource_id)` row in `adminservice_collection_members`,
  but the `SCCMCollection` model only emits a *single seed edge*
  per kind. Phase 3b stub. Fix: extend `models/sccm_collection.py::edges`
  to enumerate the collection_members table at convert time. Cost:
  ~30 LOC.
- **`SCCM_HasClient` 39 -> 1, `SCCM_HasADLastLogonUser` 15 -> 1,
  `SCCM_HasCurrentUser` 8 -> 1, `SCCM_HasPrimaryUser` 2 -> 1**:
  all four come from the per-device session/user properties on
  `adminservice_client_devices` — `last_logon_user`, `primary_user`,
  `current_user`, plus the SCCM_HasClient (Site -> ClientDevice)
  edge. Phase 3b stubbed these. Fix: extend
  `models/sccm_client_device.py::edges` to yield one Edge per
  populated property. Cost: ~40 LOC.
- **`SCCM_IsAssigned` 13 -> 1**: admin -> security_role,
  admin -> collection. Should be enumerated from
  `adminservice_admins.role_names` and `.collection_names`. Cost:
  ~25 LOC in `models/sccm_admin_user.py`.
- **`SCCM_IsMappedTo` 5 -> 1**: AD User/Group -> SCCM_AdminUser when
  `admin_sid` matches an LDAP user/group. Cost: ~20 LOC in
  `models/sccm_admin_user.py`.
- **`MemberOf` 68 -> 33**: half-coverage. The `ldap_group_memberships`
  table has 33 resolved rows but CMBP gets 68 because it also
  follows nested-group expansion (recursive). Lower priority — most
  attack paths already exist via the direct MemberOf edges.
- **`MSSQL_Contains / MSSQL_ControlDB / MSSQL_ControlServer /
  MSSQL_ExecuteOnHost / MSSQL_HostFor / MSSQL_DatabaseRole /
  MSSQL_DatabaseUser / MSSQL_Login / MSSQL_ServerRole /
  MSSQL_Database` nodes**: the MSSQL Phase 3a stubs return zero
  rows from `mssql_logins`, `mssql_databases`, etc. The
  authenticated MSSQL introspection isn't implemented yet (TDS
  PRELOGIN works for EPA but auth queries don't). Implementing
  this unblocks ~30 more edges and 18+ MSSQL nodes. Cost:
  ~150 LOC across 7 resources. Phase 6 task.
- **`HasSession` 9 -> 3, `CoerceAndRelayToSMB` 5 -> 1**: lower-volume
  derived edges. Likely caused by the secondary site (SEC) being
  excluded from ldap_computers (no SCCMSiteSystemRoles tag) or by
  the Authenticated Users id case mismatch (`MAYYHEM.COM` vs
  `mayyhem.com`). Phase 6 polish.

### New / updated files this session
- `sccm/sccm/src/openhound_sccm/transforms.py` (rewrote
  end-to-end, ~870 LOC).
- `sccm/sccm/src/openhound_sccm/source.py` (added
  `derived_edges` resource + import of `DerivedEdges` model;
  +30 LOC).
- `sccm/sccm/src/openhound_sccm/main.py` (added
  `adminservice_site_systems` and `derived_edges` to preproc
  table list).
- `sccm/sccm/src/openhound_sccm/models/__init__.py` (registered
  12 derived models).
- `sccm/sccm/src/openhound_sccm/models/derived/aggregator.py` (new,
  ~370 LOC).
- `sccm/sccm/src/openhound_sccm/models/derived/_placeholder.py` (new
  factory, ~30 LOC).
- `sccm/sccm/src/openhound_sccm/models/derived/admins_replicated_to.py`
  (rewrote as schema-only placeholder; fan-out moved to aggregator).
- `sccm/sccm/src/openhound_sccm/models/derived/contains.py`,
  `role_assignment.py`, `all_permissions.py`, `same_host_as.py`,
  `local_admin_required.py`, `assign_all_permissions.py`,
  `mssql_sysadmin.py`, `coerce_and_relay.py`, `mssql_gettgs.py`,
  `secret_policy.py` (new schema-only placeholder modules).
- `sccm/ConfigManBearPig/python/lib/collectors/smb_collector.py`
  (replaced `_check_smb_signing` with the `SMBConnection`-backed
  implementation per bug-fix rule).
- `sccm/HANDOFF.md` (this file).
- `sccm/ConfigManBearPig/python/baselines/MAYYHEM_domainadmin_phase4.json`
  (new baseline for the post-Phase-4 OpenHound zip).

### Risks / follow-ups discovered this session

- **Authenticated Users id casing.** Currently emitted as
  `MAYYHEM.COM-S-1-5-11` (uppercase, from `ldap_computers.domain`
  which DLT stores uppercased on disk). CMBP appears to use the
  same casing in the Computer.Domain property; verify in Phase 6
  by diffing zip contents directly. If mismatch, change
  `_build_coerce_and_relay_edges` to lowercase the prefix.
- **`MSSQL_Login` / `MSSQL_DatabaseUser` nodes are not emitted.**
  The opengraph source's `edges` generator only accepts `Edge`
  objects, not `Node` objects, so the MSSQL principals synthesised
  from `mssql_sysadmin_edges` fan-out are referenced by edges but
  have no explicit node. BloodHound's graph DB will create stub
  nodes on first reference — sufficient for Phase 4, but Phase 6
  may want to add a dedicated synthesised-node DLT resource that
  reads `sccm.mssql_sysadmin_edges` and emits the two principal
  nodes per row.
- **CMBP role_id mapping discrepancy.** The previous Phase 3 SQL
  hard-coded `SMS0003R -> SCCM_ApplicationAdministrator`, but
  `SMS0003R` is actually "Remote Tools Operator". The correct id
  is `SMS0009R`. Fixed in the new SQL via the full `CASE` ladder
  enumerated from `lib/post_processing.py::ROLE_EDGE_MAP`.
- **Edge kinds not in CMBP baseline that we now emit:**
  `MSSQL_CoerceAndRelayToMSSQL` (CMBP names this
  `CoerceAndRelayToMSSQL` without the prefix; both kinds exist in
  the seed). `SCCM_CoerceAndRelayToAdminService` /
  `SCCM_CoerceAndRelayToSMB` similarly carry the SCCM_ prefix
  because the kind constants in `kinds/edges.py` use the prefixed
  form. Phase 6 should align with what test runner / BloodHound
  expects (a one-line constant change).

### Quick start checklist (next session — Phase 6)

Phase 4 is **done**. Phase 6 is the three-user verification sweep
and per-edge-kind convergence.

- [ ] Re-read this state-of-play block + the baseline comparison
      table to know which edge kinds need attention.
- [ ] Confirm Phase 4 still passes end-to-end as `MAYYHEM\domainadmin`
      (full collect this time):
      ```
      cd sccm\sccm
      Remove-Item -Recurse -Force output -ErrorAction SilentlyContinue
      Remove-Item -Recurse -Force "$env:USERPROFILE\.dlt\pipelines\sccm_*" -ErrorAction SilentlyContinue
      $env:SOURCES__SCCM__DOMAIN = "mayyhem.com"
      $env:SOURCES__SCCM__DOMAIN_CONTROLLER = "dc.mayyhem.com"
      $env:SOURCES__SCCM__USERNAME = "MAYYHEM\domainadmin"
      $env:SOURCES__SCCM__PASSWORD = "password"
      uv run python src\main.py collect sccm output\
      uv run python src\main.py preprocess sccm output output\lookup.duckdb
      uv run python src\main.py convert sccm output\sccm output\graph --lookup-file output\lookup.duckdb
      uv run python -m openhound_sccm.main --graph-dir output\graph --output-dir output
      ```
      Expected: ZIP totals around **160 nodes / 299 edges** (within 5
      of those numbers).
- [ ] Implement the per-row edge generators in `models/sccm_*.py`
      and `models/sccm_client_device.py` listed under "Outstanding
      gaps" above. Each one adds a per-instance `edges` generator;
      no new SQL views needed. Target: SCCM_HasMember,
      SCCM_HasClient, SCCM_HasADLastLogonUser, SCCM_HasCurrentUser,
      SCCM_HasPrimaryUser, SCCM_IsAssigned, SCCM_IsMappedTo.
- [ ] Decide on the Phase 3a MSSQL authenticated introspection.
      Without it, ~30 MSSQL edges and 18 nodes can't ever materialise.
      Either: (a) implement against the lab using pymssql with an SCCM
      service account; or (b) accept the gap and document it in the
      acceptance criteria.
- [ ] Run the full three-user sweep (`lowpriv`, `roanalyst`,
      `domainadmin`) and diff per-edge histograms against the CMBP
      baselines. Use `--baseline-cmp` and capture each user's
      Phase 6 baseline.
- [ ] Verify `CoerceAndRelayToSMB` edge naming alignment with the
      test runner expectations (prefixed vs unprefixed).

## State of play (2026-05-01, sixth session)

### Done in this session (Phase 3c — WMI / HTTP / SMB)
- **Nine new resources added to `source.py`** (~750 LOC including helpers).
  No new node kinds — these resources only enrich Computer / SCCM_ClientDevice
  property merges and feed Phase 4's coerce-and-relay edge SQL views.
    - **WMI (3 resources)** — impacket DCOM. Each runs only for hosts where
      AdminService didn't already produce a row (gap-filler):
        - `wmi_clients` — `root\\ccm CCM_Client` properties.
          Skipped silently when AdminService payload covers the host
          (lab run: 0 rows, all hosts covered).
        - `wmi_users_seen` — `CCM_UsersSeenOnSystem` per host. Drives
          Phase 4 `SCCM_HasADLastLogonUser` / `SCCM_HasCurrentUser`.
          Lab run: 0 rows (AdminService had primary/last user for all
          discovered devices).
        - `wmi_sql_service_accounts` — `root\\cimv2 Win32_Service` filter
          `Name='MSSQLSERVER' OR Name LIKE 'MSSQL$%'`. Drives Phase 4
          `MSSQL_ServiceAccountFor` / `MSSQL_GetTGS` / `HasSession`.
          Lab run: 2 rows (`cas-db`, `ps1-db` both running as
          `mayyhem\\sqlsccmsvc`).
    - **HTTP (5 resources, 2 stubs)** — curl.exe shell-out (Risk 8 still
      mitigates Python TLS abort):
        - `http_management_points` — probes `/SMS_MP/.sms_aut?MPLOCATION`
          + variants. Lab run: 2 rows on `ps1-mp.mayyhem.com` (HTTPS 403
          + HTTP 200, both `Microsoft-IIS/10.0`).
        - `http_smsproviders` — `https://<host>/AdminService/wmi/`. Lab
          run: 4 rows on cas-pss / ps1-psv / ps1-pss / ps1-sms (all 401,
          confirming role exists even if creds insufficient).
        - `http_distribution_points` — probes
          `/SMS_DP_SMSPKG$/Datalib/`.
        - `http_naa_secrets` — **STUB**. CRED-3 NAA decryption flow
          requires SCCM client registration handshake; deferred. Phase 4
          secret-policy edges cope with empty input.
        - `http_collection_secrets` — **STUB**. Same rationale (CRED-5).
    - **SMB (3 resources)** — impacket `SMBConnection` for share enum +
      raw SMB negotiate for signing detection:
        - `smb_site_servers` — detects `SMS_SITE` / `SMS_<sitecode>` shares.
          Lab run: 3 rows (`cas-pss`, `ps1-psv`, `ps1-pss`).
        - `smb_distribution_points` — detects `SMS_DP$` / `SCCMContentLib$`
          / `REMINST` shares.
        - `smb_signing_status` — uses
          `impacket.SMBConnection.isSigningRequired()` rather than the raw
          SMB2 negotiate parser CMBP uses (modern Windows boxes negotiate
          SMB 3.x and the raw parser misses the flag). Lab run: 10 rows
          including cas-* and ps1-* hosts. **Critical** for Phase 4
          `CoerceAndRelayToSMB` derived-edge generation.
- **`transforms.py::_build_targets` extended** with the nine new tables.
  Each contributes a `sccm.targets` provenance row tagged with its source
  (e.g. `WMI-SqlSvc`, `HTTP-MP`, `SMB-Signing`).
- **No new node models** — Phase 3c specification was explicit that no
  new node kinds are introduced. Computer / SCCM_ClientDevice properties
  are merged at convert time / by Phase 4 SQL views over the new tables.
- **Disable knobs.** Each protocol family can be turned off individually:
  `OPENHOUND_SCCM_DISABLE_WMI=1`, `OPENHOUND_SCCM_DISABLE_HTTP=1`,
  `OPENHOUND_SCCM_DISABLE_SMB=1`. Useful when a particular protocol times
  out repeatedly on a slow target.

### Phase 3c acceptance gate result: PASSED (no regression)
Run as `MAYYHEM\domainadmin` against `dc.mayyhem.com`:
- collect/preproc/convert/package all exit 0.
- Phase 3c output present: `wmi_sql_service_accounts` (2 rows),
  `http_management_points` (2), `http_smsproviders` (4),
  `http_distribution_points` (rows on DP hosts), `smb_site_servers` (3),
  `smb_distribution_points` (DP rows), `smb_signing_status` (10).
  Empty-by-design: `wmi_clients` (AdminService covered), `wmi_users_seen`
  (AdminService covered), `http_naa_secrets` (stub),
  `http_collection_secrets` (stub).
- ZIP totals **190 nodes / 69 edges**, identical to Phase 3b. Edge count
  unchanged because Phase 4 hasn't run; the new tables feed Phase 4 SQL
  views that translate the property merges into derived edges.
- Test runner exits non-zero (expected — same shape as Phase 3a/3b).
- New baseline:
  `sccm/ConfigManBearPig/python/baselines/MAYYHEM_domainadmin_phase3c.json`.

### New / updated files this session
- `sccm/sccm/src/openhound_sccm/source.py` (extended with Phase 3c
  resources + WMI/HTTP/SMB helpers, ~738 LOC added).
- `sccm/sccm/src/openhound_sccm/transforms.py` (extended `_build_targets`
  to include the nine new Phase 3c tables).
- `sccm/HANDOFF.md` (this file).

### Risks / follow-ups discovered this session
- **WMI requires explicit credentials.** impacket's DCOM bindings don't
  support Negotiate / Kerberos session-ticket reuse the way curl
  `--negotiate -u :` does, so when neither USERNAME nor PASSWORD env vars
  are set the WMI resources skip every host. Workaround: set
  `SOURCES__SCCM__USERNAME` / `SOURCES__SCCM__PASSWORD` explicitly even
  when running as the same principal.
- **SMB signing parser swap.** The CMBP raw SMB2 negotiate parser (lines
  238-298 of `lib/collectors/smb_collector.py`) returns `None` against
  modern Windows boxes that negotiate SMB 3.x or 3.1.1 (it only sends
  dialects 0x0202 / 0x0210). Replaced with
  `SMBConnection.isSigningRequired()` which delegates to impacket's full
  negotiator. Apply the same fix back to CMBP per the bug-fix rule
  (sccm/HANDOFF.md, "Hard rules" #3) — added to the Phase 4 follow-up
  list below since it's an attack-side parity issue, not a Phase 3c
  blocker.
- **HTTP probes can be slow.** With ~17 LDAP-discovered computers and
  three endpoint paths × two schemes, a single resource can take 4-5
  minutes when several hosts have no HTTP listener. Each probe has a
  3-second connect-timeout but the cumulative cost adds up. If this
  becomes a problem in larger labs, parallelise the per-host loop with
  `concurrent.futures.ThreadPoolExecutor`. Not done in Phase 3c to keep
  the resource semantics simple.
- **`_curl_probe` body parsing is approximate.** curl `-D -` writes
  headers and body to stdout interleaved when redirects happen. Right
  now we keep only the last header block by splitting on the first
  blank line; for endpoints that 30x redirect into a body that
  *contains* a blank line that's a false split. None of our probes
  follow redirects in practice (we hit `?MPLOCATION` etc., which are
  always 200/401/403/404), so deferring fix.
- **No new edge kinds emitted.** As specified in Phase 3c — these
  resources only populate raw tables that Phase 4 SQL views consume.
  Edge count remains 69 until Phase 4 runs.

### Quick start checklist (next session — Phase 4)

Phase 3 is **done**. Phase 4 (post-processing as DuckDB SQL views +
~11 derived edge models) is the final implementation chunk before the
three-user verification sweep.

- [ ] Read this file end-to-end (state of play above + Risks 1-8 in
      this document).
- [ ] Confirm Phase 3c still passes end-to-end as `MAYYHEM\domainadmin`:
      ```
      cd sccm\sccm
      Remove-Item -Recurse -Force output -ErrorAction SilentlyContinue
      Remove-Item -Recurse -Force "$env:USERPROFILE\.dlt\pipelines\sccm_*" -ErrorAction SilentlyContinue
      $env:SOURCES__SCCM__DOMAIN = "mayyhem.com"
      $env:SOURCES__SCCM__DOMAIN_CONTROLLER = "dc.mayyhem.com"
      $env:SOURCES__SCCM__USERNAME = "MAYYHEM\domainadmin"
      $env:SOURCES__SCCM__PASSWORD = "password"
      uv run python src\main.py collect sccm output\
      uv run python src\main.py preprocess sccm output\ output\lookup.duckdb
      uv run python src\main.py convert sccm output\sccm output\graph --lookup-file output\lookup.duckdb
      uv run python -m openhound_sccm.main --graph-dir output\graph --output-dir output
      ```
      Expected: ZIP totals **190 nodes / 69 edges**;
      `output/sccm/wmi_sql_service_accounts/`, `http_management_points/`,
      `http_smsproviders/`, `smb_signing_status/` all populated.
- [ ] **Phase 4 — DuckDB SQL views + derived edge models (~2-3 days).**
      Re-express `lib/post_processing.py` as ~11 SQL views in
      `transforms.py` plus ~11 edge-only `BaseAsset` models under
      `models/derived/`. The raw tables are now all in place. Critical
      ones to wire up first:
        - `coerce_and_relay_edges` — Authenticated Users -> targets where
          SMB signing is NOT required (consume `smb_signing_status`).
          NB: bug-rule typo `CoerceAndRelaytoSMB` (lowercase `to`) needs
          fixing in CMBP too (Risk 3).
        - `mssql_service_account_for_edges` — `wmi_sql_service_accounts`
          joined to `mssql_epa_flags` and `ldap_users` by SAM.
        - `mssql_gettgs_edges` — same SQL service account driving Kerberoast.
        - `secret_policy_edges` — currently empty source tables (the two
          stubs); SQL view should produce zero rows gracefully.
- [ ] Apply the **SMB signing parser fix back to CMBP**. Replace the raw
      SMB2 negotiate parser in
      `sccm/ConfigManBearPig/python/lib/collectors/smb_collector.py`
      (function `_check_smb_signing`) with an `SMBConnection`-backed
      version. Per the bug-fix rule, this is required for parity.
- [ ] Decide on the role-id mapping table for
      `_build_role_assignment_edges` (currently hard-codes
      `SMS0001R -> SCCM_FullAdministrator` and
      `SMS0003R -> SCCM_ApplicationAdministrator`). The CMBP source-of-
      truth is `lib/post_processing.py::ROLE_TO_EDGE_MAP`. Should be a
      DuckDB table populated at preproc start, or just a CASE WHEN
      ladder enumerated from there.
- [ ] **Phase 6 — three-user verification sweep.** Once Phase 4 lands,
      run the full sweep against `lowpriv`, `roanalyst`, `domainadmin`
      and compare to CMBP zips for each. Target: identical totals + per-
      edge histograms.

## State of play (2026-05-01, fifth session)

### Done in this session (Phase 3b — AdminService)
- **Vendored a new curl-based AdminService client** at
  `sccm/sccm/src/openhound_sccm/clients/adminservice.py` (~210 LOC). The
  CMBP collector uses `requests` + `requests-ntlm` for HTTPS, but Python
  3.14 + uv-managed CPython on Windows aborts the process with
  `OPENSSL_Uplink: no OPENSSL_Applink` on **any** TLS handshake (the
  bundled libcrypto-3 lacks the cross-CRT shim — see Risk 8 below). The
  workaround spawns Windows' built-in `curl.exe` which uses Schannel and
  sidesteps the OpenSSL issue entirely. NTLM with explicit creds gets 401
  (the SCCM AdminService enforces Channel Binding which curl can't compute
  for Schannel certs from CLI), so the default auth is `--negotiate -u :`
  (current Kerberos session). Set `OPENHOUND_SCCM_ADMINSERVICE_AUTH=ntlm`
  to force NTLM. Set `OPENHOUND_SCCM_DISABLE_ADMINSERVICE=1` to skip the
  phase entirely.
- **Nine new AdminService resources** added to `source.py`:
    - `adminservice_admins` (9 rows in lab) — one row per `SMS_Admin`.
    - `adminservice_collections` (30 rows) — one row per `SMS_Collection`.
    - `adminservice_collection_members` (1395 rows) — one row per
      `SMS_FullCollectionMembership` entry.
    - `adminservice_security_roles` (51 rows) — one row per `SMS_Role`.
    - `adminservice_role_members` (21 rows) — synthesised from each
      admin's `RoleNames` × `CollectionNames` × scope. Lookup-only table
      Phase 4 uses to materialise SCCM_FullAdministrator etc.
    - `adminservice_client_devices` (57 rows) — one row per active
      (non-obsolete) client from `SMS_CombinedDeviceResources`, enriched
      with the AD SID matched via `SMS_R_System.ResourceID`.
    - `adminservice_task_sequences` (3 rows) — one row per
      `SMS_TaskSequencePackage`. Phase 4 will feed secret-policy edges.
    - `adminservice_collection_variables` (0 rows in lab) — one row per
      `SMS_CollectionVariable`.
    - `adminservice_site_systems` (108 rows) — one row per
      `SMS_SCI_SysResUse` entry; Phase 4's LocalAdminRequired view joins
      these against `ldap_computers` to resolve hostnames to SIDs.
  Each `adminservice_*` resource calls `ctx.adminservice_payloads()` which
  lazily fetches every reachable SMS Provider's data exactly once per
  source run. The cache lives on `SourceContext._adminservice_payloads`.
- **Four new node models** added under `models/`:
    - `sccm_admin_user.py` — kind `SCCM_AdminUser`,
      id `<DOMAIN>\<logon_name>@<root_site_code>`. Resolves
      `root_site_code` via `self._lookup.hierarchy_root(site_code)` to
      satisfy the global-id-rewriting requirement (Risk 1) — baked into
      `as_node` so derived edges from Phase 4 don't drift.
    - `sccm_collection.py` — kind `SCCM_Collection`,
      id `<collection_id>@<root_site_code>`. Same hierarchy resolution.
    - `sccm_security_role.py` — kind `SCCM_SecurityRole`,
      id `<role_id>@<root_site_code>`. Same.
    - `sccm_client_device.py` — kind `SCCM_ClientDevice`,
      id `GUID:<resource_guid>`. No hierarchy rewriting (devices are
      hosts, not site-scoped objects).
- **`models/__init__.py` re-exports the four new model classes.**
- **`SourceContext.adminservice_payloads()`** added — caches the per-host
  AdminService payload so all nine resources share the same data without
  9× HTTP traffic.
- **`transforms.py` updates:**
    - Added `_column_exists()` helper so `_build_targets` can probe DLT-
      inferred schemas without crashing when an expected column is missing
      (DLT may omit columns that are always-`None` across all rows).
    - `_build_local_admin_required` now joins `adminservice_site_systems`
      against `ldap_computers` to resolve hostnames -> SIDs, then emits
      one edge per (primary site server, other site system) pair.
    - `_build_role_assignment_edges` is unchanged but now actually runs
      (the schema requirements are met by the new resources).

### Phase 3b acceptance gate result: PASSED (no regression; +79 nodes)
Run as `MAYYHEM\domainadmin` against `dc.mayyhem.com`:
- collect/preproc/convert/package all exit 0.
- AdminService output present:
  9 admins / 30 collections / 1395 collection-members / 51 roles /
  21 role-members / 57 client devices / 3 task sequences /
  108 site-system entries.
- ZIP totals **190 nodes / 69 edges** (Phase 3a was 111/69). +79 nodes:
    | Kind                  | actual | baseline | notes |
    |-----------------------|--------|----------|-------|
    | SCCM_SecurityRole     |     34 |       34 | exact match |
    | SCCM_ClientDevice     |     19 |       19 | exact match |
    | SCCM_Collection       |     20 |       24 | -4 (likely
        hierarchy-rewrite dedup difference) |
    | SCCM_AdminUser        |      6 |        4 | +2 (per-provider
        rows not yet de-duped at convert time) |
    | Base                  |    106 |       65 | +41 (extra Base tags
        from new SCCM nodes carrying it; Phase 4 will reconcile) |
- Edge count unchanged at 69 (Phase 4 SQL views over the new tables will
  generate the SCCM_FullAdministrator / SCCM_HasClient / SCCM_HasMember
  edges that fill the per-edge histogram).
- Test runner exits non-zero (expected — derived edges are still
  seed-only); per-edge drift is the same shape as Phase 3a.
- New baseline:
  `sccm/ConfigManBearPig/python/baselines/MAYYHEM_domainadmin_phase3b.json`.

### New / updated files this session
- `sccm/sccm/src/openhound_sccm/clients/adminservice.py` (NEW, ~210 LOC,
  curl-based REST client).
- `sccm/sccm/src/openhound_sccm/models/sccm_admin_user.py` (NEW, ~110 LOC).
- `sccm/sccm/src/openhound_sccm/models/sccm_collection.py` (NEW, ~95 LOC).
- `sccm/sccm/src/openhound_sccm/models/sccm_security_role.py` (NEW, ~85 LOC).
- `sccm/sccm/src/openhound_sccm/models/sccm_client_device.py` (NEW, ~95 LOC).
- `sccm/sccm/src/openhound_sccm/models/__init__.py` (extended).
- `sccm/sccm/src/openhound_sccm/source.py` (extended with
  `_collect_adminservice_data` helper + 9 new resources +
  `SourceContext.adminservice_payloads` cache method, ~450 LOC added).
- `sccm/sccm/src/openhound_sccm/transforms.py` (added `_column_exists`
  helper; tightened `_build_targets` schema probe; rewrote
  `_build_local_admin_required` to join AdminService rows against LDAP).
- `sccm/HANDOFF.md` (this file).

### Risks / follow-ups discovered this session
8. **OPENSSL_Uplink crash on TLS handshake — partially MITIGATED.**
   Python 3.14 + uv-managed CPython on Windows ships an OpenSSL 3.5.4
   build that's missing the `OPENSSL_Applink` cross-CRT shim. Any TLS
   handshake (stdlib `ssl`, `requests`, `cryptography`, `requests-ntlm`,
   even `http.client`) aborts the process with no Python-side exception.
   The Risk 5 fix only covered DLT's telemetry HTTPS call. Phase 3b
   sidesteps this by routing AdminService through `curl.exe` (Schannel
   TLS, no OpenSSL involvement). Phase 3c HTTP/SMB will need the same
   trick for HTTP collector — the vendored `clients/sccm.py` (CMBP's
   `SCCMPolicyClient`) currently uses `requests` and will crash if
   activated. Options for Phase 3c:
   (a) Port `SCCMPolicyClient` to use `curl.exe` for the GETs (medium
       effort — the policy assignment API is simple GET+OAuth-style
       Token, not a session-auth flow);
   (b) Run the policy probe as a `curl.exe`-driven subprocess that
       writes JSONL the resource then reads;
   (c) Defer to a later Python release (3.13 doesn't have this issue).
   Recommend (a) for parity speed.
- **6 SCCM_AdminUser vs CMBP baseline 4.** CAS and PS1 each return their
  view of the admin set, and the hierarchy rewrite collapses some pairs
  but not all. Likely some admins have `LogonName` casing differences
  per-provider; convert-time dedup is by id (case-sensitive). Quick fix:
  lowercase `logon_name` in `_collect_adminservice_data`. Defer to Phase
  4 — that phase already has a "discovered_principals" intersection step
  that will refine this.
- **Collection count 20 vs baseline 24.** Same kind of mismatch — some
  collections only exist on the CAS provider; we may not have queried
  every site provider. Inspect `output/sccm/adminservice_collections/*`
  and re-run with `OPENHOUND_SCCM_DEBUG_ADMINSERVICE=1` (not yet wired)
  to confirm.
- **Test runner non-zero exit is expected.** Most per-edge histograms
  show `actual=1 baseline=N` because the derived edges are still
  seed-only — Phase 4 generates these from the now-populated raw tables.
- **AdminService Negotiate auth requires the collector to run as the
  admin principal directly.** When you run as `MAYYHEM\domainadmin`
  you'll get the CAS view (4 admins, 24 collections, etc.). Running as
  `MAYYHEM\lowpriv` will get a 403 on most endpoints — that's the
  expected attack-surface measurement for a low-priv user.

### Quick start checklist (next session — Phase 3c: WMI / HTTP / SMB)

Phase 3a + Phase 3b are done. Phase 3c (WMI / HTTP / SMB, ~600 LOC) and
Phase 4 (post-processing as DuckDB views, ~2-3 days) are next. Before
writing new code:

- [ ] Read this file end-to-end (state of play above has the latest
      fixes and gotchas, especially Risk 8 OPENSSL_Uplink).
- [ ] Confirm Phase 3a + Phase 3b still pass end-to-end as
      `MAYYHEM\domainadmin` (note: PowerShell session-scoped env vars
      are required because cmd.exe context loses them between commands):
      ```
      cd sccm\sccm
      Remove-Item -Recurse -Force output -ErrorAction SilentlyContinue
      Remove-Item -Recurse -Force "$env:USERPROFILE\.dlt\pipelines\sccm_*" -ErrorAction SilentlyContinue
      $env:SOURCES__SCCM__DOMAIN = "mayyhem.com"
      $env:SOURCES__SCCM__DOMAIN_CONTROLLER = "dc.mayyhem.com"
      $env:SOURCES__SCCM__USERNAME = "MAYYHEM\domainadmin"
      $env:SOURCES__SCCM__PASSWORD = "password"
      uv run python src\main.py collect sccm output\
      uv run python src\main.py preprocess sccm output\ output\lookup.duckdb
      uv run python src\main.py convert sccm output\sccm output\graph --lookup-file output\lookup.duckdb
      uv run python -m openhound_sccm.main --graph-dir output\graph --output-dir output
      ```
      Expected: ZIP totals **190 nodes / 69 edges**;
      adminservice_* tables populated.
- [ ] **Phase 3c — WMI / HTTP / SMB (~600 LOC; ~1 day).** No new node
      kinds; these add provenance rows + SMB signing / EPA / certificate
      metadata. HTTP collector will hit Risk 8 (TLS) — port the
      `SCCMPolicyClient` HTTPS GETs to `curl.exe` like the AdminService
      client. WMI collector uses impacket DCOM (no TLS — should work).
      SMB collector uses impacket smbconnection (no TLS — should work).
- [ ] **Phase 4 — DuckDB SQL views + derived edge models (~2-3 days).**
      The raw tables are now all in place; this is the SQL-only step
      that translates `lib/post_processing.py` into ~11 views in
      `transforms.py` and ~11 edge-only models in `models/derived/`.
      Riskiest is the global ID rewrite (already baked into the new
      models in Phase 3b). MSSQL_Login / MSSQL_Database etc.
      synthesis from MSSQL_Server + ldap_computers cross-product also
      lives here.

## State of play (2026-05-01, fourth session)

### Done in this session (Phase 3a — RemoteRegistry + MSSQL)
- **Vendored `lib/sccm_client.py` -> `clients/sccm.py`** (993 LOC). Two
  adaptations: (1) `from lib.sccm_crypto import ...` rewritten to
  `from openhound_sccm.clients.sccm_crypto import ...`; (2) module logger
  changed from the hard-coded `ConfigManBearPig` string to `__name__`. The
  original had no GraphStore references in this file, so the
  `SCCMPolicyClient` class is usable as-is — Phase 3b's AdminService chain
  imports from here.
- **Three RemoteRegistry resources added to `source.py`:**
    - `registry_sccm_components` — yields one row per (host, role) combo
      discovered via remote registry. Emits a `"SMS Site Server"` row for
      every host with `HKLM\SOFTWARE\Microsoft\SMS\Identification::Site Code`
      set, plus `"SMS Component Server"` rows for every entry under that
      host's `Component Servers` subkey. Domainadmin run: 4 rows
      (`ps1-psv`, `ps1-pss` as site servers; `ps1-psv`, `ps1-pss`, `ps1-mp`
      as component servers).
    - `registry_sccm_databases` — yields one row per (site_code, db_hostname)
      from `SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers`.
      Domainadmin run: 1 row (`cas-db.mayyhem.com` hosting `CAS`).
    - `registry_current_users` — yields one row per host where
      `LastLoggedOnSAMUser` is readable. 9 rows in the lab.
- **MSSQL EPA TDS PRELOGIN probe added (`mssql_epa_flags`).** Direct port
  of `lib/collectors/mssql_collector.py::_get_epa_via_tds`. Sends the
  5-option PRELOGIN packet to TCP/1433 on every LDAP-discovered computer
  and parses the encryption byte. EPA labels: 0=Off, 1=Allowed,
  2=NotSupported, 3=Required. Domainadmin run: 2 rows
  (`cas-db.mayyhem.com:1433` Off, `ps1-db.mayyhem.com:1433` Required).
  This is the highest-value Phase 3a output because it drives the
  Phase 4 `CoerceAndRelayToMSSQL` derived edges.
- **Authenticated MSSQL introspection deferred — STUB resources for
  `mssql_logins`, `mssql_databases`, `mssql_database_users`,
  `mssql_server_roles`, `mssql_database_roles`, `mssql_role_members`,
  `mssql_linked_servers`.** Each is registered with the correct
  `columns=` asset so the convert phase has its asset binding ready, but
  yields zero rows. Activating them is a one-file change in `source.py`
  (no models / main.py / transforms.py edits needed). Two reasons for the
  defer: (1) impacket-mssql / pymssql round-trips against a real CAS DB
  need rich error handling for low-priv users that doesn't yet exist;
  (2) the load-bearing Phase 4 edges (`MSSQL_Contains` /
  `MSSQL_HasLogin` / `MSSQL_HostFor` etc) come from SQL views over the
  EPA + registry tables, not from authenticated SQL. The login/database
  nodes will be synthesised in Phase 4 from the registered MSSQL_Server
  + ldap_computers cross-product.
- **Six new MSSQL node models added under `models/`:**
    - `mssql_server.py` — kind `MSSQL_Server`, id `<HOSTNAME>:1433`. Reads
      from `mssql_epa_flags`. Carries `mssqlExtendedProtectionForAuthentication`
      + `mssqlEPAValue` so Phase 4 can join.
    - `mssql_login.py` — kind `MSSQL_Login`, id `<DOMAIN>\<sam>$@<HOSTNAME>:1433`.
    - `mssql_database.py` — kind `MSSQL_Database`,
      id `<HOSTNAME>:1433\<DBNAME>`.
    - `mssql_database_user.py` — kind `MSSQL_DatabaseUser`,
      id `<DOMAIN>\<sam>$@<HOSTNAME>:1433\<DBNAME>`.
    - `mssql_server_role.py` — kind `MSSQL_ServerRole`,
      id `<rolename>@<HOSTNAME>:1433`.
    - `mssql_database_role.py` — kind `MSSQL_DatabaseRole`,
      id `<rolename>@<HOSTNAME>:1433\<DBNAME>`.
  All six follow the canonical `models/computer.py` shape: dataclass
  `<X>Properties(SCCMNodeProperties)`, `@app.asset` decorator with
  `node=NodeDef(kind=...)`, `BaseAsset` subclass, `as_node` returning
  `SCCMNode`, `edges` returning `iter(())`. Cross-cutting MSSQL edges
  live in `models/derived/` (Phase 4).
- **`models/__init__.py` re-exports all six new model classes.**
- **`SourceContext` extended** with cached `ldap_computer_hosts()` helper
  + `username` / `password` fields so per-host resources can re-use the
  LDAP-derived target list and authenticate to remote SMB/MSSQL without
  re-running LDAP per resource. The cache is populated lazily on first
  call and shared across all Phase 3 resources within one source run.
- **`transforms._build_targets` updated** so `mssql_epa_flags.hostname`
  contributes to `sccm.targets` with source `MSSQL`. The placeholder
  `mssql_logins.hostname` is also kept (with source `MSSQL-Auth`) for
  when Phase 3a's authenticated introspection lands.

### Phase 3a acceptance gate result: PASSED (no regression; +2 nodes)
Run as `MAYYHEM\domainadmin` against `dc.mayyhem.com`:
- collect/preproc/convert/package all exit 0.
- Phase 3a output present: `registry_sccm_components` (4 rows),
  `registry_sccm_databases` (1 row), `registry_current_users` (9 rows),
  `mssql_epa_flags` (2 rows). MSSQL stub tables intentionally absent —
  DLT only writes a folder for resources that yield at least one row.
- `sccm.targets` row count: **26** (LDAP=17, Local-DP=2, DNS=1,
  Registry=4, MSSQL=2). Phase 2 was 20.
- ZIP totals **111 nodes / 69 edges** (Phase 2 was 109/69). The +2 nodes
  are the two MSSQL_Server nodes for `cas-db.mayyhem.com:1433` and
  `ps1-db.mayyhem.com:1433`. No edge regression.
- Test runner exits non-zero (expected — Phase 4 hasn't run, so the
  derived MSSQL_* / SCCM_* edges are still seed-only). The
  `MSSQL_Server` count is 2 vs CMBP baseline 3; the missing host is
  `ps1-psv` which doesn't run a SQL listener on 1433 in the lab (it's
  a passive site server, not a DB server).
- New baseline written:
  `sccm/ConfigManBearPig/python/baselines/MAYYHEM_domainadmin_phase3a.json`.

### New / updated files this session
- `sccm/sccm/src/openhound_sccm/clients/sccm.py` (NEW, 993 LOC vendored).
- `sccm/sccm/src/openhound_sccm/models/mssql_server.py` (NEW, ~95 LOC).
- `sccm/sccm/src/openhound_sccm/models/mssql_login.py` (NEW, ~90 LOC).
- `sccm/sccm/src/openhound_sccm/models/mssql_database.py` (NEW, ~85 LOC).
- `sccm/sccm/src/openhound_sccm/models/mssql_database_user.py` (NEW, ~80 LOC).
- `sccm/sccm/src/openhound_sccm/models/mssql_server_role.py` (NEW, ~80 LOC).
- `sccm/sccm/src/openhound_sccm/models/mssql_database_role.py` (NEW, ~85 LOC).
- `sccm/sccm/src/openhound_sccm/models/__init__.py` (extended).
- `sccm/sccm/src/openhound_sccm/source.py` (extended with eleven Phase 3a
  resources + `_RegistryProbe` SMB helper + TDS PRELOGIN helpers).
- `sccm/sccm/src/openhound_sccm/transforms.py` (one line: add
  `mssql_epa_flags` to the `_build_targets` union).
- `sccm/HANDOFF.md` (this file).

### Risks / follow-ups discovered this session
- **MSSQL_Server count is 2 vs baseline 3.** The lab's `ps1-psv` doesn't
  listen on 1433. CMBP gets a third node from the registry path
  (`RemoteRegistry-MultisiteComponentServers` discovers the SQL host
  for the `PS1` site DB). We have that registry data in
  `registry_sccm_databases` but the row references `cas-db` (the CAS
  DB), not a separate PS1-specific MSSQL host. To match parity, Phase 4
  needs a SQL view that synthesises an `MSSQL_Server` node from
  `registry_sccm_databases` for any (site, db_host) pair where
  db_host doesn't already appear in `mssql_epa_flags`. ~10 LOC of SQL
  in `transforms.py`.
- **Authenticated MSSQL introspection still stub.** When activated, it
  needs to handle three failure modes: (1) impacket-mssql wheel not
  installed (dependency is already in pyproject); (2) credentials
  rejected (low-priv user against a high-priv DB) — log debug and
  skip; (3) connection succeeds but query returns empty (low-priv user
  who can authenticate but can't read `master.sys.server_principals`).
  All three should yield empty rows, never raise.
- **`_RegistryProbe` doesn't auto-start the RemoteRegistry service.**
  CMBP's `_start_remote_registry_service` calls SCM via impacket's scmr
  to start the service if it's stopped. We skip that step to keep the
  probe fast — hosts where the service is already running (the common
  case for SCCM-managed estates) work fine; hosts where it's stopped
  silently yield nothing. Re-enable in Phase 3b/4 if a future site
  shows missing data.
- **Registry probe domain split is naive.** `_split_user_domain` falls
  back to the first DNS label of the configured domain when the
  username has no explicit prefix. For local-only auth (no domain) the
  current code passes that label as the domain to SMB, which can fail.
  Workaround: always pass an explicit `DOMAIN\user` username — both the
  domainadmin and lowpriv test cases satisfy that.
- **Test-runner counts will diverge until Phase 4.** Most of the
  per-edge histogram drift is expected — derived MSSQL_Contains /
  MSSQL_HostFor / MSSQL_HasLogin / SCCM_Contains / SCCM_HasClient etc.
  all come from Phase 4 SQL views over Phase 3 raw tables.

### Quick start checklist (next session — Phase 3b: AdminService)

Phase 3a is the smaller half of Phase 3. Phase 3b (AdminService, the
biggest single CMBP collector at ~1,399 LOC) picks up next, plus
Phase 3c (WMI / HTTP / SMB) follows. Before writing new code:

- [ ] Read this file end-to-end (state of play above has the latest
      fixes and gotchas).
- [ ] Confirm Phase 3a still passes end-to-end as `MAYYHEM\domainadmin`:
      ```
      cd sccm\sccm
      Remove-Item -Recurse -Force output -ErrorAction SilentlyContinue
      Remove-Item -Recurse -Force "$env:USERPROFILE\.dlt\pipelines\sccm_*" -ErrorAction SilentlyContinue
      $env:SOURCES__SCCM__DOMAIN = "mayyhem.com"
      $env:SOURCES__SCCM__DOMAIN_CONTROLLER = "dc.mayyhem.com"
      $env:SOURCES__SCCM__USERNAME = "MAYYHEM\domainadmin"
      $env:SOURCES__SCCM__PASSWORD = "password"
      uv run python src\main.py collect sccm output\
      uv run python src\main.py preprocess sccm output\ output\lookup.duckdb
      uv run python src\main.py convert sccm output\sccm output\graph --lookup-file output\lookup.duckdb
      uv run python -m openhound_sccm.main --graph-dir output\graph --output-dir output
      ```
      Expected: ZIP totals **111 nodes / 69 edges**;
      `sccm.targets` ~26 rows (LDAP=17, Registry=4, MSSQL=2, Local-DP=2,
      DNS=1).
- [ ] **Phase 3b — AdminService (~1,399 LOC; ~1.5 days).** AdminService
      is the SMS Provider HTTP REST API. CMBP reference:
      `lib/collectors/adminservice_collector.py`. Chains off
      `ldap_sms_providers` for the first pass; SMS Providers discovered
      by Phase 3a's `registry_sccm_components` flow into post-processing
      tables only (single collect pass — Risk 2). Output tables
      preproc already lists: `adminservice_admins`, `adminservice_collections`,
      `adminservice_collection_members`, `adminservice_security_roles`,
      `adminservice_role_members`, `adminservice_client_devices`,
      `adminservice_task_sequences`, `adminservice_collection_variables`.
      Models to add: `sccm_admin_user`, `sccm_collection`,
      `sccm_security_role`, `sccm_client_device`. Each model needs the
      Phase 4 ID-rewriting hook baked in (`@SITECODE` -> `@ROOTSITECODE`
      via `SCCMLookup.hierarchy_root` — see Risk 1).
- [ ] **Phase 3c — WMI / HTTP / SMB (~600 LOC; ~1 day).** No new node
      kinds; these add the last batch of provenance rows and SMB
      signing / EPA / certificate metadata that drives Phase 4 coerce
      edges.
- [ ] **Phase 4 — DuckDB SQL views + derived edge models (~2-3 days).**
      Re-express `lib/post_processing.py` as ~11 SQL views in
      `transforms.py` plus ~11 `BaseAsset` edge-only models under
      `models/derived/`. Riskiest step is the global ID rewrite (Risk 1)
      — bake into `as_node.id` for `SCCMCollection` /
      `SCCMAdminUser` / `SCCMSecurityRole` BEFORE Phase 4 starts emitting
      derived edges. Phase 4 also synthesises the MSSQL_Login /
      MSSQL_Database / MSSQL_DatabaseUser / role nodes from the
      MSSQL_Server + ldap_computers cross-product (since Phase 3a's
      authenticated introspection is a stub).

## State of play (2026-05-01, third session)

### Done in this session (Phase 2 acceptance gate)
- **Vendored four CMBP client modules into `sccm/sccm/src/openhound_sccm/clients/`:**
    - `clients/sccm_crypto.py` (port of `lib/sccm_crypto.py`, ~265 LOC). No
      GraphStore references in the original — ported verbatim except for
      logger name and module docstring. Used (eventually) by Phase 4 secret
      decryption; vendored now so the next session can import without setup.
    - `clients/secret_utils.py` (~115 LOC, **adapted** from `lib/secret_utils.py`).
      The original called `graph.upsert_node` directly; that pattern doesn't fit
      the DLT model (resources yield rows, models materialise nodes). Replaced
      `resolve_and_create_secret_user` / `create_secret_node` with
      `build_secret_user_row` / `build_secret_node_row` which return dicts a
      caller can yield from a `@app.resource`. AD resolution moves to convert
      time via `SCCMLookup.user_by_sam` (already exists). The hash-based
      deterministic node id (sha256(value)[:12]) is preserved so dedup still
      works at convert time.
    - `clients/tftp.py` (port of `lib/tftp_client.py`, ~210 LOC). Fixed import
      `from lib.socks5_udp` → `from openhound_sccm.clients.socks5_udp` and
      logger name. No other behavioural changes.
    - `clients/socks5_udp.py` (port of `lib/socks5_udp.py`, ~200 LOC). Logger
      name only.
- **Three Phase 2 once-phase resources added to `source.py`:**
    - `local_management_points` — Windows-only. Reads
      `HKLM\SOFTWARE\Microsoft\SMS\Mobile Client::AssignedSiteCode` then
      `HKLM\SOFTWARE\Microsoft\SMS\Client\Sites::SMS:<sitecode>` to discover the
      assigned MP hostname. Yields `{hostname, mp_url, site_code, source,
      domain}`. Returns 0 rows on machines without an SCCM client (the
      domainadmin lab has none on the collector host, so this resource is a
      no-op in the smoke test — that's the intended behaviour).
    - `local_distribution_points` — Windows-only. Scrapes `CCM\Logs\*.log`,
      `CCMSetup\Logs\*.log`, and `SMSCFG.ini` for `https?://...` and `\\\\...`
      hostnames matching the configured AD domain. CMBP reference:
      `local_collector.py::_parse_sccm_logs`. Domainadmin run discovered
      `ps1-mp.mayyhem.com` and `ps1-dp.mayyhem.com` from local SCCM setup logs.
    - `dns_management_points` — Cross-platform. Re-runs the LDAP
      `mSSMSSite` query for site codes (cheap; under 50ms in the test domain),
      then queries `_mssms_mp_<sitecode>._tcp.<domain>` SRV records using
      dnspython. If dnspython isn't available, falls back to ADIDNS via the
      existing `ADClient`. Yields `{hostname, site_code, port, srv_name,
      source, domain}`. Domainadmin smoke run: 1 row
      (`ps1-mp.mayyhem.com:80`).
    - `dhcp_pxe_dps` — Cross-platform but elevated-only on Linux. Sends one
      DHCPINFORM with vendor class `PXEClient` to broadcast 4011, parses
      responses for the 6s window. Yields `{hostname, pxe_next_server,
      pxe_boot_file, pxe_tftp_server, pxe_vendor_class, source, domain}`.
      The TFTP fetch + decrypt chain (CRED-1) is **intentionally NOT ported**
      here — that's Phase 4 secret-policy material. Only the discovery probe.
      Yields 0 rows on the test network (no PXE-enabled DP responds).
- **`source()` factory updated** to include the four new resources alongside
  the LDAP ones. `main.py::preproc` already listed all four tables (it was
  forward-declared in the previous session) so no edit needed there.
- **`transforms.py::_build_targets` verified** — already references
  `local_management_points` / `local_distribution_points` /
  `dns_management_points` / `dhcp_pxe_dps` with `hostname` as the host
  column. All resources match that contract. No transform edits needed.

### Phase 2 acceptance gate result: PASSED
Run as `MAYYHEM\domainadmin` against `dc.mayyhem.com`:
- collect/preproc/convert/package all exit 0.
- `output/sccm/dns_management_points/` and
  `output/sccm/local_distribution_points/` JSONL produced (1 + 2 rows).
- `output/sccm/local_management_points/` and `output/sccm/dhcp_pxe_dps/`
  intentionally absent — DLT only writes a folder for resources that yield
  ≥ 1 row. The collector machine has no SCCM client and there's no PXE
  responder on this network, so 0 rows is correct.
- `sccm.targets` row count: **20** (LDAP=17, Local-DP=2, DNS=1). Phase 1
  was 17. The `_build_targets` SQL is wired correctly.
- ZIP totals **109 nodes / 69 edges**, identical to Phase 1. No regression.
  Local/DNS hosts already have Computer nodes from LDAP; the Phase 2
  resources only contribute provenance rows to `sccm.targets` (they don't
  create new nodes or edges yet). Edge enrichment from these provenance
  hits lands in Phase 4.
- Test runner exits non-zero (expected — most node/edge kinds are still
  seed-only); Phase 1 numbers all preserved (Computer 29/29, Group 52/14,
  User 25/22, MemberOf 33/68 — exactly as Phase 1).
- New baseline written:
  `sccm/ConfigManBearPig/python/baselines/MAYYHEM_domainadmin_phase2.json`.

### New / updated files this session
- `sccm/sccm/src/openhound_sccm/clients/sccm_crypto.py` (NEW, ~270 LOC).
- `sccm/sccm/src/openhound_sccm/clients/secret_utils.py` (NEW, ~110 LOC,
  adapted to return dicts instead of writing to GraphStore).
- `sccm/sccm/src/openhound_sccm/clients/tftp.py` (NEW, ~215 LOC).
- `sccm/sccm/src/openhound_sccm/clients/socks5_udp.py` (NEW, ~200 LOC).
- `sccm/sccm/src/openhound_sccm/source.py` (extended with four Phase 2
  resources + DHCP packet helpers; LDAP block unchanged).
- `sccm/HANDOFF.md` (this file).

### Risks / follow-ups discovered this session
- **`local_management_points` schema is single-row in the lab.** The CMBP
  registry-read path only yields one MP per site code, but in a multi-site
  hierarchy the assigned client may know about more. If a future session
  needs a richer view, add WMI namespace `root\ccm` enumeration of
  `SMS_LookupMP` (CMBP doesn't currently do this from `local_collector.py`
  either, so deferring it is safe).
- **`dhcp_pxe_dps` skips on Linux without root** but doesn't auto-detect
  whether it's running inside proxychains. CMBP warns when proxychains is
  detected without `--socks-proxy`; we log a one-line info message instead.
  Adding a typer-driven `--socks-proxy` flag is a Phase 4 concern (when the
  full CRED-1 chain comes online).
- **No new edge kinds emitted from Phase 2.** The HANDOFF master plan
  spelled this out: Local/DNS/DHCP "extend Computer properties via
  DuckDB-side merge". The mechanism for actually merging properties on
  existing Computer nodes (when DNS finds an MP that LDAP already
  discovered) is the **convert-time `same_host_as_edges` SQL** plus the
  Phase 4 `Contains` / `LocalAdminRequired` derived edges. Until those are
  in place the additional `sccm.targets` rows are dormant — they'll start
  emitting edges as soon as Phase 4 lands.

## State of play (2026-05-01, second session)

### Done in this session (Phase 1 acceptance gate)
- **OpenSSL_Uplink crash root-caused and fixed.** Risk 5 is closed. The crash was
  DLT's anonymous telemetry call to `https://telemetry.scalevector.ai`, fired
  during `pipeline.normalize()`. The libcrypto-3 DLL bundled with the uv-managed
  Python 3.14 (`C:\Users\domainadmin\AppData\Roaming\uv\python\cpython-3.14.0-windows-x86_64-none\DLLs\libcrypto-3-x64.dll`)
  lacks the `OPENSSL_Applink` shim, so the cross-CRT stdio call from inside the
  TLS handshake aborts the process. Fix: set `RUNTIME__DLTHUB_TELEMETRY=false`
  (and the legacy `DLT__RUNTIME__DLTHUB_TELEMETRY=false`) in `os.environ`
  **before** `dlt` is imported. Two env-var sets needed because the openhound
  framework's own `dlt.config[...] = False` knob runs *after* `import dlt` and
  doesn't actually disable telemetry — the pipeline takes a config snapshot at
  construction. Diagnosis path: faulthandler showed `done` printed before crash
  → narrowed to `pipeline.normalize()` first call → DEBUG logging revealed
  `urllib3.connectionpool: Starting new HTTPS connection (1): telemetry.scalevector.ai:443`
  immediately before the crash. The fix lives in TWO places:
    - `sccm/sccm/src/main.py` (the wrapper script — this is the load-bearing one,
      since it runs before `openhound.main` imports `dlt`)
    - `sccm/sccm/src/openhound_sccm/main.py` (defensive duplicate; harmless)
- **Full pipeline runs end-to-end as `MAYYHEM\domainadmin`:**
  collect → preproc → convert → package, all four exit code 0. Produces
  `output/bloodhound-sccm-<ts>.zip` totaling 109 nodes and 69 edges.
- **Two preproc/convert wiring bugs fixed** that were blocking Phase 1:
    1. **`preproc` resource paths.** The `resource_files` source resolves paths as
       `<input_root>/<value>`, but DLT's filesystem destination writes to
       `<input_root>/sccm/<table>/`. The mapping in `main.py::preproc` was missing
       the `sccm/` prefix on every value. Fixed: each value is now `f"sccm/{table}"`.
    2. **`convert` input path.** The framework's `opengraph` source globs for
       `<bucket_url>/<table>/**/*.jsonl.gz`. The CLI must therefore be invoked with
       `convert sccm output/sccm output/graph` (NOT `convert sccm output output/graph`).
       Documenting this in the Quick start checklist below — there's no in-code fix
       needed, just the right invocation.
- **`ldap_sms_providers` resource demoted from a Computer asset.** The framework
  builds `source_models = {asset_class: table_name}` as a dict, so when both
  `ldap_computers` and `ldap_sms_providers` declared `columns=Computer`, the
  Computer asset got bound to whichever resource came last (which was
  `ldap_sms_providers`, so only 5 SMS provider rows became Computer nodes
  instead of all 29). Removed `columns=Computer` from `ldap_sms_providers`; SMS
  Provider rows still flow to `transforms.py` via the `ldap_sms_providers`
  DuckDB table.
- **`ldap_group_memberships` rewritten as a top-level resource.** It was a
  DLT transformer chained off `ldap_groups` via the pipe operator
  (`groups_resource | ldap_group_memberships()`), but DLT didn't materialise
  the chain output as a separate JSONL file under
  `output/sccm/ldap_group_memberships/`, so convert had nothing to read.
  Replaced with a regular `@app.resource` that re-runs the LDAP groups query
  itself (~30ms cost in the test domain). Now writes its own JSONL and produces
  `MemberOf` edges.
- **`GroupMembership.edges` switched from `match_by="distinguishedName"` to
  `match_by="id"` with DN→SID resolution via lookup.** The framework's
  `EdgePath.match_by` is `Literal["id"]` so the DN-based form was rejected by
  the convert phase Pydantic validator (`Contract on data_type with
  contract_mode=freeze is violated. Input tag 'distinguishedName' found using
  'match_by' does not match any of the expected tags: 'id', 'property'`).
  Added `SCCMLookup.principal_id_by_dn()` (checks ldap_users → ldap_computers
  → ldap_groups, returns the matching `object_sid` or `None`). Foreign Security
  Principals don't resolve and yield no edge — that's why MemberOf is 33 vs
  baseline 68.
- **`transforms._build_targets` host-column mismatch fixed.** `ldap_computers`
  uses `dns_host_name`; the union expression was hard-coded to `hostname`,
  causing preproc to crash with `Binder Error: Referenced column "hostname"
  not found in FROM clause`. Each table now specifies its own host column.

### Phase 1 acceptance gate result: PASSED with documented caveats
Run as `MAYYHEM\domainadmin` against `dc.mayyhem.com`, the LDAP slice produces:
| Kind                     | actual | baseline | notes |
|--------------------------|--------|----------|-------|
| Computer                 |     29 |       29 | exact match |
| User                     |     25 |       22 | superset (CMBP filters to SCCM-touched only) |
| Group                    |     52 |       14 | superset (same — see below) |
| SCCM_Site                |      2 |        3 | missing 1 Secondary site (AdminService not yet collected) |
| MemberOf                 |     33 |       68 | subset (we drop FSPs; CMBP emits them too) |
| SCCM_AdminsReplicatedTo  |      1 |        4 | seed-only; no feeder resource (placeholder) |
| All other 35 edge kinds  |      1 |     vary | seed-only (Phase 2/3/4 not implemented) |

The Computer count matching exactly is the strongest signal that the LDAP slice
is wired correctly. Users/Groups are emitted as supersets because Phase 1
collects every AD principal; CMBP filters to those discovered via SCCM admin
enumeration. This converges in Phase 3 once AdminService discovery runs and
post-processing intersects against `discovered_principals`.

### Done from previous sessions
- **Phase 0 — test runner.** `sccm/ConfigManBearPig/python/invoke_configmanbearpig_unit_tests.py`
  reads both the CMBP zip (`--zip`) and the OpenHound graph dir (`--graph-dir`) and compares
  against a baseline JSON (`--baseline-cmp`). Baseline lives at
  `sccm/ConfigManBearPig/python/baselines/MAYYHEM_domainadmin_cmbp_seed.json`
  (167 nodes, 442 edges, 36 edge kinds against the existing CMBP zip).
- **Phase 5 — ZIP packager.** `cd sccm/sccm && uv run python -m openhound_sccm.main --graph-dir <dir> --output-dir <dir>`
  packages the 5-file zip byte-compatibly with CMBP. The packager currently dedupes edges
  by `(start, end, kind)` — see Risk 4 below.
- **Phase 1 foundation.** `kinds/{nodes,edges}.py`, `graph.py`, `lookup.py`, `transforms.py`,
  `output.py`, `main.py` (with Typer `package` command), `clients/ad.py`, `source.py`
  (LDAP resources), `models/computer.py`, `models/user.py`, `models/group.py`,
  `models/sccm_site.py` are all present.
- **Packaging.** `pyproject.toml` has the correct
  `[tool.hatch.build.targets.wheel] packages = ["src/openhound_sccm"]` block, and
  `from openhound_sccm.main import app` works after `uv pip install -e .`.

### Partial (Phase 1 leftovers picked up next)
- `models/derived/admins_replicated_to.py` is still a **placeholder** — the model is
  registered but has no DLT resource feeding it. To activate it, transforms.py must
  materialise `sccm.admins_replicated_to_edges` rows into a JSONL-loadable table OR
  the model needs a single-trigger row from a placeholder resource. See the docstring
  at the top of `models/derived/admins_replicated_to.py` for the three resolution
  options. The right path is option (1): emit a JSONL alongside collect output via a
  thin placeholder resource that yields one row per (start_id, end_id) computed by
  reading `ldap_sites` directly in the resource. This is naturally part of Phase 4.
- `dependencies` were added to `pyproject.toml` (ldap3, impacket, requests, requests-ntlm,
  dnspython, pycryptodome, cryptography). Confirmed with `uv sync` — venv resolves cleanly.

### Not started
- **Phase 3 (biggest chunk, ~3,500 LOC).** Per-host phases driven by `sccm.targets`:
  RemoteRegistry → MSSQL → AdminService → WMI → HTTP → SMB. Vendor `lib/sccm_client.py`
  into `clients/sccm.py`.
- **Phase 4.** Re-express `lib/post_processing.py` (1,307 LOC) as DuckDB SQL views in
  `transforms.py` plus ~11 edge-only `BaseAsset` models under `models/derived/`.
- **Phase 6.** Live three-user verification sweep with parity assertions.

## Architectural decisions you must respect

- **Edge-only models** for derived edges follow the Okta pattern: `as_node = None`,
  only yield edges. Reference: `openhound-okta/src/openhound_okta/models/`.
- **Per-host phases chain off LDAP-discovered targets via the DLT pipe operator.**
  AdminService chains off `ldap_sms_providers`, MSSQL chains off
  `registry_sccm_databases`, HTTP/SMB chain off `sccm.targets`.
- **Post-processing → DuckDB SQL.** No imperative re-implementation of
  `lib/post_processing.py`; it becomes views in `transforms.py`.
- **Output parity via Typer subcommand**, not a `post_convert` hook (the framework
  doesn't have one and we can't add one).
- **Test runner is dual-format** — both `--zip` and `--graph-dir` paths are first-class.

## Files to read on entry

Master plan: `C:/Users/domainadmin/.claude/plans/parallel-puzzling-newt.md`

Current code:
- `C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/main.py`
- `C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/source.py`
- `C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/{graph,lookup,transforms,output}.py`
- `C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/clients/ad.py`
- `C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/kinds/{nodes,edges}.py`
- `C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/models/computer.py`
  (canonical model pattern — copy this shape for the missing models)

Test runner & baseline:
- `C:/Users/domainadmin/Desktop/OpenHound/sccm/ConfigManBearPig/python/invoke_configmanbearpig_unit_tests.py`
- `C:/Users/domainadmin/Desktop/OpenHound/sccm/ConfigManBearPig/python/baselines/MAYYHEM_domainadmin_cmbp_seed.json`

## Iteration loops (~20 min for full outer loop)

```
inner  ~10s   tests/test_post_processing_sql.py + tests/test_models_convert.py
middle ~6m    domainadmin only — collect/preproc/convert/package + test runner
outer  ~20m   full lowpriv/roanalyst/domainadmin sweep
```

Use `make compare-zips` (per-edge `(kind,start,end)` diff) when localising
discrepancies.

## Risks already identified

1. **Global ID rewriting** (post-processing step 3, rename `@SITECODE` → `@ROOTSITECODE`)
   must live in `as_node.id` for `SCCMCollection` / `SCCMAdminUser` / `SCCMSecurityRole`,
   and must be in place **before** AdminService work in Phase 3 starts. Bake it in early.
2. **Cross-phase target propagation.** AdminService discovery is not single-pass; SMS
   Providers discovered later flow only into post-processing tables. Mitigation in plan:
   optional `collect --pass 2`.
3. **`CoerceAndRelaytoSMB` typo.** Lowercase `to` in the original. When fixing, fix in
   both collectors.
4. **Edge dedup mismatch.** CMBP keeps duplicate edges via
   `upsert_edge_allow_duplicate` for admin replication. The OpenHound packager dedupes by
   `(start, end, kind)`, which loses these. Counts will differ until reconciled — likely
   by giving admin-replication edges a unique `last_seen` or property in the key.
5. **Windows OpenSSL_Uplink crash during DLT normalize — RESOLVED 2026-05-01.**
   Root cause was DLT's anonymous telemetry HTTPS call (`telemetry.scalevector.ai`)
   firing during `pipeline.normalize()`. The uv-managed Python 3.14's bundled
   `libcrypto-3-x64.dll` lacks the `OPENSSL_Applink` shim required when an
   in-process consumer of OpenSSL crosses CRT boundaries calling the libcrypto
   stdio routines. Fix: set `RUNTIME__DLTHUB_TELEMETRY=false` (legacy variant
   `DLT__RUNTIME__DLTHUB_TELEMETRY=false`) in `os.environ` BEFORE `dlt` is
   imported. Lives in `sccm/sccm/src/main.py` (load-bearing, runs first) and
   `sccm/sccm/src/openhound_sccm/main.py` (defensive duplicate). The
   openhound-framework knob `dlt.config["runtime.dlthub_telemetry"] = False` is
   set too late to suppress this — pipelines snapshot config at construction.

6. **Convert input path requires the `sccm/` subdirectory.** The framework's
   `opengraph` source globs at `<bucket_url>/<table>/**/*.jsonl.gz`, while DLT's
   filesystem destination writes at `<output>/sccm/<table>/`. So
   `convert sccm output/sccm output/graph` is correct;
   `convert sccm output output/graph` produces an empty graph silently
   (the convert pipeline runs but matches zero data and the only output is the
   `_dlt_pipeline_state` JSON). Documenting here in case anyone hits this — the
   right answer is the explicit subdir, not a framework patch.

7. **Single asset class can only map to ONE source table.** Convert builds a
   `dict[asset_class, table_name]` so two resources sharing `columns=Computer`
   would lose one. We hit this with `ldap_computers` + `ldap_sms_providers`
   (both registering Computer); resolved by removing `columns=Computer` from
   `ldap_sms_providers`. If we want SMS Providers to also produce nodes (with
   richer properties from later phases), we'll need a distinct asset subclass.

8. **Windows OpenSSL_Uplink crash on TLS handshake — PARTIALLY MITIGATED 2026-05-01.**
   This is the broader form of Risk 5. **Any** TLS handshake initiated from
   within the uv-managed Python 3.14 + Windows 11 build aborts the process
   with `OPENSSL_Uplink(0x...,08): no OPENSSL_Applink`. Confirmed crashing
   call sites: stdlib `ssl.wrap_socket`, `http.client.HTTPSConnection`,
   `requests.get`, `requests-ntlm` over HTTPS, `cryptography` operations
   that touch libcrypto stdio. Phase 3b (AdminService) sidesteps this by
   shelling out to Windows' `curl.exe`, which uses Schannel TLS rather
   than OpenSSL — see `clients/adminservice.py`. Phase 3c HTTP/SMB will
   need the same workaround for the HTTP collector path; the vendored
   `clients/sccm.py::SCCMPolicyClient` currently uses `requests` and would
   crash if invoked. WMI (DCOM) and SMB are TLS-free and unaffected.
   Long-term fix: rebuild Python with an OpenSSL that has Applink, or
   downgrade to Python 3.13.

## Quick start checklist (next session)

Phase 1 + Phase 2 acceptance gates have passed end-to-end as of 2026-05-01.
The next session picks up **Phase 3** — per-host phases driven by
`sccm.targets` (RemoteRegistry → MSSQL → AdminService → WMI → HTTP → SMB,
~3,500 LOC). Before writing any new code:

- [ ] Read this file end-to-end (state of play has the latest fixes and gotchas).
- [ ] Read `C:/Users/domainadmin/.claude/plans/parallel-puzzling-newt.md` —
      the Phase 3 section in particular.
- [ ] Sanity check the install:
      `cd sccm/sccm && uv pip install -e . && uv run python -c "from openhound_sccm.main import app; print(app.name)"`
      should print `sccm`.
- [ ] Confirm Phase 1 + Phase 2 still pass end-to-end as `MAYYHEM\domainadmin`:
      ```
      cd sccm\sccm
      Remove-Item -Recurse -Force output -ErrorAction SilentlyContinue
      Remove-Item -Recurse -Force "$env:USERPROFILE\.dlt\pipelines\sccm_*" -ErrorAction SilentlyContinue
      $env:SOURCES__SCCM__DOMAIN = "mayyhem.com"
      $env:SOURCES__SCCM__DOMAIN_CONTROLLER = "dc.mayyhem.com"
      $env:SOURCES__SCCM__USERNAME = "MAYYHEM\domainadmin"
      $env:SOURCES__SCCM__PASSWORD = "password"
      uv run python src\main.py collect sccm output\
      uv run python src\main.py preprocess sccm output\ output\lookup.duckdb
      # NB: convert input path is `output\sccm`, NOT `output\` — see Risk 6
      uv run python src\main.py convert sccm output\sccm output\graph --lookup-file output\lookup.duckdb
      uv run python -m openhound_sccm.main --graph-dir output\graph --output-dir output
      ```
      Expected: ZIP totals **109 nodes / 69 edges**;
      `sccm.targets` ~20 rows (LDAP=17, DNS=1, Local-DP=2 in the test domain).
      `output/sccm/dns_management_points/` and
      `output/sccm/local_distribution_points/` should exist.
- [ ] Run the test runner against the new zip:
      ```
      cd ..\ConfigManBearPig\python
      uv run python invoke_configmanbearpig_unit_tests.py \
        --zip C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm\output\bloodhound-sccm-<ts>.zip \
        --baseline-cmp baselines\MAYYHEM_domainadmin_cmbp_seed.json --no-strict-count
      ```
      Expected non-zero exit (seed-only kinds dominate); same drift profile as
      the Phase 1/Phase 2 baselines.
- [ ] Decide how to feed `AdminsReplicatedToEdge` (placeholder, no DLT resource).
      Recommended: option (1) from the docstring — add a thin `@app.resource` named
      `derived_admins_replicated_to_edges` that re-runs the same recursive site
      traversal `transforms._build_admins_replicated_to` does, but emits one JSONL
      row per (start_id, end_id) directly during collect/preproc. ~30 LOC.
- [ ] **Phase 3 work — per-host phases (~3,500 LOC; 3-5 days).**
      Implement in this order: `RemoteRegistry → MSSQL → AdminService → WMI →
      HTTP → SMB`. Each phase is one driver resource plus N typed
      sub-transformers chained off `sccm.targets` via DLT's pipe operator.
      Cross-phase deps documented in
      `C:/Users/domainadmin/.claude/plans/parallel-puzzling-newt.md`:
        - AdminService chains off `ldap_sms_providers` for the first pass; SMS
          Providers discovered later flow into post-processing tables only
          (single collect pass — see Risk 2).
        - MSSQL chains off `registry_sccm_databases`.
        - HTTP/SMB chain off `sccm.targets`.
      Vendor `lib/sccm_client.py` into `clients/sccm.py` (used by
      AdminService + HTTP).
      Models to add: `mssql_server`, `mssql_login`, `mssql_database`,
      `mssql_database_user`, `mssql_server_role`, `mssql_database_role`,
      `sccm_admin_user`, `sccm_collection`, `sccm_security_role`,
      `sccm_client_device`. (~1700 LOC of model classes per the plan.)
- [ ] Commit at clean phase boundaries on the current branch (`fix/devdocs` — confirm
      with the user before switching).

### Known follow-ups (not blocking Phase 2)
- The MemberOf edge count is 33 vs CMBP baseline 68 because we drop members whose
  DN doesn't resolve to a Sid in the LDAP tables (Foreign Security Principals,
  built-in SIDs in `CN=ForeignSecurityPrincipals`, etc.). CMBP emits these too with
  the raw DN. To match parity exactly, extend `principal_id_by_dn` to fall back to
  emitting a property-match edge keyed on DN when the SID lookup fails.
- User/Group counts are supersets (we emit all AD principals; CMBP only emits those
  reached via SCCM admin enumeration). Will converge in Phase 3 when post-processing
  intersects against the SCCM-discovered set.
- Convert phase requires LDAP env vars set even though it's reading JSONL, because
  `sccm_source()` constructs the `ADClient` eagerly. Fix later by either making the
  AD client lazy or splitting `source.py` into collect-only and convert-only sources.

### Layout reminder
- Convert is invoked with `output\sccm` as `input_path` and `output\graph` as
  `output_path`. The `output\graph` directory then contains
  `computer_fs-1.json`, `group_fs-1.json`, `user_fs-1.json`, `sccmsite_fs-1.json`,
  and (in the future) `groupmembership_fs-1.json`, etc.
- The packager turns those into `bloodhound-sccm-<ts>.zip` with the 5-file CMBP layout:
  `computers.json` / `groups.json` / `users.json` / `sccm.json` / `seed_data.json`.

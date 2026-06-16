# SCCM preproc + convert — design spec

**Date:** 2026-06-16
**Scope:** Port the post-processing / graph-building logic of `ConfigManBearPig.ps1` (CMBP) into the
OpenHound SCCM collector's `preproc` and `convert` phases. The `collect` phase is complete and
unchanged.
**Reference tool:** `sccm/ConfigManBearPig.ps1` (CMBP) — all `:NNNN` citations are line numbers in
that file unless noted.

---

## 1. Current state (the real starting line)

`collect` is done and produces ~45 raw JSONL tables (adminservice_*, wmi_* fallback, remoteregistry_*,
mssql_server_instances, http_*, smb_*, ldap_*, dns_*, local_*). Identities that CMBP resolves inline
during collection are **already resolved to SIDs** by the collectors (LDAP/AD objects,
`adminservice_admins.AdminSid`, `r_system.SID`, `r_user.SID`, reserved/site-server/SQL-server
principals). See [privileged.py:19-21](../../src/openhound_sccm/collectors/privileged.py#L19-L21):
device users and `SecurityGroupName[]` are deliberately left **name-only** for downstream resolution.

The preproc/convert side is dismantled and must be rebuilt from scratch:

- `transforms.py`, `lookup.py`, `graph.py` — **deleted**, but `main.py:32` still
  `from .transforms import transforms` and `main.py:1135` registers `@app.preproc(transformer=transforms)`,
  so the package **does not import** today.
- **No `@app.convert`** anywhere.
- `models/__init__.py` imports `from .sccm_site import SCCMSite` and describes an "11 derived edge
  models + DerivedEdges aggregator" design — **none of those files exist**.
- `kinds/edges.py` is **empty**.
- `_preproc_table_map()` ([main.py:1067](../../src/openhound_sccm/main.py#L1067)) lists table names that
  **do not match** the real collected tables (e.g. `ldap_computers`, `registry_sccm_databases`,
  `smb_signing_status`, `mssql_epa_flags`). It is stale and must be rebuilt from the actual collect
  output.
- The README documents a previous design state that no longer exists in code.

Target graph (from CMBP): **15 node kinds + ~35 edge kinds**.

---

## 2. Locked decisions

1. **Preproc coalesces + writes JSONL; convert is thin readers.** preproc loads raw JSONL into DuckDB,
   builds coalesced **one-row-per-entity** node tables and a derived `graph_edges` table, then writes
   each back into the convert bucket as gzipped JSONL. Convert binds a trivial typed model per table:
   `row → node` / `row → edge`. Rationale: `convert` can only iterate JSONL from the bucket (the preproc
   DuckDB is reachable only via `self._lookup`), and SCCM assembles one node (e.g. a `Computer`) from
   many raw tables — coalescing must happen in preproc SQL. See §4.
2. **Offline identity resolution, no collect changes.** preproc builds a `principal_by_name` table from
   the union of every collected `(name, SID)` pair (r_user, r_system, ldap/AD objects, admins, reserved).
   Name-only fields (device users, `SecurityGroupName[]`, SQL service account) are resolved by joining
   against it; unresolved → the edge/node is dropped (matches CMBP's drop-on-failure at
   `Resolve-PrincipalInDomain` :459-904). Logged at warning level.
3. **Active MSSQL only.** Port the two live builders (`Add-MSSQLServerNodesAndEdges` :6050-6186 and
   `Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer` :6187-6292) plus `MSSQL_GetTGS` :1965-1978,
   `MSSQL_ServiceAccountFor`/`GetAdminTGS` :8012-8016, and `MSSQL_AssignAllPermissions` (db→site)
   :6173-6180. **Skip** the decommissioned `Add-MSSQLNodesAndEdgesForPrimarySite` :6293 (call site
   commented at :6539).
4. **Faithful-but-fixed.** Bug fixes folded in (§7): compute `rootSiteCode` *first* so node IDs are
   minted final (eliminates the `@siteCode`→`@rootSiteCode` rewrite, `Update-GlobalObjectIdentifiers`
   :2397); replace O(n²)/O(n³) array scans with set-based SQL; normalize `collectionSource`/
   `CollectionSource` casing; prefer the collected SQL port over hardcoded `:1433`. Possible/inferred
   edges (coerce-and-relay, EPA/SMB-signing assumptions) preserved but clearly labeled, honoring the
   "Allowed/Required" EPA-uncertainty convention and `--disable-possible-edges`.
5. **Explicit exclusions** (dead/superseded CMBP code, not ported): the `Host` node
   (`Add-HostNodeAndEdges` :2373, unused by the main flow); the WMI graph-emit functions :8210-8600
   (they never `Upsert`; the `wmi_*` raw tables feed the same coalescing as `adminservice_*`); the
   superseded `Invoke-ProcessRoleAssignments` :1986 duplicate.

### Open design points (resolve at spec review / Stage 1)

- **Root/environment node.** OpenHound requires one root/environment node and `environmentid` on every
  emitted node. CMBP has none (it merges into existing BloodHound AD data by ObjectIdentifier).
  *Proposed default:* emit a single SCCM environment node = the **hierarchy root site** (top
  CAS/primary), set `environmentid` to it on all SCCM/MSSQL nodes, and **leave Base AD
  (Computer/User/Group) `environmentid` aligned to their AD domain** so they merge cleanly with
  SharpHound data rather than being re-homed under the SCCM environment. Needs confirmation against
  BloodHound's OpenGraph conventions.
- **Edges via writeback vs lookup.** Default: materialize `graph_edges` and read it with thin edge
  models (uniform, most testable). Alternative: keep edges lookup-driven (github-style fan-out) to
  avoid writing a large edge file. Adjustable per stage.

---

## 3. Node & edge inventory (the "nothing is lost" ledger)

"PS1 creation" = where CMBP creates it: **inline** (during collection via `Upsert-Node`/`Upsert-Edge`)
or **post-proc** (`Invoke-PostProcessing` :1577-1984). Every item maps to a port stage.

### Nodes (15)

| Kind | PS1 creation | Stage | Preproc table | Convert model |
|---|---|---|---|---|
| `Computer` (+`Base`) | inline (many sites) | 1 | `node_computer` | `ComputerNode` |
| `User` (+`Base`) | inline | 1 | `node_user` | `UserNode` |
| `Group` (+`Base`) | inline | 1 | `node_group` | `GroupNode` |
| `Group` (Authenticated Users, `$Domain-S-1-5-11`) | post-proc relay :6609/6708/6766 | 6 | `node_group` | `GroupNode` |
| `SCCM_Site` | inline :7043 (+LDAP/local/http/smb/registry) | 1 | `node_site` | `SCCMSite` |
| `SCCM_ClientDevice` | inline :7220 (+possible-client :3272) | 2 | `node_client_device` | `SCCMClientDevice` |
| `SCCM_Collection` | inline :7532 | 2 | `node_collection` | `SCCMCollection` |
| `SCCM_AdminUser` | inline :7767 | 2 | `node_admin_user` | `SCCMAdminUser` |
| `SCCM_SecurityRole` | inline :7700 | 2 | `node_security_role` | `SCCMSecurityRole` |
| `MSSQL_Server` | inline :6085 | 5 | `node_mssql_server` | `MSSQLServer` |
| `MSSQL_Database` | inline :6137 | 5 | `node_mssql_database` | `MSSQLDatabase` |
| `MSSQL_ServerRole` | inline :6101 | 5 | `node_mssql_server_role` | `MSSQLServerRole` |
| `MSSQL_DatabaseRole` | inline :6151 | 5 | `node_mssql_database_role` | `MSSQLDatabaseRole` |
| `MSSQL_Login` | inline :6229 | 5 | `node_mssql_login` | `MSSQLLogin` |
| `MSSQL_DatabaseUser` | inline :6245 | 5 | `node_mssql_database_user` | `MSSQLDatabaseUser` |

### Edges (~35)

| Kind | Start → End | PS1 creation | Stage |
|---|---|---|---|
| `SCCM_AdminsReplicatedTo` | Site ↔ Site | post-proc :1604-1626 | 1 |
| `SCCM_IsMappedTo` | AD principal → AdminUser | inline :7789-7804 | 2 |
| `SCCM_IsAssigned` | AdminUser → Collection/SecurityRole | inline :7819/7841/7867 | 2 |
| `SCCM_HasMember` | Collection → member | inline :7617-7629 | 2 |
| `SCCM_HasClient` | Site → ClientDevice | inline :7257/7394 | 2 |
| `SCCM_HasPrimaryUser` | ClientDevice → User | inline :7298 | 2 |
| `SCCM_HasCurrentUser` | ClientDevice → User | inline :7275 | 2 |
| `SCCM_HasADLastLogonUser` | ClientDevice → User | inline :7266 | 2 |
| `SCCM_HasStoredAccount` | Site → User/Group | inline :7147 | 2 |
| `SCCM_HasNetworkAccessAccount` | Computer → User | inline :4185 | 2 |
| `MemberOf` | Computer/User → Group | inline :7375/7470 | 2 |
| `HasSession` | Computer → User | inline :8007/5029 | 2 |
| `SCCM_Contains` | Site → Collection/Role/AdminUser | post-proc :1659-1690 | 3 |
| `SCCM_FullAdministrator` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_ApplicationAuthor` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_ApplicationAdministrator` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_ComplianceSettingsManager` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_OSDManager` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_OperationsAdministrator` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_SecurityAdministrator` | AdminUser → ClientDevice | post-proc :1714-1827 | 3 |
| `SCCM_AllPermissions` | AdminUser → Site | post-proc :1730-1837 | 3 |
| `SCCM_AssignAllPermissions` | Computer(SMS Provider) → Site | post-proc :1932-1940 | 3 |
| `SameHostAs` | Computer ↔ ClientDevice | post-proc :2261-2311 | 4 |
| `LocalAdminRequired` | Computer → Computer | post-proc :1882-1909 | 4 |
| `MSSQL_Contains` | Server→DB / DB→role etc. | inline :6110-6160 | 5 |
| `MSSQL_ControlServer` | role → Server | inline :6101-6130 | 5 |
| `MSSQL_ControlDB` | role → DB | inline :6151-6172 | 5 |
| `MSSQL_HostFor` | Server → Computer | inline :6090-6120 | 5 |
| `MSSQL_ExecuteOnHost` | Server → Computer | inline :6090-6120 | 5 |
| `MSSQL_HasLogin` | Server → Login | inline :6230-6260 | 5 |
| `MSSQL_IsMappedTo` | Login → AD principal | inline :6232-6260 | 5 |
| `MSSQL_MemberOf` | Login → role / user → dbrole | inline :6260-6286 | 5 |
| `MSSQL_ServiceAccountFor` | User(SID) → Server | inline :8012 | 5 |
| `MSSQL_GetAdminTGS` | User(SID) → Server | inline :8016 | 5 |
| `MSSQL_GetTGS` | service acct → Login | post-proc :1965-1978 | 5 |
| `MSSQL_AssignAllPermissions` | Database → Site | inline :6173-6180 | 5 |
| `CoerceAndRelayToAdminService` | Auth Users → Site | post-proc :6572-6623 | 6 |
| `CoerceAndRelayToMSSQL` | Auth Users → MSSQL_Login | post-proc :6626-6724 | 6 |
| `CoerceAndRelayToSMB` | Auth Users → Computer | post-proc :6728-6779 | 6 |

> Exact MSSQL line sub-ranges (`:6110-6286`) are approximate from analysis; the implementer confirms
> them per stage. The traversable-flag allow-list lives at CMBP :2216-2255 and feeds Stage 0's
> `seed_data` / edge declarations.

---

## 4. Preproc → convert mechanism

### Preproc (`transforms.py` + `main.py`)

1. `main.py` `preproc(ctx)` stashes `ctx.pipeline.input_path` (the bucket) for the transformer, then
   returns the corrected raw-table map (DuckDB table → JSONL path under `sccm/<real_table>`).
2. `transforms(con)`:
   - **Coalesce** each entity into a one-row-per-ID table (`node_computer`, `node_user`, `node_group`,
     `node_site`, `node_client_device`, `node_collection`, `node_admin_user`, `node_security_role`,
     `node_mssql_*`) via `GROUP BY` + array `UNION` — this is CMBP's `Upsert-Node` merge as SQL
     (:1444-1575). `rootSiteCode` is computed here (hierarchy BFS, CMBP :2511/2620) so SCCM object IDs
     are minted final.
   - **Lookups**: `principal_by_name`, `resource_to_sid`, `device_by_resourceid`, `site_root`,
     `sites_in_hierarchy`.
   - **Derived edges**: build `graph_edges(start_id, end_id, kind, properties)` by `UNION`-ing the
     per-edge-kind SELECTs (CMBP post-processing :1577-1984 + the inline edge logic).
   - **Writeback**: write each `node_*` table and `graph_edges` to `<bucket>/sccm/<table>/data.jsonl.gz`
     (DuckDB `COPY … (FORMAT JSON)`, or Python `gzip`+`json` fallback).

### Convert (`source.py` convert source + `models/*`)

- A convert source declares one DLT resource per coalesced table: `columns=<Model>`,
  `table_name=<node_* | graph_edges>`. The framework's `opengraph` reader globs
  `<bucket>/sccm/<table>/**/*.jsonl.gz` and instantiates `<Model>` per row.
- Node models: typed `<PREFIX>NodeProperties` dataclass (documented `Attributes`) + `as_node` returning
  the node. No edge logic.
- Edge model(s): read `graph_edges`; emit `Edge(kind=row.kind, start=EdgePath(row.start_id,
  match_by="id"), end=EdgePath(row.end_id, match_by="id"), …)`. `EdgeDef` declarations grouped by stage.
- `self._lookup` is still available for any residual point resolution.

### Validation of the mechanism (Stage 0 spike)

Prove DuckDB-written gzipped NDJSON round-trips through `read_jsonl` into a model end-to-end (one tiny
`graph_edges` row → one edge in the output). If `COPY … (FORMAT JSON)` gzip is fussy, switch the
writeback to Python `gzip`+`json`. Fallback if writeback proves unworkable: the github lookup-driven
pattern (`_find_all_objects`), documented in
[the OpenHound proposal](../../docs/proposals/2026-06-16-convert-read-from-duckdb.md).

---

## 5. Files touched

| File | Role |
|---|---|
| `src/openhound_sccm/transforms.py` | recreate — coalescing + derived-edge SQL + JSONL writeback |
| `src/openhound_sccm/lookup.py` | recreate — `SCCMLookup(LookupManager)` cached methods |
| `src/openhound_sccm/graph.py` | recreate — `SCCMNodeProperties`/`SCCMNode`/`SCCMEdgeProperties` |
| `src/openhound_sccm/kinds/edges.py` | populate — all edge-kind constants |
| `src/openhound_sccm/kinds/nodes.py` | keep (already complete) |
| `src/openhound_sccm/models/*.py` | one typed model per coalesced node table + edge model(s) |
| `src/openhound_sccm/models/__init__.py` | fix imports/exports to match real files |
| `src/openhound_sccm/source.py` | add the convert source returning model-bound resources |
| `src/openhound_sccm/main.py` | fix `transforms` import; rebuild `_preproc_table_map()`; register `@app.convert(lookup=SCCMLookup)`; stash bucket path |
| `README.md` | Node/Edge Reference, preproc/convert sections, mayyhem.com examples |

---

## 6. Stages

Each stage is independently runnable and ends with a **manual validation** block. Each maps to gtk
ticket(s). Standard test loop (collect once, reuse the raw JSONL):

```bash
# one-time: collect against the lab (or reuse an existing <raw> tree)
openhound preprocess sccm <raw> <raw>/lookup.duckdb
openhound convert sccm <raw>/sccm <graph> --lookup-file <raw>/lookup.duckdb
# then inspect <graph>/*.json for the kinds the stage adds
```

### Stage 0 — Unblock & scaffold
- **PS1:** export/seed_data structure :9523-9846; traversable allow-list :2216-2255.
- **Do:** recreate `graph.py` (base node/props/edge classes), `lookup.py` (`SCCMLookup` skeleton),
  `transforms.py` (no-op transform + the writeback helper + the Stage-0 spike table); fix `main.py`
  import; rebuild `_preproc_table_map()` to the real collected tables; register `@app.convert`;
  populate `kinds/edges.py`; fix `models/__init__.py`.
- **Validate:** package imports; `openhound preprocess sccm …` and `openhound convert sccm …` both run
  to completion; the spike `graph_edges` row appears as one edge in `<graph>`.

### Stage 1 — Base nodes + Site + hierarchy
- **PS1:** `Upsert-Node` merge semantics :1444-1575; AdminService site emit :7043; hierarchy
  `Get-SitesInHierarchy` :2511 / `Get-HierarchyRoot` :2620; `SCCM_AdminsReplicatedTo` :1604-1626;
  identity corpus :459-1131.
- **Do:** coalesce `node_computer`/`node_user`/`node_group`/`node_site`; compute `rootSiteCode`;
  `principal_by_name`. Emit Computer/User/Group/Base + SCCM_Site; `SCCM_AdminsReplicatedTo`. Decide the
  root/environment node (§2 open point).
- **Validate:** `computers.json`/`users.json`/`groups.json` + `SCCM_Site` nodes present with merged
  arrays (site-system roles unioned, no dup computer nodes per SID); `SCCM_AdminsReplicatedTo` matches
  the lab hierarchy; spot-check one site's `rootSiteCode`.

### Stage 2 — SCCM entities + inline edges
- **PS1:** ClientDevice :7220-7300; Collection :7532 (+HasMember :7617); AdminUser :7767 (+IsMappedTo
  :7789, IsAssigned :7819); SecurityRole :7700; HasStoredAccount :7147; Has*User :7266/7275/7298;
  HasNetworkAccessAccount :4185; MemberOf :7375/7470; HasSession :8007/5029; possible-client :3272.
- **Do:** coalesce `node_client_device`/`node_collection`/`node_admin_user`/`node_security_role`
  (IDs already `@rootSiteCode`); `resource_to_sid`, `device_by_resourceid`; build the inline edges.
- **Validate:** all four SCCM entity kinds present; spot-check an admin's `SCCM_IsMappedTo`/`IsAssigned`,
  a collection's `HasMember`, a device's `HasPrimaryUser`, a computer's `MemberOf`, against the lab.

### Stage 3 — Containment + RBAC fan-out
- **PS1:** `SCCM_Contains` :1659-1690; role fan-out + role-kind mapping :1714-1827; `SCCM_AllPermissions`
  :1730-1837; `SCCM_AssignAllPermissions` (SMS Provider) :1932-1940.
- **Do:** derived tables `contains`, `rbac_grants` (role→admin→collection→device, edge-kind column),
  `assign_all_permissions`; append to `graph_edges`.
- **Validate:** the 7 role edges + AllPermissions + AssignAllPermissions appear; pick a Full
  Administrator and confirm `SCCM_FullAdministrator` reaches the expected devices.

### Stage 4 — SameHostAs + LocalAdminRequired
- **PS1:** `Add-SameHostAsEdges` :2261-2311 (incl. duplicate-client-device merge preferring the
  `GUID:`-authoritative node); `LocalAdminRequired` mesh :1882-1909.
- **Do:** derived `same_host` (+ device-dedup logic) and `local_admin_required`; append to `graph_edges`.
- **Validate:** `SameHostAs` links each ClientDevice to its Computer by `ADDomainSID`; duplicate client
  devices merged; site-server `LocalAdminRequired` mesh present.

### Stage 5 — MSSQL (active)
- **PS1:** `Add-MSSQLServerNodesAndEdges` :6050-6186; `Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer`
  :6187-6292; `MSSQL_GetTGS` :1965-1978; `ServiceAccountFor`/`GetAdminTGS` :8012-8016;
  `AssignAllPermissions` (db→site) :6173-6180. **Skip** :6293.
- **Do:** `node_mssql_*` tables + the MSSQL edges; prefer the collected SQL port over `:1433`.
- **Validate:** MSSQL_Server/Database/ServerRole/DatabaseRole/Login/DatabaseUser nodes + their edges;
  confirm a sysadmin computer's `MSSQL_*` chain and `MSSQL_AssignAllPermissions` to the site.

### Stage 6 — Coerce-and-relay (possible edges)
- **PS1:** `Process-CoerceAndRelayToAdminService` :6572-6623; `…ToMSSQL` :6626-6724; `…ToSMB`
  :6728-6779; synthetic Authenticated Users node :6609/6708/6766.
- **Do:** `relay_candidates_{adminservice,mssql,smb}` with EPA/SMB-signing/NTLM gating, the
  possible-edge default, and `--disable-possible-edges`; emit Authenticated Users group node; EPA
  labeled per the uncertainty convention.
- **Validate:** with possible edges on, the three relay edges appear from Authenticated Users; with
  `--disable-possible-edges`, they don't; EPA labels read correctly.

### Stage 7 — Docs + validation
- **Do:** rewrite README (Node Reference, Edge Reference, preproc/convert, mayyhem.com examples,
  diagrams/tables); run `references/validate-extension.md` checks (ruff/mypy/pytest in an isolated uv
  env); remove dead refs.
- **Validate:** all checks pass or are reported-skipped; README matches emitted nodes/edges exactly.

---

## 7. Bug-fix register

| CMBP quirk | Location | Port handling |
|---|---|---|
| `@siteCode`→`@rootSiteCode` ID rewrite, lockstep edge mutation, regex misfire | :2397-2504 | Compute `rootSiteCode` first in preproc; mint final IDs once. Rewrite eliminated. |
| O(n²)/O(n³) `Upsert`/RBAC scans | :1477, :1714-1827 | Set-based SQL (`GROUP BY`/joins) in preproc. |
| Edges dropped when endpoint node not yet created | :2118-2127 | preproc materializes all nodes before convert emits edges; ordering is structural. |
| `collectionSource` vs `CollectionSource` casing | :9072/4696 | Normalize to one key during coalescing. |
| Hardcoded `:1433` | :6055/7997 | Use collected SQL port where available; fall back to 1433 only if unknown. |
| EPA/SMB-signing default-to-vulnerable assumptions | :6675-6681 etc. | Preserve intent; label inferred/possible per EPA-uncertainty convention; gate with `--disable-possible-edges`. |
| Dead WMI graph-emit / Host node / role-assignment dup | :8210-8600 / :2373 / :1986 | Not ported (§2 exclusions). |

---

## 8. Pending external dependency

The OpenHound proposal ([docs/proposals/2026-06-16-convert-read-from-duckdb.md](../../docs/proposals/2026-06-16-convert-read-from-duckdb.md))
asks the maintainer to let convert read DuckDB tables directly. **It is not a blocker** — this spec
builds on writeback, entirely within `sccm/sccm`. If the proposal is accepted, the writeback step in
`transforms.py` is deleted and the convert resources point at DuckDB instead; convert models are
otherwise unchanged.

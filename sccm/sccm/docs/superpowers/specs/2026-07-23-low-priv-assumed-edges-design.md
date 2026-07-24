# Design: low-privilege assumed nodes/edges (default possible-edges mode)

**Date:** 2026-07-23 · **Status:** design (approved for planning) · **Driver:** SCCM extension.

## 1. Goal

Make the **default** collection mode (possible edges ON) build the SCCM/MSSQL attack graph that
ConfigManBearPig (CMBP) produces for an operator **without AdminService access** — i.e. the common
real-world case of a non-privileged domain user. `--disable-possible-edges` keeps today's conservative,
evidence-only behavior unchanged. Where CMBP's assumptions are sloppy, tighten them; and document every
assumption so an operator can tell an *assumed* edge from a *confirmed* one.

Motivating measurement (2026-07-23 live `MAYYHEM\lowpriv` run, `sccm/tests/live-comparison/lowpriv_check/`):
CMBP emitted 106–146 edges; OpenHound emitted **9**. The gap is almost entirely families OpenHound
*collects the evidence for but discards in preprocess*, plus families CMBP fabricates by template.

## 2. The linchpin: `site_hierarchy` is starved of its low-priv sources

`_site_hierarchy` ([transforms.py:192-256](../../src/openhound_sccm/transforms.py)) INSERTs **only** from
`adminservice_site_definitions` and `wmi_site_definitions` (both AdminService/WMI-only). When those are
empty (no AdminService), `site_hierarchy` is empty, so `_root_code`/`_first_primary_code` return `None`
and every builder that joins the `nonsec` CTE (derived from `site_hierarchy`) emits **zero rows** —
regardless of what LDAP/RemoteRegistry/HTTP/SMB actually collected.

But the low-priv evidence is already collected and thrown away:
- **LDAP management-point capabilities** (`ldap_management_points_raw`, parsed by `_parse_mp_capabilities`
  in [collectors/ldap.py:25-116](../../src/openhound_sccm/collectors/ldap.py)) already yields
  `site_type` (Primary/CAS/Secondary), `parent_site_code`, and the true `root_site_code` — never read by
  `_site_hierarchy`.
- **RemoteRegistry on a site server** (low-priv-readable SMS keys) already yields `site_code`
  (`remoteregistry_sites`, [registry.py:342](../../src/openhound_sccm/collectors/registry.py)) plus
  `SMS Site Server@<site>` / `SMS SQL Server@<site>` / `SMS Component Server@<site>` role tags on
  `remoteregistry_computers` ([registry.py:370,415,436](../../src/openhound_sccm/collectors/registry.py)),
  and the site database server via the "Multisite Component Servers" key.

**Fix #1 (the unlock):** feed `site_hierarchy` from the LDAP MP-capabilities data (type/parent/root) and
from `remoteregistry_sites` (site_code). This one change unblocks the `nonsec`-gated families for low-priv
users. It is a pure improvement (data already collected) and is *not* gated by possible-edges — a real
hierarchy is a real hierarchy.

## 3. Locked decisions (from grilling)

- **D1 — Scope = Tiers A+B+C.** Default mode reproduces every CMBP-assumed family reachable without
  AdminService, plus the MSSQL template scaffolding, with the tightening below. The genuinely
  uncollectable RBAC/service-account families (Tier D, §5) stay AdminService/WMI-only.
- **D2 — Site-DB signal = RemoteRegistry-confirmed first, then `MSSQLSvc` SPN + SCCM-relatedness.**
  A host is treated as a site database server if RemoteRegistry ("Multisite Component Servers", low-priv)
  confirmed it, **or** (fallback) it has an `MSSQLSvc` SPN in AD **and** is SCCM-related (a discovered
  site system / co-located with an SMS role). This tightens CMBP's "any host reachable on 1433" and works
  even when 1433 is filtered.
- **D3 — Labeling.** Assumed nodes/edges stay **traversable** (so BloodHound pathfinding uses them), and
  carry a machine-readable provenance: `collectionSource` gains an `Assumed-<basis>` tag, plus
  `assumed = true` and a human `assumptionBasis` string. Each assumed edge kind gets an entity-panel help
  blurb (via the existing edge-help property-bag pattern, [[bloodhound-opengraph-edge-help-limit]]).
  README gets a full assumption catalog; ARCHITECTURE.md gets a new subsystem section.
- **D4 — Root anchor.** Use the true `root_site_code` from MP-capabilities to resolve the hierarchy root
  (improvement over CMBP's "first primary discovered"); keep possible-client-device attachment to the
  first **primary** site to preserve OpenHound's existing `node-clientdevice-primary-site` invariant.

## 4. Per-family build plan

Legend: **confirmed** = built from observed data; **assumed** = templated/inferred (gets provenance tag);
source abbreviations — L=LDAP, MPX=LDAP MP-capabilities XML, RR=RemoteRegistry-on-site-server (low-priv),
H=HTTP `.sms_aut`/`SMS_Identification`/sitesigncert, S=SMB shares, SPN=`MSSQLSvc` SPN, P=TCP/EPA probe.

### Tier A — LDAP-only (unblocked by Fix #1)
| Family | Source | Confirmed/Assumed | Notes |
|---|---|---|---|
| `SCCM_AdminsReplicatedTo` | site_hierarchy (L/MPX/RR) | confirmed (topology) | already built; just needs non-empty hierarchy |
| `SCCM_ClientDevice` (possible) + `SCCM_SameHostAs` + `SCCM_HasClient` | `ldap_cmrc_devices` (CmRcService SPN) | assumed | already built by `_node_client_device_possible`; only blocked by `_root_code`==None (Fix #1) and `disable_possible_edges` |

### Tier B — LDAP + RemoteRegistry/HTTP/SMB role signals (+ Fix #1)
| Family | Source | Confirmed/Assumed | Notes |
|---|---|---|---|
| site-system role tags (`SMS Site Server`/`SMS Provider`/`SMS SQL Server`/`SMS Component Server`/`SMS Management Point`/`Distribution Point`) | RR/H/S | confirmed | already tagged by registry.py/http.py/smb.py into `node_computer.site_system_roles` |
| `SCCM_AssignAllPermissions` (SMS Provider host → sites; site DB → own site) | roles + site_hierarchy | assumed (structural) | needs Fix #1 |
| `SCCM_LocalAdminRequired` (site server → site systems) | roles + site_hierarchy | assumed (topology) | needs Fix #1 |
| `SCCM_CoerceAndRelayToAdminService` (SMS Site Server → SMS Provider) | roles + site_hierarchy + NTLM-restrict null/Off | assumed (relay) | needs Fix #1 |
| `SCCM_CoerceAndRelayToSMB` (site systems, SMB signing measured `false`) | roles + SMB2-negotiate signing (S, low-priv) + site_hierarchy | confirmed signing + assumed relay | needs Fix #1; **fix traversability** (§6.5) |
| `HasSession` (current-user arm) | RR current-user (low-priv) | confirmed | already low-priv reachable via RR |

### Tier C — MSSQL template from an assumed/confirmed site-DB identity (D2)
| Family | Source | Confirmed/Assumed | Notes |
|---|---|---|---|
| `MSSQL_Server` (+`MSSQL_HostFor`/`MSSQL_ExecuteOnHost`) | SPN/RR/P | confirmed | already built from SPN scan (bare server) |
| `MSSQL_ServerRole` sysadmin, `MSSQL_Database` `CM_<site>`, `MSSQL_DatabaseRole` db_owner | template off site-DB (D2) | assumed | fabricated structure — no internals observed |
| `MSSQL_Contains`/`MSSQL_ControlServer`/`MSSQL_ControlDB` | template | assumed | |
| `MSSQL_Login`/`MSSQL_DatabaseUser` (site-server machine accts) + `MSSQL_HasLogin`/`MSSQL_IsMappedTo`/`MSSQL_MemberOf` | template (machine acct assumed sysadmin/db_owner) | assumed | requires site-server/provider role (Tier B) + site-DB (D2) |
| `MSSQL_CoerceAndRelayToMSSQL` | template + EPA assume-off | assumed | EPA-off assumption honored only when possible-ON (matches existing flag semantics, [transforms.py:3056-3059](../../src/openhound_sccm/transforms.py)) |
| `SCCM_AssignAllPermissions` (site DB → its site) | template + site_hierarchy | assumed | |

## 5. Out of scope — Tier D (structurally uncollectable without privilege)

No AD/LDAP representation exists, and RemoteRegistry-on-site-server does not expose them, so neither tool
can derive them for a low-priv user in a hardened environment: `SCCM_FullAdministrator`,
`SCCM_AllPermissions`, `SCCM_ApplicationAdministrator`, `SCCM_IsAssigned`, `SCCM_IsMappedTo`,
`SCCM_Contains` of RBAC objects, `SCCM_HasMember`, the SCCM admin-user/security-role/collection nodes;
and MSSQL service-account edges `MSSQL_GetTGS`/`MSSQL_GetAdminTGS`/`MSSQL_ServiceAccountFor` and the
MSSQL-service-account arm of `HasSession` (service-account SID is AdminService-only). These remain
AdminService/WMI-gated. The default-mode README/ARCHITECTURE docs must state plainly that these require
privileged collection.

## 6. Improvements over CMBP (recommended, folded into the plan)

1. **Fix #1** — feed `site_hierarchy` from LDAP MP-caps + RemoteRegistry (CMBP re-derives per-run; OH
   currently discards). Enables the whole low-priv graph.
2. **True root** from MP-capabilities `root_site_code`, not CMBP's "first primary discovered" (correct in
   multi-hierarchy environments).
3. **Site-DB signal** RR-confirmed → SPN+SCCM-related (D2), vs CMBP's 1433-only heuristic (fewer false
   positives; works with 1433 filtered).
4. **Provenance** (`assumed`/`assumptionBasis`/`Assumed-*` collectionSource) — CMBP does not distinguish
   assumed from confirmed.
5. **`SCCM_CoerceAndRelayToSMB` traversability** — CMBP emits it non-traversable due to a kind-name
   mismatch bug ([[sccm-stage6-relay-decisions]]); OpenHound emits it traversable.
6. **Deterministic possible-client-device IDs** — CMBP uses random GUIDs (documented duplicate risk); OH
   uses stable IDs and dedupes assumed vs confirmed (`_dedup_client_device`).

## 7. `--disable-possible-edges` semantics (unchanged intent, now meaningful at low priv)

The flag stays a **tightening-only** switch. When set, it removes/does-not-create the *assumed* families:
the possible client devices (+`SameHostAs`/`HasClient`), the templated MSSQL scaffolding
(`MSSQL_Database`/roles/logins/users + their edges), `MSSQL_CoerceAndRelayToMSSQL`'s EPA-off assumption,
and the assumed SCCM permission/coerce/local-admin edges. It never removes **confirmed** data (real site
hierarchy, observed roles, `MSSQL_Server` from SPN, `HasSession` current-user, RR-confirmed site DB). Fix
#1 (site_hierarchy) is confirmed data and stays in both modes.

## 8. Documentation (D3)

- **README** — expand the possible-edges/Assumptions section into a full catalog: one row per assumed
  family with its inference rule, data source, and false-positive caveat; a "what needs privilege"
  callout (Tier D); copy-pasteable mayyhem examples for default vs `--disable-possible-edges`.
- **ARCHITECTURE.md** — new section for the LDAP/RemoteRegistry-fed `site_hierarchy` and the
  assumption/provenance engine, plus a changelog entry; update the preprocess/convert section.
- **Entity-panel help** — per assumed edge kind, a help blurb via the edge property-bag pattern.

## 9. Testing

- **Offline transforms tests** (`sccm/sccm/tests/*_test.py`, SCCM venv): synthetic DuckDB fixtures that
  exercise (a) `site_hierarchy` populated from LDAP-MP-caps-only and from RR-only, (b) each newly-unblocked
  family emitting under possible-ON and being absent under possible-OFF, (c) provenance tags present, (d)
  the D2 site-DB signal (SPN+SCCM-related fires; arbitrary SQL host does not).
- **Integration fixtures** — extend `openhound_sccm/integration/fixtures` with low-priv-expected cases so
  `--run-integration-tests` has a low-priv baseline (distinct from the domainadmin baseline), OR document
  that the existing fixtures are the privileged baseline. (Decide during planning.)
- **Live re-validation** — re-run `lowpriv_check` (CMBP vs OpenHound, both flag states) and confirm
  OpenHound's default-mode graph now approaches CMBP's, with provenance tags and no Tier-D fabrication.

## 10. Risks

- **False positives from templated MSSQL internals** — mitigated by D2 (tighter site-DB signal) and D3
  (provenance so operators can filter). Document prominently.
- **Multi-hierarchy site-code collisions** — the true-root fix (D4) reduces but does not eliminate CMBP's
  single-hierarchy assumption (README already documents it).
- **`site_hierarchy` shape drift** — adding LDAP/RR arms must preserve the existing `site_type` INTEGER
  contract (2=Primary, 4=CAS) that root resolution depends on; MP-caps strings must map to those codes.

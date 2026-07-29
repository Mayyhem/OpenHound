# Archived README documentation for the BloodHound upload feature

Both sections were removed from `sccm/sccm/README.md` on 2026-07-29 when the feature was
pulled from the published packages. Kept verbatim so restoring the docs is a copy-paste,
not a rewrite. See ../README.md for why the feature went, and the re-wiring checklist.

Two anchors elsewhere in the README used to point into the second section
(`#bloodhound-upload`) and were rewritten at removal time; if you restore this section,
re-point them:

- Quick Start step 5 ("See [BloodHound Upload](#bloodhound-upload) under Command Line
  Options for every flag …")
- The Collection Overview / `--disable-possible-edges` cross-reference

---

## 1. Quick Start step 5 (was: "### 5. Upload to BloodHound")

```markdown
### 5. Upload to BloodHound

The collector can push the graph straight into BloodHound CE itself — no manual File Ingest step. Create an API token in BloodHound CE (**Administration → API Keys**), then pass it with `-B`:

One command — collect, build the graph, and upload schema + results to BloodHound CE:

```powershell
uv run openhound collect sccm .\out -d mayyhem.com --dc dc01.mayyhem.com `
  -u "MAYYHEM\lowpriv" -p "Passw0rd!" --run-all `
  -B "<token-id>:<token-key>@https://bloodhound.mayyhem.com"
```

Re-upload an existing run without recollecting:

```powershell
uv run openhound convert sccm .\out\sccm .\out\graph --lookup-file .\out\lookup.duckdb `
  -B "<token-id>:<token-key>@https://bloodhound.mayyhem.com"
```

Push only the schema (registers the `SCCM_*` and `MSSQL_*` kinds/icons), no data:

```powershell
uv run openhound collect sccm .\out --skip-collection --upload-schema-only `
  -B "<token-id>:<token-key>@https://bloodhound.mayyhem.com"
```

See [BloodHound Upload](#bloodhound-upload) under Command Line Options for every flag, the equivalent environment variables, and what each command actually uploads.

If you'd rather upload by hand instead, the OpenGraph files convert writes can also be dragged into the BloodHound UI under **Administration → File Ingest**. Either way, to query the SCCM kinds, BloodHound must use the **PostgreSQL** graph backend (the prebuilt SCCM kinds will not resolve on Neo4j): https://bloodhound.specterops.io/get-started/custom-installation#postgresql
```

> Replaced by a manual File Ingest walkthrough that also tells the operator where the two
> shipped schema JSON files live, since registering the custom kinds is no longer automatic.

---

## 2. Command Line Options section (was: "### BloodHound Upload")

```markdown
### BloodHound Upload

The **same flag surface** is available on both `openhound collect sccm` (add `--run-all` so there's a graph to upload) and `openhound convert sccm` (uploads what that convert run just produced, without recollecting).

| Option | Description |
|---|---|
| `-B`, `--bloodhound` | Shorthand for all three credential values: `<token-id>:<token_key>@<url>`. Splits on the *last* `@`, so a URL is safe even if it happens to contain one. |
| `--bloodhound-url` | BloodHound CE instance URL (env `BLOODHOUND_URL`). Used instead of `-B` when you'd rather pass the token id/key separately. |
| `--token-id` | BloodHound API token ID (env `BLOODHOUND_TOKEN_ID`). |
| `--token-key` | BloodHound API token key (env `BLOODHOUND_TOKEN_KEY`). Supplying both an id and a key signs requests with HMAC; supplying only a token id treats it as a Bearer/JWT token instead. |
| `--upload-schema-only` | Only push the schema definitions (custom node/edge kinds + icons); skip results. Mutually exclusive with `--upload-results-only`. |
| `--upload-results-only` | Only push the collected graph; skip the schema push. Mutually exclusive with `--upload-schema-only`. |
| `--skip-collection` | Skip the rest of the command's own work — no collection on `collect sccm`, no conversion on `convert sccm` — and go straight to the upload step. Useless without `-B` and/or `--upload-dir`. |
| `--upload-dir <dir>` | Upload an existing OpenGraph directory (a prior convert's output) instead of the graph this run just produced. Combine with `--skip-collection` on either command for a pure "just push these files" invocation. |

Precedence for the URL/token-id/token-key triple is: `-B` shorthand wins over the discrete `--bloodhound-url`/`--token-id`/`--token-key` flags, which win over the `BLOODHOUND_*` environment variables. If no URL resolves, upload is silently skipped (nothing was configured); if a URL resolves but no token id, a warning is logged and upload is skipped.

**What gets uploaded.** By default (no `--upload-*-only` flag) both a schema push and a results push happen:

- **Schema** — `PUT /api/v2/extensions`, sent **twice**: once for `schema_SCCM.json` (the `SCCM_*` kinds) and once for `schema_MSSQL.json` (the `MSSQL_*` kinds). Both are needed because this collector emits `MSSQL_*` nodes/edges (site-server SQL topology) alongside its `SCCM_*` ones — uploading only the SCCM schema would leave the MSSQL kinds unrenderable. `--disable-possible-edges` mutates both schemas before the push, flipping the coerce-and-relay ("possible") relationship kinds' `is_traversable` to `false` to match the edges actually being suppressed in the graph itself (see [`--disable-possible-edges`](#--disable-possible-edges-and-the-coerce-and-relay-edges) above).
- **Results** — every `*.json` OpenGraph file in the graph directory (`sccm_nodes-*`, `sccm_edges-*`, `ad_nodes-*`, `ad_edges-*`) is zipped into one archive and pushed through the file-upload job API: `POST /api/v2/file-upload/start` (get a job id) → `POST /api/v2/file-upload/{id}` (the zip) → `POST /api/v2/file-upload/{id}/end`.

**Network note.** The upload runs as a normal HTTP client call from wherever the collector process is running — it does **not** route through `--proxy`'s SOCKS5 tunnel (that tunnel is only installed around the collection stage). If you're collecting through a pivot, make sure the collector host also has its own, separate line of sight to the BloodHound instance (direct or via VPN) for the upload step to succeed.

```powershell
# Full run with env-var credentials instead of -B (equivalent to passing -B "id:key@url")
$env:BLOODHOUND_URL = "https://bloodhound.mayyhem.com"
$env:BLOODHOUND_TOKEN_ID = "<token-id>"
$env:BLOODHOUND_TOKEN_KEY = "<token-key>"
uv run openhound collect sccm .\out -d mayyhem.com --dc dc01.mayyhem.com -u "MAYYHEM\lowpriv" -p "Passw0rd!" --run-all

# Re-push just the results from a previous graph directory, schema already registered
uv run openhound convert sccm .\out\sccm .\out\graph --lookup-file .\out\lookup.duckdb `
  --skip-collection --upload-dir .\out\graph --upload-results-only `
  -B "<token-id>:<token-key>@https://bloodhound.mayyhem.com"
```
```

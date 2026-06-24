# Phase F2 Report — README + ARCHITECTURE Updates

## README.md sections changed

- **WIP banner** — updated edge/node counts to reflect Stage 1+2 output (8 node kinds, 10 edge kinds).
- **Table of Contents** — added 4 new node entries and 8 new edge entries.
- **Graph Model** — updated "Kinds declared" note; `SCCM_ClientDevice/Collection/AdminUser/SecurityRole` now marked emitted.
- **Node Reference header** — "4 node kinds" → "8 node kinds".
- **Node Reference** — added `SCCM_ClientDevice`, `SCCM_Collection`, `SCCM_AdminUser`, `SCCM_SecurityRole` subsections with id scheme, environmentid, kinds, and property tables.
- **Edge Reference header** — "1 edge kind" → "10 edge kinds"; added preamble describing `GraphEdge` model and traversable allow-list.
- **SCCM_AdminsReplicatedTo** — fixed stale `models/replication_edge.py` / `ReplicationEdge` reference → `models/graph_edge.py` / `GraphEdge`; added Traversable column.
- **Edge Reference** — added `SCCM_HasClient`, `SCCM_HasMember`, `SCCM_IsMappedTo`, `SCCM_IsAssigned`, `SCCM_HasPrimaryUser/HasCurrentUser/HasADLastLogonUser`, `MemberOf`, `HasSession`, `SCCM_HasStoredAccount` subsections; noted `SCCM_HasNetworkAccessAccount` deferred; added MemberOf direct-only assumption/limitation.
- **Limitations** — replaced "graph output minimal" bullet with Stage 1+2 status; added possible-client and MemberOf-nesting limitation bullets.
- **Command-Line Options / Behavior table** — `--disable-possible-edges` description updated to describe functional persist-at-collect mechanism.
- **Contributing / Testing Changes** — `pytest` command updated to `pytest tests`; description updated to mention graph model tests.
- **Understanding the Codebase tree** — models entry updated to list all 7 current models.

## ARCHITECTURE.md sections changed

- **Section 9 status note** — "design stage" → "Stages 1–2 shipped".
- **Table of Contents** — added §11 with four subsections and Changelog entry.
- **New §11 "Stage 2 preproc/convert add-ons"** — four subsections:
  - §11a: `host_object_sid` on RemoteRegistry current-user rows; `collection_settings` one-row table.
  - §11b: `_read_disable_possible` persist-at-collect / gate-in-preproc mechanism; deterministic possible-client id.
  - §11c: `TRAVERSABLE_EDGE_KINDS` allow-list; generic `GraphEdge` model; `graph_edges` dedup pass.
  - §11d (new divergence category): edge-endpoint stub-node backfill (`_node_backfill` + `StubNode`), full baseline/why-it-breaks/add-on/trade-offs spine.
- **Quick reference table** — added 3 new rows for Stage 2 add-ons.
- **Maintaining this document** — added Changelog section with 2026-06-23 entry.

## Stale README:434 reference fixed

Yes — `models/replication_edge.py` / `ReplicationEdge` replaced with `models/graph_edge.py` / `GraphEdge`.

## Concerns

None.

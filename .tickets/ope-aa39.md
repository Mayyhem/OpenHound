---
id: ope-aa39
status: open
deps: []
links: []
created: 2026-07-15T20:28:47Z
type: task
priority: 2
tags: [sccm, graph, entity-panel, edges]
---

# Add entity-panel help content to SCCM edge property bags

Add per-edge entity-panel help content (general/windowsAbuse/linuxAbuse/opsec/references) to the property bag of every SCCM-emitted custom edge kind that BloodHound lacks native help for. Per-kind content map (edge_help.py) + 5 nullable fields on SCCMEdgeProperties + tiny lookup in graph_edge.py. User provides all prose; vertical slice wires SCCM_AdminsReplicatedTo and scaffolds stubs for the rest. Spec: docs/superpowers/specs/2026-07-15-edge-entity-panel-help-design.md

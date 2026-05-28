---
id: Ope-bmyk
status: open
deps: [Ope-o008]
links: []
created: 2026-05-28T13:27:52Z
type: feature
priority: 2
assignee: Mayyhem
tags: [sccm, graph, ux]
---
# Abuse Info on Edges

Surface abuse-path information in graph output describing HOW an edge can be exploited. SCCMEdgeProperties already has composition_query and reason fields in graph.py but they are unpopulated. Operators need to understand what to do with each edge without leaving BloodHound.

## Design

Add abuse_info field to SCCMEdgeProperties in graph.py. For each edge kind, define a string describing the attack steps. Link to Misconfiguration Manager technique IDs (CRED-X, ELEVATE-X, TAKEOVER-X). Populate abuse_info at edge creation time in relevant model/transform.

## Acceptance Criteria

Each SCCM-specific edge type has a non-empty abuse_info property in graph output. Abuse info includes technique ID reference where applicable.


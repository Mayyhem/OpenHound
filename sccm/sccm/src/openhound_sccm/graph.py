"""Extension-specific node/edge dataclasses for the SCCM extension.

Mirrors the property surface of nodes emitted by ConfigManBearPig
(see sccm/ConfigManBearPig/python/lib/graph.py and ad_resolver.py).

Every node carries an opaque string `node_id` set on the properties dataclass; the
`SCCMNode.__post_init__` derives `self.id` from that field so edges can reference it
unambiguously across all 13 node kinds (Computer/User SIDs, SCCM_Site code, MSSQL
server `host:port`, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from openhound.core.models.entries_dataclass import EdgeProperties
from openhound.core.models.entries_dataclass import Node as BaseNode
from openhound.core.models.entries_dataclass import NodeProperties as BaseProperties


@dataclass
class SCCMNodeProperties(BaseProperties):
    """Common properties carried by every node emitted by this extension.

    The `node_id` field is the canonical identifier used to construct the OpenGraph
    `id`. For AD-derived nodes this is the SID; for SCCM_Site it's the site code; for
    MSSQL_Server it's `<HOSTNAME>:1433`; for SCCM_ClientDevice it's `GUID:<resource-guid>`.

    `environmentid` follows a per-namespace root convention (documented in README.md
    under "Deviations from .agents/standards/openhound.md"): AD-namespace kinds
    (Computer/User/Group/Base) set it to the AD `domain`; SCCM-namespace kinds set it
    to the `site_code`; MSSQL-namespace kinds set it to the MSSQL server identifier.
    Each kind belongs to its own extension's environment root.

    Many extra properties from the original CMBP collector flow through `extra` because
    OpenGraph's NodeProperties allows arbitrary additional fields (`model_config = extra="allow"`).

    Attributes:
        node_id: Stable identifier used as the OpenGraph node id.
        environmentid: Per-namespace root id (AD domain / SCCM site_code / MSSQL server).
        samAccountName: AD sAMAccountName.
        dNSHostName: AD dNSHostName / FQDN of the host.
        distinguishedName: AD distinguishedName.
        objectClass: AD objectClass list.
        operatingSystem: Operating system reported by AD.
        enabled: Whether the AD account is enabled.
        siteCode: SCCM site code this object belongs to.
        rootSiteCode: Root site code in the hierarchy.
        parentSiteCode: Parent site code (for child sites).
        siteType: CAS / Primary / Secondary.
        collectionSource: List of collection sources that contributed to this node.
        isDomainPrincipal: Whether this principal is sourced from AD.
    """

    # `environmentid` is inherited from the framework `BaseProperties` (it has no
    # default there, so re-declaring it here with a default would violate dataclass
    # field-order rules vs. the required `node_id` field below). The per-namespace
    # root convention is documented in the class docstring's Attributes section.
    node_id: str = field(metadata={"description": "Stable identifier used as the OpenGraph node id."})
    # Optional AD/SCCM-extracted attributes (kept loose; populated where available)
    samAccountName: str | None = field(default=None, metadata={"description": "AD sAMAccountName"})
    dNSHostName: str | None = field(default=None, metadata={"description": "AD dNSHostName / FQDN of the host"})
    distinguishedName: str | None = field(default=None, metadata={"description": "AD distinguishedName"})
    objectClass: list[str] | None = field(default=None, metadata={"description": "AD objectClass list"})
    operatingSystem: str | None = field(default=None, metadata={"description": "Operating system reported by AD"})
    enabled: bool | None = field(default=None, metadata={"description": "Whether the AD account is enabled"})

    # SCCM-specific / source-tracking
    siteCode: str | None = field(default=None, metadata={"description": "SCCM site code this object belongs to"})
    rootSiteCode: str | None = field(default=None, metadata={"description": "Root site code in the hierarchy"})
    parentSiteCode: str | None = field(default=None, metadata={"description": "Parent site code (for child sites)"})
    siteType: str | None = field(default=None, metadata={"description": "CAS / Primary / Secondary"})
    collectionSource: list[str] | None = field(default=None, metadata={"description": "List of collection sources that contributed to this node"})
    isDomainPrincipal: bool | None = field(default=None, metadata={"description": "Whether this principal is sourced from AD"})


@dataclass
class SCCMNode(BaseNode):
    """OpenGraph node for SCCM-extension entities. ``id`` is derived from ``properties.node_id``."""

    properties: SCCMNodeProperties
    kinds: list[str]
    id: str = field(init=False)

    def __post_init__(self):
        self.id = self.properties.node_id


@dataclass
class SCCMEdgeProperties(EdgeProperties):
    """Extension-specific edge properties.

    `composed`/`traversable` come from the base; we add fields used by post-processing
    edges to surface attack-path provenance (e.g. coercion victim/relay target pairs,
    role assignment scope) and discovery-path tagging (``collectionSource``) used to
    differentiate duplicate edges that CMBP retains via its post-processing
    ``rename_node`` collapse — matched here by an output-stage dedup key that
    treats distinct ``collectionSource`` values as distinct edges.
    """

    reason: str | None = field(default=None, metadata={"description": "Why this edge was emitted (e.g. role assignment justification)"})
    coercionVictimAndRelayTargetPairs: list[str] | None = field(default=None, metadata={"description": "List of 'Coerce X, relay to Y' descriptions for relay edges"})
    queryComposition: str | None = field(default=None, metadata={"description": "Optional Cypher composition for derived edges"})
    scope: str | None = field(default=None, metadata={"description": "Permission scope for SCCM role-assignment edges"})
    collectionSource: list[str] | None = field(default=None, metadata={"description": "List of discovery paths that produced this edge — used for output-stage dedup"})
    SCCMInfra: bool | None = field(default=None, metadata={"description": "Marker that the edge is part of SCCM infrastructure traversal (PS1: set on SCCM_IsMappedTo etc.)"})

    def to_extra(self) -> dict[str, Any]:
        """Return only non-default fields so JSON output is minimal."""
        out: dict[str, Any] = {}
        if self.reason is not None:
            out["reason"] = self.reason
        if self.coercionVictimAndRelayTargetPairs:
            out["coercionVictimAndRelayTargetPairs"] = self.coercionVictimAndRelayTargetPairs
        if self.queryComposition is not None:
            out["queryComposition"] = self.queryComposition
        if self.scope is not None:
            out["scope"] = self.scope
        if self.collectionSource:
            out["collectionSource"] = self.collectionSource
        if self.SCCMInfra is not None:
            out["SCCMInfra"] = self.SCCMInfra
        return out

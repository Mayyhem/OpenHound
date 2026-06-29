"""Graph-kind constants for the MSSQL collector.

Re-exports the node and edge modules so callers can use either
`from openhound_mssql.kinds import nodes, edges` or the package directly.
"""

from openhound_mssql.kinds import edges, nodes

__all__ = ["nodes", "edges"]

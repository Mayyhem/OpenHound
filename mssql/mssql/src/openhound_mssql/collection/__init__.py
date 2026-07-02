"""Per-target MSSQL collection: target resolution + per-server SQL enumeration.

- ``targets`` — classify/resolve ``-t`` targets (explicit/list/file/SPN-enum/scan-all)
  using the shared ``clients.ad`` + ``discovery.dns``.
- ``queries`` — the verbatim T-SQL strings, version-aware.
- ``server``  — ``collect_server(conn, ctx)`` runs the queries in the exact ``.ps1`` order
  and yields ``(table_name, row)`` pairs for the DLT source to write as JSONL.
"""

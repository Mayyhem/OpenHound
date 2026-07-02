# Node assets for the MSSQL OpenHound collector.
#
# Stage 0 removed the example `Asset` / `MEMBER_OF` `@app.asset`. The real
# per-node-kind assets (server, login, server_role, database, db_user,
# db_role, app_role, AD nodes) are added in Stage 5 (see plan Task 5.2).
# The module stays importable with no registrations for now.

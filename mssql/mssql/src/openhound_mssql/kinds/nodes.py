"""Node-kind string constants and icon definitions for the MSSQL collector.

The kind strings here are copied VERBATIM from MSSQLHound's Go output
(`internal/bloodhound/writer.go` `NodeKinds`) so BloodHound ingest and the
MSSQLHound validators agree on the graph shape. The seven `MSSQL_*` kinds each
carry an icon; the three Active Directory kinds (`User`/`Group`/`Computer`)
carry a second `"Base"` kind and have NO icon.

Attributes:
    SERVER: Kind for a SQL Server instance node.
    LOGIN: Kind for a server-level login (SQL/Windows login, Windows group).
    SERVER_ROLE: Kind for a server-level role.
    DATABASE: Kind for a database node.
    DATABASE_USER: Kind for a database-level user.
    DATABASE_ROLE: Kind for a database-level role.
    APPLICATION_ROLE: Kind for a database application role.
    USER: AD user kind ("User").
    GROUP: AD group kind ("Group").
    COMPUTER: AD computer kind ("Computer").
    BASE: Secondary kind ("Base") attached to every AD node.
    ICONS: Map of MSSQL_* node kind -> icon definition (font-awesome name +
        color), copied from the Go `Icons` map.
    AD_KINDS: The AD kinds that also carry the BASE kind and no icon.
"""

# --- MSSQL_* node kinds (writer.go NodeKinds) -------------------------------
SERVER = "MSSQL_Server"
LOGIN = "MSSQL_Login"
SERVER_ROLE = "MSSQL_ServerRole"
DATABASE = "MSSQL_Database"
DATABASE_USER = "MSSQL_DatabaseUser"
DATABASE_ROLE = "MSSQL_DatabaseRole"
APPLICATION_ROLE = "MSSQL_ApplicationRole"

# --- Active Directory node kinds (carry a second "Base" kind, no icon) ------
USER = "User"
GROUP = "Group"
COMPUTER = "Computer"
BASE = "Base"

# All MSSQL_* node kinds, in catalog order.
MSSQL_NODE_KINDS = (
    SERVER,
    LOGIN,
    SERVER_ROLE,
    DATABASE,
    DATABASE_USER,
    DATABASE_ROLE,
    APPLICATION_ROLE,
)

# AD node kinds (each emitted alongside BASE).
AD_KINDS = (USER, GROUP, COMPUTER)

# Per-kind icon definitions (font-awesome name + color), copied from the Go
# `Icons` map in writer.go. `type` is always "font-awesome". AD nodes have no
# icon, so they are intentionally absent from this map.
ICONS = {
    SERVER: {"type": "font-awesome", "name": "server", "color": "#42b9f5"},
    LOGIN: {"type": "font-awesome", "name": "user-gear", "color": "#dd42f5"},
    SERVER_ROLE: {"type": "font-awesome", "name": "users-gear", "color": "#6942f5"},
    DATABASE: {"type": "font-awesome", "name": "database", "color": "#f54242"},
    DATABASE_USER: {"type": "font-awesome", "name": "user", "color": "#f5ef42"},
    DATABASE_ROLE: {"type": "font-awesome", "name": "users", "color": "#f5a142"},
    APPLICATION_ROLE: {"type": "font-awesome", "name": "robot", "color": "#6ff542"},
}

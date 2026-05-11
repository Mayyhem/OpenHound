"""Node kind constants for the SCCM extension.

Mirrors the 13 distinct node kinds emitted by ConfigManBearPig
(see sccm/ConfigManBearPig/python/lib/graph.py and lib/output.py).
Most kinds intentionally do not carry a prefix because they overlap with
BloodHound-native kinds (Computer, User, Group) or are already namespaced
by the platform (SCCM_*, MSSQL_*).
"""

# AD-native kinds
COMPUTER = "Computer"
USER = "User"
GROUP = "Group"
BASE = "Base"

# SCCM kinds
SCCM_SITE = "SCCM_Site"
SCCM_CLIENT_DEVICE = "SCCM_ClientDevice"
SCCM_COLLECTION = "SCCM_Collection"
SCCM_ADMIN_USER = "SCCM_AdminUser"
SCCM_SECURITY_ROLE = "SCCM_SecurityRole"

# MSSQL kinds
MSSQL_SERVER = "MSSQL_Server"
MSSQL_LOGIN = "MSSQL_Login"
MSSQL_DATABASE = "MSSQL_Database"
MSSQL_DATABASE_USER = "MSSQL_DatabaseUser"
MSSQL_SERVER_ROLE = "MSSQL_ServerRole"
MSSQL_DATABASE_ROLE = "MSSQL_DatabaseRole"

# Seed marker (only present in seed_data.json output for BHE schema registration)
IGNORE_ME = "IgnoreMe"

ALL_KINDS = (
    COMPUTER, USER, GROUP, BASE,
    SCCM_SITE, SCCM_CLIENT_DEVICE, SCCM_COLLECTION, SCCM_ADMIN_USER, SCCM_SECURITY_ROLE,
    MSSQL_SERVER, MSSQL_LOGIN, MSSQL_DATABASE, MSSQL_DATABASE_USER, MSSQL_SERVER_ROLE, MSSQL_DATABASE_ROLE,
)

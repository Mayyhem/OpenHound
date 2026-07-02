# MSSQL node-asset package.
#
# Importing the package imports every node-asset submodule, which runs their
# `@app.asset(...)` registrations (NodeDefs for the catalog/docs + conformance
# tests). main.py does `from . import models` at the bottom (after `app` is
# defined) to trigger this; the submodules each do `from ..main import app`, which
# resolves whether main or models is imported first (cycle-safe — see main.py).
from . import server  # noqa: F401
from . import server_principal  # noqa: F401
from . import database  # noqa: F401
from . import database_principal  # noqa: F401

from .server import MSSQLServer
from .server_principal import MSSQLServerPrincipal, MSSQLServerRoleAsset
from .database import MSSQLDatabase
from .database_principal import (
    MSSQLDatabasePrincipal,
    MSSQLDatabaseRoleAsset,
    MSSQLApplicationRoleAsset,
)

__all__ = [
    "MSSQLServer",
    "MSSQLServerPrincipal",
    "MSSQLServerRoleAsset",
    "MSSQLDatabase",
    "MSSQLDatabasePrincipal",
    "MSSQLDatabaseRoleAsset",
    "MSSQLApplicationRoleAsset",
]

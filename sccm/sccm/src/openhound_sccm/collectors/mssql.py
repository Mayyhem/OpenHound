"""
Checks MSSQL database servers for:
- Extended Protection for Authentication (EPA) settings via TDS PRELOGIN
- Site database MSSQL server nodes and relationships
- sysadmin login detection
- Service account detection
"""
import logging

logger = logging.getLogger(__name__)

"""Pytest hooks for the SCCM extension tests.

``invoke_configmanbearpig_unit_tests.py`` and ``unit_test_expectations.py`` are
the integration test harness, not pytest tests; pytest must not try to collect
them as test modules.
"""

collect_ignore = [
    "invoke_configmanbearpig_unit_tests.py",
    "unit_test_expectations.py",
]

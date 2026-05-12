"""Unit tests for ``main._apply_env_overrides`` and ``main._FLAG_TO_ENV``.

Validates that every CMBP-style flag exposed on ``openhound collect sccm``
maps to the documented ``SOURCES__SCCM__*`` env var, that default-``False``
booleans don't leak into ``os.environ``, and that the mapping table is
exhaustive (every Typer parameter on ``collect_sccm`` that isn't a
framework-standard argument must appear in ``_FLAG_TO_ENV``).
"""

from __future__ import annotations

import inspect
import os
import pathlib

import pytest

from openhound_sccm.main import _FLAG_TO_ENV, _apply_env_overrides, collect_sccm


_FRAMEWORK_ARGS = {
    "output_path",
    "resources",
    "progress",
    "tables",
    "columns",
    "data_type",
    "verbose",
}


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Strip every SOURCES__SCCM__* env var before each test so we observe
    only the values our helper writes."""
    for env_name in _FLAG_TO_ENV.values():
        monkeypatch.delenv(env_name, raising=False)
    yield


def test_all_collect_sccm_flags_are_mapped():
    sig = inspect.signature(collect_sccm)
    extension_flags = [
        name for name in sig.parameters
        if name not in _FRAMEWORK_ARGS
    ]
    missing = [name for name in extension_flags if name not in _FLAG_TO_ENV]
    assert not missing, f"flags missing from _FLAG_TO_ENV: {missing}"


def test_string_flag_sets_env_var():
    _apply_env_overrides({"domain": "mayyhem.com"})
    assert os.environ["SOURCES__SCCM__DOMAIN"] == "mayyhem.com"


def test_int_flag_sets_env_var_as_string():
    _apply_env_overrides({"ldap_port": 636})
    assert os.environ["SOURCES__SCCM__LDAP_PORT"] == "636"


def test_path_flag_sets_env_var_as_str_path():
    p = pathlib.Path("/tmp/targets.txt")
    _apply_env_overrides({"computer_file": p})
    assert os.environ["SOURCES__SCCM__COMPUTER_FILE"] == str(p)


def test_bool_true_sets_lowercase_true():
    _apply_env_overrides({"ldaps": True})
    assert os.environ["SOURCES__SCCM__USE_SSL"] == "true"


def test_bool_false_does_not_leak():
    # Default-False booleans should leave the env var untouched.
    _apply_env_overrides({"ldaps": False, "enable_bad_opsec": False})
    assert "SOURCES__SCCM__USE_SSL" not in os.environ
    assert "SOURCES__SCCM__ENABLE_BAD_OPSEC" not in os.environ


def test_none_does_not_leak():
    _apply_env_overrides({"username": None, "password": None})
    assert "SOURCES__SCCM__USERNAME" not in os.environ
    assert "SOURCES__SCCM__PASSWORD" not in os.environ


def test_unknown_kwargs_are_silently_ignored():
    # Future / framework / typer-internal kwargs in `locals()` shouldn't blow up.
    _apply_env_overrides({"definitely_not_a_flag": "x"})
    assert "SOURCES__SCCM__DEFINITELY_NOT_A_FLAG" not in os.environ


@pytest.mark.parametrize("flag,env_name", sorted(_FLAG_TO_ENV.items()))
def test_every_flag_maps_to_its_documented_env_var(flag, env_name):
    """Sanity-check the SOURCES__SCCM__ prefix and uppercase convention."""
    assert env_name.startswith("SOURCES__SCCM__"), env_name
    assert env_name == env_name.upper(), env_name

"""Tests for --dns-resolver flag behaviour in main.py and collectors/dns.py."""
import dns.resolver as _dns_resolver
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# _resolve_dc_via_dns
# ---------------------------------------------------------------------------

def test_resolve_dc_via_dns_uses_custom_resolver_when_provided():
    """When dns_resolver is set, Resolver(configure=False) is used with that IP."""
    from openhound_sccm.main import _resolve_dc_via_dns

    mock_resolver_instance = MagicMock()
    mock_answer = MagicMock()
    mock_answer.target.__str__ = lambda self: "dc1.corp.local."
    mock_resolver_instance.resolve.return_value = [mock_answer]

    with patch.object(_dns_resolver, "Resolver", return_value=mock_resolver_instance) as mock_cls:
        result = _resolve_dc_via_dns("corp.local", dns_resolver="192.168.1.53")

        mock_cls.assert_called_once_with(configure=False)
        assert mock_resolver_instance.nameservers == ["192.168.1.53"]
        assert result == "dc1.corp.local"


def test_resolve_dc_via_dns_uses_host_resolver_when_not_provided():
    """When dns_resolver is None, the shared make_resolver builds a host-configured
    Resolver() (no explicit nameserver) and its resolve() is used.

    (Previously this asserted the module-level dns.resolver.resolve() was called;
    _resolve_dc_via_dns now delegates resolver construction to the shared
    discovery.dns.make_resolver, which always builds a Resolver instance.)
    """
    from openhound_sccm.main import _resolve_dc_via_dns

    mock_resolver_instance = MagicMock()
    mock_answer = MagicMock()
    mock_answer.target.__str__ = lambda self: "dc1.corp.local."
    mock_resolver_instance.resolve.return_value = [mock_answer]

    with patch.object(_dns_resolver, "Resolver", return_value=mock_resolver_instance) as mock_cls:
        result = _resolve_dc_via_dns("corp.local", dns_resolver=None)

        # make_resolver(None) builds a host-configured Resolver() (no explicit nameserver).
        mock_cls.assert_called_once_with()
        assert result == "dc1.corp.local"


# ---------------------------------------------------------------------------
# _apply_env_overrides — dns_resolver → SOURCES__SCCM__DNS_RESOLVER
# ---------------------------------------------------------------------------

def test_apply_env_overrides_sets_dns_resolver(monkeypatch):
    """dns_resolver flag value propagates to the expected env var."""
    import os
    from openhound_sccm.main import _apply_env_overrides

    monkeypatch.delenv("SOURCES__SCCM__DNS_RESOLVER", raising=False)
    _apply_env_overrides({"dns_resolver": "10.0.0.53"})
    assert os.environ["SOURCES__SCCM__DNS_RESOLVER"] == "10.0.0.53"


def test_apply_env_overrides_does_not_set_dns_resolver_when_none(monkeypatch):
    """When dns_resolver is None, the env var is left untouched."""
    import os
    from openhound_sccm.main import _apply_env_overrides

    monkeypatch.delenv("SOURCES__SCCM__DNS_RESOLVER", raising=False)
    _apply_env_overrides({"dns_resolver": None})
    assert "SOURCES__SCCM__DNS_RESOLVER" not in os.environ


# ---------------------------------------------------------------------------
# dns_management_points — resolver construction
# ---------------------------------------------------------------------------

def _make_ctx(dns_resolver=None, domain_controller=None, domain="corp.local",
              site_codes=None):
    """Build a minimal mock for dns_management_points tests."""
    ctx = MagicMock()
    ctx.dns_resolver = dns_resolver
    ctx.ad.creds.domain_controller = domain_controller
    ctx.domain = domain
    ctx.site_codes = site_codes or set()
    ctx.method_enabled.return_value = True
    return ctx


def test_dns_management_points_uses_configure_false_when_dns_resolver_set():
    """When ctx.dns_resolver is set, Resolver(configure=False) is used."""
    import dns.resolver as _dns_resolver_mod
    from openhound_sccm.collectors.dns import dns_management_points

    ctx = _make_ctx(dns_resolver="192.168.1.53", site_codes={"PS1"})
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.return_value = []

    with patch.object(_dns_resolver_mod, "Resolver", return_value=mock_resolver_instance) as mock_cls:
        list(dns_management_points(ctx))

        mock_cls.assert_called_once_with(configure=False)
        assert mock_resolver_instance.nameservers == ["192.168.1.53"]


def test_dns_management_points_uses_default_resolver_when_dns_resolver_not_set():
    """When ctx.dns_resolver is None and no DC, Resolver() uses system defaults."""
    import dns.resolver as _dns_resolver_mod
    from openhound_sccm.collectors.dns import dns_management_points

    ctx = _make_ctx(dns_resolver=None, domain_controller=None, site_codes={"PS1"})
    mock_resolver_instance = MagicMock()
    mock_resolver_instance.resolve.return_value = []

    with patch.object(_dns_resolver_mod, "Resolver", return_value=mock_resolver_instance) as mock_cls:
        list(dns_management_points(ctx))

        mock_cls.assert_called_once_with()


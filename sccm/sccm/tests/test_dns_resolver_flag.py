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


def test_resolve_dc_via_dns_uses_module_resolver_when_not_provided():
    """When dns_resolver is None, the module-level dns.resolver.resolve() is used."""
    from openhound_sccm.main import _resolve_dc_via_dns

    mock_answer = MagicMock()
    mock_answer.target.__str__ = lambda self: "dc1.corp.local."

    with patch.object(_dns_resolver, "resolve", return_value=[mock_answer]) as mock_resolve:
        with patch.object(_dns_resolver, "Resolver") as mock_cls:
            result = _resolve_dc_via_dns("corp.local", dns_resolver=None)

            mock_resolve.assert_called_once()
            mock_cls.assert_not_called()
            assert result == "dc1.corp.local"

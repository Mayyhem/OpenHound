"""Unit tests for the EPA enforcement decision tree (``determine_epa``).

The decision tree is pure logic over per-probe outcomes, so it is exercised by
injecting a fake ``probe`` callable that returns canned ``ProbeOutcome`` values
per test mode. The live impacket/SSPI probers are validated separately by the
``debug_epa_matrix`` harness against a real SQL Server.
"""
import pytest

from openhound_sccm.clients.mssql_epa import (
    BOGUS_CBT,
    EMPTY_LM_HASH,
    ENCRYPT_NOT_SUP,
    ENCRYPT_OFF,
    ENCRYPT_REQ,
    ENCRYPT_STRICT,
    EPAPrereqError,
    ProbeOutcome,
    _choose_auth,
    _classify_error_text,
    _format_hashes,
    _mode_login_params,
    _select_mssql_spn,
    determine_epa,
)


def _probe_from(mapping):
    """Build a ``probe(mode)`` callable backed by a ``{mode: ProbeOutcome}`` dict."""
    return lambda mode: mapping[mode]


def test_mode_login_params_normal_uses_correct_bindings():
    assert _mode_login_params("normal") == {
        "cbt_value": None,
        "service": "MSSQLSvc",
        "strip_target_service": False,
    }


def test_mode_login_params_bogus_cbt_sends_garbage_token_correct_spn():
    params = _mode_login_params("bogus_cbt")
    assert params["cbt_value"] == BOGUS_CBT
    assert len(BOGUS_CBT) == 16
    assert params["service"] == "MSSQLSvc"
    assert params["strip_target_service"] is False


def test_mode_login_params_missing_cbt_sends_empty_token():
    # b"" tells getNTLMSSPType3 to omit the MsvAvChannelBindings AV pair entirely.
    assert _mode_login_params("missing_cbt")["cbt_value"] == b""


def test_mode_login_params_bogus_service_uses_cifs_class():
    params = _mode_login_params("bogus_service")
    assert params["service"] == "cifs"
    assert params["cbt_value"] is None
    assert params["strip_target_service"] is False


def test_mode_login_params_missing_service_strips_target_name():
    params = _mode_login_params("missing_service")
    assert params["service"] == ""
    assert params["strip_target_service"] is True


def test_mode_login_params_uses_overridden_correct_service_class():
    # The AD-registered SPN's service class (rather than the default) is used for
    # the correct-binding modes.
    assert _mode_login_params("normal", service_class="MSSQLSvc")["service"] == "MSSQLSvc"
    assert _mode_login_params("bogus_cbt", service_class="custom")["service"] == "custom"


def test_classify_error_text_untrusted_domain():
    o = _classify_error_text("The login is from an untrusted domain and cannot be used with Windows authentication.")
    assert o.is_untrusted_domain is True
    assert o.is_login_failed is False


def test_classify_error_text_login_failed():
    o = _classify_error_text("Login failed for user 'MAYYHEM\\domainadmin'.")
    assert o.is_login_failed is True
    assert o.is_untrusted_domain is False


def test_classify_error_text_other():
    o = _classify_error_text("Some unrelated server error")
    assert o.is_untrusted_domain is False
    assert o.is_login_failed is False
    assert o.error_message == "Some unrelated server error"


def test_select_mssql_spn_prefers_registered():
    spns = ["HOST/ps1-db", "TERMSRV/ps1-db", "MSSQLSvc/ps1-db.mayyhem.com:1433"]
    assert _select_mssql_spn(spns, "ps1-db.mayyhem.com", 1433) == "MSSQLSvc/ps1-db.mayyhem.com:1433"


def test_select_mssql_spn_match_is_case_insensitive():
    spns = ["mssqlsvc/PS1-DB.mayyhem.com"]
    assert _select_mssql_spn(spns, "ps1-db.mayyhem.com", 1433) == "mssqlsvc/PS1-DB.mayyhem.com"


def test_select_mssql_spn_derives_when_absent():
    assert _select_mssql_spn([], "ps1-db.mayyhem.com", 1433) == "MSSQLSvc/ps1-db.mayyhem.com:1433"


def test_select_mssql_spn_derives_when_none():
    assert _select_mssql_spn(None, "ps1-db.mayyhem.com", 1433) == "MSSQLSvc/ps1-db.mayyhem.com:1433"


def test_format_hashes_bare_nt_prepends_empty_lm():
    nt = "8846f7eaee8fb117ad06bdd830b7586c"
    assert _format_hashes(nt) == f"{EMPTY_LM_HASH}:{nt}"


def test_format_hashes_passes_through_lm_colon_nt():
    combined = f"{EMPTY_LM_HASH}:8846f7eaee8fb117ad06bdd830b7586c"
    assert _format_hashes(combined) == combined


def test_format_hashes_none_returns_none():
    assert _format_hashes(None) is None


def test_choose_auth_explicit_with_password():
    assert _choose_auth(username="u", password="p", nt_hash=None, sspi_available=True) == "explicit"


def test_choose_auth_explicit_with_nt_hash():
    assert _choose_auth(username="u", password=None, nt_hash="abcd", sspi_available=False) == "explicit"


def test_choose_auth_sspi_when_no_creds_but_available():
    assert _choose_auth(username=None, password=None, nt_hash=None, sspi_available=True) == "sspi"


def test_choose_auth_sspi_when_creds_missing_username():
    # A password without a username cannot drive explicit auth -> fall to SSPI.
    assert _choose_auth(username=None, password="p", nt_hash=None, sspi_available=True) == "sspi"


def test_choose_auth_skip_when_nothing_available():
    assert _choose_auth(username=None, password=None, nt_hash=None, sspi_available=False) == "skip"


def test_encrypted_bogus_cbt_accepted_means_epa_off():
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
        "bogus_cbt": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
    })

    result = determine_epa(probe)

    assert result.extended_protection == "Off"


def test_encrypted_bogus_rejected_missing_rejected_means_required():
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
        "bogus_cbt": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_REQ),
        "missing_cbt": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_REQ),
    })

    result = determine_epa(probe)

    assert result.extended_protection == "Required"


def test_encrypted_bogus_rejected_missing_accepted_means_allowed():
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
        "bogus_cbt": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_REQ),
        "missing_cbt": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
    })

    result = determine_epa(probe)

    assert result.extended_protection == "Allowed"


def test_sspi_encrypted_indistinguishable_reports_allowed_required():
    # Windows SSPI always emits MsvAvChannelBindings, so a server enforcing
    # EPA (Allowed *or* Required) rejects both bogus and missing identically.
    # Surface the ambiguity verbatim instead of collapsing to one label.
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
        "bogus_cbt": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_REQ),
        "missing_cbt": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_REQ),
    })

    result = determine_epa(probe, auth_method="sspi")

    assert result.extended_protection == "Allowed/Required"


def test_sspi_unencrypted_indistinguishable_reports_allowed_required():
    # Same SSPI ambiguity for the unencrypted (service-binding) path: SSPI
    # always emits MsvAvTargetName, so missing-service is rejected like bogus.
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_OFF),
        "bogus_service": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_OFF),
        "missing_service": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_OFF),
    })

    result = determine_epa(probe, auth_method="sspi")

    assert result.extended_protection == "Allowed/Required"


def test_sspi_off_still_classifies_as_off():
    # When the bogus probe is accepted, EPA is unambiguously Off regardless of
    # auth method — the SSPI special case only kicks in when bogus is rejected.
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
        "bogus_cbt": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
    })

    result = determine_epa(probe, auth_method="sspi")

    assert result.extended_protection == "Off"


def test_explicit_auth_still_distinguishes_allowed_from_required():
    # The auth_method parameter only affects the SSPI ambiguity case; explicit
    # credentials retain the precise Allowed-vs-Required distinction because
    # impacket can genuinely omit the AV pairs.
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
        "bogus_cbt": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_REQ),
        "missing_cbt": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_REQ),
    })

    result = determine_epa(probe, auth_method="explicit")

    assert result.extended_protection == "Required"


def test_strict_encryption_uses_channel_binding_path():
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_STRICT, is_strict=True),
        "bogus_cbt": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_STRICT, is_strict=True),
        "missing_cbt": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_STRICT, is_strict=True),
    })

    result = determine_epa(probe)

    assert result.extended_protection == "Required"
    assert result.strict_encryption is True


def test_not_supported_encryption_means_unknown():
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_NOT_SUP),
    })

    result = determine_epa(probe)

    assert result.extended_protection == "Unknown"


def test_prereq_untrusted_domain_raises():
    probe = _probe_from({
        "normal": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_REQ),
    })

    with pytest.raises(EPAPrereqError):
        determine_epa(probe)


def test_prereq_other_error_raises():
    probe = _probe_from({
        "normal": ProbeOutcome(error_message="boom", encryption_flag=ENCRYPT_REQ),
    })

    with pytest.raises(EPAPrereqError):
        determine_epa(probe)


def test_login_failed_counts_as_valid_prereq():
    # "Login failed for" proves the bindings were accepted far enough to be a
    # trustworthy baseline, so EPA probing proceeds rather than aborting.
    probe = _probe_from({
        "normal": ProbeOutcome(is_login_failed=True, encryption_flag=ENCRYPT_REQ),
        "bogus_cbt": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
    })

    result = determine_epa(probe)

    assert result.extended_protection == "Off"
    assert result.unmodified_success is False


def test_required_encryption_sets_force_encryption():
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
        "bogus_cbt": ProbeOutcome(success=True, encryption_flag=ENCRYPT_REQ),
    })

    result = determine_epa(probe)

    assert result.force_encryption is True
    assert result.encryption_flag == ENCRYPT_REQ
    assert result.unmodified_success is True


def test_off_encryption_clears_force_encryption():
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_OFF),
        "bogus_service": ProbeOutcome(success=True, encryption_flag=ENCRYPT_OFF),
    })

    result = determine_epa(probe)

    assert result.force_encryption is False


def test_unencrypted_bogus_service_accepted_means_epa_off():
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_OFF),
        "bogus_service": ProbeOutcome(success=True, encryption_flag=ENCRYPT_OFF),
    })

    result = determine_epa(probe)

    assert result.extended_protection == "Off"


def test_unencrypted_bogus_rejected_missing_rejected_means_required():
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_OFF),
        "bogus_service": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_OFF),
        "missing_service": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_OFF),
    })

    result = determine_epa(probe)

    assert result.extended_protection == "Required"


def test_unencrypted_bogus_rejected_missing_accepted_means_allowed():
    probe = _probe_from({
        "normal": ProbeOutcome(success=True, encryption_flag=ENCRYPT_OFF),
        "bogus_service": ProbeOutcome(is_untrusted_domain=True, encryption_flag=ENCRYPT_OFF),
        "missing_service": ProbeOutcome(success=True, encryption_flag=ENCRYPT_OFF),
    })

    result = determine_epa(probe)

    assert result.extended_protection == "Allowed"

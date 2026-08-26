import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cors_misconfiguration_scanner as cms
from cors_misconfiguration_scanner import (
    build_json_report,
    build_report,
    build_test_origins,
    evaluate_response,
    main,
    scan_url,
)


def test_build_test_origins_includes_all_four_shapes():
    origins = dict(build_test_origins("target.example"))
    assert origins["arbitrary_origin_reflected"] == "https://evil-attacker-test.example"
    assert origins["null_origin_allowed"] == "null"
    assert origins["suffix_matching_bypass"] == "https://eviltarget.example"
    assert origins["subdomain_matching_bypass"] == "https://target.example.evil-attacker-test.example"


def test_no_acao_header_is_not_a_finding():
    assert evaluate_response("arbitrary_origin_reflected", "https://evil.example", None, None) is None


def test_wildcard_without_credentials_is_not_a_finding():
    assert evaluate_response("arbitrary_origin_reflected", "https://evil.example", "*", None) is None


def test_wildcard_with_credentials_flagged_medium():
    result = evaluate_response("arbitrary_origin_reflected", "https://evil.example", "*", "true")
    assert result["severity"] == "MEDIUM"
    assert result["check"] == "wildcard_with_credentials"


def test_null_origin_without_credentials_flagged_medium():
    result = evaluate_response("null_origin_allowed", "null", "null", None)
    assert result["severity"] == "MEDIUM"
    assert result["check"] == "null_origin_allowed"


def test_null_origin_with_credentials_flagged_high():
    result = evaluate_response("null_origin_allowed", "null", "null", "true")
    assert result["severity"] == "HIGH"
    assert result["check"] == "null_origin_allowed"


def test_reflected_arbitrary_origin_with_credentials_flagged_high():
    origin = "https://evil-attacker-test.example"
    result = evaluate_response("arbitrary_origin_reflected", origin, origin, "true")
    assert result["severity"] == "HIGH"
    assert result["check"] == "arbitrary_origin_reflected"
    assert "authenticated" in result["reason"]


def test_reflected_arbitrary_origin_without_credentials_flagged_medium():
    origin = "https://evil-attacker-test.example"
    result = evaluate_response("arbitrary_origin_reflected", origin, origin, None)
    assert result["severity"] == "MEDIUM"


def test_suffix_bypass_reflected_flagged():
    origin = "https://evilexample.com"
    result = evaluate_response("suffix_matching_bypass", origin, origin, "true")
    assert result["check"] == "suffix_matching_bypass"
    assert result["severity"] == "HIGH"


def test_properly_scoped_origin_not_reflected_is_not_a_finding():
    # Server ignores our attacker Origin and returns its own real, fixed origin instead.
    result = evaluate_response("arbitrary_origin_reflected", "https://evil.example", "https://real-app.example", "true")
    assert result is None


def test_scan_url_aggregates_findings_from_all_test_origins(monkeypatch):
    def fake_fetch(url, origin, timeout=5.0):
        if origin == "null":
            return "null", "true"
        return None, None

    result = scan_url("https://target.example/api", fetch=fake_fetch)
    assert len(result["findings"]) == 1
    assert result["findings"][0]["check"] == "null_origin_allowed"
    assert result["findings"][0]["severity"] == "HIGH"


def test_scan_url_clean_target_has_no_findings(monkeypatch):
    def fake_fetch(url, origin, timeout=5.0):
        return "https://real-app.example", None

    result = scan_url("https://target.example/api", fetch=fake_fetch)
    assert result["findings"] == []


def test_default_fetch_raises_connection_error_on_url_error(monkeypatch):
    import urllib.error

    def raise_url_error(req, timeout=None):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(cms.urllib.request, "urlopen", raise_url_error)
    try:
        cms.default_fetch("https://nowhere.invalid/", "https://evil.example")
        assert False, "expected ConnectionError"
    except ConnectionError:
        pass


def test_build_report_lists_findings_in_markdown_table():
    result = {"url": "https://target.example", "findings": [
        {"severity": "HIGH", "check": "arbitrary_origin_reflected", "origin_sent": "https://evil.example",
         "reason": "reflects attacker origin", "recommendation": "fix it"},
    ]}
    report = build_report(result)
    assert "HIGH" in report
    assert "arbitrary_origin_reflected" in report


def test_build_report_clean_says_no_issues():
    report = build_report({"url": "https://target.example", "findings": []})
    assert "No issues found." in report


def test_json_report_is_valid_and_matches_findings():
    result = {"url": "https://target.example", "findings": [
        {"severity": "HIGH", "check": "x", "origin_sent": "y", "reason": "r", "recommendation": "x"},
        {"severity": "MEDIUM", "check": "x", "origin_sent": "y", "reason": "r", "recommendation": "x"},
    ]}
    payload = json.loads(build_json_report(result))
    assert payload["summary"] == {"high": 1, "medium": 1}
    assert payload["url"] == "https://target.example"


def run_main(monkeypatch, tmp_path, scan_result, extra_args):
    monkeypatch.setattr(cms, "scan_url", lambda *a, **k: scan_result)
    out = str(tmp_path / "out.md")
    argv = ["cors_misconfiguration_scanner.py", "--url", "https://target.example", "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_when_high_finding_present(monkeypatch, tmp_path):
    result = {"url": "https://target.example", "findings": [
        {"severity": "HIGH", "check": "x", "origin_sent": "y", "reason": "r", "recommendation": "x"},
    ]}
    assert run_main(monkeypatch, tmp_path, result, ["--fail-on", "high"]) == 1


def test_fail_on_high_exits_zero_for_clean_result(monkeypatch, tmp_path):
    result = {"url": "https://target.example", "findings": []}
    assert run_main(monkeypatch, tmp_path, result, ["--fail-on", "high"]) == 0


def test_fail_on_none_always_exits_zero(monkeypatch, tmp_path):
    result = {"url": "https://target.example", "findings": [
        {"severity": "HIGH", "check": "x", "origin_sent": "y", "reason": "r", "recommendation": "x"},
    ]}
    assert run_main(monkeypatch, tmp_path, result, []) == 0


def test_main_returns_2_on_connection_error(monkeypatch, tmp_path):
    def raise_connection_error(*a, **k):
        raise ConnectionError("boom")

    monkeypatch.setattr(cms, "scan_url", raise_connection_error)
    out = str(tmp_path / "out.md")
    monkeypatch.setattr(sys, "argv", ["cors_misconfiguration_scanner.py", "--url", "https://target.example", "--output", out])
    assert main() == 2

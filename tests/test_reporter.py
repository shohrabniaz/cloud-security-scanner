import json

from models import Finding, Severity
from reporter import exit_code, format_json, format_table


def _finding(severity: Severity, check_id: str = "AZ-TEST-001") -> Finding:
    return Finding(
        check_id=check_id,
        title="Example finding",
        severity=severity,
        resource="rg-demo/resource",
        detail="detail",
        remediation="fix it",
    )


def test_format_table_empty():
    assert format_table([]) == "No findings."


def test_format_table_includes_header_rows_and_summary():
    findings = [_finding(Severity.CRITICAL), _finding(Severity.MEDIUM)]

    out = format_table(findings)

    assert "SEVERITY" in out
    assert "CRITICAL" in out
    assert "Summary: CRITICAL=1, MEDIUM=1" in out


def test_format_json_round_trips():
    findings = [_finding(Severity.HIGH)]

    parsed = json.loads(format_json(findings))

    assert parsed[0]["severity"] == "HIGH"
    assert parsed[0]["check_id"] == "AZ-TEST-001"


def test_exit_code_flags_critical_and_high():
    assert exit_code([_finding(Severity.CRITICAL)]) == 1
    assert exit_code([_finding(Severity.HIGH)]) == 1


def test_exit_code_zero_for_non_blocking_severities():
    assert exit_code([]) == 0
    assert exit_code([_finding(Severity.MEDIUM), _finding(Severity.INFO)]) == 0

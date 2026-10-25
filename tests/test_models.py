from models import Finding, Severity


def test_finding_to_dict_serialises_severity_as_value():
    finding = Finding(
        check_id="AZ-STORAGE-001",
        title="Storage account allows public blob access",
        severity=Severity.HIGH,
        resource="rg-demo/st001",
        detail="allowBlobPublicAccess is true",
        remediation="Set allowBlobPublicAccess to false.",
    )

    data = finding.to_dict()

    assert data["severity"] == "HIGH"
    assert isinstance(data["severity"], str)
    assert data["check_id"] == "AZ-STORAGE-001"
    assert set(data) == {
        "check_id",
        "title",
        "severity",
        "resource",
        "detail",
        "remediation",
    }

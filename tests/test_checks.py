import checks
from models import Severity


def test_demo_findings_cover_all_five_checks():
    findings = checks.demo_findings()

    ids = [f.check_id for f in findings]
    assert ids == [
        "AZ-STORAGE-001",
        "AZ-STORAGE-002",
        "AZ-NSG-001",
        "AZ-KV-001",
        "AZ-SQL-001",
    ]


def test_storage_public_access_flags_only_public_accounts(monkeypatch):
    monkeypatch.setattr(
        checks,
        "az",
        lambda *args: [
            {"name": "stpublic", "resourceGroup": "rg", "allowBlobPublicAccess": True},
            {"name": "stprivate", "resourceGroup": "rg", "allowBlobPublicAccess": False},
        ],
    )

    findings = checks.check_storage_public_access("sub")

    assert len(findings) == 1
    assert findings[0].check_id == "AZ-STORAGE-001"
    assert findings[0].resource == "rg/stpublic"
    assert findings[0].severity is Severity.HIGH


def test_storage_https_only_flags_insecure_transfer(monkeypatch):
    monkeypatch.setattr(
        checks,
        "az",
        lambda *args: [
            {"name": "stinsecure", "resourceGroup": "rg", "enableHttpsTrafficOnly": False},
            {"name": "stsecure", "resourceGroup": "rg", "enableHttpsTrafficOnly": True},
        ],
    )

    findings = checks.check_storage_https_only("sub")

    assert len(findings) == 1
    assert findings[0].check_id == "AZ-STORAGE-002"


def test_nsg_open_admin_ports_detects_ssh_from_internet(monkeypatch):
    def fake_az(*args):
        if args[:3] == ("network", "nsg", "list"):
            return [{"name": "nsg-aks", "resourceGroup": "rg-net"}]
        return [
            {
                "name": "AllowSSH",
                "access": "Allow",
                "direction": "Inbound",
                "sourceAddressPrefix": "*",
                "destinationPortRange": "22",
            },
            {
                "name": "AllowHttpsInternal",
                "access": "Allow",
                "direction": "Inbound",
                "sourceAddressPrefix": "10.0.0.0/8",
                "destinationPortRange": "443",
            },
        ]

    monkeypatch.setattr(checks, "az", fake_az)

    findings = checks.check_nsg_open_admin_ports("sub")

    assert len(findings) == 1
    assert findings[0].check_id == "AZ-NSG-001"
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].resource == "rg-net/nsg-aks/AllowSSH"


def test_keyvault_public_network_flags_enabled(monkeypatch):
    monkeypatch.setattr(
        checks,
        "az",
        lambda *args: [
            {"name": "kv-open", "properties": {"publicNetworkAccess": "Enabled"}},
            {"name": "kv-closed", "properties": {"publicNetworkAccess": "Disabled"}},
        ],
    )

    findings = checks.check_keyvault_public_network("sub")

    assert len(findings) == 1
    assert findings[0].resource == "kv-open"


def test_sql_public_access_flags_enabled(monkeypatch):
    monkeypatch.setattr(
        checks,
        "az",
        lambda *args: [
            {"name": "sql-open", "publicNetworkAccess": "Enabled"},
            {"name": "sql-closed", "publicNetworkAccess": "Disabled"},
        ],
    )

    findings = checks.check_sql_public_access("sub")

    assert len(findings) == 1
    assert findings[0].check_id == "AZ-SQL-001"


def test_run_live_scan_records_check_errors(monkeypatch):
    def boom(*args):
        raise RuntimeError("az login required")

    monkeypatch.setattr(checks, "az", boom)

    findings = checks.run_live_scan("sub")

    assert findings, "expected at least one SCAN-ERROR finding"
    assert all(f.check_id == "SCAN-ERROR" for f in findings)
    assert all(f.severity is Severity.INFO for f in findings)

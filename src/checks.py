"""Five Azure posture checks (az CLI)."""

from models import Finding, Severity
from azure_cli import az


def check_storage_public_access(subscription_id: str) -> list[Finding]:
    findings: list[Finding] = []
    accounts = az("storage", "account", "list", "--subscription", subscription_id)
    for acct in accounts:
        name = acct.get("name", "unknown")
        rg = acct.get("resourceGroup", "unknown")
        allow = acct.get("allowBlobPublicAccess")
        if allow is True:
            findings.append(
                Finding(
                    check_id="AZ-STORAGE-001",
                    title="Storage account allows public blob access",
                    severity=Severity.HIGH,
                    resource=f"{rg}/{name}",
                    detail="allowBlobPublicAccess is true",
                    remediation="Set allowBlobPublicAccess to false unless required for static websites.",
                )
            )
    return findings


def check_storage_https_only(subscription_id: str) -> list[Finding]:
    findings: list[Finding] = []
    accounts = az("storage", "account", "list", "--subscription", subscription_id)
    for acct in accounts:
        if acct.get("enableHttpsTrafficOnly") is False:
            findings.append(
                Finding(
                    check_id="AZ-STORAGE-002",
                    title="Storage account allows insecure HTTP",
                    severity=Severity.MEDIUM,
                    resource=f"{acct.get('resourceGroup')}/{acct.get('name')}",
                    detail="enableHttpsTrafficOnly is false",
                    remediation="Enable secure transfer (HTTPS only) on the storage account.",
                )
            )
    return findings


def check_nsg_open_admin_ports(subscription_id: str) -> list[Finding]:
    findings: list[Finding] = []
    nsgs = az("network", "nsg", "list", "--subscription", subscription_id)
    sensitive = {22, 3389, 445}
    for nsg in nsgs:
        name = nsg.get("name", "")
        rg = nsg.get("resourceGroup", "")
        rules = az(
            "network", "nsg", "rule", "list",
            "--resource-group", rg,
            "--nsg-name", name,
            "--subscription", subscription_id,
        )
        for rule in rules:
            if rule.get("access") != "Allow" or rule.get("direction") != "Inbound":
                continue
            src = (rule.get("sourceAddressPrefix") or "").lower()
            if src not in ("*", "0.0.0.0/0", "internet"):
                continue
            ports = rule.get("destinationPortRange") or ""
            if ports == "*" or any(str(p) in ports for p in sensitive):
                findings.append(
                    Finding(
                        check_id="AZ-NSG-001",
                        title="NSG allows admin ports from Internet",
                        severity=Severity.CRITICAL,
                        resource=f"{rg}/{name}/{rule.get('name')}",
                        detail=f"Inbound {ports} from {src}",
                        remediation="Restrict source to bastion/VPN CIDR or use Azure Bastion.",
                    )
                )
    return findings


def check_keyvault_public_network(subscription_id: str) -> list[Finding]:
    findings: list[Finding] = []
    vaults = az("keyvault", "list", "--subscription", subscription_id)
    for vault in vaults:
        props = vault.get("properties", {})
        if props.get("publicNetworkAccess", "").lower() == "enabled":
            findings.append(
                Finding(
                    check_id="AZ-KV-001",
                    title="Key Vault public network access enabled",
                    severity=Severity.MEDIUM,
                    resource=vault.get("name", "unknown"),
                    detail="publicNetworkAccess=Enabled",
                    remediation="Use private endpoints or disable public access with firewall rules.",
                )
            )
    return findings


def check_sql_public_access(subscription_id: str) -> list[Finding]:
    findings: list[Finding] = []
    servers = az("sql", "server", "list", "--subscription", subscription_id)
    for server in servers:
        if server.get("publicNetworkAccess", "").lower() == "enabled":
            findings.append(
                Finding(
                    check_id="AZ-SQL-001",
                    title="SQL server allows public network access",
                    severity=Severity.HIGH,
                    resource=server.get("name", "unknown"),
                    detail="publicNetworkAccess=Enabled",
                    remediation="Disable public access; use private endpoint or VNet rules.",
                )
            )
    return findings


ALL_CHECKS = [
    check_storage_public_access,
    check_storage_https_only,
    check_nsg_open_admin_ports,
    check_keyvault_public_network,
    check_sql_public_access,
]


def run_live_scan(subscription_id: str) -> list[Finding]:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        try:
            findings.extend(check(subscription_id))
        except RuntimeError as exc:
            findings.append(
                Finding(
                    check_id="SCAN-ERROR",
                    title=f"Check failed: {check.__name__}",
                    severity=Severity.INFO,
                    resource="subscription",
                    detail=str(exc)[:500],
                    remediation="Ensure az login and Reader role on subscription.",
                )
            )
    return findings


def demo_findings() -> list[Finding]:
    """Sample output for portfolio / offline demo (no Azure)."""
    return [
        Finding(
            check_id="AZ-STORAGE-001",
            title="Storage account allows public blob access",
            severity=Severity.HIGH,
            resource="rg-demo/sttfstateexample",
            detail="allowBlobPublicAccess is true",
            remediation="Set allowBlobPublicAccess to false.",
        ),
        Finding(
            check_id="AZ-STORAGE-002",
            title="Storage account allows insecure HTTP",
            severity=Severity.MEDIUM,
            resource="rg-demo/stlogs001",
            detail="enableHttpsTrafficOnly is false",
            remediation="Enable secure transfer (HTTPS only).",
        ),
        Finding(
            check_id="AZ-NSG-001",
            title="NSG allows admin ports from Internet",
            severity=Severity.CRITICAL,
            resource="rg-network/nsg-aks/AllowSSH",
            detail="Inbound 22 from 0.0.0.0/0",
            remediation="Restrict SSH to bastion or VPN CIDR.",
        ),
        Finding(
            check_id="AZ-KV-001",
            title="Key Vault public network access enabled",
            severity=Severity.MEDIUM,
            resource="kv-platform-dev",
            detail="publicNetworkAccess=Enabled",
            remediation="Use private endpoints.",
        ),
        Finding(
            check_id="AZ-SQL-001",
            title="SQL server allows public network access",
            severity=Severity.HIGH,
            resource="sql-app-dev",
            detail="publicNetworkAccess=Enabled",
            remediation="Disable public access; use private endpoint.",
        ),
    ]

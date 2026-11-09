import json

from models import Finding, Severity


def format_table(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    lines = [
        f"{'SEVERITY':<10} {'CHECK':<16} {'RESOURCE':<30} TITLE",
        "-" * 90,
    ]
    for f in findings:
        lines.append(
            f"{f.severity.value:<10} {f.check_id:<16} {f.resource[:28]:<30} {f.title}"
        )
    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    lines.append("")
    lines.append("Summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return "\n".join(lines)


def format_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def exit_code(findings: list[Finding]) -> int:
    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            return 1
    return 0


_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def format_sarif(findings: list[Finding]) -> str:
    """SARIF 2.1.0 output for GitHub Code Scanning upload."""
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rules.setdefault(f.check_id, {
            "id": f.check_id,
            "shortDescription": {"text": f.title},
            "help": {"text": f.remediation},
            "properties": {"severity": f.severity.value},
        })
        results.append({
            "ruleId": f.check_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.resource}: {f.detail}. Fix: {f.remediation}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": "azure-subscription"}},
                "logicalLocations": [{"fullyQualifiedName": f.resource}],
            }],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "cloud-security-scanner",
                "informationUri": "https://github.com/shohrabniaz/cloud-security-scanner",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)

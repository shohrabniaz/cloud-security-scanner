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

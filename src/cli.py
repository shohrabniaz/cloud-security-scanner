import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from checks import demo_findings, run_live_scan
from reporter import exit_code, format_json, format_table


def main() -> None:
    p = argparse.ArgumentParser(description="Azure cloud security posture scanner")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run posture checks")
    scan.add_argument("--subscription", "-s", help="Azure subscription ID")
    scan.add_argument("--demo", action="store_true", help="Offline demo findings (no Azure)")
    scan.add_argument("--format", choices=("table", "json"), default="table")

    args = p.parse_args()

    if args.command == "scan":
        if args.demo:
            findings = demo_findings()
        elif args.subscription:
            findings = run_live_scan(args.subscription)
        else:
            print("Use --demo or --subscription <id>", file=sys.stderr)
            sys.exit(2)

        if args.format == "json":
            print(format_json(findings))
        else:
            print(format_table(findings))
        sys.exit(exit_code(findings))


if __name__ == "__main__":
    main()

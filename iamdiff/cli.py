"""
cli.py
======
Command-line entry point.

    iamdiff compare old.json new.json --output report.html
    iamdiff compare old.json new.json --json               # machine-readable diff on stdout
    iamdiff analyze policy.json                             # risk-only report for a single policy
"""
from __future__ import annotations

import argparse
import json
import sys

from .differ import compare_policies
from .policy_parser import PolicyParseError, load_policy_file
from .report import render_html
from .risk_rules import analyze_policy


def _cmd_compare(args: argparse.Namespace) -> int:
    try:
        old_policy = load_policy_file(args.old)
        new_policy = load_policy_file(args.new)
    except (PolicyParseError, FileNotFoundError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    result = compare_policies(old_policy, new_policy)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        html = render_html(result, old_label=args.old, new_label=args.new)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"Wrote {args.output}")
        print(
            f"  +{len(result.added)} added   "
            f"-{len(result.removed)} removed   "
            f"~{len(result.modified)} modified   "
            f"={result.unchanged_count} unchanged"
        )
        if result.introduced_risks:
            print(f"  ⚠ {len(result.introduced_risks)} new risk finding(s) introduced — see report.")

    if args.fail_on_risk and result.introduced_risks:
        return 2
    return 0


def _cmd_analyze(args: argparse.Namespace) -> int:
    try:
        policy = load_policy_file(args.policy)
    except (PolicyParseError, FileNotFoundError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    findings = analyze_policy(policy)
    if args.json:
        print(json.dumps(
            [{"category": f.category, "severity": f.severity, "title": f.title,
              "detail": f.detail, "actions": f.actions} for f in findings],
            indent=2,
        ))
        return 0

    if not findings:
        print(f"No risk findings for {args.policy}.")
        return 0

    print(f"{len(findings)} risk finding(s) for {args.policy}:\n")
    for f in sorted(findings, key=lambda x: {"High": 0, "Medium": 1, "Low": 2}.get(x.severity, 9)):
        print(f"[{f.severity}] {f.title}")
        print(f"    {f.detail}")
        print(f"    actions: {', '.join(f.actions)}\n")

    return 2 if args.fail_on_risk else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iamdiff",
        description="IAM Policy Diff Visualizer — shows effective permission change, not just JSON diff.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_compare = sub.add_parser("compare", help="Compare two IAM policy documents.")
    p_compare.add_argument("old", help="Path to the old/baseline policy JSON file.")
    p_compare.add_argument("new", help="Path to the new/proposed policy JSON file.")
    p_compare.add_argument("-o", "--output", default="iamdiff-report.html", help="HTML report output path.")
    p_compare.add_argument("--json", action="store_true", help="Print machine-readable diff JSON to stdout instead of writing HTML.")
    p_compare.add_argument("--fail-on-risk", action="store_true", help="Exit with code 2 if the change introduces new risk findings (useful in CI).")
    p_compare.set_defaults(func=_cmd_compare)

    p_analyze = sub.add_parser("analyze", help="Run the risk ruleset against a single policy document.")
    p_analyze.add_argument("policy", help="Path to the policy JSON file.")
    p_analyze.add_argument("--json", action="store_true", help="Print machine-readable findings JSON.")
    p_analyze.add_argument("--fail-on-risk", action="store_true", help="Exit with code 2 if any risk findings are present (useful in CI).")
    p_analyze.set_defaults(func=_cmd_analyze)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

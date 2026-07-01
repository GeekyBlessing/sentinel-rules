#!/usr/bin/env python3
"""
Sentinel Rules - AWS Detection-as-Code Engine
Evaluates Sigma-format detection rules against CloudTrail logs.

Usage:
    python3 run.py --logs fixtures/logs/sample_events.json
    python3 run.py --logs fixtures/logs/sample_events.json --format json
    python3 run.py --live --hours 24 --region eu-north-1
"""
import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from engine.rule_loader import load_rules
from engine.detection_engine import load_events, run_all_rules
from engine.output_formatters import to_json, to_sarif
from engine.slack_alerter import send_slack_alert

console = Console(stderr=True)

LEVEL_COLORS = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
}


def print_table_report(findings):
    if not findings:
        console.print("[bold green]No detections triggered.[/bold green] Environment appears clean against current ruleset.")
        return

    table = Table(title=f"{len(findings)} Detection(s) Triggered", box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", justify="center")
    table.add_column("Rule")
    table.add_column("Event")
    table.add_column("Actor")
    table.add_column("MITRE ATT&CK")
    table.add_column("Time")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: severity_order.get(f.level, 4))

    for f in findings:
        style = LEVEL_COLORS.get(f.level, "white")
        mitre = ", ".join(f.mitre_techniques) if f.mitre_techniques else "-"
        table.add_row(
            f"[{style}]{f.level.upper()}[/{style}]",
            f.rule_title,
            f.event_name,
            f.actor,
            mitre,
            f.event_time,
        )

    console.print(table)

    critical_count = sum(1 for f in findings if f.level == "critical")
    high_count = sum(1 for f in findings if f.level == "high")
    console.print(
        f"\n[bold]Summary:[/bold] {critical_count} critical, {high_count} high, "
        f"{len(findings) - critical_count - high_count} other"
    )


def main():
    parser = argparse.ArgumentParser(description="Sentinel Rules detection engine")
    parser.add_argument("--logs", help="Path to CloudTrail JSON log file")
    parser.add_argument("--live", action="store_true", help="Fetch real events from AWS CloudTrail Event History instead of a file")
    parser.add_argument("--region", default="eu-north-1", help="AWS region for live CloudTrail lookup")
    parser.add_argument("--hours", type=int, default=24, help="Lookback window in hours for live mode")
    parser.add_argument("--rules", default="rules", help="Path to rules directory")
    parser.add_argument(
        "--format", choices=["table", "json", "sarif"], default="table",
        help="Output format: table (human readable), json (machine readable), sarif (GitHub code scanning / CI integration)"
    )
    parser.add_argument("--slack-webhook", help="Slack Incoming Webhook URL to send alerts to")
    parser.add_argument("--slack-min-severity", choices=["critical", "high", "medium", "low"], default="high", help="Minimum severity to alert on Slack")
    parser.add_argument(
        "--fail-on", choices=["critical", "high", "medium", "low", "none"], default="none",
        help="Exit with non-zero status if any finding at or above this severity is present (for CI gating)"
    )
    args = parser.parse_args()

    if not args.live and not args.logs:
        console.print("[bold red]Error:[/bold red] must provide either --logs <file> or --live")
        sys.exit(1)

    if args.format == "table":
        console.print(Panel.fit(
            "[bold cyan]SENTINEL RULES[/bold cyan]\n[dim]AWS Detection-as-Code Engine[/dim]",
            border_style="cyan"
        ))

    rules = load_rules(args.rules)

    if args.live:
        from engine.aws_fetcher import fetch_cloudtrail_events
        if args.format == "table":
            console.print(f"[dim]Fetching live CloudTrail events from AWS ({args.region}, last {args.hours}h)...[/dim]")
        try:
            events = fetch_cloudtrail_events(region=args.region, hours_back=args.hours)
        except Exception as e:
            console.print(f"[bold red]AWS fetch failed:[/bold red] {e}")
            sys.exit(1)
    else:
        try:
            events = load_events(args.logs)
        except FileNotFoundError:
            console.print(f"[bold red]Error:[/bold red] log file not found: {args.logs}")
            sys.exit(1)

    if args.format == "table":
        console.print(f"[dim]Loaded {len(rules)} detection rules from {args.rules}/[/dim]")
        console.print(f"[dim]Loaded {len(events)} CloudTrail events[/dim]\n")

    findings = run_all_rules(events, rules)

    if args.format == "json":
        print(to_json(findings))
    elif args.format == "sarif":
        print(to_sarif(findings))
    else:
        print_table_report(findings)

    if args.slack_webhook and findings:
        summary = send_slack_alert(args.slack_webhook, findings, min_severity=args.slack_min_severity)
        if args.format == "table":
            console.print(
                f"[dim]Slack: {summary['alerts_sent']} sent, "
                f"{summary['alerts_failed']} failed, "
                f"{summary['suppressed_below_threshold']} below threshold[/dim]"
            )

    if args.fail_on != "none":
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold = severity_order[args.fail_on]
        if any(severity_order.get(f.level, 4) <= threshold for f in findings):
            sys.exit(1)


if __name__ == "__main__":
    main()

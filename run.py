#!/usr/bin/env python3
"""
Sentinel Rules - AWS Detection-as-Code Engine
Evaluates Sigma-format detection rules against CloudTrail logs.

Usage:
    python3 run.py --logs fixtures/logs/sample_events.json
"""
import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from engine.rule_loader import load_rules
from engine.detection_engine import load_events, run_all_rules

console = Console()

LEVEL_COLORS = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
}


def main():
    parser = argparse.ArgumentParser(description="Sentinel Rules detection engine")
    parser.add_argument("--logs", required=True, help="Path to CloudTrail JSON log file")
    parser.add_argument("--rules", default="rules", help="Path to rules directory")
    args = parser.parse_args()

    console.print(Panel.fit(
        "[bold cyan]SENTINEL RULES[/bold cyan]\n[dim]AWS Detection-as-Code Engine[/dim]",
        border_style="cyan"
    ))

    rules = load_rules(args.rules)
    console.print(f"[dim]Loaded {len(rules)} detection rules from {args.rules}/[/dim]")

    try:
        events = load_events(args.logs)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] log file not found: {args.logs}")
        sys.exit(1)

    console.print(f"[dim]Loaded {len(events)} CloudTrail events from {args.logs}[/dim]\n")

    findings = run_all_rules(events, rules)

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


if __name__ == "__main__":
    main()

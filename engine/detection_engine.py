"""Core detection engine: runs Sigma rules against a list of CloudTrail events."""
import json
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from engine.rule_loader import SigmaRule
from engine.field_matcher import match_block
from engine.condition_evaluator import evaluate_rule_detection


@dataclass
class Finding:
    rule_id: str
    rule_title: str
    level: str
    mitre_tactics: list
    mitre_techniques: list
    event_time: str
    event_name: str
    event_source: str
    actor: str
    raw_event: dict = field(default_factory=dict)


def load_events(log_path: str) -> list[dict]:
    """Loads CloudTrail-style JSON logs. Supports a single JSON array file."""
    with open(log_path) as f:
        data = json.load(f)
    # CloudTrail exports usually wrap events in a "Records" key
    if isinstance(data, dict) and "Records" in data:
        return data["Records"]
    if isinstance(data, list):
        return data
    raise ValueError(f"Unrecognized log format in {log_path}")


def _actor_of(event: dict) -> str:
    identity = event.get("userIdentity", {})
    return identity.get("arn") or identity.get("userName") or identity.get("type", "unknown")


def _event_time(event: dict):
    ts = event.get("eventTime")
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def run_standard_rules(events: list[dict], rules: list[SigmaRule]) -> list[Finding]:
    """Runs all non-timeframe rules against every event."""
    findings = []
    for rule in rules:
        if rule.timeframe:
            continue  # handled separately by run_correlation_rules
        for event in events:
            if evaluate_rule_detection(event, rule.detection, match_block):
                findings.append(Finding(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    level=rule.level,
                    mitre_tactics=rule.mitre_tactics,
                    mitre_techniques=rule.mitre_techniques,
                    event_time=event.get("eventTime", "unknown"),
                    event_name=event.get("eventName", "unknown"),
                    event_source=event.get("eventSource", "unknown"),
                    actor=_actor_of(event),
                    raw_event=event,
                ))
    return findings


def run_correlation_rules(events: list[dict], rules: list[SigmaRule]) -> list[Finding]:
    """
    Handles rules with a 'timeframe' (e.g. '10m'): for each actor, checks whether
    both named sub-blocks fire within the timeframe window, regardless of order.
    """
    findings = []
    sorted_events = sorted(
        [e for e in events if _event_time(e) is not None],
        key=_event_time
    )

    for rule in rules:
        if not rule.timeframe:
            continue

        window_minutes = int(rule.timeframe.rstrip("m"))
        block_names = [k for k in rule.detection if k != "condition"]

        # Group matching events per actor, per block
        actor_block_hits = {}  # actor -> block_name -> list[(time, event)]
        for event in sorted_events:
            actor = _actor_of(event)
            for block_name in block_names:
                block_def = rule.detection[block_name]
                if match_block(event, block_def):
                    actor_block_hits.setdefault(actor, {}).setdefault(block_name, []).append(
                        (_event_time(event), event)
                    )

        for actor, blocks_hit in actor_block_hits.items():
            if len(blocks_hit) < len(block_names):
                continue  # not all required blocks fired for this actor
            # Check every combination for one within the timeframe window
            all_times = [(name, t, e) for name, hits in blocks_hit.items() for t, e in hits]
            all_times.sort(key=lambda x: x[1])
            for i in range(len(all_times)):
                window_start = all_times[i][1]
                window_end = window_start + timedelta(minutes=window_minutes)
                names_in_window = {all_times[i][0]}
                trigger_event = all_times[i][2]
                for j in range(i + 1, len(all_times)):
                    if all_times[j][1] <= window_end:
                        names_in_window.add(all_times[j][0])
                    else:
                        break
                if names_in_window == set(block_names):
                    findings.append(Finding(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        level=rule.level,
                        mitre_tactics=rule.mitre_tactics,
                        mitre_techniques=rule.mitre_techniques,
                        event_time=trigger_event.get("eventTime", "unknown"),
                        event_name=f"CORRELATED: {' -> '.join(block_names)}",
                        event_source=trigger_event.get("eventSource", "unknown"),
                        actor=actor,
                        raw_event=trigger_event,
                    ))
                    break  # one correlated finding per actor is enough
    return findings


def run_all_rules(events: list[dict], rules: list[SigmaRule]) -> list[Finding]:
    findings = run_standard_rules(events, rules)
    findings += run_correlation_rules(events, rules)
    return findings

"""Unit tests for engine/detection_engine.py, including correlation logic."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.rule_loader import SigmaRule
from engine.detection_engine import run_standard_rules, run_correlation_rules, run_all_rules


def make_rule(id, title, level, tags, detection, timeframe=None):
    return SigmaRule(
        id=id, title=title, description="test rule", level=level,
        status="stable", tags=tags, detection=detection, timeframe=timeframe,
    )


def test_standard_rule_fires_on_matching_event():
    rule = make_rule(
        "r1", "Root Key Created", "critical", ["attack.persistence", "attack.t1098.001"],
        detection={
            "selection": {"eventName": "CreateAccessKey", "userIdentity.type": "Root"},
            "condition": "selection",
        },
    )
    events = [
        {"eventName": "CreateAccessKey", "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123:root"},
         "eventTime": "2026-06-30T09:00:00Z", "eventSource": "iam.amazonaws.com"},
        {"eventName": "CreateAccessKey", "userIdentity": {"type": "IAMUser", "arn": "arn:x"},
         "eventTime": "2026-06-30T09:00:00Z", "eventSource": "iam.amazonaws.com"},
    ]
    findings = run_standard_rules(events, [rule])
    assert len(findings) == 1
    assert findings[0].actor == "arn:aws:iam::123:root"
    assert "T1098.001" in findings[0].mitre_techniques


def test_standard_rule_no_match_produces_no_findings():
    rule = make_rule(
        "r1", "Root Key Created", "critical", [],
        detection={"selection": {"eventName": "CreateAccessKey"}, "condition": "selection"},
    )
    events = [{"eventName": "DeleteBucket", "eventTime": "2026-06-30T09:00:00Z",
               "eventSource": "s3.amazonaws.com", "userIdentity": {"type": "IAMUser"}}]
    assert run_standard_rules(events, [rule]) == []


def test_correlation_rule_fires_within_timeframe():
    rule = make_rule(
        "r6", "Account Takeover Chain", "critical", [],
        detection={
            "mfa_disable": {"eventName": ["DeactivateMFADevice"]},
            "priv_esc": {"eventName": ["AttachUserPolicy"]},
            "condition": "mfa_disable and priv_esc",
        },
        timeframe="10m",
    )
    events = [
        {"eventName": "DeactivateMFADevice", "eventTime": "2026-06-30T14:02:00Z",
         "eventSource": "iam.amazonaws.com", "userIdentity": {"arn": "arn:aws:iam::123:user/j.smith"}},
        {"eventName": "AttachUserPolicy", "eventTime": "2026-06-30T14:07:00Z",
         "eventSource": "iam.amazonaws.com", "userIdentity": {"arn": "arn:aws:iam::123:user/j.smith"}},
    ]
    findings = run_correlation_rules(events, [rule])
    assert len(findings) == 1
    assert findings[0].actor == "arn:aws:iam::123:user/j.smith"
    assert "CORRELATED" in findings[0].event_name


def test_correlation_rule_does_not_fire_outside_timeframe():
    rule = make_rule(
        "r6", "Account Takeover Chain", "critical", [],
        detection={
            "mfa_disable": {"eventName": ["DeactivateMFADevice"]},
            "priv_esc": {"eventName": ["AttachUserPolicy"]},
            "condition": "mfa_disable and priv_esc",
        },
        timeframe="10m",
    )
    events = [
        {"eventName": "DeactivateMFADevice", "eventTime": "2026-06-30T14:00:00Z",
         "eventSource": "iam.amazonaws.com", "userIdentity": {"arn": "arn:aws:iam::123:user/j.smith"}},
        {"eventName": "AttachUserPolicy", "eventTime": "2026-06-30T15:00:00Z",
         "eventSource": "iam.amazonaws.com", "userIdentity": {"arn": "arn:aws:iam::123:user/j.smith"}},
    ]
    assert run_correlation_rules(events, [rule]) == []


def test_correlation_rule_requires_same_actor():
    rule = make_rule(
        "r6", "Account Takeover Chain", "critical", [],
        detection={
            "mfa_disable": {"eventName": ["DeactivateMFADevice"]},
            "priv_esc": {"eventName": ["AttachUserPolicy"]},
            "condition": "mfa_disable and priv_esc",
        },
        timeframe="10m",
    )
    events = [
        {"eventName": "DeactivateMFADevice", "eventTime": "2026-06-30T14:02:00Z",
         "eventSource": "iam.amazonaws.com", "userIdentity": {"arn": "arn:aws:iam::123:user/alice"}},
        {"eventName": "AttachUserPolicy", "eventTime": "2026-06-30T14:07:00Z",
         "eventSource": "iam.amazonaws.com", "userIdentity": {"arn": "arn:aws:iam::123:user/bob"}},
    ]
    assert run_correlation_rules(events, [rule]) == []


def test_run_all_rules_combines_standard_and_correlation():
    standard_rule = make_rule(
        "r1", "Root Key Created", "critical", [],
        detection={"selection": {"eventName": "CreateAccessKey"}, "condition": "selection"},
    )
    correlation_rule = make_rule(
        "r6", "Account Takeover Chain", "critical", [],
        detection={
            "mfa_disable": {"eventName": ["DeactivateMFADevice"]},
            "priv_esc": {"eventName": ["AttachUserPolicy"]},
            "condition": "mfa_disable and priv_esc",
        },
        timeframe="10m",
    )
    events = [
        {"eventName": "CreateAccessKey", "eventTime": "2026-06-30T09:00:00Z",
         "eventSource": "iam.amazonaws.com", "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123:root"}},
        {"eventName": "DeactivateMFADevice", "eventTime": "2026-06-30T14:02:00Z",
         "eventSource": "iam.amazonaws.com", "userIdentity": {"arn": "arn:aws:iam::123:user/j.smith"}},
        {"eventName": "AttachUserPolicy", "eventTime": "2026-06-30T14:07:00Z",
         "eventSource": "iam.amazonaws.com", "userIdentity": {"arn": "arn:aws:iam::123:user/j.smith"}},
    ]
    findings = run_all_rules(events, [standard_rule, correlation_rule])
    assert len(findings) == 2

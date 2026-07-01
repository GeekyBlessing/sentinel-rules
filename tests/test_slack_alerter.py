"""Unit tests for engine/slack_alerter.py (uses mocking, sends no real requests)."""
import sys
import os
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.detection_engine import Finding
from engine.slack_alerter import send_slack_alert, _build_slack_payload


def make_finding(level="critical"):
    return Finding(
        rule_id="8f3c1e2a-1234-4abc-9def-000000000002",
        rule_title="Access Key Created for Root Account",
        level=level,
        mitre_tactics=["Persistence"],
        mitre_techniques=["T1098.001"],
        event_time="2026-06-30T09:15:33Z",
        event_name="CreateAccessKey",
        event_source="iam.amazonaws.com",
        actor="arn:aws:iam::358487322954:root",
    )


def test_build_slack_payload_structure():
    finding = make_finding()
    payload = _build_slack_payload(finding)
    assert "attachments" in payload
    assert payload["attachments"][0]["color"] == "#d32f2f"


@patch("engine.slack_alerter._post_to_slack")
def test_send_slack_alert_sends_above_threshold(mock_post):
    findings = [make_finding("critical"), make_finding("medium")]
    result = send_slack_alert("https://hooks.slack.com/fake", findings, min_severity="high")
    assert result["alerts_sent"] == 1
    assert result["suppressed_below_threshold"] == 1
    assert mock_post.call_count == 1


@patch("engine.slack_alerter._post_to_slack")
def test_send_slack_alert_sends_none_when_all_below_threshold(mock_post):
    findings = [make_finding("low"), make_finding("medium")]
    result = send_slack_alert("https://hooks.slack.com/fake", findings, min_severity="critical")
    assert result["alerts_sent"] == 0
    assert mock_post.call_count == 0

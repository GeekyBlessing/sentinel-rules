"""Unit tests for engine/output_formatters.py"""
import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.detection_engine import Finding
from engine.output_formatters import to_json, to_sarif


def make_finding():
    return Finding(
        rule_id="8f3c1e2a-1234-4abc-9def-000000000002",
        rule_title="Access Key Created for Root Account",
        level="critical",
        mitre_tactics=["Persistence"],
        mitre_techniques=["T1098.001"],
        event_time="2026-06-30T09:15:33Z",
        event_name="CreateAccessKey",
        event_source="iam.amazonaws.com",
        actor="arn:aws:iam::358487322954:root",
    )


def test_to_json_produces_valid_json():
    findings = [make_finding()]
    result = json.loads(to_json(findings))
    assert len(result) == 1
    assert result[0]["rule_id"] == "8f3c1e2a-1234-4abc-9def-000000000002"
    assert result[0]["level"] == "critical"


def test_to_json_empty_findings():
    assert json.loads(to_json([])) == []


def test_to_sarif_produces_valid_structure():
    findings = [make_finding()]
    result = json.loads(to_sarif(findings))
    assert result["version"] == "2.1.0"
    assert len(result["runs"]) == 1
    assert len(result["runs"][0]["results"]) == 1
    assert result["runs"][0]["results"][0]["ruleId"] == "8f3c1e2a-1234-4abc-9def-000000000002"


def test_to_sarif_maps_critical_to_error_level():
    findings = [make_finding()]
    result = json.loads(to_sarif(findings))
    assert result["runs"][0]["results"][0]["level"] == "error"


def test_to_sarif_includes_mitre_in_rule_properties():
    findings = [make_finding()]
    result = json.loads(to_sarif(findings))
    rule_meta = result["runs"][0]["tool"]["driver"]["rules"][0]
    assert "T1098.001" in rule_meta["properties"]["tags"]

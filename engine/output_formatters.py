"""Formats Finding objects as JSON or SARIF (Static Analysis Results Interchange Format)."""
import json
from datetime import datetime, timezone


def to_json(findings: list, pretty: bool = True) -> str:
    """Serializes findings to a JSON array."""
    data = [
        {
            "rule_id": f.rule_id,
            "rule_title": f.rule_title,
            "level": f.level,
            "mitre_tactics": f.mitre_tactics,
            "mitre_techniques": f.mitre_techniques,
            "event_time": f.event_time,
            "event_name": f.event_name,
            "event_source": f.event_source,
            "actor": f.actor,
        }
        for f in findings
    ]
    return json.dumps(data, indent=2 if pretty else None)


_SARIF_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def to_sarif(findings: list, tool_name: str = "Sentinel Rules", tool_version: str = "1.0.0") -> str:
    """
    Serializes findings to SARIF 2.1.0, the standard format used by GitHub code
    scanning, Semgrep, CodeQL, and most SAST/detection tooling for interop.
    """
    # Build a deduplicated rule catalog for the SARIF "rules" metadata block
    rule_catalog = {}
    for f in findings:
        if f.rule_id not in rule_catalog:
            rule_catalog[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_title,
                "shortDescription": {"text": f.rule_title},
                "properties": {
                    "tags": f.mitre_techniques,
                    "security-severity": _severity_score(f.level),
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL_MAP.get(f.level, "warning")},
            }

    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL_MAP.get(f.level, "warning"),
            "message": {
                "text": f"{f.rule_title} triggered by {f.actor} via {f.event_name} at {f.event_time}"
            },
            "locations": [
                {
                    "logicalLocations": [
                        {
                            "name": f.event_source,
                            "kind": "module",
                        }
                    ]
                }
            ],
            "properties": {
                "actor": f.actor,
                "eventTime": f.event_time,
                "mitreTactics": f.mitre_tactics,
                "mitreTechniques": f.mitre_techniques,
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": "https://github.com/GeekyBlessing/sentinel-rules",
                        "rules": list(rule_catalog.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _severity_score(level: str) -> str:
    """Maps Sentinel Rules severity to SARIF's 0.0-10.0 security-severity scale (CVSS-like)."""
    return {
        "critical": "9.5",
        "high": "7.5",
        "medium": "5.0",
        "low": "2.5",
    }.get(level, "5.0")

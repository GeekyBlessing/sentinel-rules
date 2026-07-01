"""
Sends Slack alerts for detection findings via an Incoming Webhook.
Only alerts on findings at or above a configurable severity threshold,
to avoid alert fatigue from low/medium noise.
"""
import json
import urllib.request
import urllib.error


LEVEL_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "medium": ":large_yellow_circle:",
    "low": ":information_source:",
}

LEVEL_COLOR = {
    "critical": "#d32f2f",
    "high": "#f44336",
    "medium": "#ff9800",
    "low": "#2196f3",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def send_slack_alert(webhook_url: str, findings: list, min_severity: str = "high") -> dict:
    """
    Sends one Slack message per finding at or above min_severity.
    Returns a summary dict of how many were sent vs suppressed.
    """
    threshold = _SEVERITY_ORDER.get(min_severity, 1)
    to_send = [f for f in findings if _SEVERITY_ORDER.get(f.level, 4) <= threshold]

    sent = 0
    failed = 0

    for finding in to_send:
        payload = _build_slack_payload(finding)
        try:
            _post_to_slack(webhook_url, payload)
            sent += 1
        except urllib.error.URLError:
            failed += 1

    return {
        "total_findings": len(findings),
        "alerts_sent": sent,
        "alerts_failed": failed,
        "suppressed_below_threshold": len(findings) - len(to_send),
    }


def _build_slack_payload(finding) -> dict:
    emoji = LEVEL_EMOJI.get(finding.level, ":large_yellow_circle:")
    color = LEVEL_COLOR.get(finding.level, "#9e9e9e")
    mitre = ", ".join(finding.mitre_techniques) if finding.mitre_techniques else "N/A"

    return {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"{emoji} *{finding.level.upper()}: {finding.rule_title}*",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Actor:*\n{finding.actor}"},
                            {"type": "mrkdwn", "text": f"*Event:*\n{finding.event_name}"},
                            {"type": "mrkdwn", "text": f"*Source:*\n{finding.event_source}"},
                            {"type": "mrkdwn", "text": f"*Time:*\n{finding.event_time}"},
                            {"type": "mrkdwn", "text": f"*MITRE ATT&CK:*\n{mitre}"},
                            {"type": "mrkdwn", "text": f"*Rule ID:*\n{finding.rule_id}"},
                        ],
                    },
                ],
            }
        ]
    }


def _post_to_slack(webhook_url: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data, headers={"Content-Type": "application/json"}
    )
    urllib.request.urlopen(req, timeout=10)

# Sentinel Rules

**AWS Detection-as-Code Engine using Sigma-format rules mapped to MITRE ATT&CK**

![CI](https://github.com/GeekyBlessing/sentinel-rules/actions/workflows/ci.yml/badge.svg)

Sentinel Rules is a detection engineering project that codifies AWS threat detection logic as version-controlled Sigma rules, then evaluates those rules against CloudTrail logs using a custom Python engine. It is designed to complement offensive security findings (such as those in [AWS Attack Path Analyzer](https://github.com/GeekyBlessing/aws-attack-path-analyzer)) with the blue-team detection layer that catches an attacker actually using those paths.

## Why this project exists

Most cloud security portfolios are heavy on offensive tooling and light on detection engineering. Sentinel Rules closes that gap by demonstrating the full detection lifecycle: threat modeling, rule authoring in an industry-standard format (Sigma), false-positive tuning, MITRE ATT&CK mapping, and correlation logic for multi-stage attack chains.

## Architecture
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full system diagram, detection evaluation flow, and correlation engine flow (Mermaid diagrams, render directly on GitHub).

## Detection rules included

| Rule | Severity | MITRE ATT&CK | Status |
|---|---|---|---|
| Root Access Key Creation | Critical | T1098.001 | Stable |
| MFA Device Deactivated | High | T1556.006 | Stable |
| IAM Privilege Escalation via Policy Attachment | High | T1078.004 | Stable |
| S3 Bucket Policy Public Exposure | High | T1530 | Stable |
| Suspicious Cross-Account AssumeRole | Medium | T1550.001 | Experimental |
| Correlated Account Takeover Chain | Critical | T1556.006, T1078.004 | Experimental |

The correlation rule is the most advanced piece: it links two individually weak signals (an MFA deactivation and a privilege escalation event) and fires a critical alert only when both occur for the same actor within a 10 minute window. This is the same pattern used in production SIEM correlation logic to reduce alert fatigue while preserving detection of genuine multi-stage attacks.

## Tuning and false positive reduction

Every rule includes a documented `falsepositives` field, and two rules ship with active tuning filters:

- The privilege escalation rule excludes known CI/CD and Terraform service roles by ARN pattern
- The S3 public access rule excludes buckets matching an approved naming convention for intentional static site hosting

This reflects real detection engineering practice: a rule that fires on every legitimate automation event is not a usable rule.

## Running it

```bash
python3 -m venv venv
source venv/bin/activate
pip install pyyaml jsonschema rich

python3 run.py --logs fixtures/logs/sample_events.json
```

## Example output

Running the engine against the included sample CloudTrail log (a simulated account takeover scenario) produces:
Note that a legitimate Terraform automation event and an approved public static site bucket are correctly excluded from the results, confirming the tuning filters work as intended.

## Using your own CloudTrail logs

Export CloudTrail events as JSON (either a raw array of event objects or a standard CloudTrail export with a `Records` key) and point the engine at the file:

```bash
python3 run.py --logs path/to/your/cloudtrail_export.json
```

## Roadmap

- Slack alerting integration for critical and high severity findings
- GuardDuty finding ingestion as an additional log source
- Automated CI pipeline to validate new Sigma rules on every commit
- Expansion to additional AWS services (Lambda, EC2, RDS)

## Author

Toriola Opeyemi
Cloud Security Engineer
[toriolaopeyemi.com](https://toriolaopeyemi.com)
[GitHub](https://github.com/GeekyBlessing)
opeyemitoriola41@gmail.com

## Output formats

Sentinel Rules supports three output modes:

- **table** (default): human readable terminal report with color coded severity
- **json**: machine readable, for piping into other tools or scripts
- **sarif**: SARIF 2.1.0 format, the standard used by GitHub code scanning, Semgrep, and CodeQL. This means findings can be uploaded directly to a repository's Security tab.

```bash
python3 run.py --logs fixtures/logs/sample_events.json --format sarif > results.sarif
```

## CI gating

The `--fail-on` flag allows Sentinel Rules to act as a policy gate in a CI/CD pipeline, for example failing a deployment if a critical finding is present in recent CloudTrail activity:

```bash
python3 run.py --logs recent_events.json --fail-on critical
```

## Live AWS integration

Sentinel Rules can pull real events directly from AWS CloudTrail Event History (the default 90-day event log available in every AWS account, no trail configuration required) instead of static fixture files:

```bash
python3 run.py --live --hours 24 --region eu-north-1
```

This was tested against a live AWS account (500 events over a 24 hour window). During testing, the `assume_role_anomaly` rule initially fired on every AWS service-linked role assumption (`userIdentity.type: AWSService`), which is expected internal AWS activity, not a security signal. The rule was tuned with an explicit filter to exclude AWS service principals, a real example of the false-positive reduction work that separates a usable detection rule from a noisy one.

## AWS credentials

Live mode uses standard AWS credential resolution (`aws configure`, environment variables, or an IAM role). Read-only CloudTrail access is sufficient, no write permissions are required.

## Slack alerting

Sentinel Rules can send real-time Slack alerts for findings at or above a configurable severity threshold, using a Slack Incoming Webhook:

```bash
python3 run.py --live --hours 24 --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL --slack-min-severity high
```

Alerts include the rule title, actor, event details, and MITRE ATT&CK mapping, formatted as a Slack Block Kit message with severity-based color coding.

## Feature overview

| Feature | Status |
|---|---|
| Sigma-format detection rules | Done |
| MITRE ATT&CK mapping | Done |
| Custom condition evaluator (and/or/not) | Done |
| False-positive tuning filters | Done |
| Timeframe-based correlation detection | Done |
| Unit test suite (34 tests) | Done |
| CI pipeline (GitHub Actions, 3 Python versions) | Done |
| JSON output | Done |
| SARIF 2.1.0 output (GitHub code scanning compatible) | Done |
| CI policy gating (`--fail-on`) | Done |
| Live AWS CloudTrail integration (boto3) | Done |
| Slack alerting | Done |
| Architecture and threat model documentation | Done |
| GuardDuty finding ingestion | Planned |
| N-stage correlation chains | Planned |
| Additional AWS services (Lambda, EC2, RDS) | Planned |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for system diagrams and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full threat model and ATT&CK coverage matrix.

# Threat Model

## Scope

Sentinel Rules focuses on detecting post-compromise activity within an AWS account, specifically the stages an attacker moves through after obtaining valid but stolen or misused credentials. It does not attempt to detect initial access (phishing, credential leaks) directly; that is the domain of endpoint/email security tooling. Instead it assumes a threat actor already has some level of access and is escalating.

## Threat actor assumptions

- Has valid IAM credentials (stolen, leaked, or misused by an insider)
- Does not yet have persistent administrative access
- Is attempting to escalate privileges, disable defenses, exfiltrate data, or move laterally between accounts

## Attack chain modeled

This mirrors the real-world account takeover pattern documented in multiple cloud breach post-mortems:

1. **Initial foothold** (out of scope): attacker obtains valid credentials
2. **Defense evasion**: attacker disables MFA to prevent being locked out or challenged (`mfa_disabled` rule)
3. **Privilege escalation**: attacker attaches an administrator policy to their own or a new principal (`iam_privilege_escalation` rule)
4. **Persistence**: attacker creates long-lived credentials, in the worst case for the root account itself (`root_access_key_creation` rule)
5. **Collection / exfiltration**: attacker opens data stores to public access for retrieval (`s3_public_access` rule)
6. **Lateral movement**: attacker pivots into other accounts within the organization (`assume_role_anomaly` rule)

The `correlation_account_takeover_chain` rule specifically targets steps 2 and 3 occurring together, the highest-confidence signal in this model, since individually either event has legitimate explanations, but the pair occurring within 10 minutes for the same actor does not.

## ATT&CK coverage matrix

| Tactic | Technique | Rule | Status |
|---|---|---|---|
| Persistence | T1098.001 (Additional Cloud Credentials) | root_access_key_creation | Stable |
| Defense Evasion | T1556.006 (MFA Modification) | mfa_disabled | Stable |
| Privilege Escalation | T1078.004 (Cloud Accounts) | iam_privilege_escalation | Stable |
| Exfiltration / Collection | T1530 (Data from Cloud Storage) | s3_public_access | Stable |
| Lateral Movement | T1550.001 (Application Access Token) | assume_role_anomaly | Experimental (tuned against AWS service noise) |
| Defense Evasion + Privilege Escalation (chained) | T1556.006 + T1078.004 | correlation_account_takeover_chain | Experimental |

## Known limitations

- Detection is only as good as CloudTrail log completeness; if logging is disabled or a region is not covered, events are invisible to this engine
- The correlation rule currently supports two-event chains within a fixed timeframe; it does not yet support N-stage chains or cross-rule correlation
- Rules are tuned against one specific AWS account's baseline; deploying against a different account requires re-validating the tuning filters (e.g. service role ARNs, known automation identities)

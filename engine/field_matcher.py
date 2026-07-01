"""Evaluates whether a single CloudTrail event matches a Sigma detection block."""


def _get_nested(event: dict, dotted_key: str):
    """Resolves dotted keys like 'requestParameters.policyArn' against a nested dict."""
    parts = dotted_key.split(".")
    value = event
    for part in parts:
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


def _match_value(actual, expected) -> bool:
    """Matches a single field's actual value against expected (str or list of str)."""
    if actual is None:
        return False
    if isinstance(expected, list):
        return actual in expected
    return actual == expected


def _match_contains(actual, expected) -> bool:
    """Handles the |contains Sigma modifier: substring match, list = OR."""
    if actual is None:
        return False
    actual_str = str(actual)
    if isinstance(expected, list):
        return any(exp in actual_str for exp in expected)
    return str(expected) in actual_str


def match_block(event: dict, block: dict) -> bool:
    """
    Evaluates one detection sub-block (e.g. 'selection', 'high_risk_policy')
    against an event. All fields in the block must match (AND logic).
    """
    for field_key, expected in block.items():
        if field_key.endswith("|contains"):
            real_key = field_key[: -len("|contains")]
            actual = _get_nested(event, real_key)
            if not _match_contains(actual, expected):
                return False
        else:
            actual = _get_nested(event, field_key)
            if not _match_value(actual, expected):
                return False
    return True

"""
Parses and evaluates Sigma 'condition' strings against a dict of
block_name -> bool results (already computed by field_matcher).

Supports: and, or, not, and parentheses. E.g.:
  "selection_events and high_risk_policy and not filter_known_automation"
  "mfa_disable and priv_esc"
"""
import re


def evaluate_condition(condition_str: str, block_results: dict) -> bool:
    tokens = re.findall(r"\(|\)|and|or|not|[A-Za-z_][A-Za-z0-9_]*", condition_str)

    def resolve(tok):
        if tok in ("and", "or", "not", "(", ")"):
            return tok
        return "True" if block_results.get(tok, False) else "False"

    py_expr = " ".join(resolve(t) for t in tokens)

    # Safety: only allow a strict whitelist of characters/words before eval
    allowed = re.fullmatch(r"[\sA-Za-z()]+", py_expr.replace("True", "").replace("False", ""))
    if not re.fullmatch(r"[\s()]*((True|False|and|or|not)[\s()]*)+", py_expr):
        raise ValueError(f"Unsafe or malformed condition expression: {condition_str}")

    return eval(py_expr, {"__builtins__": {}}, {})


def evaluate_rule_detection(event: dict, detection: dict, match_block_fn) -> bool:
    """
    Given an event and a rule's full 'detection' dict, computes each named
    block's match result, then evaluates the 'condition' string against them.
    """
    condition_str = detection.get("condition", "")
    block_results = {}
    for block_name, block_def in detection.items():
        if block_name == "condition":
            continue
        block_results[block_name] = match_block_fn(event, block_def)
    return evaluate_condition(condition_str, block_results)

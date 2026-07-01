"""Unit tests for engine/condition_evaluator.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from engine.condition_evaluator import evaluate_condition, evaluate_rule_detection


def test_simple_and_condition_true():
    results = {"selection": True, "high_risk_policy": True}
    assert evaluate_condition("selection and high_risk_policy", results) is True


def test_simple_and_condition_false():
    results = {"selection": True, "high_risk_policy": False}
    assert evaluate_condition("selection and high_risk_policy", results) is False


def test_and_not_condition():
    results = {"selection": True, "high_risk_policy": True, "filter_known_automation": True}
    condition = "selection and high_risk_policy and not filter_known_automation"
    assert evaluate_condition(condition, results) is False


def test_and_not_condition_when_filter_absent():
    results = {"selection": True, "high_risk_policy": True, "filter_known_automation": False}
    condition = "selection and high_risk_policy and not filter_known_automation"
    assert evaluate_condition(condition, results) is True


def test_unknown_block_defaults_to_false():
    results = {"selection": True}
    assert evaluate_condition("selection and undefined_block", results) is False


def test_rejects_unsafe_expression():
    results = {"selection": True}
    with pytest.raises(ValueError):
        evaluate_condition("selection; __import__('os').system('echo pwned')", results)


def test_evaluate_rule_detection_end_to_end():
    event = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    }
    detection = {
        "selection_events": {
            "eventSource": "iam.amazonaws.com",
            "eventName": ["AttachUserPolicy", "AttachRolePolicy"],
        },
        "high_risk_policy": {
            "requestParameters.policyArn|contains": ["AdministratorAccess"]
        },
        "condition": "selection_events and high_risk_policy",
    }

    def match_block_fn(evt, block):
        from engine.field_matcher import match_block
        return match_block(evt, block)

    assert evaluate_rule_detection(event, detection, match_block_fn) is True

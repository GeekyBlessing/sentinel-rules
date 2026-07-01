"""Unit tests for engine/field_matcher.py"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from engine.field_matcher import match_block, _get_nested, _match_contains, _match_value


def test_get_nested_simple_key():
    event = {"eventName": "AttachUserPolicy"}
    assert _get_nested(event, "eventName") == "AttachUserPolicy"


def test_get_nested_dotted_key():
    event = {"requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}}
    assert _get_nested(event, "requestParameters.policyArn") == "arn:aws:iam::aws:policy/AdministratorAccess"


def test_get_nested_missing_key_returns_none():
    event = {"eventName": "AttachUserPolicy"}
    assert _get_nested(event, "requestParameters.policyArn") is None


def test_match_value_exact_match():
    assert _match_value("AttachUserPolicy", "AttachUserPolicy") is True


def test_match_value_list_match():
    assert _match_value("AttachUserPolicy", ["AttachUserPolicy", "AttachRolePolicy"]) is True


def test_match_value_no_match():
    assert _match_value("DeleteBucket", ["AttachUserPolicy", "AttachRolePolicy"]) is False


def test_match_value_none_actual_returns_false():
    assert _match_value(None, "AttachUserPolicy") is False


def test_match_contains_substring_found():
    assert _match_contains("arn:aws:iam::aws:policy/AdministratorAccess", "AdministratorAccess") is True


def test_match_contains_list_or_logic():
    expected = ["AdministratorAccess", "PowerUserAccess"]
    assert _match_contains("arn:aws:iam::aws:policy/PowerUserAccess", expected) is True


def test_match_contains_no_match():
    assert _match_contains("arn:aws:iam::aws:policy/ReadOnlyAccess", ["AdministratorAccess"]) is False


def test_match_block_all_fields_must_match():
    event = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    }
    block = {
        "eventSource": "iam.amazonaws.com",
        "eventName": ["AttachUserPolicy", "AttachRolePolicy"],
    }
    assert match_block(event, block) is True


def test_match_block_contains_modifier():
    event = {"requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}}
    block = {"requestParameters.policyArn|contains": ["AdministratorAccess", "PowerUserAccess"]}
    assert match_block(event, block) is True


def test_match_block_fails_when_one_field_mismatches():
    event = {"eventSource": "s3.amazonaws.com", "eventName": "AttachUserPolicy"}
    block = {"eventSource": "iam.amazonaws.com", "eventName": "AttachUserPolicy"}
    assert match_block(event, block) is False

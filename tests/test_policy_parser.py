import pytest

from iamdiff.policy_parser import PolicyParseError, load_policy


def test_normalizes_single_statement_to_list():
    doc = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
    }
    policy = load_policy(doc)
    assert len(policy.statements) == 1
    assert policy.statements[0].actions == ["s3:GetObject"]


def test_normalizes_string_action_and_resource_to_lists():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b"}],
    }
    policy = load_policy(doc)
    stmt = policy.statements[0]
    assert stmt.actions == ["s3:GetObject"]
    assert stmt.resources == ["arn:aws:s3:::b"]


def test_defaults_resource_to_wildcard_when_absent():
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject"}]}
    policy = load_policy(doc)
    assert policy.statements[0].resources == ["*"]


def test_rejects_missing_statement_key():
    with pytest.raises(PolicyParseError):
        load_policy({"Version": "2012-10-17"})


def test_rejects_invalid_effect():
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Maybe", "Action": "*", "Resource": "*"}]}
    with pytest.raises(PolicyParseError):
        load_policy(doc)


def test_rejects_both_action_and_not_action():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:*", "NotAction": "s3:DeleteObject", "Resource": "*"}],
    }
    with pytest.raises(PolicyParseError):
        load_policy(doc)


def test_rejects_invalid_json_string():
    with pytest.raises(PolicyParseError):
        load_policy("{not valid json")


def test_not_action_flagged():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "NotAction": "s3:DeleteObject", "Resource": "*"}],
    }
    policy = load_policy(doc)
    assert policy.statements[0].not_action is True
    assert policy.statements[0].actions == ["s3:DeleteObject"]


def test_condition_and_sid_preserved():
    doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "MySid",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        }],
    }
    policy = load_policy(doc)
    stmt = policy.statements[0]
    assert stmt.sid == "MySid"
    assert stmt.has_condition() is True

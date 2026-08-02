from iamdiff.effective_permissions import compute_effective_permissions
from iamdiff.policy_parser import load_policy


def test_simple_allow_is_effective():
    policy = load_policy({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}],
    })
    eff = compute_effective_permissions(policy)
    assert eff["s3:GetObject"].effect == "Allow"
    assert eff["s3:GetObject"].resources[0].resource == "arn:aws:s3:::b/*"


def test_explicit_deny_overrides_allow_for_same_action():
    policy = load_policy({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "A", "Effect": "Allow", "Action": "s3:DeleteObject", "Resource": "*"},
            {"Sid": "D", "Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
        ],
    })
    eff = compute_effective_permissions(policy)
    assert eff["s3:DeleteObject"].effect == "Deny"


def test_condition_flag_propagates():
    policy = load_policy({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
        }],
    })
    eff = compute_effective_permissions(policy)
    assert eff["s3:GetObject"].conditioned is True


def test_not_action_grants_everything_except_listed():
    policy = load_policy({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "NotAction": "s3:DeleteObject", "Resource": "*"}],
    })
    eff = compute_effective_permissions(policy)
    assert "s3:GetObject" in eff
    assert "s3:DeleteObject" not in eff


def test_multiple_statements_merge_resources_for_same_action():
    policy = load_policy({
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "One", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::a/*"},
            {"Sid": "Two", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
        ],
    })
    eff = compute_effective_permissions(policy)
    resources = {r.resource for r in eff["s3:GetObject"].resources}
    assert resources == {"arn:aws:s3:::a/*", "arn:aws:s3:::b/*"}


def test_wildcard_action_expands_into_many_entries():
    policy = load_policy({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}],
    })
    eff = compute_effective_permissions(policy)
    assert "iam:PassRole" in eff
    assert len(eff) > 50

from iamdiff.policy_parser import load_policy
from iamdiff.risk_rules import analyze_policy


def test_detects_high_risk_single_action(privesc_policy):
    policy = load_policy(privesc_policy)
    findings = analyze_policy(policy)
    titles = {f.title for f in findings}
    assert any("iam:PassRole" in t for t in titles)
    assert any("ec2:RunInstances" in t for t in titles)


def test_detects_escalation_combo(privesc_policy):
    policy = load_policy(privesc_policy)
    findings = analyze_policy(policy)
    combo_findings = [f for f in findings if f.category == "escalation_combo"]
    assert len(combo_findings) == 1
    assert combo_findings[0].actions == ["ec2:RunInstances", "iam:PassRole"]


def test_detects_wildcard_resource(privesc_policy):
    policy = load_policy(privesc_policy)
    findings = analyze_policy(policy)
    assert any(f.category == "wildcard_resource" for f in findings)


def test_clean_policy_has_no_findings(empty_ish_policy):
    policy = load_policy(empty_ish_policy)
    findings = analyze_policy(policy)
    assert findings == []


def test_wildcard_action_statement_flagged():
    policy = load_policy({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    })
    findings = analyze_policy(policy)
    categories = {f.category for f in findings}
    assert "wildcard_action" in categories
    assert "wildcard_resource" in categories


def test_deny_statement_not_flagged_as_wildcard_grant():
    policy = load_policy({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
    })
    findings = analyze_policy(policy)
    assert findings == []  # a Deny * is not a risky *grant*

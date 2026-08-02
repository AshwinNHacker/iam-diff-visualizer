from iamdiff.differ import compare_policies


def test_identical_policies_show_no_changes(s3_readonly_policy):
    result = compare_policies(s3_readonly_policy, s3_readonly_policy)
    assert not result.has_changes()
    assert result.unchanged_count == 2  # s3:GetObject, s3:ListBucket


def test_wildcard_rewrite_of_same_actions_shows_extra_grants(s3_readonly_policy, s3_wildcard_policy):
    """
    s3_readonly grants exactly [GetObject, ListBucket].
    s3_wildcard grants s3:Get* (a superset including GetObject, but NOT
    ListBucket, and many other Get* actions). This proves the tool reasons
    about EFFECTIVE permissions: it should show ListBucket as removed and
    a pile of new Get*-family actions as added, not just "Action field changed".
    """
    result = compare_policies(s3_readonly_policy, s3_wildcard_policy)
    added_actions = {e.action for e in result.added}
    removed_actions = {e.action for e in result.removed}

    assert "s3:ListBucket" in removed_actions
    assert "s3:GetObject" not in added_actions  # unchanged, already granted
    assert "s3:GetObject" not in removed_actions
    assert len(added_actions) > 5  # many additional Get* actions newly granted


def test_true_equivalent_rewrite_shows_as_unchanged():
    """
    Two policies that are textually very different but expand to the exact
    same effective grant must diff as UNCHANGED -- this is the tool's core
    value proposition versus a plain JSON diff.
    """
    explicit = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}],
    }
    same_but_different_json = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "DifferentSidSameEffect", "Effect": "Allow", "Action": "s3:GetObject", "Resource": ["arn:aws:s3:::b/*"]}],
    }
    result = compare_policies(explicit, same_but_different_json)
    assert not result.has_changes()
    assert result.unchanged_count == 1


def test_introduced_risk_detected_end_to_end(s3_readonly_policy, privesc_policy):
    result = compare_policies(s3_readonly_policy, privesc_policy)
    assert len(result.introduced_risks) > 0
    titles = {r.title for r in result.introduced_risks}
    assert any("PassRole" in t for t in titles)


def test_resolved_risk_detected_end_to_end(privesc_policy, s3_readonly_policy):
    result = compare_policies(privesc_policy, s3_readonly_policy)
    assert len(result.resolved_risks) > 0


def test_deny_added_shows_as_effect_changed():
    old = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": "*"}]}
    new = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:DeleteObject", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
        ],
    }
    result = compare_policies(old, new)
    assert len(result.modified) == 1
    entry = result.modified[0]
    assert entry.change_type == "effect_changed"
    assert entry.old_effect == "Allow"
    assert entry.new_effect == "Deny"


def test_resource_widening_flagged():
    old = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::specific-bucket/*"}]}
    new = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    result = compare_policies(old, new)
    assert len(result.modified) == 1
    assert result.modified[0].resource_widened is True


def test_to_dict_is_json_serializable(s3_readonly_policy, privesc_policy):
    import json
    result = compare_policies(s3_readonly_policy, privesc_policy)
    json.dumps(result.to_dict())  # must not raise

from iamdiff.expander import expand_action, expand_actions, is_unresolved


def test_literal_action_expands_to_itself():
    result = expand_action("s3:GetObject")
    assert result == {"s3:GetObject"}


def test_service_wildcard_includes_known_action():
    result = expand_action("s3:Get*")
    assert "s3:GetObject" in result
    assert all(a.startswith("s3:Get") for a in result)
    assert len(result) > 1  # there are many s3:Get* actions


def test_full_service_wildcard_is_large():
    result = expand_action("iam:*")
    assert "iam:PassRole" in result
    assert "iam:CreateUser" in result
    assert len(result) > 50


def test_global_wildcard_covers_multiple_services():
    result = expand_action("*")
    services = {a.split(":")[0] for a in result}
    assert "s3" in services
    assert "iam" in services
    assert "ec2" in services
    assert len(result) > 1000


def test_unknown_service_returns_literal_unresolved():
    result = expand_action("totallymadeupservice:DoThing")
    assert result == {"totallymadeupservice:DoThing"}
    assert is_unresolved(next(iter(result))) is False  # no glob char present


def test_unmatched_wildcard_pattern_falls_back_to_literal():
    result = expand_action("s3:ZzzNoSuchPrefix*")
    assert result == {"s3:ZzzNoSuchPrefix*"}
    assert is_unresolved(next(iter(result))) is True


def test_expand_actions_unions_multiple_patterns():
    result = expand_actions(["s3:GetObject", "s3:PutObject"])
    assert result == {"s3:GetObject", "s3:PutObject"}


def test_case_insensitive_literal_match():
    # IAM action names are case-insensitive in practice.
    result = expand_action("s3:getobject")
    assert result == {"s3:GetObject"}

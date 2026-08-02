"""
policy_parser.py
=================
Loads and normalizes AWS IAM policy documents (identity-based or
resource-based) into a predictable internal shape so the rest of the
engine never has to special-case "string vs list" JSON quirks.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union


class PolicyParseError(ValueError):
    """Raised when a document is not a well-formed IAM policy."""


def _as_list(value: Union[None, str, List[str]]) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return list(value)
    raise PolicyParseError(f"Expected string or list, got {type(value).__name__}: {value!r}")


@dataclass
class Statement:
    sid: Optional[str]
    effect: str  # "Allow" | "Deny"
    actions: List[str]
    not_action: bool  # True if this statement used NotAction instead of Action
    resources: List[str]
    not_resource: bool  # True if this statement used NotResource instead of Resource
    condition: Dict[str, Any] = field(default_factory=dict)
    principal: Optional[Any] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_wildcard_resource(self) -> bool:
        return self.resources == ["*"]

    def has_condition(self) -> bool:
        return bool(self.condition)


@dataclass
class Policy:
    version: Optional[str]
    statements: List[Statement]
    source: Dict[str, Any] = field(default_factory=dict)


def load_policy(data: Union[str, Dict[str, Any]]) -> Policy:
    """
    Accepts a JSON string, a file-like path is NOT handled here (see cli.py),
    or an already-parsed dict, and returns a normalized Policy.
    """
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as exc:
            raise PolicyParseError(f"Invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyParseError("Policy document must be a JSON object")

    if "Statement" not in data:
        raise PolicyParseError('Policy document is missing required "Statement" key')

    raw_statements = data["Statement"]
    if isinstance(raw_statements, dict):
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list):
        raise PolicyParseError('"Statement" must be an object or a list of objects')

    statements: List[Statement] = []
    for i, raw in enumerate(raw_statements):
        if not isinstance(raw, dict):
            raise PolicyParseError(f"Statement #{i} is not a JSON object")

        effect = raw.get("Effect")
        if effect not in ("Allow", "Deny"):
            raise PolicyParseError(
                f'Statement #{i} ({raw.get("Sid", "no Sid")}) has invalid Effect: {effect!r}'
            )

        has_action = "Action" in raw
        has_not_action = "NotAction" in raw
        if has_action and has_not_action:
            raise PolicyParseError(f"Statement #{i} cannot specify both Action and NotAction")
        if not has_action and not has_not_action:
            raise PolicyParseError(f"Statement #{i} must specify Action or NotAction")

        has_resource = "Resource" in raw
        has_not_resource = "NotResource" in raw
        if has_resource and has_not_resource:
            raise PolicyParseError(f"Statement #{i} cannot specify both Resource and NotResource")

        actions = _as_list(raw.get("Action") if has_action else raw.get("NotAction"))
        resources = _as_list(raw.get("Resource") if has_resource else raw.get("NotResource")) or ["*"]

        statements.append(
            Statement(
                sid=raw.get("Sid"),
                effect=effect,
                actions=actions,
                not_action=has_not_action,
                resources=resources,
                not_resource=has_not_resource,
                condition=raw.get("Condition") or {},
                principal=raw.get("Principal"),
                raw=raw,
            )
        )

    return Policy(version=data.get("Version"), statements=statements, source=data)


def load_policy_file(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as fh:
        return load_policy(fh.read())

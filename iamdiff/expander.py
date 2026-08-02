"""
expander.py
===========
Expands IAM action patterns ("s3:Get*", "s3:*", "*", "iam:PassRole") into
the concrete set of "service:Action" strings they actually grant. This is
the piece that lets the tool reason about *effective* permissions instead
of comparing wildcard strings verbatim.
"""
from __future__ import annotations

import fnmatch
from functools import lru_cache
from typing import FrozenSet, Set

from . import actions_db


def _split_action(pattern: str):
    if ":" not in pattern:
        return None, pattern
    service, action = pattern.split(":", 1)
    return service, action


@lru_cache(maxsize=4096)
def expand_action(pattern: str) -> FrozenSet[str]:
    """
    Expands a single action pattern into a frozenset of concrete
    "service:Action" strings, using the bundled action catalogue.

    Falls back to returning the pattern itself, unexpanded, when the
    service/action isn't present in the catalogue (e.g. a brand-new AWS
    service, or a typo) -- this is surfaced to the user as an "unresolved"
    action rather than silently dropped or silently wrong.
    """
    pattern = pattern.strip()
    if pattern == "*":
        results = set()
        for service, actions in actions_db.load_db().items():
            for action in actions:
                results.add(f"{service}:{action}")
        return frozenset(results)

    service, action_pattern = _split_action(pattern)
    if service is None:
        return frozenset({pattern})

    service_lower = service.lower()
    catalogue = actions_db.actions_for_service(service_lower)

    if not catalogue:
        # Unknown service prefix: cannot expand. Return as-is (unresolved).
        return frozenset({pattern})

    if "*" not in action_pattern and "?" not in action_pattern:
        # No glob chars: literal action. Keep original casing convention
        # (service:Action) even if the catalogue's exact case differs
        # slightly; IAM action names are case-insensitive.
        matches = [a for a in catalogue if a.lower() == action_pattern.lower()]
        if matches:
            return frozenset({f"{service_lower}:{matches[0]}"})
        # Not found in catalogue -> unresolved literal action.
        return frozenset({pattern})

    matched = {
        f"{service_lower}:{a}"
        for a in catalogue
        if fnmatch.fnmatchcase(a.lower(), action_pattern.lower())
    }
    return frozenset(matched) if matched else frozenset({pattern})


def expand_actions(patterns) -> Set[str]:
    """Expands an iterable of action patterns into one combined set."""
    result: Set[str] = set()
    for p in patterns:
        result |= expand_action(p)
    return result


def is_unresolved(action: str) -> bool:
    """True if `action` still contains a glob character (i.e. expansion failed)."""
    return "*" in action or "?" in action

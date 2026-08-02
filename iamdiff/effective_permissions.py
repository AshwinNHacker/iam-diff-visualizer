"""
effective_permissions.py
=========================
Turns a parsed Policy (statements with possible wildcards, NotAction,
NotResource, and Conditions) into a flat map of *effective* grants per
concrete action:

    {
      "s3:GetObject": EffectiveGrant(
          effect="Allow",
          resources=[ResourceGrant("arn:aws:s3:::my-bucket/*", sid="Read", conditioned=False), ...],
          conditioned=False,
      ),
      ...
    }

Scope & honesty about approximation
------------------------------------
Real IAM evaluation is context-dependent (request time, source IP,
MFA presence, tags, etc.) and resource-ARN intersection is a deep
rabbit hole (wildcards, account/region variables, service-specific ARN
grammars). This engine implements the two rules that matter most for
*policy review* (which is this tool's actual job):

  1. An explicit Deny for an action always beats an Allow for that same
     action, regardless of which statement resource scopes involved
     (conservative: we flag the action as Denied and show you both
     statements so a human makes the final call on resource overlap).
  2. A statement carrying a Condition doesn't disappear -- its grant is
     kept, but flagged `conditioned=True` so the diff/report can tell you
     "this permission's real-world effect depends on a condition we
     didn't evaluate" instead of silently treating it as unconditional.

This keeps the tool honest: it never claims a more precise answer than
static policy analysis can actually give.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from . import expander
from .actions_db import load_db
from .policy_parser import Policy, Statement


@dataclass
class ResourceGrant:
    resource: str
    sid: str
    conditioned: bool
    condition: dict
    statement_index: int
    via_not_resource: bool = False


@dataclass
class EffectiveGrant:
    action: str
    effect: str  # "Allow" | "Deny"
    resources: List[ResourceGrant] = field(default_factory=list)
    conditioned: bool = False
    unresolved: bool = False  # True if the action pattern could not be expanded


def _all_known_actions() -> set:
    result = set()
    for service, actions in load_db().items():
        for a in actions:
            result.add(f"{service}:{a}")
    return result


def _actions_for_statement(stmt: Statement) -> set:
    if stmt.not_action:
        return _all_known_actions() - expander.expand_actions(stmt.actions)
    return expander.expand_actions(stmt.actions)


def compute_effective_permissions(policy: Policy) -> Dict[str, EffectiveGrant]:
    """
    Returns {action: EffectiveGrant} where Deny beats Allow per the rules
    documented above, across ALL statements in the policy.
    """
    allow_grants: Dict[str, EffectiveGrant] = {}
    deny_grants: Dict[str, EffectiveGrant] = {}

    for idx, stmt in enumerate(policy.statements):
        actions = _actions_for_statement(stmt)
        target = deny_grants if stmt.effect == "Deny" else allow_grants

        resource_label = stmt.resources
        via_not_resource = stmt.not_resource
        if via_not_resource:
            resource_display = [f"NOT({r})" for r in resource_label]
        else:
            resource_display = resource_label

        for action in actions:
            grant = target.setdefault(
                action,
                EffectiveGrant(action=action, effect=stmt.effect),
            )
            if expander.is_unresolved(action):
                grant.unresolved = True
            for r in resource_display:
                grant.resources.append(
                    ResourceGrant(
                        resource=r,
                        sid=stmt.sid or f"stmt#{idx}",
                        conditioned=stmt.has_condition(),
                        condition=stmt.condition,
                        statement_index=idx,
                        via_not_resource=via_not_resource,
                    )
                )
            if stmt.has_condition():
                grant.conditioned = True

    # Deny always wins for a given action, per module docstring policy.
    effective: Dict[str, EffectiveGrant] = {}
    for action, grant in allow_grants.items():
        effective[action] = grant
    for action, grant in deny_grants.items():
        effective[action] = grant  # overrides any Allow for the same action

    return effective

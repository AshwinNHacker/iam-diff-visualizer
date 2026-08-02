"""
differ.py
=========
The heart of the tool: given two IAM policies (old, new), compute the
*effective permission diff* -- which concrete "service:Action" grants
were added, removed, or changed (effect, resource scope, or condition) --
plus which security-relevant risks appeared or disappeared.

This is deliberately NOT a JSON diff. Two policies that look completely
different at the JSON level (e.g. "s3:Get*" replaced by an explicit list
of eleven GetObject-family actions) will correctly show as UNCHANGED
here if they expand to the same effective grants.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import risk_rules
from .effective_permissions import EffectiveGrant, compute_effective_permissions
from .policy_parser import Policy, load_policy


@dataclass
class ActionDiffEntry:
    action: str
    change_type: str  # "added" | "removed" | "effect_changed" | "scope_changed" | "condition_changed"
    old_effect: Optional[str] = None
    new_effect: Optional[str] = None
    old_resources: List[str] = field(default_factory=list)
    new_resources: List[str] = field(default_factory=list)
    old_conditioned: bool = False
    new_conditioned: bool = False
    resource_widened: bool = False
    unresolved: bool = False


@dataclass
class DiffResult:
    added: List[ActionDiffEntry] = field(default_factory=list)
    removed: List[ActionDiffEntry] = field(default_factory=list)
    modified: List[ActionDiffEntry] = field(default_factory=list)
    unchanged_count: int = 0

    old_risks: List[risk_rules.RiskFinding] = field(default_factory=list)
    new_risks: List[risk_rules.RiskFinding] = field(default_factory=list)
    introduced_risks: List[risk_rules.RiskFinding] = field(default_factory=list)
    resolved_risks: List[risk_rules.RiskFinding] = field(default_factory=list)

    old_service_summary: Dict[str, int] = field(default_factory=dict)
    new_service_summary: Dict[str, int] = field(default_factory=dict)

    unresolved_actions: List[str] = field(default_factory=list)

    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    def to_dict(self) -> dict:
        def entry(e: ActionDiffEntry):
            return {
                "action": e.action,
                "change_type": e.change_type,
                "old_effect": e.old_effect,
                "new_effect": e.new_effect,
                "old_resources": e.old_resources,
                "new_resources": e.new_resources,
                "old_conditioned": e.old_conditioned,
                "new_conditioned": e.new_conditioned,
                "resource_widened": e.resource_widened,
                "unresolved": e.unresolved,
            }

        def risk(r: risk_rules.RiskFinding):
            return {
                "category": r.category,
                "severity": r.severity,
                "title": r.title,
                "detail": r.detail,
                "actions": r.actions,
            }

        return {
            "summary": {
                "added": len(self.added),
                "removed": len(self.removed),
                "modified": len(self.modified),
                "unchanged": self.unchanged_count,
                "introduced_risks": len(self.introduced_risks),
                "resolved_risks": len(self.resolved_risks),
            },
            "added": [entry(e) for e in self.added],
            "removed": [entry(e) for e in self.removed],
            "modified": [entry(e) for e in self.modified],
            "old_risks": [risk(r) for r in self.old_risks],
            "new_risks": [risk(r) for r in self.new_risks],
            "introduced_risks": [risk(r) for r in self.introduced_risks],
            "resolved_risks": [risk(r) for r in self.resolved_risks],
            "old_service_summary": self.old_service_summary,
            "new_service_summary": self.new_service_summary,
            "unresolved_actions": self.unresolved_actions,
        }


def _resource_widened(old_resources: List[str], new_resources: List[str]) -> bool:
    """
    Heuristic: flags scope widening when the new grant includes an
    unscoped "*" resource and the old grant did not, OR when the new
    resource list contains a strictly shorter/more-generic ARN prefix
    than every old pattern (simple prefix containment check).
    Conservative by design: only flags the clear-cut case to avoid
    false positives from AWS's varied ARN grammars.
    """
    old_set, new_set = set(old_resources), set(new_resources)
    if "*" in new_set and "*" not in old_set:
        return True
    for new_r in new_set - old_set:
        if new_r.startswith("NOT("):
            continue
        for old_r in old_set:
            if old_r.startswith("NOT("):
                continue
            # new_r is a generalization of old_r if old_r starts with the
            # non-wildcard prefix of new_r and new_r is shorter/broader.
            prefix = new_r.split("*")[0]
            if prefix and old_r.startswith(prefix) and len(new_r) < len(old_r):
                return True
    return False


def _service_summary(effective: Dict[str, EffectiveGrant]) -> Dict[str, int]:
    summary: Dict[str, int] = {}
    for action, grant in effective.items():
        if grant.effect != "Allow":
            continue
        service = action.split(":", 1)[0]
        summary[service] = summary.get(service, 0) + 1
    return summary


def diff_effective_permissions(
    old_effective: Dict[str, EffectiveGrant],
    new_effective: Dict[str, EffectiveGrant],
) -> DiffResult:
    result = DiffResult()
    all_actions = set(old_effective.keys()) | set(new_effective.keys())

    for action in sorted(all_actions):
        old_grant = old_effective.get(action)
        new_grant = new_effective.get(action)

        if old_grant is None and new_grant is not None:
            result.added.append(
                ActionDiffEntry(
                    action=action,
                    change_type="added",
                    new_effect=new_grant.effect,
                    new_resources=sorted({r.resource for r in new_grant.resources}),
                    new_conditioned=new_grant.conditioned,
                    unresolved=new_grant.unresolved,
                )
            )
            continue

        if old_grant is not None and new_grant is None:
            result.removed.append(
                ActionDiffEntry(
                    action=action,
                    change_type="removed",
                    old_effect=old_grant.effect,
                    old_resources=sorted({r.resource for r in old_grant.resources}),
                    old_conditioned=old_grant.conditioned,
                    unresolved=old_grant.unresolved,
                )
            )
            continue

        # Present in both -- check for effect / scope / condition changes.
        old_resources = sorted({r.resource for r in old_grant.resources})
        new_resources = sorted({r.resource for r in new_grant.resources})

        effect_changed = old_grant.effect != new_grant.effect
        scope_changed = set(old_resources) != set(new_resources)
        condition_changed = old_grant.conditioned != new_grant.conditioned

        if effect_changed or scope_changed or condition_changed:
            change_type = (
                "effect_changed" if effect_changed else
                "scope_changed" if scope_changed else
                "condition_changed"
            )
            result.modified.append(
                ActionDiffEntry(
                    action=action,
                    change_type=change_type,
                    old_effect=old_grant.effect,
                    new_effect=new_grant.effect,
                    old_resources=old_resources,
                    new_resources=new_resources,
                    old_conditioned=old_grant.conditioned,
                    new_conditioned=new_grant.conditioned,
                    resource_widened=_resource_widened(old_resources, new_resources),
                    unresolved=new_grant.unresolved,
                )
            )
        else:
            result.unchanged_count += 1

    for grant in list(old_effective.values()) + list(new_effective.values()):
        if grant.unresolved and grant.action not in result.unresolved_actions:
            result.unresolved_actions.append(grant.action)
    result.unresolved_actions.sort()

    return result


def compare_policies(old_policy, new_policy) -> DiffResult:
    """
    Compares two IAM policies and returns a DiffResult.

    `old_policy` / `new_policy` may each be:
      - a dict (already-parsed JSON policy document)
      - a JSON string
      - a `Policy` instance (see policy_parser.load_policy)
    """
    old_parsed: Policy = old_policy if isinstance(old_policy, Policy) else load_policy(old_policy)
    new_parsed: Policy = new_policy if isinstance(new_policy, Policy) else load_policy(new_policy)

    old_effective = compute_effective_permissions(old_parsed)
    new_effective = compute_effective_permissions(new_parsed)

    result = diff_effective_permissions(old_effective, new_effective)

    result.old_service_summary = _service_summary(old_effective)
    result.new_service_summary = _service_summary(new_effective)

    result.old_risks = risk_rules.analyze_policy(old_parsed)
    result.new_risks = risk_rules.analyze_policy(new_parsed)

    old_titles = {r.title for r in result.old_risks}
    new_titles = {r.title for r in result.new_risks}
    result.introduced_risks = [r for r in result.new_risks if r.title not in old_titles]
    result.resolved_risks = [r for r in result.old_risks if r.title not in new_titles]

    return result

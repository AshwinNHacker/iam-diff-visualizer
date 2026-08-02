"""
risk_rules.py
=============
A curated catalogue of IAM actions/patterns that are known to be
security-sensitive -- either because they are classic AWS privilege
escalation primitives (see Rhino Security Labs' "AWS IAM Privilege
Escalation" research, and the AWS IAM documentation on permissions
boundaries) or because they broaden the blast radius of a policy
(wildcard actions/resources, resource-policy edits, etc.).

This module is intentionally a static, reviewable list rather than a
black box -- extend `HIGH_RISK_ACTIONS` / `ESCALATION_COMBOS` as new
techniques are published.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Set

# Single actions that are dangerous largely on their own merit, with a
# short human-readable reason shown in the report.
HIGH_RISK_ACTIONS: Dict[str, str] = {
    "iam:PassRole": "Lets the principal hand its own or another role to a service; a classic building block for privilege escalation when combined with a service that will assume the role (see ESCALATION_COMBOS).",
    "iam:CreatePolicyVersion": "Can create a new default policy version, effectively rewriting the permissions of any policy the principal can target.",
    "iam:SetDefaultPolicyVersion": "Can roll a managed policy back/forward to a version the principal controls.",
    "iam:CreateAccessKey": "Can mint long-lived credentials for any IAM user, including higher-privileged ones.",
    "iam:UpdateAssumeRolePolicy": "Can rewrite a role's trust policy to allow itself (or an external account) to assume it.",
    "iam:AttachUserPolicy": "Can attach any managed policy (including AdministratorAccess) to a user.",
    "iam:AttachRolePolicy": "Can attach any managed policy (including AdministratorAccess) to a role.",
    "iam:AttachGroupPolicy": "Can attach any managed policy (including AdministratorAccess) to a group.",
    "iam:PutUserPolicy": "Can write an arbitrary inline policy onto a user.",
    "iam:PutRolePolicy": "Can write an arbitrary inline policy onto a role.",
    "iam:PutGroupPolicy": "Can write an arbitrary inline policy onto a group.",
    "iam:AddUserToGroup": "Can add itself/another principal to a higher-privileged group.",
    "iam:CreateLoginProfile": "Can set a console password for an IAM user that has none, enabling console takeover.",
    "iam:UpdateLoginProfile": "Can reset the console password of an existing IAM user.",
    "sts:AssumeRole": "Can assume any role in scope; risk depends heavily on the resource scope (flagged separately when Resource is '*').",
    "organizations:CreateAccount": "Can create new member accounts, potentially outside existing guardrails.",
    "kms:PutKeyPolicy": "Can rewrite a KMS key's resource policy, potentially granting decrypt to arbitrary principals.",
    "kms:CreateGrant": "Can grant KMS key usage to another principal without editing the key policy.",
    "lambda:AddPermission": "Can grant other principals invoke rights on a function, or add resource-based triggers.",
    "lambda:UpdateFunctionCode": "Can overwrite the code of an existing Lambda function, hijacking its execution role at runtime.",
    "ec2:RunInstances": "Combined with iam:PassRole, allows launching an instance with an over-privileged instance profile.",
    "cloudformation:CreateStack": "Combined with iam:PassRole, can create arbitrary resources including new IAM entities.",
    "glue:CreateDevEndpoint": "Combined with iam:PassRole, a well-known privilege escalation vector (SSH into a Glue dev endpoint running under the passed role).",
    "s3:PutBucketPolicy": "Can rewrite a bucket's resource policy, potentially exposing data publicly or to other accounts.",
    "s3:PutBucketAcl": "Can change a bucket's ACL, potentially exposing data publicly.",
    "ssm:SendCommand": "Can execute arbitrary commands on any EC2 instance with the SSM agent, using the instance's role.",
    "sts:TagSession": "Can set session tags used by some ABAC policies to gain elevated access.",
}

# Multi-action combinations that only become dangerous together. Each combo
# lists the actions that must ALL be present (granted) for it to fire.
ESCALATION_COMBOS: List[Dict[str, object]] = [
    {
        "name": "PassRole + RunInstances",
        "actions": {"iam:PassRole", "ec2:RunInstances"},
        "reason": "Can launch an EC2 instance with an arbitrary instance profile, then retrieve its credentials from instance metadata.",
    },
    {
        "name": "PassRole + CreateStack",
        "actions": {"iam:PassRole", "cloudformation:CreateStack"},
        "reason": "Can pass a highly-privileged role into a CloudFormation stack to provision resources (including new IAM principals) under it.",
    },
    {
        "name": "PassRole + CreateDevEndpoint",
        "actions": {"iam:PassRole", "glue:CreateDevEndpoint"},
        "reason": "Documented AWS Glue privilege-escalation path: SSH into the dev endpoint to obtain the passed role's credentials.",
    },
    {
        "name": "PassRole + Lambda function creation/update",
        "actions": {"iam:PassRole", "lambda:CreateFunction"},
        "reason": "Can create a Lambda function with an arbitrary execution role and trigger it to run code under that role.",
    },
    {
        "name": "CreatePolicyVersion + full IAM control",
        "actions": {"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"},
        "reason": "Can rewrite and activate a new version of any policy the principal can target, up to full admin.",
    },
]


@dataclass
class RiskFinding:
    category: str  # "high_risk_action" | "escalation_combo" | "wildcard_action" | "wildcard_resource" | "deny_removed"
    severity: str  # "High" | "Medium" | "Low"
    title: str
    detail: str
    actions: List[str]


def find_high_risk_actions(granted_actions: Iterable[str]) -> List[RiskFinding]:
    findings = []
    granted = set(granted_actions)
    for action, reason in HIGH_RISK_ACTIONS.items():
        if action in granted:
            findings.append(
                RiskFinding(
                    category="high_risk_action",
                    severity="High",
                    title=f"High-risk action granted: {action}",
                    detail=reason,
                    actions=[action],
                )
            )
    return findings


def find_escalation_combos(granted_actions: Iterable[str]) -> List[RiskFinding]:
    granted = set(granted_actions)
    findings = []
    for combo in ESCALATION_COMBOS:
        combo_actions: Set[str] = combo["actions"]  # type: ignore
        if combo_actions.issubset(granted):
            findings.append(
                RiskFinding(
                    category="escalation_combo",
                    severity="High",
                    title=f"Privilege-escalation combination present: {combo['name']}",
                    detail=combo["reason"],  # type: ignore
                    actions=sorted(combo_actions),
                )
            )
    return findings


def find_wildcard_grants(policy) -> List[RiskFinding]:
    """`policy` is a parsed Policy (see policy_parser.py)."""
    findings = []
    for i, stmt in enumerate(policy.statements):
        if stmt.effect != "Allow":
            continue
        if "*" in stmt.actions and not stmt.not_action:
            findings.append(
                RiskFinding(
                    category="wildcard_action",
                    severity="High",
                    title=f"Statement {stmt.sid or f'#{i}'} grants Action: \"*\"",
                    detail="This statement allows every action on every service the resource scope permits.",
                    actions=["*"],
                )
            )
        if stmt.is_wildcard_resource and not stmt.not_resource:
            findings.append(
                RiskFinding(
                    category="wildcard_resource",
                    severity="Medium",
                    title=f"Statement {stmt.sid or f'#{i}'} grants Resource: \"*\"",
                    detail="This statement is not scoped to specific resources; combined with broad actions this can be very high risk.",
                    actions=list(stmt.actions),
                )
            )
    return findings


def analyze_policy(policy) -> List[RiskFinding]:
    """Runs the full risk ruleset against a single policy's granted (Allow) actions."""
    from .effective_permissions import compute_effective_permissions

    effective = compute_effective_permissions(policy)
    granted_allow = {a for a, g in effective.items() if g.effect == "Allow"}

    findings: List[RiskFinding] = []
    findings += find_high_risk_actions(granted_allow)
    findings += find_escalation_combos(granted_allow)
    findings += find_wildcard_grants(policy)
    return findings

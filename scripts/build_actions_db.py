#!/usr/bin/env python3
"""
build_actions_db.py
====================
Builds `iamdiff/data/actions_db.json`, the action catalogue the diff engine
uses to expand IAM wildcards (e.g. "s3:Get*", "s3:*") into concrete actions.

Source of truth
----------------
We mine botocore's bundled `service-2.json` API definitions (the same files
the official AWS CLI / SDKs ship with) for each service's list of API
operations. For the overwhelming majority of AWS services, an IAM action
name is identical to the API operation name (e.g. the `s3:GetObject`
permission corresponds 1:1 with S3's `GetObject` API operation). This is
the same technique tools like policy_sentry / iamlive use as a baseline.

This is a *reasonable, defensible approximation*, not a byte-for-byte copy
of the AWS IAM Service Authorization Reference. A handful of services define
IAM-only actions with no matching API operation (e.g. `s3:GetObjectVersion`
variants, `iam:PassRole`-style "logical" actions). Those are patched in
manually below where they materially matter for privilege-escalation /
security analysis, which is this tool's actual purpose.

Regenerate with:
    python3 scripts/build_actions_db.py
"""
import gzip
import json
import os
import re
import sys

import botocore

BOTOCORE_DATA = os.path.join(os.path.dirname(botocore.__file__), "data")
OUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "iamdiff", "data", "actions_db.json",
)

# botocore endpoint/service directory name -> IAM policy action prefix.
# Most services use the same string for both; this table lists the
# well-known exceptions plus the set of services we choose to include.
# Extend this table and re-run the script to broaden coverage.
SERVICE_PREFIX_MAP = {
    "accessanalyzer": "access-analyzer",
    "acm": "acm",
    "acm-pca": "acm-pca",
    "apigateway": "apigateway",
    "apigatewayv2": "apigateway",
    "appconfig": "appconfig",
    "application-autoscaling": "application-autoscaling",
    "athena": "athena",
    "autoscaling": "autoscaling",
    "backup": "backup",
    "batch": "batch",
    "budgets": "budgets",
    "ce": "ce",
    "cloudformation": "cloudformation",
    "cloudfront": "cloudfront",
    "cloudtrail": "cloudtrail",
    "codebuild": "codebuild",
    "codecommit": "codecommit",
    "codedeploy": "codedeploy",
    "codepipeline": "codepipeline",
    "cognito-identity": "cognito-identity",
    "cognito-idp": "cognito-idp",
    "config": "config",
    "datapipeline": "datapipeline",
    "directconnect": "directconnect",
    "dynamodb": "dynamodb",
    "ec2": "ec2",
    "ecr": "ecr",
    "ecs": "ecs",
    "efs": "elasticfilesystem",
    "eks": "eks",
    "elasticache": "elasticache",
    "elasticbeanstalk": "elasticbeanstalk",
    "elasticloadbalancing": "elasticloadbalancing",
    "elasticloadbalancingv2": "elasticloadbalancing",
    "elastictranscoder": "elastictranscoder",
    "es": "es",
    "events": "events",
    "firehose": "firehose",
    "glacier": "glacier",
    "glue": "glue",
    "guardduty": "guardduty",
    "iam": "iam",
    "inspector": "inspector",
    "inspector2": "inspector2",
    "iot": "iot",
    "kafka": "kafka",
    "kinesis": "kinesis",
    "kms": "kms",
    "lambda": "lambda",
    "logs": "logs",
    "macie2": "macie2",
    "mediaconvert": "mediaconvert",
    "monitoring": "cloudwatch",
    "opsworks": "opsworks",
    "organizations": "organizations",
    "pricing": "pricing",
    "ram": "ram",
    "rds": "rds",
    "redshift": "redshift",
    "route53": "route53",
    "s3": "s3",
    "s3control": "s3",
    "sagemaker": "sagemaker",
    "secretsmanager": "secretsmanager",
    "securityhub": "securityhub",
    "servicecatalog": "servicecatalog",
    "ses": "ses",
    "shield": "shield",
    "sms": "sms",
    "sns": "sns",
    "sqs": "sqs",
    "ssm": "ssm",
    "sso": "sso",
    "sso-admin": "sso",
    "states": "states",
    "storagegateway": "storagegateway",
    "sts": "sts",
    "support": "support",
    "swf": "swf",
    "transfer": "transfer",
    "waf": "waf",
    "waf-regional": "waf-regional",
    "wafv2": "wafv2",
    "workspaces": "workspaces",
    "xray": "xray",
}

# IAM-only actions with no 1:1 API-operation equivalent that matter for
# security analysis (privilege escalation, resource-based policy edits,
# session/session-tag abuse, etc). Hand-maintained.
MANUAL_ADDITIONS = {
    "iam": [
        "PassRole", "SimulatePrincipalPolicy", "SimulateCustomPolicy",
        "GenerateCredentialReport", "GenerateServiceLastAccessedDetails",
    ],
    "s3": [
        "GetObjectVersion", "PutObjectAcl", "PutObjectVersionAcl",
        "GetObjectVersionAcl", "BypassGovernanceRetention",
    ],
    "sts": [
        "TagSession",
    ],
    "ec2": [
        "RunInstances",
    ],
}

# Heuristic "access level" classification, used by the risk engine.
# Order matters: first matching prefix wins.
VERB_ACCESS_LEVEL = [
    (re.compile(r"^(List|Describe|Get|Head|Lookup|Query|Search|View|Check|Test|Simulate|Export|Preview|Estimate|Validate)"), "Read"),
    (re.compile(r"^(Tag|Untag|AddTags|RemoveTags)"), "Tagging"),
    (re.compile(r"^(Put.*Policy|Attach.*Policy|Detach.*Policy|Create.*Policy|Delete.*Policy|Update.*Policy|Set.*Policy|"
                r"CreateRole|DeleteRole|UpdateAssumeRolePolicy|PutRolePolicy|AttachRolePolicy|DetachRolePolicy|"
                r"PutUserPolicy|AttachUserPolicy|DetachUserPolicy|PutGroupPolicy|AttachGroupPolicy|DetachGroupPolicy|"
                r"CreateAccessKey|UpdateAccessKey|CreateLoginProfile|UpdateLoginProfile|CreatePolicyVersion|"
                r"SetDefaultPolicyVersion|PassRole|AddUserToGroup|CreateUser|AddRoleToInstanceProfile|"
                r"UpdateAssumeRolePolicy|PutBucketPolicy|PutBucketAcl|ModifyDBInstance)"), "Permissions management"),
    (re.compile(r"^(Create|Put|Add|Register|Allocate|Provision|Import|Copy|Publish|Deploy|Run|Start|Send|Invoke|Restore)"), "Write"),
    (re.compile(r"^(Update|Modify|Set|Configure|Attach|Enable|Disable|Associate|Disassociate|Grant|Revoke|Reboot|"
                r"Reset|Renew|Promote|Failover|Resize|Rotate|Cancel|Abort|Stop)"), "Write"),
    (re.compile(r"^(Delete|Remove|Terminate|Deregister|Purge|Detach)"), "Write"),
]


def classify_access_level(action_name: str) -> str:
    for pattern, level in VERB_ACCESS_LEVEL:
        if pattern.match(action_name):
            return level
    return "Write"


def load_operations(service_dir: str):
    versions_path = os.path.join(BOTOCORE_DATA, service_dir)
    if not os.path.isdir(versions_path):
        return None
    api_versions = sorted(os.listdir(versions_path))
    if not api_versions:
        return None
    latest = api_versions[-1]
    plain_path = os.path.join(versions_path, latest, "service-2.json")
    gz_path = plain_path + ".gz"
    if os.path.isfile(plain_path):
        with open(plain_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    elif os.path.isfile(gz_path):
        with gzip.open(gz_path, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        return None
    return sorted(data.get("operations", {}).keys())


def build():
    db = {}
    covered, missing = [], []
    for service_dir, iam_prefix in sorted(SERVICE_PREFIX_MAP.items()):
        ops = load_operations(service_dir)
        if ops is None:
            missing.append(service_dir)
            continue
        bucket = db.setdefault(iam_prefix, {})
        for op in ops:
            bucket[op] = classify_access_level(op)
        covered.append(service_dir)

    for iam_prefix, extra_actions in MANUAL_ADDITIONS.items():
        bucket = db.setdefault(iam_prefix, {})
        for action in extra_actions:
            bucket.setdefault(action, classify_access_level(action))

    total_actions = sum(len(v) for v in db.values())
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(db, fh, indent=1, sort_keys=True)

    print(f"Wrote {OUT_PATH}")
    print(f"Services covered: {len(covered)}  |  Total actions: {total_actions}")
    if missing:
        print(f"Skipped (not found in this botocore install): {missing}", file=sys.stderr)


if __name__ == "__main__":
    build()

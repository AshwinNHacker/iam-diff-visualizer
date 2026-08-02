"""
iamdiff — IAM Policy Diff Visualizer
=====================================

Shows the *effective permission change* between two AWS IAM policy
documents, not just a raw JSON diff.

Public API:
    from iamdiff import compare_policies
    result = compare_policies(old_policy_dict, new_policy_dict)
"""
from .differ import compare_policies, DiffResult
from .effective_permissions import compute_effective_permissions

__version__ = "1.0.0"
__all__ = ["compare_policies", "DiffResult", "compute_effective_permissions", "__version__"]

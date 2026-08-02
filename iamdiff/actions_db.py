"""
actions_db.py
=============
Loads the bundled AWS IAM action catalogue (built by
scripts/build_actions_db.py from real botocore API definitions) and
exposes lookup helpers used by the wildcard expander and risk engine.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Dict

_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "actions_db.json")


@lru_cache(maxsize=1)
def load_db() -> Dict[str, Dict[str, str]]:
    """Returns {service_prefix: {ActionName: AccessLevel}}."""
    with open(_DB_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def known_services() -> set:
    return set(load_db().keys())


def actions_for_service(service: str) -> Dict[str, str]:
    """Returns {ActionName: AccessLevel} for a given IAM action prefix (e.g. 's3')."""
    return load_db().get(service, {})


def access_level(service: str, action_name: str) -> str:
    """Best-effort access-level lookup for a single concrete action."""
    return load_db().get(service, {}).get(action_name, "Unknown")

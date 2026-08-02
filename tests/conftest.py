import json
import os

import pytest

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURE_DIR, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def s3_readonly_policy():
    return load_fixture("s3_readonly.json")


@pytest.fixture
def s3_wildcard_policy():
    return load_fixture("s3_wildcard.json")


@pytest.fixture
def privesc_policy():
    return load_fixture("privesc.json")


@pytest.fixture
def empty_ish_policy():
    return load_fixture("logs_only.json")

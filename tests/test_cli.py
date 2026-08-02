import json
import os

from iamdiff.cli import main

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _fixture(name):
    return os.path.join(FIXTURE_DIR, name)


def test_compare_writes_html_report(tmp_path):
    out = tmp_path / "report.html"
    code = main(["compare", _fixture("s3_readonly.json"), _fixture("privesc.json"), "-o", str(out)])
    assert code == 0
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "IAM Policy Diff Visualizer" in content
    assert "iam:PassRole" in content


def test_compare_json_output(capsys):
    code = main(["compare", _fixture("s3_readonly.json"), _fixture("privesc.json"), "--json"])
    assert code == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "summary" in data
    assert data["summary"]["introduced_risks"] > 0


def test_compare_fail_on_risk_exit_code(tmp_path):
    out = tmp_path / "report.html"
    code = main(["compare", _fixture("s3_readonly.json"), _fixture("privesc.json"), "-o", str(out), "--fail-on-risk"])
    assert code == 2


def test_compare_no_new_risk_exits_zero(tmp_path):
    out = tmp_path / "report.html"
    code = main(["compare", _fixture("s3_readonly.json"), _fixture("s3_readonly.json"), "-o", str(out), "--fail-on-risk"])
    assert code == 0


def test_analyze_clean_policy_exits_zero(capsys):
    code = main(["analyze", _fixture("logs_only.json"), "--fail-on-risk"])
    assert code == 0


def test_analyze_risky_policy_exits_two(capsys):
    code = main(["analyze", _fixture("privesc.json"), "--fail-on-risk"])
    assert code == 2


def test_compare_missing_file_returns_error():
    code = main(["compare", _fixture("does_not_exist.json"), _fixture("logs_only.json")])
    assert code == 1


def test_compare_invalid_policy_returns_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"Version": "2012-10-17"}')
    code = main(["compare", str(bad), _fixture("logs_only.json")])
    assert code == 1

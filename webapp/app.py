"""
webapp/app.py
=============
A minimal Flask front-end for iamdiff: paste or upload two policy
documents in the browser and get the same effective-permission diff
report rendered inline, without touching the CLI.

Run locally:
    pip install -r webapp/requirements.txt
    python3 webapp/app.py
    # then open http://127.0.0.1:5000
"""
import os
import sys

from flask import Flask, render_template, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from iamdiff.differ import compare_policies
from iamdiff.policy_parser import PolicyParseError
from iamdiff.report import render_html

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB, policies are always tiny

EXAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def _read_example(name):
    path = os.path.join(EXAMPLES_DIR, name)
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        old_text=_read_example("policy_v1_baseline.json"),
        new_text=_read_example("policy_v2_privesc.json"),
        error=None,
    )


@app.route("/compare", methods=["POST"])
def compare():
    old_text = request.form.get("old_policy", "").strip()
    new_text = request.form.get("new_policy", "").strip()

    if not old_text or not new_text:
        return render_template(
            "index.html", old_text=old_text, new_text=new_text,
            error="Both policy documents are required.",
        )

    try:
        result = compare_policies(old_text, new_text)
    except PolicyParseError as exc:
        return render_template(
            "index.html", old_text=old_text, new_text=new_text,
            error=f"Could not parse policy: {exc}",
        )

    report_html = render_html(result, old_label="Old policy", new_label="New policy")
    # Return the full standalone report -- it's a complete HTML document,
    # so we serve it directly rather than embedding it in the page shell.
    return report_html


@app.route("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(debug=True, port=5000)

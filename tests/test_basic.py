import os

from sast.analyzer import analyze_source

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "vulnerable.py")


def test_hardcoded_secret_detected():
    with open(SAMPLE, encoding="utf-8") as fh:
        findings = analyze_source(fh.read(), "vulnerable.py")
    rule_ids = {f.rule_id for f in findings}
    assert "PY001" in rule_ids

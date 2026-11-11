"""InsecureDeserializationRule（PY002）的测试。"""
from sast.analyzer import analyze_source


def test_pickle_loads_detected():
    source = (
        "import pickle\n"
        "def load_blob(blob):\n"
        "    return pickle.loads(blob)\n"
    )
    findings = analyze_source(source, "sample.py")
    py002 = [f for f in findings if f.rule_id == "PY002"]
    assert len(py002) == 1
    finding = py002[0]
    assert finding.severity == "error"
    assert finding.line == 3
    assert "pickle.loads" in finding.message


def test_pickle_load_and_marshal_loads_detected():
    source = (
        "import pickle\n"
        "import marshal\n"
        "with open('data.bin', 'rb') as fh:\n"
        "    obj = pickle.load(fh)\n"
        "obj2 = marshal.loads(blob)\n"
    )
    findings = analyze_source(source, "sample.py")
    py002 = [f for f in findings if f.rule_id == "PY002"]
    assert len(py002) == 2
    messages = " ".join(f.message for f in py002)
    assert "pickle.load" in messages
    assert "marshal.loads" in messages


def test_json_loads_not_flagged():
    source = (
        "import json\n"
        "def load_blob(blob):\n"
        "    return json.loads(blob)\n"
    )
    findings = analyze_source(source, "sample.py")
    assert all(f.rule_id != "PY002" for f in findings)

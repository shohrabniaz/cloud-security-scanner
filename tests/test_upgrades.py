import json

from checks import _ports_hit, demo_findings
from reporter import format_sarif

SENSITIVE = {22, 3389, 445}


def test_ports_exact_and_wildcard():
    assert _ports_hit(["22"], SENSITIVE)
    assert _ports_hit(["*"], SENSITIVE)


def test_ports_no_substring_false_positive():
    assert not _ports_hit(["2222"], SENSITIVE)
    assert not _ports_hit(["8445"], SENSITIVE)


def test_ports_range_and_plural():
    assert _ports_hit(["20-30"], SENSITIVE)
    assert _ports_hit(["80", "3389"], SENSITIVE)
    assert not _ports_hit(["80-443"], SENSITIVE)


def test_sarif_shape():
    doc = json.loads(format_sarif(demo_findings()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert len(run["results"]) == 5
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} >= {"AZ-NSG-001"}
    assert {r["level"] for r in run["results"]} <= {"error", "warning", "note"}

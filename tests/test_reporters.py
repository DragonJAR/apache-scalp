from datetime import datetime
import json
import xml.etree.ElementTree as ET
from scalp.core.engine import ScanResult
from scalp.core.models import AttackMatch, FilterRule, LogEntry
from scalp.reporters.html import HtmlReporter
from scalp.reporters.json_rep import JsonReporter
from scalp.reporters.text import TextReporter
from scalp.reporters.xml import XmlReporter

def make_sample_result():
    entry = LogEntry(
        ip="192.168.1.100",
        raw_line='192.168.1.100 - - [10/Oct/2024:12:00:00 +0000] "GET /?q=%3Cscript%3E HTTP/1.1" 200 500',
        timestamp=datetime(2024, 10, 10, 12, 0, 0),
        method="GET",
        url="/?q=<script>",
        protocol="HTTP/1.1",
        status_code=200,
        bytes_sent=500,
        user_agent="Mozilla/5.0"
    )
    rule = FilterRule(
        rule_id="xss_1",
        pattern=r"<script>",
        description="XSS Script Injection",
        impact=8,
        tags={"xss"}
    )
    match = AttackMatch(entry=entry, rule=rule, matched_string="<script>", tag="xss")
    return ScanResult(
        total_lines=10,
        processed_lines=10,
        matches=[match],
        unmatched_lines=[],
        elapsed_seconds=0.05
    )

def test_text_reporter(tmp_path):
    result = make_sample_result()
    out_file = tmp_path / "report.txt"
    TextReporter.generate(result, str(out_file), source_name="access.log")

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "Cross-Site Scripting" in content or "xss" in content
    assert "Impact 8" in content
    assert "192.168.1.100" in content

def test_html_reporter_modern_format(tmp_path):
    result = make_sample_result()
    out_file = tmp_path / "report.html"
    HtmlReporter.generate(result, str(out_file), source_name="access.log")

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "Scalp Report" in content
    assert "Impact 8" in content
    assert "XSS Script Injection" in content
    assert "&lt;script&gt;" in content  # Escaped safely

def test_xml_reporter_valid_structure_no_sort_crash(tmp_path):
    result = make_sample_result()
    out_file = tmp_path / "report.xml"
    XmlReporter.generate(result, str(out_file), source_name="access.log")

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "<?xml" in content
    # Parse with standard XML parser to verify validity
    root = ET.fromstring(content)
    assert root.tag == "scalp"
    attack = root.find("attack")
    assert attack is not None
    assert attack.get("type") == "xss"

def test_json_reporter_valid_json(tmp_path):
    result = make_sample_result()
    out_file = tmp_path / "report.json"
    JsonReporter.generate(result, str(out_file), source_name="access.log")

    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["summary"]["total_matches"] == 1
    assert data["summary"]["processed_lines"] == 10
    assert len(data["matches"]) == 1
    assert data["matches"][0]["impact"] == 8
    assert data["matches"][0]["ip"] == "192.168.1.100"

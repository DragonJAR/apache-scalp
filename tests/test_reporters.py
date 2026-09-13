from datetime import datetime
from html.parser import HTMLParser
import json
import re
import xml.etree.ElementTree as ET
from scalp.core.engine import ScanResult
from scalp.core.models import AttackMatch, FilterRule, LogEntry
from scalp.heuristics.anathema import AnathemaAnalyzer
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
        user_agent="Mozilla/5.0",
    )
    rule = FilterRule(
        rule_id="xss_1",
        pattern=r"<script>",
        description="XSS Script Injection",
        impact=8,
        tags={"xss"},
    )
    match = AttackMatch(entry=entry, rule=rule, matched_string="<script>", tag="xss")
    return ScanResult(
        total_lines=10,
        processed_lines=10,
        matches=[match],
        unmatched_lines=[],
        elapsed_seconds=0.05,
    )


class HTMLTagValidator(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.void_elements = {
            "area", "base", "br", "col", "embed", "hr", "img", "input",
            "link", "meta", "param", "source", "track", "wbr",
        }
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() not in self.void_elements:
            self.stack.append(tag.lower())

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.void_elements:
            return
        if not self.stack:
            self.errors.append(f"Orphaned closing tag: </{tag}>")
            return
        last = self.stack.pop()
        if last != tag:
            self.errors.append(f"Mismatched closing tag: expected </{last}>, got </{tag}>")


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

    # Verify embedded JSON dataset
    m = re.search(r'<script id="scalp-data" type="application/json">(.*?)</script>', content, re.DOTALL)
    assert m is not None, "Embedded scalp-data JSON script tag missing"
    data = json.loads(m.group(1))
    assert data["metadata"]["source"] == "access.log"
    assert data["summary"]["total_matches"] == 1
    assert data["summary"]["processed_lines"] == 10
    assert len(data["matches"]) == 1
    assert data["matches"][0]["impact"] == 8
    assert data["matches"][0]["ip"] == "192.168.1.100"


def test_html_reporter_anathema_inclusion(tmp_path):
    result = make_sample_result()
    anathema = AnathemaAnalyzer()
    banned_ip = "198.51.100.99"
    anathema.banned_ips.add(banned_ip)
    anathema.violators[banned_ip] = [result.matches[0].entry]
    result.anathema = anathema

    out_file = tmp_path / "report_anathema.html"
    HtmlReporter.generate(result, str(out_file), source_name="access.log")

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "Anathema Behavioral Intelligence" in content
    assert banned_ip in content
    assert "Copy Banned IPs" in content
    assert "iptables" in content
    assert "ipset" in content

    # Check that embedded JSON contains the banned IP
    m = re.search(r'<script id="scalp-data" type="application/json">(.*?)</script>', content, re.DOTALL)
    assert m is not None
    data = json.loads(m.group(1))
    assert banned_ip in data["banned_ips"]
    assert data["summary"]["banned_ips_count"] == 1


def test_html_reporter_clean_log(tmp_path):
    result = ScanResult(
        total_lines=50,
        processed_lines=50,
        matches=[],
        unmatched_lines=[],
        elapsed_seconds=0.02,
    )
    out_file = tmp_path / "report_clean.html"
    HtmlReporter.generate(result, str(out_file), source_name="clean.log")

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "CLEAN / NO THREATS" in content or "clean" in content.lower()

    # Validate DOM structure on clean log
    validator = HTMLTagValidator()
    validator.feed(content)
    assert len(validator.errors) == 0, f"DOM errors on clean log: {validator.errors}"
    assert len(validator.stack) == 0, f"Unclosed tags on clean log: {validator.stack}"


def test_html_reporter_valid_dom_structure(tmp_path):
    result = make_sample_result()
    out_file = tmp_path / "report_valid.html"
    HtmlReporter.generate(result, str(out_file), source_name="access.log")

    content = out_file.read_text(encoding="utf-8")
    validator = HTMLTagValidator()
    validator.feed(content)
    assert len(validator.errors) == 0, f"DOM errors found: {validator.errors}"
    assert len(validator.stack) == 0, f"Unclosed tags found: {validator.stack}"


def test_html_reporter_xss_protection_in_embedded_json(tmp_path):
    malicious_payload = "</script><script>alert('xss')</script>"
    entry = LogEntry(
        ip="10.0.0.1",
        raw_line=f'10.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /?q={malicious_payload} HTTP/1.1" 200 500',
        timestamp=datetime(2024, 10, 10, 12, 0, 0),
        method="GET",
        url=f"/?q={malicious_payload}",
        protocol="HTTP/1.1",
        status_code=200,
        bytes_sent=500,
    )
    rule = FilterRule(
        rule_id="xss_breakout",
        pattern=r"script",
        description="Script tag breakout test",
        impact=9,
        tags={"xss"},
    )
    match = AttackMatch(entry=entry, rule=rule, matched_string=malicious_payload, tag="xss")
    result = ScanResult(
        total_lines=1,
        processed_lines=1,
        matches=[match],
        unmatched_lines=[],
        elapsed_seconds=0.01,
    )

    out_file = tmp_path / "report_xss.html"
    HtmlReporter.generate(result, str(out_file), source_name="access.log")

    content = out_file.read_text(encoding="utf-8")
    # Verify the closing script tag was escaped inside JSON
    assert "</script><script>" not in content
    # But valid JSON parsing still works and yields the unescaped payload
    m = re.search(r'<script id="scalp-data" type="application/json">(.*?)</script>', content, re.DOTALL)
    assert m is not None
    data = json.loads(m.group(1))
    assert data["matches"][0]["match"] == malicious_payload


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

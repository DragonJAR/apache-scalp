from datetime import datetime
from scalp.core.models import LogEntry, FilterRule, AttackMatch

def test_log_entry_creation():
    entry = LogEntry(
        ip="192.168.1.100",
        raw_line='192.168.1.100 - - [10/Oct/2024:13:55:36 +0000] "GET /index.php HTTP/1.1" 200 1234',
        timestamp=datetime(2024, 10, 10, 13, 55, 36),
        method="GET",
        url="/index.php",
        protocol="HTTP/1.1",
        status_code=200,
        bytes_sent=1234,
        referrer=None,
        user_agent=None
    )
    assert entry.ip == "192.168.1.100"
    assert entry.method == "GET"
    assert entry.url == "/index.php"
    assert entry.status_code == 200
    assert entry.bytes_sent == 1234

def test_filter_rule_creation():
    rule = FilterRule(
        rule_id="1",
        pattern=r"(?:<script.*?>)",
        description="XSS Script Tag",
        impact=7,
        tags={"xss"}
    )
    assert rule.impact == 7
    assert "xss" in rule.tags

def test_attack_match_creation():
    entry = LogEntry(
        ip="127.0.0.1",
        raw_line="raw",
        timestamp=None,
        method="GET",
        url="/test",
        protocol="HTTP/1.1",
        status_code=200
    )
    rule = FilterRule("1", "pattern", "XSS", 5, {"xss"})
    match = AttackMatch(entry=entry, rule=rule, matched_string="/test", tag="xss")
    assert match.matched_string == "/test"
    assert match.rule.impact == 5

def test_filter_rule_impact_coerced_from_str():
    rule = FilterRule(rule_id="2", pattern="sqli", description="SQL Injection", impact="9")
    assert rule.impact == 9
    assert isinstance(rule.impact, int)


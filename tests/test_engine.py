from scalp.core.engine import ScalpEngine
from scalp.core.exclusions import DateRangeFilter, NetworkFilter
from scalp.core.models import FilterRule
from scalp.heuristics.anathema import AnathemaAnalyzer

def test_engine_matches_classic_sqli_with_url_decoding(tmp_path):
    log_content = (
        '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /test.php?id=1%27%20OR%201=1 HTTP/1.1" 200 100\n'
        '127.0.0.1 - - [10/Oct/2024:12:01:00 +0000] "GET /about.html HTTP/1.1" 200 500\n'
    )
    log_file = tmp_path / "access.log"
    log_file.write_text(log_content, encoding="utf-8")

    rules = [
        FilterRule(rule_id="sqli_1", pattern=r"(?:union\s+select|or\s+\d+=\d+|'\s*or)", description="SQL Injection", impact=8, tags={"sqli"})
    ]

    engine = ScalpEngine(rules=rules)
    result = engine.scan_file(str(log_file))

    assert result.total_lines == 2
    assert result.processed_lines == 2
    assert len(result.matches) == 1
    assert result.matches[0].rule.rule_id == "sqli_1"
    assert result.matches[0].tag == "sqli"

def test_engine_tag_filtering(tmp_path):
    log_content = (
        '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /test?x=<script>alert(1)</script> HTTP/1.1" 200 100\n'
    )
    log_file = tmp_path / "access.log"
    log_file.write_text(log_content, encoding="utf-8")

    rules = [
        FilterRule(rule_id="xss_1", pattern=r"<script", description="XSS", impact=5, tags={"xss"}),
        FilterRule(rule_id="sqli_1", pattern=r"union\s+select", description="SQLi", impact=8, tags={"sqli"}),
    ]

    # Only look for sqli
    engine = ScalpEngine(rules=rules, attack_types={"sqli"})
    result = engine.scan_file(str(log_file))
    assert len(result.matches) == 0

    # Look for xss
    engine_xss = ScalpEngine(rules=rules, attack_types={"xss"})
    result_xss = engine_xss.scan_file(str(log_file))
    assert len(result_xss.matches) == 1

def test_engine_ip_exclusion(tmp_path):
    log_content = (
        '192.168.1.50 - - [10/Oct/2024:12:00:00 +0000] "GET /test?x=<script> HTTP/1.1" 200 100\n'
        '10.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /test?x=<script> HTTP/1.1" 200 100\n'
    )
    log_file = tmp_path / "access.log"
    log_file.write_text(log_content, encoding="utf-8")

    rules = [FilterRule(rule_id="xss_1", pattern=r"<script", description="XSS", impact=5, tags={"xss"})]
    net_filter = NetworkFilter(excluded_subnets=["192.168.1.0/24"])

    engine = ScalpEngine(rules=rules, network_filter=net_filter)
    result = engine.scan_file(str(log_file))

    assert result.processed_lines == 1  # 192.168.1.50 excluded
    assert len(result.matches) == 1
    assert result.matches[0].entry.ip == "10.0.0.1"

def test_engine_with_anathema_integration(tmp_path):
    log_content = (
        '198.51.100.2 - - [10/Oct/2024:12:00:00 +0000] "GET /phpmyadmin/scripts/setup.php HTTP/1.1" 404 100\n'
    )
    log_file = tmp_path / "access.log"
    log_file.write_text(log_content, encoding="utf-8")

    rules = []
    anathema = AnathemaAnalyzer()
    engine = ScalpEngine(rules=rules, anathema=anathema)
    engine.scan_file(str(log_file))

    assert anathema.is_violator("198.51.100.2") is True

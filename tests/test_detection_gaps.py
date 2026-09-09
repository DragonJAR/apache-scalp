"""Tests verifying coverage for modern detection gaps: NoSQL, Prototype Pollution, CRLF, RCE, SSRF evasions, and Base64/Unicode normalization."""
from pathlib import Path
import pytest
from scalp.core.engine import ScalpEngine
from scalp.core.normalizer import PayloadNormalizer
from scalp.core.parser import LogParser
from scalp.core.rules import RuleLoader

DEFAULT_FILTER_XML = Path(__file__).parent.parent / "default_filter.xml"


@pytest.fixture
def modern_engine():
    rules = RuleLoader.load_xml(DEFAULT_FILTER_XML)
    return ScalpEngine(rules=rules)


def test_normalizer_handles_unicode_fullwidth_characters():
    # Fullwidth solidus U+FF0F (／) and fullwidth dot U+FF0E (．)
    raw = "..／..／etc／passwd"
    normalized = PayloadNormalizer.normalize(raw)
    assert normalized == "../../etc/passwd"


def test_normalizer_decodes_base64_embedded_payloads():
    # Base64 of 'cat /etc/passwd' is 'Y2F0IC9ldGMvcGFzc3dk'
    raw = "/index.php?cmd=Y2F0IC9ldGMvcGFzc3dk"
    normalized = PayloadNormalizer.normalize(raw)
    assert "cat /etc/passwd" in normalized


def test_detects_nosql_injection(modern_engine):
    line1 = '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /api/users?user[$ne]=admin HTTP/1.1" 200 500 "-" "Mozilla/5.0"'
    line2 = '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /api/search?q={\\"$where\\":\\"sleep(5000)\\"} HTTP/1.1" 200 500 "-" "Mozilla/5.0"'

    tmp = Path("test_nosql.log")
    tmp.write_text(line1 + "\n" + line2 + "\n", encoding="utf-8")
    try:
        res = modern_engine.scan_file(str(tmp))
        assert len(res.matches) >= 2
        tags = {m.tag for m in res.matches}
        assert "nosql" in tags
    finally:
        if tmp.exists():
            tmp.unlink()


def test_detects_prototype_pollution(modern_engine):
    line = '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /profile?__proto__[isAdmin]=true HTTP/1.1" 200 120 "-" "Mozilla/5.0"'
    tmp = Path("test_pollution.log")
    tmp.write_text(line + "\n", encoding="utf-8")
    try:
        res = modern_engine.scan_file(str(tmp))
        assert len(res.matches) >= 1
        assert any(m.tag == "pollution" for m in res.matches)
    finally:
        if tmp.exists():
            tmp.unlink()


def test_detects_crlf_header_injection(modern_engine):
    line = '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /redirect?url=http://example.com%0d%0aSet-Cookie:%20session=evil HTTP/1.1" 302 50 "-" "Mozilla/5.0"'
    tmp = Path("test_crlf.log")
    tmp.write_text(line + "\n", encoding="utf-8")
    try:
        res = modern_engine.scan_file(str(tmp))
        assert len(res.matches) >= 1
        assert any(m.tag == "crlf" for m in res.matches)
    finally:
        if tmp.exists():
            tmp.unlink()


def test_detects_command_injection_and_shellshock(modern_engine):
    # Shellshock in User-Agent
    line_shock = '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /cgi-bin/status HTTP/1.1" 200 120 "-" "() { :; }; /bin/bash -c \'whoami\'"'
    # OS Command Chaining in URL
    line_cmd = '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /lookup?host=127.0.0.1;%20cat%20/etc/passwd HTTP/1.1" 200 120 "-" "curl/7.68.0"'

    tmp = Path("test_cmd.log")
    tmp.write_text(line_shock + "\n" + line_cmd + "\n", encoding="utf-8")
    try:
        res = modern_engine.scan_file(str(tmp))
        assert len(res.matches) >= 2
        tags = {m.tag for m in res.matches}
        assert "rce" in tags or "cmd" in tags
    finally:
        if tmp.exists():
            tmp.unlink()


def test_detects_ssrf_decimal_hex_and_cloud_bypasses(modern_engine):
    # Decimal 2852039166 is 169.254.169.254
    line_dec = '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /proxy?url=http://2852039166/latest/meta-data HTTP/1.1" 200 500 "-" "Mozilla/5.0"'
    # Hex 0xa9fea9fe
    line_hex = '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /proxy?url=http://0xa9fea9fe/latest/meta-data HTTP/1.1" 200 500 "-" "Mozilla/5.0"'
    # Alibaba cloud metadata IP 100.100.100.200
    line_ali = '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /proxy?url=http://100.100.100.200/latest/meta-data HTTP/1.1" 200 500 "-" "Mozilla/5.0"'
    # Oracle cloud metadata path
    line_opc = '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /opc/v1/instance/ HTTP/1.1" 200 500 "-" "Mozilla/5.0"'

    tmp = Path("test_ssrf_bypasses.log")
    tmp.write_text("\n".join([line_dec, line_hex, line_ali, line_opc]) + "\n", encoding="utf-8")
    try:
        res = modern_engine.scan_file(str(tmp))
        assert len(res.matches) >= 4
        matched_tags = {m.tag for m in res.matches}
        assert "ssrf" in matched_tags
    finally:
        if tmp.exists():
            tmp.unlink()

"""Tests for flow-by-flow audit fixes: root scalp.py, calendar end-of-month, gzip streaming, comment filtering, and CDATA escaping."""
import gzip
from pathlib import Path
import subprocess
import sys
from scalp.core.exclusions import DateRangeFilter
from scalp.core.parser import LogParser
from scalp.core.engine import ScalpEngine
from scalp.reporters.xml import XmlReporter
from scalp.core.models import FilterRule, LogEntry


def test_date_range_handles_february_and_short_months_with_wildcard():
    # February leap year 2024
    dt_feb_leap = DateRangeFilter.parse_endpoint("*/Feb/2024", is_end=True)
    assert dt_feb_leap is not None
    assert dt_feb_leap.day == 29

    # February non-leap year 2023
    dt_feb_non_leap = DateRangeFilter.parse_endpoint("*/Feb/2023", is_end=True)
    assert dt_feb_non_leap is not None
    assert dt_feb_non_leap.day == 28

    # April (30 days)
    dt_apr = DateRangeFilter.parse_endpoint("*/Apr/2024", is_end=True)
    assert dt_apr is not None
    assert dt_apr.day == 30


def test_log_parser_streams_gzip_compressed_logs(tmp_path):
    gz_log = tmp_path / "access.log.gz"
    sample_line = '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /test HTTP/1.1" 200 100 "-" "Mozilla/5.0"\n'
    with gzip.open(gz_log, "wt", encoding="utf-8") as f:
        f.write(sample_line)

    lines = list(LogParser.stream_file(str(gz_log)))
    assert len(lines) == 1
    assert lines[0][1] is not None
    assert lines[0][1].url == "/test"


def test_scalp_engine_does_not_count_comments_and_blank_lines_as_unmatched(tmp_path):
    log_file = tmp_path / "comments.log"
    log_content = (
        "#Version: 1.0\n"
        "#Date: 2024-10-10\n"
        "\n"
        '127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 100 "-" "-"\n'
        "malformed log line here\n"
    )
    log_file.write_text(log_content, encoding="utf-8")

    engine = ScalpEngine(rules=[])
    res = engine.scan_file(str(log_file))

    # Only "malformed log line here" should be in unmatched_lines, not # comments or empty lines
    assert len(res.unmatched_lines) == 1
    assert res.unmatched_lines[0].strip() == "malformed log line here"


def test_xml_reporter_safely_escapes_cdata_closing_sequences(tmp_path):
    from scalp.core.engine import ScanResult
    from scalp.core.models import AttackMatch

    rule = FilterRule(
        rule_id="1",
        pattern=r"test]]>pattern",
        description="Description with ]]> test",
        impact=5,
        tags={"xss"}
    )
    entry = LogEntry(
        ip="127.0.0.1",
        raw_line='127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /test]]> HTTP/1.1" 200 100',
        timestamp=None,
        method="GET",
        url="/test]]>",
        protocol="HTTP/1.1",
        status_code=200
    )
    match = AttackMatch(entry=entry, rule=rule, matched_string="test]]>", tag="xss")
    res = ScanResult(total_lines=1, processed_lines=1, matches=[match])

    xml_out = tmp_path / "report.xml"
    XmlReporter.generate(res, str(xml_out))

    content = xml_out.read_text(encoding="utf-8")
    assert "]]>" not in content.replace("]]></line>", "").replace("]]></reason>", "").replace("]]></regexp>", "")


def test_root_scalp_py_entrypoint(tmp_path):
    log_file = tmp_path / "root_test.log"
    log_file.write_text('127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /?q=union+select HTTP/1.1" 200 100\n', encoding="utf-8")
    out_dir = tmp_path / "out_root"

    proc = subprocess.run([
        sys.executable, "scalp.py",
        "-l", str(log_file),
        "-f", "default_filter.xml",
        "-o", str(out_dir),
        "-t"
    ], capture_output=True, text=True)

    assert proc.returncode == 0
    txt_files = list(out_dir.glob("*_scalp_*.txt"))
    assert len(txt_files) == 1

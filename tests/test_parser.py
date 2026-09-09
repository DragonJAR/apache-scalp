import pytest
from scalp.core.parser import LogParser

def test_parse_combined_log_line():
    line = '127.0.0.1 - admin [10/Oct/2024:13:55:36 -0700] "GET /index.php?id=1 HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"'
    entry = LogParser.parse_line(line)
    assert entry is not None
    assert entry.ip == "127.0.0.1"
    assert entry.method == "GET"
    assert entry.url == "/index.php?id=1"
    assert entry.protocol == "HTTP/1.1"
    assert entry.status_code == 200
    assert entry.bytes_sent == 2326
    assert entry.referrer == "http://example.com"
    assert entry.user_agent == "Mozilla/5.0"
    assert entry.timestamp is not None
    assert entry.timestamp.year == 2024
    assert entry.timestamp.month == 10
    assert entry.timestamp.day == 10

def test_parse_http2_and_dash_bytes():
    line = '10.0.0.1 - - [10/Oct/2024:14:00:00 +0000] "GET /app HTTP/2" 304 - "-" "curl/8.0"'
    entry = LogParser.parse_line(line)
    assert entry is not None
    assert entry.ip == "10.0.0.1"
    assert entry.protocol == "HTTP/2"
    assert entry.status_code == 304
    assert entry.bytes_sent is None
    assert entry.user_agent == "curl/8.0"

def test_parse_ipv6_and_http3():
    line = '2001:db8::1 - - [10/Oct/2024:14:00:00 +0000] "POST /api/login HTTP/3" 401 512 "-" "CustomAgent/1.0"'
    entry = LogParser.parse_line(line)
    assert entry is not None
    assert entry.ip == "2001:db8::1"
    assert entry.protocol == "HTTP/3"
    assert entry.method == "POST"
    assert entry.bytes_sent == 512

def test_parse_clf_line_without_referer_and_agent():
    line = '192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] "GET /robots.txt HTTP/1.0" 200 120'
    entry = LogParser.parse_line(line)
    assert entry is not None
    assert entry.ip == "192.168.1.1"
    assert entry.url == "/robots.txt"
    assert entry.referrer is None
    assert entry.user_agent is None

def test_parse_vhost_prefix():
    line = 'mysite.com:80 192.168.1.1 - - [10/Oct/2024:13:55:36 +0000] "GET /test HTTP/1.1" 200 120 "-" "-"'
    entry = LogParser.parse_line(line)
    assert entry is not None
    assert entry.ip == "192.168.1.1"
    assert entry.url == "/test"

def test_stream_file_with_non_utf8_bytes(tmp_path):
    log_file = tmp_path / "corrupt.log"
    # Write valid line, then line with raw non-UTF8 bytes, then valid line
    content = (
        b'127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /valid HTTP/1.1" 200 100\n'
        b'127.0.0.1 - - [10/Oct/2024:12:00:01 +0000] "GET /\xff\xfe\xfa HTTP/1.1" 400 50\n'
        b'127.0.0.1 - - [10/Oct/2024:12:00:02 +0000] "GET /valid2 HTTP/1.1" 200 100\n'
    )
    log_file.write_bytes(content)

    lines = list(LogParser.stream_file(str(log_file)))
    assert len(lines) == 3
    idx1, entry1, raw1 = lines[0]
    idx2, entry2, raw2 = lines[1]
    idx3, entry3, raw3 = lines[2]

    assert entry1 is not None and entry1.url == "/valid"
    assert entry2 is not None  # Successfully parsed without raising UnicodeDecodeError
    assert entry3 is not None and entry3.url == "/valid2"

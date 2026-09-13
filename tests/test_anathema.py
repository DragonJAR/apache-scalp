from datetime import datetime
from scalp.core.models import LogEntry
from scalp.heuristics.anathema import AnathemaAnalyzer

def test_anathema_default_initialization():
    analyzer = AnathemaAnalyzer()
    assert len(analyzer.signatures) > 0

def test_anathema_scores_probe_signatures():
    analyzer = AnathemaAnalyzer()
    entry = LogEntry(
        ip="198.51.100.2",
        raw_line='198.51.100.2 - - [10/Oct/2024:12:00:00 +0000] "GET /phpmyadmin/scripts/setup.php HTTP/1.1" 404 100',
        timestamp=datetime.now(),
        method="GET",
        url="/phpmyadmin/scripts/setup.php",
        protocol="HTTP/1.1",
        status_code=404,
        bytes_sent=100
    )
    score = analyzer.score_entry(entry)
    assert score >= 10
    assert analyzer.is_violator("198.51.100.2") is True
    assert "198.51.100.2" in analyzer.banned_ips

def test_anathema_tracks_repeat_offenders():
    analyzer = AnathemaAnalyzer()
    entry1 = LogEntry(
        ip="198.51.100.5",
        raw_line="raw1",
        timestamp=datetime.now(),
        method="GET",
        url="/w00tw00t.cgi",
        protocol="HTTP/1.1",
        status_code=404
    )
    entry2 = LogEntry(
        ip="198.51.100.5",
        raw_line="raw2",
        timestamp=datetime.now(),
        method="GET",
        url="/style.css",
        protocol="HTTP/1.1",
        status_code=200
    )
    score1 = analyzer.score_entry(entry1)
    score2 = analyzer.score_entry(entry2)

    assert score1 == 10
    assert score2 == 10  # Once banned, subsequent requests receive max score
    assert len(analyzer.violators["198.51.100.5"]) == 2

def test_anathema_benign_request_scores_zero():
    analyzer = AnathemaAnalyzer()
    entry = LogEntry(
        ip="10.0.0.1",
        raw_line="benign",
        timestamp=datetime.now(),
        method="GET",
        url="/index.html",
        protocol="HTTP/1.1",
        status_code=200
    )
    score = analyzer.score_entry(entry)
    assert score == 0
    assert analyzer.is_violator("10.0.0.1") is False

def test_anathema_signatures_files_in_sync():
    import json
    from pathlib import Path

    p1 = Path("scalp/heuristics/signatures.json")
    p2 = Path("anathema/signature.json")
    d1 = json.loads(p1.read_text(encoding="utf-8"))
    d2 = json.loads(p2.read_text(encoding="utf-8"))

    assert len(d1["signatures"]) == len(d2["signatures"])
    assert [s["q"] for s in d1["signatures"]] == [s["q"] for s in d2["signatures"]]


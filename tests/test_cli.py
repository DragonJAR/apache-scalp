from pathlib import Path
import subprocess
import sys
import pytest

def test_cli_help_flag():
    proc = subprocess.run([sys.executable, "-m", "scalp.cli", "--help"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "Scalp" in proc.stdout
    assert "--log" in proc.stdout
    assert "--filters" in proc.stdout

def test_cli_scan_dry_run_json(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text('127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /?q=%3Cscript%3E HTTP/1.1" 200 100\n', encoding="utf-8")
    out_dir = tmp_path / "out"

    proc = subprocess.run([
        sys.executable, "-m", "scalp.cli",
        "-l", str(log_file),
        "-f", "default_filter.xml",
        "-o", str(out_dir),
        "--json"
    ], capture_output=True, text=True)

    assert proc.returncode == 0
    assert "Scalp results:" in proc.stdout

    json_files = list(out_dir.glob("*_scalp_*.json"))
    assert len(json_files) == 1

def test_cli_scan_with_modern_rules_and_anathema(tmp_path):
    log_file = tmp_path / "modern.log"
    log_content = (
        '10.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 100\n'
        '10.0.0.2 - - [10/Oct/2024:12:00:01 +0000] "GET /w00tw00t.cgi HTTP/1.1" 404 100\n'
    )
    log_file.write_text(log_content, encoding="utf-8")
    out_dir = tmp_path / "out_modern"

    proc = subprocess.run([
        sys.executable, "-m", "scalp.cli",
        "-l", str(log_file),
        "--modern",
        "--anathema",
        "-o", str(out_dir),
        "--json"
    ], capture_output=True, text=True)

    assert proc.returncode == 0
    assert "Processed 2 lines" in proc.stdout

def test_classic_scalp_py_entrypoint_forwards_to_cli(tmp_path):
    log_file = tmp_path / "entrypoint.log"
    log_file.write_text('127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /?q=union+select HTTP/1.1" 200 100\n', encoding="utf-8")
    out_dir = tmp_path / "out_entrypoint"

    proc = subprocess.run([
        sys.executable, "scalp/scalp.py",
        "-l", str(log_file),
        "-f", "default_filter.xml",
        "-o", str(out_dir),
        "-t"
    ], capture_output=True, text=True)

    assert proc.returncode == 0
    txt_files = list(out_dir.glob("*_scalp_*.txt"))
    assert len(txt_files) == 1

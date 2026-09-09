"""Common pytest fixtures for Scalp test suite."""
import pytest
from pathlib import Path

@pytest.fixture
def fixtures_dir():
    return Path(__file__).parent / "fixtures"

@pytest.fixture
def sample_combined_log_line():
    return '127.0.0.1 - frank [10/Oct/2024:13:55:36 -0700] "GET /index.php?id=1 HTTP/1.1" 200 2326 "http://example.com" "Mozilla/5.0"'

@pytest.fixture
def sample_http2_log_line():
    return '192.168.1.50 - - [10/Oct/2024:14:00:00 +0000] "GET /app HTTP/2" 304 - "-" "curl/8.0"'

# Scalp Modernization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform Scalp into a modern, resilient, high-performance Apache/Nginx/Web log security analyzer supporting both classic web attack patterns (SQLi, XSS, Path Traversal, LFI/RFI) and modern vectors (SSRF, Log4Shell, SSTI, HTTP/2/3, Cloud API probes), resolving all Python 3 runtime bugs and establishing a robust, DRY, modular architecture with 100% test coverage.

**Architecture:** Refactor the legacy monolithic scripts into a clean decoupled pipeline: `scalp.core.models`, `scalp.core.parsers` (CLF, Combined, VHost, JSON, HTTP/1.x, HTTP/2, HTTP/3), `scalp.core.normalizers` (multi-stage URL/HTML/unicode decoder), `scalp.core.rules` (PHPIDS XML and modern YAML/JSON rules), `scalp.core.engine` (streaming, regex matching, scoring), `scalp.core.reporters` (Text, modern responsive HTML5, XML, JSON, CSV), and fully integrated `anathema` heuristic module, driven by a modern CLI.

**Tech Stack:** Python 3.10+ (Standard Library + `regex`, `pytest`, `pytest-cov`, `ruff`, optional `rich`).

---

## 1. Deep Codebase Audit & Discovered Bugs

The audit of `scalp/scalp.py`, `scalp/sexr.py`, `anathema/anathema.py`, and `default_filter.xml` revealed 14 significant errors, runtime crashes, and architectural defects:

### 1.1 `time.clock()` Removal Crash in `--sample`
- **Location:** `scalp/scalp.py:345`
- **Defect:** `random.seed(time.clock())`. `time.clock()` was deprecated in Python 3.3 and completely removed in Python 3.8.
- **Impact:** Running `python3 scalp/scalp.py -s <percentage>` crashes immediately with `AttributeError: module 'time' has no attribute 'clock'`.
- **Solution:** Rely on default system entropy with `random.seed()` or use `time.perf_counter()` if explicit time seeding is desired.

### 1.2 `dict_keys.sort()` Crash in HTML and XML Generation
- **Location:** `scalp/scalp.py:463-464` (`generate_xml_file`) and `scalp/scalp.py:497-498` (`generate_html_file`)
- **Defect:** 
  ```python
  impacts = flag[attack_type].keys()
  impacts.sort(reverse=True)
  ```
- **Impact:** In Python 3, `dict.keys()` returns a `dict_keys` view object, which lacks a `.sort()` method. Whenever Scalp finds an attack and `--html` or `--xml` is enabled, execution terminates with `AttributeError: 'dict_keys' object has no attribute 'sort'`.
- **Solution:** Use `sorted(flag[attack_type].keys(), reverse=True)` or wrap keys in `list()`.

### 1.3 Python 2 Print Statement Tuple / Operator Mismatch
- **Location:** `scalp/scalp.py:290`, `scalp/scalp.py:668`, `scalp/scalp.py:676-677`
- **Defect:** 
  - Line 290: `print("error: the output format '%s' hasn't been recognized") % output`
  - Line 668: `print("argument error, '%s' has been ignored") % s`
  - Line 676: `print("/!\ scalp cannot write in"),preferences['odir']`
- **Impact:** In Python 3, `print()` returns `None`. Evaluating `None % output` raises `TypeError: unsupported operand type(s) for %: 'NoneType' and 'str'`. Line 676 discards the directory in an unused tuple.
- **Solution:** Use modern Python 3 f-strings: `print(f"error: the output format '{output}' hasn't been recognized")`.

### 1.4 `scalp/sexr.py` Completely Unrunnable (Python 2 Syntax)
- **Location:** `scalp/sexr.py` (entire file)
- **Defect:** Contains Python 2 `print "..."` statements throughout, `import psyco` (obsolete Python 2 JIT abandoned in 2012), `dict.has_key()`, and old `getopt`.
- **Impact:** Running `python3 scalp/sexr.py` immediately fails with `SyntaxError: Missing parentheses in call to 'print'`.
- **Solution:** Modernize or absorb reporting logic directly into the central reporter module (`scalp.core.reporters`).

### 1.5 `anathema.py` Path Traversal / Hardcoded Dependency Failures
- **Location:** `anathema/anathema.py:38`, `133`
- **Defect:** `with open('./signature.json') as rf:` assumes the CWD is `anathema/`. Line 133 references a non-existent file `../../test/satellite-access.log`.
- **Impact:** Executing from project root raises `FileNotFoundError: [Errno 2] No such file or directory: './signature.json'`.
- **Solution:** Resolve paths dynamically relative to `__file__` using `pathlib.Path(__file__).parent / "signature.json"`, and expose Anathema cleanly via package imports.

### 1.6 Missing `UnicodeDecodeError` Handling on Web Logs
- **Location:** `scalp/scalp.py:343`, `353`
- **Defect:** `open(access)` uses strict platform UTF-8 decoding.
- **Impact:** Real-world attacks frequently contain raw binary payloads, non-UTF8 percent sequences, or foreign charsets. Any non-UTF8 byte aborts analysis with `UnicodeDecodeError`.
- **Solution:** Open logs with `encoding="utf-8", errors="replace"` or `errors="surrogateescape"`.

### 1.7 Catastrophic URL Normalization Flaw in `decode_attempt()`
- **Location:** `scalp/scalp.py:207-209` (`fill_replace_dict`)
- **Defect:**
  ```python
  for i in range(0,20):
      d_replace["%%%x" % i] = "%00"
      d_replace["%%%X" % i] = "%00"
  ```
  For `i = 2`, `"%%%x" % 2` produces `"%2"`. Therefore, `d_replace["%2"] = "%00"`.
- **Impact:** When any standard URL percent-encoding sequence beginning with `%2` is processed (e.g. `%27` for `'`, `%20` for space, `%22` for `"`, `%2f` for `/`), the engine replaces `%2` with `%00`, mangling `id=1%27%20OR%201=1` into `id=1%007%000OR%0001=1`. The regex rules looking for quotes or spaces never match, causing massive false negatives.
- **Solution:** Implement a proper decoding pipeline using `urllib.parse.unquote_plus` and recursive unquoting to handle single and double encoding, followed by HTML entity decoding.

### 1.8 Log Parser Regex Breaks on HTTP/2, HTTP/3, and `-` Bytes
- **Location:** `scalp/scalp.py:71`
- **Defect:**
  `c_reg = re.compile(r'^(.+)-(.*)\[(.+)[-|+](\d+)\] "([A-Z]+)?(.+) HTTP/\d.\d" (\d+)(\s[\d]+)?(\s"(.+)" )?(.*)$')`
  1. `HTTP/\d.\d`: Fails completely on `HTTP/2` and `HTTP/3` (standard in modern Apache/Nginx/Cloudflare).
  2. `([A-Z]+)?(.+)`: URL regex captures the leading whitespace.
  3. `(\s[\d]+)?`: Fails when bytes sent is `-` (standard for 304 Not Modified, redirects, or 0 bytes). In this case, `referrer` and `agent` are improperly captured in trailing groups or set to `None`.
  4. Field swap: `agent = out.group(10)`, which actually extracts the referrer string; the real user-agent in group 11 is completely discarded!
- **Impact:** Inability to analyze modern traffic (HTTP/2/3), missing user agents, and corrupted URL strings.
- **Solution:** Build a robust, regex/token-based parser supporting Common Log Format (CLF), Combined Log Format, and modern variations, with explicit named capture groups.

### 1.9 Tag Inconsistency: `ref` vs `rfe`
- **Location:** `scalp/scalp.py:59-69`, `scalp.py:593`, `README.md:79`
- **Defect:** CLI help and README declare `ref` (Remote file reference), but `default_filter.xml` uses `<tag>rfe</tag>` (Remote File Execution), and `names` defines `'rfe'`.
- **Impact:** Specifying `-a ref` matches zero rules in `default_filter.xml`.
- **Solution:** Normalize rule tags and map aliases (`ref` <-> `rfe`) transparently.

### 1.10 Date Filter Broken Across Multi-Month Ranges
- **Location:** `scalp/scalp.py:520-534` (`correct_period`)
- **Defect:** Compares day, month, year independently:
  `if cur < period['start'][i] or cur > period['end'][i]: return False`
- **Impact:** For a date range from `25/Sep/2024` to `05/Oct/2024`, any September date with day < 25 or day > 5 is rejected. It falsely rejects almost all entries in multi-month ranges.
- **Solution:** Parse log timestamps into Python `datetime` objects and perform standard range comparisons (`start_time <= log_time <= end_time`).

### 1.11 Single-Filter XML Parser Bug
- **Location:** `scalp/scalp.py:304`
- **Defect:** `if type(xml_filters[group][f]) == type([]):`
- **Impact:** If an XML rule file contains only 1 filter, `__parse_node` leaves it as a `dict`, not a `list`. The `type([])` check fails and the filter is never loaded.
- **Solution:** Iterate directly over XML elements using standard `xml.etree.ElementTree.iter('filter')`.

### 1.12 Flawed Subnet Exclusion with String Prefix Matching
- **Location:** `scalp/scalp.py:378`
- **Defect:** `if ip_split[0].startswith(sub):`
- **Impact:** Prefix `10.0.0.1` accidentally excludes `10.0.0.10` through `10.0.0.199`. No CIDR support (`192.168.1.0/24`) and no IPv6 support.
- **Solution:** Use Python's standard `ipaddress.ip_network` and `ipaddress.ip_address`.

### 1.13 Disconnected / Orphaned Anathema Module
- **Location:** `anathema/anathema.py` vs `scalp/scalp.py`
- **Defect:** Anathema is advertised in README as providing behavioral scoring, but is completely omitted from `scalp.py`.
- **Solution:** Integrate Anathema into the core pipeline so heuristic scoring and IP violator tracking can be executed as a filter or supplementary scoring stage.

### 1.14 Outdated Signatures Missing Modern Attack Vectors
- **Location:** `default_filter.xml`
- **Defect:** Rules date back to PHPIDS (2008-2012). While classic attacks (SQLi, XSS, Path Traversal) are covered, modern vectors are completely absent:
  - SSRF (Cloud metadata: `169.254.169.254`, container endpoints)
  - Log4Shell / JNDI injection (`${jndi:ldap:...}`)
  - Server-Side Template Injection (SSTI: `{{...}}`, `${...}`)
  - Spring4Shell / ClassLoader manipulation
  - Modern recon / path probes (Actuator endpoints, `.env`, Swagger/OpenAPI exposure)
- **Solution:** Provide an extensible rule repository supporting both classic PHPIDS XML rules and modern modular rules (JSON/YAML) with updated signatures.

---

## 2. Proposed Architecture & DRY Design

```
apache-scalp/
├── pyproject.toml                     # Modern PEP 621 packaging & metadata
├── scalp/
│   ├── __init__.py                    # Package exports and version
│   ├── cli.py                         # Modern argparse CLI with classic flag backwards-compatibility
│   ├── core/
│   │   ├── __init__.py
│   │   ├── models.py                  # LogEntry, FilterRule, MatchResult, AttackType
│   │   ├── parser.py                  # Fast, robust log parser (CLF, Combined, VHost, HTTP/1-3, IPv4/6)
│   │   ├── normalizer.py              # Multi-stage decoders (URL, recursive, unicode, HTML entities)
│   │   ├── filters.py                 # XML (PHPIDS) & JSON rule loaders, tag normalizer
│   │   ├── engine.py                  # Streaming analysis engine, pre-filtering, multiprocessing
│   │   └── exclusions.py              # IP & CIDR subnet exclusions via ipaddress
│   ├── heuristics/
│   │   ├── __init__.py
│   │   ├── anathema.py                # Refactored Anathema heuristic analyzer
│   │   └── signatures.json            # Modernized heuristic signatures
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── base.py                    # BaseReporter interface
│   │   ├── text.py                    # Text reporter
│   │   ├── html.py                    # Modern responsive HTML5 reporter
│   │   ├── xml.py                     # XML reporter (with valid DTD/structure)
│   │   ├── json.py                    # JSON/NDJSON reporter for SIEM/pipelines
│   │   └── csv.py                     # CSV reporter
│   └── rules/
│       ├── default_filter.xml         # Classic PHPIDS rules
│       └── modern_rules.json          # Modern web attacks (SSRF, Log4j, SSTI, Spring)
└── tests/
    ├── conftest.py                    # Fixtures: sample logs, filter rules
    ├── test_parser.py                 # Tests for CLF, Combined, HTTP/2, HTTP/3, IPv6, '-' bytes
    ├── test_normalizer.py             # Tests for %2x decoding, double-encoding, unicode
    ├── test_filters.py                # Tests for XML and JSON rule loading, tags
    ├── test_exclusions.py             # Tests for IP and CIDR exclusions
    ├── test_engine.py                 # Tests for attack matching, classic and modern
    ├── test_anathema.py               # Tests for heuristic scoring and violator tracking
    ├── test_reporters.py              # Tests for HTML, XML, Text, JSON outputs
    └── test_cli.py                    # End-to-end CLI tests
```

---

## 3. Implementation Tasks

### Task 1: Project Setup, Tooling & Modern Packaging

**Files:**
- Create: `pyproject.toml`
- Modify: `requirements.txt`
- Create: `tests/conftest.py`

**Step 1: Write `pyproject.toml` with packaging & pytest/ruff configuration**
```toml
[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "apache-scalp"
version = "1.0.0"
description = "Modern Apache/Nginx web log attack analyzer based on PHPIDS and modern signatures"
authors = [
    { name = "DragonJAR SAS", email = "contacto@dragonjar.org" }
]
license = { text = "Apache-2.0" }
readme = "README.md"
requires-python = ">=3.10"
dependencies = [
    "regex>=2023.0.0"
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-cov>=5.0.0",
    "ruff>=0.4.0"
]

[project.scripts]
scalp = "scalp.cli:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]

[tool.ruff]
line-length = 100
target-version = "py310"
```

**Step 2: Run test suite to verify test runner works**
Run: `pytest`
Expected: `no tests ran in 0.00s`

**Step 3: Commit**
```bash
git add pyproject.toml requirements.txt tests/conftest.py
git commit -m "chore: configure modern pyproject.toml and pytest setup"
```

---

### Task 2: Core Data Models (`scalp/core/models.py`)

**Files:**
- Create: `scalp/core/models.py`
- Test: `tests/test_models.py`

**Step 1: Write failing test for data models**
```python
# tests/test_models.py
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
```

**Step 2: Run test to verify it fails**
Run: `pytest tests/test_models.py`
Expected: FAIL (`ModuleNotFoundError: No module named 'scalp.core.models'`)

**Step 3: Write minimal implementation**
```python
# scalp/core/models.py
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Set

@dataclass(frozen=True, slots=True)
class LogEntry:
    ip: str
    raw_line: str
    timestamp: Optional[datetime]
    method: str
    url: str
    protocol: str
    status_code: int
    bytes_sent: Optional[int] = None
    referrer: Optional[str] = None
    user_agent: Optional[str] = None

@dataclass(frozen=True, slots=True)
class FilterRule:
    rule_id: str
    pattern: str
    description: str
    impact: int
    tags: Set[str] = field(default_factory=set)

@dataclass(slots=True)
class AttackMatch:
    entry: LogEntry
    rule: FilterRule
    matched_string: str
    tag: str
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_models.py`
Expected: PASS

**Step 5: Commit**
```bash
git add scalp/core/models.py tests/test_models.py
git commit -m "feat(core): add immutable data models for log entries and attack rules"
```

---

### Task 3: Robust Log Parser (`scalp/core/parser.py`)

**Files:**
- Create: `scalp/core/parser.py`
- Test: `tests/test_parser.py`

Must support:
- Standard Common Log Format (CLF)
- Combined Log Format
- Virtual Host Combined Format
- HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3
- Dash `-` in bytes sent (e.g. 304 Not Modified)
- IPv4 and IPv6 addresses
- Safe UTF-8 decoding (`errors='replace'`)

**Step 1: Write failing tests for diverse log line variations**
```python
# tests/test_parser.py
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

def test_parse_http2_and_dash_bytes():
    line = '10.0.0.1 - - [10/Oct/2024:14:00:00 +0000] "GET /app HTTP/2" 304 - "-" "curl/8.0"'
    entry = LogParser.parse_line(line)
    assert entry is not None
    assert entry.protocol == "HTTP/2"
    assert entry.status_code == 304
    assert entry.bytes_sent is None
    assert entry.user_agent == "curl/8.0"

def test_parse_ipv6():
    line = '2001:db8::1 - - [10/Oct/2024:14:00:00 +0000] "POST /api/login HTTP/3" 401 512 "-" "CustomAgent/1.0"'
    entry = LogParser.parse_line(line)
    assert entry is not None
    assert entry.ip == "2001:db8::1"
    assert entry.protocol == "HTTP/3"
    assert entry.method == "POST"
```

**Step 2: Run test to verify failure**
Run: `pytest tests/test_parser.py`
Expected: FAIL

**Step 3: Implement `LogParser`**
```python
# scalp/core/parser.py
from datetime import datetime
from typing import Generator, Optional
import regex as re
from scalp.core.models import LogEntry

COMBINED_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+(?P<proto>HTTP\/[\d\.]+))?"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

class LogParser:
    @staticmethod
    def parse_timestamp(ts_str: str) -> Optional[datetime]:
        try:
            return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None

    @classmethod
    def parse_line(cls, line: str) -> Optional[LogEntry]:
        match = COMBINED_PATTERN.match(line.strip())
        if not match:
            return None
        data = match.groupdict()
        bytes_val = int(data['bytes']) if data['bytes'] and data['bytes'] != '-' else None
        return LogEntry(
            ip=data['ip'],
            raw_line=line.rstrip('\r\n'),
            timestamp=cls.parse_timestamp(data['time']),
            method=data['method'],
            url=data['url'],
            protocol=data.get('proto') or 'HTTP/1.1',
            status_code=int(data['status']),
            bytes_sent=bytes_val,
            referrer=data.get('referrer'),
            user_agent=data.get('agent')
        )

    @classmethod
    def stream_file(cls, filepath: str) -> Generator[tuple[int, Optional[LogEntry], str], None, None]:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f, 1):
                yield idx, cls.parse_line(line), line
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_parser.py`
Expected: PASS

**Step 5: Commit**
```bash
git add scalp/core/parser.py tests/test_parser.py
git commit -m "feat(parser): add robust log parser supporting HTTP/1-3, IPv6, and non-UTF8 logs"
```

---

### Task 4: Normalizer & Anti-Evasion Engine (`scalp/core/normalizer.py`)

**Files:**
- Create: `scalp/core/normalizer.py`
- Test: `tests/test_normalizer.py`

Must fix the catastrophic `%2` mangling defect, providing:
- Standard URL unquoting (`urllib.parse.unquote_plus`)
- Recursive unquoting to defeat double/triple encoding (`%2527` -> `%27` -> `'`)
- HTML entity decoding (`&quot;`, `&#x27;`, `&#39;`)
- Unicode null-byte stripping (`%00`)
- Optional SQL keyword and comment normalization without corrupting URL tokens

**Step 1: Write failing tests for normalizer**
```python
# tests/test_normalizer.py
from scalp.core.normalizer import PayloadNormalizer

def test_url_decoding_preserves_single_quotes_and_spaces():
    raw = "id=1%27%20OR%201=1--"
    normalized = PayloadNormalizer.normalize(raw)
    assert normalized == "id=1' OR 1=1--"
    assert "%00" not in normalized

def test_recursive_double_encoding():
    raw = "q=%2522%253E%253Cscript%253E"
    normalized = PayloadNormalizer.normalize(raw)
    assert '"><script>' in normalized

def test_html_entity_decoding():
    raw = "search=&lt;svg/onload=alert(1)&gt;"
    normalized = PayloadNormalizer.normalize(raw)
    assert "<svg/onload=alert(1)>" in normalized
```

**Step 2: Run test to verify failure**
Run: `pytest tests/test_normalizer.py`
Expected: FAIL

**Step 3: Implement `PayloadNormalizer`**
```python
# scalp/core/normalizer.py
import html
import urllib.parse

class PayloadNormalizer:
    @staticmethod
    def normalize(text: str, max_iterations: int = 3) -> str:
        current = text
        for _ in range(max_iterations):
            unquoted = urllib.parse.unquote_plus(current)
            if unquoted == current:
                break
            current = unquoted
        current = html.unescape(current)
        current = current.replace("\x00", "")
        return current
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_normalizer.py`
Expected: PASS

**Step 5: Commit**
```bash
git add scalp/core/normalizer.py tests/test_normalizer.py
git commit -m "feat(normalizer): replace broken replacement table with recursive URL/HTML normalizer"
```

---

### Task 5: Date Filtering & IP/CIDR Exclusions (`scalp/core/exclusions.py`)

**Files:**
- Create: `scalp/core/exclusions.py`
- Test: `tests/test_exclusions.py`

Must fix:
- Multi-month date filtering logic using datetime comparisons
- IP and CIDR subnet exclusions via standard `ipaddress` module

**Step 1: Write failing tests**
```python
# tests/test_exclusions.py
from datetime import datetime, timezone, timedelta
from scalp.core.exclusions import DateRangeFilter, NetworkFilter

def test_date_range_spans_month_boundary():
    tz = timezone(timedelta(hours=-5))
    start = datetime(2024, 9, 25, 0, 0, 0, tzinfo=tz)
    end = datetime(2024, 10, 5, 23, 59, 59, tzinfo=tz)
    date_filter = DateRangeFilter(start=start, end=end)

    in_sep = datetime(2024, 9, 28, 12, 0, 0, tzinfo=tz)
    in_oct = datetime(2024, 10, 2, 12, 0, 0, tzinfo=tz)
    before = datetime(2024, 9, 20, 12, 0, 0, tzinfo=tz)
    after = datetime(2024, 10, 10, 12, 0, 0, tzinfo=tz)

    assert date_filter.is_valid(in_sep) is True
    assert date_filter.is_valid(in_oct) is True
    assert date_filter.is_valid(before) is False
    assert date_filter.is_valid(after) is False

def test_network_filter_cidr_and_single_ip():
    net_filter = NetworkFilter(excluded_ips=["127.0.0.1"], excluded_subnets=["192.168.1.0/24", "10.0.0.0/8"])
    assert net_filter.is_excluded("127.0.0.1") is True
    assert net_filter.is_excluded("192.168.1.50") is True
    assert net_filter.is_excluded("10.5.4.3") is True
    assert net_filter.is_excluded("172.16.0.1") is False
```

**Step 2: Run test to verify failure**
Run: `pytest tests/test_exclusions.py`
Expected: FAIL

**Step 3: Implement `DateRangeFilter` and `NetworkFilter`**
```python
# scalp/core/exclusions.py
from datetime import datetime
import ipaddress
from typing import Iterable, Optional

class DateRangeFilter:
    def __init__(self, start: Optional[datetime] = None, end: Optional[datetime] = None):
        self.start = start
        self.end = end

    def is_valid(self, dt: Optional[datetime]) -> bool:
        if dt is None:
            return True
        if self.start and dt < self.start:
            return False
        if self.end and dt > self.end:
            return False
        return True

class NetworkFilter:
    def __init__(self, excluded_ips: Optional[Iterable[str]] = None, excluded_subnets: Optional[Iterable[str]] = None):
        self._ips = set()
        for ip_str in (excluded_ips or []):
            try:
                self._ips.add(ipaddress.ip_address(ip_str.strip()))
            except ValueError:
                pass
        self._subnets = []
        for net_str in (excluded_subnets or []):
            try:
                self._subnets.append(ipaddress.ip_network(net_str.strip(), strict=False))
            except ValueError:
                pass

    def is_excluded(self, ip_str: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False
        if addr in self._ips:
            return True
        return any(addr in net for net in self._subnets)
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_exclusions.py`
Expected: PASS

**Step 5: Commit**
```bash
git add scalp/core/exclusions.py tests/test_exclusions.py
git commit -m "feat(exclusions): add precise datetime range filtering and CIDR IP exclusion"
```

---

### Task 6: Rule Loader & Tag Normalizer (`scalp/core/rules.py`)

**Files:**
- Create: `scalp/core/rules.py`
- Test: `tests/test_rules.py`

Must fix:
- Single-filter XML parsing defect
- Tag discrepancy (`ref` <-> `rfe`)
- Compile regexes safely with regex engine error handling
- Support loading both XML and JSON rule formats

**Step 1: Write failing tests**
```python
# tests/test_rules.py
from scalp.core.rules import RuleLoader

def test_load_classic_phpids_xml(tmp_path):
    xml_content = """<?xml version="1.0"?>
    <filters>
        <filter>
            <id>1</id>
            <rule><![CDATA[(?:<script.*?>)]]></rule>
            <description>XSS Tag</description>
            <tags><tag>xss</tag></tags>
            <impact>5</impact>
        </filter>
    </filters>
    """
    rule_file = tmp_path / "test_filter.xml"
    rule_file.write_text(xml_content, encoding="utf-8")

    rules = RuleLoader.load_xml(str(rule_file))
    assert len(rules) == 1
    assert rules[0].rule_id == "1"
    assert "xss" in rules[0].tags

def test_tag_alias_mapping():
    assert RuleLoader.normalize_tag("ref") == "rfe"
    assert RuleLoader.normalize_tag("rfe") == "rfe"
```

**Step 2: Run test to verify failure**
Run: `pytest tests/test_rules.py`
Expected: FAIL

**Step 3: Implement `RuleLoader`**
```python
# scalp/core/rules.py
import json
import xml.etree.ElementTree as ET
from typing import List, Set
import regex as re
from scalp.core.models import FilterRule

TAG_ALIASES = {
    "ref": "rfe",
}

class RuleLoader:
    @staticmethod
    def normalize_tag(tag: str) -> str:
        clean = tag.strip().lower()
        return TAG_ALIASES.get(clean, clean)

    @classmethod
    def load_xml(cls, filepath: str) -> List[FilterRule]:
        tree = ET.parse(filepath)
        root = tree.getroot()
        rules = []
        for f in root.findall(".//filter"):
            rule_id = f.findtext("id", default="").strip()
            rule_text = f.findtext("rule", default="").strip()
            description = f.findtext("description", default="").strip()
            impact_text = f.findtext("impact", default="0").strip()
            try:
                impact = int(impact_text)
            except ValueError:
                impact = 0
            tags: Set[str] = set()
            for tag_elem in f.findall(".//tag"):
                if tag_elem.text:
                    tags.add(cls.normalize_tag(tag_elem.text))
            if rule_text:
                rules.append(FilterRule(
                    rule_id=rule_id,
                    pattern=rule_text,
                    description=description,
                    impact=impact,
                    tags=tags
                ))
        return rules

    @classmethod
    def load_json(cls, filepath: str) -> List[FilterRule]:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = []
        for item in data.get("rules", []):
            tags = {cls.normalize_tag(t) for t in item.get("tags", [])}
            rules.append(FilterRule(
                rule_id=str(item.get("id", "")),
                pattern=item.get("pattern", ""),
                description=item.get("description", ""),
                impact=int(item.get("impact", 0)),
                tags=tags
            ))
        return rules
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_rules.py`
Expected: PASS

**Step 5: Commit**
```bash
git add scalp/core/rules.py tests/test_rules.py
git commit -m "feat(rules): implement XML and JSON rule loader with tag normalization"
```

---

### Task 7: Modern Attack Signatures (`scalp/rules/modern_rules.json`)

**Files:**
- Create: `scalp/rules/modern_rules.json`
- Test: `tests/test_modern_rules.py`

Add detection signatures for modern attacks:
- **SSRF:** AWS metadata (`169.254.169.254`), GCP metadata (`metadata.google.internal`), Docker daemon sockets.
- **Log4Shell:** JNDI lookups (`${jndi:ldap://...}`, `${jndi:rmi://...}`, `${${lower:j}ndi:...}`).
- **SSTI:** Jinja2 / Freemarker / Thymeleaf injections (`{{7*7}}`, `${7*7}`, `#{7*7}`, `<#assign`).
- **Spring4Shell / Deserialization:** `class.module.classLoader`, Java serialization magic bytes, Python pickle payloads.
- **Recon / Probes:** `.env`, `.git/HEAD`, `actuator/heapdump`, `swagger-ui.html`.

**Step 1: Create `scalp/rules/modern_rules.json` with tested regular expressions**
**Step 2: Write test verifying that modern attack samples trigger matches**
```python
# tests/test_modern_rules.py
import regex as re
from scalp.core.rules import RuleLoader

def test_detects_log4shell_variants():
    rules = RuleLoader.load_json("scalp/rules/modern_rules.json")
    log4j_rule = next(r for r in rules if "log4j" in r.tags or "jndi" in r.tags)
    compiled = re.compile(log4j_rule.pattern, re.IGNORECASE)
    assert compiled.search("/test?param=${jndi:ldap://attacker.com/a}") is not None
    assert compiled.search("/test?param=${${lower:j}ndi:rmi://attacker.com/a}") is not None

def test_detects_ssrf_metadata():
    rules = RuleLoader.load_json("scalp/rules/modern_rules.json")
    ssrf_rule = next(r for r in rules if "ssrf" in r.tags)
    compiled = re.compile(ssrf_rule.pattern, re.IGNORECASE)
    assert compiled.search("/proxy?url=http://169.254.169.254/latest/meta-data/") is not None
```

**Step 3: Run test to verify it passes**
Run: `pytest tests/test_modern_rules.py`
Expected: PASS

**Step 4: Commit**
```bash
git add scalp/rules/modern_rules.json tests/test_modern_rules.py
git commit -m "feat(signatures): add modern attack signatures for SSRF, Log4Shell, SSTI and Cloud Probes"
```

---

### Task 8: Anathema Heuristic Engine Integration (`scalp/heuristics/anathema.py`)

**Files:**
- Create: `scalp/heuristics/anathema.py`
- Move & update: `anathema/signature.json` -> `scalp/heuristics/signatures.json`
- Test: `tests/test_anathema.py`

Must fix:
- Dynamic path resolution for `signatures.json`
- Proper integration with `LogEntry` objects
- IP violator and incident tracking with severity scoring threshold

**Step 1: Write failing tests for Anathema**
```python
# tests/test_anathema.py
from scalp.core.models import LogEntry
from scalp.heuristics.anathema import AnathemaAnalyzer

def test_anathema_detects_probe_signatures():
    analyzer = AnathemaAnalyzer()
    entry = LogEntry(
        ip="198.51.100.2",
        raw_line="raw",
        timestamp=None,
        method="GET",
        url="/phpmyadmin/scripts/setup.php",
        protocol="HTTP/1.1",
        status_code=404,
        bytes_sent=100
    )
    score = analyzer.score_entry(entry)
    assert score >= 10
    assert analyzer.is_violator("198.51.100.2") is True
```

**Step 2: Run test to verify failure**
Run: `pytest tests/test_anathema.py`
Expected: FAIL

**Step 3: Implement `AnathemaAnalyzer`**
```python
# scalp/heuristics/anathema.py
import json
from pathlib import Path
from typing import Dict, List, Set, Tuple
import regex as re
from scalp.core.models import LogEntry

DEFAULT_SIGNATURES_FILE = Path(__file__).parent / "signatures.json"

class AnathemaAnalyzer:
    def __init__(self, signatures_path: Path = DEFAULT_SIGNATURES_FILE):
        with open(signatures_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self._compiled: List[Tuple[re.Pattern, int]] = []
        for s in data.get("signatures", []):
            self._compiled.append((re.compile(s["q"], re.IGNORECASE), int(s.get("s", 5))))
        self.violators: Dict[str, List[LogEntry]] = {}
        self.banned_ips: Set[str] = set()

    def score_entry(self, entry: LogEntry) -> int:
        if entry.ip in self.banned_ips:
            self.violators[entry.ip].append(entry)
            return 10
        for pattern, score in self._compiled:
            if pattern.search(entry.url) or (entry.user_agent and pattern.search(entry.user_agent)):
                if entry.ip not in self.violators:
                    self.violators[entry.ip] = []
                self.violators[entry.ip].append(entry)
                if score >= 10:
                    self.banned_ips.add(entry.ip)
                return score
        return 0

    def is_violator(self, ip: str) -> bool:
        return ip in self.violators
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_anathema.py`
Expected: PASS

**Step 5: Commit**
```bash
git add scalp/heuristics/ tests/test_anathema.py
git commit -m "feat(anathema): integrate heuristic analyzer with dynamic path resolution and IP tracking"
```

---

### Task 9: Core Analysis Engine (`scalp/core/engine.py`)

**Files:**
- Create: `scalp/core/engine.py`
- Test: `tests/test_engine.py`

Responsibilities:
- Coordinate `LogParser`, `PayloadNormalizer`, `RuleLoader`, `DateRangeFilter`, `NetworkFilter`, and `AnathemaAnalyzer`
- Pre-compile regexes
- Stream logs to keep memory footprint constant (`O(1)` memory regardless of log file size)
- Support `--exhaustive` (find all rules matched per request) or fast mode (first match)

**Step 1: Write failing tests for Engine**
```python
# tests/test_engine.py
from scalp.core.engine import ScalpEngine
from scalp.core.models import FilterRule

def test_engine_matches_attack_in_log(tmp_path):
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
    assert len(result.matches) >= 1
    assert result.matches[0].rule.rule_id == "sqli_1"
```

**Step 2: Run test to verify failure**
Run: `pytest tests/test_engine.py`
Expected: FAIL

**Step 3: Implement `ScalpEngine`**
```python
# scalp/core/engine.py
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
import regex as re
from scalp.core.exclusions import DateRangeFilter, NetworkFilter
from scalp.core.models import AttackMatch, FilterRule
from scalp.core.normalizer import PayloadNormalizer
from scalp.core.parser import LogParser
from scalp.heuristics.anathema import AnathemaAnalyzer

@dataclass
class ScanResult:
    total_lines: int = 0
    processed_lines: int = 0
    matches: List[AttackMatch] = field(default_factory=list)
    unmatched_lines: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

class ScalpEngine:
    def __init__(
        self,
        rules: List[FilterRule],
        attack_types: Optional[Set[str]] = None,
        date_filter: Optional[DateRangeFilter] = None,
        network_filter: Optional[NetworkFilter] = None,
        anathema: Optional[AnathemaAnalyzer] = None,
        exhaustive: bool = False,
        normalize_payloads: bool = True,
        sample_pct: float = 100.0,
    ):
        self.rules = rules
        self.attack_types = attack_types
        self.date_filter = date_filter or DateRangeFilter()
        self.network_filter = network_filter or NetworkFilter()
        self.anathema = anathema
        self.exhaustive = exhaustive
        self.normalize_payloads = normalize_payloads
        self.sample_pct = sample_pct

        self._compiled_rules = []
        for r in self.rules:
            if not self.attack_types or any(t in self.attack_types for t in r.tags):
                try:
                    self._compiled_rules.append((r, re.compile(r.pattern, re.IGNORECASE)))
                except Exception:
                    pass

    def scan_file(self, filepath: str) -> ScanResult:
        import time, random
        start_time = time.time()
        result = ScanResult()

        for idx, entry, raw_line in LogParser.stream_file(filepath):
            result.total_lines += 1
            if self.sample_pct < 100.0 and random.uniform(0, 100) > self.sample_pct:
                continue
            if not entry:
                result.unmatched_lines.append(raw_line)
                continue
            if self.network_filter.is_excluded(entry.ip):
                continue
            if not self.date_filter.is_valid(entry.timestamp):
                continue

            result.processed_lines += 1
            search_target = PayloadNormalizer.normalize(entry.url) if self.normalize_payloads else entry.url

            matched_any = False
            for rule, compiled in self._compiled_rules:
                m = compiled.search(search_target)
                if m:
                    matched_any = True
                    for tag in rule.tags:
                        if not self.attack_types or tag in self.attack_types:
                            result.matches.append(AttackMatch(
                                entry=entry,
                                rule=rule,
                                matched_string=m.group(0),
                                tag=tag
                            ))
                    if not self.exhaustive:
                        break

            if self.anathema:
                self.anathema.score_entry(entry)

        result.elapsed_seconds = time.time() - start_time
        return result
```

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_engine.py`
Expected: PASS

**Step 5: Commit**
```bash
git add scalp/core/engine.py tests/test_engine.py
git commit -m "feat(engine): implement streaming scan engine with rule compilation and sampling"
```

---

### Task 10: Pluggable Reporters (`scalp/reporters/`)

**Files:**
- Create: `scalp/reporters/base.py`
- Create: `scalp/reporters/text.py`
- Create: `scalp/reporters/html.py`
- Create: `scalp/reporters/xml.py`
- Create: `scalp/reporters/json_rep.py`
- Test: `tests/test_reporters.py`

Fixes:
- HTML reporter uses modern, accessible, responsive CSS (dark/light theme, clean tables, impact badges)
- XML reporter produces valid XML complying with DTD without sorting crashes
- JSON reporter exports structured matches for SIEM / DevSecOps pipelines
- Text reporter provides clean human-readable output

**Step 1: Write tests verifying reporters generate valid outputs without exceptions**
```python
# tests/test_reporters.py
from datetime import datetime
from scalp.core.engine import ScanResult
from scalp.core.models import AttackMatch, FilterRule, LogEntry
from scalp.reporters.html import HtmlReporter
from scalp.reporters.xml import XmlReporter
from scalp.reporters.json_rep import JsonReporter

def test_html_and_xml_reporters(tmp_path):
    entry = LogEntry("127.0.0.1", "raw", datetime.now(), "GET", "/test", "HTTP/1.1", 200, 100)
    rule = FilterRule("1", "pattern", "XSS", 8, {"xss"})
    result = ScanResult(total_lines=1, processed_lines=1, matches=[AttackMatch(entry, rule, "/test", "xss")])

    html_file = tmp_path / "report.html"
    HtmlReporter.generate(result, str(html_file))
    assert html_file.exists()
    assert "Impact 8" in html_file.read_text(encoding="utf-8")

    xml_file = tmp_path / "report.xml"
    XmlReporter.generate(result, str(xml_file))
    assert xml_file.exists()
    assert "<scalp" in xml_file.read_text(encoding="utf-8")

    json_file = tmp_path / "report.json"
    JsonReporter.generate(result, str(json_file))
    assert json_file.exists()
    assert '"impact": 8' in json_file.read_text(encoding="utf-8")
```

**Step 2: Run test to verify failure**
Run: `pytest tests/test_reporters.py`
Expected: FAIL

**Step 3: Implement Reporters**
Implement `TextReporter`, `HtmlReporter`, `XmlReporter`, `JsonReporter`. Ensure HTML uses modern semantic HTML5 and valid UTF-8.

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_reporters.py`
Expected: PASS

**Step 5: Commit**
```bash
git add scalp/reporters/ tests/test_reporters.py
git commit -m "feat(reporters): implement modern HTML5, XML, Text, and JSON reporters"
```

---

### Task 11: Unified CLI Interface & Backwards Compatibility (`scalp/cli.py`)

**Files:**
- Create: `scalp/cli.py`
- Modify: `scalp/scalp.py` (redirect or maintain as backwards-compatible runner calling `scalp.cli`)
- Test: `tests/test_cli.py`

Features:
- Full support for classic flags: `-l/--log`, `-f/--filters`, `-p/--period`, `-a/--attack`, `-s/--sample`, `-e/--exhaustive`, `-u/--tough`, `-h/--html`, `-x/--xml`, `-t/--text`, `-o/--output`, `-i/--ignore-ip`, `-n/--ignore-subnet`, `-c/--except`.
- New modern flags: `--json`, `--rules-dir`, `--modern` (load modern attack signatures), `--anathema` (enable heuristic scoring), `--quiet`.
- Clear, formatted `--help` with examples.

**Step 1: Write failing CLI tests**
```python
# tests/test_cli.py
import subprocess
import sys

def test_cli_help():
    proc = subprocess.run([sys.executable, "-m", "scalp.cli", "--help"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "Scalp" in proc.stdout
    assert "--log" in proc.stdout

def test_cli_scan_dry_run(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text('127.0.0.1 - - [10/Oct/2024:12:00:00 +0000] "GET /?q=%3Cscript%3E HTTP/1.1" 200 100\n')
    out_dir = tmp_path / "out"
    proc = subprocess.run([
        sys.executable, "-m", "scalp.cli",
        "-l", str(log_file),
        "-f", "default_filter.xml",
        "-o", str(out_dir),
        "--json"
    ], capture_output=True, text=True)
    assert proc.returncode == 0
```

**Step 2: Run test to verify failure**
Run: `pytest tests/test_cli.py`
Expected: FAIL

**Step 3: Implement `scalp/cli.py` using `argparse`**
Implement argument parsing cleanly with defaults, validation, and invocation of `ScalpEngine` and chosen reporters.

**Step 4: Run test to verify it passes**
Run: `pytest tests/test_cli.py`
Expected: PASS

**Step 5: Commit**
```bash
git add scalp/cli.py scalp/scalp.py tests/test_cli.py
git commit -m "feat(cli): provide modern argparse CLI with 100% backwards compatibility with classic flags"
```

---

## 4. Execution Handoff

Plan complete and saved to `docs/plans/2026-09-09-scalp-modernization-plan.md`. Two execution options:

1. **Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration.
2. **Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints.

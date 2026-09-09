# Scalp! — Apache Log Attack Analyzer

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](#-license) [![Python](https://img.shields.io/badge/python-3-green.svg)](https://www.python.org) [![Upstream](https://img.shields.io/badge/upstream-nanopony%2Fapache--scalp-orange.svg)](https://github.com/nanopony/apache-scalp) [![Author](https://img.shields.io/badge/original%20author-Romain%20Gaucher-orange.svg)](http://rgaucher.info) [![Maintainer](https://img.shields.io/badge/maintained%20by-DragonJAR%20SAS-blue.svg)](https://www.DragonJAR.org) [![Español](https://img.shields.io/badge/leer%20en-Espa%C3%B1ol-blue.svg)](README.es.md)

> Scalp! is a log analyzer for the Apache web server that searches huge access logs for attack patterns sent through HTTP GET/POST requests, using the high-quality regular expressions of the [PHPIDS project](https://github.com/PHPIDS/PHPIDS).

This repository is a **modernization of [Nanopony's fork](https://github.com/nanopony/apache-scalp)** of the original Scalp! tool by Romain Gaucher. We only keep it alive: Python 3 compatibility, updated filter file, and maintenance fixes. All credit for the tool and its evolution belongs to the original authors.

## 🎯 What It Does

- Scans Apache and Nginx access logs line by line against the PHPIDS `default_filter.xml` regex rule set and modern JSON signatures.
- Supports **plain text and compressed gzip logs (`.gz`)** transparently.
- Inspects **multiple HTTP vectors**: Request URL, `User-Agent`, and `Referer` headers with vector provenance tracking.
- Supports **HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/3**, IPv4, IPv6 (including bracketed `[::1]`), hostnames, and ports.
- Detects and classifies classic attacks: XSS, SQL injection, CSRF, DoS, directory traversal, spam, information disclosure, remote file execution (`rfe`/`ref`), and local file inclusion (`lfi`).
- Detects modern web attacks (`--modern`):
  - **NoSQL Injection**: MongoDB/CouchDB operators (`$ne`, `$gt`, `$where`, `$regex`).
  - **Prototype Pollution**: JavaScript runtime manipulation (`__proto__`, `constructor.prototype`).
  - **CRLF Injection**: Header splitting and poisoning (`%0d%0aSet-Cookie:`, `Location:`).
  - **OS Command Injection & Shellshock**: Shell syntax (`() { :; };`, `$(...)`, chaining `;`, `|`, `&`).
  - **SSRF**: Cloud metadata (AWS, GCP, Azure, Alibaba, Oracle) with decimal, hex, and octal IP evasion bypasses.
  - **Log4Shell/JNDI**: Injection and obfuscation variants (`${jndi:...}`).
  - **SSTI & Spring4Shell**: Template engines and ClassLoader exploitation.
  - **Sensitive Probes**: `.env`, `.git`, Actuator endpoints, and GraphQL introspection.
- Multi-pass anti-evasion decoder: recursive URL decoding, HTML entity unescaping, Unicode NFKC normalization (fullwidth character conversion), control-character stripping, and Base64 payload extraction.
- Prioritizes rules by impact severity (10 to 0) to highlight critical exploits.
- Correlates attacks with HTTP response codes (highlighting potential executions like `200/500` vs blocked `404/403`).
- Includes the integrated **Anathema** heuristic module (`--anathema`) for behavioral attack scoring and malicious IP tracking.
- Outputs results in TEXT, XML, modern responsive HTML5, or JSON (for SIEM and CI/CD pipelines).

## 📦 Installation

```bash
git clone https://github.com/DragonJAR/apache-scalp
cd apache-scalp
pip install -r requirements.txt
```

## ⚙️ Prerequisites

| Tool | Purpose |
|------|---------|
| Python 3.10+ | Runtime |
| `regex` (see `requirements.txt`) | Advanced regular expression engine |
| Apache / Nginx access log (`.log`, `.txt`, or `.gz`) | Input data |
| `default_filter.xml` (bundled) | Comprehensive attack signatures |
| `scalp/rules/modern_rules.json` (bundled) | Modern attack signatures |

The filter file ships with this repository. If missing, Scalp! downloads it automatically from the [PHPIDS project](https://github.com/PHPIDS/PHPIDS/blob/master/lib/IDS/default_filter.xml).

## 🚀 Usage

Run directly from the root directory:

```bash
python3 scalp.py -l /var/log/apache2/access.log -f default_filter.xml -o ./scalp-output --html --modern --anathema
```

Or analyze rotated gzip logs directly:

```bash
python3 scalp.py -l /var/log/nginx/access.log.1.gz -o ./scalp-output --json
```

```text
usage: scalp [--help] [-V] [-l LOG] [-f FILTERS] [-o OUTPUT] [-h] [-x] [-t]
             [--json] [-a ATTACK] [-p PERIOD] [-s SAMPLE] [-i IGNORE_IP]
             [-n IGNORE_SUBNET] [-e] [-u] [-c] [--modern] [--anathema]

Scalp! Apache/Nginx attack analyzer based on PHPIDS and modern signatures.

options:
  --help                Show this help message and exit.
  -V, --version         Show version.
  -l, --log LOG         Path to Apache/Nginx access log file (supports .gz archives)
  -f, --filters FILTERS Path to rule filters file (XML or JSON)
  -o, --output OUTPUT   Directory to write output files (default: current directory)
  -h, --html            Generate an HTML report
  -x, --xml             Generate an XML report
  -t, --text            Generate a plain text report
  --json                Generate a structured JSON report
  -a, --attack ATTACK   Comma-separated list of attack tags to detect (e.g. xss,sqli,lfi,ssrf,log4j,nosql,rce)
  -p, --period PERIOD   Timeframe to analyze (e.g. '04/Apr/2024:15:45;10/May/2024:23:59')
  -s, --sample SAMPLE   Percentage sample of lines to analyze (0.0 to 100.0, default: 100.0)
  -i, --ignore-ip IGNORE_IP
                        Comma-separated list of IP addresses to exclude
  -n, --ignore-subnet IGNORE_SUBNET
                        Comma-separated list of subnets/CIDR to exclude (e.g. 192.168.1.0/24)
  -e, --exhaustive      Report all matching attack types per line instead of stopping at first match
  -u, --tough           Enable deep payload anti-evasion decoding (enabled by default)
  -c, --except          Save non-parsed log lines into scalp_except.txt
  --modern              Also load modern attack rules (SSRF, Log4Shell, SSTI, Spring4Shell, Cloud Probes)
  --anathema            Enable the Anathema behavioral heuristic scoring module
```

### Attack Classes

| Flag | Attack class | Description |
|------|--------------|-------------|
| `xss` | Cross-site scripting | Injection of browser-executable scripts and HTML tags |
| `sqli` | SQL injection | SQL syntax manipulation, comment injection, boolean blind |
| `nosql` | NoSQL injection | MongoDB/CouchDB BSON operators (`$ne`, `$where`, `$regex`, `$gt`) |
| `pollution` | Prototype pollution | JavaScript property and prototype injection (`__proto__`) |
| `crlf` | CRLF injection | HTTP response splitting and header injection (`%0d%0a`) |
| `rce` / `cmd` | Remote code execution | Shell syntax (`() { :; };`, `$(...)`, command chaining `;`, `|`, `&`) |
| `csrf` | Cross-site request forgery | Unauthorized state-changing actions |
| `dos` | Denial of service | Heavy resource exhaustion patterns |
| `dt` | Directory traversal | Path traversal sequences (`../`, URL-encoded equivalents) |
| `spam` | Spam | Forum, guestbook, and form submission spam bots |
| `id` | Information disclosure | Source code leaks, server tokens, debug parameters |
| `rfe` / `ref` | Remote file execution | Code injection, remote inclusions, Log4j/JNDI lookups |
| `lfi` | Local file inclusion | Reading server configuration, shadow, and environment files |
| `ssrf` | Server-side request forgery | Accessing cloud metadata (AWS, GCP, Azure, Alibaba, Oracle) |
| `log4j` | Log4Shell | JNDI lookups (`${jndi:ldap://...}`) and evasion variations |
| `ssti` | Template injection | Jinja2, Twig, Spring EL, and Freemarker expression attacks |
| `spring` | Spring4Shell | ClassLoader exploitation and deserialization vectors |
| `probe` | Reconnaissance probes | Probes for `.env`, `.git`, Actuator endpoints, Swagger UI |

## 🧪 Testing

Run the test suite with pytest:

```bash
pytest
```

## 🧠 Anathema Heuristic Module

The `anathema/` package and `--anathema` CLI switch activate a behavioral heuristic layer (originally by Nanopony, modernized by DragonJAR) that scores requests beyond pure regex matching, tracking repeat offending IPs, web scanners, and probe patterns against a signature base.

## ⚠️ Limitations

1. **Apache does not log POST bodies by default** — attack detection is primarily request-line and query-based unless your log format captures request bodies.
2. **Regex-based detection** — highly custom or non-standard payloads may evade matching; payload normalizer runs automatically to decode nested encodings.
3. **Log format variations** — supports standard CLF, Combined, VHost Combined, and Nginx formats.

## 🏛️ History & Credits

This tool stands on the shoulders of others:

- **[Romain Gaucher](http://rgaucher.info)** — original author of Scalp! (2008), hosted at the original Google Code project.
- **[Nanopony](https://github.com/nanopony/apache-scalp)** — maintained and modernized the project: Python 3 rewrite, the Anathema heuristic module, and continued development after Google Code shut down.
- **[PHPIDS team](https://github.com/PHPIDS/PHPIDS)** — the `default_filter.xml` regular expressions powering the detection engine.
- **[DragonJAR SAS](https://www.DragonJAR.org)** — current maintenance: updated dependencies and filter file, documentation, and keeping the tool usable.

## 📄 License

Apache License 2.0 — inherited from the original project.

## 👨‍💻 Maintainer

**DragonJAR SAS** — [https://www.DragonJAR.org](https://www.DragonJAR.org)

[Experts in IT security services, proactive validation, and offensive security.](https://www.dragonjar.org/servicios-de-seguridad-informatica)

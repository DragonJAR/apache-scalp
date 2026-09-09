# Scalp! — Apache Log Attack Analyzer

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](#-license) [![Python](https://img.shields.io/badge/python-3-green.svg)](https://www.python.org) [![Upstream](https://img.shields.io/badge/upstream-nanopony%2Fapache--scalp-orange.svg)](https://github.com/nanopony/apache-scalp) [![Author](https://img.shields.io/badge/original%20author-Romain%20Gaucher-orange.svg)](http://rgaucher.info) [![Maintainer](https://img.shields.io/badge/maintained%20by-DragonJAR%20SAS-blue.svg)](https://www.DragonJAR.org) [![Español](https://img.shields.io/badge/leer%20en-Espa%C3%B1ol-blue.svg)](README.es.md)

> Scalp! is a log analyzer for the Apache web server that searches huge access logs for attack patterns sent through HTTP GET/POST requests, using the high-quality regular expressions of the [PHPIDS project](https://github.com/PHPIDS/PHPIDS).

This repository is a **modernization of [Nanopony's fork](https://github.com/nanopony/apache-scalp)** of the original Scalp! tool by Romain Gaucher. We only keep it alive: Python 3 compatibility, updated filter file, and maintenance fixes. All credit for the tool and its evolution belongs to the original authors.

## 🎯 What It Does

- Scans Apache and Nginx access logs line by line against the PHPIDS `default_filter.xml` regex rule set and modern JSON signatures.
- Supports **HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/3**, IPv4, and IPv6 traffic.
- Detects and classifies classic attacks: XSS, SQL injection, CSRF, DoS, directory traversal, spam, information disclosure, remote file execution (`rfe`/`ref`), and local file inclusion.
- Detects modern web attacks (`--modern`): SSRF (Cloud metadata AWS/GCP/Azure), Log4Shell/JNDI injection, SSTI, Spring4Shell, and sensitive file/API probes.
- Includes the integrated **Anathema** heuristic module (`--anathema`) for behavioral attack scoring and malicious IP tracking.
- Multi-pass anti-evasion decoder: recursive URL unquoting, HTML entity unescaping, and null-byte elimination.
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
| Apache / Nginx access log | Input data |
| `default_filter.xml` (bundled) | PHPIDS attack signatures |
| `scalp/rules/modern_rules.json` (bundled) | Modern attack signatures |

The filter file ships with this repository. If missing, Scalp! downloads it automatically from the [PHPIDS project](https://github.com/PHPIDS/PHPIDS/blob/master/lib/IDS/default_filter.xml).

## 🚀 Usage

```bash
python3 scalp/scalp.py -l /var/log/apache2/access.log -f default_filter.xml -o ./scalp-output --html --modern --anathema
```

```text
usage: scalp [--help] [-V] [-l LOG] [-f FILTERS] [-o OUTPUT] [-h] [-x] [-t]
             [--json] [-a ATTACK] [-p PERIOD] [-s SAMPLE] [-i IGNORE_IP]
             [-n IGNORE_SUBNET] [-e] [-u] [-c] [--modern] [--anathema]

Scalp! Apache/Nginx attack analyzer based on PHPIDS and modern signatures.

options:
  --help                Show this help message and exit.
  -V, --version         Show version.
  -l, --log LOG         Path to Apache/Nginx access log file (default: access_log)
  -f, --filters FILTERS Path to rule filters file (XML or JSON)
  -o, --output OUTPUT   Directory to write output files (default: current directory)
  -h, --html            Generate an HTML report
  -x, --xml             Generate an XML report
  -t, --text            Generate a plain text report
  --json                Generate a structured JSON report
  -a, --attack ATTACK   Comma-separated list of attack tags to detect (e.g. xss,sqli,lfi,ssrf,log4j)
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
| `csrf` | Cross-site request forgery | Unauthorized state-changing actions |
| `dos` | Denial of service | Heavy resource exhaustion patterns |
| `dt` | Directory traversal | Path traversal sequences (`../`, URL-encoded equivalents) |
| `spam` | Spam | Forum, guestbook, and form submission spam bots |
| `id` | Information disclosure | Source code leaks, server tokens, debug parameters |
| `rfe` / `ref` | Remote file execution | Code injection, remote inclusions, Log4j/JNDI lookups |
| `lfi` | Local file inclusion | Reading server configuration, shadow, and environment files |
| `ssrf` | Server-side request forgery | Accessing AWS/GCP/Azure metadata or private subnets |
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

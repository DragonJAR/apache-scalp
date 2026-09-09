# Scalp! — Apache Log Attack Analyzer

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](#-license) [![Python](https://img.shields.io/badge/python-3-green.svg)](https://www.python.org) [![Upstream](https://img.shields.io/badge/upstream-nanopony%2Fapache--scalp-orange.svg)](https://github.com/nanopony/apache-scalp) [![Author](https://img.shields.io/badge/original%20author-Romain%20Gaucher-orange.svg)](http://rgaucher.info) [![Maintainer](https://img.shields.io/badge/maintained%20by-DragonJAR%20SAS-blue.svg)](https://www.DragonJAR.org) [![Español](https://img.shields.io/badge/leer%20en-Espa%C3%B1ol-blue.svg)](README.es.md)

> Scalp! is a log analyzer for the Apache web server that searches huge access logs for attack patterns sent through HTTP GET/POST requests, using the high-quality regular expressions of the [PHPIDS project](https://github.com/PHPIDS/PHPIDS).

This repository is a **modernization of [Nanopony's fork](https://github.com/nanopony/apache-scalp)** of the original Scalp! tool by Romain Gaucher. We only keep it alive: Python 3 compatibility, updated filter file, and maintenance fixes. All credit for the tool and its evolution belongs to the original authors.

## 🎯 What It Does

- Scans Apache access logs line by line and matches them against the PHPIDS `default_filter.xml` regex rule set.
- Detects and classifies attacks: XSS, SQL injection, CSRF, DoS, directory traversal, spam, information disclosure, remote file reference, and local file inclusion.
- Reports matches per rule with impact score, description, and tags.
- Includes the **Anathema** heuristic module (by Nanopony) for behavioral attack scoring.
- Outputs results in TEXT, XML, or HTML.

## 📦 Installation

```bash
git clone https://github.com/DragonJAR/apache-scalp
cd apache-scalp
pip install -r requirements.txt
```

## ⚙️ Prerequisites

| Tool | Purpose |
|------|---------|
| Python 3 | Runtime |
| `regex` (see `requirements.txt`) | Advanced regular expression engine |
| Apache access log | Input data |
| `default_filter.xml` (bundled) | PHPIDS attack signatures |

The filter file ships with this repository. If missing, Scalp! downloads it automatically from the [PHPIDS project](https://github.com/PHPIDS/PHPIDS/blob/master/lib/IDS/default_filter.xml).

## 🚀 Usage

```bash
python3 scalp/scalp.py -l /var/log/apache2/access.log -f default_filter.xml -o ./scalp-output --html
```

```text
Scalp the apache log! by Romain Gaucher
usage:  ./scalp.py [--log|-l log_file] [--filters|-f filter_file] [--period time-frame] [OPTIONS] [--attack a1,a2,..,an]
                   [--sample|-s 4.2]
   --log       |-l:  the apache log file './access_log' by default
   --filters   |-f:  the filter file     './default_filter.xml' by default
   --exhaustive|-e:  will report all type of attacks detected and not stop at the first found
   --tough     |-u:  try to decode the potential attack vectors (may increase the examination time)
   --period    |-p:  the period must be specified in the same format as in the Apache logs using * as wild-card
                     ex: 04/Apr/2008:15:45;*/Mai/2008
   --html      |-h:  generate an HTML output
   --xml       |-x:  generate an XML output
   --text      |-t:  generate a simple text output (default)
   --except    |-c:  generate a file that contains the non examined logs due to the main regular
                     expression; ill-formed Apache log etc.
   --attack    |-a:  specify the list of attacks to look for
                     list: xss, sqli, csrf, dos, dt, spam, id, ref, lfi
                     ex: xss,sqli,lfi,ref
   --ignore-ip|-i:  specify the list of IP Addresses to exclude (comma separated)
   --ignore-subnet|-n:  specify the list of Subnets to exclude (comma separated)
   --output    |-o:  specifying the output directory; by default, scalp will try to write in the
                     same directory as the log file
   --sample    |-s:  use a random sample of the lines, the number (float in [0,100]) is the
                     percentage, ex: --sample 0.1 for 1/1000
```

### Attack Classes

| Flag | Attack class |
|------|--------------|
| `xss` | Cross-site scripting |
| `sqli` | SQL injection |
| `csrf` | Cross-site request forgery |
| `dos` | Denial of service |
| `dt` | Directory traversal |
| `spam` | Spam |
| `id` | Information disclosure |
| `ref` | Remote file reference |
| `lfi` | Local file inclusion |

## 🧠 Anathema Heuristic Module

The `anathema/` package adds a heuristic layer (by Nanopony) that scores requests beyond pure regex matching, analyzing IP, method, URL, and user-agent patterns against a JSON signature base.

## ⚠️ Limitations

1. **Apache does not log POST bodies by default** — attack detection is primarily GET-based unless your log format captures request bodies.
2. **Regex-based detection** — sophisticated or obfuscated payloads may evade matching; use `--tough` to decode encoded vectors.
3. **Legacy codebase** — the tool originates from 2008 (Python 2 era); this fork patches Python 3 compatibility but the engine remains simple by design.
4. **Log format assumptions** — non-standard Apache log formats may not parse correctly.

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

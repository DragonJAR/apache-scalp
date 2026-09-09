"""Command Line Interface for Scalp! Log Analyzer.
Provides full backwards compatibility with classic flags while adding modern options.
"""
import argparse
from datetime import datetime
import os
from pathlib import Path
import sys
import time
from typing import List

from scalp.core.engine import ScalpEngine
from scalp.core.exclusions import DateRangeFilter, NetworkFilter
from scalp.core.models import FilterRule
from scalp.core.rules import RuleLoader
from scalp.heuristics.anathema import AnathemaAnalyzer
from scalp.reporters.html import HtmlReporter
from scalp.reporters.json_rep import JsonReporter
from scalp.reporters.text import TextReporter
from scalp.reporters.xml import XmlReporter

__version__ = "1.0.0"
DEFAULT_FILTER_XML = Path(__file__).parent.parent / "default_filter.xml"
MODERN_RULES_JSON = Path(__file__).parent / "rules" / "modern_rules.json"


def build_parser() -> argparse.ArgumentParser:
    # Disable default -h for help so -h can remain classic --html
    parser = argparse.ArgumentParser(
        prog="scalp",
        description="Scalp! Apache/Nginx attack analyzer based on PHPIDS and modern signatures.",
        add_help=False,
    )

    # Help and Version
    parser.add_argument("--help", action="help", help="Show this help message and exit.")
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}", help="Show version."
    )

    # Core inputs
    parser.add_argument(
        "-l", "--log", default="access_log", help="Path to Apache/Nginx access log file (default: access_log)"
    )
    parser.add_argument(
        "-f",
        "--filters",
        default=str(DEFAULT_FILTER_XML if DEFAULT_FILTER_XML.is_file() else "default_filter.xml"),
        help="Path to rule filters file (XML or JSON)",
    )
    parser.add_argument(
        "-o", "--output", default=".", help="Directory to write output files (default: current directory)"
    )

    # Output format switches
    parser.add_argument("-h", "--html", action="store_true", help="Generate an HTML report")
    parser.add_argument("-x", "--xml", action="store_true", help="Generate an XML report")
    parser.add_argument("-t", "--text", action="store_true", help="Generate a plain text report")
    parser.add_argument("--json", action="store_true", help="Generate a structured JSON report")

    # Filtering options
    parser.add_argument(
        "-a",
        "--attack",
        default=None,
        help="Comma-separated list of attack tags to detect (e.g. xss,sqli,lfi,ssrf,log4j)",
    )
    parser.add_argument(
        "-p",
        "--period",
        default=None,
        help="Timeframe to analyze (e.g. '04/Apr/2024:15:45;10/May/2024:23:59')",
    )
    parser.add_argument(
        "-s",
        "--sample",
        type=float,
        default=100.0,
        help="Percentage sample of lines to analyze (0.0 to 100.0, default: 100.0)",
    )
    parser.add_argument(
        "-i",
        "--ignore-ip",
        default=None,
        help="Comma-separated list of IP addresses to exclude",
    )
    parser.add_argument(
        "-n",
        "--ignore-subnet",
        default=None,
        help="Comma-separated list of subnets/CIDR to exclude (e.g. 192.168.1.0/24)",
    )

    # Engine tuning
    parser.add_argument(
        "-e",
        "--exhaustive",
        action="store_true",
        help="Report all matching attack types per line instead of stopping at first match",
    )
    parser.add_argument(
        "-u",
        "--tough",
        action="store_true",
        default=True,
        help="Enable deep payload anti-evasion decoding (enabled by default in modern Scalp)",
    )
    parser.add_argument(
        "-c",
        "--except",
        dest="save_unparsed",
        action="store_true",
        help="Save non-parsed log lines into scalp_except.txt",
    )

    # Modern capabilities
    parser.add_argument(
        "--modern",
        action="store_true",
        help="Also load modern attack rules (SSRF, Log4Shell, SSTI, Spring4Shell, Cloud Probes)",
    )
    parser.add_argument(
        "--anathema",
        action="store_true",
        help="Enable the Anathema behavioral heuristic scoring module",
    )

    return parser


def main(argv: list = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    log_path = Path(args.log)
    if not log_path.is_file():
        print(f"error: the log file '{args.log}' doesn't exist")
        return 1

    # Load primary filters
    filter_path = Path(args.filters)
    if not filter_path.is_file():
        # Fallback check relative to current dir or package dir
        if DEFAULT_FILTER_XML.is_file():
            filter_path = DEFAULT_FILTER_XML
        else:
            print(f"error: the filters file '{args.filters}' doesn't exist")
            return 1

    rules: List[FilterRule] = []
    print(f"Loading rules file '{filter_path}'...")
    if filter_path.suffix.lower() == ".json":
        rules.extend(RuleLoader.load_json(filter_path))
    else:
        rules.extend(RuleLoader.load_xml(filter_path))

    # Load modern rules if requested or if modern_rules.json exists
    if args.modern and MODERN_RULES_JSON.is_file():
        print(f"Loading modern attack signatures '{MODERN_RULES_JSON}'...")
        rules.extend(RuleLoader.load_json(MODERN_RULES_JSON))

    # Output directory
    odir = Path(args.output)
    odir.mkdir(parents=True, exist_ok=True)

    # Exclusions
    excluded_ips = args.ignore_ip.split(",") if args.ignore_ip else []
    excluded_subnets = args.ignore_subnet.split(",") if args.ignore_subnet else []
    network_filter = NetworkFilter(excluded_ips=excluded_ips, excluded_subnets=excluded_subnets)

    # Date period
    date_filter = DateRangeFilter.from_cli_period(args.period) if args.period else None

    # Tag filtering
    attack_tags = None
    if args.attack:
        raw_tags = [t.strip() for t in args.attack.split(",") if t.strip()]
        attack_tags = {RuleLoader.normalize_tag(t) for t in raw_tags}

    # Anathema heuristic
    anathema = AnathemaAnalyzer() if args.anathema else None

    print(f"Processing the file '{args.log}'...")
    engine = ScalpEngine(
        rules=rules,
        attack_types=attack_tags,
        date_filter=date_filter,
        network_filter=network_filter,
        anathema=anathema,
        exhaustive=args.exhaustive,
        normalize_payloads=True,
        sample_pct=args.sample,
    )

    result = engine.scan_file(str(log_path))

    print("Scalp results:")
    print(f"\tProcessed {result.processed_lines} lines over {result.total_lines}")
    print(f"\tFound {len(result.matches)} attack patterns in {result.elapsed_seconds:.4f} s")

    # Format selection (default to text if none specified)
    if not (args.html or args.xml or args.text or args.json):
        args.text = True

    short_name = log_path.name
    curdate = time.strftime("%Y%m%d_%H%M%S", time.localtime())

    if len(result.matches) > 0 or not (args.html or args.xml or args.json):
        print(f"Generating output in {odir}/")
        if args.text:
            out_file = odir / f"{short_name}_scalp_{curdate}.txt"
            TextReporter.generate(result, str(out_file), source_name=short_name)
            print(f"\tWritten text report to: {out_file}")
        if args.html:
            out_file = odir / f"{short_name}_scalp_{curdate}.html"
            HtmlReporter.generate(result, str(out_file), source_name=short_name)
            print(f"\tWritten HTML report to: {out_file}")
        if args.xml:
            out_file = odir / f"{short_name}_scalp_{curdate}.xml"
            XmlReporter.generate(result, str(out_file), source_name=short_name)
            print(f"\tWritten XML report to: {out_file}")
        if args.json:
            out_file = odir / f"{short_name}_scalp_{curdate}.json"
            JsonReporter.generate(result, str(out_file), source_name=short_name)
            print(f"\tWritten JSON report to: {out_file}")

    if args.save_unparsed and len(result.unmatched_lines) > 0:
        except_file = odir / "scalp_except.txt"
        with open(except_file, "w", encoding="utf-8") as ef:
            for l in result.unmatched_lines:
                ef.write(l + "\n")
        print(f"\tWritten {len(result.unmatched_lines)} unparsed lines to {except_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

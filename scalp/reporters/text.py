"""Plain text reporter for Scalp."""
import time
from scalp.core.engine import ScanResult
from scalp.core.rules import ATTACK_NAMES
from scalp.reporters.base import BaseReporter

TXT_HEADER = """#
# File created by Scalp! (Modernized Edition)
# Web log attack analyzer based on PHPIDS and modern signatures
#
"""


class TextReporter(BaseReporter):
    @classmethod
    def generate(cls, result: ScanResult, output_path: str, source_name: str = "") -> None:
        curtime = time.strftime("%a-%d-%b-%Y %H:%M:%S", time.localtime())

        # Group matches: tag -> impact -> list of matches
        grouped = {}
        for match in result.matches:
            tag = match.tag
            impact = match.rule.impact
            if tag not in grouped:
                grouped[tag] = {}
            if impact not in grouped[tag]:
                grouped[tag][impact] = []
            grouped[tag][impact].append(match)

        with open(output_path, "w", encoding="utf-8") as out:
            out.write(TXT_HEADER)
            out.write(f"Analyzed log: {source_name or 'N/A'}\n")
            out.write(f"Creation date: {curtime}\n")
            out.write(f"Total lines processed: {result.processed_lines} / {result.total_lines}\n")
            out.write(f"Total attack matches: {len(result.matches)} (in {result.elapsed_seconds:.3f}s)\n\n")

            if not grouped:
                out.write("No attack patterns detected. The analyzed log is clean.\n")

            for tag, impacts_dict in grouped.items():
                tag_name = ATTACK_NAMES.get(tag.lower(), tag.upper())
                out.write(f"Attack: {tag_name} ({tag})\n")
                out.write("=" * 60 + "\n")

                for impact in sorted(impacts_dict.keys(), reverse=True):
                    matches_list = impacts_dict[impact]
                    out.write(f"\n  ### Impact {impact} ({len(matches_list)} hits)\n")
                    for m in matches_list:
                        vector = getattr(m, "matched_field", "url")
                        out.write(f"    - IP: {m.entry.ip} | Method: {m.entry.method} | URL: {m.entry.url}\n")
                        out.write(f"      Rule [{m.rule.rule_id}]: \"{m.rule.description}\"\n")
                        out.write(f"      Vector: {vector} | Matched Token: {m.matched_string}\n")
                        out.write(f"      Raw Line: {m.entry.raw_line}\n\n")

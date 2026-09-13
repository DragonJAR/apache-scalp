from collections import defaultdict
import time
from xml.sax.saxutils import escape
from scalp.core.engine import ScanResult
from scalp.core.rules import ATTACK_NAMES
from scalp.reporters.base import BaseReporter

XML_HEADER = """<?xml version="1.0" encoding="utf-8"?>
<!--
 File created by Scalp! (Modernized Edition)
 Web log attack analysis tool based on PHPIDS and modern signatures
-->
"""


class XmlReporter(BaseReporter):
    @classmethod
    def generate(cls, result: ScanResult, output_path: str, source_name: str = "") -> None:
        curtime = time.strftime("%a-%d-%b-%Y %H:%M:%S", time.localtime())

        # Group matches: tag -> impact -> list of matches
        grouped = defaultdict(lambda: defaultdict(list))
        for match in result.matches:
            grouped[match.tag][match.rule.impact].append(match)

        lines = [
            XML_HEADER,
            f'<scalp file="{escape(source_name or "access.log")}" time="{curtime}">',
        ]

        for tag, impacts_dict in grouped.items():
            tag_name = ATTACK_NAMES.get(tag.lower(), tag.upper())
            lines.append(f'  <attack type="{escape(tag)}" name="{escape(tag_name)}">')

            # FIX: In Python 3, impacts_dict.keys() is a view; convert to sorted list
            for impact in sorted(impacts_dict.keys(), reverse=True):
                lines.append(f'    <impact value="{impact}">')
                for m in impacts_dict[impact]:
                    desc = m.rule.description.replace("]]>", "]]&gt;")
                    pat = m.rule.pattern.replace("]]>", "]]&gt;")
                    raw = m.entry.raw_line.replace("]]>", "]]&gt;")
                    lines.append("      <item>")
                    lines.append(f"        <reason><![CDATA[{desc}]]></reason>")
                    lines.append(f"        <regexp><![CDATA[{pat}]]></regexp>")
                    lines.append(f"        <line><![CDATA[{raw}]]></line>")
                    lines.append("      </item>")
                lines.append("    </impact>")

            lines.append("  </attack>")

        lines.append("</scalp>\n")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

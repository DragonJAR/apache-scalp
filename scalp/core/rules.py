"""Rule loaders for PHPIDS XML format and modern JSON formats."""
import json
from pathlib import Path
from typing import List, Set, Union
import xml.etree.ElementTree as ET
from scalp.core.models import FilterRule

# Normalize aliases so both 'ref' (CLI/docs) and 'rfe' (PHPIDS XML tag) work seamlessly
TAG_ALIASES = {
    "ref": "rfe",
}

ATTACK_NAMES = {
    "xss": "Cross-Site Scripting",
    "sqli": "SQL Injection",
    "csrf": "Cross-Site Request Forgery",
    "dos": "Denial Of Service",
    "dt": "Directory Traversal",
    "spam": "Spam",
    "id": "Information Disclosure",
    "rfe": "Remote File Execution",
    "lfi": "Local File Inclusion",
    "ssrf": "Server-Side Request Forgery",
    "log4j": "Log4Shell / JNDI Injection",
    "ssti": "Server-Side Template Injection",
    "deserialization": "Insecure Deserialization",
    "probe": "Scanner / Sensitive File Probe",
}


class RuleLoader:
    """Parses and normalizes attack signatures from XML and JSON rule repositories."""

    @staticmethod
    def normalize_tag(tag: str) -> str:
        """Normalizes a rule tag string to lowercase, stripped, and maps known aliases."""
        clean = tag.strip().lower()
        return TAG_ALIASES.get(clean, clean)

    @classmethod
    def load_xml(cls, filepath: Union[str, Path]) -> List[FilterRule]:
        """Loads classic PHPIDS XML filter files (e.g. default_filter.xml)."""
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Filter XML file not found: {filepath}")

        tree = ET.parse(str(path))
        root = tree.getroot()
        rules: List[FilterRule] = []

        # Find all <filter> elements regardless of hierarchy
        for filter_node in root.findall(".//filter"):
            rule_id = (filter_node.findtext("id") or "").strip()
            rule_text = (filter_node.findtext("rule") or "").strip()
            description = (filter_node.findtext("description") or "").strip()

            raw_impact = (filter_node.findtext("impact") or "0").strip()
            try:
                impact = int(raw_impact)
            except ValueError:
                impact = 0

            tags: Set[str] = set()
            for tag_elem in filter_node.findall(".//tag"):
                if tag_elem.text:
                    tags.add(cls.normalize_tag(tag_elem.text))

            if not tags:
                tags = {"general"}

            if rule_text:
                rules.append(
                    FilterRule(
                        rule_id=rule_id,
                        pattern=rule_text,
                        description=description,
                        impact=impact,
                        tags=tags,
                    )
                )

        return rules

    @classmethod
    def load_json(cls, filepath: Union[str, Path]) -> List[FilterRule]:
        """Loads modern JSON rule definitions."""
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Rules JSON file not found: {filepath}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        rules: List[FilterRule] = []
        for item in data.get("rules", []):
            tags = {cls.normalize_tag(t) for t in item.get("tags", [])}
            if not tags:
                tags = {"general"}
            rules.append(
                FilterRule(
                    rule_id=str(item.get("id", "")),
                    pattern=item.get("pattern", ""),
                    description=item.get("description", ""),
                    impact=int(item.get("impact", 0)),
                    tags=tags,
                )
            )

        return rules

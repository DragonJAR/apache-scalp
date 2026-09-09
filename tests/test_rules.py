from pathlib import Path
import pytest
from scalp.core.rules import RuleLoader

def test_load_bundled_default_filter_xml():
    xml_path = Path("default_filter.xml")
    assert xml_path.exists()
    rules = RuleLoader.load_xml(str(xml_path))
    assert len(rules) == 74
    # Ensure all rules have an id, pattern, and at least one tag
    for r in rules:
        assert r.rule_id != ""
        assert r.pattern != ""
        assert len(r.tags) > 0
        assert r.impact >= 0

def test_load_single_filter_xml(tmp_path):
    single_xml = r"""<?xml version="1.0"?>
    <filters>
        <filter>
            <id>42</id>
            <rule><![CDATA[(?:union\s+select)]]></rule>
            <description>Simple SQLi</description>
            <tags><tag>sqli</tag></tags>
            <impact>9</impact>
        </filter>
    </filters>
    """
    fpath = tmp_path / "single.xml"
    fpath.write_text(single_xml, encoding="utf-8")

    rules = RuleLoader.load_xml(str(fpath))
    assert len(rules) == 1
    assert rules[0].rule_id == "42"
    assert rules[0].description == "Simple SQLi"
    assert "sqli" in rules[0].tags
    assert rules[0].impact == 9

def test_tag_alias_normalization():
    assert RuleLoader.normalize_tag("ref") == "rfe"
    assert RuleLoader.normalize_tag("RFE") == "rfe"
    assert RuleLoader.normalize_tag("  XSS  ") == "xss"
    assert RuleLoader.normalize_tag("sqli") == "sqli"

def test_load_json_rules(tmp_path):
    json_content = r"""{
        "rules": [
            {
                "id": "ssrf_1",
                "pattern": "(?:169\\.254\\.169\\.254)",
                "description": "AWS Metadata SSRF",
                "impact": 10,
                "tags": ["ssrf", "cloud"]
            }
        ]
    }"""
    fpath = tmp_path / "rules.json"
    fpath.write_text(json_content, encoding="utf-8")

    rules = RuleLoader.load_json(str(fpath))
    assert len(rules) == 1
    assert rules[0].rule_id == "ssrf_1"
    assert "ssrf" in rules[0].tags
    assert rules[0].impact == 10

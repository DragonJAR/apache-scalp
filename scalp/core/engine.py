"""Core scanning and analysis engine for Scalp."""
from dataclasses import dataclass, field
import random
import time
from typing import List, Optional, Set, Tuple
import regex as re
from scalp.core.exclusions import DateRangeFilter, NetworkFilter
from scalp.core.models import AttackMatch, FilterRule
from scalp.core.normalizer import PayloadNormalizer
from scalp.core.parser import LogParser
from scalp.heuristics.anathema import AnathemaAnalyzer


@dataclass
class ScanResult:
    """Aggregated results of a log scan."""
    total_lines: int = 0
    processed_lines: int = 0
    matches: List[AttackMatch] = field(default_factory=list)
    unmatched_lines: List[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0


class ScalpEngine:
    """Core log processing engine. Evaluates log entries against compiled attack rules
    and heuristic behavioral analyzers."""

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
        self.attack_types = {t.lower() for t in attack_types} if attack_types else None
        self.date_filter = date_filter or DateRangeFilter()
        self.network_filter = network_filter or NetworkFilter()
        self.anathema = anathema
        self.exhaustive = exhaustive
        self.normalize_payloads = normalize_payloads
        self.sample_pct = sample_pct

        # Pre-compile applicable rules
        self._compiled_rules: List[Tuple[FilterRule, re.Pattern]] = []
        for r in self.rules:
            # If tag filter is specified, only include rules that match at least one requested tag
            if self.attack_types and not any(t.lower() in self.attack_types for t in r.tags):
                continue
            try:
                compiled = re.compile(r.pattern, re.IGNORECASE)
                self._compiled_rules.append((r, compiled))
            except Exception:
                # Malformed regex in rule set skipped gracefully
                pass

        # Sort compiled rules by impact descending so highest-severity rules match first
        self._compiled_rules.sort(key=lambda item: item[0].impact, reverse=True)

    def scan_file(self, filepath: str) -> ScanResult:
        """Processes a log file in a single pass with O(1) memory footprint."""
        start_time = time.time()
        result = ScanResult()

        for _, entry, raw_line in LogParser.stream_file(filepath):
            result.total_lines += 1

            # Sample filter if percentage < 100
            if self.sample_pct < 100.0 and random.uniform(0.0, 100.0) > self.sample_pct:
                continue

            if not entry:
                stripped_raw = raw_line.strip()
                if stripped_raw and not stripped_raw.startswith("#"):
                    result.unmatched_lines.append(raw_line)
                continue

            # IP / Subnet exclusion
            if self.network_filter.is_excluded(entry.ip):
                continue

            # Date range filter
            if not self.date_filter.is_valid(entry.timestamp):
                continue

            result.processed_lines += 1

            # Multi-vector inspection (URL, User-Agent, Referrer)
            targets = [
                (
                    "url",
                    PayloadNormalizer.normalize(entry.url)
                    if self.normalize_payloads
                    else entry.url,
                )
            ]
            if entry.user_agent:
                targets.append(
                    (
                        "user_agent",
                        PayloadNormalizer.normalize(entry.user_agent)
                        if self.normalize_payloads
                        else entry.user_agent,
                    )
                )
            if entry.referrer:
                targets.append(
                    (
                        "referrer",
                        PayloadNormalizer.normalize(entry.referrer)
                        if self.normalize_payloads
                        else entry.referrer,
                    )
                )

            # Match rules against target fields
            line_matched = False
            for field_name, search_target in targets:
                for rule, compiled in self._compiled_rules:
                    m = compiled.search(search_target)
                    if m:
                        line_matched = True
                        effective_tags = rule.tags or {"general"}
                        for tag in effective_tags:
                            if not self.attack_types or tag.lower() in self.attack_types:
                                result.matches.append(
                                    AttackMatch(
                                        entry=entry,
                                        rule=rule,
                                        matched_string=m.group(0),
                                        tag=tag,
                                        matched_field=field_name,
                                    )
                                )
                        if not self.exhaustive:
                            break
                if line_matched and not self.exhaustive:
                    break

            # Anathema behavioral evaluation
            if self.anathema:
                self.anathema.score_entry(entry)

        result.elapsed_seconds = time.time() - start_time
        return result

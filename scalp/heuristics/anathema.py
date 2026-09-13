"""Anathema Heuristic Engine: behavioral attack scoring and violator tracking."""
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import regex as re
from scalp.core.models import LogEntry

DEFAULT_SIGNATURES_PATH = Path(__file__).parent / "signatures.json"


class AnathemaAnalyzer:
    """Analyzes request traffic patterns against heuristic signatures to track
    suspicious behavior, scanners, and malicious IPs."""

    def __init__(self, signatures_path: Optional[Path] = None):
        path = signatures_path or DEFAULT_SIGNATURES_PATH
        if not path.is_file():
            raise FileNotFoundError(f"Heuristic signatures file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.signatures = data.get("signatures", [])
        self._compiled: List[Tuple[re.Pattern, int, List[str]]] = []

        for s in self.signatures:
            pattern = re.compile(s["q"], re.IGNORECASE)
            severity = int(s.get("s", 5))
            tags = s.get("tags", ["scan"])
            self._compiled.append((pattern, severity, tags))

        # violator IP -> list of matching LogEntry records
        self.violators: Dict[str, List[LogEntry]] = {}
        # Banned IPs (severity >= 10)
        self.banned_ips: Set[str] = set()

    def score_entry(self, entry: LogEntry) -> int:
        """Evaluates a LogEntry and returns its heuristic threat score (0 to 10).
        If an IP is already banned, automatically assigns max threat score 10."""
        if entry.ip in self.banned_ips:
            self.violators.setdefault(entry.ip, []).append(entry)
            return 10

        highest_score = 0
        for pattern, severity, _ in self._compiled:
            target = entry.url
            if pattern.search(target) or (entry.user_agent and pattern.search(entry.user_agent)):
                if severity > highest_score:
                    highest_score = severity

        if highest_score > 0:
            self.violators.setdefault(entry.ip, []).append(entry)
            if highest_score >= 10:
                self.banned_ips.add(entry.ip)

        return highest_score

    def is_violator(self, ip: str) -> bool:
        """Returns True if the given IP address has triggered heuristic violations."""
        return ip in self.violators

"""Data models for log entries, filter rules, and attack matches."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Set


@dataclass(frozen=True, slots=True)
class LogEntry:
    ip: str
    raw_line: str
    timestamp: Optional[datetime]
    method: str
    url: str
    protocol: str
    status_code: int
    bytes_sent: Optional[int] = None
    referrer: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass(frozen=True, slots=True)
class FilterRule:
    rule_id: str
    pattern: str
    description: str
    impact: int
    tags: Set[str] = field(default_factory=set)


@dataclass(slots=True)
class AttackMatch:
    entry: LogEntry
    rule: FilterRule
    matched_string: str
    tag: str
    matched_field: str = "url"

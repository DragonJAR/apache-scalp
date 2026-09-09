"""High-performance, robust log parser for Apache, Nginx, and web server access logs."""
from datetime import datetime
from typing import Generator, Optional, Tuple
import regex as re
from scalp.core.models import LogEntry

# Regex matching Common Log Format (CLF), Combined Log Format, and VHost Combined
LOG_LINE_REGEX = re.compile(
    r'^(?:(?P<vhost>\S+)\s+)?'                          # Optional vhost prefix
    r'(?P<ip>(?!-+\s)\[?[0-9a-zA-Z\.\:\-_]+\]?(?::\d+)?)\s+'  # Client IP (IPv4, IPv6, hostname, optional port)
    r'\S+\s+'                                           # Ident / remote logname
    r'(?P<user>\S+)\s+'                                 # Remote user
    r'\[(?P<time>[^\]]+)\]\s+'                          # [dd/Mon/yyyy:hh:mm:ss ±zzzz]
    r'"(?P<method>[A-Z]+)\s+'                           # Request method (GET, POST, etc.)
    r'(?P<url>.+?)'                                     # Request URL (clean or with spaces)
    r'(?:\s+(?P<proto>HTTP\/[\d\.]+))?"\s+'             # Protocol (HTTP/1.0, 1.1, 2, 2.0, 3)
    r'(?P<status>\d{3})\s+'                             # HTTP status code
    r'(?P<bytes>\d+|-)'                                 # Response bytes ('-' for none/304)
    r'(?:\s+"(?P<referrer>(?:[^"\\]|\\.)*)"\s+"(?P<agent>(?:[^"\\]|\\.)*)")?' # Optional Referrer & User-Agent
)


class LogParser:
    """Parses Apache and Nginx access logs safely and efficiently."""

    @staticmethod
    def parse_timestamp(ts_str: str) -> Optional[datetime]:
        """Parses Apache format timestamp '10/Oct/2024:13:55:36 -0700'."""
        try:
            return datetime.strptime(ts_str.strip(), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                # Fallback without timezone
                clean_ts = ts_str.strip().split()[0]
                return datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                return None

    @classmethod
    def parse_line(cls, line: str) -> Optional[LogEntry]:
        """Parses a single log line into a LogEntry dataclass, or returns None if malformed."""
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return None

        match = LOG_LINE_REGEX.match(stripped)
        if not match:
            return None

        data = match.groupdict()

        raw_bytes = data.get("bytes")
        bytes_sent = int(raw_bytes) if raw_bytes and raw_bytes != "-" else None

        referrer = data.get("referrer")
        if referrer == "-" or referrer == "":
            referrer = None
        elif referrer:
            referrer = referrer.replace(r'\"', '"')

        agent = data.get("agent")
        if agent == "-" or agent == "":
            agent = None
        elif agent:
            agent = agent.replace(r'\"', '"')

        proto = data.get("proto") or "HTTP/1.1"

        return LogEntry(
            ip=data["ip"],
            raw_line=line.rstrip("\r\n"),
            timestamp=cls.parse_timestamp(data["time"]),
            method=data["method"],
            url=data["url"],
            protocol=proto,
            status_code=int(data["status"]),
            bytes_sent=bytes_sent,
            referrer=referrer,
            user_agent=agent,
        )

    @classmethod
    def stream_file(
        cls, filepath: str
    ) -> Generator[Tuple[int, Optional[LogEntry], str], None, None]:
        """Streams a log file yielding (line_number, parsed_entry, raw_line).
        Uses errors='replace' to avoid terminating on invalid UTF-8 bytes."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line_no, raw_line in enumerate(f, start=1):
                entry = cls.parse_line(raw_line)
                yield line_no, entry, raw_line

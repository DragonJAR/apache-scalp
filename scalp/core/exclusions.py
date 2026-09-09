"""Filtering mechanisms for date ranges and network/IP exclusions."""
import calendar
from datetime import datetime
import ipaddress
from typing import Iterable, List, Optional, Set, Union


MONTH_NAMES = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


class DateRangeFilter:
    """Filters log entries based on start and end datetime bounds."""

    def __init__(self, start: Optional[datetime] = None, end: Optional[datetime] = None):
        self.start = start
        self.end = end

    def is_valid(self, dt: Optional[datetime]) -> bool:
        """Returns True if dt falls within [start, end]. None datetimes pass by default."""
        if dt is None:
            return True

        # If one is timezone-aware and the other is naive, normalize comparison
        if self.start:
            target_start = self.start
            if dt.tzinfo is None and target_start.tzinfo is not None:
                target_start = target_start.replace(tzinfo=None)
            elif dt.tzinfo is not None and target_start.tzinfo is None:
                dt = dt.replace(tzinfo=None)
            if dt < target_start:
                return False

        if self.end:
            target_end = self.end
            if dt.tzinfo is None and target_end.tzinfo is not None:
                target_end = target_end.replace(tzinfo=None)
            elif dt.tzinfo is not None and target_end.tzinfo is None:
                dt = dt.replace(tzinfo=None)
            if dt > target_end:
                return False

        return True

    @classmethod
    def parse_endpoint(cls, s: str, is_end: bool = False) -> Optional[datetime]:
        """Parses an Apache-like timestamp endpoint e.g. 04/Apr/2024:15:45."""
        clean = s.strip()
        if not clean or clean == "*":
            return None

        # Replace colons and slashes
        parts = clean.replace(":", "/").split("/")
        if len(parts) < 3:
            return None

        try:
            month_str = parts[1].lower()[:3]
            month = MONTH_NAMES.get(month_str, int(parts[1]) if parts[1].isdigit() else 1)
            year = int(parts[2]) if parts[2] != "*" else (9999 if is_end else 1)

            if parts[0] != "*":
                day = int(parts[0])
            elif is_end:
                # Use actual days in month for the specified year (e.g. 28/29 for Feb)
                valid_year = year if 1 <= year <= 9999 else 2024
                day = calendar.monthrange(valid_year, month)[1]
            else:
                day = 1

            hour = int(parts[3]) if len(parts) > 3 and parts[3] != "*" else (23 if is_end else 0)
            minute = int(parts[4]) if len(parts) > 4 and parts[4] != "*" else (59 if is_end else 0)
            second = int(parts[5]) if len(parts) > 5 and parts[5] != "*" else (59 if is_end else 0)

            return datetime(year, month, day, hour, minute, second)
        except Exception:
            return None

    @classmethod
    def from_cli_period(cls, period_str: str) -> "DateRangeFilter":
        """Parses 'start;end' period format e.g. '04/Apr/2024:15:45;10/May/2024:23:59'."""
        if not period_str or ";" not in period_str:
            return cls()

        start_str, end_str = period_str.split(";", 1)
        start_dt = cls.parse_endpoint(start_str, is_end=False)
        end_dt = cls.parse_endpoint(end_str, is_end=True)
        return cls(start=start_dt, end=end_dt)


def clean_ip_string(ip_str: str) -> str:
    """Strips brackets, ports, and whitespace from IPv4, IPv6, and host strings."""
    s = ip_str.strip()
    if not s:
        return ""
    if s.startswith("["):
        end_idx = s.find("]")
        if end_idx != -1:
            return s[1:end_idx].strip()
    elif s.count(":") == 1:
        return s.split(":", 1)[0].strip()
    return s


class NetworkFilter:
    """Filters IPs based on exact IP addresses, CIDR network blocks, or hostnames."""

    def __init__(
        self,
        excluded_ips: Optional[Iterable[str]] = None,
        excluded_subnets: Optional[Iterable[str]] = None,
    ):
        self._ips: Set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
        self._subnets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self._hostnames: Set[str] = set()

        for ip_s in (excluded_ips or []):
            clean = clean_ip_string(ip_s)
            if clean:
                try:
                    self._ips.add(ipaddress.ip_address(clean))
                except ValueError:
                    self._hostnames.add(clean.lower())

        for subnet_s in (excluded_subnets or []):
            clean = subnet_s.strip()
            if clean:
                try:
                    self._subnets.append(ipaddress.ip_network(clean, strict=False))
                except ValueError:
                    pass

    def is_excluded(self, ip_str: str) -> bool:
        """Returns True if the given IP is explicitly excluded or falls inside an excluded subnet."""
        clean = clean_ip_string(ip_str)
        if not clean:
            return False

        if clean.lower() in self._hostnames:
            return True

        try:
            addr = ipaddress.ip_address(clean)
        except ValueError:
            return False

        if addr in self._ips:
            return True

        for subnet in self._subnets:
            if addr in subnet:
                return True

        return False

from datetime import datetime, timezone, timedelta
from scalp.core.exclusions import DateRangeFilter, NetworkFilter

def test_date_range_spans_month_boundary():
    tz = timezone(timedelta(hours=-5))
    start = datetime(2024, 9, 25, 0, 0, 0, tzinfo=tz)
    end = datetime(2024, 10, 5, 23, 59, 59, tzinfo=tz)
    date_filter = DateRangeFilter(start=start, end=end)

    in_sep = datetime(2024, 9, 28, 12, 0, 0, tzinfo=tz)
    in_oct = datetime(2024, 10, 2, 12, 0, 0, tzinfo=tz)
    before = datetime(2024, 9, 20, 12, 0, 0, tzinfo=tz)
    after = datetime(2024, 10, 10, 12, 0, 0, tzinfo=tz)

    assert date_filter.is_valid(in_sep) is True
    assert date_filter.is_valid(in_oct) is True
    assert date_filter.is_valid(before) is False
    assert date_filter.is_valid(after) is False

def test_date_range_open_ended():
    start = datetime(2024, 1, 1, 0, 0, 0)
    filter_start_only = DateRangeFilter(start=start)
    assert filter_start_only.is_valid(datetime(2024, 6, 1)) is True
    assert filter_start_only.is_valid(datetime(2023, 12, 31)) is False

    filter_none = DateRangeFilter()
    assert filter_none.is_valid(datetime(2024, 1, 1)) is True
    assert filter_none.is_valid(None) is True

def test_date_range_parse_cli_string():
    date_filter = DateRangeFilter.from_cli_period("04/Apr/2024:15:45;10/May/2024:23:59")
    assert date_filter.start is not None
    assert date_filter.end is not None
    assert date_filter.start.month == 4
    assert date_filter.end.month == 5

def test_network_filter_cidr_and_single_ip():
    net_filter = NetworkFilter(
        excluded_ips=["127.0.0.1", "2001:db8::1"],
        excluded_subnets=["192.168.1.0/24", "10.0.0.0/8", "2001:db8:1::/48"]
    )
    # Exact IP exclusion
    assert net_filter.is_excluded("127.0.0.1") is True
    assert net_filter.is_excluded("2001:db8::1") is True

    # CIDR subnet exclusion
    assert net_filter.is_excluded("192.168.1.50") is True
    assert net_filter.is_excluded("10.5.4.3") is True
    assert net_filter.is_excluded("2001:db8:1::99") is True

    # Allowed IPs
    assert net_filter.is_excluded("192.168.2.1") is False
    assert net_filter.is_excluded("172.16.0.1") is False

def test_network_filter_no_accidental_prefix_matches():
    net_filter = NetworkFilter(excluded_ips=["10.0.0.1"])
    assert net_filter.is_excluded("10.0.0.1") is True
    assert net_filter.is_excluded("10.0.0.10") is False
    assert net_filter.is_excluded("10.0.0.100") is False

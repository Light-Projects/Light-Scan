# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.utils.CIDR (TargetParser, parse_targets, parse_targets_from_file).

Hostname resolution and ARP-based resolve_ipv4 are network/L2 dependent and
are mocked so the suite runs offline and deterministically.
"""
import pytest
from LightPacket.utils.CIDR import TargetParser, parse_targets, parse_targets_from_file


# ---------------------------------------------------------------------------
# expand_cidr
# ---------------------------------------------------------------------------

def test_expand_cidr_slash_24_include_all():
    ips = TargetParser.expand_cidr("192.168.1.0/24", include_all=True)
    assert len(ips) == 256
    assert "192.168.1.0" in ips
    assert "192.168.1.255" in ips


def test_expand_cidr_slash_24_exclude_network_broadcast():
    ips = TargetParser.expand_cidr("192.168.1.0/24", include_all=False)
    assert len(ips) == 254
    assert "192.168.1.0" not in ips
    assert "192.168.1.255" not in ips


def test_expand_cidr_slash_32_returns_single_host():
    ips = TargetParser.expand_cidr("10.0.0.5/32")
    assert ips == ["10.0.0.5"]


def test_expand_cidr_slash_31_returns_both_addresses_rfc3021():
    ips = TargetParser.expand_cidr("10.0.0.0/31")
    assert set(ips) == {"10.0.0.0", "10.0.0.1"}


def test_expand_cidr_respects_max_hosts_limit():
    # /8 has 16M+ hosts, way over a small limit
    ips = TargetParser.expand_cidr("10.0.0.0/8", max_hosts=100)
    assert ips == []


def test_expand_cidr_invalid_notation_returns_empty_list():
    assert TargetParser.expand_cidr("not-a-cidr") == []


# ---------------------------------------------------------------------------
# expand_hyphen_range
# ---------------------------------------------------------------------------

def test_expand_hyphen_range_last_octet():
    ips = TargetParser.expand_hyphen_range("192.168.1.1-5")
    assert ips == [f"192.168.1.{i}" for i in range(1, 6)]


def test_expand_hyphen_range_full_ip_to_ip():
    ips = TargetParser.expand_hyphen_range("192.168.1.253-255")
    assert ips == ["192.168.1.253", "192.168.1.254", "192.168.1.255"]


def test_expand_hyphen_range_invalid_start_greater_than_end():
    assert TargetParser.expand_hyphen_range("192.168.1.10-5") == ['192.168.1.10-5']

def test_expand_hyphen_range_respects_max_hosts():
    assert TargetParser.expand_hyphen_range("192.168.1.1-254", max_hosts=10) == []


def test_expand_hyphen_range_multi_octet_ranges():
    ips = TargetParser.expand_hyphen_range("192.168.1-2.1")
    assert set(ips) == {"192.168.1.1", "192.168.2.1"}


def test_expand_hyphen_range_out_of_bounds_octet_value():
    assert TargetParser.expand_hyphen_range("192.168.1.1-300") == ["192.168.1.1-300"]


def test_expand_network_range_single_octet_range_with_cidr():
    ips = TargetParser.expand_network_range("192-193.168.1.0/24")
    # 2 networks * 256 hosts = 512
    assert len(ips) == 512
    assert "192.168.1.0" in ips
    assert "193.168.1.255" in ips


def test_expand_network_range_no_hyphen_falls_back_to_plain_cidr():
    ips = TargetParser.expand_network_range("10.0.0.0/30")
    assert len(ips) == 4


def test_expand_network_range_respects_max_hosts():
    ips = TargetParser.expand_network_range("192-255.168.1.0/24", max_hosts=100)
    assert ips == []


def test_expand_network_range_invalid_octet_count():
    ips = TargetParser.expand_network_range("192-193.168.1/24")
    assert ips == []


# ---------------------------------------------------------------------------
# parse_multi_target
# ---------------------------------------------------------------------------

def test_parse_multi_target_single_ip():
    assert TargetParser.parse_multi_target("192.168.1.1") == ["192.168.1.1"]


def test_parse_multi_target_comma_separated():
    result = TargetParser.parse_multi_target("192.168.1.1,192.168.1.2,192.168.1.3")
    assert result == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_parse_multi_target_dedupes_preserving_order():
    result = TargetParser.parse_multi_target("192.168.1.1,192.168.1.1,192.168.1.2")
    assert result == ["192.168.1.1", "192.168.1.2"]


def test_parse_multi_target_mixed_cidr_and_range():
    result = TargetParser.parse_multi_target("192.168.1.1,192.168.1.2-3")
    assert result == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_parse_multi_target_empty_string_returns_empty():
    assert TargetParser.parse_multi_target("") == []
    assert TargetParser.parse_multi_target("   ") == []


def test_parse_multi_target_ignores_blank_comma_segments():
    result = TargetParser.parse_multi_target("192.168.1.1,,192.168.1.2,")
    assert result == ["192.168.1.1", "192.168.1.2"]


# ---------------------------------------------------------------------------
# validate_ip / validate_hostname / validate_target
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ip", ["192.168.1.1", "10.0.0.0", "255.255.255.255", "0.0.0.0"])
def test_validate_ip_valid_ipv4(ip):
    assert TargetParser.validate_ip(ip, version=4) is True


@pytest.mark.parametrize("ip", ["256.1.1.1", "not-an-ip", "1.2.3", "1.2.3.4.5"])
def test_validate_ip_invalid_ipv4(ip):
    assert TargetParser.validate_ip(ip, version=4) is False


def test_validate_ip_valid_ipv6():
    assert TargetParser.validate_ip("::1", version=6) is True
    assert TargetParser.validate_ip("2001:db8::1", version=6) is True


def test_validate_ip_version_none_checks_both():
    assert TargetParser.validate_ip("192.168.1.1", version=None) is True
    assert TargetParser.validate_ip("::1", version=None) is True


def test_validate_hostname_known_tld_short_circuits_dns():
    # Ends with a recognized extension -> should validate without a DNS call
    assert TargetParser.validate_hostname("example.com") is True


def test_validate_hostname_rejects_invalid_characters():
    assert TargetParser.validate_hostname("bad_host!name.com") is False


def test_validate_hostname_rejects_empty_and_too_long():
    assert TargetParser.validate_hostname("") is False
    assert TargetParser.validate_hostname("a" * 254) is False


def test_validate_hostname_unknown_tld_uses_dns_resolution(monkeypatch):
    import socket as socket_mod

    monkeypatch.setattr(socket_mod, "gethostbyname", lambda h: "1.2.3.4")
    assert TargetParser.validate_hostname("myhost.internal") is True

    def raise_error(h):
        raise OSError("not found")

    monkeypatch.setattr(socket_mod, "gethostbyname", raise_error)
    assert TargetParser.validate_hostname("myhost.internal") is False


def test_validate_target_accepts_ip_or_hostname():
    assert TargetParser.validate_target("192.168.1.1") is True
    assert TargetParser.validate_target("example.com") is True
    assert TargetParser.validate_target("!!!not-valid!!!") is False


# ---------------------------------------------------------------------------
# resolve_hostname
# ---------------------------------------------------------------------------

def test_resolve_hostname_success(monkeypatch):
    import socket as socket_mod
    monkeypatch.setattr(socket_mod, "gethostbyname", lambda h: "93.184.216.34")
    assert TargetParser.resolve_hostname("example.com") == "93.184.216.34"


def test_resolve_hostname_failure_returns_none(monkeypatch):
    import socket as socket_mod

    def raise_error(h):
        raise OSError("no such host")

    monkeypatch.setattr(socket_mod, "gethostbyname", raise_error)
    assert TargetParser.resolve_hostname("nonexistent.invalid") is None


# ---------------------------------------------------------------------------
# parse_and_validate_targets / parse_targets (public API)
# ---------------------------------------------------------------------------

def test_parse_targets_single_ip():
    assert parse_targets("192.168.1.1") == ["192.168.1.1"]


def test_parse_targets_cidr_include_all():
    result = parse_targets("192.168.1.0/30", include_all=True)
    assert result == ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_parse_targets_cidr_exclude_network_broadcast():
    result = parse_targets("192.168.1.0/30", include_all=False)
    assert result == ["192.168.1.1", "192.168.1.2"]


def test_parse_targets_hyphen_range():
    result = parse_targets("192.168.1.1-3")
    assert result == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_parse_targets_drops_invalid_unresolvable_hostname(monkeypatch):
    import socket as socket_mod

    def raise_error(h):
        raise OSError("no such host")

    monkeypatch.setattr(socket_mod, "gethostbyname", raise_error)
    result = parse_targets("not a valid target!!")
    assert result == []


def test_parse_targets_from_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("192.168.1.1\n192.168.1.2\n192.168.1.3\n")
    result = parse_targets_from_file(str(f))
    assert result == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]


def test_parse_targets_from_file_mixed_cidr_and_hosts(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("192.168.1.0/30\n")
    result = parse_targets_from_file(str(f))
    assert result == ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"]
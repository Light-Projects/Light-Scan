# LightPacket/tests/test_network.py
"""
network.py tests.

Only `is_ip_locale` is a pure function; the rest shell out and would
need system stubs. Skip those here.
"""

from LightPacket.helper.network import is_ip_locale


class TestIsIpLocale:

    def test_private_ipv4(self):
        assert is_ip_locale('192.168.1.1') is True
        assert is_ip_locale('10.0.0.1') is True
        assert is_ip_locale('172.16.0.1') is True

    def test_loopback(self):
        assert is_ip_locale('127.0.0.1') is True
        assert is_ip_locale('::1') is True

    def test_link_local(self):
        assert is_ip_locale('169.254.1.1') is True
        assert is_ip_locale('fe80::1') is True

    def test_public(self):
        assert is_ip_locale('8.8.8.8') is False
        assert is_ip_locale('1.1.1.1') is False
        assert is_ip_locale('2001:4860:4860::8888') is False

    def test_invalid_returns_string(self):
        assert is_ip_locale('not-an-ip') == "Invalid IP address"
        assert is_ip_locale('999.999.999.999') == "Invalid IP address"
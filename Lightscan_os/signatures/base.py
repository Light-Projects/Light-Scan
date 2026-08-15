# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Adam Boulaaz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


"""
Base primitives for OS signature definitions.

Every OS-specific module (windows.py, linux.py, macos.py, bsd.py, unix.py,
android.py) builds one or more `OSSignature` instances. The engine in
core/engine.py never hard-codes OS names -- it just iterates whatever
signatures are registered in signatures/__init__.py, so adding a new OS is
just "drop a new file in here and register it".
"""

from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Optional, Any


@dataclass
class VersionRule:
    """
    One rule used to pin a specific OS version/build once the family is
    already known (e.g. once we know it's Windows, which build?).
    All provided fields must match for the rule to fire.
    """
    version: str
    ttl: Optional[int] = None
    window: Optional[int] = None
    wscale: Optional[int] = None
    mss: Optional[int] = None
    option_order: Optional[List[str]] = None
    banner_contains: Optional[str] = None
    requires_timestamp: Optional[bool] = None
    requires_sack: Optional[bool] = None

    def matches(self, ctx: Dict[str, Any]) -> bool:
        if self.ttl is not None and ctx.get('ttl') != self.ttl:
            return False
        if self.window is not None and ctx.get('window') != self.window:
            return False
        if self.wscale is not None and ctx.get('wscale') != self.wscale:
            return False
        if self.mss is not None and ctx.get('mss') != self.mss:
            return False
        if self.option_order is not None:
            clean = [o for o in ctx.get('order', []) if o not in ('NOP', 'EOL')]
            wanted = [o for o in self.option_order if o not in ('NOP', 'EOL')]
            if clean != wanted and ctx.get('order') != self.option_order:
                return False
        if self.requires_timestamp is not None and bool(ctx.get('timestamp')) != self.requires_timestamp:
            return False
        if self.requires_sack is not None and bool(ctx.get('sack')) != self.requires_sack:
            return False
        if self.banner_contains is not None:
            banner = (ctx.get('banner') or '').lower()
            if self.banner_contains.lower() not in banner:
                return False
        return True


@dataclass
class OSSignature:
    name: str                          # e.g. "Windows 10/11"
    family: str                        # "windows" | "linux" | "macos" | "bsd" | "unix" | "android"

    # --- TCP/IP stack fingerprint ---------------------------------------
    common_orders: List[List[str]] = field(default_factory=list)
    windows: List[int] = field(default_factory=list)          # observed TCP window sizes
    ttl_range: Tuple[int, int] = (0, 255)                      # IPv4 TTL
    hlim_range: Tuple[int, int] = (0, 255)                      # IPv6 hop limit
    wscale_values: List[int] = field(default_factory=list)
    mss_values: List[int] = field(default_factory=list)
    timestamp_high: bool = False
    ip_id_zero: bool = False
    ip_id_sequential: bool = False
    df_bit_set: bool = True

    # --- ICMP fingerprint --------------------------------------------------
    icmp_default_ttl: Optional[int] = None
    icmp_code_quirk: Optional[str] = None       # e.g. echo-reply code != 0 quirk name

    # --- UDP closed-port fingerprint (nmap-style U1 test) -------------------
    udp_closed_port_quirk: Optional[str] = None  # name of a matching quirk, see probes/udp_probe.py

    # --- Service banners -----------------------------------------------
    banner_keywords: List[Tuple[str, float]] = field(default_factory=list)     # (substring, weight)
    service_keywords: List[Tuple[str, float]] = field(default_factory=list)    # (service name substring, weight)
    exclusive_banner_keywords: List[str] = field(default_factory=list)         # near-certain -> zero out rivals

    # --- Version fingerprinting (only used once family is the top match) ---
    version_rules: List[VersionRule] = field(default_factory=list)

    # ---------------------------------------------------------------- scoring
    def score_tcp(self, analysis: Dict[str, Any], window: int, ttl_or_hlim: int, ip_version: int = 4) -> float:
        score = 0.0
        order = analysis.get('order', [])
        clean_order = [o for o in order if o not in ('NOP', 'EOL')]

        for pattern in self.common_orders:
            clean_pattern = [o for o in pattern if o not in ('NOP', 'EOL')]
            if order == pattern:
                score += 8
                break
            if clean_order == clean_pattern:
                score += 6
                break

        if window in self.windows:
            score += 5

        lo, hi = self.hlim_range if ip_version == 6 else self.ttl_range
        if lo <= ttl_or_hlim <= hi:
            score += 3

        if self.wscale_values and analysis.get('wscale') in self.wscale_values:
            score += 3

        if self.mss_values and analysis.get('mss') in self.mss_values:
            score += 4

        if self.timestamp_high and analysis.get('timestamp'):
            ts = analysis['timestamp']
            if isinstance(ts, tuple) and ts[0] and ts[0] > 100_000_000:
                score += 2

        if ip_version == 4 and self.ip_id_zero and analysis.get('id') == 0:
            score += 3

        return score

    def score_banner(self, banner_text: str) -> float:
        if not banner_text:
            return 0.0
        text = banner_text.lower()
        return sum(weight for kw, weight in self.banner_keywords if kw.lower() in text)

    def score_service(self, service_name: str) -> float:
        if not service_name:
            return 0.0
        text = service_name.lower()
        return sum(weight for kw, weight in self.service_keywords if kw.lower() in text)

    def is_exclusive_match(self, banner_text: str) -> bool:
        if not banner_text or not self.exclusive_banner_keywords:
            return False
        text = banner_text.lower()
        return any(k.lower() in text for k in self.exclusive_banner_keywords)

    def score_icmp(self, reply_ttl: Optional[int], code_quirk: Optional[str]) -> float:
        score = 0.0
        if self.icmp_default_ttl is not None and reply_ttl is not None:
            # OSes round-trip with a handful of common default TTLs (64/128/255);
            # closeness after hop decrement is a weak-but-useful signal.
            if abs(reply_ttl - self.icmp_default_ttl) <= 2:
                score += 2
        if self.icmp_code_quirk is not None and code_quirk == self.icmp_code_quirk:
            score += 3
        return score

    def score_udp(self, quirk: Optional[str]) -> float:
        if self.udp_closed_port_quirk is not None and quirk == self.udp_closed_port_quirk:
            return 4.0
        return 0.0

    def detect_version(self, ctx: Dict[str, Any]) -> Optional[str]:
        for rule in self.version_rules:
            if rule.matches(ctx):
                return rule.version
        return None
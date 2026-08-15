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
OSFingerprintEngine: orchestrates a full OS detection pass against one
host -- TCP SYN probes on every open port, one ICMP echo, one UDP
closed-port probe, banner/service scoring -- and folds all of it into a
single ranked, confidence-rated candidate list.
"""

from typing import Dict, List, Optional

from ..probes.tcp_probe import probe_tcp
from ..probes.icmp_probe import probe_icmp
from ..probes.udp_probe import probe_udp
from ..signatures import SIGNATURES_BY_NAME
from .analyzer import analyze_tcp_options
from .banner_matcher import score_banners, guess_version
from .scorer import ScoreBoard, OSMatch


class OSFingerprintResult:
    def __init__(self, matches: List[OSMatch], ip_version: int, probes_used: List[str]):
        self.matches = matches            # best-first
        self.ip_version = ip_version
        self.probes_used = probes_used

    @property
    def top(self) -> Optional[OSMatch]:
        return self.matches if self.matches else None

    def as_dict(self) -> Dict:
        return {
            "ip_version": self.ip_version,
            "probes_used": self.probes_used,
            "candidates": [
                {"os": m.name, "family": m.family, "score": round(m.score, 1),
                 "confidence": round(m.confidence, 1), "version": m.version}
                for m in self.matches
            ],
        }


class OSFingerprintEngine:
    def __init__(self, min_score: float = 1.0, min_report_confidence: float = 5.0):
        self.min_score = min_score
        self.min_report_confidence = min_report_confidence

    def fingerprint(
        self,
        target: str,
        open_ports: List[int],
        banners: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
        version: int = 4,
        use_icmp: bool = True,
        use_udp: bool = True,
        timeout: float = 2.0,
        verbose: bool = False,
    ) -> OSFingerprintResult:
        banners = banners or []
        services = services or []
        board = ScoreBoard()
        probes_used = []
        last_tcp_reading = None  # (option_order, window, ttl, wscale, mss, timestamp, sack)

        if not open_ports:
            return OSFingerprintResult([], version, probes_used)

        # --- multi-port TCP SYN probing -------------------------------------
        for port in open_ports:
            try:
                reading = probe_tcp(target, port, version=version, timeout=timeout)
            except Exception as exc:
                if verbose:
                    print(f"[!] TCP probe failed on port {port}: {exc}")
                continue

            if reading is None:
                continue

            probes_used.append(f"tcp:{port}")
            analysis = analyze_tcp_options(reading["options"], reading["ip_id"], version)
            board.add_tcp(analysis, reading["window"], reading["ttl_or_hlim"], version)

            last_tcp_reading = {
                "order": analysis.get("order", []),
                "window": reading["window"],
                "ttl": reading["ttl_or_hlim"],
                "wscale": analysis.get("wscale"),
                "mss": analysis.get("mss"),
                "timestamp": analysis.get("timestamp"),
                "sack": analysis.get("sack"),
            }

        # --- ICMP echo (weak but free extra signal) --------------------------
        if use_icmp and version == 4:
            try:
                icmp_reading = probe_icmp(target, timeout=timeout)
            except Exception as exc:
                icmp_reading = None
                if verbose:
                    print(f"[!] ICMP probe failed: {exc}")
            if icmp_reading:
                probes_used.append("icmp")
                board.add_icmp(icmp_reading.get("ttl"), icmp_reading.get("code_quirk"))

        # --- UDP closed-port quirk test ---------------------------------------
        if use_udp and version == 4:
            try:
                udp_reading = probe_udp(target, timeout=timeout)
            except Exception as exc:
                udp_reading = None
                if verbose:
                    print(f"[!] UDP probe failed: {exc}")
            if udp_reading:
                probes_used.append("udp")
                board.add_udp(udp_reading.get("quirk"))

        # --- banner / service fingerprinting -----------------------------------
        if banners or services:
            probes_used.append("banner")
            banner_scores = score_banners(banners, services)
            board.add_banner_scores(banner_scores)

        matches = board.rank(min_score=self.min_score)
        
        tcp_context = None
        if last_tcp_reading:
            tcp_context = {
                'ttl': last_tcp_reading["ttl"],
                'window': last_tcp_reading["window"],
                'wscale': last_tcp_reading["wscale"],
                'mss': last_tcp_reading["mss"],
                'order': last_tcp_reading["order"],
                'timestamp': last_tcp_reading["timestamp"],
                'sack': last_tcp_reading["sack"],
            }

        # --- version pin for the winner, if we have enough context -------------

        if matches:
            top_match = matches[0]
            sig = SIGNATURES_BY_NAME.get(top_match.name)
            if sig:
                versions_found = set()
                ctx = {}
                if tcp_context:
                    ctx.update(tcp_context)
                
                for rule in sig.version_rules:
                    if rule.banner_contains is not None and banners:
                        for banner in banners:
                            ctx_copy = ctx.copy()
                            ctx_copy['banner'] = banner
                            if rule.matches(ctx_copy):
                                versions_found.add(rule.version)
                    elif rule.banner_contains is None:
                        if rule.matches(ctx):
                            versions_found.add(rule.version)
                
                top_match.version = sorted(list(versions_found)) if versions_found else None
        
        #if matches and last_tcp_reading:
        #    top_sig = SIGNATURES_BY_NAME.get(matches[0].name)
        #    if top_sig:
        #        version_guess = guess_version(
        #            top_sig,
        #            ttl=last_tcp_reading["ttl"],
        #            window=last_tcp_reading["window"],
        #            wscale=last_tcp_reading["wscale"],
        #            mss=last_tcp_reading["mss"],
        #            option_order=last_tcp_reading["order"],
        #            timestamp=last_tcp_reading["timestamp"],
        #            sack=last_tcp_reading["sack"],
        #            banners=banners,
        #       )
        #        matches[0].version = version_guess
        
        #elif matches and banners:
        #    top_sig = SIGNATURES_BY_NAME.get(matches[0].name)
        #    if top_sig:
        #        matches[0].version = guess_version(
        #            top_sig, ttl=None, window=None, wscale=None, mss=None,
        #            option_order=[], timestamp=None, sack=None, banners=banners,
        #        )

        return OSFingerprintResult(matches, version, probes_used)

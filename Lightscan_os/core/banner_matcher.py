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
Scores banners (grabbed from open services -- SSH/HTTP/FTP/SMB headers,
etc.) and open-service names against every registered signature.
"""

from typing import Dict, Iterable, List

from ..signatures import ALL_SIGNATURES


def score_banners(banners: Iterable[str], services: Iterable[str]) -> Dict[str, float]:
    """
    banners: list of raw banner strings collected from open ports.
    services: list of service names (e.g. from a port scanner's service map).
    Returns {os_name: score}.
    """
    scores = {sig.name: 0.0 for sig in ALL_SIGNATURES}
    banners = list(banners or [])
    services = list(services or [])

    exclusive_hit = False

    for banner in banners:
        for sig in ALL_SIGNATURES:
            if sig.is_exclusive_match(banner):
                exclusive_hit = True

    for banner in banners:
        for sig in ALL_SIGNATURES:
            b_score = sig.score_banner(banner)
            if b_score:
                scores[sig.name] += b_score
                if sig.is_exclusive_match(banner):
                    # a near-certain banner (distro tag, "FreeBSD", "Darwin", ...)
                    # should dominate -- zero out every other family's banner
                    # contribution accumulated so far.
                    for other in ALL_SIGNATURES:
                        if other.name != sig.name:
                            scores[other.name] = min(scores[other.name], 0.0)

    for service in services:
        for sig in ALL_SIGNATURES:
            s_score = sig.score_service(service)
            if s_score:
                scores[sig.name] += s_score

    return scores


def guess_version(top_signature, ttl, window, wscale, mss, option_order, timestamp, sack, banners) -> str:
    """
    Once we know the winning family, try to pin a specific version using
    that signature's version_rules -- first against the TCP/IP fingerprint,
    then falling back to whichever banner (if any) matches.
    """
    ctx = {
        'ttl': ttl,
        'window': window,
        'wscale': wscale,
        'mss': mss,
        'order': option_order,
        'timestamp': timestamp,
        'sack': sack,
    }

    version = top_signature.detect_version(ctx)
    if version:
        return version

    for banner in (banners or []):
        ctx['banner'] = banner
        version = top_signature.detect_version(ctx)
        if version:
            return version

    return None
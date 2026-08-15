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
Aggregates TCP + ICMP + UDP + banner scores per OS signature and turns
raw scores into a ranked, confidence-rated candidate list -- so instead
of a single guess, a caller (or the printed report) can see every
signature that got a meaningful hit and how confident each one is
relative to the others.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional

from ..signatures import ALL_SIGNATURES


@dataclass
class OSMatch:
    name: str
    family: str
    score: float
    confidence: float          # 0-100, relative to the total score across all candidates
    version: Optional[str] = None


class ScoreBoard:
    def __init__(self):
        self.scores: Dict[str, float] = {sig.name: 0.0 for sig in ALL_SIGNATURES}

    def add_tcp(self, analysis, window, ttl_or_hlim, ip_version=4):
        for sig in ALL_SIGNATURES:
            self.scores[sig.name] += sig.score_tcp(analysis, window, ttl_or_hlim, ip_version)

    def add_icmp(self, reply_ttl, code_quirk):
        for sig in ALL_SIGNATURES:
            self.scores[sig.name] += sig.score_icmp(reply_ttl, code_quirk)

    def add_udp(self, quirk):
        for sig in ALL_SIGNATURES:
            self.scores[sig.name] += sig.score_udp(quirk)

    def add_banner_scores(self, banner_scores: Dict[str, float]):
        for name, score in banner_scores.items():
            self.scores[name] = self.scores.get(name, 0.0) + score

    def rank(self, min_score: float = 1.0) -> List[OSMatch]:
        """
        Returns every signature with score >= min_score, sorted best first,
        each carrying a confidence percentage relative to the total score
        across ALL candidates (so a runaway top match correctly compresses
        everyone else's confidence, and a murky result shows several
        close, low-confidence candidates instead of one falsely-certain one).
        """
        total = sum(max(s, 0.0) for s in self.scores.values())
        candidates = []
        for sig in ALL_SIGNATURES:
            score = self.scores.get(sig.name, 0.0)
            if score < min_score:
                continue
            confidence = (score / total * 100) if total > 0 else 0.0
            candidates.append(OSMatch(name=sig.name, family=sig.family, score=score, confidence=confidence))

        candidates.sort(key=lambda m: m.score, reverse=True)
        return candidates
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

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Tuple, Any
from collections import Counter

class FirewallType(Enum):
    """Firewall classification types"""
    NONE = "No Firewall"
    STATEFUL = "Stateful Firewall"
    STATELESS = "Stateless Firewall"
    WAF = "Web Application Firewall"
    IDS_IPS = "IDS/IPS Enabled"
    RATE_LIMITING = "Rate Limiting"
    DPI = "Deep Packet Inspection"
    HYBRID = "Hybrid Firewall"
    UNKNOWN = "Unknown"


class RiskLevel(Enum):
    """Risk assessment levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


@dataclass
class FirewallMetrics:
    """Comprehensive firewall metrics"""
    total_ports: int
    open_ports: int
    closed_ports: int
    filtered_ports: int
    open_filtered_ports: int
    unfiltered_ports: int = 0
    defended_ports: int = 0
    undefended_ports: int = 0
    null_ports: int = 0
    timeouts: int = 0
    responses: int = 0

    reset_ratio: float = 0.0
    timeout_ratio: float = 0.0
    rejection_ratio: float = 0.0
    filtered_ratio: float = 0.0
    open_ratio: float = 0.0

    common_port_open: int = 0
    ephemeral_port_open: int = 0
    privileged_port_open: int = 0

    avg_response_time: float = 0.0
    response_variance: float = 0.0

    def get(self, key, default=None):
        """Dict-like get method for compatibility"""
        if hasattr(self, key):
            return getattr(self, key)
        return default

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'total_ports': self.total_ports,
            'open_ports': self.open_ports,
            'closed_ports': self.closed_ports,
            'filtered_ports': self.filtered_ports,
            'open_filtered_ports': self.open_filtered_ports,
            'unfiltered_ports': self.unfiltered_ports,
            'defended_ports': self.defended_ports,
            'undefended_ports': self.undefended_ports,
            'null_ports': self.null_ports,
            'timeouts': self.timeouts,
            'responses': self.responses,
            'reset_ratio': self.reset_ratio,
            'timeout_ratio': self.timeout_ratio,
            'rejection_ratio': self.rejection_ratio,
            'filtered_ratio': self.filtered_ratio,
            'open_ratio': self.open_ratio,
            'common_port_open': self.common_port_open,
            'ephemeral_port_open': self.ephemeral_port_open,
            'privileged_port_open': self.privileged_port_open,
            'avg_response_time': self.avg_response_time,
            'response_variance': self.response_variance
        }


@dataclass
class FirewallAssessment:
    """Complete firewall assessment result"""
    detected: bool
    firewall_type: FirewallType
    confidence: int
    risk_level: RiskLevel
    signature: str
    detection_methods: List[str]
    metrics: FirewallMetrics
    scan_type_analysis: Dict[str, Any]
    attack_surface: Dict[str, Any]


class FirewallDetector:
    """Advanced firewall detection system with multi-method analysis"""

    def __init__(self):
        self.signature_db = self._build_signature_db()
        self.detection_methods = []

    def _build_signature_db(self) -> Dict:
        """Build firewall signature database"""
        return {
            "stateful": {
                "patterns": [
                    "high filtered ratio",
                    "consistent blocking",
                    "session tracking behavior"
                ],
                "indicators": {
                    "filtered_ratio": (0.7, 1.0),
                    "timeout_ratio": (0.3, 1.0),
                    "rejection_ratio": (0.0, 0.3)
                }
            },
            "stateless": {
                "patterns": [
                    "irregular filtering",
                    "port-based blocking",
                    "no session tracking"
                ],
                "indicators": {
                    "filtered_ratio": (0.3, 0.8),
                    "timeout_ratio": (0.1, 0.5),
                    "rejection_ratio": (0.2, 0.7)
                }
            },
            "waf": {
                "patterns": [
                    "HTTP filtering",
                    "request inspection",
                    "anomaly detection"
                ],
                "indicators": {
                    "http_headers_modified": True,
                    "cookies_modified": True,
                    "url_encoding_detected": True
                }
            },
            "ids_ips": {
                "patterns": [
                    "inconsistent responses",
                    "probe detection",
                    "rate limiting"
                ],
                "indicators": {
                    "response_variance_high": True,
                    "retry_success_rate": (0.1, 0.5)
                }
            },
            "rate_limiting": {
                "patterns": [
                    "throttled responses",
                    "time-based blocking",
                    "burst rejection"
                ],
                "indicators": {
                    "avg_response_time": (2.0, float('inf')),
                    "timeout_ratio": (0.5, 1.0)
                }
            }
        }

    def detect(self, target: str, results: Dict, scan_type: str,
               timeout_count: int = 0, **kwargs) -> FirewallAssessment:
        """Main detection method"""

        self.detection_methods = []
        metrics = self._calculate_metrics(results, timeout_count, **kwargs)

        analyses = {
            "ratio_analysis": self._analyze_ratios(metrics),
            "pattern_analysis": self._analyze_patterns(results, scan_type),
            "scan_type_specific": self._analyze_scan_type(results, scan_type),
            "timing_analysis": self._analyze_timing(kwargs.get('timing_data', {})),
            "behavioral_analysis": self._analyze_behavior(results),
            "signature_matching": self._match_signatures(metrics, results)
        }

        firewall_detected, confidence = self._determine_firewall_presence(analyses)

        firewall_type = self._classify_firewall(analyses, scan_type)

        risk_level, attack_surface = self._assess_risk(metrics, analyses)

        return FirewallAssessment(
            detected=firewall_detected,
            firewall_type=firewall_type,
            confidence=confidence,
            risk_level=risk_level,
            signature=self._generate_signature(analyses, firewall_type),
            detection_methods=list(set(self.detection_methods)),
            metrics=metrics,
            scan_type_analysis=analyses,
            attack_surface=attack_surface
        )

    def _calculate_metrics(self, results: Dict, timeout_count: int,
                           **kwargs) -> FirewallMetrics:
        """Calculate comprehensive metrics"""
        total = len(kwargs.get('ports_to_scan', []))
        open_ports = len(results.get('open_ports', []))
        closed_ports = len(results.get('closed_ports', []))
        filtered_ports = len(results.get('filtered_ports', []))
        open_filtered = len(results.get('open_filtered_ports', []))
        unfiltered = len(results.get('unfiltered_ports', []))

        filtered_ratio = filtered_ports / total if total > 0 else 0
        open_ratio = open_ports / total if total > 0 else 0

        common_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                        443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080}

        common_port_open = sum(1 for p in results.get('open_ports', [])
                               if p in common_ports)
        privileged_open = sum(1 for p in results.get('open_ports', [])
                              if p < 1024)

        timings = kwargs.get('timing_data', {}).get('response_times', [])
        if timings:
            avg_time = sum(timings) / len(timings)
            variance = sum((t - avg_time) ** 2 for t in timings) / len(timings)
        else:
            avg_time = 0.0
            variance = 0.0

        return FirewallMetrics(
            total_ports=total,
            open_ports=open_ports,
            closed_ports=closed_ports,
            filtered_ports=filtered_ports,
            open_filtered_ports=open_filtered,
            unfiltered_ports=unfiltered,
            timeouts=timeout_count,
            responses=total - timeout_count,
            reset_ratio=results.get('reset_count', 0) / total if total > 0 else 0,
            timeout_ratio=timeout_count / total if total > 0 else 0,
            rejection_ratio=results.get('rejection_count', 0) / total if total > 0 else 0,
            filtered_ratio=filtered_ratio,
            open_ratio=open_ratio,
            common_port_open=common_port_open,
            ephemeral_port_open=open_ports - common_port_open - privileged_open,
            privileged_port_open=privileged_open,
            avg_response_time=avg_time,
            response_variance=variance
        )

    def _analyze_ratios(self, metrics: FirewallMetrics) -> Dict:
        """Analyze port state ratios for firewall detection"""
        analysis = {
            "filtered_ratio": metrics.filtered_ratio,
            "open_ratio": metrics.open_ratio,
            "closed_ratio": metrics.closed_ports / metrics.total_ports if metrics.total_ports > 0 else 0
        }

        if metrics.filtered_ratio > 0.8:
            analysis["filtering_strength"] = "VERY_STRONG"
        elif metrics.filtered_ratio > 0.6:
            analysis["filtering_strength"] = "STRONG"
        elif metrics.filtered_ratio > 0.4:
            analysis["filtering_strength"] = "MODERATE"
        elif metrics.filtered_ratio > 0.2:
            analysis["filtering_strength"] = "WEAK"
        else:
            analysis["filtering_strength"] = "NONE"

        if metrics.timeout_ratio > 0.5:
            analysis["rate_limiting"] = "HIGH_LIKELIHOOD"
        elif metrics.timeout_ratio > 0.3:
            analysis["rate_limiting"] = "MODERATE_LIKELIHOOD"
        else:
            analysis["rate_limiting"] = "LOW_LIKELIHOOD"

        self.detection_methods.append("ratio_analysis")
        return analysis

    def _analyze_patterns(self, results: Dict, scan_type: str) -> Dict:
        """Analyze response patterns"""
        patterns = {}

        if results.get('rejection_count', 0) > len(results.get('open_ports', [])):
            patterns["consistent_rejection"] = True
        else:
            patterns["consistent_rejection"] = False

        responses = results.get('responses', {})
        pattern_counts = Counter(responses.values())

        if len(pattern_counts) <= 2 and 'timeout' in pattern_counts:
            patterns["uniform_filtering"] = True
        else:
            patterns["uniform_filtering"] = False

        if scan_type in ['syn', 'tcp', 'null', 'fin', 'xmas']:
            patterns["stealth_scan_detected"] = True

        self.detection_methods.append("pattern_analysis")
        return patterns

    def _analyze_scan_type(self, results: Dict, scan_type: str) -> Dict:
        """Analyze results specific to scan type"""
        analysis = {
            "scan_type": scan_type,
            "detections": []
        }

        if scan_type == "fdd":
            defended = len(results.get('defended_ports', []))
            undefended = len(results.get('undefended_ports', []))
            analysis["defended_ratio"] = defended / (defended + undefended) if (defended + undefended) > 0 else 0
            analysis["detections"].append("fdd_scan_completed")

        elif scan_type == "null":
            null_ports = len(results.get('null_ports', []))
            analysis["null_ports"] = null_ports
            if null_ports > 20:
                analysis["detections"].append("null_scan_detection")
                analysis["inference"] = "FIREWALL_DETECTED"

        elif scan_type == "ack":
            unfiltered = len(results.get('unfiltered_ports', []))
            filtered = len(results.get('filtered_ports', []))
            analysis["unfiltered_ratio"] = unfiltered / (unfiltered + filtered) if (unfiltered + filtered) > 0 else 0
            if analysis["unfiltered_ratio"] > 0.3:
                analysis["detections"].append("ack_scan_filtering_detected")

        self.detection_methods.append("scan_type_specific_analysis")
        return analysis

    def _analyze_timing(self, timing_data: Dict) -> Dict:
        """Analyze timing patterns for firewall detection"""
        analysis = {
            "avg_response": timing_data.get('avg_response_time', 0),
            "variance": timing_data.get('variance', 0),
            "detections": []
        }

        if analysis["avg_response"] > 1.0:
            analysis["detections"].append("possible_dpi")
            analysis["dpi_likelihood"] = "HIGH" if analysis["avg_response"] > 2.0 else "MODERATE"
        else:
            analysis["dpi_likelihood"] = "LOW"

        if analysis["variance"] > 0.5:
            analysis["detections"].append("possible_rate_limiting")

        self.detection_methods.append("timing_analysis")
        return analysis

    def _analyze_behavior(self, results: Dict) -> Dict:
        """Analyze behavioral patterns"""
        analysis = {
            "detections": [],
            "behavior_type": "NORMAL"
        }

        if results.get('syn_ack_count', 0) > 0 and results.get('reset_count', 0) > 0:
            analysis["detections"].append("possible_scan_alert")
            analysis["behavior_type"] = "DEFENSIVE"

        if results.get('closed_ports', []) and not results.get('filtered_ports', []):
            analysis["detections"].append("host_based_filtering")

        if results.get('filtered_ports', []) and not results.get('closed_ports', []):
            analysis["detections"].append("network_based_filtering")

        self.detection_methods.append("behavioral_analysis")
        return analysis

    def _match_signatures(self, metrics: FirewallMetrics,
                          results: Dict) -> Dict:
        """Match against firewall signatures"""
        matches = []
        confidence_scores = []

        for fw_type, signature in self.signature_db.items():
            score = 0
            indicators = signature.get('indicators', {})

            for indicator, value in indicators.items():
                if isinstance(value, tuple):
                    if hasattr(metrics, indicator):
                        metric_value = getattr(metrics, indicator)
                        if value[0] <= metric_value <= value[1]:
                            score += 1
                elif isinstance(value, bool):
                    if value == metrics.get(indicator, False):
                        score += 1

            confidence = (score / len(indicators)) * 100
            if confidence > 30:  # Only consider matches above threshold
                matches.append((fw_type, confidence))
                confidence_scores.append(confidence)

        matches.sort(key=lambda x: x[1], reverse=True)

        self.detection_methods.append("signature_matching")
        return {
            "matches": matches,
            "best_match": matches[0] if matches else ("UNKNOWN", 0),
            "total_matches": len(matches)
        }

    def _determine_firewall_presence(self, analyses: Dict) -> Tuple[bool, int]:
        """Determine if firewall exists and confidence level"""
        signals = []
        weights = {
            "filtering_strength": {"VERY_STRONG": 100, "STRONG": 80, "MODERATE": 60,
                                   "WEAK": 30, "NONE": 0},
            "uniform_filtering": {True: 70, False: 10},
            "defended_ratio": 85,
            "null_ports": 60,
            "dpi_likelihood": {"HIGH": 80, "MODERATE": 50, "LOW": 10},
            "behavior_type": {"DEFENSIVE": 75, "NORMAL": 20}
        }

        if 'ratio_analysis' in analyses:
            ratio_analysis = analyses['ratio_analysis']
            strength = ratio_analysis.get('filtering_strength', 'NONE')
            signals.append(weights['filtering_strength'].get(strength, 0))

            if ratio_analysis.get('rate_limiting') in ['HIGH_LIKELIHOOD', 'MODERATE_LIKELIHOOD']:
                signals.append(70)

        if 'pattern_analysis' in analyses:
            if analyses['pattern_analysis'].get('uniform_filtering'):
                signals.append(weights['uniform_filtering'][True])

        if 'scan_type_specific' in analyses:
            scan_type_analysis = analyses['scan_type_specific']
            if scan_type_analysis.get('detections'):
                signals.append(60)

            if scan_type_analysis.get('scan_type') == 'fdd':
                defended_ratio = scan_type_analysis.get('defended_ratio', 0)
                signals.append(defended_ratio * weights['defended_ratio'])

        if 'timing_analysis' in analyses:
            timing = analyses['timing_analysis']
            if timing.get('detections'):
                signals.append(60)
            dpi_likelihood = timing.get('dpi_likelihood', 'LOW')
            signals.append(weights['dpi_likelihood'].get(dpi_likelihood, 10))

        if 'behavioral_analysis' in analyses:
            behavior = analyses['behavioral_analysis']
            signals.append(weights['behavior_type'].get(behavior.get('behavior_type', 'NORMAL'), 20))

        if signals:
            confidence = int(sum(signals) / len(signals))
        else:
            confidence = 0

        detected = confidence >= 40

        if confidence >= 70:
            self.detection_methods.append("high_confidence_detection")

        return detected, min(confidence, 100)

    def _classify_firewall(self, analyses: Dict, scan_type: str) -> FirewallType:
        """Classify the type of firewall detected"""
        if 'signature_matching' in analyses:
            best_match = analyses['signature_matching']['best_match']
            if best_match[1] > 50:
                fw_type_map = {
                    "stateful": FirewallType.STATEFUL,
                    "stateless": FirewallType.STATELESS,
                    "waf": FirewallType.WAF,
                    "ids_ips": FirewallType.IDS_IPS,
                    "rate_limiting": FirewallType.RATE_LIMITING
                }
                if best_match[0] in fw_type_map:
                    return fw_type_map[best_match[0]]

        if 'scan_type_specific' in analyses:
            st_analysis = analyses['scan_type_specific']
            if st_analysis.get('scan_type') == 'fdd':
                if st_analysis.get('defended_ratio', 0) > 0.5:
                    return FirewallType.STATEFUL

        if 'timing_analysis' in analyses:
            if analyses['timing_analysis'].get('dpi_likelihood') in ['HIGH', 'MODERATE']:
                return FirewallType.DPI

        if 'behavioral_analysis' in analyses:
            if len(analyses['behavioral_analysis'].get('detections', [])) > 2:
                return FirewallType.HYBRID

        return FirewallType.UNKNOWN

    def _assess_risk(self, metrics: FirewallMetrics,
                     analyses: Dict) -> Tuple[RiskLevel, Dict]:
        """Assess security risk and attack surface"""
        risk_factors = []
        attack_surface = {}

        if metrics.open_ports > 0:
            risk_factors.append(("open_services", metrics.open_ports))
            attack_surface["open_services"] = metrics.open_ports

        if metrics.privileged_port_open > 0:
            risk_factors.append(("privileged_ports", metrics.privileged_port_open))
            attack_surface["privileged_ports"] = metrics.privileged_port_open

        if metrics.filtered_ratio < 0.3:
            risk_factors.append(("weak_filtering", metrics.filtered_ratio))

        if not any(analyses.get('detection_methods', [])):
            risk_factors.append(("no_firewall", 1))

        risk_score = 0
        for factor, value in risk_factors:
            if factor == "open_services":
                risk_score += min(value * 10, 50)
            elif factor == "privileged_ports":
                risk_score += min(value * 15, 30)
            elif factor == "weak_filtering":
                risk_score += int((1 - value) * 30)
            elif factor == "no_firewall":
                risk_score += 40

        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 50:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 30:
            risk_level = RiskLevel.MEDIUM
        elif risk_score >= 10:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.NONE

        attack_surface.update({
            "risk_score": risk_score,
            "risk_level": risk_level.value,
            "vulnerable_services": metrics.privileged_port_open > 0,
            "recommended_action": self._get_risk_recommendation(risk_level, metrics)
        })

        return risk_level, attack_surface

    def _get_risk_recommendation(self, risk_level: RiskLevel,
                                 metrics: FirewallMetrics) -> str:
        """Get risk-based recommendation"""
        if risk_level == RiskLevel.CRITICAL:
            return "IMMEDIATE ACTION REQUIRED: Restrict access and implement proper firewall rules"
        elif risk_level == RiskLevel.HIGH:
            return "Review and harden firewall configuration, restrict unnecessary open ports"
        elif risk_level == RiskLevel.MEDIUM:
            return "Consider additional filtering and monitoring"
        elif risk_level == RiskLevel.LOW:
            return "Maintain current security posture, monitor for changes"
        else:
            return "No immediate action required"

    def _generate_signature(self, analyses: Dict,
                            firewall_type: FirewallType) -> str:
        """Generate unique signature for the detected firewall"""
        components = []

        if 'ratio_analysis' in analyses:
            ratio = analyses['ratio_analysis']
            components.append(f"filter:{ratio.get('filtering_strength', 'UNKNOWN')}")

        components.append(f"type:{firewall_type.value}")

        if 'timing_analysis' in analyses:
            timing = analyses['timing_analysis']
            if timing.get('dpi_likelihood') in ['HIGH', 'MODERATE']:
                components.append("dpi:true")

        if 'behavioral_analysis' in analyses:
            components.append(f"behavior:{analyses['behavioral_analysis'].get('behavior_type', 'NORMAL')}")

        return "|".join(components)

    def _print_assessment(self, assessment: FirewallAssessment, target: str):
        """Pretty print the firewall assessment"""
        print(f"\n[!] Firewall Analysis for : {target}\n")

        status = "DETECTED" if assessment.detected else "NOT DETECTED"
        print(f"   [+] Status: {status}")
        print(f"   [+] Confidence: {assessment.confidence}%")
        print(f"   [+] Firewall Type: {assessment.firewall_type.value}")
        print(f"   [+] Risk Level: {assessment.risk_level.value}")

        print(f"\n   [+] Signature: {assessment.signature}")

        print(f"\n   [+] Metrics:")
        print(f"       Open Ports: {assessment.metrics.open_ports}")
        print(f"       Closed Ports: {assessment.metrics.closed_ports}")
        print(f"       Filtered Ports: {assessment.metrics.filtered_ports}")
        print(f"       Open|Filtered: {assessment.metrics.open_filtered_ports}")
        print(f"       Filtered Ratio: {assessment.metrics.filtered_ratio:.1%}")

        print(f"\n   [+] Attack Surface:")
        for key, value in assessment.attack_surface.items():
            if key not in ['risk_level', 'recommended_action']:
                print(f"       {key.replace('_', ' ').title()}: {value}")

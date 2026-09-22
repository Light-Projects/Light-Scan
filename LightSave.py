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

import time
import html
import datetime
import json
import csv
import io
import yaml
import toml
import os
import re

ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

Version = "1.0.3"

def _enrich_open_ports(data):
    enriched = []
    for port in data.get('open_ports', []):
        port_num = port.get('port')
        banner = next(
            (b for b in data.get('banners', [])
             if str(b.get('port')) == str(port_num)),
            None,
        )
        enriched.append({
            'port': port_num,
            'service': port.get('service'),
            'status': 'OPEN',
            'banner': banner.get('content') if banner else None,
            'banner_length': len(banner.get('content', '')) if banner else 0,
        })
    return enriched

def _compute_totals(data):
    open_count = len(data.get('open_ports', []))
    closed_count = data.get('closed_ports_count', 0) or 0
    filtered_count = data.get('filtered_ports_count', 0) or 0
    total = open_count + closed_count + filtered_count
    pct = round((open_count / max(1, total)) * 100, 2)
    return total, open_count, closed_count, filtered_count, pct

def _clean_none(obj):
    if isinstance(obj, dict):
        return {k: _clean_none(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_clean_none(item) for item in obj if item is not None]
    return obj

def _build_report_dict(data, raw_output):
    total, open_count, closed_count, filtered_count, pct = _compute_totals(data)

    return {
        'metadata': {
            'report_generated': datetime.datetime.now().isoformat(),
            'tool_version': Version,
            'lightscan_version': data.get('version'),
            'scan_date': data.get('scan_date'),
            'target': data.get('target'),
            'scan_type': data.get('scan_type'),
            'scan_time_seconds': float(data.get('scan_time', 0)) if data.get('scan_time') else None,
            'host_status': data.get('host_status'),
            'ip_status': data.get('ip_status'),
            'mac_address': data.get('mac_address'),
            'reverse_dns': data.get('reverse_dns'),
        },
        'statistics': {
            'total_ports_scanned': total,
            'open_ports_count': open_count,
            'closed_ports_count': closed_count,
            'filtered_ports_count': filtered_count,
            'open_filtered_ports_count': data.get('open_filtered_ports_count', 0),
            'open_ports_percentage': pct,
            'banners_found': len(data.get('banners', [])),
            'has_firewall': data.get('firewall_status') is not None
                            and 'NO FIREWALL DETECTED' not in (data.get('firewall_status') or ''),
            'os_identified': data.get('os_fingerprint') is not None,
        },
        'firewall_analysis': {
            'status': data.get('firewall_status'),
            'firewall_detected': data.get('firewall_detected'),
            'risk_level': data.get('firewall_risk'),
        } if data.get('firewall_status') else None,
        'os_fingerprint': {
            'name': data.get('os_fingerprint'),
            'version': data.get('os_version'),
            'confidence': data.get('os_confidence'),
        } if data.get('os_fingerprint') else None,
        'open_ports': _enrich_open_ports(data),
        'closed_ports': data.get('closed_ports') if data.get('closed_ports') else None,
        'filtered_ports': data.get('filtered_ports') if data.get('filtered_ports') else None,
        'banners_captured': data.get('banners') if data.get('banners') else None,
        'lsse_results': {
            'target_url': data.get('lsse_response'),
            'scripts_detected_count': len(data.get('lsse_scripts_detected', [])),
            'scripts_detected': data.get('lsse_scripts_detected', []),
        } if data.get('lsse_response') or data.get('lsse_scripts') else None,
        'raw_output': raw_output,
    }

def _scan_dict_to_report_data(scan_dict, target):
    open_ports = []
    services = scan_dict.get('opened_ports_services', [])
    for i, port in enumerate(scan_dict.get('open_ports', [])):
        service = services[i] if i < len(services) else 'unknown'
        open_ports.append({'port': str(port), 'service': str(service)})

    closed_ports = [str(p) for p in scan_dict.get('closed_ports', [])]
    filtered_ports = [str(p) for p in scan_dict.get('filtered_ports', [])]

    banners = []
    banner_ports = scan_dict.get('banners_ports', [])
    banner_contents = scan_dict.get('banners', [])
    for i, content in enumerate(banner_contents):
        port = banner_ports[i] if i < len(banner_ports) else '?'
        banners.append({
            'port': str(port),
            'version': '',
            'content': content,
        })

    os_fingerprint = scan_dict.get('os_main_tree','')
    os_confidence = scan_dict.get('os_confi','')
    os_version = scan_dict.get('os_version','')

    return {
        'target':                    target,
        'scan_type':                 scan_dict.get('scan_type') or 'unknown',
        'open_ports':                open_ports,
        'open_ports_count':          len(open_ports),
        'closed_ports':              closed_ports,
        'closed_ports_count':        len(closed_ports),
        'filtered_ports':            filtered_ports,
        'filtered_ports_count':      len(filtered_ports),
        'open_filtered_ports_count': len(scan_dict.get('open_filtered_ports', [])),
        'os_fingerprint':            os_fingerprint,
        'os_confidence':             os_confidence,
        'os_version':                os_version,
        'firewall_status':           None,
        'firewall_detected':         None,
        'firewall_risk':             None,
        'host_status':               'up' if scan_dict.get('up', 0) > 0 else None,
        'ip_status':                 None,
        'mac_address':               None,
        'reverse_dns':               None,
        'scan_time':                 None,
        'scan_date':                 datetime.datetime.now().isoformat(),
        'version':                   '1.2.0',
        'banners':                   banners,
        'lsse_response':             None,
        'lsse_scripts':              [],
        'lsse_scripts_detected':     [],
    }

def generate_json(data, raw_output):
    report = _clean_none(_build_report_dict(data, raw_output))
    return json.dumps(report, indent=2, ensure_ascii=False)


def generate_yaml(data, raw_output):
    report = _clean_none(_build_report_dict(data, raw_output))
    return yaml.dump(
        report,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        indent=2,
        line_break='\n',
    )


def generate_toml(data, raw_output):
    report = _clean_none(_build_report_dict(data, raw_output))
    return toml.dumps(report)

def generate_csv(data, raw_output):
    out = io.StringIO()
    w = csv.writer(out)

    w.writerow(['#' * 60])
    w.writerow(['# LightScan Security Report'])
    w.writerow(['# Generated by LightSave v' + Version])
    w.writerow(['# Generated on: ' + data.get('scan_date', 'Unknown')])
    w.writerow(['#' * 60])
    w.writerow([])

    w.writerow(['[SCAN INFORMATION]'])
    w.writerow(['-' * 40])
    w.writerow(['Parameter', 'Value'])
    w.writerow(['Target', data.get('target', 'Unknown')])
    w.writerow(['Scan Type', data.get('scan_type', 'Unknown')])
    w.writerow(['Scan Duration (seconds)', data.get('scan_time', '0')])
    w.writerow(['IP Status', data.get('ip_status', 'Unknown')])
    w.writerow(['MAC Address', data.get('mac_address', 'Unknown')])
    w.writerow(['Reverse DNS', data.get('reverse_dns', 'Unknown')])
    w.writerow(['Host Status', data.get('host_status', 'Unknown')])
    w.writerow(['LightScan Version', data.get('version', 'Unknown')])
    w.writerow([])

    w.writerow(['[FIREWALL ANALYSIS]'])
    w.writerow(['-' * 40])
    w.writerow(['Status', data.get('firewall_status', 'Unknown')])
    w.writerow(['Detected', data.get('firewall_detected', 'Unknown')])
    w.writerow(['Risk Level', data.get('firewall_risk', 'Unknown')])
    w.writerow([])

    total, open_count, closed_count, filtered_count, pct = _compute_totals(data)
    w.writerow(['[SCAN STATISTICS]'])
    w.writerow(['-' * 40])
    w.writerow(['Metric', 'Count'])
    w.writerow(['Total Ports Scanned', total])
    w.writerow(['Open Ports', open_count])
    w.writerow(['Closed Ports', closed_count])
    w.writerow(['Filtered Ports', filtered_count])
    w.writerow(['Open|Filtered Ports', data.get('open_filtered_ports_count', 0)])
    if total > 0:
        w.writerow(['Open Ports Percentage', f'{pct:.1f}%'])
    w.writerow([])

    if data.get('os_fingerprint'):
        w.writerow(['[OS FINGERPRINT]'])
        w.writerow(['-' * 40])
        w.writerow(['Detected Operating System', data['os_fingerprint']])
        if data.get('os_version'):
            w.writerow(['Version', data['os_version']])
        w.writerow(['Confidence Score', f"{data.get('os_confidence', '0')}%"])
        w.writerow([])

    w.writerow(['[OPEN PORTS SUMMARY]'])
    w.writerow(['-' * 40])
    if data.get('open_ports'):
        w.writerow(['Port', 'Service', 'Status', 'Banner (truncated)'])
        w.writerow(['----', '-------', '------', '----------------'])
        for port in data.get('open_ports', []):
            banner = next(
                (b['content'] for b in data.get('banners', [])
                 if str(b['port']) == str(port['port'])),
                '',
            )
            clean = banner.replace('\n', ' ').replace('\r', '')[:200]
            w.writerow([port['port'], port['service'], 'OPEN', clean or '(no banner)'])
    else:
        w.writerow(['No open ports found'])
    w.writerow([])

    if data.get('closed_ports'):
        w.writerow(['[CLOSED PORTS]'])
        w.writerow(['-' * 40])
        w.writerow(['Port'])
        for port in data['closed_ports']:
            w.writerow([port])
        w.writerow([])

    if data.get('filtered_ports'):
        w.writerow(['[FILTERED PORTS]'])
        w.writerow(['-' * 40])
        w.writerow(['Port'])
        for port in data['filtered_ports']:
            w.writerow([port])
        w.writerow([])

    if data.get('banners'):
        w.writerow(['[BANNER CAPTURE DETAILS]'])
        w.writerow(['-' * 40])
        w.writerow(['Port', 'Full Banner Content'])
        w.writerow(['----', '--------------------'])
        for banner in data['banners']:
            clean = banner['content'].replace('\n', ' ').replace('\r', '')[:500]
            w.writerow([banner['port'], clean])
        w.writerow([])

    if data.get('lsse_response') or data.get('lsse_scripts_detected') or data.get('lsse_scripts'):
        w.writerow(['[LSSE SCRIPT ENGINE RESULTS]'])
        w.writerow(['-' * 40])

        if data.get('lsse_response'):
            w.writerow(['Target URL/Host', data['lsse_response']])

        if data.get('lsse_scripts_detected'):
            w.writerow([])
            w.writerow(['[JavaScript Files Detected]'])
            w.writerow(['#', 'Script Source'])
            for idx, script in enumerate(data['lsse_scripts_detected'], 1):
                clean = script[:300].replace('\n', ' ').replace('\r', '')
                w.writerow([f'#{idx}', clean + ('...' if len(script) > 300 else '')])

        w.writerow([])

    w.writerow(['#' * 60])
    w.writerow(['# RAW SCANNER OUTPUT'])
    w.writerow(['#' * 60])
    w.writerow([])

    if raw_output:
        for line in raw_output.split('\n'):
            w.writerow([line])
    else:
        w.writerow(['(No raw output available)'])

    w.writerow([])
    w.writerow(['#' * 60])
    w.writerow(['# End of Report'])
    w.writerow(['#' * 60])

    return out.getvalue()

def _xml_safe(value):
    if value is None:
        return ""
    return html.escape(str(value))


def generate_xml(data, raw_output):
    raw_output = raw_output or ""
    x = ['<?xml version="1.0" encoding="UTF-8"?>']
    x.append(f'<LightScanReport version="{data.get("version", "1.1.6")}" '
             f'generated="{data.get("scan_date", datetime.datetime.now().isoformat())}">')

    x.append('  <ScanInfo>')
    x.append(f'    <Target>{_xml_safe(data.get("target", "Unknown"))}</Target>')
    x.append(f'    <ScanType>{_xml_safe(data.get("scan_type", "Unknown"))}</ScanType>')
    x.append(f'    <Duration>{data.get("scan_time", "0")} seconds</Duration>')
    x.append(f'    <Timestamp>{data.get("scan_date", "")}</Timestamp>')
    x.append(f'    <IPStatus>{_xml_safe(data.get("ip_status", "Unknown"))}</IPStatus>')
    x.append(f'    <HostStatus>{_xml_safe(data.get("host_status", "Unknown"))}</HostStatus>')
    if data.get('reverse_dns'):
        x.append(f'    <ReverseDNS>{_xml_safe(data["reverse_dns"])}</ReverseDNS>')
    if data.get('mac_address'):
        x.append(f'    <MACAddress>{data["mac_address"]}</MACAddress>')
    x.append('  </ScanInfo>')

    if data.get('firewall_status'):
        x.append('  <FirewallAnalysis>')
        x.append(f'    <Status>{_xml_safe(data["firewall_status"])}</Status>')
        x.append(f'    <Detected>{_xml_safe(data.get("firewall_detected"))}</Detected>')
        if data.get('firewall_risk'):
            x.append(f'    <RiskLevel>{_xml_safe(data["firewall_risk"])}</RiskLevel>')
        x.append('  </FirewallAnalysis>')

    total, open_count, closed_count, filtered_count, _ = _compute_totals(data)
    x.append('  <Statistics>')
    x.append(f'    <TotalPortsScanned>{total}</TotalPortsScanned>')
    x.append(f'    <OpenPorts>{open_count}</OpenPorts>')
    x.append(f'    <ClosedPorts>{closed_count}</ClosedPorts>')
    x.append(f'    <FilteredPorts>{filtered_count}</FilteredPorts>')
    x.append(f'    <OpenFilteredPorts>{data.get("open_filtered_ports_count", 0)}</OpenFilteredPorts>')
    x.append('  </Statistics>')

    if data.get('open_ports'):
        x.append(f'  <OpenPorts count="{len(data["open_ports"])}">')
        for port in data['open_ports']:
            x.append('    <Port>')
            x.append(f'      <Number>{_xml_safe(port.get("port"))}</Number>')
            x.append(f'      <Service>{_xml_safe(port.get("service"))}</Service>')
            x.append('    </Port>')
        x.append('  </OpenPorts>')

    if data.get('closed_ports'):
        x.append(f'  <ClosedPortsList count="{len(data["closed_ports"])}">')
        for port in data['closed_ports']:
            x.append(f'    <Port><Number>{port}</Number></Port>')
        x.append('  </ClosedPortsList>')

    if data.get('filtered_ports'):
        x.append(f'  <FilteredPortsList count="{len(data["filtered_ports"])}">')
        for port in data['filtered_ports']:
            x.append(f'    <Port><Number>{port}</Number></Port>')
        x.append('  </FilteredPortsList>')

    if data.get('banners'):
        x.append(f'  <CapturedBanners count="{len(data["banners"])}">')
        for banner in data['banners']:
            x.append('    <Banner>')
            x.append(f'      <Port>{_xml_safe(banner.get("port"))}</Port>')
            content = banner.get('content') or ""
            x.append(f'      <Content><![CDATA[{content}]]></Content>')
            x.append('    </Banner>')
        x.append('  </CapturedBanners>')

    if data.get('os_fingerprint'):
        x.append('  <OSFingerprint>')
        x.append(f'    <DetectedOS>{_xml_safe(data["os_fingerprint"])}</DetectedOS>')
        if data.get('os_version'):
            x.append(f'    <Version>{_xml_safe(data["os_version"])}</Version>')
        x.append(f'    <Confidence>{data.get("os_confidence", "0")}%</Confidence>')
        x.append('  </OSFingerprint>')

    if data.get('lsse_response') or data.get('lsse_scripts'):
        x.append('  <LSSEResults>')
        if data.get('lsse_response'):
            x.append(f'    <Target>{_xml_safe(data["lsse_response"])}</Target>')

        if data.get('lsse_scripts_detected'):
            x.append(f'    <DetectedScripts count="{len(data["lsse_scripts_detected"])}">')
            for idx, script in enumerate(data['lsse_scripts_detected']):
                script = script or ""
                x.append(f'      <Script index="{idx + 1}"><![CDATA[{script}]]></Script>')
            x.append('    </DetectedScripts>')

        x.append('  </LSSEResults>')
    x.append('  <RawOutput>')
    x.append('    <![CDATA[')
    for line in str(raw_output).split('\n'):
        x.append(f'    {line}')
    x.append('    ]]>')
    x.append('  </RawOutput>')

    x.append('</LightScanReport>')
    return '\n'.join(x)


def _html_banners_section(data):
    if not data.get('banners'):
        return ""
    parts = [f'<div class="ports-section">'
             f'<h2 class="section-title">📎 Captured Banners ({len(data["banners"])})</h2>'
             f'<div class="banners-grid">']
    for banner in data['banners']:
        parts.append(f'''
            <div class="banner-card">
                <h3>Port {banner['port']}</h3>
                <div class="banner-content">
                    <pre>{html.escape(banner['content'])}</pre>
                </div>
            </div>''')
    parts.append('</div></div>')
    return ''.join(parts)


def _html_firewall_section(data):
    if not data.get('firewall_status'):
        return ""
    color = ("#00ff41" if data.get('firewall_detected') is False
             else "#ffaa00" if data.get('firewall_risk') == 'WEAK'
             else "#ff4444")
    icon = ("🔓" if data.get('firewall_detected') is False
            else "🛡️" if data.get('firewall_detected') is True
            else "⚠️")
    return f'''
        <div class="ports-section">
            <h2 class="section-title">🛡️ Firewall Analysis</h2>
            <div class="info-card" style="border-color: {color};">
                <h3 style="color: {color};">{icon} {data['firewall_status']}</h3>
                <div class="firewall-stats">
                    <p>📊 Open: {len(data.get('open_ports', []))} |
                       🔴 Closed: {data.get('closed_ports_count', 0)} |
                       🟡 Filtered: {data.get('filtered_ports_count', 0)}</p>
                </div>
            </div>
        </div>'''


def _html_open_ports_rows(data):
    if not data.get('open_ports'):
        return '<tr><td colspan="3">No open ports found</td></tr>'
    rows = []
    for p in data['open_ports']:
        rows.append(f'<tr><td>{p["port"]}</td><td>{p["service"]}</td>'
                    f'<td><span class="badge badge-open">OPEN</span></td></tr>')
    return ''.join(rows)


def generate_html(data, raw_output):
    banners_html = _html_banners_section(data)
    firewall_html = _html_firewall_section(data)
    open_rows = _html_open_ports_rows(data)
    _, open_count, closed_count, filtered_count, _ = _compute_totals(data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Light-Scan Report - {data.get('target', 'Unknown')}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Consolas', 'Monaco', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #00ff41; padding: 20px; line-height: 1.6; }}
    .container {{ max-width: 1200px; margin: 0 auto;
                  background: rgba(0, 0, 0, 0.85); border-radius: 15px;
                  padding: 30px; box-shadow: 0 0 30px rgba(0, 255, 65, 0.2);
                  border: 1px solid #00ff41; }}
    h1 {{ font-size: 2.5em; text-align: center; margin-bottom: 10px;
          text-shadow: 0 0 10px #00ff41; }}
    .subtitle {{ text-align: center; color: #888; margin-bottom: 30px;
                 border-bottom: 1px solid #333; padding-bottom: 20px; }}
    .info-grid {{ display: grid;
                  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                  gap: 20px; margin-bottom: 30px; }}
    .info-card {{ background: rgba(0, 255, 65, 0.05);
                  border: 1px solid #00ff41; border-radius: 10px; padding: 15px;
                  transition: all 0.3s ease; }}
    .info-card:hover {{ transform: translateY(-3px);
                        box-shadow: 0 5px 20px rgba(0, 255, 65, 0.2);
                        background: rgba(0, 255, 65, 0.1); }}
    .info-card h3 {{ color: #00ff41; margin-bottom: 10px; font-size: 1.1em; }}
    .info-card p {{ color: #ccc; font-size: 1.2em; font-weight: bold; }}
    .section-title {{ font-size: 1.8em; margin-bottom: 20px;
                      padding-bottom: 10px; border-bottom: 2px solid #00ff41;
                      margin-top: 30px; }}
    .ports-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
    .ports-table th, .ports-table td {{ padding: 12px; text-align: left;
                                        border-bottom: 1px solid #333; }}
    .ports-table th {{ background: rgba(0, 255, 65, 0.1); color: #00ff41;
                       font-weight: bold; }}
    .ports-table tr:hover {{ background: rgba(0, 255, 65, 0.05); }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 5px;
              font-size: 0.85em; font-weight: bold; }}
    .badge-open {{ background: rgba(0, 255, 65, 0.2); color: #00ff41;
                   border: 1px solid #00ff41; }}
    .banner-card {{ background: rgba(0, 255, 65, 0.03);
                    border: 1px solid #00ff41; border-radius: 10px;
                    padding: 15px; margin-bottom: 15px; }}
    .banner-card h3 {{ color: #00ff41; margin-bottom: 10px; }}
    .banner-content pre {{ background: #0a0a0a; padding: 10px; border-radius: 5px;
                           overflow-x: auto; font-size: 0.85em; color: #ccc; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(3, 1fr);
                   gap: 20px; margin: 20px 0; }}
    .stat-card {{ text-align: center; padding: 20px;
                  background: rgba(0, 255, 65, 0.05); border-radius: 10px; }}
    .stat-number {{ font-size: 2.5em; font-weight: bold; }}
    .stat-label {{ color: #888; margin-top: 10px; }}
    .firewall-stats {{ margin-top: 10px; padding-top: 10px;
                       border-top: 1px solid #333; }}
    .raw-output {{ background: #0a0a0a; border: 1px solid #333;
                   border-radius: 10px; padding: 20px; margin-top: 30px;
                   overflow-x: auto; }}
    .raw-output pre {{ color: #00ff41; font-family: 'Consolas', monospace;
                       font-size: 0.85em; white-space: pre-wrap;
                       word-wrap: break-word; }}
    .footer {{ text-align: center; margin-top: 30px; padding-top: 20px;
               border-top: 1px solid #333; color: #666; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="container">
    <h1>🔍 Light-Scan Security Report</h1>
    <div class="subtitle">Professional Network Security Assessment</div>

    <div class="info-grid">
        <div class="info-card"><h3>🎯 Target</h3><p>{data.get('target', 'Unknown')}</p></div>
        <div class="info-card"><h3>⚡ Scan Type</h3><p>{data.get('scan_type', 'Unknown')}</p></div>
        <div class="info-card"><h3>⏱️ Scan Duration</h3><p>{data.get('scan_time', 'N/A')} seconds</p></div>
        <div class="info-card"><h3>🖥️ Host Status</h3><p>{data.get('host_status', 'Unknown')}</p></div>
    </div>

    {firewall_html}

    <div class="ports-section">
        <h2 class="section-title">📊 Open Ports ({open_count})</h2>
        <table class="ports-table">
            <thead><tr><th>Port</th><th>Service</th><th>Status</th></tr></thead>
            <tbody>{open_rows}</tbody>
        </table>
    </div>

    <div class="ports-section">
        <h2 class="section-title">📈 Scan Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-number" style="color: #00ff41;">{open_count}</div><div class="stat-label">🟢 Open Ports</div></div>
            <div class="stat-card"><div class="stat-number" style="color: #ff4444;">{closed_count}</div><div class="stat-label">🔴 Closed Ports</div></div>
            <div class="stat-card"><div class="stat-number" style="color: #ffaa00;">{filtered_count}</div><div class="stat-label">🟡 Filtered Ports</div></div>
        </div>
    </div>

    {banners_html}

    <div class="raw-output">
        <h3>📄 Raw Scan Output</h3>
        <pre>{html.escape(raw_output)}</pre>
    </div>

    <div class="footer">
        <p>Generated by Light-Save v{Version} | Light-Scan Security Tool | {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p style="color: #444">For authorized security testing only.</p>
    </div>
</div>
</body>
</html>"""


def generate_hexstr(raw_output):
    return raw_output.encode('utf-8').hex()

_PER_TARGET_GENERATORS = {
    "html": (generate_html, ".html", False),
    "xml":  (generate_xml,  ".xml",  False),
    "csv":  (generate_csv,  ".csv",  True),
    "json": (generate_json, ".json", False),
    "yaml": (generate_yaml, ".yaml", False),
    "toml": (generate_toml, ".toml", False),
}


def main(filename, format, output, tar_res, tar_list):

    print(f"[+] Saving to: {filename}\n")
    print("-" * 60)

    save_path = os.path.join(os.path.dirname(__file__), "Saving")
    os.makedirs(save_path, exist_ok=True)

    if not os.path.isfile("./Saving/empty.txt"):
        with open("./Saving/empty.txt", 'w', encoding='utf-8') as f:
            f.write("""# This is where you are gonna find your saving results
# Light-Scan developers wish you a good day""")

    fmt = format.lower()
    output = ANSI_ESCAPE.sub("", output)

    if fmt in ("txt", "light"):
        path = "./Saving/" + filename
        with open(path, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"\n[+] Scan saved to {path}")
        return

    if fmt == "hex-str":
        print("\n[+] Generating Hex-Str report...")
        content = generate_hexstr(output)
        path = "./Saving/" + filename.replace(".hex-str", ".hex")
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[+] Hex-Str report saved to {path}")
        return

    if fmt not in _PER_TARGET_GENERATORS:
        return

    gen_fn, ext, needs_newline = _PER_TARGET_GENERATORS[fmt]
    print(f"\n[+] Generating {fmt.upper()} report...")

    tar_index = 1
    for tar in tar_list:
        scan_dict = tar_res.get(tar)
        if not scan_dict:
            continue

        parsed = _scan_dict_to_report_data(scan_dict, tar)
        if not parsed.get('target'):
            continue

        content = gen_fn(parsed, output)

        base = filename.replace(ext, "")
        path = f"./Saving/{base}-Target{tar_index}{ext}"
        tar_index += 1

        kwargs = {'encoding': 'utf-8'}
        if needs_newline:
            kwargs['newline'] = ''

        with open(path, 'w', **kwargs) as f:
            f.write(content)

        print(f"[+] {fmt.upper()} report saved to {path}")
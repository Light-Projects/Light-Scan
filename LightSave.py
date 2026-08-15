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

import platform
import time
import re
import html
import datetime
import sys
import json
import csv
import os
import io
import yaml
import toml
from font import fontpath

Version = "1.0.2"
fontpath()

def parse_scan_output(output):
    results = {
        'target': None,
        'scan_type': None,
        'open_ports': [],
        'closed_ports': [],
        'closed_ports_count': 0,
        'filtered_ports': [],
        'filtered_ports_count': 0,
        'os_fingerprint': None,
        'firewall_status': None,
        'firewall_detected': None,
        'scan_time': None,
        'scan_date': datetime.datetime.now().isoformat(),
        'version': None,
        'banners': [],
        'lsse_scripts': [],
        'lsse_response': None,
        'lsse_scripts_detected': [],
        'mac_address': None,
        'ip_status': None,
        'host_status': None
    }

    version_match = re.search(r'Version : ([\d\.]+)', output)
    if version_match:
        results['version'] = version_match.group(1)

    target_match = re.search(r'\[\+\] Scan result for : (.+)', output)
    if target_match:
        results['target'] = target_match.group(1)

    host_match = re.search(fr'Host {results['target']} is (up|down)!', output)
    if host_match:
        results['host_status'] = host_match.group(2)
        if not results['target']:
            results['target'] = host_match.group(1)


    ip_status_match = re.search(r'\[\+\] IP Status: (.+)', output)
    if ip_status_match:
        results['ip_status'] = ip_status_match.group(1)

    mac_match = re.search(r'\[\+\] Mac Address: ([0-9a-fA-F:]+)', output)
    if mac_match:
        results['mac_address'] = mac_match.group(1)

    type_match = re.search(r'Scan Type: (.+) \|', output)
    if type_match:
        results['scan_type'] = type_match.group(1)

    open_section = re.search(r'\[\+\] Open Ports: (\d+)(.*?)(?=\[\+\] Closed Ports:|$)', output, re.DOTALL)
    if open_section:
        results['open_ports_count'] = int(open_section.group(1))
        open_text = open_section.group(2)

        port_matches = re.findall(r'Port (\d+) ([^\s]+)', open_text)
        for port, service in port_matches:
            results['open_ports'].append({'port': port, 'service': service.strip()})

    closed_match = re.search(r'\[\+\] Closed Ports: (\d+)', output)
    if closed_match:
        results['closed_ports_count'] = int(closed_match.group(1))

    filtered_match = re.search(r'\[\+\] Filtered Ports: (\d+)', output)
    if filtered_match:
        results['filtered_ports_count'] = int(filtered_match.group(1))

    banner_section = re.search(
        r'\[\+\] Captured Banner/s: (\d+)\s*(.*?)(?=\[\+\] OS Fingerprint Results|\[\+\] Lightscan scanned|$)',
        output, re.DOTALL)
    if banner_section:
        banner_count = int(banner_section.group(1))
        banner_text = banner_section.group(2)

        banner_matches = re.findall(
            r'\[\*\] Banner from Port (\d+):(.*?)={10,}(.*?)={10,}',
            banner_text, re.DOTALL
        )
        for port, version_line, banner_content in banner_matches:
            results['banners'].append({
                'port': port,
                'version': version_line.strip(),
                'content': banner_content.strip()
            })

    firewall_section = re.search(
        r'\[\!\] Firewall Analysis for .+?:\s*(.*?)(?=\[\+\] Captured Banner/s:|\[\+\] OS Fingerprint Results|\[\+\] Lightscan scanned|$)',
        output, re.DOTALL)
    if firewall_section:
        firewall_text = firewall_section.group(1)

        conclusion_match = re.search(r'\[\+\] (.+?)(?=\n|$)', firewall_text)
        if conclusion_match:
            conclusion = conclusion_match.group(1).strip()
            results['firewall_status'] = conclusion

            if 'STRONG FIREWALL DETECTED' in conclusion:
                results['firewall_detected'] = 'STRONG'
            elif 'NO FIREWALL DETECTED' in conclusion:
                results['firewall_detected'] = 'NONE'
            elif 'WEAK FIREWALL' in conclusion:
                results['firewall_detected'] = 'WEAK'
            else:
                results['firewall_detected'] = 'UNKNOWN'

    block_match = re.search(
        r'\[\+\] OS Fingerprint Results.*?:\n(.*?)(?=\n\[\+\]\s*\w.*Results|\n\n|\Z)',
        output,
        re.DOTALL
    )

    if block_match:
        block = block_match.group(1)
        entries = re.findall(r'\[\+\]\s+(.+?):\s+(\d+\.?\d*)%', block)
        results['os_fingerprint'] = {'os':entries[0][0],'confidence':entries[0][1]}

    time_match = re.search(r'\[\*\] Scan completed in ([\d\.]+) seconds', output)
    if time_match:
        results['scan_time'] = time_match.group(1)

    lsse_response_match = re.search(r'\[\+\] LSSE Response for (.+?):', output)
    if lsse_response_match:
        results['lsse_response'] = lsse_response_match.group(1)

    return results


def generate_pdf(data, raw_output):
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72,
        title=f"LightScan Report - {data.get('target', 'Unknown')}",
        author="LightSave",
        subject="Network Security Assessment"
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#00cc44'),
        alignment=TA_CENTER,
        spaceAfter=30,
        fontName='Helvetica-Bold'
    )

    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#00cc44'),
        spaceAfter=12,
        spaceBefore=20,
        fontName='Helvetica-Bold'
    )

    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#00cc44'),
        spaceAfter=8,
        spaceBefore=15,
        fontName='Helvetica-Bold'
    )

    info_style = ParagraphStyle(
        'InfoStyle',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.black,
        spaceAfter=6,
        fontName='Helvetica'
    )

    mono_style = ParagraphStyle(
        'MonoStyle',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#333333'),
        fontName='Courier',
        spaceAfter=4,
        leading=12
    )

    story = []

    story.append(Paragraph("[+] Light-Scan", title_style))
    story.append(Paragraph("Professional Security Assessment Report",
                           ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=16,
                                          textColor=colors.grey, alignment=TA_CENTER, spaceAfter=30)))

    target_info = f"""
    <b>Target:</b> {data.get('target', 'Unknown')}<br/>
    <b>Scan Type:</b> {data.get('scan_type', 'Unknown')}<br/>
    <b>Scan Date:</b> {data.get('scan_date', datetime.datetime.now().isoformat())}<br/>
    <b>Duration:</b> {data.get('scan_time', 'N/A')} seconds<br/>
    <b>LightScan Version:</b> {data.get('version', 'Unknown')}
    """
    story.append(Paragraph(target_info, info_style))
    story.append(Spacer(0, 0.5 * inch))
    story.append(Paragraph("Executive Summary", heading1_style))

    total = len(data.get('open_ports', [])) + data.get('closed_ports_count', 0) + data.get('filtered_ports_count', 0)
    open_pct = round((len(data.get('open_ports', [])) / max(1, total)) * 100, 1)

    summary_text = f"""
    <b>Host Status:</b> {data.get('host_status', 'Unknown').upper()}<br/>
    <b>Total Ports Scanned:</b> {total}<br/>
    <b>Open Ports:</b> {len(data.get('open_ports', []))} ({open_pct}%)<br/>
    <b>Closed Ports:</b> {data.get('closed_ports_count', 0)}<br/>
    <b>Filtered Ports:</b> {data.get('filtered_ports_count', 0)}
    """
    if data.get('firewall_status'):
        firewall_icon = "" if data.get('firewall_detected') == 'STRONG' else "" if data.get(
            'firewall_detected') == 'NONE' else "️"
        story.append(Paragraph(f"{firewall_icon} <b>Firewall Status:</b> {data['firewall_status']}", info_style))

    if data.get('os_fingerprint'):
        story.append(Paragraph(f" <b>Detected OS:</b> {data['os_fingerprint'].get('os', 'Unknown')} "
                               f"({data['os_fingerprint'].get('confidence', '0')}% confidence)", info_style))
    story.append(Paragraph(summary_text, info_style))


    total = len(data.get('open_ports', [])) + data.get('closed_ports_count', 0) + data.get('filtered_ports_count', 0)
    open_pct = round((len(data.get('open_ports', [])) / max(1, total)) * 100, 1)

    story.append(PageBreak())
    story.append(Paragraph("Open Ports", heading1_style))

    if data.get('open_ports'):
        table_data = [['Port', 'Service', 'Status', 'Banner']]
        for port in data.get('open_ports', []):
            banner = next((b['content'][:50] + '...' if len(b['content']) > 50 else b['content']
                           for b in data.get('banners', []) if str(b['port']) == str(port['port'])), '')
            clean_banner = banner.replace('\n', ' ').replace('\r', '')[:100]
            table_data.append([
                str(port['port']),
                port['service'],
                'OPEN',
                clean_banner if clean_banner else '-'
            ])

        table = Table(table_data, colWidths=[0.8 * inch, 2.25 * inch, 1 * inch, 3.5 * inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00cc44')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
        ]))
        story.append(table)
    else:
        story.append(Paragraph("No open ports found.", info_style))

    if data.get('banners'):
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph("Banner Capture", heading2_style))

        for banner in data['banners']:
            banner_text = f"<b>Port {banner['port']}:</b><br/>{banner['content'][:500]}"
            if len(banner['content']) > 500:
                banner_text += "... (truncated)"
            story.append(Paragraph(banner_text, mono_style))
            story.append(Spacer(1, 0.1 * inch))

    if data.get('firewall_status'):
        story.append(PageBreak())
        story.append(Paragraph("Firewall Analysis", heading1_style))

        firewall_color = "#00cc44" if data.get('firewall_detected') == 'NONE' else "#ffaa00" if data.get(
            'firewall_detected') == 'WEAK' else "#ff4444"
        firewall_text = f"""
        <b>Status:</b> {data['firewall_status']}<br/>
        <b>Classification:</b> {data.get('firewall_detected', 'UNKNOWN')}
        """
        story.append(Paragraph(firewall_text, info_style))

        stats_data = [
            ['Metric', 'Value'],
            ['Open Ports', str(len(data.get('open_ports', [])))],
            ['Closed Ports', str(data.get('closed_ports_count', 0))],
            ['Filtered Ports', str(data.get('filtered_ports_count', 0))]
        ]
        stats_table = Table(stats_data, colWidths=[2 * inch, 2 * inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#00cc44')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f5f5f5')),
        ]))
        story.append(stats_table)

    if data.get('os_fingerprint') and data['os_fingerprint'].get('os'):
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph("Operating System Fingerprint", heading2_style))
        story.append(Paragraph(f"<b>Detected OS:</b> {data['os_fingerprint'].get('os', 'Unknown')}", info_style))
        story.append(Paragraph(f"<b>Confidence:</b> {data['os_fingerprint'].get('confidence', '0')}%", info_style))

    if data.get('lsse_response') or data.get('lsse_scripts_detected'):
        story.append(PageBreak())
        story.append(Paragraph("LSSE Script Engine Results", heading1_style))

        if data.get('lsse_response'):
            story.append(Paragraph(f"<b>Target URL:</b> {data['lsse_response']}", info_style))

        if data.get('lsse_scripts_detected'):
            story.append(Spacer(1, 0.2 * inch))
            story.append(Paragraph("Detected Scripts:", heading2_style))
            for idx, script in enumerate(data['lsse_scripts_detected'][:10], 1):
                clean_script = script[:200].replace('\n', ' ').replace('\r', '')
                story.append(Paragraph(f"{idx}. {clean_script}", mono_style))
            if len(data['lsse_scripts_detected']) > 10:
                story.append(Paragraph(f"... and {len(data['lsse_scripts_detected']) - 10} more", info_style))

        for script in data.get('lsse_scripts', []):
            if script.get('type') == 'subdomain':
                story.append(Spacer(1, 0.2 * inch))
                story.append(Paragraph(f" Subdomain: {script.get('name', 'Unknown')} → {script.get('ip', 'Unknown')}",
                                       info_style))
            elif script.get('type') == 'ssl_cert':
                story.append(Spacer(1, 0.2 * inch))
                story.append(Paragraph(" SSL/TLS Certificate:", heading2_style))
                for key, value in script.get('data', {}).items():
                    if key.lower() in ['notbefore', 'notafter', 'subject', 'issuer']:
                        story.append(Paragraph(f"<b>{key}:</b> {value}", info_style))

    story.append(PageBreak())
    story.append(Paragraph("Raw Scan Output", heading1_style))

    output_lines = raw_output.split('\n')

    for line in output_lines:
        if line.strip():
            story.append(Paragraph(html.escape(line), mono_style))

    story.append(Spacer(0, 0.1 * inch))
    story.append(Paragraph(
        f"Report generated by LightSave v{Version} on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9,
                       textColor=colors.grey, alignment=TA_CENTER)))
    story.append(Paragraph("For authorized security testing only.",
                           ParagraphStyle('Footer2', parent=styles['Normal'], fontSize=8,
                                          textColor=colors.grey, alignment=TA_CENTER)))

    doc.build(story)

    pdf_data = buffer.getvalue()
    buffer.close()

    return pdf_data


def generate_toml(data, raw_output):
    lsse_scripts_processed = []

    for script in data.get('lsse_scripts', []):
        if script.get('type') == 'subdomain':
            lsse_scripts_processed.append({
                'type': 'subdomain',
                'subdomain': script.get('name'),
                'ip': script.get('ip')
            })
        elif script.get('type') == 'ssl_cert':
            lsse_scripts_processed.append({
                'type': 'ssl_certificate',
                'certificate_data': script.get('data', {})
            })
        elif script.get('type') == 'http_title':
            lsse_scripts_processed.append({
                'type': 'http_titles',
                'titles': script.get('titles', [])
            })
        elif script.get('type') == 'robots':
            lsse_scripts_processed.append({
                'type': 'robots_txt',
                'disallowed_paths': script.get('disallowed', []),
                'sitemaps': script.get('sitemaps', [])
            })

    open_ports_enriched = []
    for port in data.get('open_ports', []):
        port_num = port.get('port')
        banner_info = next((b for b in data.get('banners', [])
                            if str(b.get('port')) == str(port_num)), None)

        open_ports_enriched.append({
            'port': port_num,
            'service': port.get('service'),
            'status': 'OPEN',
            'banner': banner_info.get('content') if banner_info else None,
            'banner_length': len(banner_info.get('content', '')) if banner_info else 0
        })

    total_ports = len(data.get('open_ports', [])) + data.get('closed_ports_count', 0) + data.get('filtered_ports_count',
                                                                                                 0)
    open_pct = round((len(data.get('open_ports', [])) / max(1, total_ports)) * 100, 2)

    toml_data = {
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
            'mac_address': data.get('mac_address')
        },
        'summary': {
            'total_ports_scanned': total_ports,
            'open_ports_count': len(data.get('open_ports', [])),
            'closed_ports_count': data.get('closed_ports_count', 0),
            'filtered_ports_count': data.get('filtered_ports_count', 0),
            'open_ports_percentage': open_pct,
            'banners_found': len(data.get('banners', [])),
            'has_firewall': data.get('firewall_status') is not None and
                            'NO FIREWALL DETECTED' not in data.get('firewall_status', ''),
            'os_identified': data.get('os_fingerprint') is not None
        },
        'firewall_analysis': {
            'status': data.get('firewall_status'),
            'detection_method': data.get('firewall_detected')
        } if data.get('firewall_status') else None,
        'os_fingerprint': data.get('os_fingerprint'),
        'open_ports': open_ports_enriched,
        'closed_ports': data.get('closed_ports', []) if data.get('closed_ports') else None,
        'filtered_ports': data.get('filtered_ports', []) if data.get('filtered_ports') else None,
        'banners_captured': data.get('banners', []) if data.get('banners') else None,
        'lsse_results': {
            'target_url': data.get('lsse_response'),
            'scripts_detected_count': len(data.get('lsse_scripts_detected', [])),
            'scripts_detected': data.get('lsse_scripts_detected', []),
            'script_results': lsse_scripts_processed
        } if data.get('lsse_response') or lsse_scripts_processed else None,
        'raw_output': raw_output
    }

    def clean_none(obj):
        if isinstance(obj, dict):
            return {k: clean_none(v) for k, v in obj.items() if v is not None}
        elif isinstance(obj, list):
            return [clean_none(item) for item in obj if item is not None]
        else:
            return obj

    toml_data = clean_none(toml_data)

    return toml.dumps(toml_data)

def generate_yaml(data, raw_output):
    lsse_scripts_processed = []

    open_ports_enriched = []
    for port in data.get('open_ports', []):
        port_num = port.get('port')
        banner_info = next((b for b in data.get('banners', [])
                            if str(b.get('port')) == str(port_num)), None)

        open_ports_enriched.append({
            'port': port_num,
            'service': port.get('service'),
            'status': 'OPEN',
            'banner': banner_info.get('content') if banner_info else None,
            'banner_length': len(banner_info.get('content', '')) if banner_info else 0
        })

    total_ports = len(data.get('open_ports', [])) + data.get('closed_ports_count', 0) + data.get('filtered_ports_count',
                                                                                                 0)
    open_pct = round((len(data.get('open_ports', [])) / max(1, total_ports)) * 100, 2)

    yaml_data = {
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
            'mac_address': data.get('mac_address')
        },
        'summary': {
            'total_ports_scanned': total_ports,
            'open_ports_count': len(data.get('open_ports', [])),
            'closed_ports_count': data.get('closed_ports_count', 0),
            'filtered_ports_count': data.get('filtered_ports_count', 0),
            'open_ports_percentage': open_pct,
            'banners_found': len(data.get('banners', [])),
            'has_firewall': data.get('firewall_status') is not None and
                            'NO FIREWALL DETECTED' not in data.get('firewall_status', ''),
            'os_identified': data.get('os_fingerprint') is not None
        },
        'firewall_analysis': {
            'status': data.get('firewall_status'),
            'detection_method': data.get('firewall_detected')
        } if data.get('firewall_status') else None,
        'os_fingerprint': data.get('os_fingerprint'),
        'open_ports': open_ports_enriched,
        'closed_ports': data.get('closed_ports', []) if data.get('closed_ports') else None,
        'filtered_ports': data.get('filtered_ports', []) if data.get('filtered_ports') else None,
        'banners_captured': data.get('banners', []) if data.get('banners') else None,
        'lsse_results': {
            'target_url': data.get('lsse_response'),
            'scripts_detected_count': len(data.get('lsse_scripts_detected', [])),
            'scripts_detected': data.get('lsse_scripts_detected', []),
            'script_results': lsse_scripts_processed
        } if data.get('lsse_response') or lsse_scripts_processed else None,
        'raw_output': raw_output
    }

    def clean_none(obj):
        if isinstance(obj, dict):
            return {k: clean_none(v) for k, v in obj.items() if v is not None}
        elif isinstance(obj, list):
            return [clean_none(item) for item in obj if item is not None]
        else:
            return obj

    yaml_data = clean_none(yaml_data)

    return yaml.dump(
        yaml_data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        indent=2,
        line_break='\n'
    )

def generate_csv(data, raw_output):
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(['#' * 60])
    writer.writerow(['# LightScan Security Report'])
    writer.writerow(['# Generated by LightSave v' + Version])
    writer.writerow(['# Generated on: ' + data.get('scan_date', 'Unknown')])
    writer.writerow(['#' * 60])
    writer.writerow([])

    writer.writerow(['[SCAN INFORMATION]'])
    writer.writerow(['-' * 40])
    writer.writerow(['Parameter', 'Value'])
    writer.writerow(['Target', data.get('target', 'Unknown')])
    writer.writerow(['Scan Type', data.get('scan_type', 'Unknown')])
    writer.writerow(['Scan Duration (seconds)', data.get('scan_time', '0')])
    writer.writerow(['IP Status', data.get('ip_status', 'Unknown')])
    writer.writerow(['MAC Address', data.get('mac_address', 'Unknown')])
    writer.writerow(['Host Status', data.get('host_status', 'Unknown')])
    writer.writerow(['LightScan Version', data.get('version', 'Unknown')])
    writer.writerow([])

    writer.writerow(['[FIREWALL ANALYSIS]'])
    writer.writerow(['-' * 40])
    writer.writerow(['Status', data.get('firewall_status', 'Unknown')])
    writer.writerow(['Detection Method', data.get('firewall_detected', 'Unknown')])
    writer.writerow([])

    total = len(data.get('open_ports', [])) + data.get('closed_ports_count', 0) + data.get('filtered_ports_count', 0)
    writer.writerow(['[SCAN STATISTICS]'])
    writer.writerow(['-' * 40])
    writer.writerow(['Metric', 'Count'])
    writer.writerow(['Total Ports Scanned', total])
    writer.writerow(['Open Ports', len(data.get('open_ports', []))])
    writer.writerow(['Closed Ports', data.get('closed_ports_count', 0)])
    writer.writerow(['Filtered Ports', data.get('filtered_ports_count', 0)])

    if total > 0:
        open_pct = (len(data.get('open_ports', [])) / total) * 100
        writer.writerow(['Open Ports Percentage', f'{open_pct:.1f}%'])
    writer.writerow([])

    if data.get('os_fingerprint') and data['os_fingerprint'].get('os'):
        writer.writerow(['[OS FINGERPRINT]'])
        writer.writerow(['-' * 40])
        writer.writerow(['Detected Operating System', data['os_fingerprint'].get('os', 'Unknown')])
        writer.writerow(['Confidence Score', f"{data['os_fingerprint'].get('confidence', '0')}%"])
        writer.writerow([])


    writer.writerow(['[OPEN PORTS SUMMARY]'])
    writer.writerow(['-' * 40])
    if data.get('open_ports'):
        writer.writerow(['Port', 'Service', 'Status', 'Banner (truncated)'])
        writer.writerow(['----', '-------', '------', '----------------'])
        for port in data.get('open_ports', []):
            banner = next((b['content'] for b in data.get('banners', []) if str(b['port']) == str(port['port'])), '')
            clean_banner = banner.replace('\n', ' ').replace('\r', '')[:200]
            writer.writerow([port['port'], port['service'], 'OPEN', clean_banner if clean_banner else '(no banner)'])
    else:
        writer.writerow(['No open ports found'])
    writer.writerow([])

    if data.get('closed_ports'):
        writer.writerow(['[CLOSED PORTS]'])
        writer.writerow(['-' * 40])
        writer.writerow(['Port'])
        for port in data['closed_ports']:
            writer.writerow([port])
        writer.writerow([])

    if data.get('filtered_ports'):
        writer.writerow(['[FILTERED PORTS]'])
        writer.writerow(['-' * 40])
        writer.writerow(['Port'])
        for port in data['filtered_ports']:
            writer.writerow([port])
        writer.writerow([])

    if data.get('banners'):
        writer.writerow(['[BANNER CAPTURE DETAILS]'])
        writer.writerow(['-' * 40])
        writer.writerow(['Port', 'Full Banner Content'])
        writer.writerow(['----', '--------------------'])
        for banner in data['banners']:
            clean_banner = banner['content'].replace('\n', ' ').replace('\r', '')[:500]
            writer.writerow([banner['port'], clean_banner])
        writer.writerow([])

    if data.get('lsse_response') or data.get('lsse_scripts_detected') or data.get('lsse_scripts'):
        writer.writerow(['[LSSE SCRIPT ENGINE RESULTS]'])
        writer.writerow(['-' * 40])

        if data.get('lsse_response'):
            writer.writerow(['Target URL/Host', data['lsse_response']])

        if data.get('lsse_scripts_detected'):
            writer.writerow(['\n[JavaScript Files Detected]'])
            writer.writerow(['#', 'Script Source'])
            for idx, script in enumerate(data['lsse_scripts_detected'], 1):
                clean_script = script[:300].replace('\n', ' ').replace('\r', '')
                writer.writerow([f'#{idx}', clean_script + ('...' if len(script) > 300 else '')])

        for script in data.get('lsse_scripts', []):
            if script.get('type') == 'subdomain':
                writer.writerow(['\n[Subdomain Discovered]'])
                writer.writerow(['Subdomain', script.get('name', 'Unknown')])
                writer.writerow(['IP Address', script.get('ip', 'Unknown')])
            elif script.get('type') == 'ssl_cert':
                writer.writerow(['\n[SSL/TLS Certificate Info]'])
                for key, value in script.get('data', {}).items():
                    writer.writerow([f'  {key}', str(value)[:200]])
            elif script.get('type') == 'http_title':
                writer.writerow(['\n[HTTP Page Titles]'])
                writer.writerow(['Page Title'])
                for title in script.get('titles', []):
                    writer.writerow([title])
            elif script.get('type') == 'robots':
                writer.writerow(['\n[Robots.txt Entries]'])
                writer.writerow(['Disallowed Paths'])
                for path in script.get('disallowed', []):
                    writer.writerow([path])
            elif script.get('type') == 'cert_info':
                writer.writerow(['\n[Certificate Information]'])
                for key, value in script.get('data', {}).items():
                    writer.writerow([f'  {key}', str(value)[:200]])

        writer.writerow([])

    writer.writerow(['#' * 60])
    writer.writerow(['# RAW SCANNER OUTPUT'])
    writer.writerow(['#' * 60])
    writer.writerow([])


    if raw_output:
        for line in raw_output.split('\n'):
            if line.strip():
                writer.writerow([line])
            else:
                writer.writerow([''])
    else:
        writer.writerow(['(No raw output available)'])

    writer.writerow([])
    writer.writerow(['#' * 60])
    writer.writerow(['# End of Report'])
    writer.writerow(['#' * 60])

    return output.getvalue()


def generate_json(data, raw_output):
    lsse_scripts_processed = []
    for script in data.get('lsse_scripts', []):
        if script.get('type') == 'subdomain':
            lsse_scripts_processed.append({
                'type': 'subdomain',
                'subdomain': script.get('name'),
                'ip': script.get('ip')
            })
        elif script.get('type') == 'ssl_cert':
            lsse_scripts_processed.append({
                'type': 'ssl_certificate',
                'certificate_data': script.get('data', {})
            })
        elif script.get('type') == 'http_title':
            lsse_scripts_processed.append({
                'type': 'http_titles',
                'titles': script.get('titles', [])
            })
        elif script.get('type') == 'robots':
            lsse_scripts_processed.append({
                'type': 'robots_txt',
                'disallowed_paths': script.get('disallowed', []),
                'sitemaps': script.get('sitemaps', [])
            })
        elif script.get('type') == 'cert_info':
            lsse_scripts_processed.append({
                'type': 'certificate_info',
                'details': script.get('data', {})
            })
        elif script.get('type') == 'http_dir':
            lsse_scripts_processed.append({
                'type': 'directory_bruteforce',
                'found_directories': script.get('directories', []),
                'wordlist_used': script.get('wordlist'),
                'total_tested': script.get('total_tested', 0)
            })

    closed_ports_list = data.get('closed_ports', [])
    filtered_ports_list = data.get('filtered_ports', [])

    open_ports_enriched = []
    for port in data.get('open_ports', []):
        port_num = port.get('port')
        banner_info = next((b for b in data.get('banners', []) if str(b.get('port')) == str(port_num)), None)

        open_ports_enriched.append({
            'port': port_num,
            'service': port.get('service'),
            'status': 'OPEN',
            'banner': banner_info.get('content') if banner_info else None,
            'banner_length': len(banner_info.get('content', '')) if banner_info else 0
        })

    json_data = {
        'metadata': {
            'version': data.get('version'),
            'scan_date': data.get('scan_date'),
            'target': data.get('target'),
            'scan_type': data.get('scan_type'),
            'scan_time_seconds': float(data.get('scan_time', 0)) if data.get('scan_time') else None,
            'ip_status': data.get('ip_status'),
            'mac_address': data.get('mac_address'),
            'host_status': data.get('host_status'),
            'lightscan_version': data.get('version')
        },
        'firewall_analysis': {
            'status': data.get('firewall_status'),
            'detection_method': data.get('firewall_detected'),
            'firewall_detected': data.get(
                'firewall_status') != 'NO FIREWALL DETECTED : no such filtered or open | filtered ports'
        } if data.get('firewall_status') else None,
        'os_fingerprint': data.get('os_fingerprint'),
        'statistics': {
            'total_ports_scanned': len(data.get('open_ports', [])) + data.get('closed_ports_count', 0) + data.get(
                'filtered_ports_count', 0),
            'open_ports_count': len(data.get('open_ports', [])),
            'closed_ports_count': data.get('closed_ports_count', 0),
            'filtered_ports_count': data.get('filtered_ports_count', 0),
            'open_ports_percentage': round((len(data.get('open_ports', [])) / max(1, len(data.get('open_ports',
                                                                                                  [])) + data.get(
                'closed_ports_count', 0) + data.get('filtered_ports_count', 0))) * 100, 2)
        },
        'open_ports': open_ports_enriched,
        'closed_ports': closed_ports_list if closed_ports_list else None,
        'filtered_ports': filtered_ports_list if filtered_ports_list else None,
        'banners_captured': data.get('banners', []),
        'lsse_results': {
            'target': data.get('lsse_response'),
            'scripts_detected_count': len(data.get('lsse_scripts_detected', [])),
            'scripts_detected': data.get('lsse_scripts_detected', []),
            'script_results': lsse_scripts_processed if lsse_scripts_processed else None
        } if data.get('lsse_response') or lsse_scripts_processed else None,
        'raw_output': raw_output,
        'summary': {
            'success': len(data.get('open_ports', [])) > 0 or data.get('closed_ports_count', 0) > 0,
            'has_firewall': data.get(
                'firewall_status') != 'NO FIREWALL DETECTED : no such filtered or open | filtered ports' if data.get(
                'firewall_status') else None,
            'os_identified': data.get('os_fingerprint') is not None and data.get('os_fingerprint', {}).get(
                'os') is not None,
            'banners_found': len(data.get('banners', []))
        }
    }

    def clean_none(obj):
        if isinstance(obj, dict):
            return {k: clean_none(v) for k, v in obj.items() if v is not None}
        elif isinstance(obj, list):
            return [clean_none(item) for item in obj]
        else:
            return obj

    json_data = clean_none(json_data)

    return json.dumps(json_data, indent=2, ensure_ascii=False)


def stream_output(process, output_lines):
    for line in iter(process.stdout.readline, ''):
        if line:
            print(line, end='')
            sys.stdout.flush()
            output_lines.append(line)
    for line in iter(process.stderr.readline, ''):
        if line:
            print(line, end='')
            sys.stderr.flush()
            output_lines.append(line)


def generate_html(data, raw_output):
    banners_html = ""
    if data['banners']:
        banners_html = f'''
        <div class="ports-section">
            <h2 class="section-title"> Captured Banners ({len(data['banners'])})</h2>
            <div class="banners-grid">
        '''
        for banner in data['banners']:
            banners_html += f'''
                <div class="banner-card">
                    <h3> Port {banner['port']}</h3>
                    <div class="banner-content">
                        <pre>{html.escape(banner['content'])}</pre>
                    </div>
                </div>
            '''
        banners_html += '''
            </div>
        </div>
        '''

    firewall_html = ""
    if data.get('firewall_status'):
        firewall_color = "#00ff41" if data.get('firewall_detected') == 'NONE' else "#ffaa00" if data.get(
            'firewall_detected') == 'WEAK' else "#ff4444"
        firewall_icon = "🛡️" if data.get('firewall_detected') == 'STRONG' else "🔓" if data.get(
            'firewall_detected') == 'NONE' else "⚠️"
        firewall_html = f'''
        <div class="ports-section">
            <h2 class="section-title">🛡️ Firewall Analysis</h2>
            <div class="info-card" style="border-color: {firewall_color};">
                <h3 style="color: {firewall_color};">{firewall_icon} {data['firewall_status']}</h3>
                <div class="firewall-stats">
                    <p>📊 Open: {len(data.get('open_ports', []))} | 🔴 Closed: {data.get('closed_ports_count', 0)} | 🟡 Filtered: {data.get('filtered_ports_count', 0)}</p>
                </div>
            </div>
        </div>
        '''

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Light-Scan Report - {data.get('target', 'Unknown')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Consolas', 'Monaco', monospace;
            background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 100%);
            color: #00ff41;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(0, 0, 0, 0.85);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 0 30px rgba(0, 255, 65, 0.2);
            border: 1px solid #00ff41;
        }}
        h1 {{ font-size: 2.5em; text-align: center; margin-bottom: 10px; text-shadow: 0 0 10px #00ff41; }}
        .subtitle {{ text-align: center; color: #888; margin-bottom: 30px; border-bottom: 1px solid #333; padding-bottom: 20px; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .info-card {{
            background: rgba(0, 255, 65, 0.05);
            border: 1px solid #00ff41;
            border-radius: 10px;
            padding: 15px;
            transition: all 0.3s ease;
        }}
        .info-card:hover {{ transform: translateY(-3px); box-shadow: 0 5px 20px rgba(0, 255, 65, 0.2); background: rgba(0, 255, 65, 0.1); }}
        .info-card h3 {{ color: #00ff41; margin-bottom: 10px; font-size: 1.1em; }}
        .info-card p {{ color: #ccc; font-size: 1.2em; font-weight: bold; }}
        .section-title {{ font-size: 1.8em; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #00ff41; margin-top: 30px; }}
        .ports-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        .ports-table th, .ports-table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #333; }}
        .ports-table th {{ background: rgba(0, 255, 65, 0.1); color: #00ff41; font-weight: bold; }}
        .ports-table tr:hover {{ background: rgba(0, 255, 65, 0.05); }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 5px; font-size: 0.85em; font-weight: bold; }}
        .badge-open {{ background: rgba(0, 255, 65, 0.2); color: #00ff41; border: 1px solid #00ff41; }}
        .badge-closed {{ background: rgba(255, 68, 68, 0.2); color: #ff4444; border: 1px solid #ff4444; }}
        .badge-filtered {{ background: rgba(255, 170, 0, 0.2); color: #ffaa00; border: 1px solid #ffaa00; }}
        .banner-card {{
            background: rgba(0, 255, 65, 0.03);
            border: 1px solid #00ff41;
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 15px;
        }}
        .banner-card h3 {{ color: #00ff41; margin-bottom: 10px; }}
        .banner-content pre {{
            background: #0a0a0a;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.85em;
            color: #ccc;
        }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-card {{ text-align: center; padding: 20px; background: rgba(0, 255, 65, 0.05); border-radius: 10px; }}
        .stat-number {{ font-size: 2.5em; font-weight: bold; }}
        .stat-label {{ color: #888; margin-top: 10px; }}
        .firewall-stats {{ margin-top: 10px; padding-top: 10px; border-top: 1px solid #333; }}
        .raw-output {{ background: #0a0a0a; border: 1px solid #333; border-radius: 10px; padding: 20px; margin-top: 30px; overflow-x: auto; }}
        .raw-output pre {{ color: #00ff41; font-family: 'Consolas', monospace; font-size: 0.85em; white-space: pre-wrap; word-wrap: break-word; }}
        .footer {{ text-align: center; margin-top: 30px; padding-top: 20px; border-top: 1px solid #333; color: #666; font-size: 0.85em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 <span style="background: linear-gradient(90deg, #00ff41 0%, #008f1f 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;">Light-Scan Security Report</span></h1>
        <div class="subtitle">Professional Network Security Assessment</div>

        <div class="info-grid">
            <div class="info-card"><h3>🎯 Target</h3><p>{data.get('target', 'Unknown')}</p></div>
            <div class="info-card"><h3>⚡ Scan Type</h3><p>{data.get('scan_type', 'Unknown')}</p></div>
            <div class="info-card"><h3>⏱️ Scan Duration</h3><p>{data.get('scan_time', 'N/A')} seconds</p></div>
            <div class="info-card"><h3>🖥️ Host Status</h3><p>{data.get('host_status', 'Unknown')}</p></div>
        </div>

        {firewall_html}

        <div class="ports-section">
            <h2 class="section-title">📊 Open Ports ({len(data.get('open_ports', []))})</h2>
            <table class="ports-table">
                <thead><tr><th>Port</th><th>Service</th><th>Status</th></tr></thead>
                <tbody>
                    {''.join([f'<tr><td>{p["port"]}</td><td>{p["service"]}</td><td><span class="badge badge-open">OPEN</span></td></tr>' for p in data.get('open_ports', [])]) or '<tr><td colspan="3">No open ports found</td></tr>'}
                </tbody>
            </table>
        </div>

        <div class="ports-section">
            <h2 class="section-title">📈 Scan Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card"><div class="stat-number" style="color: #00ff41;">{len(data.get('open_ports', []))}</div><div class="stat-label">🟢 Open Ports</div></div>
                <div class="stat-card"><div class="stat-number" style="color: #ff4444;">{data.get('closed_ports_count', 0)}</div><div class="stat-label">🔴 Closed Ports</div></div>
                <div class="stat-card"><div class="stat-number" style="color: #ffaa00;">{data.get('filtered_ports_count', 0)}</div><div class="stat-label">🟡 Filtered Ports</div></div>
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

    return html_template


def generate_xml(data, raw_output):
    if raw_output is None:
        raw_output = ""

    raw_output = str(raw_output) if raw_output is not None else ""

    prettified_output = '\n'.join(raw_output.splitlines())

    xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>']

    xml_parts.append(
        f'<LightScanReport version="{data.get("version", "1.1.6")}" generated="{data.get("scan_date", datetime.datetime.now().isoformat())}">')

    xml_parts.append('  <ScanInfo>')
    xml_parts.append(f'    <Target>{html.escape(str(data.get("target", "Unknown")))}</Target>')
    xml_parts.append(f'    <ScanType>{html.escape(str(data.get("scan_type", "Unknown")))}</ScanType>')
    xml_parts.append(f'    <Duration>{data.get("scan_time", "0")} seconds</Duration>')
    xml_parts.append(f'    <Timestamp>{data.get("scan_date", "")}</Timestamp>')
    xml_parts.append(f'    <IPStatus>{html.escape(str(data.get("ip_status", "Unknown")))}</IPStatus>')
    xml_parts.append(f'    <HostStatus>{html.escape(str(data.get("host_status", "Unknown")))}</HostStatus>')
    if data.get('mac_address'):
        xml_parts.append(f'    <MACAddress>{data["mac_address"]}</MACAddress>')
    xml_parts.append('  </ScanInfo>')

    if data.get('firewall_status'):
        xml_parts.append('  <FirewallAnalysis>')
        xml_parts.append(f'    <Status>{html.escape(str(data["firewall_status"]))}</Status>')
        xml_parts.append(f'    <Detection>{data.get("firewall_detected", "UNKNOWN")}</Detection>')
        xml_parts.append('  </FirewallAnalysis>')

    total = len(data.get('open_ports', [])) + data.get('closed_ports_count', 0) + data.get('filtered_ports_count', 0)
    xml_parts.append('  <Statistics>')
    xml_parts.append(f'    <TotalPortsScanned>{total}</TotalPortsScanned>')
    xml_parts.append(f'    <OpenPorts>{len(data.get("open_ports", []))}</OpenPorts>')
    xml_parts.append(f'    <ClosedPorts>{data.get("closed_ports_count", 0)}</ClosedPorts>')
    xml_parts.append(f'    <FilteredPorts>{data.get("filtered_ports_count", 0)}</FilteredPorts>')
    xml_parts.append('  </Statistics>')

    if data.get('open_ports'):
        xml_parts.append(f'  <OpenPorts count="{len(data["open_ports"])}">')
        for port in data['open_ports']:
            xml_parts.append('    <Port>')
            xml_parts.append(f'      <Number>{port.get("port", "unknown")}</Number>')
            xml_parts.append(f'      <Service>{html.escape(str(port.get("service", "unknown")))}</Service>')
            xml_parts.append('    </Port>')
        xml_parts.append('  </OpenPorts>')

    if data.get('closed_ports'):
        xml_parts.append(f'  <ClosedPortsList count="{len(data["closed_ports"])}">')
        for port in data['closed_ports']:
            xml_parts.append('    <Port>')
            xml_parts.append(f'      <Number>{port}</Number>')
            xml_parts.append('    </Port>')
        xml_parts.append('  </ClosedPortsList>')

    if data.get('filtered_ports'):
        xml_parts.append(f'  <FilteredPortsList count="{len(data["filtered_ports"])}">')
        for port in data['filtered_ports']:
            xml_parts.append('    <Port>')
            xml_parts.append(f'      <Number>{port}</Number>')
            xml_parts.append('    </Port>')
        xml_parts.append('  </FilteredPortsList>')

    if data.get('banners'):
        xml_parts.append(f'  <CapturedBanners count="{len(data["banners"])}">')
        for banner in data['banners']:
            xml_parts.append('    <Banner>')
            xml_parts.append(f'      <Port>{banner.get("port", "unknown")}</Port>')
            content = banner.get("content", "")
            if content is None:
                content = ""
            xml_parts.append(f'      <Content><![CDATA[{content}]]></Content>')
            xml_parts.append('    </Banner>')
        xml_parts.append('  </CapturedBanners>')

    if data.get('os_fingerprint'):
        xml_parts.append('  <OSFingerprint>')
        xml_parts.append(
            f'    <DetectedOS>{html.escape(str(data["os_fingerprint"].get("os", "Unknown")))}</DetectedOS>')
        xml_parts.append(f'    <Confidence>{data["os_fingerprint"].get("confidence", "0")}%</Confidence>')
        xml_parts.append('  </OSFingerprint>')

    if data.get('lsse_response') or data.get('lsse_scripts'):
        xml_parts.append('  <LSSEResults>')
        if data.get('lsse_response'):
            xml_parts.append(f'    <Target>{html.escape(str(data["lsse_response"]))}</Target>')

        if data.get('lsse_scripts_detected'):
            xml_parts.append(f'    <DetectedScripts count="{len(data["lsse_scripts_detected"])}">')
            for idx, script in enumerate(data['lsse_scripts_detected']):
                if script is None:
                    script = ""
                xml_parts.append(f'      <Script index="{idx + 1}"><![CDATA[{script}]]></Script>')
            xml_parts.append('    </DetectedScripts>')

        for script in data.get('lsse_scripts', []):
            if script.get('type') == 'subdomain':
                xml_parts.append('    <Subdomain>')
                xml_parts.append(f'      <Name>{html.escape(str(script.get("name", "Unknown")))}</Name>')
                xml_parts.append(f'      <IP>{html.escape(str(script.get("ip", "Unknown")))}</IP>')
                xml_parts.append('    </Subdomain>')
            elif script.get('type') == 'ssl_cert':
                xml_parts.append('    <SSLCertificate>')
                for key, value in script.get('data', {}).items():
                    if value is None:
                        value = ""
                    key_clean = key.replace(' ', '').replace(':', '').replace('-', '')
                    xml_parts.append(f'      <{key_clean}>{html.escape(str(value))}</{key_clean}>')
                xml_parts.append('    </SSLCertificate>')
            elif script.get('type') == 'http_title':
                xml_parts.append('    <HTTPTitles>')
                for title in script.get('titles', []):
                    if title is None:
                        title = ""
                    xml_parts.append(f'      <Title>{html.escape(str(title))}</Title>')
                xml_parts.append('    </HTTPTitles>')

        xml_parts.append('  </LSSEResults>')

    if prettified_output is None:
        prettified_output = ""

    xml_parts.append('  <RawOutput>')
    xml_parts.append('    <![CDATA[')
    for line in str(prettified_output).split('\n'):
        xml_parts.append(f'    {line}')
    xml_parts.append('    ]]>')
    xml_parts.append('  </RawOutput>')

    xml_parts.append('</LightScanReport>')

    return '\n'.join(xml_parts)

def generate_hexstr(raw_output):
    one_line_hex_str = raw_output.encode('utf-8').hex()
    return one_line_hex_str

def main(filename,format,output):

    print(f"[+] Saving to: {filename}\n")
    print("-" * 60)

    pattern = r'(\[\+\] Scan result for : \d+\.\d+\.\d+\.\d+)'
    parts = re.split(pattern, output)

    if format.lower() in ["txt", "light"]:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"\n[+] Scan saved to {filename}")

    elif format.lower() == "hex-str":
        print(f"\n[+] Generating Hex-Str report...")
        content = generate_hexstr(output)
        with open(filename.replace(".hex-str",".hex"), 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[+] Hex-Str report saved to {filename.replace(".hex-str",".hex")}")

    elif format.lower() == "html":
        print(f"\n[+] Generating HTML report...")
        html_content = ''
        j = 1
        I = 0
        for i in range(1,len(parts),2):
            parsed_data = parse_scan_output(parts[0]+parts[j+I]+parts[j+1+I])
            html_content += generate_html(parsed_data, output)
            j+=1
            I += 1

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"[+] HTML report saved to {filename}")

    elif format.lower() == "xml":
        print(f"\n[+] Generating XML report...")
        xml_content = ''
        j = 1
        I = 0
        for i in range(1, len(parts), 2):
            parsed_data = parse_scan_output(parts[0] + parts[j + I] + parts[j + 1 + I])
            xml_content += generate_xml(parsed_data, output)
            j += 1
            I += 1

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(xml_content)
        print(f"[+] XML report saved to {filename}")

    elif format.lower() == "csv":
        print(f"\n[+] Generating CSV report...")
        csv_content = ''
        j = 1
        I = 0
        for i in range(1, len(parts), 2):
            parsed_data = parse_scan_output(parts[0] + parts[j + I] + parts[j + 1 + I])
            csv_content += generate_csv(parsed_data, output)
            j += 1
            I += 1

        with open(filename, 'w', encoding='utf-8', newline='') as f:
            f.write(csv_content)
        print(f"[+] CSV report saved to {filename}")

    elif format.lower() == "json":
        print(f"\n[+] Generating JSON report...")
        json_content = ''
        j = 1
        I = 0
        for i in range(1, len(parts), 2):
            parsed_data = parse_scan_output(parts[0] + parts[j + I] + parts[j + 1 + I])
            json_content += generate_json(parsed_data, output)
            j += 1
            I += 1

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(json_content)
        print(f"[+] JSON report saved to {filename}")

    elif format.lower() == "pdf":
        print(f"\n[+] Generating PDF report...")
        pdf_content = ''
        j = 1
        I = 0
        for i in range(1, len(parts), 2):
            parsed_data = parse_scan_output(parts[0] + parts[j + I] + parts[j + 1 + I])
            pdf_content += generate_pdf(parsed_data, output)
            j += 1
            I += 1

        with open(filename, 'wb') as f:
            f.write(pdf_content)
        print(f"[+] PDF report saved to {filename}")

    elif format.lower() == "yaml":
        print(f"\n[+] Generating YAML report...")
        yaml_content = ''
        j = 1
        I = 0
        for i in range(1, len(parts), 2):
            parsed_data = parse_scan_output(parts[0] + parts[j + I] + parts[j + 1 + I])
            yaml_content += generate_yaml(parsed_data, output)
            j += 1
            I += 1

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(yaml_content)
        print(f"[+] YAML report saved to {filename}")

    elif format.lower() == "toml":
        print(f"\n[+] Generating TOML report...")
        toml_content = ''
        j = 1
        I = 0
        for i in range(1, len(parts), 2):
            parsed_data = parse_scan_output(parts[0] + parts[j + I] + parts[j + 1 + I])
            toml_content += generate_toml(parsed_data, output)
            j += 1
            I += 1

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(toml_content)
        print(f"[+] TOML report saved to {filename}")


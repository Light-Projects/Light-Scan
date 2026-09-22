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
LightDiff — compare two LightScan reports and print/save the difference.

Supported input formats (auto-detected by extension):
  .json  .yaml  .yml  .toml  .xml
"""

import sys
import os
import json
import xml.etree.ElementTree as ET
import argparse
import yaml
import toml

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"

C_GREEN = "\033[92m"
C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_MAGENTA = "\033[95m"
C_GREY = "\033[90m"

_USE_COLOR = sys.stdout.isatty()


def c(text, color):
    if not _USE_COLOR:
        return text
    return f"{color}{text}{C_RESET}"

def strip_ansi(text):
    import re
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

def _load_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def _load_yaml(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def _load_toml(path):
    with open(path, 'r', encoding='utf-8') as f:
        return toml.load(f)

def _xml_text(node, tag, default=None):
    child = node.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()

def _load_xml(path):
    tree = ET.parse(path)
    root = tree.getroot()

    data = {
        'metadata': {},
        'statistics': {},
        'firewall_analysis': None,
        'os_fingerprint': None,
        'open_ports': [],
        'closed_ports': [],
        'filtered_ports': [],
        'banners_captured': [],
    }

    info = root.find('ScanInfo')
    if info is not None:
        data['metadata']['target'] = _xml_text(info, 'Target')
        data['metadata']['scan_type'] = _xml_text(info, 'ScanType')
        data['metadata']['scan_date'] = _xml_text(info, 'Timestamp')
        data['metadata']['ip_status'] = _xml_text(info, 'IPStatus')
        data['metadata']['host_status'] = _xml_text(info, 'HostStatus')
        data['metadata']['mac_address'] = _xml_text(info, 'MACAddress')
        data['metadata']['reverse_dns'] = _xml_text(info, 'ReverseDNS')

    fw = root.find('FirewallAnalysis')
    if fw is not None:
        data['firewall_analysis'] = {
            'status': _xml_text(fw, 'Status'),
            'firewall_detected': _xml_text(fw, 'Detected'),
            'risk_level': _xml_text(fw, 'RiskLevel'),
        }

    stats = root.find('Statistics')
    if stats is not None:
        for tag, key in [
            ('TotalPortsScanned', 'total_ports_scanned'),
            ('OpenPorts', 'open_ports_count'),
            ('ClosedPorts', 'closed_ports_count'),
            ('FilteredPorts', 'filtered_ports_count'),
            ('OpenFilteredPorts', 'open_filtered_ports_count'),
        ]:
            val = _xml_text(stats, tag)
            if val is not None:
                try:
                    data['statistics'][key] = int(val)
                except ValueError:
                    data['statistics'][key] = val

    open_ports_node = root.find('OpenPorts')
    if open_ports_node is not None:
        for port_node in open_ports_node.findall('Port'):
            data['open_ports'].append({
                'port': _xml_text(port_node, 'Number'),
                'service': _xml_text(port_node, 'Service'),
                'status': 'OPEN',
            })

    closed_node = root.find('ClosedPortsList')
    if closed_node is not None:
        for port_node in closed_node.findall('Port'):
            data['closed_ports'].append(_xml_text(port_node, 'Number'))

    filtered_node = root.find('FilteredPortsList')
    if filtered_node is not None:
        for port_node in filtered_node.findall('Port'):
            data['filtered_ports'].append(_xml_text(port_node, 'Number'))

    banners_node = root.find('CapturedBanners')
    if banners_node is not None:
        for banner in banners_node.findall('Banner'):
            data['banners_captured'].append({
                'port': _xml_text(banner, 'Port'),
                'content': _xml_text(banner, 'Content') or '',
            })

    os_node = root.find('OSFingerprint')
    if os_node is not None:
        data['os_fingerprint'] = {
            'name': _xml_text(os_node, 'DetectedOS'),
            'version': _xml_text(os_node, 'Version'),
            'confidence': (_xml_text(os_node, 'Confidence') or '').rstrip('%'),
        }
    return data

_LOADERS = {
    '.json': _load_json,
    '.yaml': _load_yaml,
    '.yml':  _load_yaml,
    '.toml': _load_toml,
    '.xml':  _load_xml,
}

def load_report(path):
    ext = os.path.splitext(path)[1].lower()
    loader = _LOADERS.get(ext)
    if loader is None:
        raise ValueError(f"Unsupported format: {ext} ({path})")
    return loader(path)

def _normalize(report):
    meta = report.get('metadata', {}) or {}
    stats = report.get('statistics', {}) or {}
    fw = report.get('firewall_analysis') or {}
    os_info = report.get('os_fingerprint') or {}

    open_ports = {}
    for p in report.get('open_ports', []) or []:
        port = str(p.get('port', '')).strip()
        if port:
            open_ports[port] = {
                'service': (p.get('service') or 'unknown').strip(),
                'banner': (p.get('banner') or '').strip(),
            }

    return {
        'target':         meta.get('target'),
        'scan_date':      meta.get('scan_date'),
        'scan_type':      meta.get('scan_type'),
        'host_status':    meta.get('host_status'),
        'ip_status':      meta.get('ip_status'),
        'mac_address':    meta.get('mac_address'),
        'os_name':        os_info.get('name'),
        'os_version':     os_info.get('version'),
        'firewall':       fw.get('status') if fw else None,
        'fw_detected':    fw.get('firewall_detected') if fw else None,
        'open_ports':     open_ports,
        'open_count':     stats.get('open_ports_count', len(open_ports)),
        'closed_count':   stats.get('closed_ports_count', 0),
        'filtered_count': stats.get('filtered_ports_count', 0),
    }

def diff_reports(a, b):

    diff = {
        'target': a['target'] or b['target'],
        'host_status_change': None,
        'os_change':          None,
        'firewall_change':    None,
        'ports_new':     [],
        'ports_removed': [],
        'ports_changed': [],
        'ports_same':    [],
        'is_new_host':     False,
        'is_removed_host': False,
        'has_any_change':  False,
    }

    if a['host_status'] != b['host_status']:
        diff['host_status_change'] = (a['host_status'], b['host_status'])

    if a['os_name'] != b['os_name'] or a['os_version'] != b['os_version']:
        diff['os_change'] = (
            (a['os_name'], a['os_version']),
            (b['os_name'], b['os_version']),
        )

    if a['firewall'] != b['firewall'] or a['fw_detected'] != b['fw_detected']:
        diff['firewall_change'] = (
            (a['firewall'], a['fw_detected']),
            (b['firewall'], b['fw_detected']),
        )

    a_ports = set(a['open_ports'].keys())
    b_ports = set(b['open_ports'].keys())

    diff['ports_new'] = sorted(b_ports - a_ports, key=int)
    diff['ports_removed'] = sorted(a_ports - b_ports, key=int)

    for port in sorted(a_ports & b_ports, key=int):
        a_svc = a['open_ports'][port]['service']
        b_svc = b['open_ports'][port]['service']
        if a_svc != b_svc:
            diff['ports_changed'].append((port, a_svc, b_svc))
        else:
            diff['ports_same'].append(port)

    if diff['ports_new'] or diff['ports_changed'] or diff['host_status_change'] or diff['os_change']:
        diff['has_any_change'] = True
    if diff['ports_removed']:
        diff['has_any_change'] = True
    if diff['firewall_change']:
        diff['has_any_change'] = True

    return diff

def _fmt_metadata_change(label, before, after):
    if before == after:
        return f"  {label:<14} {before}   {c('[ unchanged ]', C_GREY)}"
    return f"  {label:<14} {c(before or '?', C_RED)} → {c(after or '?', C_GREEN)}   {c('[ CHANGED ]', C_YELLOW)}"

def format_diff(diff, a_header=None, b_header=None):
    lines = []

    lines.append("═" * 60)
    lines.append(f"  {c('LightScan Diff', C_BOLD + C_CYAN)}")
    if a_header:
        lines.append(f"  A: {a_header}")
    if b_header:
        lines.append(f"  B: {b_header}")
    lines.append("═" * 60)
    lines.append("")

    d = diff

    if d['is_new_host']:
        lines.append(f"  {c('[ NEW HOST ]', C_GREEN + C_BOLD)}  "
                     f"{d['target']}  •  {len(d['ports_new'])} open ports "
                     f"({', '.join(d['ports_new'][:10])}"
                     f"{', ...' if len(d['ports_new']) > 10 else ''})")
        lines.append("")
        return "\n".join(lines)

    if d['is_removed_host']:
        lines.append(f"  {c('[ HOST REMOVED ]', C_RED + C_BOLD)}  "
                     f"{d['target']}  •  had {len(d['ports_removed'])} open ports "
                     f"({', '.join(d['ports_removed'][:10])}"
                     f"{', ...' if len(d['ports_removed']) > 10 else ''})")
        lines.append("")
        return "\n".join(lines)

    lines.append(f"  {c('Target:', C_BOLD)} {d['target']}")
    lines.append("  " + "─" * 56)

    lines.append(_fmt_metadata_change("Host status:", "", "").replace("    →     ", ""))

    return _format_existing_host(d, lines)

def _format_existing_host(d, lines):
    if lines and lines[-1].startswith("  Host status:"):
        lines.pop()
    if lines and lines[-1].strip() == "─" * 56:
        pass

    if d['host_status_change']:
        before, after = d['host_status_change']
        lines.append(f"  Host status:  {c(before or '?', C_RED)} → {c(after or '?', C_GREEN)}   {c('[ CHANGED ]', C_YELLOW)}")
    else:
        lines.append(f"  Host status:  {'':<12}   {c('[ unchanged ]', C_GREY)}")

    if d['os_change']:
        (a_name, a_ver), (b_name, b_ver) = d['os_change']
        a_os = f"{a_name} {a_ver}".strip() or '?'
        b_os = f"{b_name} {b_ver}".strip() or '?'
        lines.append(f"  OS:           {c(a_os, C_RED)} → {c(b_os, C_GREEN)}   {c('[ CHANGED ]', C_YELLOW)}")

    if d['firewall_change']:
        (a_fw, a_det), (b_fw, b_det) = d['firewall_change']
        lines.append(f"  Firewall:     {c(str(a_fw), C_RED)} → {c(str(b_fw), C_GREEN)}   {c('[ CHANGED ]', C_YELLOW)}")

    lines.append("")

    has_port_changes = (d['ports_new'] or d['ports_removed'] or d['ports_changed'])

    if not has_port_changes and not d['has_any_change']:
        lines.append(f"  {c('No changes detected.', C_GREY)}")
        lines.append("")
        return "\n".join(lines)

    lines.append(f"  {c('Open ports:', C_BOLD)}")

    for port in d['ports_new']:
        lines.append(f"    {c('[+]', C_GREEN)} {port:<6} {c('NEW', C_GREEN)}")

    for port, a_svc, b_svc in d['ports_changed']:
        lines.append(f"    {c('[~]', C_YELLOW)} {port:<6} {c(a_svc, C_RED)} → {c(b_svc, C_GREEN)}   {c('SERVICE CHANGED', C_YELLOW)}")

    for port in d['ports_removed']:
        lines.append(f"    {c('[-]', C_RED)} {port:<6} {c('REMOVED', C_RED)}")

    if has_port_changes and d['ports_same']:
        unchanged = ', '.join(d['ports_same'][:20])
        if len(d['ports_same']) > 20:
            unchanged += f", ... ({len(d['ports_same']) - 20} more)"
        lines.append(f"    {c('[=]', C_GREY)} {c('unchanged:', C_GREY)} {unchanged}")

    lines.append("")
    return "\n".join(lines)

def format_summary(all_diffs):
    lines = []
    lines.append("═" * 60)
    lines.append(f"  {c('Summary', C_BOLD + C_CYAN)}")
    lines.append("═" * 60)

    total = len(all_diffs)
    changed = sum(1 for d in all_diffs if d['has_any_change'])
    unchanged = total - changed

    new_hosts = sum(1 for d in all_diffs if d['is_new_host'])
    removed_hosts = sum(1 for d in all_diffs if d['is_removed_host'])

    new_ports = sum(len(d['ports_new']) for d in all_diffs)
    removed_ports = sum(len(d['ports_removed']) for d in all_diffs)
    changed_services = sum(len(d['ports_changed']) for d in all_diffs)
    status_flips = sum(1 for d in all_diffs if d['host_status_change'])
    os_changes = sum(1 for d in all_diffs if d['os_change'])
    fw_changes = sum(1 for d in all_diffs if d['firewall_change'])

    lines.append(f"  Targets compared:    {total}")
    lines.append(f"  Changed targets:     {c(str(changed), C_YELLOW) if changed else str(changed)}")
    lines.append(f"  Unchanged:           {unchanged}")
    lines.append("")
    lines.append(f"  New hosts:           {c(str(new_hosts), C_GREEN) if new_hosts else str(new_hosts)}")
    lines.append(f"  Removed hosts:       {c(str(removed_hosts), C_RED) if removed_hosts else str(removed_hosts)}")
    lines.append(f"  New ports:           {c(str(new_ports), C_GREEN) if new_ports else str(new_ports)}")
    lines.append(f"  Removed ports:       {c(str(removed_ports), C_RED) if removed_ports else str(removed_ports)}")
    lines.append(f"  Service changes:     {c(str(changed_services), C_YELLOW) if changed_services else str(changed_services)}")
    lines.append(f"  Host status flips:   {c(str(status_flips), C_YELLOW) if status_flips else str(status_flips)}")
    lines.append(f"  OS changes:          {c(str(os_changes), C_YELLOW) if os_changes else str(os_changes)}")
    lines.append(f"  Firewall changes:    {c(str(fw_changes), C_YELLOW) if fw_changes else str(fw_changes)}")
    lines.append("═" * 60)

    return "\n".join(lines)

def compare_files(path_a, path_b, save_light=None):
    try:
        report_a = load_report(path_a)
        report_b = load_report(path_b)
    except Exception as e:
        print(f"{c('[!] Error loading reports:', C_RED)} {e}")
        return 2

    norm_a = _normalize(report_a)
    norm_b = _normalize(report_b)
    a_target = norm_a['target']
    b_target = norm_b['target']

    if a_target and b_target and a_target != b_target:
        print(f"{c('[!] Target mismatch:', C_RED)} '{a_target}' vs '{b_target}'")
        print(f"    This tool compares the same target across two scans.")
        return 2

    diff = diff_reports(norm_a, norm_b)
    header_a = f"{path_a}  ({norm_a['scan_date'] or 'no date'})"
    header_b = f"{path_b}  ({norm_b['scan_date'] or 'no date'})"

    body = format_diff(diff, header_a, header_b)
    summary = format_summary([diff])

    output = body + "\n" + summary + "\n"
    print(output)

    if save_light:
        with open(save_light, 'w', encoding='utf-8') as f:
            f.write(strip_ansi(output))
        print(f"{c('[+]', C_GREEN)} Saved diff to {save_light}")
    return 1 if diff['has_any_change'] else 0

def main():
    parser = argparse.ArgumentParser(
        prog="LightDiff",
        description="Compare two LightScan reports (JSON/YAML/TOML/XML).",
        epilog=(
            "Exit codes:\n"
            "  0  no changes\n"
            "  1  changes detected\n"
            "  2  error"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("A", help="First report file (older scan)")
    parser.add_argument("B", help="Second report file (newer scan)")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Save the diff to a .light file")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    args = parser.parse_args()

    if args.no_color:
        global _USE_COLOR
        _USE_COLOR = False

    return compare_files(args.A, args.B, save_light=args.output)

if __name__ == "__main__":
    sys.exit(main())
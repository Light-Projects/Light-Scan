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
LightPanel OS Fingerprint Visual Manager
-----------------------------------------
A self-contained, thread-safe results viewer for Lightscan output.
"""

import datetime
import re
import os

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QWidget, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QTextEdit, QFrame, QSplitter
)
from PySide6.QtCore import Qt, Signal, QObject, QSize
from PySide6.QtGui import QFont, QPixmap, QShortcut, QKeySequence


def split_targets(output):
    if not output:
        return []
    parts = re.split(r'(?=\[\+\]\s*Scan result for\s*:\s*)', output)
    return [p for p in parts if re.search(r'\[\+\]\s*Scan result for\s*:', p)]

def parse_scan_output(output):
    results = {
        'target': None,
        'scan_type': None,
        'open_ports': [],
        'open_ports_count': 0,
        'closed_ports_count': 0,
        'filtered_ports_count': 0,
        'open_filtered_ports_count':0,
        'os_fingerprint': None,
        'os_confidence': None,
        'firewall_status': None,
        'firewall_detected': None,
        'firewall_risk': None,
        'scan_time': None,
        'scan_date': datetime.datetime.now().isoformat(),
        'version': None,
        'banners': [],
        'mac_address': None,
        'ip_status': None,
        'reverse_dns': None,
        'host_status': None,
    }

    version_match = re.search(r'Version\s*:\s*([\d.]+)', output)
    if version_match:
        results['version'] = version_match.group(1)

    target_match = re.search(r'\[\+\]\s*Scan result for\s*:\s*(.+)', output)
    if target_match:
        results['target'] = target_match.group(1).strip()

    ip_status_match = re.search(r'\[\+\]\s*IP Status:\s*(.+)', output)
    if ip_status_match:
        results['ip_status'] = ip_status_match.group(1).strip()

    rdns_match = re.search(r'\[\+\]\s*Reverse DNS:\s*(.+)', output)
    if rdns_match:
        results['reverse_dns'] = rdns_match.group(1).strip()

    mac_match = re.search(r'\[\+\]\s*Mac Address:\s*([0-9a-fA-F:]+)', output)
    if mac_match:
        results['mac_address'] = mac_match.group(1)

    type_match = re.search(r'Scan Type:\s*(\S+)', output)
    if type_match:
        results['scan_type'] = type_match.group(1)

    open_section = re.search(
        r'\[\+\]\s*Open Ports:\s*(\d+)(.*?)'
        r'(?=\[\+\]\s*Closed Ports:|\[\+\]\s*Filtered Ports:|$)',
        output, re.DOTALL
    )
    if open_section:
        results['open_ports_count'] = int(open_section.group(1))
        open_text = open_section.group(2)
        for port, service in re.findall(r'Port\s+(\d+)\s+(\S+)', open_text):
            results['open_ports'].append({'port': port, 'service': service.strip()})

    closed_match = re.search(r'\[\+\]\s*Closed Ports:\s*(\d+)', output)
    if closed_match:
        results['closed_ports_count'] = int(closed_match.group(1))

    if results['target']:
        host_match = re.search(
            rf'Host\s+{re.escape(results["target"])}\s*is\s*(up|down|alive|dead|reachable|unreachable|online|offline)!?',
            output, re.IGNORECASE
        )
        if host_match:
            state_word = host_match.group(1).lower()
            UP_WORDS = {"up", "alive", "reachable", "online"}
            DOWN_WORDS = {"down", "dead", "unreachable", "offline"}
            if state_word in UP_WORDS:
                results['host_status'] = "up"
            elif state_word in DOWN_WORDS:
                results['host_status'] = "down"
        elif results['open_ports_count'] > 0 or results['closed_ports_count'] > 0:
            results['host_status'] = "up"
        else:
            results['host_status'] = "down"

    filtered_match = re.search(r'\[\+\]\s*Filtered Ports:\s*(\d+)', output)
    if filtered_match:
        results['filtered_ports_count'] = int(filtered_match.group(1))

    open_filtered_match = re.search(r'\[\+\]\s*Open\|Filtered Ports:\s*(\d+)', output)
    if open_filtered_match:
        results['open_filtered_ports_count'] = int(open_filtered_match.group(1))

    firewall_section = re.search(
        r'\[!\]\s*Firewall Analysis for\s*:?\s*\S+\s*\n(.*?)'
        r'(?=\[\+\]\s*Captured Banner/s:|\[\+\]\s*OS Fingerprint Results|'
        r'\[\+\]\s*Lightscan scanned|$)',
        output, re.DOTALL
    )
    if firewall_section:
        fw_text = firewall_section.group(1)

        status_match = re.search(r'\[\+\]\s*Status:\s*(.+)', fw_text)
        if status_match:
            results['firewall_detected'] = 'NOT DETECTED' not in status_match.group(1).upper()

        sig_match = re.search(r'\[\+\]\s*Signature:\s*(.+)', fw_text)
        if sig_match:
            results['firewall_status'] = sig_match.group(1).strip()

        risk_match = re.search(r'\[\+\]\s*Risk Level:\s*(.+)', fw_text)
        if risk_match:
            results['firewall_risk'] = risk_match.group(1).strip()

    banner_section = re.search(
        r'\[\+\]\s*Captured Banner/s:\s*\d+\s*(.*?)'
        r'(?=\[\+\]\s*OS Fingerprint Results|\[\+\]\s*Lightscan scanned|$)',
        output, re.DOTALL
    )
    if banner_section:
        banner_text = banner_section.group(1)
        for port, version_line, content in re.findall(
            r'\[\*\]\s*Banner from Port\s+(\d+):(.*?)={5,}(.*?)={5,}',
            banner_text, re.DOTALL
        ):
            results['banners'].append({
                'port': port,
                'version': version_line.strip(),
                'content': content.strip(),
            })

    os_match = re.search(
        r'\[\+\]\s*OS Fingerprint Results.*?:\s*\n[-\s]*\n?\s*\[\+\]\s+(.+?):\s+([\d.]+)%\s*(?:\n\s*Version:\s*\[(.*?)\])?',
        output, re.DOTALL
    )
    if os_match:
        results['os_fingerprint'] = os_match.group(1).strip()
        results['os_confidence'] = os_match.group(2)
        version_raw = re.search(r'└─ Version:\s*\[(.*?)\]', output)
        if version_raw:
            results['os_version'] = str(version_raw.group(1))
        else:
            results['os_version'] = ""

    time_match = re.search(r'\[\*\]\s*Scan completed in\s*([\d.]+)\s*seconds', output)
    if time_match:
        results['scan_time'] = time_match.group(1)

    return results


def parse_multi_target_output(output):
    result = {}
    for chunk in split_targets(output):
        parsed = parse_scan_output(chunk)
        if parsed['target']:
            result[parsed['target']] = parsed
    return result


_OS_ICON_NAMES = ['windows', 'linux', 'macos', 'bsd', 'android', 'unix']
_LINUX_DISTROS = ['centos', 'ubuntu', 'debian']
_PRIVATE_SYSTEMS = ['aws', 'cloudflare', 'pantheon', 'google']
_OS_EMOJI_FALLBACK = {
    'windows': '🪟', 'linux': '🐧', 'macos': '🍎',
    'bsd': '🔱', 'android': '📱', 'unix': '💻',
}


def _detect_os_key(os_fingerprint_text, version):
    if not os_fingerprint_text:
        return None
    text = os_fingerprint_text.lower()
    guess = (version or "").lower()
    if 'windows' in text:
        return 'windows'
    if 'linux' in text:
        if 'centos' in guess:
            return 'centos'
        elif 'ubuntu' in guess:
            return 'ubuntu'
        elif 'debian' in guess:
            return 'debian'
        elif 'aws' in guess:
            return 'aws'
        elif 'cloudflare' in guess:
            return 'cloudflare'
        elif 'pantheon' in guess:
            return 'pantheon'
        elif 'google' in guess:
            return 'google'
        else:
            return 'linux'
    if 'mac' in text or 'darwin' in text or 'os x' in text:
        return 'macos'
    if 'bsd' in text:
        return 'bsd'
    if 'android' in text:
        return 'android'
    if 'unix' in text:
        return 'unix'
    return None


def load_os_icons(size=20):
    icons = {}
    base = os.path.dirname(__file__)

    for name in _OS_ICON_NAMES:
        path = os.path.join(base, "Assets/os", f"{name}.png")
        pix = QPixmap(path)
        if not pix.isNull():
            icons[name] = pix.scaled(
                size, size, Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )

    for name in _LINUX_DISTROS:
        path = os.path.join(base, "Assets/os/linux-distros", f"{name}.png")
        pix = QPixmap(path)
        if not pix.isNull():
            icons[name] = pix.scaled(
                size, size, Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )

    for name in _PRIVATE_SYSTEMS:
        path = os.path.join(base, "Assets/os/private-systems", f"{name}.png")
        pix = QPixmap(path)
        if not pix.isNull():
            icons[name] = pix.scaled(
                size, size, Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )

    for name in _OS_ICON_NAMES:
        if name not in icons:
            icons[name] = _OS_EMOJI_FALLBACK[name]

    return icons


class _IngestBridge(QObject):
    output_received = Signal(str)


class OSMenu(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.target_data = {}
        self.current_target = None
        self.target_rows = {}

        self.setWindowTitle("Fingerprint - Lightscan OS Fingerprint")
        self.setGeometry(0, 0, 1100, 800)
        self.setMinimumSize(860, 600)

        self.os_icons = load_os_icons(size=24)
        self.os_icons_large = load_os_icons(size=70)

        self._bridge = _IngestBridge()
        self._bridge.output_received.connect(self._ingest)

        self.setup_ui()
        self.center_window()
        self.apply_styles()
        self.bind_shortcuts()

        self._show_welcome()

    def bind_shortcuts(self):
        self.shortcut_close_1 = QShortcut(QKeySequence("Escape"), self)
        self.shortcut_close_1.activated.connect(self.hide)
        self.shortcut_close_2 = QShortcut(QKeySequence("F2"), self)
        self.shortcut_close_2.activated.connect(self.hide)

    def center_window(self):
        screen = self.screen().size()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)

    def show(self):
        super().show()
        self.raise_()
        self.activateWindow()

        if hasattr(self.parent, 'output_box'):
            try:
                existing = self.parent.output_box.toPlainText()
            except Exception:
                existing = ""
            if existing.strip():
                self._ingest(existing)

    def update_from_output(self, output):
        if not output or not output.strip():
            return
        self._bridge.output_received.emit(output)

    def clear_all(self):
        self.target_data = {}
        self.current_target = None
        self._rebuild_sidebar()
        self._show_welcome()

    def _ingest(self, output):
        parsed_targets = parse_multi_target_output(output)
        if not parsed_targets:
            return

        for target, data in parsed_targets.items():
            self.target_data[target] = data
            self.current_target = target

        self._rebuild_sidebar()
        if self.current_target:
            self._show_target(self.current_target)

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        header = self.create_header()
        main_layout.addWidget(header)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(10)

        sidebar_container = QWidget()
        sidebar_layout = QVBoxLayout(sidebar_container)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(6)

        self.sidebar = QListWidget()
        self.sidebar.setFrameShape(QFrame.Shape.NoFrame)
        self.sidebar.setSpacing(3)
        self.sidebar.setIconSize(QSize(24, 24))
        self.sidebar.setVerticalScrollMode(QListWidget.ScrollMode.ScrollPerPixel)
        self.sidebar.currentRowChanged.connect(self._on_row_changed)
        sidebar_layout.addWidget(self.sidebar, 1)

        self.count_label = QLabel("Targets: 0")
        self.count_label.setObjectName("countLabel")
        self.count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(self.count_label)

        sidebar_container.setFixedWidth(260)
        splitter.addWidget(sidebar_container)

        content_container = QWidget()
        content_layout = QVBoxLayout(content_container)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)

        detail_header = QWidget()
        detail_layout = QHBoxLayout(detail_header)
        detail_layout.setContentsMargins(4, 4, 4, 4)
        detail_layout.setSpacing(14)

        self.detail_icon_label = QLabel("🔎")
        self.detail_icon_label.setFixedSize(72, 72)
        self.detail_icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        detail_icon_font = QFont("Segoe UI Emoji", 40)
        self.detail_icon_label.setFont(detail_icon_font)
        detail_layout.addWidget(self.detail_icon_label)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)

        self.detail_title_label = QLabel("Fingerprint Analysis")
        self.detail_title_label.setFont(QFont("Segoe UI", 16, QFont.Weight.DemiBold))
        text_col.addWidget(self.detail_title_label)

        self.detail_subtitle_label = QLabel("Select a target from the left to view details")
        self.detail_subtitle_label.setObjectName("subtitle")
        self.detail_subtitle_label.setFont(QFont("Segoe UI", 11))
        text_col.addWidget(self.detail_subtitle_label)

        detail_layout.addLayout(text_col, 1)
        content_layout.addWidget(detail_header)

        self.content_text = QTextEdit()
        self.content_text.setReadOnly(True)
        self.content_text.setFont(QFont("Consolas", 13))
        content_layout.addWidget(self.content_text, 1)

        splitter.addWidget(content_container)
        splitter.setSizes([260, 840])
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        main_layout.addWidget(splitter, 1)

        footer = self.create_footer()
        main_layout.addWidget(footer)

    def create_header(self):
        header = QWidget()
        layout = QHBoxLayout(header)
        layout.setContentsMargins(4, 0, 4, 0)
        layout.setSpacing(10)

        title = QLabel("🔎 Fingerprint Analysis")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.DemiBold))
        layout.addWidget(title, 0)

        subtitle = QLabel("Visual Fingerprint Detection Results")
        subtitle.setObjectName("subtitle")
        subtitle.setFont(QFont("Segoe UI", 11))
        layout.addWidget(subtitle)

        layout.addStretch()

        self.clear_btn = QPushButton("Clear All")
        self.clear_btn.setFixedSize(96, 32)
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_btn.clicked.connect(self.clear_all)
        layout.addWidget(self.clear_btn)

        return header

    def create_footer(self):
        footer = QWidget()
        layout = QHBoxLayout(footer)
        layout.setContentsMargins(4, 8, 4, 0)

        info = QLabel("Esc / F2 to close  •  target list updates automatically after each scan")
        info.setObjectName("footerLabel")
        layout.addWidget(info)

        layout.addStretch()

        return footer

    def _rebuild_sidebar(self):
        self.sidebar.clear()
        self.target_rows = {}

        if not self.target_data:
            placeholder = QListWidgetItem("No targets yet — run a scan to see results here")
            placeholder.setFlags(Qt.ItemFlag.NoItemFlags)
            self.sidebar.addItem(placeholder)
            self.count_label.setText("Targets: 0")
            return

        for target, data in self.target_data.items():
            self._add_sidebar_row(target, data)

        self.count_label.setText(f"Targets: {len(self.target_data)}")

    def _add_sidebar_row(self, target, data):
        os_key = _detect_os_key(data.get('os_fingerprint'), data.get('os_version'))
        icon = self.os_icons.get(os_key, '💻') if os_key else '💻'
        status_dot = "🟢"

        if isinstance(icon, QPixmap):
            item = QListWidgetItem(icon, f"  {target}   {status_dot}")
        else:
            item = QListWidgetItem(f"{icon}  {target}   {status_dot}")

        self.sidebar.addItem(item)
        self.target_rows[target] = self.sidebar.count() - 1

    def _on_row_changed(self, row):
        for target, idx in self.target_rows.items():
            if idx == row:
                self._show_target(target)
                return

    def show_target_by_name(self, target):
        if target in self.target_rows:
            self.sidebar.setCurrentRow(self.target_rows[target])

    def _show_welcome(self):
        self.detail_icon_label.setText("🔎")
        self.detail_title_label.setText("Fingerprint Analysis")
        self.detail_subtitle_label.setText("Select a target from the left to view details")

        self.content_text.setPlainText(
            "Each target shows:\n"
            "  - Detected operating system + confidence (shown above as an icon)\n"
            "  - Open / closed / filtered ports\n"
            "  - Captured service banners\n"
            "  - Firewall detection status\n\n"
            "Results update automatically after each scan."
        )

    def _show_target(self, target):
        data = self.target_data.get(target)
        if not data:
            return

        self.current_target = target

        os_key = _detect_os_key(data.get('os_fingerprint'), data.get('os_version'))
        big_icon = self.os_icons_large.get(os_key) if os_key else None
        if isinstance(big_icon, QPixmap):
            self.detail_icon_label.setPixmap(big_icon)
        else:
            fallback = self.os_icons_large.get(os_key, '💻') if os_key else '💻'
            self.detail_icon_label.setText(str(fallback))

        self.detail_title_label.setText(target)
        if data.get('os_fingerprint'):
            self.detail_subtitle_label.setText(
                f"{data['os_fingerprint']} • {data.get('os_confidence', 'N/A')}% confidence"
            )
        else:
            self.detail_subtitle_label.setText("OS not detected (run with -O -b)")

        lines = []

        lines.append(f"[+] TARGET: {target}")
        lines.append("")

        lines.append("[+] OPERATING SYSTEM")
        lines.append("─" * 40)
        if data.get('os_fingerprint'):
            lines.append(f"  -> Detected OS : {data['os_fingerprint']}")
        if data.get('os_version'):
            lines.append(f"  -> OS Version  : {data['os_version']}")
            lines.append(f"  -> Confidence  :  {data.get('os_confidence', 'N/A')}%")
        else:
            lines.append("  -> OS not detected (run with -O -b)")
        lines.append("")

        lines.append("[+] HOST STATUS")
        lines.append("─" * 40)
        status = data.get('host_status') or 'unknown'
        lines.append(f"  -> Status:      {status.upper()}")
        if data.get('ip_status'):
            lines.append(f"  -> IP Type:     {data['ip_status']}")
        if data.get('reverse_dns'):
            lines.append(f"  -> Reverse DNS: {data['reverse_dns']}")
        if data.get('mac_address'):
            lines.append(f"  -> MAC:         {data['mac_address']}")
        lines.append("")

        lines.append("[+] PORTS")
        lines.append("─" * 40)
        lines.append(f"  -> Open:          {data.get('open_ports_count', 0)}")
        lines.append(f"  -> Closed:        {data.get('closed_ports_count', 0)}")
        lines.append(f"  -> Filtered:      {data.get('filtered_ports_count', 0)}")
        lines.append(f"  -> Open Filtered  {data.get('open_filtered_ports_count', 0)}")
        if data.get('open_ports'):
            lines.append("")
            lines.append("  -> Open Ports:")
            for p in data['open_ports']:
                lines.append(f"    - Port {p['port']:<5} -> {p.get('service', 'unknown')}")
        lines.append("")

        lines.append("[&] FIREWALL")
        lines.append("─" * 40)
        if data.get('firewall_detected') is not None:
            lines.append(f" < Detected:    {'YES' if data['firewall_detected'] else 'NO'}")
            if data.get('firewall_status'):
                lines.append(f" < Signature:   {data['firewall_status']}")
            if data.get('firewall_risk'):
                lines.append(f" < Risk Level:  {data['firewall_risk']}")
        else:
            lines.append(" < Not analyzed")
        lines.append("")

        if data.get('banners'):
            lines.append("[+] BANNERS")
            lines.append("─" * 40)
            for b in data['banners']:
                lines.append(f"  -> Port {b['port']}:")
                if b.get('version'):
                    lines.append(f"    {b['version']}")
                if b.get('content'):
                    content = b['content']
                    preview = content[:200] + "..." if len(content) > 200 else content
                    lines.append(f"    {preview}")
            lines.append("")

        lines.append("[+] SCAN INFO")
        lines.append("─" * 40)
        if data.get('scan_type'):
            lines.append(f"  -> Scan Type:   {data['scan_type']}")
        if data.get('scan_time'):
            lines.append(f"  -> Duration:    {data['scan_time']} seconds")
        if data.get('version'):
            lines.append(f"  -> Lightscan:   v{data['version']}")
        lines.append("")
        lines.append("=" * 70)

        self.content_text.setPlainText("\n".join(lines))

    def apply_styles(self):
        is_light = hasattr(self.parent, 'dark_mode') and not self.parent.dark_mode

        if not is_light:
            accent = "#1e6fe0"
            self.setStyleSheet(f"""
                QDialog {{
                    background-color: #f7f5f0;
                }}
                QLabel {{
                    color: {accent};
                }}
                QLabel#subtitle {{
                    color: {accent};
                }}
                QLabel#footerLabel {{
                    color: {accent};
                }}
                QLabel#countLabel {{
                    color: {accent};
                    font-size: 11px;
                }}
                QListWidget {{
                    background-color: #ffffff;
                    border: 1px solid #dde2e9;
                    border-radius: 16px;
                    padding: 8px;
                    outline: none;
                    font-size: 13px;
                }}
                QListWidget::item {{
                    color: {accent};
                    background-color: #f7f9fb;
                    border-radius: 12px;
                    padding: 8px;
                    margin: 2px 0px;
                }}
                QListWidget::item:hover {{
                    background-color: #e7edf6;
                }}
                QListWidget::item:selected {{
                    background-color: {accent};
                    color: #ffffff;
                }}
                QPushButton {{
                    background-color: #ffffff;
                    color: #1e6fe0;
                    border: 1px solid #dde2e9;
                    border-radius: 10px;
                    font-size: 12px;
                    font-weight: 600;
                }}
                QPushButton:hover {{
                    background-color: #eef2f7;
                }}
                QPushButton:pressed {{
                    background-color: {accent};
                    color: #ffffff;
                }}
                QTextEdit {{
                    background-color: #ffffff;
                    color: {accent};
                    border: 1px solid #dde2e9;
                    border-radius: 16px;
                    padding: 18px;
                    font-family: 'Consolas', monospace;
                    font-size: 13px;
                    selection-background-color: {accent};
                    selection-color: #ffffff;
                }}
                QSplitter::handle {{
                    background-color: #f7f5f0;
                }}
                QScrollBar:vertical {{
                    background: #f7f5f0;
                    width: 10px;
                    margin: 4px 0;
                }}
                QScrollBar::handle:vertical {{
                    background: {accent};
                    border-radius: 5px;
                    min-height: 24px;
                }}
                QScrollBar::handle:vertical:hover {{
                    background: {accent};
                }}
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                    height: 0px;
                }}
            """)
        else:
            accent = "#00ffb2"
            self.setStyleSheet(f"""
                QDialog {{
                    background-color: #1a1a1a;
                }}
                QLabel {{
                    color: {accent};
                }}
                QLabel#subtitle {{
                    color: {accent};
                }}
                QLabel#footerLabel {{
                    color: {accent};
                }}
                QLabel#countLabel {{
                    color: {accent};
                    font-size: 11px;
                }}
                QListWidget {{
                    background-color: #0a0a0a;
                    border-radius: 16px;
                    padding: 8px;
                    outline: none;
                    font-size: 13px;
                }}
                QListWidget::item {{
                    color: {accent};
                    background-color: #000000;
                    border-radius: 12px;
                    padding: 8px;
                    margin: 2px 0px;
                }}
                QListWidget::item:hover {{
                    background-color: #0a0a0a;
                    color: #ffffff;
                }}
                QListWidget::item:selected {{
                    background-color: #7ef2cf;
                    color: {accent};
                    border: 1px solid {accent};
                }}
                QPushButton {{
                    background-color: #0a0a0a;
                    color: {accent};
                    border: 1px solid #0a0a0a;
                    border-radius: 10px;
                    font-size: 12px;
                    font-weight: 600;
                }}
                QPushButton:hover {{
                    background-color: #000000;
                }}
                QPushButton:pressed {{
                    background-color: {accent};
                    color: #000000;
                }}
                QTextEdit {{
                    background-color: #0a0a0a;
                    color: {accent};
                    border-radius: 16px;
                    padding: 18px;
                    font-family: 'Consolas', monospace;
                    font-size: 13px;
                    selection-background-color: #0a0a0a;
                    selection-color: {accent};
                }}
                QSplitter::handle {{
                    background-color: transparent;
                }}
                QScrollBar:vertical {{
                    background: transparent;
                    width: 10px;
                    margin: 4px 0;
                }}
                QScrollBar::handle:vertical {{
                    background: #0a0a0a;
                    border-radius: 5px;
                    min-height: 24px;
                }}
                QScrollBar::handle:vertical:hover {{
                    background: #0a0a0a;
                }}
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                    height: 0px;
                }}
            """)

    def closeEvent(self, event):
        self.hide()
        event.ignore()

def get_instance(parent):
    if not hasattr(parent, '_os_menu_instance') or parent._os_menu_instance is None:
        parent._os_menu_instance = OSMenu(parent)
    return parent._os_menu_instance

def show_os_menu(parent):
    menu = get_instance(parent)
    menu.show()
    return menu

def update_os_menu(menu_instance, output):
    if menu_instance is not None:
        menu_instance.update_from_output(output)
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

import customtkinter
import datetime
import re
import os
import threading
from PIL import Image, ImageTk


def split_targets(output):
    if not output:
        return []
    parts = re.split(r'(?=\[\+\]\s*Scan result for\s*:\s*)', output)
    return [p for p in parts if re.search(r'\[\+\]\s*Scan result for\s*:', p)]


def parse_scan_output(output):
    """Parse a single target's scan output chunk into a structured dict."""
    results = {
        'target': None,
        'scan_type': None,
        'open_ports': [],
        'open_ports_count': 0,
        'closed_ports_count': 0,
        'filtered_ports_count': 0,
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

    if results['target']:
        host_match = re.search(
            rf'Host\s+{re.escape(results["target"])}\s+is\s+(up|down)!',
            output, re.IGNORECASE
        )
        if host_match:
            results['host_status'] = host_match.group(1).lower()

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

    filtered_match = re.search(r'\[\+\]\s*Filtered Ports:\s*(\d+)', output)
    if filtered_match:
        results['filtered_ports_count'] = int(filtered_match.group(1))

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
    """Parse full scan output (one or more targets) into {target: data}."""
    result = {}
    for chunk in split_targets(output):
        parsed = parse_scan_output(chunk)
        if parsed['target']:
            result[parsed['target']] = parsed
    return result

_OS_ICON_NAMES = ['windows', 'linux', 'macos', 'bsd', 'android', 'unix']
_LINUX_DISTROS = ['centos','ubuntu','debian']
_PRIVATE_SYSTEMS = ['aws','cloudflare','pantheon','google']
_OS_EMOJI_FALLBACK = {
    'windows': '🪟', 'linux': '🐧', 'macos': '🍎',
    'bsd': '🔱', 'android': '📱', 'unix': '💻',
}


def _detect_os_key(os_fingerprint_text,version):
    if not os_fingerprint_text:
        return None
    text = os_fingerprint_text.lower()
    guess = version.lower()
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


def load_os_icons(size=24):
    icons = {}

    try:
        resample_filter = Image.Resampling.LANCZOS
    except AttributeError:
        resample_filter = Image.LANCZOS

    for name in _OS_ICON_NAMES:
        try:
            img = Image.open(os.path.join(os.path.dirname(__file__), f"Assets/os/{name}.png")).resize((size, size), resample_filter)
            icons[name] = ImageTk.PhotoImage(img)
        except Exception as e:
            print(f"[!] Failed to load icon {name}: {e}")
    for name in _LINUX_DISTROS:
        try:
            img = Image.open(os.path.join(os.path.dirname(__file__), f"Assets/os/linux-distros/{name}.png")).resize((size, size),                                                                              resample_filter)
            icons[name] = ImageTk.PhotoImage(img)
        except Exception as e:
            print(f"[!] Failed to load icon {name}: {e}")
    for name in _PRIVATE_SYSTEMS:
        try:
            img = Image.open(os.path.join(os.path.dirname(__file__), f"Assets/os/private-systems/{name}.png")).resize((size, size),                                                                              resample_filter)
            icons[name] = ImageTk.PhotoImage(img)
        except Exception as e:
            print(f"[!] Failed to load icon {name}: {e}")

    for name in _OS_ICON_NAMES:
        if name not in icons:
            icons[name] = _OS_EMOJI_FALLBACK[name]

    return icons


class OSMenu:
    """OS Fingerprint visual results manager."""

    def __init__(self, parent):
        self.parent = parent
        self.target_data = {}
        self.current_target = None
        self.target_buttons = {}

        self.window = None
        self.scroll_frame = None
        self.content_text = None
        self.empty_label = None
        self.count_label = None
        self.detail_header = None
        self.detail_icon_label = None
        self.detail_title_label = None
        self.detail_subtitle_label = None

        self.os_icons = load_os_icons(size=24)
        self.os_icons_large = load_os_icons(size=96)

    def _alive(self):
        if self.window is None:
            return False
        try:
            return bool(self.window.winfo_exists())
        except Exception:
            return False

    def _reset_widget_refs(self):
        self.window = None
        self.scroll_frame = None
        self.content_text = None
        self.empty_label = None
        self.count_label = None
        self.target_buttons = {}
        self.detail_header = None
        self.detail_icon_label = None
        self.detail_title_label = None
        self.detail_subtitle_label = None

    def _on_close(self):
        if self.window is not None:
            try:
                self.window.destroy()
            except Exception:
                pass
        self._reset_widget_refs()

    def show(self):
        if self._alive():
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()
            return

        self._reset_widget_refs()

        self.window = customtkinter.CTkToplevel(self.parent)
        self.window.title("Fingerprint - Lightscan OS Fingerprint")
        self.window.geometry("1100x800")
        self.window.resizable(True, True)
        self.window.transient(self.parent)
        self.window.grab_set()
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
        self.window.bind('<Escape>', lambda e: self._on_close())
        self.window.bind('<F2>', lambda e: self._on_close())

        customtkinter.set_appearance_mode(customtkinter.get_appearance_mode())
        self._build_ui()
        self._center_window()

        if hasattr(self.parent, 'output_text'):
            try:
                existing = self.parent.output_text.get("1.0", "end-1c")
            except Exception:
                existing = ""
            if existing.strip():
                self._ingest(existing)

    def hide(self):
        self._on_close()

    def update_from_output(self, output):
        if not output or not output.strip():
            return

        if threading.current_thread() is threading.main_thread():
            self._ingest(output)
        else:
            try:
                self.parent.after(0, lambda: self._ingest(output))
            except Exception:
                pass

    def clear_all(self):
        self.target_data = {}
        self.current_target = None
        if self._alive():
            self._rebuild_sidebar()
            self._show_welcome()


    def _ingest(self, output):
        """Parse output and update the data model + UI (main thread only)."""
        parsed_targets = parse_multi_target_output(output)
        if not parsed_targets:
            return

        for target, data in parsed_targets.items():
            self.target_data[target] = data
            self.current_target = target

        if not self._alive():
            return

        self._rebuild_sidebar()
        if self.current_target:
            self._show_target(self.current_target)


    def _center_window(self):
        self.window.update_idletasks()
        w = self.window.winfo_width()
        h = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (w // 2)
        y = (self.window.winfo_screenheight() // 2) - (h // 2)
        self.window.geometry(f'{w}x{h}+{x}+{y}')

    def _build_ui(self):
        main_frame = customtkinter.CTkFrame(self.window)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self._build_header(main_frame)

        content_frame = customtkinter.CTkFrame(main_frame)
        content_frame.pack(fill="both", expand=True, pady=(10, 0))

        sidebar = customtkinter.CTkFrame(content_frame, width=220)
        sidebar.pack(side="left", fill="y", padx=(0, 10))
        sidebar.pack_propagate(False)
        self._build_sidebar(sidebar)

        self._build_content_area(content_frame)
        self._build_footer(main_frame)

    def _build_header(self, parent):
        header = customtkinter.CTkFrame(parent)
        header.pack(fill="x", padx=5, pady=5)

        customtkinter.CTkLabel(
            header, text="🔎 Fingerprint Analysis",
            font=("Arial", 22, "bold"), text_color=("black", "white")
        ).pack(side="left", padx=5)

        customtkinter.CTkLabel(
            header, text="Visual Fingerprint Detection Results",
            font=("Arial", 12), text_color=("gray", "gray")
        ).pack(side="left", padx=(10, 0))

        customtkinter.CTkButton(
            header, text="Clear All", width=90, height=28,
            command=self.clear_all,
            fg_color=("#f7f5f0", "#1a1a1a"), text_color=("black", "white"),
            hover_color="grey", border_width=1,
            border_color=("#dbdbdb", "#121211"), corner_radius=8,
        ).pack(side="right", padx=5)

    def _build_sidebar(self, parent):
        self.scroll_frame = customtkinter.CTkScrollableFrame(
            parent, height=500, border_width=0, fg_color="transparent",
        )
        self.scroll_frame.pack(fill="both", expand=True)

        self.empty_label = customtkinter.CTkLabel(
            self.scroll_frame,
            text="No targets yet\n\nRun a scan to see results here",
            font=("Arial", 13), text_color=("gray", "gray")
        )
        self.empty_label.pack(expand=True, pady=50)

        self.count_label = customtkinter.CTkLabel(
            parent, text="Targets: 0",
            font=("Arial", 11), text_color=("gray", "gray")
        )
        self.count_label.pack(side="bottom", pady=5)

        self._rebuild_sidebar()

    def _build_content_area(self, parent):
        frame = customtkinter.CTkFrame(parent)
        frame.pack(side="left", fill="both", expand=True)

        self.detail_header = customtkinter.CTkFrame(frame, fg_color="transparent")
        self.detail_header.pack(fill="x", padx=8, pady=8)

        self.detail_icon_label = customtkinter.CTkLabel(
            self.detail_header, text="", font=("Arial", 60), width=96
        )
        self.detail_icon_label.pack(side="left", padx=(2, 14))

        text_col = customtkinter.CTkFrame(self.detail_header, fg_color="transparent")
        text_col.pack(side="left", fill="both", expand=True)

        self.detail_title_label = customtkinter.CTkLabel(
            text_col, text="", font=("Arial", 20, "bold"),
            text_color=("black", "white"), anchor="w"
        )
        self.detail_title_label.pack(fill="x", anchor="w")

        self.detail_subtitle_label = customtkinter.CTkLabel(
            text_col, text="", font=("Arial", 13),
            text_color=("gray", "gray"), anchor="w"
        )
        self.detail_subtitle_label.pack(fill="x", anchor="w")

        self.content_text = customtkinter.CTkTextbox(
            frame, font=("Consolas", 12), wrap="word",
            border_width=1, border_color=("#dbdbdb", "#121211")
        )
        self.content_text.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        self.content_text.configure(state="disabled")

        if self.target_data and self.current_target:
            self._show_target(self.current_target)
        else:
            self._show_welcome()

    def _build_footer(self, parent):
        footer = customtkinter.CTkFrame(parent)
        footer.pack(fill="x", pady=(10, 0))

        customtkinter.CTkLabel(
            footer, text="  Esc/F2 to close • target list updates automatically after each scan",
            font=("Arial", 10), text_color=("gray", "gray")
        ).pack(side="left")


    def _rebuild_sidebar(self):
        if not self._alive() or self.scroll_frame is None:
            return

        for widget in self.scroll_frame.winfo_children():
            if widget is not self.empty_label:
                widget.destroy()
        self.target_buttons = {}

        if not self.target_data:
            self.empty_label.pack(expand=True, pady=50)
            if self.count_label is not None:
                self.count_label.configure(text="Targets: 0")
            return

        self.empty_label.pack_forget()

        for target, data in self.target_data.items():
            self._add_sidebar_row(target, data)

        if self.count_label is not None:
            self.count_label.configure(text=f"Targets: {len(self.target_data)}")

    def _add_sidebar_row(self, target, data):
        row = customtkinter.CTkFrame(self.scroll_frame, fg_color="transparent")
        row.pack(fill="x", pady=2, padx=5)

        os_key = _detect_os_key(data.get('os_fingerprint'),data.get('os_version'))
        icon = self.os_icons.get(os_key, '💻') if os_key else '💻'

        if isinstance(icon, ImageTk.PhotoImage):
            customtkinter.CTkLabel(row, image=icon, text="").pack(side="left", padx=(5, 10))
        else:
            customtkinter.CTkLabel(row, text=str(icon), font=("Arial", 18)).pack(side="left", padx=(5, 10))

        btn = customtkinter.CTkButton(
            row, text=target, anchor="w",
            command=lambda t=target: self._show_target(t),
            font=("Arial", 13), height=35, corner_radius=8,
            fg_color="transparent", hover_color=("#e0e0e0", "#333333"),
            text_color=("black", "white"),
        )
        btn.pack(side="left", fill="x", expand=True)

        status_color = "#27ae60" if data.get('host_status') == 'up' else "#e74c3c"
        customtkinter.CTkLabel(
            row, text="●", text_color=status_color, font=("Arial", 10)
        ).pack(side="right", padx=5)

        self.target_buttons[target] = btn


    def _show_welcome(self):
        if not self._alive() or self.content_text is None:
            return

        if self.detail_icon_label is not None:
            self.detail_icon_label.configure(image="", text="🔎")
        if self.detail_title_label is not None:
            self.detail_title_label.configure(text="Fingerprint Analysis")
        if self.detail_subtitle_label is not None:
            self.detail_subtitle_label.configure(text="Select a target from the left to view details")

        self.content_text.configure(state="normal")
        self.content_text.delete("1.0", "end")
        self.content_text.insert("1.0", (
            "Each target shows:\n"
            "  - Detected operating system + confidence (shown above as an icon)\n"
            "  - Open / closed / filtered ports\n"
            "  - Captured service banners\n"
            "  - Firewall detection status\n\n"
            "Results update automatically after each scan.\n"
        ))
        self.content_text.configure(state="disabled")

    def _show_target(self, target):
        if not self._alive() or self.content_text is None:
            return
        data = self.target_data.get(target)
        if not data:
            return

        self.current_target = target

        for t, btn in self.target_buttons.items():
            btn.configure(fg_color=("#d4e6f1", "#2c3e50") if t == target else "transparent")

        os_key = _detect_os_key(data.get('os_fingerprint'), data.get('os_version'))
        big_icon = self.os_icons_large.get(os_key) if os_key else None
        if self.detail_icon_label is not None:
            if isinstance(big_icon, ImageTk.PhotoImage):
                self.detail_icon_label.configure(image=big_icon, text="")
            else:
                fallback = self.os_icons_large.get(os_key, '💻') if os_key else '💻'
                self.detail_icon_label.configure(image="", text=str(fallback))

        if self.detail_title_label is not None:
            self.detail_title_label.configure(text=target)
        if self.detail_subtitle_label is not None:
            if data.get('os_fingerprint'):
                self.detail_subtitle_label.configure(
                    text=f"{data['os_fingerprint']} • {data.get('os_confidence', 'N/A')}% confidence"
                )
            else:
                self.detail_subtitle_label.configure(text="OS not detected (run with -O -b)")

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
        lines.append(f"  -> Open:        {data.get('open_ports_count', 0)}")
        lines.append(f"  -> Closed:      {data.get('closed_ports_count', 0)}")
        lines.append(f"  -> Filtered:    {data.get('filtered_ports_count', 0)}")
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

        self.content_text.configure(state="normal")
        self.content_text.delete("1.0", "end")
        self.content_text.insert("1.0", "\n".join(lines))
        self.content_text.configure(state="disabled")
        self.content_text.see("1.0")



def get_instance(parent):
    if not hasattr(parent, '_os_menu_instance') or parent._os_menu_instance is None:
        parent._os_menu_instance = OSMenu(parent)
    return parent._os_menu_instance


def show_os_menu(parent):
    """Open (or refocus) the OS menu window for this parent."""
    menu = get_instance(parent)
    menu.show()
    return menu


def update_os_menu(menu_instance, output):
    """Feed new scan output into an existing OSMenu instance."""
    if menu_instance is not None:
        menu_instance.update_from_output(output)
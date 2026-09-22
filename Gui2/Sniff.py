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

import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QLabel, QHBoxLayout, QVBoxLayout, QWidget,
    QLineEdit, QPushButton, QComboBox, QCheckBox, QTextEdit,
    QMessageBox, QFileDialog
)
from PySide6.QtGui import (
    QIcon, QKeySequence, QShortcut, QAction, QFont
)
from PySide6.QtCore import (
    QProcess
)
import PySide6
from Gui2.Sniffer.CapWorker import CaptureWorker
from Gui2.Sniffer.SniffHelp import show_sniff_help
from Gui2.About import show_about
from Interfaces import interfaces
from ch_admin import check_admin

app_info = {
"panel": {
    "name": "📦 LightPanel6",
    "version": "v1.0.4",
    "description": "Graphical user interface (GUI) for Lightscan network scanner tool"
},
"scanner": {
    "name": "📡 LightSniff",
    "version": "v1.0.3",
    "description": "Real-time packet capture and analysis tool"
},
"gui_lib": {
    "name": "⚡ PySide6",
    "version": PySide6.__version__,
    "description": "Official Python bindings for Qt6 framework (LGPLv3)"
},
"license": "GNU General Public License v2",
"copyright": "© 2026 Adam Boulaaz",
"website": "https://github.com/Light-Projects/Light-Scan"
}

class LightSniffGui(QMainWindow):
    def __init__(self, width: int, height: int):
        super().__init__()

        if not check_admin():
            msg = QMessageBox()
            msg.setWindowTitle('Reminder')
            msg.setText(
                ' - You are trying to run LightPanel6 without root privileges .\n\n - Some of LightSniff functionality may not work \n   due to the lack of needed Permession to run .')
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.exec()

        self.setWindowTitle("LightSniff - Packet Capture GUI")
        self.setGeometry(0, 0, width, height)
        self.setWindowIcon(QIcon("images/LightPanel.png"))

        self.size_font = QFont()
        self.size_font.setPointSize(10)
        self.platform = sys.platform

        self.output_box = QTextEdit()
        font = QFont("Consolas", 10)
        self.output_box.setStyleSheet("border: 1px solid #b0b0b0; border-radius: 5px;")
        self.output_box.setFont(font)
        self.output_box.setReadOnly(True)
        self.output_box.setPlaceholderText("Captured packets will appear here...")

        self.boxes_style = """
            QCheckBox::indicator {
                border: 2px solid #555;
                border-radius: 9px;
                width: 15px;
                height: 15px;
            }
            QCheckBox::indicator:checked {
                border: 2px solid #00ffaa;
                background-color: #00ffaa;
            }
            QCheckBox::indicator:checked:after {
                color: #000000;
            }
        """

        self.labels = []
        self.entries = []
        self.combos = []
        self.boxes = []
        self.worker = None
        self.dark_mode = False

        self.interface = ""
        self.filter_text = ""
        self.count = "0"
        self.write_path = ""
        self.read_path = ""
        self.mac_filter = ""
        self.exp_path = ""

        shortcut = QShortcut(QKeySequence("F5"), self)
        shortcut.activated.connect(self.toggle_theme)
        shortcut1 = QShortcut(QKeySequence("F12"), self)
        shortcut1.activated.connect(self.clear_output)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.layout = QVBoxLayout()
        central_widget.setLayout(self.layout)

        self.create_widgets()
        self.start_theme()
        self.design_entries(self.entries, self.dark_mode)
        self.MenuBar()
        self.layout.addWidget(self.output_box, 1)

    def create_widgets(self) -> None:
        row = QHBoxLayout()

        iface_label = QLabel("Interface : ", margin=2)
        iface_label.setFont(self.size_font)
        row.addWidget(iface_label)
        self.labels.append(iface_label)

        self.iface_combo = QComboBox()
        self.iface_combo.setEditable(True)
        self.iface_combo.addItems(interfaces)
        self.iface_combo.setCurrentIndex(0)
        self.iface_combo.currentTextChanged.connect(self._change_iface)
        self._change_iface(self.iface_combo.currentText())
        row.addWidget(self.iface_combo, 1)
        self.combos.append(self.iface_combo)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_interfaces)
        row.addWidget(refresh_btn)

        row1 = QHBoxLayout()

        filter_label = QLabel("BPF Filter : ", margin=2)
        filter_label.setFont(self.size_font)
        row1.addWidget(filter_label)
        self.labels.append(filter_label)

        filter_entry = QLineEdit(placeholderText=" tcp port 80 or icmp or arp ")
        filter_entry.textChanged.connect(self._change_filter)
        row1.addWidget(filter_entry, 3)
        self.entries.append(filter_entry)

        count_label = QLabel("Count : ", margin=2)
        count_label.setFont(self.size_font)
        row1.addWidget(count_label)
        self.labels.append(count_label)

        count_entry = QLineEdit(placeholderText=" 0 = infinite ")
        count_entry.setText("0")
        count_entry.textChanged.connect(self._change_count)
        row1.addWidget(count_entry, 1)
        self.entries.append(count_entry)

        row2 = QHBoxLayout()
        self.protocol_boxes(row2)

        row3 = QHBoxLayout()

        save_label = QLabel("Save to : ", margin=2)
        save_label.setFont(self.size_font)
        row3.addWidget(save_label)
        self.labels.append(save_label)

        self.save_entry = QLineEdit(placeholderText=" capture.pcap ")
        self.save_entry.textChanged.connect(self._change_write)
        row3.addWidget(self.save_entry, 2)
        self.entries.append(self.save_entry)

        browse_save_btn = QPushButton("Browse")
        browse_save_btn.clicked.connect(self.browse_save)
        row3.addWidget(browse_save_btn)

        load_label = QLabel("Read from : ", margin=2)
        load_label.setFont(self.size_font)
        row3.addWidget(load_label)
        self.labels.append(load_label)

        self.load_entry = QLineEdit(placeholderText=" capture.pcap ")
        self.load_entry.textChanged.connect(self._change_read)
        row3.addWidget(self.load_entry, 2)
        self.entries.append(self.load_entry)

        browse_load_btn = QPushButton("Browse")
        browse_load_btn.clicked.connect(self.browse_load)
        row3.addWidget(browse_load_btn)

        row4 = QHBoxLayout()

        mac_label = QLabel("MAC Filter : ", margin=2)
        mac_label.setFont(self.size_font)
        row4.addWidget(mac_label)
        self.labels.append(mac_label)

        mac_entry = QLineEdit(placeholderText=" aa:bb:cc:dd:ee:ff ")
        mac_entry.textChanged.connect(self._change_mac)
        row4.addWidget(mac_entry, 2)
        self.entries.append(mac_entry)

        self.verbose_box = QCheckBox("Verbose")
        self.verbose_box.setStyleSheet(self.boxes_style)
        self.verbose_box.setFont(self.size_font)
        row4.addWidget(self.verbose_box)
        self.boxes.append(self.verbose_box)

        self.stats_box = QCheckBox("Statistics")
        self.stats_box.setStyleSheet(self.boxes_style)
        self.stats_box.setFont(self.size_font)
        row4.addWidget(self.stats_box)
        self.boxes.append(self.stats_box)

        self.promisc_box = QCheckBox("No Promisc")
        self.promisc_box.setStyleSheet(self.boxes_style)
        self.promisc_box.setFont(self.size_font)
        row4.addWidget(self.promisc_box)
        self.boxes.append(self.promisc_box)

        self.eth = QCheckBox("Ethernet")
        self.eth.setStyleSheet(self.boxes_style)
        self.eth.setFont(self.size_font)
        row4.addWidget(self.eth)
        self.boxes.append(self.eth)

        self.vlan = QCheckBox("VLAN")
        self.vlan.setStyleSheet(self.boxes_style)
        self.vlan.setFont(self.size_font)
        row4.addWidget(self.vlan)
        self.boxes.append(self.vlan)

        self.compress = QCheckBox("Compress (only for .lbn)")
        self.compress.setStyleSheet(self.boxes_style)
        self.compress.setFont(self.size_font)
        row4.addWidget(self.compress)
        self.boxes.append(self.compress)

        row5 = QHBoxLayout()

        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self.start_capture)
        row5.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_capture)
        self.stop_btn.setEnabled(False)
        row5.addWidget(self.stop_btn)

        export_label = QLabel("Export Stats : ", margin=2)
        export_label.setFont(self.size_font)
        row5.addWidget(export_label)
        self.labels.append(export_label)

        self.stats = QLineEdit(placeholderText=" stats.txt ")
        self.stats.textChanged.connect(self._change_stats)
        row5.addWidget(self.stats, 2)
        self.entries.append(self.stats)

        browse_stat = QPushButton("Browse")
        browse_stat.clicked.connect(self.browse_stats)
        row5.addWidget(browse_stat)

        row5.addStretch()

        self.status_label = QLabel("Status : Idle", margin=2)
        self.status_label.setStyleSheet("color: grey;")
        self.status_label.setFont(self.size_font)
        row5.addWidget(self.status_label)

        self.layout.addLayout(row)
        self.layout.addLayout(row1)
        self.layout.addLayout(row2)
        self.layout.addLayout(row3)
        self.layout.addLayout(row4)
        self.layout.addLayout(row5)
        self.layout.addStretch()

    def protocol_boxes(self, row) -> None:
        protocols = [
            ("ARP", "--arp"),
            ("TCP", "--tcp"),
            ("UDP", "--udp"),
            ("ICMP", "--icmp"),
            ("IGMP", "--igmp"),
            ("IPv4", "--ipv4"),
            ("IPv6", "--ipv6"),
            ("SCTP", "--sctp"),
            ("ICMPv6", "--icmpv6"),
        ]

        for label, flag in protocols:
            box = QCheckBox(label)
            box.setStyleSheet(self.boxes_style)
            box.setFont(self.size_font)
            row.addWidget(box)
            self.boxes.append(box)

    def refresh_interfaces(self) -> None:
        self.append_output("\n[+] Fetching available interfaces...\n")
        if sys.platform == "win32":
            ext = "python"
        else:
            ext = "venv/bin/python"
        worker = CaptureWorker(
            program=ext,
            args=["LightSniff.py", "-I"]
        )
        worker.output_ready.connect(self.append_output)
        worker.error_occurred.connect(self.append_output)
        worker.finished.connect(worker.deleteLater)
        self._iface_worker = worker
        worker.start()

    def browse_save(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Capture", "",
            "PCAP Files (*.pcap);;PCAPNG Files (*.pcapng);;LightBin (*.lbn);;All Files (*)"
        )
        if path:
            self.save_entry.setText(path)

    def browse_load(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Capture", "",
            "PCAP Files (*.pcap);;PCAPNG Files (*.pcapng);;LightBin (*.lbn);;All Files (*)"
        )
        if path:
            self.load_entry.setText(path)

    def browse_stats(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Stats Export", "",
            "TXT (*.txt);;All Files (*)"
        )
        if path:
            self.stats.setText(path)

    def _change_iface(self, text) -> None:
        self.interface = text

    def _change_filter(self, text) -> None:
        self.filter_text = text

    def _change_count(self, text) -> None:
        self.count = text

    def _change_write(self, text) -> None:
        self.write_path = text

    def _change_read(self, text) -> None:
        self.read_path = text

    def _change_stats(self, text) -> None:
        self.exp_path = text

    def _change_mac(self, text) -> None:
        self.mac_filter = text

    def append_output(self, text: str) -> None:
        self.output_box.append(text)

    def clear_output(self) -> None:
        self.output_box.clear()

    def copy_output(self) -> None:
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output_box.toPlainText())
        self.append_output("\n[+] Output copied to clipboard\n")

    def set_status(self, text: str, color: str = "grey") -> None:
        self.status_label.setText(f"Status : {text}")
        self.status_label.setStyleSheet(f"color: {color};")

    def start_theme(self) -> None:
        self.setStyleSheet("""background-color: #1a1a1a; color: #dbdbdb;""")
        self.design_entries(self.entries, False)
        self.design_menubar(self.menuBar(), False)
        self.dark_mode = False

    def toggle_theme(self) -> None:
        if not self.dark_mode:
            self.setStyleSheet("""background-color: #f7f5f0; color: #1a1a1a;""")
            self.design_entries(self.entries, True)
            self.design_menubar(self.menuBar(), True)
            self.dark_mode = True
        else:
            self.setStyleSheet("""background-color: #1a1a1a; color: #ffffff;""")
            self.design_entries(self.entries, False)
            self.design_menubar(self.menuBar(), False)
            self.dark_mode = False

    def design_entries(self, entries: list, dark_mode: bool) -> None:
        for en in entries:
            if dark_mode:
                en.setStyleSheet("""
                    QLineEdit {
                        border: 1px solid;
                        border-radius: 5px;
                        padding: 3px;
                        background-color: #dbdbdb
                    }
                    QLineEdit:focus {
                        border: 1px solid;
                    }
                    QLineEdit:hover {
                        border: 1px solid #0066cc;
                    }
                    """)
            else:
                en.setStyleSheet("""
                    QLineEdit {
                        border: 1px solid;
                        border-radius: 5px;
                        padding: 3px;
                        background-color: #2a2a2a
                    }
                    QLineEdit:focus {
                        border: 1px solid;
                    }
                    QLineEdit:hover {
                        border: 1px solid #00ffaa;
                    }
                    """)

    def design_menubar(self, menubar, dark_mode: bool) -> None:
        if dark_mode:
            menubar.setStyleSheet("""
                QMenuBar {
                    background-color: #f7f5f0;
                    color: #1a1a1a;
                    border-bottom: 2px solid #d0d0d0;
                    font-family: "Segoe UI", "Arial", sans-serif;
                    font-size: 13px;
                    padding: 2px 5px;
                }
                QMenuBar::item {
                    background-color: transparent;
                    padding: 6px 12px;
                    margin: 2px 2px;
                    border-radius: 4px;
                }
                QMenuBar::item:selected {
                    background-color: #d0d0d0;
                    color: #0066cc;
                    border: 1px solid #b0b0b0;
                }
                QMenuBar::item:pressed {
                    background-color: #0066cc;
                    color: #ffffff;
                }
                QMenu {
                    background-color: #f7f5f0;
                    color: #1a1a1a;
                    border: 1px solid #b0b0b0;
                    padding: 5px 0px;
                    font-family: "Segoe UI", "Arial", sans-serif;
                    font-size: 13px;
                }
                QMenu::item {
                    padding: 8px 30px 8px 20px;
                    margin: 2px 5px;
                    border-radius: 4px;
                }
                QMenu::item:selected {
                    background-color: #d0d0d0;
                    color: #0066cc;
                    border: 1px solid #b0b0b0;
                }
                QMenu::item:pressed {
                    background-color: #0066cc;
                    color: #ffffff;
                }
                QMenu::separator {
                    height: 1px;
                    background-color: #d0d0d0;
                    margin: 4px 10px;
                }
                QMenu::item:disabled {
                    color: #999999;
                }
                QMenu::icon {
                    padding-right: 10px;
                }
                QMenu::right-arrow {
                    background-color: transparent;
                    color: #1a1a1a;
                    padding-right: 10px;
                }
                QMenu::right-arrow:selected {
                    color: #0066cc;
                }
            """)
        else:
            menubar.setStyleSheet("""
                QMenuBar {
                    background-color: #1a1a1a;
                    color: #ffffff;
                    border-bottom: 2px solid #2a2a2a;
                    font-family: "Segoe UI", "Arial", sans-serif;
                    font-size: 13px;
                    padding: 2px 5px;
                }
                QMenuBar::item {
                    background-color: transparent;
                    padding: 6px 12px;
                    margin: 2px 2px;
                    border-radius: 4px;
                }
                QMenuBar::item:selected {
                    background-color: #2a2a2a;
                    color: #00ffaa;
                    border: 1px solid #3a3a3a;
                }
                QMenuBar::item:pressed {
                    background-color: #00ffaa;
                    color: #000000;
                }
                QMenu {
                    background-color: #1e1e1e;
                    color: #ffffff;
                    border: 1px solid #3a3a3a;
                    padding: 5px 0px;
                    font-family: "Segoe UI", "Arial", sans-serif;
                    font-size: 13px;
                }
                QMenu::item {
                    padding: 8px 30px 8px 20px;
                    margin: 2px 5px;
                    border-radius: 4px;
                }
                QMenu::item:selected {
                    background-color: #2a2a2a;
                    color: #00ffaa;
                    border: 1px solid #3a3a3a;
                }
                QMenu::item:pressed {
                    background-color: #00ffaa;
                    color: #000000;
                }
                QMenu::separator {
                    height: 1px;
                    background-color: #3a3a3a;
                    margin: 4px 10px;
                }
                QMenu::item:disabled {
                    color: #666666;
                }
                QMenu::icon {
                    padding-right: 10px;
                }
                QMenu::right-arrow {
                    background-color: transparent;
                    color: #ffffff;
                    padding-right: 10px;
                }
                QMenu::right-arrow:selected {
                    color: #00ffaa;
                }
            """)

    def MenuBar(self) -> None:
        menu_bar = self.menuBar()

        file_menu = menu_bar.addMenu("&File")

        export_action = QAction(QIcon.fromTheme("document-save-as"), "&Export Output", self)
        export_action.setShortcut(QKeySequence("Ctrl+S"))
        export_action.triggered.connect(self.export_output)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        exit_action = QAction(QIcon.fromTheme("application-exit"), "&Exit", self)
        exit_action.setShortcut(QKeySequence("Alt+F4"))
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        help_menu = menu_bar.addMenu("&Help")

        qhelp = QAction(QIcon.fromTheme("help-contents"), "&Quick Help", self)
        qhelp.setShortcut(QKeySequence("F1"))
        qhelp.triggered.connect(lambda: show_sniff_help(self))
        help_menu.addAction(qhelp)

        about_action = QAction(QIcon.fromTheme("help-about"), "&About LightSniff", self)
        about_action.triggered.connect(lambda: show_about(self,app_info=app_info))
        help_menu.addAction(about_action)



    def export_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Output", "", "Text Files (*.txt);;All Files (*)"
        )
        if path:
            with open(path, "w") as f:
                f.write(self.output_box.toPlainText())
            self.append_output(f"\n[+] Output exported to {path}\n")

    def build_args(self) -> list:
        args = ["LightSniff.py"]

        if self.read_path:
            args += ["-r", self.read_path]

        if self.exp_path:
            args += ["--export-stats", self.exp_path]

        if self.interface:
            args += ["-i", self.interface]

        if self.filter_text:
            args += ["-f", self.filter_text]

        if self.count and self.count != "0":
            args += ["-c", self.count]

        if self.write_path:
            args += ["-w", self.write_path]

        if self.mac_filter:
            args += ["--mac", self.mac_filter]

        protocol_flags = [
            "--arp", "--tcp", "--udp", "--icmp", "--igmp",
            "--ipv4", "--ipv6", "--sctp", "--icmpv6"
        ]
        for i, flag in enumerate(protocol_flags):
            if self.boxes[i].isChecked():
                args.append(flag)

        if self.verbose_box.isChecked():
            args.append("-v")

        if self.stats_box.isChecked():
            args.append("--stats")

        if self.promisc_box.isChecked():
            args.append("--no-promisc")

        if self.eth.isChecked():
            args.append("--eth")

        if self.vlan.isChecked():
            args.append("--vlan")

        if self.compress.isChecked():
            args.append("-C")

        return args

    def start_capture(self) -> None:
        self.clear_output()

        args = self.build_args()
        if sys.platform == "win32":
            ext = "python"
        else:
            ext = "venv/bin/python"
        self.append_output(f"\n[+] Running : {ext} {' '.join(args)}\n\n")

        self.worker = CaptureWorker(
            program=ext,
            args=args
        )

        self.worker.output_ready.connect(self.append_output)
        self.worker.error_occurred.connect(self.append_output)
        self.worker.finished.connect(self.capture_finished)

        self.worker.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.set_status("Capturing ...", "orange")

    def stop_capture(self) -> None:
        if self.worker:
            self.append_output("\n[!] Stopping capture ...\n")
            self.worker.stop()

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.set_status("Stopped", "green")

    def capture_finished(self) -> None:
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.set_status("Completed", "green")

    def closeEvent(self, event):
        if self.worker and self.worker.process.state() != QProcess.ProcessState.NotRunning:
            reply = QMessageBox.question(
                self,
                "Capture Running",
                "A capture is still running. Stop it and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return

            self.worker.stop()
            self.worker.process.waitForFinished(2000)

        event.accept()


def Smain() -> None:
    app = QApplication([])
    app.setStyle('Fusion')

    w, h = resolution(app)
    window = LightSniffGui(w, h)

    window.show()
    sys.exit(app.exec())


def resolution(app: QApplication) -> tuple:
    screen = app.primaryScreen()
    rect = screen.size()
    return rect.width(), rect.height()

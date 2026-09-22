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

from PySide6.QtWidgets import (
   QApplication, QMainWindow, QLabel, QHBoxLayout, QVBoxLayout, QWidget, QLineEdit, QPushButton,
   QComboBox, QCheckBox, QStyle, QTextEdit, QMessageBox, QTabWidget
)
from PySide6.QtGui import (
   QIcon, QKeySequence, QShortcut, QAction, QFont
)
from PySide6.QtCore import (
   QThread, Signal, QObject
)
from confparser import speed_presets_list
from Gui2.About import show_about
from Gui2.Help import show_quick_help
from Gui2.OSMenu import show_os_menu, update_os_menu
from Gui2.Dashboard import Dashboard
from Gui2.Sniff import Smain
from ch_admin import check_admin
import subprocess
import argparse
import json
import signal
import sys
import os
import re
import time

timestamp = time.time()
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
version = "1.0.4"

class LightPanel(QMainWindow):
    def __init__(self, width: int, height: int):
        super().__init__()
        if not check_admin():
            msg = QMessageBox()
            msg.setWindowTitle('Reminder')
            msg.setText(' - You are trying to run LightPanel6 without root privileges .\n\n - Some of Lightscan functionality may not work \n   due to the lack of needed Permession to run .')
            msg.setIcon(QMessageBox.Icon.Warning)
            msg.exec()

        self.lagier = 0
        self.setWindowTitle("LightPanel - Network Scanner GUI")
        self.setGeometry(0, 0, width, height)
        self.setWindowIcon(QIcon("images/LightPanel.png"))
        self.size_font = QFont()
        self.size_font.setPointSize(10)
        self.platform = sys.platform
        self.output_box = QTextEdit()
        font = QFont("Consolas", 10)
        self.output_box.setStyleSheet("border: 1px solid #b0b0b0;border-radius: 5px;")
        self.output_box.setFont(font)
        self.output_box.setReadOnly(True)
        self.output_box.setPlaceholderText("Output will appear here...")

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
        self.entries= []
        self.combos = []
        self.boxes  = []
        self.dark_mode = False
        self.scan_type = "TCP"
        self.host_discovery = ""
        self.host_discovery_dict = {
            "IP":" -Pi ","TCP":" -Pt ","SYN":" -Ps ","ACK":" -Pk ",
            "UDP":" -Pu ","ICMP-TIMESTAMP":" -PIt ",
            "ICMP-ADDRESS":" -PA ","ICMP-ECHO":"","ICMP-INFO":" -Pin ",
            "ICMP-SOLI":" -Pas ","IGMP":" -Pg "
        }
        self.speed_pre = "normal"
        self.ptar = "None"
        self.pcmd = "None"
        self.format = "None"
        self.profiles = ["None"]
        self.profile_c = "None"

        self.profiles.extend(
            [f.replace(".json","") for f in os.listdir(os.path.join(os.path.dirname(__file__), "Profiles")) if f.endswith('.json')])

        shortcut = QShortcut(QKeySequence("F5"), self)
        shortcut.activated.connect(self.toggle_theme)
        shortcut1 = QShortcut(QKeySequence("F12"), self)
        shortcut1.activated.connect(self.clear_output)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        self.layout = QVBoxLayout()
        central_widget.setLayout(self.layout)

        scan_tab = QWidget()
        scan_tab.setLayout(self.layout)

        self._dashboard_instance = Dashboard(self)

        self.tabs = QTabWidget()
        self.tabs.addTab(scan_tab, "Scan")
        self.tabs.addTab(self._dashboard_instance, "Dashboard")

        outer = QVBoxLayout(central_widget)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(self.tabs)

        self.toggle_theme()
        self.create_labels_and_entries()
        self.start_theme()
        self.design_entries(self.entries,self.dark_mode)
        self.MenuBar()
        self.layout.addWidget(self.output_box,1)

    def create_labels_and_entries(self) -> None:
        row = QHBoxLayout()

        cmd_label = QLabel("Command : ",margin=2)
        cmd_label.setFont(self.size_font)
        row.addWidget(cmd_label)
        self.labels.append(cmd_label)

        cmd_entry = QLineEdit(placeholderText=" (EX: Lightscan.py -T example.com -st SYN -F -b -O ")
        row.addWidget(cmd_entry)
        self.entries.append(cmd_entry)

        scan_button = QPushButton("Scan")
        scan_button.clicked.connect(self.start_scan)
        row.addWidget(scan_button)
        self.scan_button = scan_button

        stop_button = QPushButton("Stop")
        stop_button.clicked.connect(self.stop_scan)
        stop_button.setEnabled(False)
        row.addWidget(stop_button)
        self.stop_button = stop_button

        row1 = QHBoxLayout()

        target_label = QLabel("Target : ",margin=2)
        target_label.setFont(self.size_font)
        row1.addWidget(target_label)
        self.labels.append(target_label)

        target_entry = QLineEdit(placeholderText=" exapmple.com or 192.168.1.0/24 ")
        row1.addWidget(target_entry)
        self.entries.append(target_entry)

        port_label = QLabel("Port : ",margin=2)
        port_label.setFont(self.size_font)
        row1.addWidget(port_label)
        self.labels.append(port_label)

        port_entry = QLineEdit(placeholderText=" 80,443 or 1-1000 ")
        row1.addWidget(port_entry)
        self.entries.append(port_entry)

        self.drop_downs1(row1)
        row2 = QHBoxLayout()
        self.check_boxes(row2)

        row3 = QHBoxLayout()
        self.drop_down2(row3)

        row4 = QHBoxLayout()
        self.footer(row4)

        row5 = QHBoxLayout()
        self.drop_down3(row5)

        self.layout.addLayout(row)
        self.layout.addLayout(row1)
        self.layout.addLayout(row2)
        self.layout.addLayout(row3)
        self.layout.addLayout(row5)
        self.layout.addLayout(row4)
        self.layout.addStretch()

    def append_output(self, text: str) -> None:
        self.output_box.append(text)

    def clear_output(self) -> None:
        self.output_box.clear()

    def footer(self,row) -> None:
        slabel = QLabel("Status : Init ",margin=2)
        slabel.setStyleSheet("color: grey;")
        slabel.setFont(self.size_font)
        row.addWidget(slabel)
        self.labels.append(slabel)

    def footer_yellow(self):
        self.labels[9].setText("Status : Running ... ")
        self.labels[9].setStyleSheet("color: orange;")

    def footer_green(self):
        self.labels[9].setText("Status : Completed")
        self.labels[9].setStyleSheet("color: green;")

    def drop_downs1(self,row) -> None:

        scan_label = QLabel("Scan Type : ",margin=2)
        scan_label.setFont(self.size_font)
        row.addWidget(scan_label)
        self.labels.append(scan_label)

        scan_type = QComboBox()
        scan_type.addItems(["TCP","SYN","UDP","NULL","FIN","ACK","XMAS","MAIMON","WINDOW",
                            "FDD","FTP-BOUNCE","IPPROTO","IDLE","PING","SCTP-INIT"])
        scan_type.setCurrentIndex(0)
        scan_type.currentTextChanged.connect(self._change_scan)
        row.addWidget(scan_type)
        self.combos.append(scan_type)

        labell = QLabel("Pinging Type : ",margin=2)
        labell.setFont(self.size_font)
        row.addWidget(labell)
        self.labels.append(labell)

        pinging_type = QComboBox()
        pinging_type.addItems(["IP","TCP","SYN","ACK","UDP","ICMP-ECHO","ICMP-ADDRESS",
                               "ICMP-TIMESTAMP","ICMP-INFO","ICMP-SOLI","IGMP"])
        pinging_type.setCurrentIndex(5)
        pinging_type.currentTextChanged.connect(self._change_pinging)
        row.addWidget(pinging_type)
        self.combos.append(pinging_type)

        speed_label = QLabel("Speed : ",margin=2)
        speed_label.setFont(self.size_font)
        row.addWidget(speed_label)
        self.labels.append(speed_label)

        speed_combo = QComboBox()
        speed_combo.addItems(speed_presets_list())
        speed_combo.setCurrentIndex(2)
        speed_combo.currentTextChanged.connect(self._change_speed)
        row.addWidget(speed_combo)
        self.combos.append(speed_combo)

    def drop_down2(self, row) -> None:

        saving_group = QHBoxLayout()

        saving = QLabel("Saving Format : ", margin=2)
        saving.setFont(self.size_font)
        saving_group.addWidget(saving, 0)
        self.labels.append(saving)

        saving_formats = QComboBox()
        saving_formats.addItems(["None", "TXT", "LIGHT", "HTML", "XML", "JSON", "CSV",
                                 "YAML", "TOML", "HEX-STR"])
        saving_formats.setCurrentIndex(0)
        saving_formats.currentTextChanged.connect(self._change_format)
        saving_group.addWidget(saving_formats, 1)
        self.combos.append(saving_formats)

        profiles_group = QHBoxLayout()

        profiles = QLabel("Profiles : ", margin=2)
        profiles.setFont(self.size_font)
        profiles_group.addWidget(profiles, 0)
        self.labels.append(profiles)

        profiles_list = QComboBox()
        profiles_list.addItems(self.profiles)
        profiles_list.setCurrentIndex(0)
        profiles_list.currentTextChanged.connect(self._change_profiles)
        profiles_group.addWidget(profiles_list, 1)
        self.combos.append(profiles_list)

        save_profile_group = QHBoxLayout()

        sprofiles = QLabel("Save Profile : ", margin=2)
        sprofiles.setFont(self.size_font)
        save_profile_group.addWidget(sprofiles, 0)
        self.labels.append(sprofiles)

        profiles_name = QLineEdit(placeholderText=" heretic_scan ")
        save_profile_group.addWidget(profiles_name, 1)
        self.entries.append(profiles_name)

        row.addLayout(saving_group, 1)
        row.addSpacing(20)
        row.addLayout(profiles_group, 1)
        row.addSpacing(20)
        row.addLayout(save_profile_group, 1)

    def drop_down3(self, row) -> None:

        cmdh = QHBoxLayout()

        pp = QLabel("Past Commands : ", margin=2)
        pp.setFont(self.size_font)
        cmdh.addWidget(pp, 0)
        self.labels.append(pp)

        cmd_history = QComboBox()
        cmd_history.addItems(["None"])
        cmd_history.currentTextChanged.connect(self._change_pcmd)
        cmd_history.setCurrentIndex(0)
        cmdh.addWidget(cmd_history, 1)
        self.combos.append(cmd_history)

        tarh = QHBoxLayout()

        ss = QLabel("Past Targets : ", margin=2)
        ss.setFont(self.size_font)
        tarh.addWidget(ss, 0)
        self.labels.append(ss)

        target_history = QComboBox()
        target_history.addItems(["None"])
        target_history.currentTextChanged.connect(self._change_ptar)
        target_history.setCurrentIndex(0)
        tarh.addWidget(target_history, 1)
        self.combos.append(target_history)

        row.addLayout(cmdh, 1)
        row.addSpacing(20)
        row.addLayout(tarh, 1)

    def check_boxes(self,row) -> None:
        F = QCheckBox('Top 100 Ports')
        F.setStyleSheet(self.boxes_style)
        F.setFont(self.size_font)
        row.addWidget(F)
        self.boxes.append(F)

        OS = QCheckBox('OS Detect')
        OS.setStyleSheet(self.boxes_style)
        OS.setFont(self.size_font)
        row.addWidget(OS)
        self.boxes.append(OS)

        banner = QCheckBox('Banner Grab')
        banner.setStyleSheet(self.boxes_style)
        banner.setFont(self.size_font)
        row.addWidget(banner)
        self.boxes.append(banner)

        nopi = QCheckBox('No Ping')
        nopi.setStyleSheet(self.boxes_style)
        nopi.setFont(self.size_font)
        row.addWidget(nopi)
        self.boxes.append(nopi)

        ip6 = QCheckBox('IPv6')
        ip6.setStyleSheet(self.boxes_style)
        ip6.setFont(self.size_font)
        row.addWidget(ip6)
        self.boxes.append(ip6)

        frag = QCheckBox('Fragment')
        frag.setStyleSheet(self.boxes_style)
        frag.setFont(self.size_font)
        row.addWidget(frag)
        self.boxes.append(frag)

        rec = QCheckBox('Recursively')
        rec.setStyleSheet(self.boxes_style)
        rec.setFont(self.size_font)
        row.addWidget(rec)
        self.boxes.append(rec)

        rdns = QCheckBox('rDNS')
        rdns.setStyleSheet(self.boxes_style)
        rdns.setFont(self.size_font)
        row.addWidget(rdns)
        self.boxes.append(rdns)

        help_b = QCheckBox('Help')
        help_b.setStyleSheet(self.boxes_style)
        help_b.setFont(self.size_font)
        row.addWidget(help_b)
        self.boxes.append(help_b)

    def _change_scan(self, text) -> None:
        self.scan_type = text

    def _change_pinging(self, text) -> None:
        self.host_discovery = self.host_discovery_dict.get(text)

    def _change_speed(self, text) -> None:
        self.speed_pre = text

    def _change_format(self, text) -> None:
        self.format = text

    def _change_profiles(self, text) -> None:
        self.profile_c = text

    def _change_ptar(self, text) -> None:
        self.ptar = text

    def _change_pcmd(self, text) -> None:
        self.pcmd = text

    def start_theme(self) -> None:
         self.setStyleSheet("""background-color: #1a1a1a; color: #dbdbdb;""")
         self.design_entries(self.entries, False)
         self.design_menubar(self.menuBar(),False)
         self.dark_mode = False

    def toggle_theme(self) -> None:
        if not self.dark_mode:
            self.setStyleSheet("""background-color: #f7f5f0; color: #1a1a1a;""")
            self.design_entries(self.entries,True)
            self.design_menubar(self.menuBar(), True)
            self.dark_mode = True
        else:
            self.setStyleSheet("""background-color: #1a1a1a; color: #ffffff;""")
            self.design_entries(self.entries, False)
            self.design_menubar(self.menuBar(), False)
            self.dark_mode = False

        existing_menu = getattr(self, '_os_menu_instance', None)
        if existing_menu is not None:
            existing_menu.apply_styles()

        if self.lagier != 0:
            existing_dash = getattr(self, '_dashboard_instance', None)
            if existing_dash is not None:
                existing_dash.apply_styles()
        self.lagier += 1

    def design_entries(self, entries: list,dark_mode: bool) -> None:
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
        #####################################################################
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

        help_menu = menu_bar.addMenu("&Help")

        help_action = QAction(QIcon.fromTheme("help-contents"),"&Quick Help", self)
        help_action.setShortcut(QKeySequence("F1"))
        help_action.triggered.connect(self._show_quick_help)
        help_menu.addAction(help_action)

        help_menu.addSeparator()

        about_action = QAction(QIcon.fromTheme("help-about"),"&About LightPanel", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

        file_menu = menu_bar.addMenu("&Stop")

        exit_action = QAction(QIcon.fromTheme("application-exit"),"&Exit", self)
        exit_action.setShortcut(QKeySequence("Alt+F4"))
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        os_menu = menu_bar.addMenu("&OS")
        os_img = self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogContentsView)
        show_os_action = QAction(os_img,"&Show OS Fingerprint", self)
        show_os_action.setShortcut(QKeySequence("F2"))
        show_os_action.triggered.connect(self.show_os_fingerprint)
        os_menu.addAction(show_os_action)

    def save_history(self):
        os.makedirs(".lightpanel6",exist_ok=True)
        with open(f".lightpanel6/history_{timestamp}.json", "w") as f:
            json.dump({
                "targets": [self.combos[6].itemText(i).strip() for i in range(self.combos[5].count())],
                "commands": [self.combos[5].itemText(i).strip() for i in range(self.combos[4].count())]
            }, f, indent=2)

    def _show_quick_help(self):
        show_quick_help(self)

    def _show_about(self) -> None:
        show_about(self)

    def show_os_fingerprint(self):
        show_os_menu(self)

    def start_scan(self) -> None:
        commd = self.build_cmd()
        self.clear_output()
        self.thread = QThread()
        self.worker = ScanWorker(commd, self)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.output_ready.connect(self.append_output)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.def_but)
        self.worker.finished.connect(self.footer_green)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()
        self.footer_yellow()

        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def stop_scan(self) -> None:
        if hasattr(self, 'worker') and self.worker:
            self.append_output("\n[!] Killing scan...\n")
            self.worker.kill()

        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def def_but(self) -> None:
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def build_cmd(self) -> str:
        if self.platform == "win32":
            executer = "sudo python Lightscan.py "
        else:
            executer = "sudo venv/bin/python Lightscan.py "


        command = self.entries[0].text()
        trusted_command = ""

        if command == "":
            if self.pcmd != "None":
                self.combos[5].addItem(self.pcmd)
                return self.pcmd

            trusted_command += executer
            if self.boxes[8].isChecked():
                trusted_command += f" -h "
                if trusted_command != self.pcmd:
                    self.combos[5].addItems([trusted_command])
                return trusted_command

            if self.entries[1].text() != "":
                trusted_command += f" -T {self.entries[1].text()}"
                if self.entries[1].text().strip() not in [self.combos[6].itemText(i).strip() for i in range(self.combos[6].count())]:
                    self.combos[6].addItems([self.entries[1].text()])

                self.entries[1].setText("")
            else:
                if self.ptar != "None":
                    trusted_command += f" -T {self.ptar}"
                    if self.ptar.strip() not in [self.combos[6].itemText(i).strip() for i in range(self.combos[6].count())]:
                        self.combos[6].addItems([self.ptar])
                else:
                    trusted_command += f" -T localhost"
                    if "localhost" not in [self.combos[6].itemText(i).strip() for i in range(self.combos[6].count())]:
                        self.combos[6].addItems(["localhost"])

            if self.entries[2].text() != "":
                trusted_command += f" -p {self.entries[2].text()}"
            if self.entries[3].text() != "":
                trusted_command += f" --save-profile {self.entries[3].text()}"

            if self.format != "None":
                trusted_command += f" --save {self.format}"
            if self.profile_c != "None":
                trusted_command += f" --load-profile {self.profile_c}"
            if self.scan_type != "":
                trusted_command += f" -st {self.scan_type}"
            if self.speed_pre != "":
                trusted_command += f" -s {self.speed_pre}"

            if self.boxes[0].isChecked():
                trusted_command += f" -F "
            if self.boxes[1].isChecked():
                trusted_command += f" -O "
            if self.boxes[2].isChecked():
                trusted_command += f" -b "
            if self.boxes[3].isChecked():
                trusted_command += f" -Pn "
            if self.boxes[4].isChecked():
                trusted_command += f" -V6 "
            if self.boxes[5].isChecked():
                trusted_command += f" -f "
            if self.boxes[6].isChecked():
                trusted_command += f" -Rc "
            if self.boxes[7].isChecked():
                trusted_command += f" -n "

            trusted_command += self.host_discovery

        else:
            if command is not None and "sudo" not in command:
                self.append_output("\n[!] Lightscan need root privillege to run, use sudo. \n")
            elif command.startswith("sudo venv/bin/python Lightscan.py"):
                invalid_chars = ['&', '|', ':', '`', '$', '>', '<']
                for char in invalid_chars:
                    if char in command:
                        sys.exit(-1)
                trusted_command = str(command)
            else:
                self.append_output(f"\n[!] Make sure the python env name is 'venv' .\n")

        if trusted_command != self.pcmd:
            self.combos[5].addItems([trusted_command])
        self.save_history()

        return trusted_command

    def closeEvent(self, event):
        if hasattr(self, 'worker') and self.worker:
            if self.worker.process and self.worker.process.poll() is None:
                reply = QMessageBox.question(
                    self,
                    "Scan Running",
                    "A scan is still running. Stop it and exit?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    event.ignore()
                self.worker.kill()

        event.accept()

class ScanWorker(QObject):
    output_ready = Signal(str)
    finished = Signal()

    def __init__(self, cmd, parent_window):
        super().__init__()
        self.cmd = cmd
        self.parent_window = parent_window
        self.process = None

    def run(self):
        self.output_ready.emit("\n[+] Running command : " + self.cmd + "\n")
        try:
            if sys.platform == "win32":
                self.process = subprocess.Popen(
                    self.cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )
            else:
                self.process = subprocess.Popen(
                    self.cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    start_new_session=True
                )

            stdout, _ = self.process.communicate()
            text = ANSI_ESCAPE.sub("", stdout)
            self.output_ready.emit(text)

            self.process.wait()

            if self.process.returncode == 0:
                self.output_ready.emit("\n[+] Scan completed successfully\n")
            else:
                self.output_ready.emit(f"\n[!] Process exited with code {self.process.returncode}\n")

            existing_menu = getattr(self.parent_window, '_os_menu_instance', None)
            if existing_menu is not None:
                update_os_menu(existing_menu, stdout)

            existing_dash = getattr(self.parent_window, '_dashboard_instance', None)
            if existing_dash is not None:
                existing_dash.update_from_output(stdout)

        except Exception as e:
            self.output_ready.emit(f"[-] Error: {e}\n")
        finally:
            self.finished.emit()

    def kill(self):
        if self.process is None:
            return
        try:
            if sys.platform == "win32":
                self.process.terminate()
            else:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass

        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            if sys.platform == "win32":
                self.process.kill()
            else:
                os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)

def main() -> None:
    args = parse_args()
    if args.gui == "lightscan":
        app = QApplication([])
        app.setStyle('Fusion')
        w, h = resolution(app)
        window = LightPanel(w, h)
    elif args.gui == "lightsniff":
        window = Smain()
    else:
        app = QApplication([])
        app.setStyle('Fusion')
        w, h = resolution(app)
        window = LightPanel(w, h)

    window.show()
    sys.exit(app.exec())

def parse_args():
    parser = argparse.ArgumentParser(
        description="LightPanel6 - Light-Scan Multi Graphical User Interface",
        epilog="""
Examples:
    LightPanel6 --gui lightscan """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    basic = parser.add_argument_group('Basic Options')
    basic.add_argument("-G", "--gui", default="lightscan",choices=["lightscan","lightsniff"])
    return parser.parse_args()

def resolution(app: QApplication) -> tuple[int,int]:
    screen = app.primaryScreen()
    rect = screen.size()
    return rect.width(), rect.height()

if __name__ == "__main__":
    main()
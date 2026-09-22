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
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QWidget, QScrollArea
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
import PySide6


class AboutDialog(QDialog):
    def __init__(self, parent=None,app_info=None):
        super().__init__(parent)
        self.parent = parent

        if app_info is None:
            self.app_info = {
                "panel": {
                    "name": "📦 LightPanel6",
                    "version": "v1.0.4",
                    "description": "Graphical user interface (GUI) for Lightscan network scanner tool"
                },
                "scanner": {
                    "name": "🔍 Lightscan",
                    "version": "v1.1.9",
                    "description": "Open source network security tool for pentesters and network admins"
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
        else:
            self.app_info = app_info

        self.setWindowTitle("About - Lightscan and LightPanel")
        self.setGeometry(0, 0, 650, 500)
        self.setMinimumSize(450, 400)

        self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)

        self.setup_ui()
        self.center_window()
        self.apply_styles()

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)

        header = self.create_header()
        main_layout.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setContentsMargins(10, 10, 10, 10)
        content_layout.setSpacing(5)

        self.create_content(content_layout)
        scroll.setWidget(content_widget)
        main_layout.addWidget(scroll)

        footer = self.create_footer()
        main_layout.addWidget(footer)

    def create_header(self):
        header = QWidget()
        layout = QHBoxLayout(header)
        layout.setContentsMargins(5, 5, 5, 5)

        title = QLabel("📖 About Light-Scan")
        title_font = QFont("Arial", 20, QFont.Weight.Bold)
        title.setFont(title_font)
        layout.addWidget(title)
        layout.addStretch()

        return header

    def create_content(self, parent_layout):
        panel_name = QLabel(self.app_info["panel"]["name"])
        panel_name_font = QFont("Arial", 18, QFont.Weight.Bold)
        panel_name.setFont(panel_name_font)
        parent_layout.addWidget(panel_name)

        panel_version = QLabel(f"Version: {self.app_info['panel']['version']}")
        panel_version.setStyleSheet("color: gray; font-size: 13px;")
        parent_layout.addWidget(panel_version)

        panel_desc = QLabel(self.app_info["panel"]["description"])
        panel_desc.setWordWrap(True)
        panel_desc.setStyleSheet("font-size: 13px;")
        parent_layout.addWidget(panel_desc)

        spacer = QWidget()
        spacer.setFixedHeight(10)
        parent_layout.addWidget(spacer)

        scanner_name = QLabel(self.app_info["scanner"]["name"])
        scanner_name_font = QFont("Arial", 18, QFont.Weight.Bold)
        scanner_name.setFont(scanner_name_font)
        parent_layout.addWidget(scanner_name)

        scanner_version = QLabel(f"Version: {self.app_info['scanner']['version']}")
        scanner_version.setStyleSheet("color: gray; font-size: 13px;")
        parent_layout.addWidget(scanner_version)

        scanner_desc = QLabel(self.app_info["scanner"]["description"])
        scanner_desc.setWordWrap(True)
        scanner_desc.setStyleSheet("font-size: 13px;")
        parent_layout.addWidget(scanner_desc)

        spacer = QWidget()
        spacer.setFixedHeight(10)
        parent_layout.addWidget(spacer)

        gui_name = QLabel(self.app_info["gui_lib"]["name"])
        gui_name_font = QFont("Arial", 18, QFont.Weight.Bold)
        gui_name.setFont(gui_name_font)
        parent_layout.addWidget(gui_name)

        gui_version = QLabel(f"Version: {self.app_info['gui_lib']['version']}")
        gui_version.setStyleSheet("color: gray; font-size: 13px;")
        parent_layout.addWidget(gui_version)

        gui_desc = QLabel(self.app_info["gui_lib"]["description"])
        gui_desc.setWordWrap(True)
        gui_desc.setStyleSheet("font-size: 13px;")
        parent_layout.addWidget(gui_desc)

        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFixedHeight(1)
        separator.setStyleSheet("background-color: gray;")
        parent_layout.addSpacing(10)
        parent_layout.addWidget(separator)

        license_label = QLabel(f"📜 License: {self.app_info['license']}")
        license_label.setStyleSheet("color: gray; font-size: 11px;")
        parent_layout.addWidget(license_label)

        copyright_label = QLabel(f"© {self.app_info['copyright']}")
        copyright_label.setStyleSheet("color: gray; font-size: 11px;")
        parent_layout.addWidget(copyright_label)

        website_label = QLabel(f'🔗 <a href="{self.app_info["website"]}" style="color: #0066cc;">GitHub Repository</a>')
        website_label.setOpenExternalLinks(True)
        website_label.setStyleSheet("font-size: 11px;")
        parent_layout.addWidget(website_label)

        parent_layout.addStretch()

    def create_footer(self):
        footer = QWidget()
        layout = QHBoxLayout(footer)
        layout.setContentsMargins(5, 10, 5, 5)

        info = QLabel("Esc to close")
        info.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(info)

        layout.addStretch()

        version = QLabel(f"Light-Scan v{self.app_info['scanner']['version']}  •  PySide6 {self.app_info['gui_lib']['version']}")
        version.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(version)

        return footer

    def center_window(self):
        screen = self.screen().size()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)

    def apply_styles(self):
        is_light = hasattr(self.parent, 'dark_mode') and not self.parent.dark_mode

        if not is_light:
            self.setStyleSheet("""
                background-color: #f7f5f0;
                QDialog {
                    background-color: #f5f5f5;
                }
                QLabel {
                    color: #1a1a1a;
                }
                QScrollArea {
                    border: none;
                    background-color: transparent;
                }
                QFrame {
                    background-color: transparent;
                }
            """)
        else:
            self.setStyleSheet("""
                background-color: #1a1a1a;
                QDialog {
                    background-color: #0a0a0a;
                }
                QLabel {
                    color: #00ffaa;
                }
                QScrollArea {
                    border: none;
                    background-color: transparent;
                }
                QFrame {
                    background-color: transparent;
                }
            """)


def show_about(parent,app_info=None):
    dialog = AboutDialog(parent,app_info=app_info)
    dialog.exec()
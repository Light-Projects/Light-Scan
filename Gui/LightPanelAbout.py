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

import customtkinter
from typing import Optional

class About:
    def __init__(self, parent):
        self.parent = parent
        self.window: Optional[customtkinter.CTkToplevel] = None

        self.app_info = {
            "panel": {
                "name": "LightPanel",
                "version": "v1.0.3",
                "description": "Graphical user interface (GUI) for Lightscan network scanner tool"
            },
            "scanner": {
                "name": "Lightscan",
                "version": "v1.1.9",
                "description": "Open source network security tool for pentesters and network admins"
            },
            "license": "GNU General Public License v2",
            "copyright": "© 2026 Adam Boulaaz",
            "website": "https://github.com/Light-Projects/Light-Scan"
        }

    def show(self):
        self.window = customtkinter.CTkToplevel(self.parent)
        self.window.title("About - Lightscan and LightPanel")
        self.window.geometry("700x500")
        self.window.minsize(500, 400)
        self.window.transient(self.parent)
        self.window.grab_set()

        self.sync_theme()
        self.center_window()
        self.build_ui()

    def sync_theme(self):
        customtkinter.set_appearance_mode(customtkinter.get_appearance_mode())

    def center_window(self):
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')

    def build_ui(self):
        main_frame = customtkinter.CTkFrame(self.window)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.build_header(main_frame)

        scroll_frame = customtkinter.CTkScrollableFrame(main_frame)
        scroll_frame.pack(fill="both", expand=True, pady=(10, 0))

        self.build_content(scroll_frame)
        self.build_footer(main_frame)

        self.window.bind('<Escape>', lambda e: self.window.destroy())

    def build_header(self, parent):
        header = customtkinter.CTkFrame(parent)
        header.pack(fill="x")

        title = customtkinter.CTkLabel(
            header,
            text="📖 About Light-Scan Framework",
            font=("Arial", 24, "bold"),
            text_color=("black", "white")
        )
        title.pack(side="left", padx=5)

    def build_content(self, parent):
        panel_label = customtkinter.CTkLabel(
            parent,
            text=self.app_info["panel"]["name"],
            font=("Arial", 20, "bold"),
            text_color=("black", "white")
        )
        panel_label.grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))

        panel_version = customtkinter.CTkLabel(
            parent,
            text=self.app_info["panel"]["version"],
            font=("Arial", 14),
            text_color=("gray", "gray")
        )
        panel_version.grid(row=0, column=1, sticky="w", padx=10, pady=(10, 0))

        panel_desc = customtkinter.CTkLabel(
            parent,
            text=self.app_info["panel"]["description"],
            font=("Arial", 14),
            text_color=("black", "white"),
            wraplength=600,
            justify="left"
        )
        panel_desc.grid(row=1, column=0, columnspan=2, sticky="w", padx=10, pady=5)

        scanner_label = customtkinter.CTkLabel(
            parent,
            text=self.app_info["scanner"]["name"],
            font=("Arial", 20, "bold"),
            text_color=("black", "white")
        )
        scanner_label.grid(row=2, column=0, sticky="w", padx=10, pady=(20, 0))

        scanner_version = customtkinter.CTkLabel(
            parent,
            text=self.app_info["scanner"]["version"],
            font=("Arial", 14),
            text_color=("gray", "gray")
        )
        scanner_version.grid(row=2, column=1, sticky="w", padx=10, pady=(20, 0))

        scanner_desc = customtkinter.CTkLabel(
            parent,
            text=self.app_info["scanner"]["description"],
            font=("Arial", 14),
            text_color=("black", "white"),
            wraplength=600,
            justify="left"
        )
        scanner_desc.grid(row=3, column=0, columnspan=2, sticky="w", padx=10, pady=5)

        separator = customtkinter.CTkFrame(parent, height=2, fg_color=("gray", "gray"))
        separator.grid(row=4, column=0, columnspan=2, sticky="ew", padx=10, pady=15)

        license_label = customtkinter.CTkLabel(
            parent,
            text=f"License: {self.app_info['license']}",
            font=("Arial", 12),
            text_color=("gray", "gray")
        )
        license_label.grid(row=5, column=0, columnspan=2, sticky="w", padx=10, pady=5)

        copyright_label = customtkinter.CTkLabel(
            parent,
            text=self.app_info["copyright"],
            font=("Arial", 12),
            text_color=("gray", "gray")
        )
        copyright_label.grid(row=6, column=0, columnspan=2, sticky="w", padx=10, pady=5)


    def build_footer(self, parent):
        footer = customtkinter.CTkFrame(parent)
        footer.pack(fill="x", pady=(10, 0))

        info = customtkinter.CTkLabel(
            footer,
            text="  Esc to close • Theme sync enabled",
            font=("Arial", 10),
            text_color=("gray", "gray")
        )
        info.pack(side="left")

        close_btn = customtkinter.CTkButton(
            footer,
            text="Close",
            width=80,
            height=30,
            command=self.window.destroy
        )
        close_btn.pack(side="right", padx=(0, 5))

        version = customtkinter.CTkLabel(
            footer,
            text=f"Lightscan {self.app_info['scanner']['version']}   ",
            font=("Arial", 10),
            text_color=("gray", "gray")
        )
        version.pack(side="right", padx=5)


def show_about(parent):
    About(parent).show()
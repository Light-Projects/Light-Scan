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
import customtkinter
import tkinter
import subprocess
import threading
import os
from CTkMessagebox import CTkMessagebox

version = "1.0.0"


def invalid_lightscan_command():
    CTkMessagebox(
        title="Error",
        message="Invalid Lightscan command!",
        icon="cancel",
        option_1="OK"
    )

def copy_output():
    try:
        output_text.clipboard_clear()
        output_text.clipboard_append(output_text.get("1.0", "end-1c"))
        CTkMessagebox(
            title="Copied",
            message="Output copied to clipboard!",
            icon="info",
            option_1="OK"
        )
    except:
        CTkMessagebox(
            title="Error",
            message="Failed to copy output!",
            icon="cancel",
            option_1="OK"
        )

def clear_output():
    output_text.delete("1.0", "end")

def build_command():
    command = command_entry.get()

    if not command or command == "sudo venv/bin/python Lightscan.py -T example.com -F -st SYN":
        command = "sudo venv/bin/python Lightscan.py"

        target = target_entry.get()
        if target:
            command += f" -T {target}"

        ports = ports_entry.get()
        if ports:
            command += f" -p {ports}"

        proname = pro_entry.get()
        if proname:
            command += f" --save-profile {proname}"

        scan_type = scan_type_var.get()
        if scan_type != "TCP Connect (default)":
            if scan_type == "SYN Stealth":
                command += " -st SYN"
            elif scan_type == "UDP Scan":
                command += " -st UDP"
            elif scan_type == "NULL Scan":
                command += " -st NULL"
            elif scan_type == "FIN Scan":
                command += " -st FIN"
            elif scan_type == "ACK Scan":
                command += " -st ACK"
            elif scan_type == "WINDOW Scan":
                command += " -st WINDOW"
            elif scan_type == "MAIMON Scan":
                command += " -st MAIMON"
            elif scan_type == "XMAS Scan":
                command += " -st XMAS"
            elif scan_type == "FDD Scan":
                command += " -st FDD"
            elif scan_type == "FTP Bounce":
                command += " -st FTP-BOUNCE"
            elif scan_type == "IPPROTO Scan":
                command += " -st IPPROTO"
            elif scan_type == "IDLE Scan":
                command += " -st IDLE"
            elif scan_type == "Ping Sweep":
                command += " -st PING"
            elif scan_type == "SCTP-INIT":
                command += " -st SCTP-INIT"


        speed_preset = speed_var.get()
        if speed_preset != "Normal (default)":
            if speed_preset == "Paranoid (2 threads, 4.5s timeout)":
                command += " -s paranoid"
            elif speed_preset == "Slow (30 threads, 3.3s timeout)":
                command += " -s slow"
            elif speed_preset == "Normal (60 threads, 2.8s timeout)":
                command += " -s normal"
            elif speed_preset == "Fast (120 threads, 2.8s timeout)":
                command += " -s fast"
            elif speed_preset == "Insane (240 threads, 1.5s timeout)":
                command += " -s insane"
            elif speed_preset == "Light-mode (400 threads, 1.5s timeout)":
                command += " -s Light-mode"

        if fast_scan_var.get():
            command += " -F"
        if os_detect_var.get():
            command += " -O"
        if rdns_var.get():
            command += " -n"
        if banner_grab_var.get():
            command += " -b"
        if no_ping_var.get():
            command += " -Pn"
        if ipv6_var.get():
            command += " -V6"
        if fragment_var.get():
            command += " -f"
        if rc_var.get():
            command += " -Rc"

        pro_preset = pro_var.get()
        pro_preset = pro_preset.split(".")[0]
        if pro_preset == "None":
            pass
        else:
            command += f" --load-profile {pro_preset}"

        save_preset = save_var.get()
        if save_preset != "None":
            if save_preset == "TXT":
                command += f" --save txt"
            elif save_preset == "LIGHT":
                command += f" --save light"
            elif save_preset == "HTML":
                command += f" --save html"
            elif save_preset == "XML":
                command += f" --save xml"
            elif save_preset == "CSV":
                command += f" --save csv"
            elif save_preset == "JSON":
                command += f" --save json"
            elif save_preset == "PDF":
                command += f" --save pdf"
            elif save_preset == "YAML":
                command += f" --save yaml"
            elif save_preset == "TOML":
                command += f" --save toml"
            elif save_preset == "HEX-STR":
                command += f" --save hex-str"

        return command
    return command


def run_scan():
    command = build_command()

    command_entry.delete(0, "end")
    command_entry.insert(0, command)
    
    if command is not None and "sudo" not in command:
        output_text.insert("end","\n[!] Lightscan need root privillege to run, use sudo. \n")

    elif command.startswith("sudo venv/bin/python Lightscan.py "):
        invalid_chars = ['&', '|',':','`','$','>','<']

        for char in invalid_chars:
            if char in command:
                print(f"\n[!] CMD INJECTION\n")
                sys.exit(-1)
        exploit_args = ['cd', 'pwd', 'netstat', 'ifconfig', 'winget', 'wmic', 'ls', 'ping','chdir', 'mkdir', 'dir']
        for arg in exploit_args:
            if arg in command:
                print(f"\n[!] CMD INJECTION\n")
                sys.exit(-1)

        output_text.delete("1.0", "end")
        output_text.insert("end", f"[+] Running: {command}\n\n")

        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30000)
            output = result.stdout + result.stderr
            output_text.insert("end", output)
            command_entry.delete(0, "end")
        except subprocess.TimeoutExpired:
            output_text.insert("end", "[!] Scan timed out after 5 minutes\n")
        except Exception as e:
            output_text.insert("end", f"[-] Error: {e}\n")
    else:
        invalid_lightscan_command()
        output_text.insert("end",f"\n[!] Make sure the python env name is 'venv' .\n")


def start_scan():
    scan_thread = threading.Thread(target=run_scan, daemon=True)
    scan_thread.start()

def switch_mode():
    mode = customtkinter.get_appearance_mode()
    if mode == "Dark":
        customtkinter.set_appearance_mode("Light")
    else:
        customtkinter.set_appearance_mode("Dark")

customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("blue")

root = customtkinter.CTk()
root.geometry("1300x880")
root.title("LightPanel Linux - Light-Scan GUI")
try:
    icon = tkinter.PhotoImage(file='images/Light-Scan-Logo.png')
    root.iconphoto(True, icon)
except:
    print("\n[!] Couldn't load Light-Scan-Logo.png \n")

switch_mode_button = customtkinter.CTkButton(
    root,
    text="Switch Mode",
    command=switch_mode,
    width=55,
    height=28,
    font=("Arial", 15),
    border_spacing=5,
    corner_radius=10,
    fg_color=("#f7f5f0", "#1a1a1a"),
    bg_color="transparent",
    text_color=("black", "white"),
    hover_color="grey",
    border_color=("#dbdbdb", "#121211"),
    border_width=2
)
switch_mode_button.place(x=10, y=10)

command_label = customtkinter.CTkLabel(
    root,
    text="Command :",
    font=("Arial", 15),
    text_color=("black", "white")
)
command_label.place(x=120, y=11)

command_entry = customtkinter.CTkEntry(
    root,
    width=700,
    height=28,
    placeholder_text="sudo venv/bin/python Lightscan.py -T example.com -F -st SYN",
    font=("Arial", 15),
    corner_radius=10,
    border_color=("#dbdbdb", "#121211"),
    fg_color=("#f7f5f0", "#1a1a1a"),
    bg_color="transparent",
    border_width=2
)
command_entry.place(x=210, y=11)

start_scan_button = customtkinter.CTkButton(
    root,
    command=start_scan,
    text="Start Scan",
    width=80,
    height=28,
    font=("Arial", 15),
    border_spacing=5,
    corner_radius=10,
    fg_color=("#f7f5f0", "#1a1a1a"),
    bg_color="transparent",
    text_color=("black", "white"),
    hover_color="grey",
    border_color=("#dbdbdb", "#121211"),
    border_width=2
)
start_scan_button.place(x=920, y=11)

target_label = customtkinter.CTkLabel(
    root,
    text="Target :",
    font=("Arial", 14),
    text_color=("black", "white")
)
target_label.place(x=25, y=60)

target_entry = customtkinter.CTkEntry(
    root,
    width=300,
    height=30,
    placeholder_text="example.com or 192.168.1.1",
    font=("Arial", 14),
    corner_radius=10,
    border_color=("#dbdbdb", "#121211"),
    fg_color=("#f7f5f0", "#1a1a1a"),
    bg_color="transparent",
    border_width=2
)
target_entry.place(x=100, y=60)

ports_label = customtkinter.CTkLabel(
    root,
    text="Ports :",
    font=("Arial", 14),
    text_color=("black", "white")
)
ports_label.place(x=430, y=60)

ports_entry = customtkinter.CTkEntry(
    root,
    width=200,
    height=30,
    placeholder_text="80,443 or 1-1000",
    font=("Arial", 14),
    corner_radius=10,
    border_color=("#dbdbdb", "#121211"),
    fg_color=("#f7f5f0", "#1a1a1a"),
    bg_color="transparent",
    border_width=2
)
ports_entry.place(x=490, y=60)

scan_type_label = customtkinter.CTkLabel(
    root,
    text="Scan Type :",
    font=("Arial", 14),
    text_color=("black", "white")
)
scan_type_label.place(x=720, y=60)

scan_types = [
    "TCP Connect (default)",
    "SYN Stealth",
    "UDP Scan",
    "NULL Scan",
    "FIN Scan",
    "ACK Scan",
    "XMAS Scan",
    "MAIMON Scan",
    "WINDOW Scan",
    "FDD Scan",
    "FTP Bounce",
    "IPPROTO Scan",
    "IDLE Scan",
    "Ping Sweep",
    "SCTP-INIT"
]

saving_label = customtkinter.CTkLabel(
    root,
    text="Saving Format :",
    font=("Arial", 14),
    text_color=("black", "white")
)
saving_label.place(x=25, y=760)

saving_formats = [
    "None",
    "TXT",
    "LIGHT",
    "HTML",
    "XML",
    "JSON",
    "CSV",
    "PDF",
    "YAML",
    "TOML",
    "HEX-STR"
]

save_var = customtkinter.StringVar(value="None")
save_dropdown = customtkinter.CTkOptionMenu(
    root,
    values=saving_formats,
    variable=save_var,
    width=140,
    height=30,
    font=("Arial", 13),
    corner_radius=10,
    fg_color=("#f7f5f0", "#1a1a1a"),
    button_color=("#dbdbdb", "#121211"),
    button_hover_color="grey",
    text_color=("black", "white")
)
save_dropdown.place(x=150, y=760)

pro_label = customtkinter.CTkLabel(
    root,
    text="Profiles :",
    font=("Arial", 14),
    text_color=("black", "white")
)
pro_label.place(x=320, y=760)

profiles = ["None"]
profiles.extend([f for f in os.listdir(os.path.join(os.path.dirname(__file__), "Profiles")) if f.endswith('.json')])
for profile in profiles:
    if profile == "None":
        pass
    else:
        a = profile.split('.')[0]
        profiles.remove(profile)
        profiles.append(a)

pro_var = customtkinter.StringVar(value="None")
pro_dropdown = customtkinter.CTkOptionMenu(
    root,
    values=profiles,
    variable=pro_var,
    width=140,
    height=30,
    font=("Arial", 13),
    corner_radius=10,
    fg_color=("#f7f5f0", "#1a1a1a"),
    button_color=("#dbdbdb", "#121211"),
    button_hover_color="grey",
    text_color=("black", "white")
)
pro_dropdown.place(x=400, y=760)

pro_name_label = customtkinter.CTkLabel(
    root,
    text="Save Profile :",
    font=("Arial", 14),
    text_color=("black", "white")
)
pro_name_label.place(x=570, y=760)

rdns_var = customtkinter.BooleanVar()
rdns_check = customtkinter.CTkCheckBox(
    root,
    text="No rDNS (-n)",
    variable=rdns_var,
    font=("Arial", 13),
    corner_radius=5,
    hover_color=("lightblue","#525452"),
    fg_color="#72d466"
)
rdns_check.place(x=1000, y=763)

pro_entry = customtkinter.CTkEntry(
    root,
    width=300,
    height=30,
    placeholder_text="heretic_scan",
    font=("Arial", 14),
    corner_radius=10,
    border_color=("#dbdbdb", "#121211"),
    fg_color=("#f7f5f0", "#1a1a1a"),
    bg_color="transparent",
    border_width=2
)
pro_entry.place(x=680, y=760)

scan_type_var = customtkinter.StringVar(value="TCP Connect (default)")
scan_type_dropdown = customtkinter.CTkOptionMenu(
    root,
    values=scan_types,
    variable=scan_type_var,
    width=140,
    height=30,
    font=("Arial", 13),
    corner_radius=10,
    fg_color=("#f7f5f0", "#1a1a1a"),
    button_color=("#dbdbdb", "#121211"),
    button_hover_color="grey",
    text_color=("black", "white")
)
scan_type_dropdown.place(x=820, y=60)

speed_label = customtkinter.CTkLabel(
    root,
    text="Speed :",
    font=("Arial", 14),
    text_color=("black", "white")
)
speed_label.place(x=25, y=100)

speed_presets = [
    "Paranoid (2 threads, 4.5s timeout)",
    "Slow (30 threads, 3.3s timeout)",
    "Normal (60 threads, 2.8s timeout)",
    "Fast (120 threads, 2.8s timeout)",
    "Insane (240 threads, 1.5s timeout)",
    "Light-mode (400 threads, 1.5s timeout)"
]

speed_var = customtkinter.StringVar(value="Normal (60 threads, 2.8s timeout)")
speed_dropdown = customtkinter.CTkOptionMenu(
    root,
    values=speed_presets,
    variable=speed_var,
    width=250,
    height=30,
    font=("Arial", 13),
    corner_radius=10,
    fg_color=("#f7f5f0", "#1a1a1a"),
    button_color=("#dbdbdb", "#121211"),
    button_hover_color="grey",
    text_color=("black", "white")
)
speed_dropdown.place(x=100, y=100)

fast_scan_var = customtkinter.BooleanVar()
fast_scan_check = customtkinter.CTkCheckBox(
    root,
    text="Top 100 Ports (-F)",
    variable=fast_scan_var,
    font=("Arial", 13),
    corner_radius=5,
    hover_color=("lightblue","#525452"),
    fg_color="#72d466"
)
fast_scan_check.place(x=400, y=103)

os_detect_var = customtkinter.BooleanVar()
os_detect_check = customtkinter.CTkCheckBox(
    root,
    text="OS Detect (-O)",
    variable=os_detect_var,
    font=("Arial", 13),
    corner_radius=5,
    hover_color=("lightblue","#525452"),
    fg_color="#72d466"
)
os_detect_check.place(x=550, y=103)

banner_grab_var = customtkinter.BooleanVar()
banner_grab_check = customtkinter.CTkCheckBox(
    root,
    text="Banner Grab (-b)",
    variable=banner_grab_var,
    font=("Arial", 13),
    corner_radius=5,
    hover_color=("lightblue","#525452"),
    fg_color="#72d466"
)
banner_grab_check.place(x=690, y=103)

no_ping_var = customtkinter.BooleanVar()
no_ping_check = customtkinter.CTkCheckBox(
    root,
    text="No Ping (-Pn)",
    variable=no_ping_var,
    font=("Arial", 13),
    corner_radius=5,
    hover_color=("lightblue","#525452"),
    fg_color="#72d466"
)
no_ping_check.place(x=830, y=103)

ipv6_var = customtkinter.BooleanVar()
ipv6_check = customtkinter.CTkCheckBox(
    root,
    text="IPv6 Target (-V6)",
    variable=ipv6_var,
    font=("Arial", 13),
    corner_radius=5,
    hover_color=("lightblue","#525452"),
    fg_color="#72d466"
)
ipv6_check.place(x=950, y=103)

fragment_var = customtkinter.BooleanVar()
fragment_check = customtkinter.CTkCheckBox(
    root,
    text="Fragmentation (-f)",
    variable=fragment_var,
    font=("Arial", 13),
    corner_radius=5,
    hover_color=("lightblue","#525452"),
    fg_color="#72d466"
)
fragment_check.place(x=1090, y=103)

rc_var = customtkinter.BooleanVar()
rc_check = customtkinter.CTkCheckBox(
    root,
    text="Recursively (-Rc)",
    variable=rc_var,
    font=("Arial", 13),
    corner_radius=5,
    hover_color=("lightblue","#525452"),
    fg_color="#72d466"
)
rc_check.place(x=1015, y=63)

copy_button = customtkinter.CTkButton(
    root,
    text="Copy Output",
    command=copy_output,
    width=100,
    height=28,
    font=("Arial", 13),
    corner_radius=10,
    fg_color=("#f7f5f0", "#1a1a1a"),
    bg_color="transparent",
    text_color=("black", "white"),
    hover_color="grey",
    border_color=("#dbdbdb", "#121211"),
    border_width=2
)
copy_button.place(x=1025, y=11)

clear_button = customtkinter.CTkButton(
    root,
    text="Clear Output",
    command=clear_output,
    width=100,
    height=28,
    font=("Arial", 13),
    corner_radius=10,
    fg_color=("#f7f5f0", "#1a1a1a"),
    bg_color="transparent",
    text_color=("black", "white"),
    hover_color="grey",
    border_color=("#dbdbdb", "#121211"),
    border_width=2
)
clear_button.place(x=1140, y=11)

output_text = customtkinter.CTkTextbox(
    root,
    width=1250,
    height=600,
    font=("Consolas", 12),
    corner_radius=10,
    border_color=("#dbdbdb", "#121211"),
    border_width=2,
    wrap="word"
)
output_text.place(x=25, y=145)
try:
    root.mainloop()
except Exception as e:
    print(f"\n[!] Error : {e}")
    root.mainloop()

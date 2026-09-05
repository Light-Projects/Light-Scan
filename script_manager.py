import os
import yaml
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
import shutil
import sys
import re

class LSSEScriptManager:
    def __init__(self, root):
        self.root = root
        self.root.title("LSSE Script Manager v1.0")
        self.root.geometry("780x550")
        icon = tk.PhotoImage(file='images/Light-Scan-Logo.png')
        try:
            self.root.iconphoto(True, icon)
        except:
            try:
                self.root.iconbitmap("images/Light-Scan-Logo.ico")
            except:
                print("\n[!] Couldn't load Light-Scan-Logo \n")

        self.bg_color = "#B0D4F1"
        self.fg_color = "#000000"
        self.btn_bg = "#8BB8D6"
        self.btn_fg = "#000000"
        self.entry_bg = "#FFFFFF"
        self.frame_bg = "#C3DFF5"

        self.base_path = Path(__file__).parent

        self.config_path = self.base_path / "Config" / "lsse.conf"
        self.metadata_path = self.base_path / "LSSE" / "metadata"
        self.scripts_path = self.base_path / "LSSE" / "scripts"

        self.available_args = [
            ('--domain', 'domain'),
            ('--dns-server', 'dns'),
            ('-W', 'wordlist'),
            ('--extensions', 'extensions'),
            ('--status-codes', 'status_codes'),
            ('--redirect', 'redirect'),
            ('--url', 'url'),
            ('--mxp', 'max_pages'),
            ('--mxd', 'max_depth'),
            ('--starget', 't'),
            ('-sp', 'ports'),
            ('--username', 'user'),
            ('--password', 'password'),
            ('--userlist', 'userlist'),
            ('--passwordlist', 'passwordlist'),
            ('--file', 'file'),
            ('--request', 'req'),
            ('--ssl', 'ssl')
        ]

        self.arg_names = [arg[0] for arg in self.available_args]
        self.arg_names1 = [arg[0] for arg in self.available_args]
        self.arg_names1.remove('-sp')
        self.yaml_to_param = {arg[0]: arg[1] for arg in self.available_args}

        self.category_map = {
            'safe': 'safe',
            'medium': 'medium',
            'dangerous': 'dangerous'
        }

        self.sub_categories = [
            'analysis', 'discovery', 'extracting', 'exploitation'
        ]

        self.protocols = [
            'http_https', 'dns', 'ssh', 'smb', 'dhcp', 'ftp',
            'https', 'tcp', 'udp', 'ssl'
        ]

        self.root.configure(bg=self.bg_color)
        self.has_ports = False
        self.port_mode = "single"
        self.selected_script_path = None

        self.create_widgets()
        self.load_config()

    def create_widgets(self):
        canvas_frame = tk.Frame(self.root, bg=self.bg_color)
        canvas_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.canvas = tk.Canvas(canvas_frame, bg=self.bg_color, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg=self.bg_color)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Mouse wheel scrolling
        def on_mousewheel(event):
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def on_mousewheel_win(event):
            self.canvas.yview_scroll(int(-1 * (event.delta / 40)), "units")

        self.canvas.bind_all("<MouseWheel>", on_mousewheel)
        self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))

        main_frame = tk.Frame(self.scrollable_frame, bg=self.frame_bg, relief=tk.RAISED, bd=3)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        title_frame = tk.Frame(main_frame, bg=self.bg_color)
        title_frame.pack(fill=tk.X, pady=5)

        title_label = tk.Label(title_frame, text="=== LSSE SCRIPT MANAGER ===",
                               font=("Courier New", 14, "bold"),
                               bg=self.bg_color, fg=self.fg_color)
        title_label.pack()

        separator = tk.Label(title_frame, text="=" * 50,
                             font=("Courier New", 10),
                             bg=self.bg_color, fg=self.fg_color)
        separator.pack()

        form = tk.Frame(main_frame, bg=self.bg_color, relief=tk.SUNKEN, bd=2)
        form.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tk.Label(form, text="Script Name:", font=("Courier New", 10),
                 bg=self.bg_color, fg=self.fg_color).grid(row=0, column=0, sticky='w', pady=5, padx=5)
        self.script_name = tk.Entry(form, width=40, font=("Courier New", 10),
                                    bg=self.entry_bg, fg=self.fg_color, relief=tk.SUNKEN, bd=2)
        self.script_name.grid(row=0, column=1, sticky='w', pady=5, padx=5)
        tk.Label(form, text="(lowercase, use hyphens)", font=("Courier New", 9),
                 bg=self.bg_color, fg=self.fg_color).grid(row=0, column=2, sticky='w', pady=5, padx=5)

        tk.Label(form, text="Description:", font=("Courier New", 10),
                 bg=self.bg_color, fg=self.fg_color).grid(row=1, column=0, sticky='w', pady=5, padx=5)
        self.description = tk.Entry(form, width=60, font=("Courier New", 10),
                                    bg=self.entry_bg, fg=self.fg_color, relief=tk.SUNKEN, bd=2)
        self.description.grid(row=1, column=1, columnspan=2, sticky='w', pady=5, padx=5)

        tk.Label(form, text="Category:", font=("Courier New", 10),
                 bg=self.bg_color, fg=self.fg_color).grid(row=2, column=0, sticky='w', pady=5, padx=5)
        self.category = ttk.Combobox(form, values=['safe', 'medium', 'dangerous'],
                                     width=20, font=("Courier New", 10))
        self.category.grid(row=2, column=1, sticky='w', pady=5, padx=5)
        self.category.set('safe')
        self.category.bind('<<ComboboxSelected>>', self.on_category_change)

        tk.Label(form, text="Sub-category:", font=("Courier New", 10),
                 bg=self.bg_color, fg=self.fg_color).grid(row=3, column=0, sticky='w', pady=5, padx=5)
        self.sub_category = ttk.Combobox(form, values=self.sub_categories,
                                         width=20, font=("Courier New", 10))
        self.sub_category.grid(row=3, column=1, sticky='w', pady=5, padx=5)
        self.sub_category.set('discovery')

        tk.Label(form, text="Protocol:", font=("Courier New", 10),
                 bg=self.bg_color, fg=self.fg_color).grid(row=4, column=0, sticky='w', pady=5, padx=5)
        self.protocol = ttk.Combobox(form, values=self.protocols,
                                     width=20, font=("Courier New", 10))
        self.protocol.grid(row=4, column=1, sticky='w', pady=5, padx=5)
        self.protocol.set('http_https')

        tk.Label(form, text="Has Ports:", font=("Courier New", 10),
                 bg=self.bg_color, fg=self.fg_color).grid(row=5, column=0, sticky='w', pady=5, padx=5)

        port_frame = tk.Frame(form, bg=self.bg_color)
        port_frame.grid(row=5, column=1, columnspan=2, sticky='w', pady=5, padx=5)

        self.has_ports_var = tk.IntVar(value=0)
        self.has_ports_check = tk.Checkbutton(port_frame, text="Enable Port Support",
                                              variable=self.has_ports_var,
                                              font=("Courier New", 10),
                                              bg=self.bg_color, fg=self.fg_color,
                                              command=self.toggle_port_options)
        self.has_ports_check.pack(side=tk.LEFT)

        self.port_mode_frame = tk.Frame(port_frame, bg=self.bg_color)
        self.port_mode_frame.pack(side=tk.LEFT, padx=10)

        self.port_mode_label = tk.Label(self.port_mode_frame, text="Port Mode:",
                                        font=("Courier New", 10),
                                        bg=self.bg_color, fg=self.fg_color)
        self.port_mode_label.pack(side=tk.LEFT)

        self.port_mode_combo = ttk.Combobox(self.port_mode_frame, values=['single', 'multiple'],
                                            width=10, font=("Courier New", 10))
        self.port_mode_combo.pack(side=tk.LEFT, padx=5)
        self.port_mode_combo.set('single')

        self.port_mode_frame.pack_forget()

        tk.Label(form, text="Script File:", font=("Courier New", 10),
                 bg=self.bg_color, fg=self.fg_color).grid(row=6, column=0, sticky='w', pady=5, padx=5)

        script_file_frame = tk.Frame(form, bg=self.bg_color)
        script_file_frame.grid(row=6, column=1, columnspan=2, sticky='w', pady=5, padx=5)

        self.script_file_path = tk.Entry(script_file_frame, width=50, font=("Courier New", 10),
                                         bg=self.entry_bg, fg=self.fg_color, relief=tk.SUNKEN, bd=2)
        self.script_file_path.pack(side=tk.LEFT, padx=5)

        browse_btn = tk.Button(script_file_frame, text="Browse...",
                               font=("Courier New", 9), bg=self.btn_bg,
                               fg=self.btn_fg, relief=tk.RAISED, bd=2,
                               command=self.browse_script)
        browse_btn.pack(side=tk.LEFT, padx=5)

        tk.Label(form, text="Required Arguments:", font=("Courier New", 10),
                 bg=self.bg_color, fg=self.fg_color).grid(row=7, column=0, sticky='nw', pady=5, padx=5)

        self.req_frame = tk.Frame(form, bg=self.bg_color)
        self.req_frame.grid(row=7, column=1, columnspan=2, sticky='w', pady=5, padx=5)

        self.req_args = []
        self.add_req_button = tk.Button(self.req_frame, text="Add Required Arg",
                                        font=("Courier New", 9), bg=self.btn_bg,
                                        fg=self.btn_fg, relief=tk.RAISED, bd=2,
                                        command=self.add_required_arg)
        self.add_req_button.pack(side=tk.LEFT, padx=5)

        tk.Label(form, text="Optional Arguments:", font=("Courier New", 10),
                 bg=self.bg_color, fg=self.fg_color).grid(row=8, column=0, sticky='nw', pady=5, padx=5)

        self.opt_frame = tk.Frame(form, bg=self.bg_color)
        self.opt_frame.grid(row=8, column=1, columnspan=2, sticky='w', pady=5, padx=5)

        self.opt_args = []
        self.add_opt_button = tk.Button(self.opt_frame, text="Add Optional Arg",
                                        font=("Courier New", 9), bg=self.btn_bg,
                                        fg=self.btn_fg, relief=tk.RAISED, bd=2,
                                        command=self.add_optional_arg)
        self.add_opt_button.pack(side=tk.LEFT, padx=5)

        button_frame = tk.Frame(form, bg=self.bg_color)
        button_frame.grid(row=9, column=0, columnspan=3, pady=20)

        add_btn = tk.Button(button_frame, text="Add Script",
                            font=("Courier New", 10, "bold"), bg=self.btn_bg,
                            fg=self.btn_fg, relief=tk.RAISED, bd=3,
                            command=self.add_script)
        add_btn.pack(side=tk.LEFT, padx=20)

        reset_btn = tk.Button(button_frame, text="Reset Form",
                              font=("Courier New", 10), bg=self.btn_bg,
                              fg=self.btn_fg, relief=tk.RAISED, bd=3,
                              command=self.reset_form)
        reset_btn.pack(side=tk.LEFT, padx=20)

        delete_btn = tk.Button(button_frame, text="Delete Script",
                               font=("Courier New", 10, "bold"), bg="#FF6B6B",
                               fg="white", relief=tk.RAISED, bd=3,
                               command=self.delete_script)
        delete_btn.pack(side=tk.LEFT, padx=20)

        self.status_frame = tk.Frame(self.root, bg=self.bg_color, relief=tk.SUNKEN, bd=2)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=10, pady=5)

        self.status_label = tk.Label(self.status_frame, text="Ready",
                                     font=("Courier New", 9),
                                     bg=self.bg_color, fg=self.fg_color)
        self.status_label.pack(fill=tk.X, padx=5, pady=2)

        self.apply_old_school_style()

    def apply_old_school_style(self):
        style = ttk.Style()
        style.theme_use('default')
        style.configure('TCombobox',
                        fieldbackground=self.entry_bg,
                        background=self.entry_bg,
                        foreground=self.fg_color)

    def toggle_port_options(self):
        if self.has_ports_var.get() == 1:
            self.port_mode_frame.pack(side=tk.LEFT, padx=10)
            self.has_ports = True
        else:
            self.port_mode_frame.pack_forget()
            self.has_ports = False

    def on_category_change(self, event=None):
        cat = self.category.get()
        if cat == 'safe':
            self.sub_category.set('discovery')
        elif cat == 'medium':
            self.sub_category.set('analysis')
        elif cat == 'dangerous':
            self.sub_category.set('exploitation')

    def browse_script(self):
        file_path = filedialog.askopenfilename(
            title="Select Python Script",
            filetypes=[("Python files", "*.py"), ("All files", "**")]
        )
        if file_path:
            self.script_file_path.delete(0, tk.END)
            self.script_file_path.insert(0, file_path)
            self.selected_script_path = file_path

            if not self.script_name.get():
                script_name = Path(file_path).stem
                self.script_name.insert(0, script_name.lower().replace('_', '-'))

    def add_required_arg(self):
        self.add_arg(self.req_frame, self.req_args, True)

    def add_optional_arg(self):
        self.add_arg(self.opt_frame, self.opt_args, False)

    def add_arg(self, parent, args_list, is_required):
        frame = tk.Frame(parent, bg=self.bg_color)
        frame.pack(side=tk.TOP, pady=2)
        if is_required:
            combo = ttk.Combobox(frame, values=self.arg_names, width=18,
                                 font=("Courier New", 9))
            combo.pack(side=tk.LEFT)
        else:
            combo = ttk.Combobox(frame, values=self.arg_names1, width=18,
                                 font=("Courier New", 9))
            combo.pack(side=tk.LEFT)

        args_list.append(combo)

        remove_btn = tk.Button(frame, text="X", width=2,
                               font=("Courier New", 8), bg="#FF6B6B",
                               fg="white", relief=tk.RAISED, bd=2,
                               command=lambda: self.remove_arg(frame, args_list, combo))
        remove_btn.pack(side=tk.LEFT, padx=5)

        combo.port_mode = None

    def remove_arg(self, frame, args_list, combo):
        frame.destroy()
        if combo in args_list:
            args_list.remove(combo)

    def get_required_args(self):
        required = []
        for combo in self.req_args:
            arg_name = combo.get().strip()
            if arg_name:
                required.append(arg_name)
        return required

    def get_optional_args(self):
        optional = []
        for combo in self.opt_args:
            arg_name = combo.get().strip()
            if arg_name:
                optional.append(arg_name)
        return optional

    def reset_form(self):
        self.script_name.delete(0, tk.END)
        self.description.delete(0, tk.END)
        self.category.set('safe')
        self.sub_category.set('discovery')
        self.protocol.set('http_https')
        self.has_ports_var.set(0)
        self.has_ports = False
        self.port_mode_frame.pack_forget()
        self.port_mode_combo.set('single')
        self.script_file_path.delete(0, tk.END)
        self.selected_script_path = None

        for frame in [self.req_frame, self.opt_frame]:
            for child in frame.winfo_children():
                if child != self.add_req_button and child != self.add_opt_button:
                    child.destroy()

        self.req_args.clear()
        self.opt_args.clear()

        self.status_label.config(text="Form reset")

    def load_config(self):
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    content = f.read()
                    self.status_label.config(text="Configuration loaded successfully")
        except Exception as e:
            self.status_label.config(text=f"Error loading config: {e}")

    def create_category_directory(self, category, sub_category, protocol):
        script_dir = self.scripts_path / category / sub_category / protocol
        script_dir.mkdir(parents=True, exist_ok=True)
        return script_dir

    def copy_script_file(self, script_name, script_dir, source_path):
        if not source_path or not os.path.exists(source_path):
            messagebox.showerror("Error", "Please select a valid script file")
            return False

        dest_path = script_dir / f"{script_name}.py"

        if dest_path.exists():
            overwrite = messagebox.askyesno(
                "File Exists",
                f"Script file {script_name}.py already exists. Overwrite?"
            )
            if not overwrite:
                return False

        try:
            shutil.copy2(source_path, dest_path)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy script: {e}")
            return False

    def create_yaml_metadata(self, script_name, description, category,
                             required_args, optional_args, sub_category):
        full_category = f"{category}/{sub_category}/{self.protocol.get()}"

        required_list = []
        for arg in required_args:
            required_list.append(arg)

        optional_list = []
        for arg in optional_args:
            optional_list.append(arg)

        metadata = {
            'script_name': script_name,
            'description': description,
            'args': {
                'required': ', '.join(required_list) if required_list else 'null',
                'optional': ', '.join(optional_list) if optional_list else 'null',
                'category': full_category
            }
        }

        metadata_file = self.metadata_path / f"{script_name}.yaml"

        if metadata_file.exists():
            overwrite = messagebox.askyesno(
                "File Exists",
                f"Metadata file {script_name}.yaml already exists. Overwrite?"
            )
            if not overwrite:
                return False

        with open(metadata_file, 'w') as f:
            yaml.dump(metadata, f, default_flow_style=False)

        return True

    def add_to_config(self, script_name, required_args, optional_args):
        try:
            with open(self.config_path, 'r') as f:
                content = f.read()

            if f'{script_name} =' in content:
                overwrite = messagebox.askyesno(
                    "Script Exists",
                    f"Script {script_name} already exists in configuration. Overwrite?"
                )
                if not overwrite:
                    return False

                lines = content.split('\n')
                new_lines = []
                for line in lines:
                    if not line.strip().startswith(f'{script_name} ='):
                        new_lines.append(line)
                content = '\n'.join(new_lines)

            args_parts = []
            has_ports = False

            for arg in required_args:
                if arg == '-sp':
                    has_ports = True
                    if self.port_mode_combo.get() == 'single':
                        args_parts.append('ports->1')
                    else:
                        args_parts.append('ports->+')
                else:
                    param_name = self.yaml_to_param.get(arg, arg)
                    if param_name.startswith('--'):
                        param_name = param_name[2:]
                    elif param_name.startswith('-'):
                        param_name = param_name[1:]
                    args_parts.append(param_name)

            args_str = '|'.join(args_parts) if args_parts else ''

            entry = f'{script_name} = {{args: {args_str}, script-path: LSSE.scripts.{self.category.get()}.{self.sub_category.get()}.{self.protocol.get()}.{script_name}}}'

            lines = content.split('\n')
            script_section_index = -1

            for i, line in enumerate(lines):
                if line.strip().startswith('[SCRIPTS]'):
                    script_section_index = i
                    break

            if script_section_index == -1:
                content += '\n\n[SCRIPTS]\n'
                content += entry + '\n'
            else:
                insert_pos = script_section_index + 1
                while insert_pos < len(lines) and not lines[insert_pos].strip().startswith('['):
                    insert_pos += 1

                if insert_pos == len(lines):
                    lines.append(entry)
                else:
                    lines.insert(insert_pos, entry)
                content = '\n'.join(lines)

            if has_ports:
                section_key = 'sscripts'
            else:
                section_key = 'dscripts'

            lines = content.split('\n')
            found_section = False

            start_idx = None
            for i, line in enumerate(lines):
                if line.strip().startswith(f'{section_key} = ['):
                    start_idx = i
                    break

            if start_idx is not None:
                found_section = True

                end_idx = None
                for j in range(start_idx, len(lines)):
                    if ']' in lines[j]:
                        end_idx = j
                        break

                if end_idx is not None:
                    block = '\n'.join(lines[start_idx:end_idx + 1])
                    if script_name not in block:
                        bracket_pos = lines[end_idx].rfind(']')
                        lines[end_idx] = (
                                lines[end_idx][:bracket_pos]
                                + f",'{script_name}'"
                                + lines[end_idx][bracket_pos:]
                        )

            if not found_section:
                vars_section_index = -1
                for i, line in enumerate(lines):
                    if line.strip().startswith('[VARS]'):
                        vars_section_index = i
                        break

                if vars_section_index != -1:
                    insert_pos = vars_section_index + 1
                    while insert_pos < len(lines) and not lines[insert_pos].strip().startswith('['):
                        insert_pos += 1

                    new_line = f'{section_key} = [\'{script_name}\']'
                    if insert_pos == len(lines):
                        lines.append(new_line)
                    else:
                        lines.insert(insert_pos, new_line)

            content = '\n'.join(lines)

            with open(self.config_path, 'w') as f:
                f.write(content)

            return True

        except Exception as e:
            messagebox.showerror("Error", f"Error updating configuration: {e}")
            return False

    def delete_script(self):
        script_name = self.script_name.get().strip().lower().replace(' ', '-')

        if not script_name:
            messagebox.showerror("Error", "Please enter the script name to delete")
            return

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete script '{script_name}'?\n\n"
            "This will remove:\n"
            "- Python script file\n"
            "- Metadata YAML file\n"
            "- Configuration entry\n"
            "- Entry from dscripts or sscripts list\n\n"
            "This action cannot be undone!",
            icon='warning'
        )

        if not confirm:
            return

        try:
            deleted_files = []
            errors = []

            script_file_found = False
            for category in self.category_map:
                for sub_category in self.sub_categories:
                    for protocol in self.protocols:
                        script_path = self.scripts_path / category / sub_category / protocol / f"{script_name}.py"
                        if script_path.exists():
                            try:
                                os.remove(script_path)
                                script_file_found = True
                                deleted_files.append(f"Script: {script_path}")
                            except Exception as e:
                                errors.append(f"Failed to delete script file: {e}")

            if not script_file_found:
                errors.append(f"Script file not found for '{script_name}'")

            metadata_file = self.metadata_path / f"{script_name}.yaml"
            if metadata_file.exists():
                try:
                    os.remove(metadata_file)
                    deleted_files.append(f"Metadata: {metadata_file}")
                except Exception as e:
                    errors.append(f"Failed to delete metadata: {e}")
            else:
                errors.append(f"Metadata file not found for '{script_name}'")

            config_updated = self.remove_from_config(script_name)
            if config_updated:
                deleted_files.append("Configuration entry removed")
            else:
                errors.append("Failed to remove from configuration")

            if errors:
                error_msg = "Errors occurred:\n" + "\n".join(errors)
                if deleted_files:
                    error_msg = "Partially deleted:\n" + "\n".join(deleted_files) + "\n\n" + error_msg
                messagebox.showwarning("Partial Deletion", error_msg)
                self.status_label.config(text=f"Partial deletion of {script_name}")
            else:
                messagebox.showinfo("Success",
                                    f"Script '{script_name}' deleted successfully!\n\n"
                                    "Removed:\n" + "\n".join(deleted_files))
                self.status_label.config(text=f"Script {script_name} deleted successfully")
                self.reset_form()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete script: {e}")
            self.status_label.config(text=f"Error deleting script: {e}")

    def remove_from_config(self, script_name):
        try:
            if not self.config_path.exists():
                messagebox.showerror("Error", "Configuration file not found")
                return False

            with open(self.config_path, 'r') as f:
                lines = f.readlines()

            new_lines = []
            i = 0
            while i < len(lines):
                line = lines[i]

                if line.strip().startswith(f'{script_name} ='):
                    i += 1
                    while i < len(lines) and (lines[i].startswith(' ') or lines[i].startswith('\t')):
                        i += 1
                    continue

                new_lines.append(line)
                i += 1

            content = ''.join(new_lines)

            import re
            pattern_dscripts = r'(dscripts\s*=\s*\[)([^\]]*)\]'
            pattern_sscripts = r'(sscripts\s*=\s*\[)([^\]]*)\]'

            def remove_script_from_list(match):
                prefix = match.group(1)
                items = match.group(2)
                item_list = [item.strip() for item in items.split(',') if item.strip()]
                filtered = []
                for item in item_list:
                    clean_item = item.strip("'\" ")
                    if clean_item != script_name:
                        filtered.append(item)

                if filtered:
                    return prefix + ', '.join(filtered) + ']'
                else:
                    return prefix + ']'

            content = re.sub(pattern_dscripts, remove_script_from_list, content)
            content = re.sub(pattern_sscripts, remove_script_from_list, content)

            with open(self.config_path, 'w') as f:
                f.write(content)

            return True

        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove from config: {e}")
            return False

    def add_script(self):
        script_name = self.script_name.get().strip().lower().replace(' ', '-')
        if not script_name:
            messagebox.showerror("Error", "Please enter a script name")
            return

        description = self.description.get().strip()
        if not description:
            messagebox.showerror("Error", "Please enter a description")
            return

        category = self.category.get().strip()
        sub_category = self.sub_category.get().strip()
        protocol = self.protocol.get().strip()

        if category not in self.category_map:
            messagebox.showerror("Error", "Invalid category. Must be safe, medium, or dangerous")
            return

        required_args = self.get_required_args()
        optional_args = self.get_optional_args()

        script_file = self.script_file_path.get().strip()
        if not script_file:
            messagebox.showerror("Error", "Please select a script file")
            return

        if not os.path.exists(script_file):
            messagebox.showerror("Error", "Selected script file does not exist")
            return

        confirm_msg = f"Script: {script_name}\n"
        confirm_msg += f"Description: {description}\n"
        confirm_msg += f"Category: {category}/{sub_category}/{protocol}\n"
        confirm_msg += f"Has Ports: {'Yes' if self.has_ports else 'No'}\n"
        if self.has_ports:
            confirm_msg += f"Port Mode: {self.port_mode_combo.get()}\n"
        confirm_msg += f"Required Args: {', '.join(required_args) if required_args else 'None'}\n"
        confirm_msg += f"Optional Args: {', '.join(optional_args) if optional_args else 'None'}\n"
        confirm_msg += f"Script File: {os.path.basename(script_file)}\n\n"
        confirm_msg += "Do you want to add this script?"

        if not messagebox.askyesno("Confirm", confirm_msg):
            return

        try:
            script_dir = self.create_category_directory(category, sub_category, protocol)

            copy_success = self.copy_script_file(script_name, script_dir, script_file)
            if not copy_success:
                return

            yaml_success = self.create_yaml_metadata(
                script_name, description, category,
                required_args, optional_args, sub_category
            )

            config_success = self.add_to_config(script_name, required_args, optional_args)

            if yaml_success and copy_success and config_success:
                messagebox.showinfo("Success",
                                    f"Script {script_name} added successfully!\n\n"
                                    f"Created:\n"
                                    f"- YAML: LSSE/metadata/{script_name}.yaml\n"
                                    f"- Script: {script_dir}/{script_name}.py\n"
                                    f"- Updated: Config/lsse.conf"
                                    )
                self.status_label.config(text=f"Script {script_name} added successfully")
                self.reset_form()
            else:
                messagebox.showerror("Error", "Failed to add script. Check the status messages.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to add script: {e}")
            self.status_label.config(text=f"Error: {e}")


def main():
    root = tk.Tk()
    app = LSSEScriptManager(root)
    root.mainloop()


if __name__ == "__main__":
    main()
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

import configparser
import importlib
import sys

RED = "\033[31m"
RESET = "\033[0m"
config = configparser.ConfigParser()


class Global:
    buitin = ["paranoid", "slow", "normal", "fast", "insane", "light-mode"]

def speed_parser(name):
    try:
        config.read('./Config/speed-presets.conf', encoding='utf-8')
        if name in Global.buitin:
            preset = config['BUILT-IN'][name].replace("{","").replace("}","")
            threads, timeout = preset.replace("threads:","").replace("timeout:","").replace(" ", "").split(",")
            return {"threads": int(threads),"timeout": float(timeout)}
        else:
            preset = config['CUSTOM'][name].replace("{", "").replace("}", "")
            threads, timeout = preset.replace("threads:", "").replace("timeout:", "").replace(" ", "").split(",")
            return {"threads": int(threads), "timeout": float(timeout)}
    except Exception:
        return {'threads':60,'timeout':2.8}

def speed_presets_list():
    config.read("./Config/speed-presets.conf", encoding='utf-8')

    all_vars = []
    for section in config.sections():
        for key, value in config.items(section):
            all_vars.append(key)

    return all_vars

def import_script(module_path: str):
    try:
        module = importlib.import_module(module_path)
        return module
    except ImportError as e:
        print(f"Error importing module {module_path}: {e}")
        return None

def ds_parser():
    config.read("./Config/lsse.conf", encoding='utf-8')
    try:
        d = []
        s = []
        for key, value in config.items('VARS'):
            if key == "dscripts":
                dd = value.replace("[","").replace("]","").replace("'","").replace("\n","").split(',')
                d.extend(dd)
            elif key == "sscripts":
                ss = value.replace("[","").replace("]","").replace("'","").replace("\n","").split(',')
                s.extend(ss)

        return d,s
    except Exception as e:
        print(f"\n{RED}[!] {e}{RESET}\n")


def clsse_runner(
        sname: str,
        ports: list[int] | None = None,
        redirect: bool | None = None,
        domain: str | None = None,
        dns: str | None = None,
        wordlist: str | None = None,
        url: str | None = None,
        max_pages: str | int | None = None,
        max_depth: str | int | None = None,
        extensions: str | None = None,
        status_codes: str | None = None,
        t: str | None = None,
        user: str | None = None,
        password: str | None = None,
        userlist: str | None = None,
        passwordlist: str | None = None,
        file: str | None = None,
        req: str | None = None,
        ssl: bool | None = None
) -> None:
    try:
        config.read("./Config/lsse.conf", encoding='utf-8')
        preset = config['SCRIPTS'][sname].replace("{", "").replace("}", "").replace('\n', '').split(",")
        args = preset[0].replace("args:", "").replace(" ", "").split('|')
        path = preset[1].replace("script-path:", "").replace(" ", "")

        final_arg_dict = {}

        param_map = {
            'ports': ports,
            'redirect': redirect,
            'domain': domain,
            'dns': dns,
            'wordlist': wordlist,
            'url': url,
            'max_pages': max_pages,
            'max_depth': max_depth,
            'extensions': extensions,
            'status_codes': status_codes,
            't': t,
            'user': user,
            'password': password,
            'userlist': userlist,
            'passwordlist': passwordlist,
            'file': file,
            'req': req,
            'ssl': ssl
        }
        if args[0].strip() == '':
            pass
        else:
            for arg in args:
                arg = arg.strip()
                if "ports" in arg:
                    P = arg.split("->")
                    param_name = P[0].strip()
                    port_spec = P[1].strip() if len(P) > 1 else '0'

                    if port_spec == '1' or port_spec == '0':
                        final_arg_dict[param_name] = ports[0] if ports else None
                    else:
                        final_arg_dict[param_name] = ports
                elif "=" in arg:
                    arg_parts = arg.split("=")
                    param_name = arg_parts[0].strip()
                    default_value = arg_parts[1].strip() if len(arg_parts) > 1 else None

                    if param_name in param_map and param_map[param_name] is not None:
                        final_arg_dict[param_name] = param_map[param_name]
                    elif default_value is not None:

                        try:
                            if default_value.isdigit():
                                final_arg_dict[param_name] = int(default_value)
                            elif default_value.lower() == 'true':
                                final_arg_dict[param_name] = True
                            elif default_value.lower() == 'false':
                                final_arg_dict[param_name] = False
                            else:
                                final_arg_dict[param_name] = default_value
                        except ValueError:
                            final_arg_dict[param_name] = default_value
                    else:
                        final_arg_dict[param_name] = None
                else:

                    param_name = arg.strip()
                    if param_name in param_map:
                        final_arg_dict[param_name] = param_map[param_name]
                    else:
                        final_arg_dict[param_name] = None

        script_module = import_script(path)
        if script_module:
            if hasattr(script_module, 'main'):
                script_module.main(**final_arg_dict)
            elif hasattr(script_module, 'run'):
                script_module.main(**final_arg_dict)
            elif hasattr(script_module, 'start'):
                script_module.main(**final_arg_dict)
            else:
                print(f"{RED}[!] No Main Entry Was Found!{RESET}")
                sys.exit(3)
        else:
            print(f"{RED}[!] Cannot Import {path} !{RESET}")
            sys.exit(4)


    except Exception as e:
        print(f"{RED}[!] Custom Script Not Found !{e}{RESET}")






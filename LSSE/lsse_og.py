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
Light-Scan Scripting Engine: (LSSE)
Main Author: ognamgeek
Other Devs: Adam Boulaaz
"""

from __future__ import annotations
from confparser import clsse_runner

import sys
from pathlib import Path
from types import ModuleType
from importlib.util import spec_from_loader, module_from_spec
from importlib.machinery import SourceFileLoader
from collections.abc import Callable
from dataclasses import dataclass

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"


def load_script(path: Path) -> ModuleType:
    """
    Load an .lsse (or .py) file as an importable Python module.

    `path` must be an absolute path to an existing file, e.g.
        Path("/home/adam/.../http_https/http-headers.lsse")
    """
    path = Path(path).resolve()
    if not path.is_file():
        raise FileNotFoundError(path)

    name = "lsse_" + path.stem.replace("-", "_")

    loader = SourceFileLoader(name, str(path))
    spec   = spec_from_loader(name, loader)
    mod    = module_from_spec(spec)

    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        del sys.modules[name]
        raise
    return mod


@dataclass(frozen=True)
class ScriptArgs:
    """Arguments passed to a script. Each handler uses only what it needs."""

    ports: list[int] | None = None
    redirect: bool | None = None
    domain: str | None = None
    dns: str | None = None
    wordlist: str | None = None
    url: str | None = None
    max_pages: str | int | None = None
    max_depth: str | int | None = None
    extensions: str | None = None
    status_codes: str | None = None
    t: str | None = None
    user: str | None = None
    password: str | None = None
    userlist: str | None = None
    passwordlist: str | None = None
    file: str | None = None
    req: str | None = None
    ssl: bool | None = None

class LSSE:
    """Light-Scan Scripting Engine: looks up a script by name and runs it."""

    def __init__(self):
        self.handlers: dict[str, Callable[[ScriptArgs], None]] = {
            "http-title": self._http_title,
            "http-headers": self._http_headers,
            "http-cookie": self._http_cookie,
            "http-methods": self._http_methods,
            "http-cert": self._http_cert,
            "http-robots": self._http_robots,
            "spider": self._spider,
            "dns-subdomain-fuzzing": self._dns_subdomain_fuzzing,
            "script": self._script,
            "http-dir": self._http_dir,
            "dns-lookup": self._dns_lookup,
            "dns-zone-transfer": self._dns_zone_transfer,
            "dns-ns": self._dns_ns,
            "firewall-detect": self._firewall_detection,
            "whois-domain": self._whois_domain,
            "http-past-pages": self._http_past_pages,
            "eternalblue":self._eternalblue,
            "dhcp-discover":self._dhcp_discover,
            "http-comments":self._http_comments,
            "http-request":self._http_request,
            "ssh-info":self._ssh_info,
            "http-security-txt":self._http_security_text,
        }
        self.scripts_list = list(self.handlers)

    def script_list(
        self,
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
        """Run the script named sname, or exit if there's no such script."""
        handler = self.handlers.get(sname)
        if handler is None:
            clsse_runner(
                    sname=sname,
                    ports=ports,
                    redirect=redirect,
                    domain=domain,
                    dns=dns,
                    wordlist=wordlist,
                    url=url,
                    max_pages=max_pages,
                    max_depth=max_depth,
                    extensions=extensions,
                    status_codes=status_codes,
                    t=t,
                    user=user,
                    password=password,
                    userlist=userlist,
                    passwordlist=passwordlist,
                    file=file,
                    req=req,
                    ssl=ssl
                )
            return

        output = handler(
            ScriptArgs(
                ports=ports,
                redirect=redirect,
                domain=domain,
                dns=dns,
                wordlist=wordlist,
                url=url,
                max_pages=max_pages,
                max_depth=max_depth,
                extensions=extensions,
                status_codes=status_codes,
                t=t,
                user=user,
                password=password,
                userlist=userlist,
                passwordlist=passwordlist,
                file=file,
                req=req,
                ssl=ssl
            )
        )
        return output

    def _ports(self, a: ScriptArgs) -> list[int]:
        """Return the requested ports, or exit if none were given."""
        if not a.ports:
            print(f"\n{red}[!] This script requires at least one port (-sp){reset}\n")
            sys.exit(1)
        return a.ports

    def _http_title(self, a: ScriptArgs):
        """Grab the <title> of each HTTP/HTTPS port."""

        mod = load_script(Path("LSSE/scripts/safe/analysis/http_https/http_title.lsse"))

        res = mod.threaded_http_title(a.domain, self._ports(a), bool(a.redirect))
        return res

    def _ssh_info(self, a: ScriptArgs) -> None:
        """Grab SSH_MSG_KEXINIT packet and parse it."""
        mod = load_script(Path("LSSE/scripts/safe/analysis/ssh/ssh_info.lsse"))
        try:
            ssh = mod.SSHRequest(target=a.t,port=int(self._ports(a)[0]))
            ssh.start()
        except Exception as e:
            print(f"\n{red}[!] {e}{reset}")
            sys.exit(1)

    def _eternalblue(self, a: ScriptArgs) -> None:
        """Eternal Blue Exploit CVE-2017-0144"""
        mod = load_script(Path("LSSE/scripts/safe/discovery/smb/eternalblue.lsse"))
        mod.run(target=a.t,port=int(self._ports(a)[0]))

    def _http_comments(self, a: ScriptArgs) -> None:
        """Detect Comments in a page's HTML."""
        mod = load_script(Path("LSSE/scripts/safe/analysis/http_https/http_comments.lsse"))
        try:
            mod.HttpComment(url=a.url).start()
        except Exception as e:
            print(f"\n{red}[!] {e}{reset}")
            sys.exit(1)

    def _http_request(self, a: ScriptArgs):
        """Send Raw HTTP Request"""

        mod = load_script(Path("LSSE/scripts/safe/analysis/http_https/http_request.lsse"))
        try:
            mod.HttpRequest(target=a.t,request_file=a.file,raw_request=a.req,
                        port=int(self._ports(a)[0]),ssl=a.ssl).start()
        except Exception as e:
            print(f"\n{red}[!] {e}{reset}")
            sys.exit(1)

    def _dhcp_discover(self, a: ScriptArgs) -> None:
        """DHCP Discovery For Local Servers and Devices"""
        mod = load_script(Path("LSSE/scripts/safe/discovery/dhcp/dhcp_discover.lsse"))
        mod.main()


    def _firewall_detection(self, a: ScriptArgs) -> None:
        """Do an Advanced Firewall Detection scan"""

        mod = load_script(Path("LSSE/scripts/medium/analysis/firewall/firewall_detect.lsse"))

        mod.main(a.t, int(self._ports(a)[0]))

    def _http_headers(self, a: ScriptArgs) -> None:
        """Dump the response headers of an HTTP/HTTPS port."""
        mod = load_script(Path("LSSE/scripts/safe/analysis/http_https/http_headers.lsse"))
        mod.run(a.domain, port=int(self._ports(a)[0]), redirect=bool(a.redirect))

    def _http_cookie(self, a: ScriptArgs) -> None:
        """Read the cookies set by an HTTP/HTTPS port."""
        mod = load_script(Path("LSSE/scripts/safe/analysis/http_https/http_cookie.lsse"))
        mod.run(a.domain, port=int(self._ports(a)[0]), redirect=bool(a.redirect))

    def _http_methods(self, a: ScriptArgs) -> None:
        """List the HTTP methods a port allows (OPTIONS)."""
        mod = load_script(Path("LSSE/scripts/safe/discovery/http_https/http_methods.lsse"))
        mod.run(a.domain, port=int(self._ports(a)[0]))

    def _http_cert(self, a: ScriptArgs) -> None:
        """Pull the TLS/SSL certificate details of each port."""

        mod = load_script(Path("LSSE/scripts/safe/analysis/https/http_cert.lsse"))
        mod.threaded_tls_ssl_cert_info(a.domain, self._ports(a))

    def _http_robots(self, a: ScriptArgs) -> None:
        """Fetch and parse robots.txt for hidden paths."""

        mod = load_script(Path("LSSE/scripts/safe/extracting/http_https/http_robots.lsse"))
        mod.threaded_http_robots(a.domain, self._ports(a))

    def _http_security_text(self, a: ScriptArgs) -> None:
        """Fetch and parse security.txt for hidden paths."""
        mod = load_script(Path("LSSE/scripts/safe/extracting/http_https/http_security_txt.lsse"))
        mod.http_sec(a.domain)

    def _spider(self, a: ScriptArgs) -> None:
        """Crawl a site for links up to max_pages/max_depth."""
        mod = load_script(Path("LSSE/scripts/safe/extracting/http_https/spider.lsse"))
        max_pages = 5 if a.max_pages is None else int(a.max_pages)
        max_depth = 2 if a.max_depth is None else int(a.max_depth)
        mod.Spider().spider(start_url=a.url, max_pages=max_pages, max_depth=max_depth)

    def _dns_subdomain_fuzzing(self, a: ScriptArgs) -> None:
        """Brute-force subdomains from a wordlist."""
        mod = load_script(Path("LSSE/scripts/medium/discovery/dns/dns_subdomain_fuzzing.lsse"))
        mod.main(a.domain, dns=a.dns, wordlist=a.wordlist)

    def _script(self, a: ScriptArgs) -> None:
        """Detect <script> tags in a page's HTML."""
        mod = load_script(Path("LSSE/scripts/safe/analysis/http_https/script.lsse"))
        try:
            mod.Script(url=a.url).start()
        except Exception as e:
            print(f"\n{red}[!] {e}{reset}")
            sys.exit(1)

    def _http_dir(self, a: ScriptArgs) -> None:
        """Brute-force directories/files on a web server."""
        mod = load_script(Path("LSSE/scripts/medium/discovery/http_https/http_dir.lsse"))
        try:
            mod.HTTPDIR(
                url=a.url,
                extensions=a.extensions,
                wordlist=a.wordlist,
                status_codes=a.status_codes,
            ).start()
        except Exception as e:
            print(f"\n{red}[!] {e}{reset}")
            sys.exit(1)

    def _dns_lookup(self, a: ScriptArgs) -> None:
        """Resolve a domain's DNS records."""
        mod = load_script(Path("LSSE/scripts/safe/discovery/dns/dns_lookup.lsse"))
        if a.dns is None:
            mod.dns_lookup(a.domain)
        else:
            mod.dns_lookup(a.domain, dns_server=a.dns)

    def _dns_zone_transfer(self, a: ScriptArgs) -> None:
        """Attempt a DNS zone transfer (AXFR)."""
        mod = load_script(Path("LSSE/scripts/medium/extracting/dns/dns_zone_transfer.lsse"))
        if a.dns is None:
            mod.runzon(a.domain)
        else:
            mod.runzon(a.domain, dns_server=a.dns)

    def _dns_ns(self, a: ScriptArgs) -> None:
        """List the name servers for a domain."""
        mod = load_script(Path("LSSE/scripts/safe/discovery/dns/dns_ns.lsse"))
        if a.dns is None:
            mod.run(a.domain)
        else:
            mod.run(a.domain, dns_server=a.dns)


    def _whois_domain(self, a: ScriptArgs) -> None:
        """Look up WHOIS registration info for a domain."""
        mod = load_script(Path("LSSE/scripts/safe/discovery/dns/whois_domain.lsse"))
        mod.main(a.domain)

    def _http_past_pages(self, a: ScriptArgs) -> None:
        """Look up archived/past pages for a domain (e.g. Wayback Machine)."""
        mod = load_script(Path("LSSE/scripts/safe/discovery/http_https/http_past_pages.lsse"))
        mod.main(a.domain)


Lsse = LSSE()

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
Light-Scan Scripting Engine (LSSE)
Script Name : http-request
Author : Adam Boulaaz, ognamgeek
Arguments
--> Required Arguments
----> --starget
----> -sp
--> Optional Arguments
----> --ssl
----> --file
----> --request
Categorie :safe/analysis/http_https
"""

import socket
import ssl
from banner_grabber.sprobes.http import HTTP_PROBES

class HttpRequest:
    def __init__(self, target=None, request_file=None, raw_request=None, ssl=None, port=80):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target = target
        self.request_file = request_file
        self.raw_request = raw_request
        self.port = port
        self.ssl = ssl

    def start(self):
        self.sock.connect((self.target, self.port))
        if self.request_file:
            req = open(self.request_file, 'r').read().replace('\\r\\n', '\r\n').replace('\\r','\r').encode()
        elif self.raw_request:
            req = self.raw_request.replace('\\r','\r').replace('\\n','\n').encode()
        else:
            req = HTTP_PROBES[1](self.target)

        if self.ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(self.sock, server_hostname=self.target)

        print(f"[+] Request: \n",req,"\n")
        self.sock.send(req)

        response = b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            response += chunk

        if response != b'':
            print(f"[+] Response: ")
            print(response.decode().split('\r\n\r\n')[0])
        else:
            print(f"[!] No Response .. ")

        self.sock.close()

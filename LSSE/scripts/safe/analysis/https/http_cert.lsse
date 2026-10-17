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
Script Name : http-cert
Author : Sebrey
Arguments
--> Required Arguments
----> --domain
----> -sp
Categorie :safe/analysis/https
"""


import ssl
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
from OpenSSL import crypto
import time

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"
Data = {}


def init(port):
    global Data
    Data[port] = {
        'Data': ''
    }

def tls_ssl_cert_info(host, port):
    global Data

    Data[port]['Data'] += f"\n [+] TLS/SSL Analysis for {host} on port {port}\n\n"

    try:
        sock = socket.create_connection((host, port), timeout=5)
        context = ssl.create_default_context()
        context.check_hostname = False
        secure_sock = context.wrap_socket(sock, server_hostname=host)

        cipher = secure_sock.cipher()
        Data[port]['Data'] += f"   [→] Version: {secure_sock.version()}\n\n"
        Data[port]['Data'] += f"   [→] Cipher: {cipher[0]} ({cipher[2]} bits)\n\n"

        cert = secure_sock.getpeercert()
        der_cert = secure_sock.getpeercert(binary_form=True)

        if cert:
            Data[port]['Data'] += f"   [→] Certificate:\n\n"

            subject_dict = {}
            if 'subject' in cert:
                for item in cert['subject']:
                    for key, value in item:
                        subject_dict[key] = value
            Data[port]['Data'] += f"       • Subject: {subject_dict.get('commonName', 'N/A')}\n"

            if der_cert:
                x509_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

                signature_algo = x509_cert.get_signature_algorithm().decode('utf-8')

                pubkey = x509_cert.get_pubkey()
                key_type = pubkey.type()
                key_bits = pubkey.bits()

                key_type_names = {
                    6: "RSA",
                    408: "EC",
                    116: "DSA",
                }
                key_name = key_type_names.get(key_type, f"Unknown({key_type})")

                Data[port]['Data'] += f"       • Signature Algorithm: {signature_algo}\n"
                Data[port]['Data'] += f"       • Public Key: {key_name} {key_bits} bits\n"

            issuer_dict = {}
            if 'issuer' in cert:
                for item in cert['issuer']:
                    for key, value in item:
                        issuer_dict[key] = value
            Data[port]['Data'] += f"       • Issuer: {issuer_dict.get('organizationName', 'N/A')}\n"

            Data[port]['Data'] += f"       • Valid: {cert.get('notBefore', 'N/A')} to {cert.get('notAfter', 'N/A')}\n"

            if 'subjectAltName' in cert:
                sans = [name[1] for name in cert['subjectAltName'] if name[0] == 'DNS']
                if sans:
                    Data[port]['Data'] += f"       • SANs: {', '.join(sans)}\n"

            if 'serialNumber' in cert:
                Data[port]['Data'] += f"       • Serial: {cert['serialNumber']}\n"

            if 'keyUsage' in cert:
                Data[port]['Data'] += f"       • Key Usage: {', '.join(cert['keyUsage'])}\n"

            if 'extendedKeyUsage' in cert:
                Data[port]['Data'] += f"       • Extended Usage: {', '.join(cert['extendedKeyUsage'])}\n"

            if 'crlDistributionPoints' in cert:
                Data[port]['Data'] += f"       • CRL URLs: {cert['crlDistributionPoints']}\n"

            if 'authorityInfoAccess' in cert:
                ocsp_urls = []
                for access_method, access_location in cert['authorityInfoAccess']:
                    if access_method == 'OCSP':
                        ocsp_urls.append(access_location)
                if ocsp_urls:
                    Data[port]['Data'] += f"       • OCSP Responder: {ocsp_urls[0]}\n"

            if 'certificatePolicies' in cert:
                policies = []
                for policy in cert['certificatePolicies']:
                    if isinstance(policy, tuple) and len(policy) > 0:
                        policies.append(policy[0])
                if policies:
                    Data[port]['Data'] += f"       • Policies: {', '.join(policies[:3])}\n"

            der_cert = secure_sock.getpeercert(binary_form=True)
            if der_cert:
                md5_hash = hashlib.md5(der_cert).hexdigest()
                Data[port]['Data'] += f"       • MD5 FP: {md5_hash}\n"

                sha1_hash = hashlib.sha1(der_cert).hexdigest()
                Data[port]['Data'] += f"       • SHA-1 FP: {sha1_hash}\n"

                sha256_hash = hashlib.sha256(der_cert).hexdigest()
                Data[port]['Data'] += f"       • SHA-256 FP: {sha256_hash}\n"

        Data[port]['Data'] += f"\n   [→] Testing protocol support:\n\n"

        supported = []
        protocol_tests = [
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ("TLSv1.0", ssl.TLSVersion.TLSv1)
        ]

        for proto_name, tls_version in protocol_tests:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.minimum_version = tls_version
                context.maximum_version = tls_version
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                test_sock = socket.create_connection((host, port), timeout=5)
                with context.wrap_socket(test_sock, server_hostname=host):
                    supported.append(proto_name)
                    Data[port]['Data'] += f"       • {proto_name}: +\n"
            except:
                Data[port]['Data'] += f"       • {proto_name}: X\n"

        if supported:
            weak_protos = [p for p in supported if p in ["TLSv1.0", "TLSv1.1"]]
            if weak_protos:
                Data[port]['Data'] += f"\n     [!] Security: Weak protocols enabled: {', '.join(weak_protos)} \n"
            else:
                Data[port]['Data'] += f"\n     [+] Security: Strong configuration \n"

        secure_sock.close()
        sock.close()

    except Exception as e:
        Data[port]['Data'] += f"     {red}[!] Error: {e}{reset}\n"


def threaded_tls_ssl_cert_info(host, ports):
    start = time.time()
    if host == None:
        print(f"\n{yellow}[LSSE] No url was assagned for script {reset}\n")
        exit()
    else:
        pass

    for port in ports:
        init(port)

    with ThreadPoolExecutor(max_workers=60) as executor:
        futures = []
        for port in ports:
            future = executor.submit(tls_ssl_cert_info, host, port)
            futures.append(future)

        for future in as_completed(futures):
            try:
                future.result(timeout=10)
            except Exception as e:
                print(f"{red}[!] Error in thread: {e}{reset}")

    for port in sorted(ports):
        print(Data[port]['Data'])

    print(f"\n\n [+] Analysis complete")
    end = time.time()
    elapsed = end - start
    print(f"\n[+] LSSE Finished in {elapsed:.2f} seconds")

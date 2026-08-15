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

class VersionParser:

    @staticmethod
    def parse_version(banner, port):

        if not banner:
            return None

        if port == 22:
            version_info = VersionParser._parse_ssh(banner)
        elif port == 53:
            version_info = VersionParser._parse_dns(banner)
        elif port == 80 or port == 443 or port == 8080 or port == 8443:
            version_info = VersionParser._parse_http(banner)
        elif port == 21:
            version_info = VersionParser._parse_ftp(banner)
        elif port == 25 or port == 587 or port == 465:
            version_info = VersionParser._parse_smtp(banner)
        elif port == 3306:
            version_info = VersionParser._parse_mysql(banner)
        elif port == 5432:
            version_info = VersionParser._parse_postgresql(banner)
        elif port == 6379:
            version_info = VersionParser._parse_redis(banner)
        elif port == 1433:
            version_info = VersionParser._parse_mssql(banner)
        elif port == 27017:
            version_info = VersionParser._parse_mongodb(banner)
        elif port == 9200:
            version_info = VersionParser._parse_elasticsearch(banner)
        elif port == 110 or port == 995:
            version_info = VersionParser._parse_pop3(banner)
        elif port == 143 or port == 993:
            version_info = VersionParser._parse_imap(banner)
        elif port == 3389:
            version_info = VersionParser._parse_rdp(banner)
        elif port == 5900:
            version_info = VersionParser._parse_vnc(banner)
        elif port == 139 or port == 445:
            version_info = VersionParser._parse_smb(banner)
        elif port == 135:
            version_info = VersionParser._parse_msrpc(banner)
        else:
            version_info = VersionParser._parse_generic(banner)

        return version_info

    @staticmethod
    def _extract_between(text, start_marker, end_marker=None):
        start_pos = text.find(start_marker)
        if start_pos == -1:
            return None

        start_pos += len(start_marker)

        if end_marker is None:
            end_pos = start_pos
            while end_pos < len(text) and text[end_pos] not in ' \t\n\r':
                end_pos += 1
            return text[start_pos:end_pos]

        end_pos = text.find(end_marker, start_pos)
        if end_pos == -1:
            return None

        return text[start_pos:end_pos]

    @staticmethod
    def _extract_version(text):
        version = ""
        i = 0
        found_digit = False

        while i < len(text):
            if text[i].isdigit():
                version = ""
                found_digit = True
                while i < len(text) and (text[i].isdigit() or text[i] == '.' or text[i] == '-'):
                    version += text[i]
                    i += 1

                if '.' in version and len(version.split('.')[0]) > 0:
                    return version
            else:
                i += 1

        return None if not found_digit else version

    @staticmethod
    def _extract_product(text):
        product = ""
        i = 0
        while i < len(text) and text[i].isalpha():
            product += text[i]
            i += 1

        common_products = ['OpenSSH', 'Apache', 'Nginx', 'IIS','VMware', 'Microsoft', 'MySQL', 'PostgreSQL']
        for prod in common_products:
            if text.startswith(prod):
                return prod

        return product if product else 'unknown'

    @staticmethod
    def _parse_ssh(banner):
        if banner.startswith('SSH-'):
            protocol_end = banner.find('-', 4)
            if protocol_end != -1:
                protocol = banner[4:protocol_end]
                rest = banner[protocol_end + 1:]
                underscore_pos = rest.find('_')
                space_pos = rest.find(' ')
                if underscore_pos != -1:
                    product = rest[:underscore_pos]

                    version_start = underscore_pos + 1
                    version_end = rest.find(' ', version_start)
                    if version_end == -1:
                        version_end = len(rest)
                    version = rest[version_start:version_end]
                    return {
                        'service': 'ssh',
                        'protocol': protocol,
                        'product': product,
                        'version': version
                    }
                elif space_pos != -1:
                    product = rest[:space_pos]
                    version_start = space_pos + 1
                    version_end = len(rest)
                    while version_end > version_start and rest[version_end - 1].isspace():
                        version_end -= 1
                    version = rest[version_start:version_end]
                    if version and any(c.isdigit() for c in version):
                        return {
                            'service': 'ssh',
                            'protocol': protocol,
                            'product': product,
                            'version': version
                        }
                else:
                    product = rest
                    return {
                        'service': 'ssh',
                        'protocol': protocol,
                        'product': product,
                        'version': 'unknown'
                    }

        return None

    @staticmethod
    def _parse_http(banner):
        if 'Microsoft-HTTPAPI/2.0' in banner:
            return {
                'service': 'http',
                'product': 'Microsoft-HTTPAPI',
                'version': '2.0',
            }

        server_pos = banner.find('Server:')
        if server_pos != -1:
            line_end = banner.find('\n', server_pos)
            if line_end == -1:
                line_end = len(banner)

            server_line = banner[server_pos:line_end]

            slash_pos = server_line.find('/')
            if slash_pos != -1:
                product_start = server_line.find(' ') + 1
                if product_start == 0:
                    product_start = server_line.find(':') + 2
                product = server_line[product_start:slash_pos].strip()

                version_end = server_line.find(' ', slash_pos)
                if version_end == -1:
                    version_end = len(server_line)
                version = server_line[slash_pos + 1:version_end].strip()

                if product and version:
                    return {
                        'service': 'http',
                        'product': product,
                        'version': version
                    }

            space_pos = server_line.find(' ')
            if space_pos != -1:
                second_space = server_line.find(' ', space_pos + 1)
                if second_space != -1:
                    product = server_line[space_pos + 1:second_space].strip()
                    version = server_line[second_space + 1:].strip()
                    if product and version and any(c.isdigit() for c in version):
                        return {
                            'service': 'http',
                            'product': product,
                            'version': version
                        }

        powered_pos = banner.find('X-Powered-By:')
        if powered_pos != -1:
            line_end = banner.find('\n', powered_pos)
            if line_end == -1:
                line_end = len(banner)

            powered_line = banner[powered_pos:line_end]
            slash_pos = powered_line.find('/')
            if slash_pos != -1:
                product_start = powered_line.find(' ') + 1
                if product_start == 0:
                    product_start = powered_line.find(':') + 2
                product = powered_line[product_start:slash_pos].strip()
                version = powered_line[slash_pos + 1:].strip()
                if product and version:
                    return {
                        'service': 'http',
                        'product': product,
                        'version': version
                    }

        framework_indicators = {
            'X-Powered-By: PHP': 'php',
            'X-Powered-By: ASP.NET': 'asp.net',
            'X-Generator: WordPress': 'wordpress',
            'X-Generator: Drupal': 'drupal',
            'X-Generator: Joomla': 'joomla',
            'X-Generator: Laravel': 'laravel',
            'X-Generator: Django': 'django',
            'X-Generator: Ruby on Rails': 'rails',
            'X-Generator: Node.js': 'nodejs',
            'X-Generator: Express': 'express',
            'X-Generator: Flask': 'flask',
        }

        for indicator, product in framework_indicators.items():
            if indicator in banner:
                return {
                    'service': 'http',
                    'product': product,
                    'version': 'unknown',
                    'framework': True
                }

        return None

    @staticmethod
    def _parse_ftp(banner):
        if banner.startswith('220 '):
            after_220 = banner[4:].strip()

            space_pos = after_220.find(' ')
            if space_pos != -1:
                product = after_220[:space_pos]
                version = VersionParser._extract_version(after_220[space_pos:])
                if product and version:
                    return {
                        'service': 'ftp',
                        'product': product,
                        'version': version
                    }

            slash_pos = after_220.find('/')
            if slash_pos != -1:
                product = after_220[:slash_pos].strip()
                version = VersionParser._extract_version(after_220[slash_pos + 1:])
                if product and version:
                    return {
                        'service': 'ftp',
                        'product': product,
                        'version': version
                    }

        version = VersionParser._extract_version(banner)
        if version:
            product = VersionParser._extract_product(banner)
            if product:
                return {
                    'service': 'ftp',
                    'product': product,
                    'version': version
                }

        return None

    @staticmethod
    def _parse_smtp(banner):
        esmtp_pos = banner.find('ESMTP')
        if esmtp_pos != -1:
            after_esmtp = banner[esmtp_pos + 5:].strip()
            space_pos = after_esmtp.find(' ')
            if space_pos != -1:
                product = after_esmtp[:space_pos]
                paren_start = after_esmtp.find('(')
                if paren_start != -1:
                    paren_end = after_esmtp.find(')', paren_start)
                    if paren_end != -1:
                        version = after_esmtp[paren_start + 1:paren_end].strip()
                        if version and any(c.isdigit() for c in version):
                            return {
                                'service': 'smtp',
                                'product': product,
                                'version': version
                            }

                version = VersionParser._extract_version(after_esmtp[space_pos:])
                if version:
                    return {
                        'service': 'smtp',
                        'product': product,
                        'version': version
                    }
            else:
                product = after_esmtp
                if product and product != 'Ubuntu':
                    return {
                        'service': 'smtp',
                        'product': product,
                        'version': 'unknown'
                    }

        if banner.startswith('220 '):
            after_220 = banner[4:]
            version = VersionParser._extract_version(after_220)
            if version:
                return {
                    'service': 'smtp',
                    'product': 'unknown',
                    'version': version
                }

        return None

    @staticmethod
    def _parse_dns(banner):
        raw = banner.encode('latin-1')
        i = len(raw) - 1
        import re
        strings = re.findall(rb'[\x20-\x7e]{3,}', raw)
        product = strings[-1].decode('ascii')
        cproduct = re.sub(r"[-.\d]", "", product)

        version = VersionParser._extract_version(product)
        return  {
            'service': 'dns',
            'product': cproduct,
            'version': version
        }

    @staticmethod
    def _parse_mysql(banner):
        version = ""
        i = 0
        found_digit = False
        dot_count = 0

        while i < len(banner):
            if banner[i].isdigit():
                version = ""
                dot_count = 0
                found_digit = True
                while i < len(banner):
                    if banner[i].isdigit():
                        version += banner[i]
                    elif banner[i] == '.':
                        version += banner[i]
                        dot_count += 1
                    elif banner[i] == '-':
                        version += banner[i]
                        i += 1
                        while i < len(banner) and (banner[i].isalnum() or banner[i] == '.'):
                            version += banner[i]
                            i += 1
                        break
                    else:
                        break
                    i += 1

                if dot_count >= 1 and version:
                    parts = version.split('.')
                    if len(parts) >= 2:
                        return {
                            'service': 'mysql',
                            'product': 'MySQL',
                            'version': version
                        }
            else:
                i += 1

        return None

    @staticmethod
    def _parse_postgresql(banner):
        postgres_pos = banner.find('PostgreSQL')
        if postgres_pos != -1:
            version_start = postgres_pos + 10
            while version_start < len(banner) and banner[version_start].isspace():
                version_start += 1

            version = ""
            while version_start < len(banner) and (banner[version_start].isdigit() or banner[version_start] == '.'):
                version += banner[version_start]
                version_start += 1

            if version and '.' in version:
                return {
                    'service': 'postgresql',
                    'product': 'PostgreSQL',
                    'version': version
                }

        version = VersionParser._extract_version(banner)
        if version and 'PostgreSQL' in banner:
            return {
                'service': 'postgresql',
                'product': 'PostgreSQL',
                'version': version
            }

        return None

    @staticmethod
    def _parse_redis(banner):
        v_pos = banner.find('v=')
        if v_pos != -1:
            version_start = v_pos + 2
            version = ""
            while version_start < len(banner) and (banner[version_start].isdigit() or banner[version_start] == '.'):
                version += banner[version_start]
                version_start += 1

            if version and '.' in version:
                return {
                    'service': 'redis',
                    'product': 'Redis',
                    'version': version
                }

        redis_ver_pos = banner.find('redis_version=')
        if redis_ver_pos != -1:
            version_start = redis_ver_pos + 14
            version = ""
            while version_start < len(banner) and (banner[version_start].isdigit() or banner[version_start] == '.'):
                version += banner[version_start]
                version_start += 1

            if version and '.' in version:
                return {
                    'service': 'redis',
                    'product': 'Redis',
                    'version': version
                }

        return None

    @staticmethod
    def _parse_mssql(banner):
        sql_pos = banner.find('Microsoft SQL Server')
        if sql_pos != -1:
            year_start = sql_pos + 19
            while year_start < len(banner) and not banner[year_start].isdigit():
                year_start += 1

            year = ""
            while year_start < len(banner) and banner[year_start].isdigit():
                year += banner[year_start]
                year_start += 1

            if year and len(year) == 4:
                return {
                    'service': 'mssql',
                    'product': 'Microsoft SQL Server',
                    'version': year
                }

        return None

    @staticmethod
    def _parse_mongodb(banner):
        version = VersionParser._extract_version(banner)
        if version and '.' in version:
            if 'mongodb' in banner.lower() or 'mongo' in banner.lower():
                return {
                    'service': 'mongodb',
                    'product': 'MongoDB',
                    'version': version
                }
        return None

    @staticmethod
    def _parse_elasticsearch(banner):
        number_pos = banner.find('"number"')
        if number_pos != -1:
            colon_pos = banner.find(':', number_pos)
            if colon_pos != -1:
                quote_start = banner.find('"', colon_pos)
                if quote_start != -1:
                    quote_end = banner.find('"', quote_start + 1)
                    if quote_end != -1:
                        version = banner[quote_start + 1:quote_end]
                        if version and '.' in version:
                            return {
                                'service': 'elasticsearch',
                                'product': 'Elasticsearch',
                                'version': version
                            }
        return None

    @staticmethod
    def _parse_pop3(banner):
        if '+OK' in banner:
            ok_pos = banner.find('+OK')
            after_ok = banner[ok_pos + 3:].strip()

            pop3_pos = after_ok.find('POP3')
            if pop3_pos != -1:
                after_pop3 = after_ok[pop3_pos + 4:].strip()
                space_pos = after_pop3.find(' ')
                if space_pos != -1:
                    product = after_pop3[:space_pos]
                    version = VersionParser._extract_version(after_pop3[space_pos:])
                    if product and version:
                        return {
                            'service': 'pop3',
                            'product': product,
                            'version': version
                        }

        version = VersionParser._extract_version(banner)
        if version:
            return {
                'service': 'pop3',
                'product': 'unknown',
                'version': version
            }
        return None

    @staticmethod
    def _parse_imap(banner):
        if '* OK' in banner:
            ok_pos = banner.find('* OK')
            after_ok = banner[ok_pos + 4:].strip()

            imap_pos = after_ok.find('IMAP')
            if imap_pos != -1:
                after_imap = after_ok[imap_pos + 4:].strip()
                space_pos = after_imap.find(' ')
                if space_pos != -1:
                    product = after_imap[:space_pos]
                    version = VersionParser._extract_version(after_imap[space_pos:])
                    if product and version:
                        return {
                            'service': 'imap',
                            'product': product,
                            'version': version
                        }

        version = VersionParser._extract_version(banner)
        if version:
            return {
                'service': 'imap',
                'product': 'unknown',
                'version': version
            }
        return None

    @staticmethod
    def _parse_rdp(banner):
        windows_pos = banner.find('Windows')
        if windows_pos != -1:
            i = windows_pos
            while i < len(banner):
                if banner[i].isdigit():
                    year = ""
                    while i < len(banner) and banner[i].isdigit():
                        year += banner[i]
                        i += 1
                    if year and len(year) == 4:
                        return {
                            'service': 'rdp',
                            'product': 'Windows',
                            'version': year
                        }
                i += 1

        return None

    @staticmethod
    def _parse_vnc(banner):
        rfb_pos = banner.find('RFB')
        if rfb_pos != -1:
            version_start = rfb_pos + 3
            while version_start < len(banner) and banner[version_start].isspace():
                version_start += 1

            version = ""
            while version_start < len(banner) and (banner[version_start].isdigit() or banner[version_start] == '.'):
                version += banner[version_start]
                version_start += 1

            if version and '.' in version:
                return {
                    'service': 'vnc',
                    'product': 'VNC',
                    'version': version
                }
        return None

    @staticmethod
    def _parse_msrpc(banner):
        if banner.startswith('05 00'):
            return {
                'service': 'MSRPC',
                'product': 'MSRPC',
                'version': '5.00'
            }

    @staticmethod
    def _parse_smb(banner):
        smb_pos = banner.find('SMB')
        if smb_pos != -1:
            version_start = smb_pos + 3
            while version_start < len(banner) and banner[version_start].isspace():
                version_start += 1

            version = ""
            while version_start < len(banner) and (banner[version_start].isdigit() or banner[version_start] == '.'):
                version += banner[version_start]
                version_start += 1

            if version and '.' in version:
                return {
                    'service': 'smb',
                    'product': 'SMB',
                    'version': version
                }
        return None

    @staticmethod
    def _parse_generic(banner):
        version = VersionParser._extract_version(banner)
        if version:
            product = VersionParser._extract_product(banner)
            if not product or product == 'unknown':
                common_products = ['Apache', 'nginx', 'IIS', 'Tomcat','VMware', 'Jetty', 'Node', 'Python']
                for prod in common_products:
                    if prod.lower() in banner.lower():
                        product = prod
                        break

            return {
                'service': 'unknown',
                'product': product if product else 'unknown',
                'version': version
            }
        return None
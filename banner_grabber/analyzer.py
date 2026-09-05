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

SERVICE_PATTERNS = {
    "http": ["server: ", "http/", "apache", "nginx", "iis", "cloudflare","gws"],
    "ssh": ["ssh", "openssh", "dropbear","putty","libssh","paramiko"],
    "ftp": ["vsftpd", "proftpd", "pure-ftpd", "filezilla", "microsoft ftp"],
    "smtp": ["postfix", "exim", "sendmail", "dovecot","courier", "microsoft esmtp"],
    "imap": ["dovecot", "courier", "microsoft imap"],
    "vmware": ["vmware authentication","vmware"],
    "https": ["ssl", "tls"],
    "mysql": ["mysql", "mariadb"],
    "postgresql": ["postgresql"],
    "mongodb": ["mongodb"],
    "redis": ["redis"],
    "vnc": ["rfb", "vnc", "realvnc", "tigervnc"],
    "rdp": ["remote desktop"],
    "dns": ["bind", "dnsmasq", "unbound"],
    "msrpc": ["05 00 0d 03", "msrpc","rpc"],
    "smb": ["ff 53 4d 42","fe 53 4d 42","smb","SMB"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes"],
    "jenkins": ["jenkins"],
    "git": ["git-upload-pack", "git-receive-pack"],
    "activemq": ["activemq", "openwire"],
    "rabbitmq": ["rabbitmq", "amqp"],
    "zookeeper": ["zookeeper"],
    "etcd": ["etcd"],
    "consul": ["consul"],
    "elasticsearch": ["elasticsearch"],
    "logstash": ["logstash"],
    "kibana": ["kibana"],
    "zabbix": ["zabbix"],
    "snmp": ["snmp", "net-snmp"],
    "sip": ["sip"],
    "rtsp": ["rtsp"],
    "xmpp": ["xmpp", "jabber"],
    "ldap": ["ldap"],
    "kerberos": ["kerberos"],
    "oracle": ["oracle"],
    "db2": ["db2"],
    "mssql": ["microsoft sql", "sql server"],
    "cassandra": ["cassandra"],
    "couchdb": ["couchdb"],
    "memcached": ["memcached"],
    "riak": ["riak"],
    "openldap": ["openldap"],
    "samba": ["samba", "netbios"],
    "nfs": ["nfs", "mountd"],
    "rpc": ["rpcbind", "portmap"],
    "ntp": ["ntp"],
    "tftp": ["tftp"],
    "syslog": ["syslog"],
    "bacnet": ["bacnet"],
    "modbus": ["modbus"],
    "dnp3": ["dnp3"],
    "iec": ["iec"],
    "s7": ["s7"],
    "opc": ["opc"],
    "mqtt": ["mqtt"],
    "coap": ["coap"],
    "amqp": ["amqp"],
    "stomp": ["stomp"],
}

def analyse_banner(banner, port):
    if not banner:
        return None
    banner_lower = banner.lower()
    for service, patterns in SERVICE_PATTERNS.items():
        for p in patterns:
            if p in banner_lower:
                if service == 'http' and port in {443, 465, 993, 995, 8443, 4643, 636, 3269}:
                    return 'https'
                return service
    return None

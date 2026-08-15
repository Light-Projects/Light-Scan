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
Script Name : http-dir
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --url
--> Optional Arguments
----> --wordlist
----> --status-codes (default: 200,301,302,403)
----> --extensions (default: php,asp,aspx,jsp,html,txt)
Categorie : medium/discovery/http_https
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import sys
import os

green = "\033[32m"
reset = "\033[0m"
yellow = "\033[33m"
red = "\033[31m"
cyan = "\033[36m"

class HTTPDIR:
    def __init__(self, url, wordlist=None, threads=20, status_codes=None, extensions=None):
        self.url = url.rstrip('/')
        self.wordlist_source = wordlist
        self.threads = threads

        if status_codes and isinstance(status_codes, str):
            self.status_codes = [int(c.strip()) for c in status_codes.split(',') if c.strip()]
        else:
            self.status_codes = status_codes or [200, 301, 302, 400, 403]

        if extensions and isinstance(extensions, str):
            ext_list = [ext.strip() for ext in extensions.split(',') if ext.strip()]
            self.extensions = []
            for ext in ext_list:
                if ext and not ext.startswith('.'):
                    self.extensions.append(f".{ext}")
                elif ext:
                    self.extensions.append(ext)
            if '' not in self.extensions:
                self.extensions.insert(0, '')
        else:
            self.extensions = extensions or ['']

        self.found = []
        self.lock = threading.Lock()
        self.total = 0
        self.completed = 0

    def start(self):
        if self.wordlist_source:
            paths = self.load_wordlist(self.wordlist_source)
        else:
            paths = self.get_default_wordlist()

        full_paths = []
        for path in paths:
            for ext in self.extensions:
                full_paths.append(f"{path}{ext}")

        self.total = len(full_paths)

        print(f"\n{cyan}[+] HTTP Directory Brute Force Started{reset}")
        print(f"{cyan}[+] Target: {self.url}{reset}")
        print(f"{cyan}[+] Wordlist: {len(paths)} base paths × {len(self.extensions)} extensions = {self.total} total{reset}")
        print(f"{cyan}[+] Status codes: {self.status_codes}{reset}")
        print(f"{cyan}[+] Extensions: {self.extensions}{reset}")
        print()

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.test_path, path): path for path in full_paths}
            for future in as_completed(futures):
                self.completed += 1
                self.show_progress()

        elapsed = time.time() - start_time
        self.print_results(elapsed)
        return self.found

    def test_path(self, path):
        test_url = f"{self.url}/{path}"
        try:
            response = requests.get(test_url, timeout=5, allow_redirects=False, headers={'User-Agent': 'LightScan-LSSE/1.0'})
            if response.status_code in self.status_codes:
                with self.lock:
                    self.found.append({'url': test_url, 'status': response.status_code, 'size': len(response.content), 'title': self.extract_title(response.text)})
            return response.status_code in self.status_codes
        except:
            return False

    def extract_title(self, html):
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'html.parser')
            return soup.title.string.strip()[:50] if soup.title else ''
        except:
            return ''

    def show_progress(self):
        percent = (self.completed / self.total) * 100
        sys.stdout.write(f"\r{cyan}[*] Progress: {self.completed}/{self.total} ({percent:.1f}%) | Found: {len(self.found)}{reset}")
        sys.stdout.flush()

    def print_results(self, elapsed):
        print(f"\n\n{green}[+] Scan completed in {elapsed:.2f} seconds{reset}")
        print(f"{green}[+] Found {len(self.found)} directories/files:{reset}\n")
        if self.found:
            by_status = {}
            for item in self.found:
                by_status.setdefault(item['status'], []).append(item)
            for status, items in sorted(by_status.items()):
                status_color = green if status == 200 else yellow
                print(f"{status_color}[{status}] Found {len(items)} items:{reset}")
                for item in items[:20]:
                    print(f"    {item['url']} ({item['size']} bytes)")
                if len(items) > 20:
                    print(f"    ... and {len(items) - 20} more")
                print()
        else:
            print(f"{yellow}[!] No directories or files found{reset}")

    def get_default_wordlist(self):
        return [
            "admin", "administrator", "adminpanel", "admin-console", "adm", "cp", "control",
            "dashboard", "manager", "management", "sysadmin", "webadmin", "root", "master",
            "api", "v1", "v2", "v3", "api/v1", "api/v2", "rest", "restapi", "graphql",
            "swagger", "swagger-ui", "docs", "documentation", "apidoc", "redoc",
            "login", "signin", "logon", "auth", "authenticate", "oauth", "oauth2",
            "register", "signup", "join", "create-account", "user", "users",
            "profile", "account", "settings", "preferences", "config", "configuration",
            "backup", "backups", "dump", "dbdump", "sql", "database", "db",
            "phpmyadmin", "pma", "myadmin", "mysqladmin", "adminer", "phpPgAdmin",
            "wordpress", "wp-admin", "wp-login", "wp-content", "wp-includes", "wp-json",
            "joomla", "administrator", "joomla-admin", "joomla-login",
            "drupal", "admin/drupal", "drupal-login", "user/login",
            "magento", "admin/magento", "magento-login", "backend",
            "prestashop", "admin-prestashop", "prestashop-login",
            "shopify", "admin/shopify", "shopify-login",
            "laravel", "laravel-admin", "laravel-login",
            "symfony", "symfony-admin", "symfony-login",
            "codeigniter", "ci-admin", "ci-login",
            "yii", "yii-admin", "yii-login",
            "cakephp", "cake-admin", "cake-login",
            "rails", "rails-admin", "rails-login",
            "django", "django-admin", "django-login",
            "flask", "flask-admin", "flask-login",
            "express", "express-admin", "express-login",
            "angular", "react", "vue", "next", "nuxt",
            "static", "assets", "public", "resources",
            "images", "img", "css", "js", "javascript", "fonts", "icons",
            "uploads", "upload", "files", "downloads", "media", "storage",
            "tmp", "temp", "cache", "logs", "log", "error_log",
            "debug", "test", "tests", "testing", "stage", "staging", "dev", "development",
            "sandbox", "demo", "example", "samples", "examples",
            "git", ".git", "git/config", ".git/config", "svn", ".svn",
            "env", ".env", "htaccess", ".htaccess", "htpasswd", ".htpasswd",
            "robots.txt", "sitemap.xml", "security.txt", "humans.txt",
            "crossdomain.xml", "clientaccesspolicy.xml",
            "backup.zip", "backup.tar", "backup.gz", "backup.sql",
            "old", "original", "copy", "bak", "bkp", "save",
            "hidden", "secret", "private", "internal", "confidential",
            "cgi-bin", "cgi-bin/test", "cgi-bin/printenv", "cgi-bin/status",
            "iisstart", "iisadmin", "aspnet_client",
            "tomcat", "tomcat-docs", "examples", "sample", "host-manager", "manager/html",
            "jboss", "jboss-web", "jboss-admin",
            "weblogic", "websphere", "oracle", "oracle-em",
            "jenkins", "jenkins/login", "jenkins/script",
            "sonarqube", "sonar", "nexus", "artifactory",
            "gitlab", "gitlab/login", "gitlab/admin",
            "github", "bitbucket", "gitea", "gogs",
            "jira", "confluence", "bamboo", "crucible",
            "zabbix", "nagios", "icinga", "check_mk", "prometheus", "grafana",
            "kibana", "elasticsearch", "logstash", "graylog",
            "portainer", "docker", "rancher", "k8s", "kubernetes", "kube-system",
            "redis", "redis-commander", "redisinsight",
            "mongodb", "mongo-express", "rockmongo",
            "phpinfo", "info", "phpinfo.php", "test.php", "info.php",
            "blog", "weblog", "weblogs", "wordpress", "mediawiki", "wiki", "Main_Page",
            "tikiwiki", "cgi-bin/mj_wwwusr", "majordomo/mj_wwwusr", "j2ee/examples/servlets",
            "j2ee/examples/jsp", "dsc", "reg_1.htm", "adr.htm", "line_login.htm", "tbook.csv",
            "globalSIPsettings.html", "SIPsettingsLine1.html", "websvn", "repos", "repo",
            "archiva/index.action", "login.stm", "tools_admin.php", "bsc_lan.php", "Manage.tri",
            "logo_t.gif", "system.html", "main_configure.cgi", "OvCgi/Toolbar.exe", "frontend/x3",
            "awstatstotals/awstatstotals.php", "awstats/awstatstotals.php", "awstatstotals.php",
            "awstats/index.php", "egroupware", "calendar/cal_search.php", "cal_search.php",
            "a_viewusers.php", "aphpkb", "webedition/we/include/we_modules", "webedition",
            "Examples", "LightNEasy.php", "channel_detail.php", "cgi-bin/vcs", "ocsreports",
            "vbseo.php", "forum", "forums", "smf", "phpbb", "manager", "admin.php", "admin",
            "admin/admin", "moderator", "webadmin", "adminarea", "bb-admin", "adminLogin",
            "admin_area", "panel-administracion", "instadmin", "memberadmin", "administratorlogin",
            "adm", "admin/account.php", "admin/index.php", "admin/login.php", "admin/admin.php",
            "joomla/administrator", "login.php", "admin_area/admin.php", "admin_area/login.php",
            "siteadmin/login.php", "siteadmin/index.php", "siteadmin/login.html", "admin/index.html",
            "admin/login.html", "admin/admin.html", "admin_area/index.php", "bb-admin/index.php",
            "bb-admin/login.php", "bb-admin/admin.php", "admin/home.php", "admin_area/login.html",
            "admin_area/index.html", "admin/controlpanel.php", "admincp", "admincp/index.asp",
            "admincp/index.html", "admincp/login.php", "admin/account.html", "adminpanel.html",
            "webadmin.html", "webadmin/index.html", "webadmin/admin.html", "webadmin/login.html",
            "admin/admin_login.html", "admin_login.html", "panel-administracion/login.html",
            "admin/cp.php", "cp.php", "administrator/index.php", "administrator/login.php",
            "nsw/admin/login.php", "webadmin/login.php", "admin/admin_login.php", "admin_login.php",
            "administrator/account.php", "administrator.php", "admin_area/admin.html",
            "pages/admin/admin-login.php", "admin/admin-login.php", "admin-login.php",
            "bb-admin/index.html", "bb-admin/login.html", "bb-admin/admin.html", "admin/home.html",
            "modelsearch/login.php", "moderator.php", "moderator/login.php", "moderator/admin.php",
            "account.php", "pages/admin/admin-login.html", "admin/admin-login.html",
            "admin-login.html", "controlpanel.php", "admincontrol.php", "admin/adminLogin.html",
            "adminLogin.html", "home.html", "rcjakar/admin/login.php", "adminarea/index.html",
            "adminarea/admin.html", "webadmin.php", "webadmin/index.php", "webadmin/admin.php",
            "admin/controlpanel.html", "admin.html", "admin/cp.html", "cp.html", "adminpanel.php",
            "moderator.html", "administrator/index.html", "administrator/login.html", "user.html",
            "administrator/account.html", "administrator.html", "login.html", "modelsearch/login.html",
            "moderator/login.html", "adminarea/login.html", "panel-administracion/index.html",
            "panel-administracion/admin.html", "modelsearch/index.html", "modelsearch/admin.html",
            "admincontrol/login.html", "adm/index.html", "adm.html", "moderator/admin.html",
            "user.php", "account.html", "controlpanel.html", "admincontrol.html",
            "panel-administracion/login.php", "wp-login.php", "wp-json", "adminLogin.php",
            "admin/adminLogin.php", "adminarea/index.php", "adminarea/admin.php",
            "adminarea/login.php", "panel-administracion/index.php", "panel-administracion/admin.php",
            "modelsearch/index.php", "modelsearch/admin.php", "admincontrol/login.php",
            "adm/admloginuser.php", "admloginuser.php", "admin2.php", "admin2/login.php",
            "admin2/index.php", "adm/index.php", "adm.php", "affiliate.php", "adm_auth.php",
            "memberadmin.php", "administratorlogin.php", "account.cfm", "admin/account.cfm",
            "admin/index.cfm", "admin/login.cfm", "admin/admin.cfm", "admin.cfm",
            "admin/admin_login.cfm", "admin_login.cfm", "adminpanel.cfm", "admin/controlpanel.cfm",
            "admincontrol.cfm", "panel-administracion/login.cfm", "admin/cp.cfm",
            "pages/admin/admin-login.cfm", "admincp/index.cfm", "admincp/login.cfm",
            "admin_area/admin.cfm", "admin_area/login.cfm", "moderator/login.cfm",
            "administrator/login.cfm", "moderator.cfm", "modelsearch/index.cfm",
            "panel-administracion/admin.cfm", "adm/admloginuser.cfm", "adm.cfm", "adm_auth.cfm",
            "administratorlogin.cfm", "webadmin.cfm", "webadmin/index.cfm", "modelsearch/login.cfm",
            "login.cfm", "administrator.cfm", "administrator/account.cfm", "adminLogin.cfm",
            "siteadmin/login.cfm", "admin2/index.cfm", "adm/index.cfm", "admin_area/index.cfm",
            "bb-admin/index.cfm", "bb-admin/login.cfm", "bb-admin/admin.cfm", "siteadmin/index.cfm",
            "memberadmin.cfm", "admin2/login.cfm", "admloginuser.cfm", "admincontrol/login.cfm",
            "administrator/index.cfm", "modelsearch/admin.cfm", "panel-administracion/index.cfm",
            "adminarea/login.cfm", "adminarea/admin.cfm", "adminarea/index.cfm",
            "admin/adminLogin.cfm", "webadmin/login.cfm", "webadmin/admin.cfm", "user.cfm",
            "controlpanel.cfm", "moderator/admin.cfm", "cp.cfm", "admin-login.cfm",
            "admin/admin-login.cfm", "admin/home.cfm", "adm1n", "4dm1n", "account.asp",
            "admin/account.asp", "admin/index.asp", "admin/login.asp", "admin/admin.asp",
            "admin_area/admin.asp", "admin_area/login.asp", "admin_area/index.asp",
            "bb-admin/index.asp", "bb-admin/login.asp", "bb-admin/admin.asp", "admin/home.asp",
            "admin/controlpanel.asp", "admin.asp", "pages/admin/admin-login.asp",
            "admin/admin-login.asp", "admin-login.asp", "admin/cp.asp", "cp.asp",
            "administrator/account.asp", "administrator.asp", "login.asp", "modelsearch/login.asp",
            "moderator.asp", "moderator/login.asp", "administrator/login.asp", "moderator/admin.asp",
            "controlpanel.asp", "user.asp", "admincp/login.asp", "admincontrol.asp",
            "adminpanel.asp", "webadmin.asp", "webadmin/index.asp", "webadmin/admin.asp",
            "webadmin/login.asp", "admin/admin_login.asp", "admin_login.asp",
            "panel-administracion/login.asp", "adminLogin.asp", "admin/adminLogin.asp", "home.asp",
            "adminarea/index.asp", "adminarea/admin.asp", "adminarea/login.asp",
            "panel-administracion/index.asp", "panel-administracion/admin.asp",
            "modelsearch/index.asp", "modelsearch/admin.asp", "administrator/index.asp",
            "admincontrol/login.asp", "adm/admloginuser.asp", "admloginuser.asp", "admin2.asp",
            "admin2/login.asp", "admin2/index.asp", "adm/index.asp", "adm.asp", "adm_auth.asp",
            "memberadmin.asp", "administratorlogin.asp", "siteadmin/login.asp", "siteadmin/index.asp",
            "account.aspx", "admin/account.aspx", "admin/index.aspx", "admin/login.aspx",
            "admin/admin.aspx", "admin_area/admin.aspx", "admin_area/login.aspx",
            "admin_area/index.aspx", "bb-admin/index.aspx", "bb-admin/login.aspx",
            "bb-admin/admin.aspx", "admin/home.aspx", "admin/controlpanel.aspx", "admin.aspx",
            "pages/admin/admin-login.aspx", "admin/admin-login.aspx", "admin-login.aspx",
            "admin/cp.aspx", "cp.aspx", "administrator/account.aspx", "administrator.aspx",
            "login.aspx", "modelsearch/login.aspx", "moderator.aspx", "moderator/login.aspx",
            "administrator/login.aspx", "moderator/admin.aspx", "controlpanel.aspx", "user.aspx",
            "admincp/index.aspx", "admincp/login.aspx", "admincontrol.aspx", "adminpanel.aspx",
            "webadmin.aspx", "webadmin/index.aspx", "webadmin/admin.aspx", "webadmin/login.aspx",
            "admin/admin_login.aspx", "admin_login.aspx", "panel-administracion/login.aspx",
            "adminLogin.aspx", "admin/adminLogin.aspx", "home.aspx", "adminarea/index.aspx",
            "adminarea/admin.aspx", "adminarea/login.aspx", "panel-administracion/index.aspx",
            "panel-administracion/admin.aspx", "modelsearch/index.aspx", "modelsearch/admin.aspx",
            "administrator/index.aspx", "admincontrol/login.aspx", "adm/admloginuser.aspx",
            "admloginuser.aspx", "admin2.aspx", "admin2/login.aspx", "admin2/index.aspx",
            "adm/index.aspx", "adm.aspx", "adm_auth.aspx", "memberadmin.aspx",
            "administratorlogin.aspx", "siteadmin/login.aspx", "siteadmin/index.aspx",
            "account.jsp", "admin/index.jsp", "admin/login.jsp", "admin/admin.jsp",
            "admin_area/admin.jsp", "admin_area/login.jsp", "admin_area/index.jsp",
            "bb-admin/index.jsp", "bb-admin/login.jsp", "bb-admin/admin.jsp", "admin/home.jsp",
            "admin/controlpanel.jsp", "admin.jsp", "pages/admin/admin-login.jsp",
            "admin/admin-login.jsp", "admin-login.jsp", "admin/cp.jsp", "cp.jsp",
            "administrator/account.jsp", "administrator.jsp", "login.jsp", "modelsearch/login.jsp",
            "moderator.jsp", "moderator/login.jsp", "administrator/login.jsp", "moderator/admin.jsp",
            "controlpanel.jsp", "user.jsp", "admincp/index.jsp", "admincp/login.jsp",
            "admincontrol.jsp", "admin/account.jsp", "adminpanel.jsp", "webadmin.jsp",
            "webadmin/index.jsp", "webadmin/admin.jsp", "webadmin/login.jsp",
            "admin/admin_login.jsp", "admin_login.jsp", "panel-administracion/login.jsp",
            "adminLogin.jsp", "admin/adminLogin.jsp", "home.jsp", "adminarea/index.jsp",
            "adminarea/admin.jsp", "adminarea/login.jsp", "panel-administracion/index.jsp",
            "panel-administracion/admin.jsp", "modelsearch/index.jsp", "modelsearch/admin.jsp",
            "administrator/index.jsp", "admincontrol/login.jsp", "adm/admloginuser.jsp",
            "admloginuser.jsp", "admin2.jsp", "admin2/login.jsp", "admin2/index.jsp",
            "adm/index.jsp", "adm.jsp", "adm_auth.jsp", "memberadmin.jsp", "administratorlogin.jsp",
            "siteadmin/login.jsp", "siteadmin/index.jsp", "admin1.php", "administr8.asp",
            "administr8.php", "administr8.jsp", "administr8.aspx", "administr8.cfm", "administr8",
            "administer", "administracao.php", "administracao.asp", "administracao.aspx",
            "administracao.cfm", "administracao.jsp", "administracion.php", "administracion.asp",
            "administracion.aspx", "administracion.jsp", "administracion.cfm", "administrators",
            "adminpro", "admins", "admins.cfm", "admins.php", "admins.jsp", "admins.asp",
            "admins.aspx", "maintenance", "Lotus_Domino_Admin", "hpwebjetadmin", "_admin",
            "_administrator", "_administrador", "_admins", "_administrators", "_administradores",
            "_administracion", "_4dm1n", "_adm1n", "_Admin", "system_administration",
            "system-administration", "system-admin", "system-admins", "system-administrators",
            "administracion-sistema", "Administracion", "Admin", "Administrator", "Manager", "Adm",
            "systemadmin", "AdminLogin.asp", "AdminLogin.php", "AdminLogin.jsp", "AdminLogin.aspx",
            "AdminLogin.cfm", "admin108", "pec_admin", "system/admin", "plog-admin", "ESAdmin",
            "axis2-admin", "_sys", "admin_cp.asp", "sitecore/admin", "sitecore/login/admin",
            "backup", "backup.sql", "backup.sql.gz", "backup.sql.bz2", "backup.zip", "backups", "bak",
            "back", "cache/backup", "admin/backup", "dbbackup.txt", "b.sql", "db.sql", "ddb.sql",
            "users.sql", "database.sql", "mysql.sql", "dump.sql", "respaldo.sql", "data.sql",
            "old.sql", "usuarios.sql", "bdb.sql", "1.sql", "admin/download/backup.sql",
            "clientaccesspolicy.xml", "atom", "atom.aspx", "atom.php", "atom.xml", "atom.jsp",
            "rss", "rss.aspx", "rss.php", "rss.xml", "rss.jsp", "etc/passwd", "boot.ini",
            "example", "examples", "iissamples", "j2eeexamples", "j2eeexamplesjsp", "sample",
            "ncsample", "fpsample", "cmsample", "samples", "mono/1.1/index.aspx", "login", "login.htm",
            "login.jsp", "test.asp", "test.class", "test", "test.htm", "test.html", "test.php",
            "test.txt", "webmail", "mail", "log", "log.htm", "log.php", "log.asp", "log.aspx",
            "log.jsp", "logs", "logs.htm", "logs.php", "logs.asp", "logs.aspx", "logs.jsp",
            "wwwlog", "wwwlogs", "mail_log_files", "images/rails.png", "mono", "robots.txt",
            "crossdomain.xml", "css/cake.generic.css", "img/cake.icon.gif", "img/cake.icon.png",
            "js/vendors.php", "cgi-bin/ffileman.cgi", "fshow.php", "admin/upload.php",
            "upload_multiple_js.php", "uploadtester.asp", "info.php", "phpinfo.php",
            "kusabax/manage_page.php", "plus/lurking.php", "adm/barra/assetmanager/assetmanager.php",
            "eyeos", "NETWARE.HTM", "setup.cgi", "debug.cgi", "ehcp", "tools_admin.cgi", "level/15",
            "exec/show/log/CR", "level/15/exec/-/configure/http", "level/15/exec/-",
            "appServer/jvmReport.jsf", "common/appServer/jvmReport.jsf", "console/login/loginForm.jsp",
            "login_img.jpg", "cirronetlogo.gif", "browserId/wizardForm.jhtml",
            "webline/html/forms/callback.jhtml", "webline/html/forms/callbackICM.jhtml",
            "webline/html/agent/AgentFrame.jhtml", "webline/html/agent/default/badlogin.jhtml",
            "callme/callForm.jhtml", "webline/html/multichatui/nowDefunctWindow.jhtml",
            "browserId/wizard.jhtml", "admin/CiscoAdmin.jhtml", "msccallme/mscCallForm.jhtml",
            "webline/html/admin/wcs/LoginPage.jhtml", "restoreinfo.cgi", "confirminvite.php",
            "sourcebans", "swfupload/index.php", "mymarket/shopping/index.php", "myshop_start.php",
            "piranha/secure/passwd.php3", "cgi-bin/ck/mimencode", "cgi-bin/masterCGI",
            "tiny_mce/plugins/filemanager", "upload/scp/ajax.php", "cgi-mod/view_help.cgi",
            "cgi-mod/index.cgi", "cgi-mod/smtp_test.cgi", "TopToolArea.html", "switchSystem.html",
            "intruvert/jsp/module/Login.jsp", "ajaxfilemanager", "upload/data/settings.cdb", "fm.php",
            "nagios3/cgi-bin/statuswml.cgi", "nagios3", "test/logon.html", "cal_cat.php",
            "calendar/cal_cat.php", "cal/cal_cat.php", "private/sdc.tgz", "cacti",
            "cgi-bin/awstats.pl", "wiki/rankings.php", "reqdetails.php", "shared/help.php",
            "seti.php", "imc", "imcws", "partymgr", "Base/upload.php", "Base/example_1.php",
            "YUI-upload/html", "tools/filemanager/skins/mobile/admin1.template.php", "Uploadify",
            "syssite", "updown.php", "modules/docmanager/doctypetemplates/myuploadedfile",
            "ReqWebHelp/advanced/workingSet.jsp", "dhost", "engine/api/api.class.php",
            "jsft_resource.jsf", "scales_static_resource.jsf", "setup/password_required.html",
            "zp-core", "amember", ".hgignore", ".gitignore", ".bzrignore", "debug.seam",
            "CSS/Miniweb.css", "S7Web.css", "Portal0000.htm", "arcsight",
            "arcsight/images/logo-login-arcsight.gif", "arcsight/images/navbar-icon-logout-on.gif",
            "images/logo-arcsight.gif", "logger/monitor.ftl", "beef", "BEEF", "beef/images/beef.gif",
            "gfx/form_top_left_corner.gif", "gfx/logout_24.png", "gfx/new_logo.gif",
            "javascript/sorttable.js", "images/btn_help_nml.gif", "images/hdr_icon_homeG.gif",
            "spControl.php", "images/isslogo.gif", "deploymentmanager",
            "i18n/EN/css/foundstone.css", "i18n/EN/images/external_nav_square.gif",
            "officescan/console/html/cgi/cgiChkMasterPwd.exe",
            "officescan/console/html/ClientInstall/officescannt.htm",
            "officescan/console/html/images/icon_refresh.gif", "picts/BC_bwlogorev.gif",
            "picts/menu_leaf.gif", "theme/images/en/login1.gif", "NessusClient.swf", "dotDefender",
            "hop.php", "CSCOSSLC/config-auth",
            "actuator", "auditevents", "autoconfig", "beans", "configprops", "env", "flyway",
            "health", "healthcheck", "healthchecks", "loggers", "liquibase", "metrics", "mappings",
            "trace", "heapdump", "jolokia", "vmware", "vmware/imx/vmware_boxes-16x16.png", "ui",
            "ui/imx/vmwareLogo-16x16.png", "ui/imx/vmwarePaperBagLogo-16x16.png", "ui/vManage.do",
            "client/VMware-viclient.exe", "en/welcomeRes.js", "citrix", "Citrix",
            "Citrix/MetaFrame/auth/login.aspx", "images/ctxHeader01.jpg", "images/Safeword_Token.jpg",
            "sw/auth/login.aspx", "vpn/images/AccessGateway.ico",
            "citrix/AccessPlatform/auth/clientscripts", "AccessPlatform/auth/clientscripts",
            "Citrix//AccessPlatform/auth/clientscripts/cookies.js",
            "Citrix/AccessPlatform/auth/clientscripts/login.js", "Citrix/PNAgent/config.xml",
            "cgi-bin/image/shikaku2.png", "config/public/usergrp.gif", "pictures/buttons/file_view_mark.gif",
            "cpqlogin.htm", "hplogo.gif", "ie_index.htm", "ilo.gif", "images/icon_server_connected.gif",
            "mxhtml/images/signin_logo.gif", "mxhtml/images/status_critical_15.gif",
            "mxportal/home/en_US/servicetools.gif", "mxportal/home/MxPortalFrames.jsp", "xymon/menu/menu.css",
            "rrc.htm", "manager/html/upload", "manager/html", "axis2/axis2-web/HappyAxis.jsp", "axis2",
            "happyaxis.jsp", "web-console/ServerInfo.jsp", "web-console/Invoker", "invoker/JMXInvokerServlet",
            "invoker", "jmx-console", "admin-console", "CFIDE/administrator/enter.cfm",
            "CFIDE/administrator/entman/index.cfm", "cfide/install.cfm",
            "CFIDE/administrator/archives/index.cfm", "CFIDE/wizards/common/_logintowizard.cfm",
            "CFIDE/componentutils/login.cfm", "CFIDE/Administrator/startstop.html",
            "common/help/en/go/login_ts.html", "system/login", "system/login/reset",
            "common/images/logos/img_logoMain.jpg", "Dashboard/Dashboard.html", "flexfm",
            "lib/usermanagement/userInfo.php", "security/xamppsecurity.php", "system/console",
            "dm-albums/dm-albums.php", "ibm/console/logon.jsp", "console", "console/portal/0/Welcome",
            "rest/applinks/1.0/manifest", "jira/rest/applinks/1.0/manifest",
            "secure/rest/applinks/1.0/manifest", "rest/servicedeskapi/info",
            "jira/rest/servicedeskapi/info", "secure/rest/servicedeskapi/info",
            "confluence/rest/applinks/1.0/manifest", "wiki/rest/applinks/1.0/manifest",
            "bitbucket/rest/applinks/1.0/manifest", "bamboo/rest/applinks/1.0/manifest",
            "crowd/rest/applinks/1.0/manifest",
            "x_logo.gif", "gif/hp.gif", "gif/hp_invent_logo.gif", "gif/printer.gif",
            "hp/device/this.LCDispatcher", "hp/device/webAccess/index.htm", "PageSelector.class",
            "images/lexbold.gif", "images/lexlogo.gif", "images/printer.gif", "printer/image",
            "images/mute_alloff.gif", "images/pic_bri.gif", "scanweb/images/scanwebtm.gif",
            "view/index.shtml",
            "phpmyadmin", "phpMyAdmin", "PHPMyAdmin", "PMA", "pma", "dbadmin", "myadmin",
            "php-my-admin", "phpMyAdmin2", "phpMyAdmin-2", "phpMyAdmin-2.2.3", "phpMyAdmin-2.2.6",
            "phpMyAdmin-2.5.1", "phpMyAdmin-2.5.4", "phpMyAdmin-2.5.5-rc1", "phpMyAdmin-2.5.5-rc2",
            "phpMyAdmin-2.5.5", "phpMyAdmin-2.5.5-pl1", "phpMyAdmin-2.5.6-rc1",
            "phpMyAdmin-2.5.6-rc2", "phpMyAdmin-2.5.6", "phpMyAdmin-2.5.7", "phpMyAdmin-2.5.7-pl1",
            "phpMyAdmin-2.6.0-alpha", "phpMyAdmin-2.6.0-alpha2", "phpMyAdmin-2.6.0-beta1",
            "phpMyAdmin-2.6.0-beta2", "phpMyAdmin-2.6.0-rc1", "phpMyAdmin-2.6.0-rc2",
            "phpMyAdmin-2.6.0-rc3", "phpMyAdmin-2.6.0", "phpMyAdmin-2.6.0-pl1",
            "phpMyAdmin-2.6.0-pl2", "phpMyAdmin-2.6.0-pl3", "phpMyAdmin-2.6.1-rc1",
            "phpMyAdmin-2.6.1-rc2", "phpMyAdmin-2.6.1", "phpMyAdmin-2.6.1-pl1",
            "phpMyAdmin-2.6.1-pl2", "phpMyAdmin-2.6.1-pl3", "phpMyAdmin-2.6.2-rc1",
            "phpMyAdmin-2.6.2-beta1", "phpMyAdmin-2.6.2", "phpMyAdmin-2.6.2-pl1",
            "phpMyAdmin-2.6.3", "phpMyAdmin-2.6.3-rc1", "phpMyAdmin-2.6.3-pl1",
            "phpMyAdmin-2.6.4-rc1", "phpMyAdmin-2.6.4-pl1", "phpMyAdmin-2.6.4-pl2",
            "phpMyAdmin-2.6.4-pl3", "phpMyAdmin-2.6.4-pl4", "phpMyAdmin-2.6.4",
            "phpMyAdmin-2.7.0-beta1", "phpMyAdmin-2.7.0-rc1", "phpMyAdmin-2.7.0-pl1",
            "phpMyAdmin-2.7.0-pl2", "phpMyAdmin-2.7.0", "phpMyAdmin-2.8.0-beta1",
            "phpMyAdmin-2.8.0-rc1", "phpMyAdmin-2.8.0-rc2", "phpMyAdmin-2.8.0",
            "phpMyAdmin-2.8.0.1", "phpMyAdmin-2.8.0.2", "phpMyAdmin-2.8.0.3", "phpMyAdmin-2.8.0.4",
            "phpMyAdmin-2.8.1-rc1", "phpMyAdmin-2.8.1", "phpMyAdmin-2.8.2", "sqlmanager",
            "php-myadmin", "phpmy-admin", "mysqladmin", "mysql-admin", "websql", "_phpmyadmin",
            "footer1.gif", "homepage.nsf", "icons/ecblank.gif", "852566C90012664F", "admin4.nsf",
            "admin5.nsf", "admin.nsf", "agentrunner.nsf", "alog.nsf", "a_domlog.nsf", "bookmark.nsf",
            "busytime.nsf", "catalog.nsf", "certa.nsf", "certlog.nsf", "certsrv.nsf", "chatlog.nsf",
            "clbusy.nsf", "cldbdir.nsf", "clusta4.nsf", "collect4.nsf", "da.nsf", "dba4.nsf",
            "dclf.nsf", "DEASAppDesign.nsf", "DEASLog01.nsf", "DEASLog02.nsf", "DEASLog03.nsf",
            "DEASLog04.nsf", "DEASLog05.nsf", "DEASLog.nsf", "decsadm.nsf", "decslog.nsf",
            "DEESAdmin.nsf", "dirassist.nsf", "doladmin.nsf", "domadmin.nsf", "domcfg.nsf",
            "domguide.nsf", "domlog.nsf", "dspug.nsf", "events4.nsf", "events5.nsf", "events.nsf",
            "event.nsf", "iNotes/Forms5.nsf", "jotter.nsf", "leiadm.nsf", "leilog.nsf", "leivlt.nsf",
            "log4a.nsf", "log.nsf", "l_domlog.nsf", "mab.nsf", "mail10.box", "mail1.box", "mail2.box",
            "mail3.box", "mail4.box", "mail5.box", "mail6.box", "mail7.box", "mail8.box", "mail9.box",
            "mail.box", "msdwda.nsf", "mtatbls.nsf", "mtstore.nsf", "names.nsf", "nntppost.nsf",
            "nntp/nd000001.nsf", "nntp/nd000002.nsf", "nntp/nd000003.nsf", "ntsync45.nsf", "perweb.nsf",
            "qpadmin.nsf", "quickplace/quickplace/main.nsf", "reports.nsf", "sample/siregw46.nsf",
            "schema50.nsf", "setupweb.nsf", "setup.nsf", "smbcfg.nsf", "smconf.nsf", "smency.nsf",
            "smhelp.nsf", "smmsg.nsf", "smquar.nsf", "smsolar.nsf", "smtime.nsf", "smtpibwq.nsf",
            "smtpobwq.nsf", "smtp.box", "smtp.nsf", "smvlog.nsf", "srvnam.htm", "statmail.nsf",
            "statrep.nsf", "stauths.nsf", "stautht.nsf", "stconfig.nsf", "stconf.nsf", "stdnaset.nsf",
            "stdomino.nsf", "stlog.nsf", "streg.nsf", "stsrc.nsf", "userreg.nsf", "vpuserinfo.nsf",
            "webadmin.nsf", "web.nsf", ".nsf/../winnt/win.ini", "_api/version",
            "_layouts/images/helpicon.gif", "Pages/Default.aspx", "PublishingImages/NewsArticleImage.jpg",
            "_admin/operations.aspx", "_app_bin", "_controltemplates", "_layouts", "_layouts/viewlsts.aspx",
            "forms/allitems.aspx", "forms/webfldr.aspx", "forms/mod-view.aspx", "forms/my-sub.aspx",
            "pages/categoryresults.aspx", "categories/viewcategory.aspx", "sitedirectory", "editdocs.aspx",
            "workflowtasks/allitems.aspx", "lists/tasks", "categories/allcategories.aspx",
            "mycategories.aspx", "lists", "lists/allitems.aspx", "lists/default.aspx", "lists/allposts.aspx",
            "lists/archive.aspx", "lists/byauthor.aspx", "lists/calendar.aspx", "lists/mod-view.aspx",
            "lists/myposts.aspx", "lists/my-sub.aspx", "lists/allcomments.aspx", "lists/mycomments.aspx",
            "_layouts/userdisp.aspx", "_layouts/help.aspx", "_layouts/download.aspx",
            "projectserver/Home/HomePage.asp", "projectserver/images/branding.gif",
            "projectserver/images/pgHome.gif", "projectserver/images/pgTask.gif", "projectserver/Tasks/Taskspage.asp",
            "exchweb/bin/auth/owalogon.asp", "images/outlook.jpg", "owa/8.1.375.2/themes/base/lgntopl.gif", "owa",
            "tsweb", "reportserver",
            "sdk/../../../../../../../etc/vmware/hostd/vmInventory.xml",
            "../../../../../../../../../../etc/passwd", "../../../../../../../../../../boot.ini",
            ".htaccess", ".htpasswd", "_vti_bin", "_vti_cnf", "_vti_log", "_vti_pvt", "_vti_txt",
            "postinfo.html", "_vti_bin/_vti_aut/author.dll", "_vti_bin/_vti_aut/author.exe",
            "_vti_bin/_vti_aut/dvwssr.dll", "_vti_bin/_vti_adm/admin.dll", "_vti_bin/_vti_adm/admin.exe",
            "_vti_bin/fpcount.exe", "_vti_bin/shtml.dll", "_vti_bin/shtml.exe", "_vti_pvt/_x_todo.htm",
            "_vti_pvt/_x_todoh.htm", "_vti_pvt/access.cnf", "_vti_pvt/administrator.pwd",
            "_vti_pvt/administrators.pwd", "_vti_pvt/authors.pwd", "_vti_pvt/bots.cnf",
            "_vti_pvt/botinfs.cnf", "_vti_pvt/deptodoc.btr", "_vti_pvt/doctodep.btr", "_vti_pvt/frontpg.lck",
            "_vti_pvt/linkinfo.cnf", "_vti_pvt/service.cnf", "_vti_pvt/service.grp", "_vti_pvt/service.lck",
            "_vti_pvt/service.pwd", "_vti_pvt/Service.stp", "_vti_pvt/services.cnf", "_vti_pvt/services.org",
            "_vti_pvt/structure.cnf", "_vti_pvt/svcacl.cnf", "_vti_pvt/users.pwd", "_vti_pvt/uniqueperm.cnf",
            "_vti_pvt/writeto.cnf", ".svn", ".svn/text-base/.htaccess.svn-base",
            ".svn/text-base/.htpasswd.svn-base", ".svn/text-base/Web.config.svn-base", ".git/HEAD",
            ".hg/requires", ".bzr/README", "downloadFile.php", "BackupConfig.php",
            "cwhp/auditLog.do", "Info.live.htm", "CuteSoft_Client/CuteEditor/Load.ashx",
            "plugins/PluginController.php", "tiki-listmovies.php", "index.php",
            "d41d8cd98f00b204e9800998ecf8427e.php", "bsc_lan.php", "rom-0",
            "Telerik.Web.UI.DialogHandler.aspx", "Telerik.Web.UI.DialogHandler.ashx",
            "DesktopModules/Admin/RadEditorProvider/DialogHandler.aspx", "uir//etc/passwd",
            "uir//tmp/csman/0", "cgi-bin/export_debug_msg.exp", "cgi-bin/config.exp",
            "readme.html", "wp-includes/images/rss.png", "wp-includes/js/scriptaculous/sound.js",
            "wp-includes/js/jquery/suggest.js", "wp-includes/images/blank.gif",
            "wp-includes/js/comment-reply.js", "wp-includes/js/codepress/codepress.js",
            "wp-login.php", "wordpress/wp-login.php", "blog/wp-login.php", "administrator/wp-login.php",
            "weblog/wp-login.php", "wp-admin/upgrade.php", "docs", "store/docs", "zencart/docs",
            "cart/docs", "docs/CHANGELOG.html", "forum/docs/CHANGELOG.html", "forums/docs/CHANGELOG.html",
            "board/docs/CHANGELOG.html", "boards/docs/CHANGELOG.html", "changelog.txt",
            "tinymce/changelog.txt", "readme.html", "pligg/readme.html", "digg/readme.html",
            "news/readme.html", "cmspages.php", "sc_webcat/ecat/cms_view.php", "kbcat.cgi",
            "workorder/FileDownload.jsp", "sd/workorder/FileDownload.jsp", "sections/reference.inc.php",
            "store.php", "catalog/main.php", "index.php", "forum_answer.php", "templates1/view_product.php",
            "escort-profile.php", "pages/indexheader.php", "pages/searcher.php", "pages/indexviewentry.php",
            "tinymcpuk/filemanager/browser.html", "admin/libraries/ajaxfilemanager/ajaxfilemanager.php",
            "leftmenubody.php", "dsp_page.cfm", "zikula/index.php", "system/admin/header.php",
            "system/admin/comments_items.php", "scripts/fckeditor/editor/filemanager/connectors/test.html",
            "scripts/fckeditor/editor/filemanager/connectors/uploadtest.html",
            "fckeditor/editor/filemanager/connectors/test.html",
            "fckeditor/editor/filemanager/upload/test.html",
            "admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html",
            "fckeditor/editor/filemanager/connectors/php/config.php",
            "includes/FCKeditor/editor/filemanager/browser/default/connectors/php/connector.php",
            "includes/FCKeditor/editor/filemanager/browser/default/connectors/asp/connector.asp",
            "includes/FCKeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx",
            "includes/FCKeditor/editor/filemanager/browser/default/connectors/cfm/connector.cfm",
            "includes/FCKeditor/editor/filemanager/browser/default/connectors/lasso/connector.lasso",
            "includes/FCKeditor/editor/filemanager/browser/default/connectors/perl/connector.cgi",
            "includes/FCKeditor/editor/filemanager/browser/default/connectors/py/connector.py",
            "FCKEditor/editor/filemanager/browser/default/connectors/test.html",
            "admin/includes/tiny_mce/plugins/tinybrowser/upload.php",
            "Backstage/Components/FreeTextBox/ftb.imagegallery.aspx",
            "_plugin/fckeditor/editor/filemanager/connectors/test.html",
            "html/news_fckeditor/editor/filemanager/upload/php/upload.php",
            "fckeditor/editor/filemanager/connectors/test.html",
            "admin/includes/FCKeditor/editor/filemanager/upload/test.html", "uploadsnaps.php",
            "upload/includes/js/files/upload.php", "tinybrowser/upload.php",
            "editor/editor/filemanager/upload/test.html", "photogallery_open.php",
            "Providers/HtmlEditorProviders/Fck/fcklinkgallery.aspx", "assetmanager/assetmanager.asp",
            "Final/login/ava_upl.php", "Final/login/ava_upl2.php", "spaw/demo.php",
            "admin/jscript/upload.php", "admin/jscript/upload.html", "admin/jscript/upload.pl",
            "admin/jscript/upload.asp", "databases/acidcat_3.mdb", "mdb-database/dblog.mdb",
            "db/users.mdb", "db", "infusions/avatar_studio/avatar_studio.php", "bnnr.php",
            "vb/bnnr.php", "forum/bnnr.php", "weblink_cat_list.php", "UPGRADE.txt", "INSTALL.txt",
            "MAINTENERS.txt", "INSTALL.mysql.txt", "INSTALL.pgsql.txt", "update.php",
            "administrator/manifests/files/joomla.xml", "language/en-GB/en-GB.xml",
            "modules/custom.xml", "htaccess.txt", "templates/system/css/toolbar.css",
            "templates/beez/css/template_rtl.css", "CHANGELOG.txt", "pix/moodlelogo.gif",
            "admin/environment.xml", "typo3/index.php", "typo3/README.txt", "t3lib/README.txt",
            "typo3/sysext/t3skin/images/login/typo3logo-white-greyback.gif",
            "squirrelmail/src/login.php", "webmail/src/login.php", "src/login.php",
            "squirrelmail/images/sm_logo.png", "webmail/images/sm_logo.png", "program",
            "skins/default/images/roundcube_logo.png", "manifest.json", "archive/flash:home/html/images/Cisco_logo.gif",
            "Default?MAIN=DEVICE", "TopAccess/images/RioGrande/Rio_PPC.gif", "jwsappmngr.jnlp",
            "nfdesktop.jnlp", "nfservlets/servlet/SPSRouterServlet", "na_admin/styles/dfm.css",
            "lib/db/install.xml", "lib/thirdpartylibs.xml", "local/readme.txt", "README", "README.txt",
            "xoda/README", "docs/README", "documents/README", "dms/README", "status/README",
            "statusnet/README", "twitter/README", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r",
            "s", "t", "u", "v", "w", "x", "y", "z", "acceso", "access", "accesswatch", "acciones",
            "accounting", "active", "activex", "admcgi", "admisapi", "AdvWebAdmin", "agentes", "Agent",
            "Agents", "AlbumArt_", "AlbumArt", "Album", "allow", "analog", "anthill", "apache", "api-docs",
            "app", "applets", "appl", "application", "applications", "applmgr", "apply", "appsec",
            "apps", "archive", "archives", "ar", "asa", "asp", "atc", "aut", "authadmin", "author",
            "authors", "aw", "ayuda", "b2-include", "backend", "bad", "banca", "banco", "bank",
            "banner01", "banner", "banners", "bar", "batch", "bb-dnbd", "bbv", "bdata", "bdatos",
            "beta", "billpay", "bin", "binaries", "binary", "boadmin", "boot", "bottom", "browse",
            "browser", "bsd", "btauxdir", "bug", "bugs", "bugzilla", "buy", "buynow", "cached",
            "cache-stats", "caja", "card", "cards", "cart", "cash", "caspsamp", "catalog", "cbi-bin",
            "ccard", "ccards", "cd-cgi", "cd", "cdrom", "ce_html", "cert", "certificado", "certificate",
            "cfappman", "cfdocs", "cfide", "cgi-914", "cgi-915", "cgi-auth", "cgi-bin2", "cgibin",
            "cgi.cgi", "cgi-csc", "cgi-exe", "cgi-home", "cgi-lib", "cgilib", "cgi-local", "cgi-perl",
            "cgi-scripts", "cgiscripts", "cgis", "cgi-shl", "cgi-shop", "cgi-sys", "cgi-weddico",
            "cgi-win", "cgiwin", "class", "classes", "cliente", "clientes", "client", "clients", "cm",
            "cobalt-images", "code", "com", "comments", "common", "communicator", "company", "comp",
            "compra", "compras", "compressed", "conecta", "conf", "configs", "configure", "connect",
            "console", "contact", "contacts", "content", "content.ie5", "controlpanel", "core", "corp",
            "correo", "counter", "credit", "cron", "crons", "crypto", "CS", "csr", "css", "cuenta",
            "cuentas", "currency", "cust", "customer", "customers", "custom", "CVS", "cvsweb",
            "cybercash", "darkportal", "datafiles", "dat", "data", "dato", "datos", "dbase", "dcforum",
            "ddreport", "ddrint", "debugs", "default", "deleted", "delete", "demoauct", "demomall",
            "demos", "demouser", "deny", "derived", "design", "devel", "directories", "directory",
            "directorymanager", "dir", "dl", "dm", "DMR", "dms0", "dmsdump", "dnn", "doc1", "doc",
            "doc-html", "docs1", "DocuColor", "document", "dotnetnuke", "down", "durep", "easylog",
            "eforum", "ejemplo", "ejemplos", "emailclass", "email", "employees", "empoyees", "empris",
            "enter", "envia", "enviamail", "error.html", "error", "errors", "es", "estmt", "etcpasswd",
            "excel", "exc", "exchange", "exchweb", "exec", "exe", "exit", "export", "external",
            "extranet", "failure", "fbsd", "fcgi-bin", "fcgi", "features", "fileadmin", "file",
            "filemanager", "find", "flash", "foldoc", "foobar", "foo", "form", "formsmgr", "form-totaller",
            "foto", "fotos", "fpadmin", "fpclass", "fpdb", "fpe", "framesets", "frames", "frontpage",
            "ftp", "ftproot", "func", "function", "functions", "fun", "general", "gfx", "gif", "gifs",
            "global", "globals", "good", "graphics", "grocery", "guestbook", "guest", "guests", "GXApp",
            "HB", "HBTemplates", "helpdesk", "help", "hidden", "hide", "hitmatic", "hit_tracker",
            "hlstats", "hosted", "hostingcontroller", "hosting", "hp", "htbin", "htdocs", "ht", "htm",
            "http", "https", "hyperstat", "i18n", "ibank", "ibill", "IBMWebAS", "idea", "ideas", "I",
            "iisadmin", "image", "imagenes", "imagery", "imp", "import", "impreso", "inc", "include",
            "includes", "incoming", "index", "inet", "inf", "information", "in", "ingresa", "ingreso",
            "install", "internal", "internet", "intranet", "inventory", "invitado", "isapi", "j2ee",
            "japidoc", "java", "javascript", "javasdk", "javatest", "jave", "JBookIt", "jdbc", "job",
            "jrun", "jsa", "jscript", "jserv", "js", "jslib", "jsp", "junk", "kiva", "known", "labs",
            "lcgi", "lib", "libraries", "library", "libro", "license", "licenses", "links", "linux",
            "loader", "local", "location", "locations", "logfile", "logfiles", "logger", "logg",
            "logging", "logon", "logout", "lost+found", "mailman", "mailroot", "makefile", "manage",
            "man", "manual", "map", "maps", "marketing", "member", "mem_bin", "mem", "message",
            "messaging", "metacart", "microsoft", "misc", "mkstats", "mod", "module", "movimientos",
            "mpcgi", "mqseries", "msfpe", "ms", "msql", "Msword", "mxhtml", "mxportal", "my",
            "My Shared Folder", "mysql_admin", "name", "names", "ncadmin", "nchelp", "netbasic",
            "netcat", "NetDynamic", "NetDynamics", "net", "netmagstats", "netscape", "netshare",
            "nettracker", "network", "new", "News", "nextgeneration", "nl", "notes", "noticias",
            "NSearch", "objects", "odbc", "officescan", "ojspdemos", "old_files", "oldfiles",
            "oprocmgr-service", "oprocmgr-status", "oracle", "oradata", "order", "orders", "os", "out",
            "outgoing", "owners", "ows-bin", "page", "_pages", "partner", "passport", "password",
            "passwords", "path", "payment", "payments", "pccsmysqladm", "PDG_Cart", "perl5", "personal",
            "pforum", "phorum", "phpBB", "php_classes", "phpclassifieds", "phpimageview", "phpnuke",
            "phpPhotoAlbum", "phpprojekt", "phpSecurePages", "pics", "pike", "piranha", "pls", "plsql",
            "plssampleadmin_", "plssampleadmin", "plssampleadmin_help", "plssample", "poll", "polls",
            "porn", "portal", "portals", "postgres", "postnuke", "ppwb", "printer", "printers",
            "privacy", "privado", "_private", "priv", "prod", "projectserver", "protected", "proxy",
            "prueba", "pruebas", "prv", "pub", "_public", "publica", "publicar", "publico", "publish",
            "purchase", "purchases", "pw", "python", "random_banner", "rdp", "Readme", "recycler",
            "registered", "registry", "remote", "remove", "report", "reports", "reseller", "restricted",
            "retail", "reveal", "reviews", "ROADS", "robot", "robots", "root", "rsrc", "ruby", "sales",
            "save", "script", "ScriptLibrary", "scripts", "search", "search-ui", "sec", "secret",
            "secured", "secure", "sell", "server", "server-info", "servers", "server_stats",
            "serverstats", "server-status", "service", "servicio", "servicios", "servlet", "servlets",
            "session", "sharedtemplates", "share", "shell-cgi", "shipping", "shop", "shopper", "show",
            "SilverStream", "site", "sitemgr", "siteminderagent", "siteminder", "siteserver", "sites",
            "sitestats", "siteupdate", "smreports", "smreportsviewer", "soapdocs", "soap", "software",
            "solaris", "source", "sql", "squid", "src", "srchadm", "ssi", "ssl", "sslkeys", "staff",
            "state", "stat", "statistic", "statistics", "stats-bin-p", "stats_old", "status",
            "storage", "StoreDB", "storemgr", "stronghold-info", "stronghold-status", "stuff",
            "style", "styles", "stylesheet", "stylesheets", "subir", "sun", "super_stats", "supplier",
            "suppliers", "supply", "supporter", "support", "sysadmin", "sysbackup", "sys", "systems",
            "tar", "target", "tarjetas", "tech", "technote", "te_html", "temp", "template", "templates",
            "temporal", "test-cgi", "testing", "testweb", "themes", "ticket", "tickets", "tip", "tips",
            "ToDo", "tool", "TopAccess", "top", "tpv", "trabajo", "track", "tracking", "transfer",
            "transito", "transpolar", "tree", "trees", "trick", "tricks", "u02", "unix", "unknown",
            "updates", "upload", "uploads", "usage", "userdb", "us", "usr", "ustats", "usuario",
            "usuarios", "util", "utils", "vendor", "vfs", "view", "vpn", "vti_txt", "w2000", "w2k",
            "w3perl", "w-agora", "way-board", "web800fo", "webaccess", "webAdmin", "webalizer",
            "webapps", "WebBank", "webboard", "WebCalendar", "webcart", "webcart-lite", "webcgi",
            "webdata", "webdav", "webdb", "webDB", "web", "webimages2", "webimages", "web-inf",
            "webmaster", "webmaster_logs", "webMathematica", "webpub", "webpub-ui", "webreports",
            "webreps", "webshare", "WebShop", "website", "webstat", "webstats", "Web_store", "webtrace",
            "WebTrend", "webtrends", "web_usage", "win2k", "window", "windows", "win", "winnt", "word",
            "work", "world", "wsdocs", "WS_FTP", "wstats", "wusage", "www0", "www2", "www3", "www4",
            "wwwjoin", "wwwrooot", "www-sql", "wwwstat", "wwwstats", "xGB", "xml", "XSL", "xtemp",
            "xymon", "zb41", "zipfiles", "zip", "_docs",
            "sitecore/shell/sitecore.version.xml", "sitecore/login/default.aspx",
            "sitecore/admin/stats.aspx", "sitecore/admin/unlock_admin.aspx",
            "sitecore/shell/Applications/shell.xml", "sitecore/admin/ShowConfig.aspx",
            "App_Config/Security/Domains.config.xml", "App_Config/Security/GlobalRoles.config.xml",
            "sitecore%20modules/staging/service/api.asmx", "sitecore%20modules/staging/workdir",
            "sitecore/system/Settings/Security/Profiles"
        ]

    def load_wordlist(self, wordlist_source):
        paths = []
        if isinstance(wordlist_source, list):
            paths = [p.strip().lower() for p in wordlist_source if p.strip()]
        elif isinstance(wordlist_source, str) and os.path.isfile(wordlist_source):
            with open(wordlist_source, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [line.strip().lower() for line in f if line.strip()]
        elif isinstance(wordlist_source, str):
            paths = [p.strip().lower() for p in wordlist_source.split(',') if p.strip()]
        return sorted(list(set(paths)))
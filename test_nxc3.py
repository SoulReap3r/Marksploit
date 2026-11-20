#!/usr/bin/env python3
"""Offline regression tests for nxc3.

Fixtures reproduce the *format* of real nxc / tool output (the behaviour that
live runs against a lab verified) but use only sanitised placeholder data:
TEST-NET-1 IPs (192.0.2.0/24, RFC 5737), the public empty-password NT hash
(31d6cfe0d16ae931b73c59d7e0c089c0), and generic account names. No real
credentials, hashes or internal addresses are stored here.

No live boxes or third-party deps required:  python3 test_nxc3.py
"""
import importlib.util, io, re, sys
from contextlib import redirect_stdout

_SPEC = importlib.util.spec_from_file_location("nxc3_mod", "nxc3.py")
_SRC  = open(_SPEC.origin, encoding="utf-8").read()
_G = {"__name__": "nxc3_selftest"}           # avoid running __main__
exec(compile(_SRC, _SPEC.origin, "exec"), _G)
Nxc3           = _G["Nxc3"]
PORT_HINTS     = _G["PORT_HINTS"]
PROTOCOL_PORTS = _G["PROTOCOL_PORTS"]
privilege_label = _G["privilege_label"]
parse          = Nxc3._parse_nxc_findings
_ANSI          = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_EMPTY_NT      = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

_passed = _failed = 0
def check(name, cond, detail=""):
    global _passed, _failed
    if cond: _passed += 1; print(f"  PASS  {name}")
    else:    _failed += 1; print(f"  FAIL  {name}  {detail}")

# ── the exact GPP filter nxc3 applies in _cred_enum (kept in sync) ───────────
_GPP_RE = re.compile(r"(?i)\b(?:user(?:name)?s?|pass(?:word)?s?|cpassword|"
                     r"credential|accountname|runas|domains?)\b")
def gpp_filter(stdout):
    lines = [l for l in parse(stdout) if not set(l) <= set("- ")]
    return [l for l in lines if _GPP_RE.search(l)]

def shares_filter(stdout):                    # mirrors the "shares" branch
    lines = [l for l in parse(stdout) if not set(l) <= set("- ")]
    return [l for l in lines
            if not (l.split()[:1] == ["Share"] and "Permissions" in l)]

# ══ 1. LDAP enrichment lines parse to just the account names ═════════════════
dc_ldap = """LDAP        192.0.2.97  389    DC01             [*] Windows 10 / Server 2016 Build 14393 (name:DC01) (domain:corp.local) (signing:None)
LDAP        192.0.2.97  389    DC01             Administrator
LDAP        192.0.2.97  389    DC01             krbtgt
LDAP        192.0.2.97  389    DC01             svcadmin
LDAP        192.0.2.97  389    DC01             helpdesk"""
check("parse strips prefix+banner", parse(dc_ldap) == ["Administrator","krbtgt","svcadmin","helpdesk"],
      parse(dc_ldap))

# ══ 2. --shares output: header row dropped, 6 data rows ══════════════════════
dc_shares = """SMB         192.0.2.97  445    DC01             [*] Enumerated shares
SMB         192.0.2.97  445    DC01             Share           Permissions     Remark
SMB         192.0.2.97  445    DC01             -----           -----------     ------
SMB         192.0.2.97  445    DC01             ADMIN$                          Remote Admin
SMB         192.0.2.97  445    DC01             C$                              Default share
SMB         192.0.2.97  445    DC01             IPC$            READ            Remote IPC
SMB         192.0.2.97  445    DC01             NETLOGON        READ            Logon server share
SMB         192.0.2.97  445    DC01             SYSVOL          READ            Logon server share
SMB         192.0.2.97  445    DC01             test            READ"""
sh = shares_filter(dc_shares)
check("shares: header row dropped", not any(l.startswith("Share ") for l in sh), sh)
check("shares: 6 data rows", len(sh) == 6, f"got {len(sh)}: {sh}")

# ══ 3. admin SAM dump parses to credential rows, banner dropped ══════════════
sam = f"""SMB         192.0.2.95  445    SECURE           [*] Dumping SAM hashes
SMB         192.0.2.95  445    SECURE           Administrator:500:{_EMPTY_NT}:::
SMB         192.0.2.95  445    SECURE           Guest:501:{_EMPTY_NT}:::
SMB         192.0.2.95  445    SECURE           svc_app:1002:{_EMPTY_NT}:::"""
sam_hits = [l for l in parse(sam) if not set(l) <= set("- ")]
check("SAM: 3 hash rows, banner dropped", len(sam_hits) == 3 and all(":::" in l for l in sam_hits), sam_hits)

# ══ 4. GPP positive hits — BOTH modules (the plural-key bug fix) ═════════════
gpp_pass = """GPP_PASS... 192.0.2.97  445   DC01  [+] Found SYSVOL share
GPP_PASS... 192.0.2.97  445   DC01  [+] Found credentials in Groups.xml
GPP_PASS... 192.0.2.97  445   DC01  Password: Placeholder123
GPP_PASS... 192.0.2.97  445   DC01  userName: svc_backup
GPP_PASS... 192.0.2.97  445   DC01  changed: 2022-01-01
SMB         192.0.2.97  445   DC01  Share           Permissions     Remark
SMB         192.0.2.97  445   DC01  ADMIN$                          Remote Admin"""
gp = gpp_filter(gpp_pass)
check("GPP password: cred+user kept", "Password: Placeholder123" in gp and any("svc_backup" in l for l in gp), gp)
check("GPP password: share-table noise dropped", not any("ADMIN$" in l for l in gp), gp)

gpp_auto = """GPP_AUTO... 192.0.2.97  445   DC01  [+] Found credentials in Registry.xml
GPP_AUTO... 192.0.2.97  445   DC01  Usernames: ['Administrator']
GPP_AUTO... 192.0.2.97  445   DC01  Domains: ['CORP']
GPP_AUTO... 192.0.2.97  445   DC01  Passwords: ['Placeholder123']"""
ga = gpp_filter(gpp_auto)
check("GPP autologin: plural Usernames/Passwords kept (regression)",
      any("Usernames" in l for l in ga) and any("Passwords" in l for l in ga), ga)

gpp_miss = """GPP_PASS... 192.0.2.97  445   DC01  [+] Found SYSVOL share
GPP_PASS... 192.0.2.97  445   DC01  [*] Searching for potential XML files containing passwords
SMB         192.0.2.97  445   DC01  ADMIN$                          Remote Admin
SMB         192.0.2.97  445   DC01  SYSVOL          READ            Logon server share"""
check("GPP no-hit: empty (no false section)", gpp_filter(gpp_miss) == [], gpp_filter(gpp_miss))

# ══ 5. PRIME TARGETS: built-ins filtered, custom admins surfaced ════════════
def deleg_text(found):
    sc = Nxc3.__new__(Nxc3); sc.quiet = False
    buf = io.StringIO()
    with redirect_stdout(buf): sc._deleg_next_steps(found, "192.0.2.97", "corp.local")
    return _ANSI.sub("", buf.getvalue())

live = deleg_text({"adminCount=1 (protected)": ["Administrator","krbtgt","svcadmin","helpdesk"],
                   "MachineAccountQuota": ["MachineAccountQuota: 10"],
                   "unconstrained delegation": ["DC01$"]})
check("PRIME: custom admins flagged", "PRIME TARGETS" in live and "svcadmin, helpdesk" in live, live)
check("PRIME: built-ins excluded from target line",
      not re.search(r"PRIME TARGETS[^\n]*(Administrator|krbtgt)", live), live)
check("MAQ next-step present", "MachineAccountQuota=10" in live and "noPac" in live)
check("unconstrained deleg next-step present", "unconstrained delegation present" in live)

builtins_only = deleg_text({"adminCount=1 (protected)": ["Administrator","krbtgt","Guest"]})
check("PRIME: built-ins-only degrades gracefully",
      "only built-ins" in builtins_only and "PRIME TARGETS" not in builtins_only, builtins_only)

# ══ 6. port-hint dedupe: cracked SMB suppresses 139/445, keeps 8443 ══════════
class _S:  # minimal stand-in for Success
    def __init__(self, proto): self.protocol = proto
def surviving_hints(ports, successes):
    authed = {PROTOCOL_PORTS[s.protocol] for s in successes if s.protocol in PROTOCOL_PORTS}
    if any(s.protocol == "smb" for s in successes): authed |= {139, 445}
    return [p for p in ports if p in PORT_HINTS and p not in authed]
secure_ports = [135, 139, 445, 3389, 8443]
hints = surviving_hints(secure_ports, [_S("smb"), _S("rdp")])
check("hints: 445/139 suppressed when SMB authed", 445 not in hints and 139 not in hints, hints)
check("hints: 3389 suppressed when RDP authed", 3389 not in hints, hints)
check("hints: 8443 (uncracked web) retained", 8443 in hints, hints)

# ══ 7. honest privilege labels (the tool's headline feature) ════════════════
def lbl(is_guest, is_admin, is_dc, local): return privilege_label(is_guest, is_admin, is_dc, local)[1]
# admin on DC via DOMAIN cred => Domain Admin (the only case that earns that label)
check("label: admin+DC+domain => DOMAIN ADMIN", lbl(False, True, True, False) == "[DOMAIN ADMIN — admin on the DC!]")
# admin on DC but via LOCAL cred is only local admin of the DC, NOT domain admin
check("label: admin+DC+local => LOCAL ADMIN (not domain)", lbl(False, True, True, True) == "[LOCAL ADMIN — Pwn3d on this host]")
# admin on a member server (e.g. SECURE .95 with Eric) => local admin, never domain
check("label: admin on member => LOCAL ADMIN", lbl(False, True, False, False) == "[LOCAL ADMIN — Pwn3d on this host]")
# plain valid domain user (e.g. Eric on the DC .97) => just a user
check("label: non-admin domain => valid domain user", lbl(False, False, True, False) == "[valid — domain user]")
check("label: non-admin local => valid local user", lbl(False, False, False, True) == "[valid — local user]")
# guest mapping is not real auth and must win over any admin flag
check("label: guest wins over admin", lbl(True, True, True, False) == "[guest]")

# ══ 8. nmap greppable parse (two-stage -oG line) ═════════════════════════════
grep_line = ("Host: 192.0.2.95 ()\tPorts: 135/open/tcp//msrpc///, "
             "445/open/tcp//microsoft-ds///, 8443/open/tcp//ssl|https-alt//AppManager/\t")
parsed = Nxc3._parse_nmap_grep(grep_line)
check("nmap parse: finds 3 ports incl 8443", 8443 in parsed and 135 in parsed and 445 in parsed, parsed)

# ══ 9. recon-only host (non-nxc ports): renders ports+hints, no phantom SMB ═══
# A host whose only open port is non-nxc (e.g. DNS/53) used to render nothing,
# because the nmap deep-scan was gated behind the nxc-protocol probe. It must
# now surface the port + its hint, and must NOT fake an "SMB ... [*] <ip>" line.
TargetResult       = _G["TargetResult"]
print_target_block = _G["print_target_block"]
def block_text(**kw):
    r = TargetResult(target=kw.pop("target", "192.0.2.254"))
    for k, v in kw.items(): setattr(r, k, v)
    buf = io.StringIO()
    with redirect_stdout(buf): print_target_block(r, None, False)
    return _ANSI.sub("", buf.getvalue())

recon = block_text(nmap_ports=[(53, "domain", "")])          # open_protocols empty
check("recon-only: open-ports block rendered", "open ports (1)" in recon and "53/tcp" in recon, recon)
check("recon-only: DNS next-step hint shown", "zone transfer" in recon, recon)
check("recon-only: no phantom SMB identity line",
      not re.search(r"(?m)^SMB\s+192\.0\.2\.254", recon), recon)

# a host we actually protocol-scanned (nxc port open) still gets its identity
# echo — the fix must not over-suppress. nmap_ports present so it clears the
# "nothing to show" guard, exactly as a real SMB host does.
scanned = block_text(open_protocols=["smb"], nmap_ports=[(445, "microsoft-ds", "")],
                     hostname="HOST1", real_ip="192.0.2.50", target="192.0.2.50")
check("scanned host: identity echo retained", re.search(r"(?m)^SMB\s+192\.0\.2\.50", scanned), scanned)

# ══ 10. credentialed-enum must not render an nxc traceback as "shares" ═══════
# A failed --shares (broken pipe / access-denied mid-enum) makes nxc emit a Rich
# traceback with no prefix and no [*]/[-]/[+] marker — which once rendered as
# "shares (106)" of garbage. The noise filter must drop it; clean shares survive.
_is_nxc_noise = _G["_is_nxc_noise"]
_nxc_errored  = _G["_nxc_errored"]
def cred_shares_filter(stdout):
    lines = [l for l in parse(stdout)
             if not set(l) <= set("- ") and not _is_nxc_noise(l)]
    return [l for l in lines
            if not (l.split()[:1] == ["Share"] and "Permissions" in l)]

shares_err = """SMB  192.0.2.97  445  HOST  [06:29:26] ERROR    Exception while calling proto_flow()   connection.py:187
SMB  192.0.2.97  445  HOST  target 192.0.2.97: [Errno 32] Broken pipe
SMB  192.0.2.97  445  HOST  ╭── Traceback (most recent call last) ───╮
SMB  192.0.2.97  445  HOST  │ /usr/lib/python3/dist-packages/nxc/connection.py:177 │
SMB  192.0.2.97  445  HOST  │   177 │   self.proto_flow()                           │
SMB  192.0.2.97  445  HOST  ╰─────────────────────────────────────────────────────╯"""
check("cred-enum: nxc traceback filtered to nothing", cred_shares_filter(shares_err) == [],
      cred_shares_filter(shares_err))
check("cred-enum: hard error is detected (-> honest note, not silence)", _nxc_errored(shares_err))

good_shares = """SMB 192.0.2.97 445 HOST Share           Permissions     Remark
SMB 192.0.2.97 445 HOST -----           -----------     ------
SMB 192.0.2.97 445 HOST ADMIN$                          Remote Admin
SMB 192.0.2.97 445 HOST C$                              Default share
SMB 192.0.2.97 445 HOST IPC$            READ            Remote IPC"""
gs = cred_shares_filter(good_shares)
check("cred-enum: clean shares survive the noise filter (no false positives)",
      len(gs) == 3 and not _nxc_errored(good_shares), gs)

# ══ 11. AD-enrichment path applies the same noise filter (PRIME TARGETS safe) ═
# _run_delegation must not capture an nxc traceback as delegation/admin-count
# "findings" — that would poison PRIME TARGETS and the delegation next-steps.
deleg_err = """LDAP 192.0.2.97 389 DC01 [06:00:00] ERROR    LDAP bind failed    connection.py:187
LDAP 192.0.2.97 389 DC01 ╭── Traceback (most recent call last) ───────────╮
LDAP 192.0.2.97 389 DC01 │ /usr/lib/python3/dist-packages/nxc/protocols/ldap.py:300 │
LDAP 192.0.2.97 389 DC01 │ ❱ 300 │   self.find_delegation()                 │
LDAP 192.0.2.97 389 DC01 ╰────────────────────────────────────────────────╯"""
enrich = [h for h in parse(deleg_err) if not _is_nxc_noise(h)]
check("enrichment: traceback not captured as findings", enrich == [], enrich)
check("enrichment: hard error detected (not reported as 'none found')", _nxc_errored(deleg_err))

admincount = """LDAP 192.0.2.97 389 DC01 Administrator
LDAP 192.0.2.97 389 DC01 svcadmin
LDAP 192.0.2.97 389 DC01 helpdesk"""
ac = [h for h in parse(admincount) if not _is_nxc_noise(h)]
check("enrichment: clean admin-count names survive the filter",
      ac == ["Administrator", "svcadmin", "helpdesk"] and not _nxc_errored(admincount), ac)

# ══ 12. PORT_HINTS covers the common OSCP/PG services (recon completeness) ════
for p, kw in [(873, "rsync"), (1521, "oracle"), (5986, "winrm"),
              (11211, "memcached"), (27017, "mongo")]:
    check(f"PORT_HINTS has {p} ({kw})",
          p in PORT_HINTS and kw in PORT_HINTS[p].lower() and "{ip}" in PORT_HINTS[p],
          PORT_HINTS.get(p))

print(f"\n{_passed} passed, {_failed} failed")
sys.exit(1 if _failed else 0)

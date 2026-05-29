# marksploit

Credential spray and enumeration wrapper around [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec).

Tests credentials across SMB, SSH, LDAP, WinRM, RDP, WMI, MSSQL, FTP, VNC, and NFS. Surfaces hits with suggested follow-up commands and optionally writes a ready-to-run bash script.

**Enumeration only — never exploits.**

---

## Requirements

```bash
pip install netexec        # provides the nxc binary
python3 marksploit.py -h
```

---

## Quick Start

```bash
# Single host, single cred
python3 marksploit.py -t 192.168.1.10 -u admin -p 'Password123'

# CIDR range
python3 marksploit.py -t 192.168.1.0/24 -u james -p Toyota

# Users and passwords from files
python3 marksploit.py -t targets.txt -u users.txt -p passwords.txt

# Pass-the-Hash
python3 marksploit.py -t 192.168.1.10 -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Kerberos ticket cache
export KRB5CCNAME=/tmp/admin.ccache
python3 marksploit.py -t dc01.corp.local -u admin -k
```

---

## Spray Mode (Recommended for AD)

Standard mode hammers **all credentials against each target** before moving on — risky against Active Directory lockout policies.

**Spray mode** flips the loop: **one credential across all targets per round**, then optionally waits before the next round. Maximum one bad-password attempt per account per observation window.

```bash
# Safe AD spray — 30s gap between rounds (matches common 30-min lockout window)
python3 marksploit.py -t 192.168.1.0/24 -u users.txt -p passwords.txt \
    --spray --spray-delay 30

# No delay (only safe if lockout is disabled or you've confirmed the policy)
python3 marksploit.py -t targets.txt -u users.txt -p passwords.txt \
    --spray --spray-delay 0
```

> **Lockout warning:** marksploit will warn you if you queue more than 3 credentials without `--spray`. Set `--spray-delay` to match your target's observation window (usually 30–60 minutes for default AD policy).

---

## Auto Share Enumeration

`--auto-enum` runs `nxc smb --shares` automatically on any host with anonymous or guest access and folds the results into the output block.

```bash
python3 marksploit.py -t 172.16.1.0/24 -u guest -p '' --auto-enum
```

---

## Saving Output

| Flag | Description |
|------|-------------|
| `-S output.txt` | Plain-text copy of all output (ANSI stripped) |
| `--creds-file creds.tsv` | TSV of confirmed valid credentials |
| `--json-output results.json` | Full structured JSON results |
| `--script cmds.sh` | Ready-to-run bash script with all suggested commands |

The shell script is `chmod +x`'d automatically. Review it before running — it contains pre-filled impacket, evil-winrm, BloodHound, etc. commands based on what was found.

---

## Progress Display

marksploit keeps a live progress line on stderr while scanning. In normal parallel mode, the host bar shows how many targets have completed and the status shows the active target-worker count:

```text
███████░░░░░░░░░░░░░ 100/254 hosts  │ scanning with 3 target workers
```

For per-target protocol progress, run a single target worker:

```bash
python3 marksploit.py -t targets.txt -u users.txt -p passwords.txt --target-workers 1
```

That mode shows the host bar plus the protocol/scope currently being checked. The progress line is cleared before result blocks are printed so it does not get mixed into the formatted host output.

---

## Protocol Reference

| Protocol | Default Port | Notes |
|----------|-------------|-------|
| smb | 445 | Tested domain + local auth. Anonymous probe always runs. |
| ssh | 22 | Password only (hashes/kerberos not applicable) |
| ldap | 389 | AD attacks suggested on DC hits |
| ftp | 21 | Password only |
| wmi | 135 | Windows only |
| winrm | 5985 | Windows only |
| rdp | 3389 | Windows only |
| vnc | 5900 | Password only |
| mssql | 1433 | Windows auth |
| nfs | 2049 | Mount suggestions on hit |

Test a subset with `--protocols smb,winrm,rdp`.

---

## All Options

```
TARGET:
  -t TARGET         IP, hostname, CIDR, or file of targets

CREDENTIALS:
  -u USER           Username or file of usernames
  -p PASS           Password or file of passwords
  -H HASH           NTLM hash (LM:NT or NT-only), or file of hashes
  -k                Kerberos ticket cache ($KRB5CCNAME)

PROTOCOLS:
  --protocols LIST  Comma-separated subset (default: all)
  --no-port-probe   Skip TCP probe, test all protocols blindly
  --timeout-skip    Skip remaining protocols on a host that times out
  --max-cidr-hosts  Max hosts to expand from CIDR (default: 1024)

SPRAY MODE:
  --spray           Enable lockout-safe spray mode (creds-first loop)
  --spray-delay N   Seconds between rounds (default: 30, set 0 to disable)

OUTPUT:
  -o FILE           nxc raw log path (default: timestamp.txt)
  --creds-file FILE Append valid creds to TSV
  --json-output FILE Full JSON results
  -S FILE           Save formatted output (ANSI stripped)
  --script FILE     Write ready-to-run bash script

MISC:
  --auto-enum       Auto-run share enum on anon/guest hits
  -w N              Parallel workers per target (default: 15)
  --target-workers N
                    Parallel targets in normal mode (default: 3)
  -q                Quiet — suppress banner and next-steps
  -v                Verbose — show [-] failure lines
  --no-color        Disable ANSI colours
  --debug           Full Python tracebacks on errors
```

---

## Full Example (Dante/OSCP Lab)

```bash
python3 marksploit.py \
    -t 172.16.1.0/24 \
    -u users.txt \
    -p passwords.txt \
    --spray \
    --spray-delay 0 \
    --auto-enum \
    --timeout-skip \
    --protocols smb,winrm,rdp,ssh,ldap,mssql \
    --creds-file creds.tsv \
    --script followup.sh \
    -S scan_output.txt
```

After the scan, `followup.sh` contains pre-filled commands for every hit — secretsdump, evil-winrm, BloodHound, psexec, etc. Review and run selectively.

---

## Output Format

```
[*] marksploit  |  254 targets  3 users  3p / 0h  15 workers
[*] target workers: 3
[*] protocols: smb,winrm,rdp  timeout: 30s/attempt

────────────────────────────────────────────────────────────────

SMB   172.16.1.20   445   DANTE-DC01   [*] Windows Server 2012 R2 (domain:DANTE.local) [DC]

  [+] DANTE.local\james:Toyota   [SMB/domain/password]  [valid]

  [*] suggested next steps  DANTE-DC01 [DC]

  [SMB]
    # secretsdump -just-dc
    impacket-secretsdump -just-dc DANTE.local/james:Toyota@172.16.1.20

    # BloodHound
    bloodhound-python -u james -p Toyota -d DANTE.local -dc DANTE-DC01.DANTE.local ...
```

---

## License

For authorised security testing only.

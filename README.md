# nxc_plus

A credential-spray, enumeration **and pivot** wrapper around [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec).
Forked from nxc3 (spray/Kerberos/delegation base) with the nxc4 cherry-picks ported in.

**Enumeration only — never exploits.** Every attack step is *suggested*, you run it.

```bash
nxc_plus -t 192.168.1.0/24 -u admin -p 'Passw0rd!'      # scan, enum, loot, pivot
nxc_plus -t targets.txt -u users.txt -p pws.txt --spray # lockout-safe AD spray
nxc_plus -t 10.10.10.5                                   # no creds — recon only
```

## What it does

1. **Discover** — nmap service scan (per-host), or `--no-nmap` for the fast socket probe.
2. **Validate** — tests creds across smb/winrm/wmi/rdp/ldap/ssh/mssql; marks where you're admin (`Pwn3d!`).
3. **Enumerate** (auto, by access level):
   - any valid cred → `shares`, `users`, `pass-pol`, `logged-on users`
   - DC → `groups`, SYSVOL `gpp_password` / `gpp_autologin`
   - **local admin** → `--sam`, `--lsa` (+ plaintext/machine/DCC2 harvested from the secrets files), **`enum_interfaces`**
4. **Reuse** — sprays every looted credential (plaintext + NTLM) back across all hosts, reports only **NEW** access.
5. **Report** — credential matrix, **PIVOT SUBNETS** (dual-homed hosts → hidden networks), and **LOOT** with each hash type IDed and the exact crack/use command.

## Key features

| | |
|---|---|
| **Spray mode** | `--spray --spray-delay N` — one attempt per account per round, lockout-safe |
| **Pivot discovery** | `enum_interfaces` finds dual-homed boxes → flags the hidden subnet + tunnel command |
| **Plaintext loot** | follows nxc's `.secrets`/`.cached` files to pull cleartext creds `--lsa` only writes to disk |
| **Hash ID** | NTLM → pass-the-hash or `-m 1000`; DCC2 → `-m 2100`; AS-REP/Kerberoast → `-m 18200/13100` |
| **Credential reuse** | auto-spray looted creds across the range, new-access only |
| **Delegation enum** | kerberoastable / AS-REP / unconstrained / RBCD paths on the DC |
| **Kerberos / PtH** | `-k` (ccache), `-H` (NTLM hash) |

Loot is written to `./nxc_plus-loot/` (gitignored): `ntlm_hashes.txt`, `plaintext_creds.txt`, `dcc2.hash`.

## Install

```bash
ln -sf "$PWD/nxc_plus.py" ~/.local/bin/nxc_plus   # already on PATH on Kali
```

Requires `nmap` and `nxc` (NetExec) on PATH.

## OSCP note

Auto-run is enumeration + credential reads only. Coercion, relay, NTDS-via-exploit,
ADCS abuse, DCSync are **suggested, never executed** — keeps it clear of the
"no automated exploitation" rule.

# ADEnumToolkit

An educational Active Directory **enumeration & initial-recon** toolkit that
wraps standard, widely-documented techniques behind one clean CLI and finishes
with a **LinPEAS-style, colour-coded report** that explains each finding and
links to further reading.

> ⚠️ **For educational / authorized lab use only.**
> This project is a learning aid. Use it only against
> systems you own or are explicitly authorized to test (e.g. your own lab,
> [GOAD](https://github.com/Orange-Cyberdefense/GOAD), HackTheBox, TryHackMe).
> Unauthorized use against systems you do not control is illegal.

## What it does

It stitches together two well-known, freely available toolsets:

| Capability | Backed by | Subcommand |
|---|---|---|
| Validate credentials (incl. null/guest) | netexec | `check` |
| Enumerate domain users | netexec | `users` |
| Enumerate domain groups | netexec | `groups` |
| Enumerate SMB shares & permissions | netexec | `shares` |
| Dump domain password policy | netexec | `pass-pol` |
| RID brute forcing (works over null/guest) | netexec | `rid-brute` |
| Direct LDAP queries (users/groups/computers/SPNs/AS-REP) | impacket | `ldap` |
| Kerberoasting (request TGS hashes) | impacket `GetUserSPNs` | `kerberoast` |
| AS-REP roasting (request AS-REP hashes) | impacket `GetNPUsers` | `asreproast` |
| Known-vulnerability detection (SMB/LDAP) | netexec modules + impacket | `vulns` |
| Domain trusts & domain info | impacket LDAP | `ldap --what trusts domaininfo` |
| Writable objects (DACL analysis) | bloodyAD | `writable` |
| AD-integrated DNS dump (ADIDNS) | bloodyAD | `dns` |
| gMSA accounts & managed passwords | impacket LDAP + bloodyAD | `gmsa` |
| Full recon pass + report | all of the above | `all` |

### bloodyAD-style reads

Inspired by [this bloodyAD walkthrough](https://soyjoel.com/blog/bloodyad-comandos/).
These add capabilities the LDAP/SMB enumeration above does **not** already cover
(no duplicated commands):

```bash
# Objects your principal can modify (targeted Kerberoast, RBCD, shadow creds, ...)
./ADEnumToolkit.py writable -t 10.10.10.10 -d corp.local -u jdoe -p pass

# AD-integrated DNS records (internal network map; flags wildcard records)
./ADEnumToolkit.py dns -t 10.10.10.10 -d corp.local -u jdoe -p pass

# gMSA accounts, and read msDS-ManagedPassword where permitted
./ADEnumToolkit.py gmsa -t 10.10.10.10 -d corp.local -u jdoe -p pass

# Trusts and domain config are part of LDAP enumeration
./ADEnumToolkit.py ldap -t 10.10.10.10 -d corp.local -u jdoe -p pass --what trusts domaininfo
```

Extra flags: `--ldaps` (use LDAPS/636 instead of LDAP/389 — on `ldap`, `vulns`,
`gmsa`, `all`) and `--include-del` (also check deleted/related objects, on
`writable`).

Requires bloodyAD for `writable`/`dns`/`gmsa` password reads:
`pipx install bloodyAD` ([project](https://github.com/CravateRouge/bloodyAD)).
The `all` pass runs these automatically when bloodyAD is installed and
credentials are supplied.

### Vulnerability detection (`vulns`)

Detection only — nothing is exploited. It runs netexec's check-mode modules and
some standalone impacket checks, then reports each with a CVE reference:

| Check | Source | CVE / issue |
|---|---|---|
| EternalBlue | netexec `ms17-010` | CVE-2017-0144 |
| Zerologon | netexec `zerologon` | CVE-2020-1472 |
| noPac | netexec `nopac` | CVE-2021-42278/42287 |
| PetitPotam | netexec `petitpotam` | CVE-2021-36942 |
| PrintNightmare / Spooler | netexec `printnightmare`, `spooler` | CVE-2021-1675/34527 |
| SMBGhost | netexec `smbghost` | CVE-2020-0796 |
| LDAP signing / channel binding | netexec `ldap-checker` | NTLM relay to LDAP |
| MachineAccountQuota | netexec `maq` + impacket LDAP | noPac/RBCD prerequisite |
| SMB signing required? | standalone impacket | NTLM relay to SMB |
| SMBv1 enabled? | standalone impacket | EternalBlue surface |
| Anonymous LDAP bind? | standalone impacket | info disclosure |

```bash
# All vulnerability checks
./ADEnumToolkit.py vulns -t 10.10.10.10 -d corp.local -u jdoe -p pass

# Only specific checks (plus the impacket-only 'standalone' group)
./ADEnumToolkit.py vulns -t 10.10.10.10 --null --checks ms17-010 zerologon standalone
```

Add `--vuln-scan` to the `all` subcommand to include these checks in the full pass.

Every subcommand feeds its results into a central report. At the end of a run
the toolkit prints a severity-ranked summary (CRIT / HIGH / MED / INFO / OK)
with a short explanation and a reference link for each finding.

## Install

```bash
# Python dependency (LDAP client + Kerberos example scripts)
pip install -r requirements.txt

# External CLI tool (install separately, not via pip)
pipx install netexec
```

The toolkit auto-detects netexec whether it is installed as `nxc`, `netexec`
or `crackmapexec`, and finds impacket's scripts whether they are named
`GetUserSPNs.py` or `impacket-GetUserSPNs`.

## Authentication options

All subcommands share the same target/auth flags:

| Flag | Meaning |
|---|---|
| `-t, --dc-ip` | Domain Controller IP (required) |
| `-d, --domain` | Domain FQDN, e.g. `corp.local` |
| `-u, --username` | Username |
| `-p, --password` | Password (omit to be prompted securely) |
| `-H, --hashes` | NTLM hash for pass-the-hash (`LMHASH:NTHASH` or `:NTHASH`) |
| `--null` | Null / anonymous session (no credentials) |

Supported auth modes: **null session**, **guest** (`-u guest -p ''`),
**password**, and **pass-the-hash**.

## Usage

```bash
# Validate a set of credentials
./ADEnumToolkit.py check -t 10.10.10.10 -d corp.local -u jdoe -p 'Passw0rd!'

# Enumerate users with no credentials (null or guest)
./ADEnumToolkit.py users -t 10.10.10.10 --null
./ADEnumToolkit.py users -t 10.10.10.10 -u guest -p ''

# RID brute forcing when --users is blocked
./ADEnumToolkit.py rid-brute -t 10.10.10.10 --null --max-rid 5000

# Direct LDAP enumeration
./ADEnumToolkit.py ldap -t 10.10.10.10 -d corp.local -u jdoe -p pass --what all

# Kerberoasting / AS-REP roasting
./ADEnumToolkit.py kerberoast -t 10.10.10.10 -d corp.local -u jdoe -p pass -o tgs.txt
./ADEnumToolkit.py asreproast -t 10.10.10.10 -d corp.local -U users.txt -o asrep.txt

# Full recon pass with the LinPEAS-style report at the end
./ADEnumToolkit.py all -t 10.10.10.10 -d corp.local -u jdoe -p pass
```

Useful global flags: `--dry-run` (print commands without running them),
`--no-color`, `--no-report`, `--no-ask-password`.

## Quiet mode (firewalled / monitored labs)

Opt-in options to make noisy checks gentler on rate/volume-based detections and
firewalls. They are **additive** — the default loud behaviour is unchanged.

| Flag | Effect |
|---|---|
| `--delay SEC` | Fixed wait before **every** request (LDAP searches included) |
| `--jitter SEC` | Add a random `0..SEC` on top of `--delay` (irregular timing) |
| `--stealth` | Profile: sets delay/jitter if unset, caps RID range to 1500, prefers LDAPS, and skips exploit-signature vuln modules unless named |
| `--passive` (`vulns`) | Skip only the noisy vuln modules (no pacing changes) |
| `--request-user ACC` (`kerberoast`) | Request a single TGS instead of bulk-roasting every SPN |

What `--stealth` targets — the loudest parts of the toolkit:

- **RID brute forcing** → smaller range + spaced requests.
- **`vulns` exploit modules** (`ms17-010`, `zerologon`, `nopac`, `petitpotam`,
  `printnightmare`, `spooler`, `smbghost`) → skipped unless you name one; the
  benign checks (SMB signing, LDAP signing, MAQ, anon bind) still run.
- **Kerberoasting** → warns about the bulk-request burst; use `--request-user`.
- **LDAP** → prefers LDAPS (encrypted, defeats on-wire content inspection) and
  spaces out each search.

```bash
# Full pass, quiet
./ADEnumToolkit.py all -t 10.10.10.10 -d corp.local -u jdoe -p pass --stealth

# Custom pacing only
./ADEnumToolkit.py ldap -t 10.10.10.10 -d corp.local -u jdoe -p pass --what all \
    --delay 2 --jitter 3

# Vuln checks without the EDR-tripping modules
./ADEnumToolkit.py vulns -t 10.10.10.10 -d corp.local -u jdoe -p pass --passive
```

> Note: quiet mode reduces *volume/timing* signatures and prefers encrypted
> channels. It is **not** full opsec — authenticated LDAP/SMB/Kerberos activity
> is still logged on the DC. This is a learning aid, not an evasion framework.

## How cracking fits in

This toolkit only *collects* hashes; cracking is a separate offline step:

- Kerberoast TGS hashes → `hashcat -m 13100`
- AS-REP hashes → `hashcat -m 18200`

## Learning references

- The Hacker Recipes — Active Directory: https://www.thehacker.recipes/ad/
- HackTricks — AD methodology: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
- impacket: https://github.com/fortra/impacket
- NetExec: https://github.com/Pennyw0rth/NetExec

## Disclaimer

Provided for education and authorized testing only. The author assumes no
liability for misuse. You are responsible for complying with all applicable
laws and for having explicit permission before testing any environment.

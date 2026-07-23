#!/usr/bin/env python3
"""
CPTS-focused security checks for ADE — SMB signing, MachineAccountQuota,
and other exam-critical misconfigurations.
"""

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
        import re

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

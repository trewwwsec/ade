#!/usr/bin/env python3
"""
Credential verification for ADE.
"""

import subprocess
import sys
import re
from termcolor import colored

from .config import SECTION_ART, ASCII_ART_KERBEROS, ASCII_ART_KERBEROS_DETECTED
from .utils import print_status, print_header


def verify_credentials(r: str, u: str, p: str) -> str:
    """
    Verify credentials via SMB authentication check.
    
    Args:
        r: Target IP address
        u: Username to verify
        p: Password to verify
    
    Returns:
        str: Status of credential verification
            - "no-creds": No username/password provided
            - "ok": Credentials valid
            - "bad": Credentials invalid
            - "kerberos": Kerberos-only environment detected
            - "ambiguous": Unable to determine status
    
    Behavior:
        Runs silent nxc SMB check and interprets output:
        - STATUS_LOGON_FAILURE → "bad"
        - Authenticated/STATUS_SUCCESS → "ok"
        - STATUS_NOT_SUPPORTED/NTLM negotiation failed → "kerberos"
        - Empty or unclear output → "ambiguous"
    """
    print_header(SECTION_ART["credentials_check"])

    if u and p:
        print_status("\n[*] Verifying credentials and initializing kerberos check...")
        auth_opts = ["-u", u, "-p", p]
    else:
        print_status("\n[*] Checking for kerberos authentication...")
        auth_opts = ["-u", "", "-p", ""]

    # Run nxc smb check (silent)
    try:
        smb_cmd = ["nxc", "smb", r, "--shares"] + auth_opts
        result = subprocess.run(smb_cmd, capture_output=True, text=True, check=False)
        text = (result.stdout + result.stderr).strip()

        # Kerberos / negotiation hints in SMB output
        if re.search(r'STATUS_NOT_SUPPORTED|KDC_ERR|SPNEGO|NTLM negotiation failed', text, re.IGNORECASE):
            print_header(f"{ASCII_ART_KERBEROS}")
            print_header(f"{ASCII_ART_KERBEROS_DETECTED}")
            if not u.strip() or not p.strip():
                print_status("[-] Kerberos authentication requires valid credentials (-u and -p).")
                print_status("[-] Please rerun with:")
                print(colored("    python script.py -r <box-ip> -u <user> -p <password>", "yellow"))
                sys.exit(1)
            else:    
                return "kerberos"

        if not u or not p:
            print_status("[*] Kerberos not detected...")
            print_status("[-] No username and/or password detected... moving on with anonymous checks")
            return "no-creds"

        if not text:
            print_status("[-] No output from nxc smb probe; treating as ambiguous.")
            return "ambiguous"

        # explicit failures
        if re.search(r'STATUS_ACCESS_DENIED|STATUS_LOGON_FAILURE|NT_STATUS_LOGON_FAILURE|authentication failed', text, re.IGNORECASE):
            print_status("[-] Provided credentials failed SMB authentication.")
            return "bad"

        # explicit success markers
        if re.search(r'\[\+\]|Authenticated|STATUS_SUCCESS', text, re.IGNORECASE):
            print_status("[+] Credentials validated (SMB authentication succeeded).")
            return "ok"

        # ambiguous but non-empty output - show why
        print_status("[!] Credential verification returned ambiguous result.")
        print_status("[!] Reason: Output contained no clear success or failure indicators")
        print_status("[!] Output excerpt (first 200 chars):")
        print_status(f"    {text[:200]}")
        return "ambiguous"


    except Exception as e:
        print_status(f"[!] Exception during SMB credential probe: {e}")
        return "ambiguous"

#!/usr/bin/env python3
"""
SMB enumeration for ADE.
"""

import os
import shutil
import time

from termcolor import colored

from .config import SECTION_ART, USERS_FILE, get_output_path
from .utils import print_status, print_header, run_command
from .users import create_users_from_nxc


def _find_or_stage_ccache(username: str) -> str | None:
    """
    Locate the Kerberos cache where Impacket created it.

    If an output directory is configured, copy the cache there for operator
    convenience while preserving the original file as the authoritative source.
    """
    source_path = os.path.abspath(f"{username}.ccache")
    routed_path = os.path.abspath(get_output_path(f"{username}.ccache"))

    if os.path.exists(routed_path):
        return routed_path

    if not os.path.exists(source_path):
        return None

    if source_path == routed_path:
        return source_path

    try:
        os.makedirs(os.path.dirname(routed_path), exist_ok=True)
        shutil.copy2(source_path, routed_path)
        return routed_path
    except Exception as e:
        print_status(f"[!] Failed to copy Kerberos cache into output dir: {e}")
        return source_path


def smb_enum(r: str, f: str, d: str, u: str, p: str, k: bool) -> None:
    """
    Perform SMB share enumeration and user discovery.
    
    Args:
        r: Target IP address
        f: Fully qualified domain name of DC
        d: Domain name
        u: Username
        p: Password
        k: Boolean indicating if Kerberos authentication is enabled
    """
    print_header(SECTION_ART["smb_enumeration"])
    
    # Authenticated Path (u and p are set) 
    if u and p:
        print_status("\n[*] Running Authenticated checks...")
        
        if k and d:
            auth_opts = ["-u", u, "-p", p] 
        elif u and p:
            # Standard NTLM authentication (initial run or when k is False).
            auth_opts = ["-u", u, "-p", p]
        else:
            auth_opts = []
        
        # Kerberos Ticket/Connection Logic (for the second run)
        if k and f and d:
            ccache_file = os.path.abspath(get_output_path(f"{u}.ccache"))

            # Get Kerberos TGT FIRST (This tool requires the password, but FQDN positional argument is REMOVED)
            run_command(["getTGT.py", f"{d}/{u}:{p}", "-k", "-dc-ip", r], "Get Kerberos TGT with getTGT.py", timeout=60)

            # Wait briefly and verify the cache file exists before proceeding
            max_wait = 5  # seconds
            wait_interval = 0.5
            elapsed = 0
            active_ccache = None
            while active_ccache is None and elapsed < max_wait:
                active_ccache = _find_or_stage_ccache(u)
                if active_ccache is not None:
                    break
                time.sleep(wait_interval)
                elapsed += wait_interval
            
            if active_ccache is not None:
                os.environ["KRB5CCNAME"] = active_ccache
                print_status(f"[+] Found TGT cache {active_ccache} and exported KRB5CCNAME.")
                
                # Small additional delay to ensure file is fully written
                time.sleep(0.5)
                
                # NOW run NXC Kerberos Share Enumeration (using FQDN) with the ticket ready - with intelligent retry
                run_command(["nxc", "smb", f, "-u", u, "-p", p, "-k", "--shares"], 
                           "Enumerate SMB shares (Kerberos with nxc)", retry_on_invalid=True)
                
                cmd_str = f"KRB5CCNAME={active_ccache} smbclient.py -k {f}"
                print(colored(f"\nConnect to SMB using Kerberos ticket", 'blue'))
                print(colored(f"\n{'='*60}", 'yellow'))
                print(colored(f"  MANUAL SMB CONNECTION COMMAND", 'yellow'))
                print(colored(f"  {cmd_str}", 'yellow'))
                print(colored(f"{'='*60}", 'yellow'))                
                print_status("[*] Kerberos ticket is now active for this script's remaining commands.")
                print_status("[*] To use manually in your shell, run the command shown above.")
            else:
                print_status(f"[-] ERROR: Kerberos ticket file '{ccache_file}' not found after getTGT.py (waited {max_wait}s).")
            
            # Always try to refresh/merge usernames from RID brute (merge only adds new users)
            print_status(f"\n[*] Ensuring {USERS_FILE} is up-to-date via nxc RID-brute (may merge new names).")
            create_users_from_nxc(r, users_file=get_output_path(USERS_FILE), username=u, password=p, kerberos=True, fqdn=f)
        else:
            # NTLM/Kerberos Authenticated Checks (Uses IP address)
            run_command(["nxc", "smb", r] + auth_opts + ["--shares"], 
                       "Enumerate SMB shares (Authenticated)", retry_on_invalid=True)
            create_users_from_nxc(r, users_file=get_output_path(USERS_FILE), username=u, password=p)

    # Anonymous/Guest Path (ONLY runs if NO credentials were provided) 
    else:
        print_status("\n[*] Running initial Anonymous/Guest checks...")

        # Anonymous Shares (no extra quotes) - with intelligent retry
        run_command(["nxc", "smb", r, "-u", "anonymous", "-p", "", "--shares"],
                    "Enumerate SMB shares (Anonymous) ", retry_on_invalid=True)
        
        # Add delay between commands to avoid connection issues
        time.sleep(1)

        # Guest Shares - with intelligent retry
        run_command(["nxc", "smb", r, "-u", "guest", "-p", "", "--shares"],
                    "Enumerate SMB shares (Guest) ", retry_on_invalid=True)
        
        # Add delay before RID brute-force
        time.sleep(1)

        # RID Brute-Force to create user list 
        create_users_from_nxc(r, users_file=get_output_path(USERS_FILE))

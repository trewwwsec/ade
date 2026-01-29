#!/usr/bin/env python3
"""
SMB enumeration for ADE.
"""

import os
import time

from termcolor import colored

from .config import SECTION_ART, USERS_FILE
from .utils import print_status, print_header, run_command
from .users import create_users_from_nxc


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
            ccache_file = f"{u}.ccache"

            # Get Kerberos TGT FIRST (This tool requires the password, but FQDN positional argument is REMOVED)
            run_command(["getTGT.py", f"{d}/{u}:{p}", "-k", "-dc-ip", r], "Get Kerberos TGT with getTGT.py")

            # Wait briefly and verify the cache file exists before proceeding
            max_wait = 5  # seconds
            wait_interval = 0.5
            elapsed = 0
            while not os.path.exists(ccache_file) and elapsed < max_wait:
                time.sleep(wait_interval)
                elapsed += wait_interval
            
            if os.path.exists(ccache_file):
                os.environ["KRB5CCNAME"] = ccache_file
                print_status(f"[+] Found TGT cache {ccache_file} and exported KRB5CCNAME.")
                
                # Small additional delay to ensure file is fully written
                time.sleep(0.5)
                
                # NOW run NXC Kerberos Share Enumeration (using FQDN) with the ticket ready - with intelligent retry
                run_command(["nxc", "smb", f, "-u", u, "-p", p, "-k", "--shares"], 
                           "Enumerate SMB shares (Kerberos with nxc)", retry_on_invalid=True)
                
                cmd_str = f"KRB5CCNAME={ccache_file} smbclient.py -k {f}"
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
            create_users_from_nxc(r, username=u, password=p, kerberos=True, fqdn=f)
        else:
            # NTLM/Kerberos Authenticated Checks (Uses IP address)
            run_command(["nxc", "smb", r] + auth_opts + ["--shares"], 
                       "Enumerate SMB shares (Authenticated)", retry_on_invalid=True)
            create_users_from_nxc(r, username=u, password=p)

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
        create_users_from_nxc(r)

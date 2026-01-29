#!/usr/bin/env python3
"""
Post-exploitation collection modules for ADE - BloodHound, bloodyAD, Certipy.
"""

import time
from termcolor import colored

from .config import SECTION_ART
from .utils import print_status, print_header, run_command


def bloodhound(r: str, f: str, d: str, u: str, p: str, k: bool) -> None:
    """
    Run BloodHound data collector to gather AD information.
    
    Args:
        r: Target IP address
        f: Fully qualified domain name of DC
        d: Domain name
        u: Username
        p: Password
        k: Boolean indicating if Kerberos authentication is enabled
    """
    print_header(SECTION_ART["bloodhound"])

    kerberos_auth = ["-k"] if k else []
    
    # Introduce a retry loop
    max_retries = 2  # 1 initial attempt + 1 retry
    current_attempt = 1
    
    while current_attempt <= max_retries:
        print_status(f"[*] Running BloodHound collector (Attempt {current_attempt}/{max_retries})...")
        
        _, return_code = run_command(
            [
                "bloodhound-ce-python",
                "-d", d,
                "-u", u,
                "-p", p,
                "-dc", f,   
                "-ns", r,
                "--dns-timeout", "10",
                "-c", "all",
                "-op", u,
                *kerberos_auth,
                "--zip"
            ],
            "Run BloodHound collector",
            capture_output=True 
        )

        if return_code == 0:
            print_status("\n[+] BloodHound collector finished successfully.")
            return  # Exit the function on success
        
        # If it failed, check if we have more retries
        current_attempt += 1
        if current_attempt <= max_retries:
            print_status("[-] BloodHound collector failed. Retrying in 5 seconds...")
            time.sleep(5)
        
    # If the loop finishes without returning, all attempts failed
    print_status("\n[!!!] BLOODHOUND FAILURE DETECTED [!!!]")
    print_status(f"[-] All {max_retries} attempts failed.")
    print_status("[-] Check the output above for reasons like invalid credentials, DNS failure, or network block.")


def bloodyad(r: str, u: str, p: str, k: bool, d: str, f: str) -> None:
    """
    Check for writable AD objects using bloodyAD.
    
    Args:
        r: Target IP address (used for DC IP)
        u: Username
        p: Password
        k: Boolean indicating if Kerberos authentication is enabled
        d: Domain name
        f: Fully qualified domain name (used as host for Kerberos)
    """
    print_header(SECTION_ART["bloodyad"])

    # Define the Kerberos flag string to be added ONLY if 'k' is True
    kerberos_auth = "-k" if k else ""

    # Construct command, using FQDN (f) as the host for Kerberos and DC IP (r) for the DC-IP.
    # Note: bloodyAD often requires FQDN for the host argument when using Kerberos.
    cmd = f"bloodyAD -u {u} -p {p} {kerberos_auth} -d {d} --dc-ip {r} --host {f} get writable".strip()

    run_command(cmd, "Check for writable objects with bloodyAD", is_shell_command=True)


def adcs_certipy(r: str, f: str, d: str, u: str, p: str, k: bool) -> None:
    """
    Enumerate ADCS (Active Directory Certificate Services) vulnerabilities.
    
    Args:
        r: Target IP address
        f: Fully qualified domain name of DC
        d: Domain name
        u: Username
        p: Password
        k: Boolean indicating if Kerberos authentication is enabled
    """
    print_header(SECTION_ART["adcs"])

    auth_opts = ["-u", u, "-p", p]
    kerberos_flag_list = ["-k"] if k else []

    # NXC Check
    run_command(["nxc", "ldap", r] + auth_opts + kerberos_flag_list + ["-M", "adcs"], "Check for ADCS with nxc")

    # Certipy Find
    if k:
        # Kerberos Auth for Certipy
        certipy_cmd = ["certipy", "find", "-target", f, "-u", f"{u}@{d}", "-p", p, "-k", "-dc-ip", r, "-vulnerable", "-stdout", "-ldap-scheme", "ldap"]
        run_command(certipy_cmd, "Find vulnerable cert templates (Kerberos)")
    else:
        # NTLM Auth for Certipy (Also add -no-tls for consistency)
        certipy_cmd = ["certipy", "find", "-u", u, "-p", p, "-dc-ip", r, "-vulnerable", "-stdout", "-ldap-scheme", "ldap"]
        run_command(certipy_cmd, "Find vulnerable cert templates (NTLM)")

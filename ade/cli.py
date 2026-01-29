#!/usr/bin/env python3
"""
CLI module for ADE - argument parsing and main execution loop.
"""

import argparse
import sys
from termcolor import colored

from .config import (
    ASCII_ART_BANNER,
    ASCII_ART_FINISH,
    USERNAME_DEFAULT,
    PASSWORD_DEFAULT,
    USERS_FILE,
)
from .utils import print_status, print_header
from .dependencies import check_dependencies
from .host import check_host_nmap
from .discovery import domain_discovery
from .credentials import verify_credentials
from .ldap import ldap_enumeration
from .smb import smb_enum
from .attacks import user_spraying, kerberoasting
from .collection import bloodhound, bloodyad, adcs_certipy


def main():
    """Main entry point for ADE."""
    parser = argparse.ArgumentParser(
        description="Automated Active Directory Enumeration Script for Educational/Lab Use.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Example Usage:
 Basic: ade -r 10.10.10.161
 Auth:  ade -r 10.10.10.161 -u 'user' -p 'pass'
"""
    )
    # Core arguments
    parser.add_argument("-r", "--rhosts", help="Target DC IP Address (Required).", required=True)
    parser.add_argument("-d", "--domain", help="Domain name (e.g., CORP.LOCAL). Needed for most checks.")
    parser.add_argument("-f", "--fqdn", help="Fully Qualified Domain Name of DC (e.g., dc01.corp.local). Needed for Kerberos and Certipy.")
    # Standard credentials
    parser.add_argument("-u", "--username", default=USERNAME_DEFAULT, help="Username for authenticated scans.")
    parser.add_argument("-p", "--password", default=PASSWORD_DEFAULT, help="Password for authenticated scans.")


    args = parser.parse_args()

    args.kerberos = False

    # Rerun Loop Setup 
    run_authenticated_checks = True
    cred_status = "no-creds"

    while run_authenticated_checks:
        if not args.kerberos:
            # Print the colored ASCII Art
            print(colored("\n" + ASCII_ART_BANNER, "magenta"))
            print(colored(f"\n[CONFIG] Target IP:", "blue") + colored(f" {args.rhosts}", "white"))
            print(colored(f"[CONFIG] Domain:", "blue") + colored(f"    {args.domain or 'Not Provided. Script will attempt discovery.'}", "white"))
            print(colored(f"[CONFIG] FQDN:", "blue") + colored(f"      {args.fqdn or 'Not Provided. Script will attempt discovery.'}", "white"))
            print(colored(f"[CONFIG] User:", "blue") + colored(f"      {args.username or 'Anonymous/Guest'}", "white"))
            print(colored(f"[CONFIG] Password:", "blue") + colored(f"  {args.password or 'Not Provided'}", "white"))

        run_authenticated_checks = False
        if not args.kerberos:
            check_dependencies()

        # Check if host is up
        if not args.kerberos:
            if not check_host_nmap(args.rhosts):
                print_status(f"[!] Host Inactive")
                print_status(f"[-] Target IP {args.rhosts} did not respond to nmap scan.")
                print_status("[-] Please check the IP address and network connectivity.")
                sys.exit(1)

        # This discovers domain/fqdn
        if not args.kerberos:
            discovered_domain, discovered_fqdn = domain_discovery(args.rhosts)
            if discovered_domain:
                args.domain = discovered_domain
            if discovered_fqdn:
                args.fqdn = discovered_fqdn
            
        if not args.kerberos:
            cred_status = "no-creds"
            needs_rerun_from_creds = False
            cred_status = verify_credentials(args.rhosts, args.username, args.password)
            if args.username and args.password:
                if cred_status == "kerberos":
                    needs_rerun_from_creds = True
                elif cred_status == "bad":
                    print_status("\n[-] Stopping: invalid credentials supplied. \n[-] Fix credentials or rerun without them to continue anonymous checks.")
                    sys.exit(1)
                elif cred_status == "ambiguous":
                    print_status("\n[!] Credential verification ambiguous — proceeding but be cautious; you can rerun without creds for anonymous checks.")

            # Check required Kerberos and we're not already in Kerberos mode, restart
            if needs_rerun_from_creds and not args.kerberos and args.username and args.password:
                args.kerberos = True
                print_status("[*] Restarting enumeration with Kerberos enabled.")
                run_authenticated_checks = True
                continue 

        ldap_enumeration(args.rhosts, args.username, args.password, args.kerberos)

        # SMB Enumeration
        smb_enum(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)

        # User Spraying / AS-REP Roasting
        if args.domain:
            user_spraying(args.rhosts, args.domain, args.username, args.password, k=args.kerberos, cred_status=cred_status)
        else:
            print_status("\n[!] Skipping User Spraying (AS-REP Roasting), as it requires domain discovery.")

        # Authenticated-only follow-ups
        if not args.username or not args.password:
            print_status("\n[*] No credentials provided. Skipping authenticated checks.")
        elif not args.domain or not args.fqdn:
            print_status("\n[!] Skipping advanced authenticated checks, as they require discovered domain and fqdn.")
        else:
            # Kerberoasting (this can flip to Kerberos if NTLM fails later)
            rerun_kerberos = kerberoasting(
                args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos
            )

            if rerun_kerberos and not args.kerberos:
                args.kerberos = True
                run_authenticated_checks = True
                print_status("[*] Restarting Enumeration with Kerberos Enabled")
                continue

            # Continue with remaining authenticated tasks
            bloodhound(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)
            bloodyad(args.rhosts, args.username, args.password, args.kerberos, args.domain, args.fqdn)
            adcs_certipy(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)

    print_header(f"\n{ASCII_ART_FINISH}\n")


if __name__ == "__main__":
    main()

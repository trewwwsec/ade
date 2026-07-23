#!/usr/bin/env python3
"""
CLI module for ADE - argument parsing and main execution loop.
"""

import argparse
import datetime
import os
import sys
from termcolor import colored

from . import config
from .config import (
    ASCII_ART_BANNER,
    ASCII_ART_FINISH,
    USERNAME_DEFAULT,
    PASSWORD_DEFAULT,
    AVAILABLE_MODULES,
    module_enabled,
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
from .checks import smb_signing, machine_account_quota
from .summary import generate_summary


def _resolve_output_dir(args):
    """Resolve and store the output directory without creating it."""
    if args.output_dir:
        out_dir = args.output_dir
    else:
        date_str = datetime.datetime.now().strftime("%Y%m%d")
        out_dir = f"ade_{args.rhosts}_{date_str}"

    config.OUTPUT_DIR = os.path.abspath(out_dir)
    return config.OUTPUT_DIR


def _setup_modules(args):
    """Parse --modules / --skip and set config.ENABLED_MODULES."""
    if args.modules and args.skip:
        print_status("[-] Cannot use --modules and --skip together.")
        sys.exit(1)

    if args.modules:
        names = [n.strip() for n in args.modules.split(",") if n.strip()]
        for name in names:
            if name not in AVAILABLE_MODULES:
                print_status(f"[-] Unknown module: '{name}'. Available: {', '.join(AVAILABLE_MODULES)}")
                sys.exit(1)
        config.ENABLED_MODULES = set(names)
    elif args.skip:
        names = [n.strip() for n in args.skip.split(",") if n.strip()]
        for name in names:
            if name not in AVAILABLE_MODULES:
                print_status(f"[-] Unknown module: '{name}'. Available: {', '.join(AVAILABLE_MODULES)}")
                sys.exit(1)
        config.ENABLED_MODULES = set(AVAILABLE_MODULES) - set(names)
    else:
        config.ENABLED_MODULES = None


def _missing_module_requirements(module_name, args):
    """Return a list of unmet prerequisites for a module at its execution point."""
    if module_name == "asrep":
        return [] if args.domain else ["domain"]

    if module_name in {"kerberoast", "bloodhound", "bloodyad", "adcs"}:
        missing = []
        if not args.username or not args.password:
            missing.append("credentials")
        if not args.domain:
            missing.append("domain")
        if not args.fqdn:
            missing.append("fqdn")
        return missing

    if module_name == "maq":
        missing = []
        if not args.username or not args.password:
            missing.append("credentials")
        if not args.domain:
            missing.append("domain")
        return missing

    return []


def _report_module_skip(module_name, missing):
    """Emit a consistent skip message for a module with unmet prerequisites."""
    pretty = ", ".join(missing)
    print_status(f"[!] Skipping {module_name}: missing required {pretty}.")


def main():
    """Main entry point for ADE."""
    config.reset_runtime_state()

    try:
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
        parser.add_argument("-v", "--verbose", "--debug", dest="debug", action="store_true", help="Show raw tool output and write a verbose debug log.")
        parser.add_argument("-o", "--output-dir", default=None, help="Output directory for loot (default: ade_<IP>_<date>/).")
        parser.add_argument("--modules", default=None, help="Comma-separated list of modules to run.")
        parser.add_argument("--skip", default=None, help="Comma-separated list of modules to skip.")

        args = parser.parse_args()
        out_dir = _resolve_output_dir(args)
        _setup_modules(args)

        # Initialize Debug Mode
        if args.debug:
            config.DEBUG = True

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
                print(colored(f"[CONFIG] Output:", "blue") + colored(f"    {out_dir}", "white"))
                if config.ENABLED_MODULES is not None:
                    print(colored(f"[CONFIG] Modules:", "blue") + colored(f"   {', '.join(sorted(config.ENABLED_MODULES))}", "white"))

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

            if args.debug and config.DEBUG_LOG_FILE is None:
                from .utils import init_debug_log
                init_debug_log()
                print_status("[*] Debug mode enabled - verbose output will be logged to file")

            # This discovers domain/fqdn
            if not args.kerberos and module_enabled("discovery"):
                discovered_domain, discovered_fqdn = domain_discovery(args.rhosts)
                if discovered_domain:
                    args.domain = discovered_domain
                if discovered_fqdn:
                    args.fqdn = discovered_fqdn
                
            if not args.kerberos and module_enabled("creds"):
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

            if module_enabled("ldap"):
                ldap_enumeration(args.rhosts, args.username, args.password, args.kerberos)

            # SMB Enumeration
            if module_enabled("smb"):
                smb_enum(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)

            # User Spraying / AS-REP Roasting
            if module_enabled("asrep"):
                missing = _missing_module_requirements("asrep", args)
                if missing:
                    _report_module_skip("asrep", missing)
                else:
                    user_spraying(args.rhosts, args.domain, args.fqdn, args.username, args.password, k=args.kerberos, cred_status=cred_status)

            # Authenticated-only follow-ups
            if module_enabled("kerberoast"):
                missing = _missing_module_requirements("kerberoast", args)
                if missing:
                    _report_module_skip("kerberoast", missing)
                else:
                    rerun_kerberos = kerberoasting(
                        args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos
                    )

                    if rerun_kerberos and not args.kerberos:
                        args.kerberos = True
                        run_authenticated_checks = True
                        print_status("[*] Restarting Enumeration with Kerberos Enabled")
                        continue

            if module_enabled("bloodhound"):
                missing = _missing_module_requirements("bloodhound", args)
                if missing:
                    _report_module_skip("bloodhound", missing)
                else:
                    bloodhound(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)

            if module_enabled("bloodyad"):
                missing = _missing_module_requirements("bloodyad", args)
                if missing:
                    _report_module_skip("bloodyad", missing)
                else:
                    bloodyad(args.rhosts, args.username, args.password, args.kerberos, args.domain, args.fqdn)

            if module_enabled("adcs"):
                missing = _missing_module_requirements("adcs", args)
                if missing:
                    _report_module_skip("adcs", missing)
                else:
                    adcs_certipy(args.rhosts, args.fqdn, args.domain, args.username, args.password, args.kerberos)

            # CPTS-focused checks (no credential prerequisites for smb-signing)
            if module_enabled("smb-signing"):
                smb_signing(args.rhosts, args.username, args.password)

            if module_enabled("maq"):
                missing = _missing_module_requirements("maq", args)
                if missing:
                    _report_module_skip("maq", missing)
                else:
                    machine_account_quota(args.rhosts, args.username, args.password, args.domain, args.kerberos)

            # Findings summary — always runs last when enabled
            if module_enabled("summary"):
                generate_summary(
                    args.rhosts,
                    args.domain,
                    args.fqdn,
                    args.username,
                    args.kerberos,
                    out_dir,
                    cred_status,
                )

        print_header(f"\n{ASCII_ART_FINISH}\n")
    finally:
        config.reset_runtime_state()


if __name__ == "__main__":
    main()

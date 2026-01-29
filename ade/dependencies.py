#!/usr/bin/env python3
"""
Dependency checking for ADE.
"""

import shutil
import sys
from termcolor import colored

from .config import DEPENDENCIES, INSTALL_COMMANDS
from .utils import print_status, print_header


def check_dependencies() -> bool:
    """
    Check for required external tools and exit if any are missing.
    
    Required tools:
        - nmap: Network scanning
        - nxc (NetExec): SMB/LDAP enumeration
        - certipy: ADCS enumeration
        - bloodhound-ce-python: BloodHound data collection
        - bloodyAD: Permission checking
        - Impacket scripts: GetNPUsers.py, getTGT.py, GetUserSPNs.py
    
    Returns:
        bool: True if all dependencies are found
    
    Exits:
        Exits with code 1 if any dependencies are missing, printing installation instructions
    """
    print_header("\nChecking external dependencies")

    missing_tools = []
    missing_install_keys = set()  # Use a set to store unique install keys

    # Loop through all dependencies and check if they exist
    for command, (display_name, install_key) in DEPENDENCIES.items():
        if not shutil.which(command):
            missing_tools.append(display_name)
            missing_install_keys.add(install_key)

    # If anything is missing, print a detailed report and exit
    if missing_tools:
        print_status("\n[!] Dependencies Missing")
        for tool in sorted(missing_tools):
            print_status(f"[-] Missing: {tool}")

        if missing_install_keys:
            print_status("\n[*] To fix, please run the relevant command(s):")
            # Sort the keys to provide a consistent order
            for key in sorted(list(missing_install_keys)):
                command = INSTALL_COMMANDS.get(key)
                if command:
                    print(colored(f"    {command}", "yellow"))
        
        print_status("Make sure you use the install.sh script")
        sys.exit(1)
        
    print_status("[+] All dependencies found.")
    return True

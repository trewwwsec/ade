#!/usr/bin/env python3
"""
Domain discovery functionality for ADE.
"""

import re

from .config import SECTION_ART
from .utils import print_status, print_header, run_command
from .host import ensure_hosts_entry


def domain_discovery(r: str):
    """
    Performs anonymous LDAP enumeration to discover the domain and FQDN.

    This function runs an anonymous query against the target's LDAP service
    to automatically determine the domain controller's name and the domain it
    belongs to. If successful, it constructs the Fully Qualified Domain Name
    (FQDN) and calls `ensure_hosts_entry` to update the local /etc/hosts file.

    Args:
        r (str): The target IP address of the domain controller.

    Returns:
        tuple: A tuple containing (discovered_domain, discovered_fqdn).
            - discovered_domain (str or None): The discovered domain name
              (e.g., "corp.local"), or None if parsing fails.
            - discovered_fqdn (str or None): The discovered FQDN
              (e.g., "dc01.corp.local"), or None if parsing fails.
    """
    print_header(SECTION_ART["domain_discovery"])

    discovered_domain = None
    discovered_fqdn = None

    # Query LDAP anonymously to discover domain info 
    anon_user = ""
    anon_pass = ""
    nxc_list = ["nxc", "ldap", r, "-u", anon_user, "-p", anon_pass]
    nxc_output, _ = run_command(nxc_list, "Get domain name via anonymous LDAP", capture_output=True)

    if nxc_output and nxc_output.strip():
        match = re.search(r"\(name:(?P<name>[^)]+)\)\s*\(domain:(?P<domain>[^)]+)\)", nxc_output)
        if match:
            dc_name = match.group("name")
            discovered_domain = match.group("domain")
            discovered_fqdn = f"{dc_name}.{discovered_domain}"
            print_status(f"[+] Parsed FQDN: {discovered_fqdn}")
            ensure_hosts_entry(r, discovered_fqdn, discovered_domain)
        else:
            print_status("[!] Could not parse FQDN/Domain information from LDAP output.")
            
    else:
        print_status("[!] No LDAP response from anonymous query; skipping host mapping.")

    return discovered_domain, discovered_fqdn

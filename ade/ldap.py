#!/usr/bin/env python3
"""
LDAP enumeration for ADE.
"""

import shlex
import os

from .config import SECTION_ART, USERS_FILE
from .utils import print_status, print_header, run_command
from .users import update_users_file


def ldap_enumeration(r: str, u: str, p: str, k: bool) -> None:
    """
    Perform LDAP enumeration to discover domain information and usernames.
    
    Args:
        r: Target IP address
        u: Username (empty string for anonymous)
        p: Password (empty string for anonymous)
        k: Boolean indicating if Kerberos authentication should be used
    
    Actions:
        1. Anonymous LDAP query to discover domain/FQDN
        2. Extract user descriptions from LDAP
        3. Extract usernames and update users.txt file
    """
    print_header(SECTION_ART["ldap_enumeration"])

    # Enumerate user descriptions and collect usernames
    awk_script = r"""/description/{desc=substr($0,index($0,$6));valid=(desc!~/Built-in account for guest access to the computer\/domain/)} /sAMAccountName/&&valid{ if(!seen[$6]++){ printf "[+]Description: %-30s User: %s\n", desc, $6 } valid=0 }"""

    # Prepare shell-quoted creds for pipeline commands
    ldap_user_shell = shlex.quote(u) if u else "''"
    ldap_pass_shell = shlex.quote(p) if p else "''"
    auth_type = "Authenticated" if u and p else "Anonymous"

    # Dynamically add the Kerberos flag only if 'k' is True
    kerberos_opts = ["-k"] if k else []
    

    # Build the base command as a list first
    base_nxc_cmd_list = ["nxc", "ldap", r, "-u", ldap_user_shell, "-p", ldap_pass_shell] + kerberos_opts

    # Then join it into a string for the shell pipeline
    base_nxc_cmd_str = ' '.join(base_nxc_cmd_list)

    # Now build the final commands using the dynamic base string
    ldap_desc_cmd = f"{base_nxc_cmd_str} --query '(objectclass=user)' '' | awk '{awk_script}'"
    cmd_check_users = f"{base_nxc_cmd_str} --query '(objectclass=user)' '' | grep sAMAccountName | awk '{{print $6}}'"

   
    print_status("[*] Running LDAP description extraction.")
    output_desc, _ = run_command(ldap_desc_cmd, f"Check for linked description/sAMAccountName ({auth_type})", is_shell_command=True, capture_output=True)

    if not output_desc or not output_desc.strip():
        print_status("\n[*] No descriptions found in LDAP results.")

    print_status("\n[*] Running LDAP username extraction.")
    output_users, _ = run_command(cmd_check_users, f"Check for sAMAccountName ({auth_type})", is_shell_command=True, capture_output=True)

    if output_users and output_users.strip():
        raw_names = [n.strip() for n in output_users.splitlines() if n.strip()]
        seen_new = set()
        new_unique = []
        for n in raw_names:
            nl = n.lower()
            if nl in seen_new:
                continue
            seen_new.add(nl)
            new_unique.append(n)

        print_status(f"[+] Found unique usernames from LDAP.")
        update_users_file(new_unique, USERS_FILE, print_status)
    else:
        print_status("[*] No usernames discovered via LDAP username extraction.")

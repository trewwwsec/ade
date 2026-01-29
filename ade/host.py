#!/usr/bin/env python3
"""
Host checking and /etc/hosts management for ADE.
"""

import subprocess
import shlex
import re

from .utils import print_status, print_header, run_command


def check_host_nmap(r: str, use_pn_fallback: bool = True) -> bool:
    """
    Check if target host is active using nmap and ping.
    
    Args:
        r: Target IP address
        use_pn_fallback: Currently unused (kept for compatibility)
    
    Returns:
        bool: True if host is up, False otherwise
    
    Method:
        1. Try ICMP echo with nmap (-PE -sn -n)
        2. Fallback to direct ping if nmap doesn't confirm
    """
    print_header(f"Checking if host {r} is active with nmap")

    def run_nmap(args):
        result = subprocess.run(args, capture_output=True, text=True)
        return result.stdout.strip()

    # ICMP echo request with nmap
    command = ["sudo", "nmap", "-PE", "-sn", "-n", r]
    output = run_nmap(command)

    if re.search(r"Host is up.*latency", output, re.IGNORECASE):
        print_status(f"[+] Host {r} is active (nmap confirmed).")
        return True

    # Ping fallback
    ping = subprocess.run(["ping", "-c", "1", "-W", "2", r], capture_output=True, text=True)
    if "1 received" in ping.stdout or "bytes from" in ping.stdout:
        print_status(f"[+] Host {r} is active (confirmed via ping fallback).")
        return True
    
    return False


def ensure_hosts_entry(ip: str, fqdn: str, domain: str) -> bool:
    """
    Ensure /etc/hosts maps domain and FQDN to the correct IP.
    
    Args:
        ip: Target IP address
        fqdn: Fully qualified domain name (e.g., dc01.corp.local)
        domain: Domain name (e.g., corp.local)
    
    Returns:
        bool: True if modifications were made, False otherwise
    
    Behavior:
        - If domain maps to same IP: no change
        - If domain maps to different IP: remove old entry and add new one
        - If domain not present: add new entry
        - Always displays /etc/hosts content afterward
    """
    hosts_path = "/etc/hosts"
    domain_esc = re.escape(domain)
    

    # Read /etc/hosts (safe to read as non-root)
    try:
        with open(hosts_path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except Exception as e:
        print_status(f"[!] Unable to read {hosts_path}: {e}")
        return False

    # Find any existing mappings
    found_lines = []
    for ln in lines:
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            if domain.lower() in [p.lower() for p in parts[1:]]:
                found_lines.append((ln, parts[0]))

    modified = False

    # If any existing correct mapping found -> done
    for ln, mapped_ip in found_lines:
        if mapped_ip == ip:
            print_status(f"\n[*] Domain '{domain}' already mapped to {ip} in /etc/hosts (no change).")
            run_command("cat /etc/hosts", "Current /etc/hosts contents", is_shell_command=True)
            return False

    # If found with different IP -> remove them
    if found_lines:
        print_status(f"\n[!] Domain '{domain}' exists with different IP(s). Removing and updating mapping.")
        sed_pattern = rf"/\b{domain_esc}\b/Id"
        try:
            subprocess.run(["sudo", "sed", "-i", sed_pattern, hosts_path], check=False)
            modified = True
        except Exception as e:
            print_status(f"[!] Failed to remove old /etc/hosts entries: {e}")
            run_command("cat /etc/hosts", "Current /etc/hosts contents", is_shell_command=True)
            return False

    # Append new mapping if not already correct
    new_entry = f"{ip} {fqdn} {domain}"
    try:
        cmd = f"echo {shlex.quote(new_entry)} >> {shlex.quote(hosts_path)}"
        subprocess.run(["sudo", "sh", "-c", cmd], check=True)
        print_status(f"[+] Added new /etc/hosts entry: {new_entry}")
        modified = True
    except Exception as e:
        print_status(f"[!] Failed to append new entry: {e}")

    # Always show current /etc/hosts contents
    run_command("cat /etc/hosts", "Current /etc/hosts contents", is_shell_command=True)
    return modified

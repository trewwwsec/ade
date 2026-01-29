#!/usr/bin/env python3
"""
User file management and RID brute-force enumeration for ADE.
"""

import os
import re

from .config import USERS_FILE
from .utils import print_status, run_command


def update_users_file(new_unique: list, users_file: str, print_status_func) -> None:
    """
    Reads the existing users file, removes case-insensitive duplicates,
    merges in new_unique usernames (preserving first-seen case), and
    finally appends a lowercase version for every unique username.

    Args:
        new_unique (list): A list of case-preserved, unique usernames discovered from LDAP.
        users_file (str): The path to the file to be updated.
        print_status_func (function): The function used for logging status messages.
    """
    
    # Read existing users file and dedupe it preserving first-seen case/order
    existing_usernames = []
    seen_existing = set()
    file_exists = os.path.exists(users_file)
    file_had_dupes = False

    if file_exists:
        try:
            with open(users_file, "r", encoding="utf-8") as ef:
                for line in ef:
                    ln = line.strip()
                    if not ln:
                        continue
                    lnl = ln.lower()
                    if lnl in seen_existing:
                        file_had_dupes = True
                        continue
                    seen_existing.add(lnl)
                    existing_usernames.append(ln)
        except Exception as e:
            print_status_func(f"[-] Warning: failed to read existing {users_file}: {e}")
            existing_usernames = []
            seen_existing = set()
            file_exists = False  # Treat as non-existent on read failure

    # If the existing file had duplicates, rewrite it deduped first
    if file_had_dupes:
        try:
            with open(users_file, "w", encoding="utf-8") as ef:
                for name in existing_usernames:
                    ef.write(name + "\n")
            print_status_func(f"[+] Removed duplicates from existing {users_file} (rewrote file).")
        except Exception as e:
            print_status_func(f"[-] Warning: failed to rewrite {users_file} to remove duplicates: {e}")

    # Determine which new names to add (case-insensitive)
    to_add_originals = []
    for name in new_unique:
        if name.lower() not in seen_existing:
            to_add_originals.append(name)
            seen_existing.add(name.lower())  # mark as present so later names don't duplicate

    # Append only missing originals (if any)
    if to_add_originals:
        mode = "w" if not file_exists else "a"
        action = "Created" if not file_exists else "Appended"
        
        try:
            with open(users_file, mode, encoding="utf-8") as ef:
                for name in to_add_originals:
                    ef.write(name + "\n")
            
            print_status_func(f"[+] {action} new username(s) to {users_file}.")
        except Exception as e:
            print_status_func(f"[-] Error {action.lower()} to {users_file}: {e}")
    else:
        if not file_exists:
            print_status_func(f"[*] No new usernames to write; {users_file} not created.")
        else:
            print_status_func(f"[*] {users_file} already up-to-date. No originals added.")


    # Ensure every username has a lowercase entry (append missing lowercase lines only)
    try:
        # Re-read the file content after all original additions
        if os.path.exists(users_file):
            with open(users_file, "r", encoding="utf-8") as ef:
                lines = [ln.strip() for ln in ef if ln.strip()]
        else:
            # If we still don't have a file, there's nothing to lowercase
            return 

        exact_lines = set(lines)  # exact strings currently present
        
        # Dedupe case-insensitively while preserving order for finding unique names
        seen_lower = set()
        unique_by_lower = []
        for ln in lines:
            lnl = ln.lower()
            if lnl in seen_lower:
                continue
            seen_lower.add(lnl)
            unique_by_lower.append(ln)

        # Find lowercase forms missing as exact lines
        to_append = []
        for name in unique_by_lower:
            lower_name = name.lower()
            if lower_name not in exact_lines:
                to_append.append(lower_name)
                exact_lines.add(lower_name)  # mark as present for this run

        if to_append:
            with open(users_file, "a", encoding="utf-8") as ef:
                for ln in to_append:
                    ef.write(ln + "\n")
            print_status_func(f"[+] Appended lowercase name(s) to {users_file}.")
        else:
            print_status_func(f"[*] Lowercase entries already present in {users_file}. No changes made.")
            
    except Exception as e:
        print_status_func(f"[-] Error ensuring lowercase entries in {users_file}: {e}")


def create_users_from_nxc(
    r: str,
    users_file: str = USERS_FILE,
    debug_log: str = "nxc_rid_debug.log",
    username: str = None,
    password: str = None,
    kerberos: bool = False,
    fqdn: str = None,
) -> bool:
    """
    Perform RID brute-force to enumerate usernames and update users.txt.
    
    Args:
        r: Target IP address
        users_file: Path to output file for discovered usernames
        debug_log: Path to save raw nxc output for debugging
        username: Username for authenticated enumeration (None for anonymous)
        password: Password for authenticated enumeration (None for anonymous)
        kerberos: If True, use Kerberos authentication
        fqdn: Fully qualified domain name (required for Kerberos)
    
    Returns:
        bool: True if usernames were discovered and added, False otherwise
    
    Authentication priority:
        1. Kerberos (if kerberos=True and fqdn provided)
        2. Authenticated (if username/password provided)
        3. Anonymous, with Guest fallback
    
    Notes:
        - Brutes RIDs up to 5000
        - Case-preserving username deduplication
        - Updates users.txt via update_users_file()
    """
    abs_users = os.path.abspath(users_file)

    def parse_users(output):
        """Return a case-preserved, deduped list of usernames parsed from output."""
        candidates = []
        for line in (output or "").splitlines():
            if "SidTypeUser" not in line:
                continue
            # primary pattern: backslash then username then space + (SidTypeUser)
            m = re.search(r'\\([^\s\\(]+)\s*\(SidTypeUser\)', line)
            if m:
                candidates.append(m.group(1))
                continue
            # fallback: any token after last backslash
            if "\\" in line:
                part = line.rsplit("\\", 1)[-1].strip()
                if part:
                    candidates.append(part.split(None, 1)[0])
                    continue
            # final fallback: id: domain\user
            m2 = re.search(r'^\s*\d+:\s*[^\\\s]*\\([^\s(]+)', line)
            if m2:
                candidates.append(m2.group(1))

        # dedupe case-insensitively while preserving first-seen case
        seen_lower = set()
        unique_users = []
        for u in candidates:
            ul = u.lower()
            if ul in seen_lower:
                continue
            seen_lower.add(ul)
            unique_users.append(u)
        return unique_users

    # Helper to normalize run_command return to a string
    def normalize_result(result):
        if result is None:
            return ""
        if isinstance(result, tuple):
            return result[0] or ""
        if isinstance(result, str):
            return result
        if hasattr(result, "stdout"):
            return (result.stdout or "") + (getattr(result, "stderr", "") or "")
        try:
            return str(result)
        except Exception:
            return ""

    users = []
    output = ""

    # Kerberos mode
    if kerberos and fqdn:
        cmd = ["nxc", "smb", fqdn, "--rid-brute", "5000", "-k"]
        if username and password:
            cmd += ["-u", username, "-p", password]
        label = "RID Brute-Force (Kerberos)"
        print_status(f"[+] {label}")
        result = run_command(cmd, label, capture_output=True, retry_on_invalid=True)
        output = normalize_result(result)
        users = parse_users(output)

    # Authenticated mode
    elif username and password:
        cmd = ["nxc", "smb", r, "-u", username, "-p", password, "--rid-brute", "5000"]
        label = f"RID Brute-Force (Authenticated as {username})"
        print_status(f"[+] {label}")
        result = run_command(cmd, label, capture_output=True, retry_on_invalid=True)
        output = normalize_result(result)
        users = parse_users(output)

    # Anonymous/Guest mode
    else:
        # Try anonymous first
        print_status(f"\n[+] No credentials provided — attempting Anonymous RID brute")
        result = run_command(
            ["nxc", "smb", r, "-u", "anonymous", "-p", "", "--rid-brute", "5000"],
            "RID Brute-Force (Anonymous)",
            capture_output=True,
            retry_on_invalid=True
        )
        output = normalize_result(result)
        users = parse_users(output)

        # If anonymous found none, try guest fallback
        if not users:
            print_status(f"[!] Anonymous yielded no users — trying Guest fallback")
            result = run_command(
                ["nxc", "smb", r, "-u", "guest", "-p", "", "--rid-brute", "5000"],
                "RID Brute-Force (Guest)",
                capture_output=True,
                retry_on_invalid=True
            )
            output = normalize_result(result)
            users = parse_users(output)

    # Save raw output for debugging (last run's output)
    try:
        with open(debug_log, "w", encoding="utf-8") as dbg:
            dbg.write(output or "")
    except Exception:
        pass

    if not users:
        print_status("[!] No usernames parsed from nxc output.")
        print_status(f"[*] See {debug_log} for raw nxc output and adjust parser if needed.")
        return False

    # Merge/update existing users 
    update_users_file(users, users_file, print_status)

    return True

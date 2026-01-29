#!/usr/bin/env python3
"""
Password policy enumeration for ADE.
"""

import re
from termcolor import colored

from .config import SECTION_ART
from .utils import print_status, print_header, run_command


# Patterns to find anywhere in an output line
_MATCH_PATTERNS = [
    re.compile(r'\[\+\]'),                       # success token anywhere
    re.compile(r'\[\-\]'),                       # failure token anywhere
    re.compile(r'\[\!\]'),
    re.compile(r'STATUS_[A-Z_]+', re.IGNORECASE),# STATUS_ codes
    re.compile(r'Authenticated', re.IGNORECASE), # auth success word
    re.compile(r'Connection Error', re.IGNORECASE), # connection errors
]


def line_matches(line: str) -> bool:
    """Check if a line matches any of the output patterns."""
    for pat in _MATCH_PATTERNS:
        if pat.search(line):
            return True
    return False


def get_password_policy(r: str, u: str = None, p: str = None, k: bool = False) -> dict:
    """
    Retrieve and display domain password policy to prevent account lockouts.
    
    Args:
        r: Target IP address
        u: Username (None for anonymous)
        p: Password (None for anonymous)
        k: Boolean indicating if Kerberos authentication should be used
    
    Returns:
        dict: Password policy information with keys:
            - lockout_threshold: Number of failed attempts before lockout (0 = no lockout)
            - lockout_duration: Duration of lockout in minutes
            - lockout_observation_window: Time window for counting failed attempts
            - min_password_length: Minimum password length
            - password_history: Number of passwords remembered
            - max_password_age: Maximum password age in days
            - min_password_age: Minimum password age in days
            - password_complexity: Whether complexity is required
            - safe_to_spray: Boolean indicating if spraying is safe
        Returns None if policy cannot be retrieved.
    
    Behavior:
        - Uses nxc --pass-pol to retrieve password policy
        - Parses lockout settings and password requirements
        - Warns user if lockout threshold is low
        - Returns policy dict for use by spraying functions
    """
    print_header(SECTION_ART["password_policy"])

    # Build authentication options
    if u and p:
        auth_opts = ["-u", u, "-p", p]
        auth_type = "Authenticated"
    else:
        auth_opts = ["-u", "", "-p", ""]
        auth_type = "Anonymous"

    kerberos_opts = ["-k"] if k else []

    # Run nxc to get password policy
    cmd = ["nxc", "smb", r] + auth_opts + kerberos_opts + ["--pass-pol"]
    output, _ = run_command(cmd, f"Retrieve password policy ({auth_type})", capture_output=True)

    if not output or not output.strip():
        print_status("[!] Could not retrieve password policy.")
        return None

    # Parse the password policy output
    policy = {
        "lockout_threshold": None,
        "lockout_duration": None,
        "lockout_observation_window": None,
        "min_password_length": None,
        "password_history": None,
        "max_password_age": None,
        "min_password_age": None,
        "password_complexity": None,
        "safe_to_spray": True
    }

    # Common patterns in nxc --pass-pol output
    patterns = {
        "lockout_threshold": [
            r"Account Lockout Threshold:\s*(\d+)",
            r"Lockout Threshold:\s*(\d+)",
            r"lockoutThreshold:\s*(\d+)"
        ],
        "lockout_duration": [
            r"Account Lockout Duration:\s*(\d+)",
            r"Lockout Duration:\s*(\d+)",
            r"lockoutDuration:\s*(-?\d+)"
        ],
        "lockout_observation_window": [
            r"Lockout Observation Window:\s*(\d+)",
            r"Reset Account Lockout.*:\s*(\d+)",
            r"lockoutObservationWindow:\s*(-?\d+)"
        ],
        "min_password_length": [
            r"Minimum Password Length:\s*(\d+)",
            r"Min Password Length:\s*(\d+)",
            r"minPwdLength:\s*(\d+)"
        ],
        "password_history": [
            r"Password History Length:\s*(\d+)",
            r"Password History:\s*(\d+)",
            r"pwdHistoryLength:\s*(\d+)"
        ],
        "max_password_age": [
            r"Maximum Password Age:\s*(\d+)",
            r"Max Password Age:\s*(\d+)"
        ],
        "min_password_age": [
            r"Minimum Password Age:\s*(\d+)",
            r"Min Password Age:\s*(\d+)"
        ],
        "password_complexity": [
            r"Password Complexity:\s*(Enabled|Disabled|1|0)",
            r"Complexity:\s*(Enabled|Disabled|1|0)"
        ]
    }

    for key, pattern_list in patterns.items():
        for pattern in pattern_list:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                value = match.group(1)
                # Convert to int if numeric
                if value.isdigit() or (value.startswith('-') and value[1:].isdigit()):
                    policy[key] = int(value)
                elif value.lower() in ("enabled", "1"):
                    policy[key] = True
                elif value.lower() in ("disabled", "0"):
                    policy[key] = False
                else:
                    policy[key] = value
                break

    # Display parsed policy
    print_status("\n[*] Domain Password Policy:")
    print_status("=" * 50)
    
    lockout_threshold = policy.get("lockout_threshold")
    if lockout_threshold is not None:
        if lockout_threshold == 0:
            print_status(colored(f"    Account Lockout Threshold: {lockout_threshold} (No lockout - safe to spray!)", "green"))
        elif lockout_threshold <= 3:
            print_status(colored(f"    Account Lockout Threshold: {lockout_threshold} (DANGEROUS - very low!)", "red"))
            policy["safe_to_spray"] = False
        elif lockout_threshold <= 5:
            print_status(colored(f"    Account Lockout Threshold: {lockout_threshold} (Caution - low threshold)", "yellow"))
        else:
            print_status(colored(f"    Account Lockout Threshold: {lockout_threshold}", "white"))
    
    if policy.get("lockout_duration") is not None:
        duration = policy["lockout_duration"]
        if duration == -1 or duration == 0:
            print_status(f"    Lockout Duration: Permanent (admin unlock required)")
        else:
            print_status(f"    Lockout Duration: {duration} minutes")
    
    if policy.get("lockout_observation_window") is not None:
        window = policy["lockout_observation_window"]
        print_status(f"    Lockout Observation Window: {window} minutes")
    
    if policy.get("min_password_length") is not None:
        print_status(f"    Minimum Password Length: {policy['min_password_length']}")
    
    if policy.get("password_complexity") is not None:
        complexity = "Required" if policy["password_complexity"] else "Not Required"
        print_status(f"    Password Complexity: {complexity}")
    
    if policy.get("password_history") is not None:
        print_status(f"    Password History: {policy['password_history']} passwords remembered")
    
    if policy.get("max_password_age") is not None:
        print_status(f"    Maximum Password Age: {policy['max_password_age']} days")
    
    print_status("=" * 50)

    # Safety warnings
    if lockout_threshold is not None and lockout_threshold > 0 and lockout_threshold <= 3:
        print_status(colored("\n[!!!] WARNING: Very low lockout threshold detected!", "red"))
        print_status(colored("[!!!] Password spraying with user:user could lock out accounts!", "red"))
        print_status(colored("[!!!] Proceeding with extreme caution. Only 1 attempt per user.", "red"))
    elif lockout_threshold is not None and lockout_threshold > 0 and lockout_threshold <= 5:
        print_status(colored("\n[!] Caution: Low lockout threshold. Spraying will be conservative.", "yellow"))
    elif lockout_threshold == 0 or lockout_threshold is None:
        print_status(colored("\n[+] No account lockout policy or threshold is 0 - safe to spray.", "green"))

    return policy

#!/usr/bin/env python3
"""
Utility functions for ADE - output formatting and command execution.
"""

import subprocess
import time
import re
from termcolor import colored

from .config import TAG_COLORS


def print_status(message: str) -> None:
    """
    Prints a status message with colored tags.
    
    Supported tags: [+], [-], [!], [!!!], [*], [INFO]
    Only the tags are colored, not the entire message.
    """
    for tag, color in TAG_COLORS.items():
        if tag in message:
            message = message.replace(tag, colored(tag, color))
    print(f"{message}")


def print_header(title: str) -> None:
    """Prints a formatted section header in magenta."""
    print(colored(f"\n\n{title}", "magenta"))


def run_command(
    cmd_list_or_str,
    title: str,
    is_shell_command: bool = False,
    capture_output: bool = False,
    retry_on_empty: bool = False,
    retry_on_invalid: bool = False,
    max_retries: int = 2
):
    """
    Execute a command with optional intelligent retry logic.
    
    Args:
        cmd_list_or_str: Command as list (e.g., ["nxc", "smb", ip]) or string for shell commands
        title: Description printed before command execution
        is_shell_command: If True, execute as shell command (default: False)
        capture_output: If True, return (output, returncode) tuple (default: False)
        retry_on_empty: Retry if command returns completely empty output (default: False)
        retry_on_invalid: Retry if output is empty, too short, or lacks success indicators (default: False)
                         This is a superset of retry_on_empty - handles all empty cases plus validation
        max_retries: Maximum number of attempts (default: 2)
    
    Returns:
        If capture_output=True: tuple of (output_string, return_code)
        If capture_output=False: tuple of (None, return_code)
    
    Retry Logic (when retry_on_invalid=True):
        - Empty output → Retry
        - Output < 50 chars → Retry (suspiciously short)
        - No success indicators ([+], READ, WRITE, Authenticated, STATUS_SUCCESS, SidTypeUser) → Retry
        - After max_retries attempts, returns whatever output was received
    
    Examples:
        # Simple command, no retry
        run_command(["nmap", "-sV", target], "Port scan")
        
        # SMB command with intelligent retry
        run_command(["nxc", "smb", ip, "--shares"], "Enumerate shares", retry_on_invalid=True)
        
        # Capture output for parsing
        output, rc = run_command(["nxc", "smb", ip], "SMB check", capture_output=True, retry_on_invalid=True)
    """
    print(colored(f"\n{title}", "blue"))

    if isinstance(cmd_list_or_str, list):
        # Create display string with proper quoting for empty strings
        display_parts = []
        for part in cmd_list_or_str:
            if part == "":
                display_parts.append("''")
            elif " " in part:
                display_parts.append(f"'{part}'")
            else:
                display_parts.append(part)
        cmd_str = " ".join(display_parts)
    else:
        cmd_str = cmd_list_or_str

    print(colored(f"$ {cmd_str}", "white"))

    attempt = 0
    full_output = ""
    result = None
    
    # Success indicators for SMB commands (when retry_on_invalid is True)
    success_patterns = [
        r'\[\+\]',           # Success tag
        r'READ',             # Share permissions
        r'WRITE',            # Share permissions
        r'Authenticated',    # Auth success
        r'STATUS_SUCCESS',   # Explicit success
        r'SidTypeUser',      # RID brute results
    ]
    
    def colorize_tags(line):
        """Color only tags, not the whole line."""
        tag_patterns = {
            r"\[\+\]": colored("[+]", "green"),
            r"\[\-\]": colored("[-]", "red"),
            r"\[\!\]": colored("[!]", "red"),
            r"\[!!!\]": colored("[!!!]", "red"),
            r"\[\*\]": colored("[*]", "blue"),
            r"\[INFO\]": colored("[INFO]", "blue"),
        }
        for pattern, repl in tag_patterns.items():
            line = re.sub(pattern, repl, line)
        return line

    while attempt < max_retries:
        if attempt > 0:
            print_status(f"[*] Retry attempt {attempt + 1}/{max_retries} (waiting 2 seconds)...")
            time.sleep(2)  # Wait before retry
        
        result = subprocess.run(
            cmd_list_or_str,
            shell=is_shell_command,
            capture_output=True,
            text=True,
            check=False  # Prevent crash on failure
        )

        full_output = result.stdout + result.stderr

        # Only print output on first attempt or if it's the last attempt
        if attempt == 0 or attempt == max_retries - 1:
            for line in full_output.splitlines():
                print(colorize_tags(line))

        # Check if we should retry
        should_retry = False
        
        # Check for empty output
        if retry_on_empty and not full_output.strip() and attempt < max_retries - 1:
            should_retry = True
            print_status("[!] Command returned empty output, retrying...")
        
        # Check for invalid/incomplete output (also checks for empty if retry_on_invalid is True)
        if retry_on_invalid and attempt < max_retries - 1:
            # Empty output is also invalid
            if not full_output.strip():
                should_retry = True
                print_status("[!] Command returned empty output, retrying...")
            else:
                has_success_indicator = any(re.search(pattern, full_output, re.IGNORECASE) for pattern in success_patterns)
                
                # Check if output is suspiciously short (less than 50 chars, likely incomplete)
                is_too_short = len(full_output.strip()) < 50
                
                # If no success indicators, the output might be wrong/incomplete
                # OR if the output is suspiciously short
                if not has_success_indicator or is_too_short:
                    should_retry = True
                    if is_too_short:
                        print_status(f"[!] Command output suspiciously short ({len(full_output.strip())} chars), retrying...")
                    else:
                        print_status("[!] Command output appears incomplete (no success indicators), retrying...")
        
        if should_retry:
            attempt += 1
            continue
        
        # Success or final attempt - break the loop
        break
    
    if capture_output:
        return full_output, result.returncode
    else:
        return None, result.returncode

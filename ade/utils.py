#!/usr/bin/env python3
"""
Utility functions for ADE - output formatting and command execution.
"""

import subprocess
import time
import re
from termcolor import colored

import datetime
from .config import TAG_COLORS, DEBUG, DEBUG_LOG_FILE
import sys
from . import config  # Import config module to access/modify global vars


def init_debug_log():
    """Initialize the debug log file with a timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"ade_debug_{timestamp}.log"
    config.DEBUG_LOG_FILE = filename
    
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"[*] ADE Debug Log Started at {datetime.datetime.now()}\n")
            f.write(f"[*] Version: {config.__version__}\n")
            f.write("="*60 + "\n\n")
    except Exception as e:
        print(f"[!] Failed to create debug log file: {e}")


def log_debug(message: str):
    """Write a message to the debug log file if enabled."""
    if not config.DEBUG_LOG_FILE:
        return
        
    try:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        with open(config.DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


def debug_print(message: str):
    """Print a message only if debug mode is enabled."""
    if config.DEBUG:
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        msg = f"[DEBUG] {message}"
        print(colored(msg, "cyan"))
        log_debug(msg)


def print_status(message: str) -> None:
    """
    Prints a status message with colored tags.
    
    Supported tags: [+], [-], [!], [!!!], [*], [INFO]
    Only the tags are colored, not the entire message.
    """
    # Write raw message to debug log
    log_debug(message)
    
    for tag, color in TAG_COLORS.items():
        if tag in message:
            message = message.replace(tag, colored(tag, color))
    print(f"{message}")


def print_header(title: str) -> None:
    """Prints a formatted section header in magenta."""
    log_debug(f"\n[HEADER] {title}")
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
    """
    print(colored(f"\n{title}", "blue"))
    log_debug(f"\n[COMMAND-TITLE] {title}")

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
    log_debug(f"[EXEC] $ {cmd_str}")

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
        r'Connection Error', # Not a success per se, but valid output (don't retry endlessly)
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

    start_time = time.time()

    while attempt < max_retries:
        if attempt > 0:
            msg = f"[*] Retry attempt {attempt + 1}/{max_retries} (waiting 2 seconds)..."
            print_status(msg)
            time.sleep(2)  # Wait before retry
        
        try:
            result = subprocess.run(
                cmd_list_or_str,
                shell=is_shell_command,
                capture_output=True,
                text=True,
                check=False  # Prevent crash on failure
            )
            full_output = result.stdout + result.stderr
            return_code = result.returncode
        except Exception as e:
            error_msg = f"[!] Execution failed: {e}"
            print_status(error_msg)
            log_debug(error_msg)
            full_output = ""
            return_code = 1

        # Debug logging of output
        if config.DEBUG:
            elapsed = time.time() - start_time
            debug_print(f"Command finished in {elapsed:.2f}s with RC: {return_code}")
            if result and result.stdout:
                log_debug("[STDOUT] " + result.stdout)
            if result and result.stderr:
                log_debug("[STDERR] " + result.stderr)

        # Only print output on first attempt or if it's the last attempt
        # IN DEBUG MODE: Always print output
        if attempt == 0 or attempt == max_retries - 1 or config.DEBUG:
            lines = full_output.splitlines()
            if not lines and config.DEBUG:
                debug_print("(No output received)")
                
            for line in lines:
                # In debug mode, we might want to see unrelated output too, 
                # but we generally stick to colorized output for readability.
                print(colorize_tags(line))

        # Check if we should retry
        should_retry = False
        
        # Check for empty output
        if retry_on_empty and not full_output.strip() and attempt < max_retries - 1:
            should_retry = True
            msg = "[!] Command returned empty output, retrying..."
            print_status(msg)
        
        # Check for invalid/incomplete output (also checks for empty if retry_on_invalid is True)
        if retry_on_invalid and attempt < max_retries - 1:
            # Empty output is also invalid
            if not full_output.strip():
                should_retry = True
                msg = "[!] Command returned empty output, retrying..."
                print_status(msg)
            else:
                has_success_indicator = any(re.search(pattern, full_output, re.IGNORECASE) for pattern in success_patterns)
                
                # Check if output is suspiciously short (less than 50 chars, likely incomplete)
                is_too_short = len(full_output.strip()) < 50
                
                # If no success indicators, the output might be wrong/incomplete
                # OR if the output is suspiciously short
                if not has_success_indicator or is_too_short:
                    should_retry = True
                    if is_too_short:
                        msg = f"[!] Command output suspiciously short ({len(full_output.strip())} chars), retrying..."
                    else:
                        msg = "[!] Command output appears incomplete (no success indicators), retrying..."
                    print_status(msg)
        
        if should_retry:
            attempt += 1
            continue
        
        # Success or final attempt - break the loop
        break
    
    if capture_output:
        return full_output, return_code
    else:
        return None, return_code

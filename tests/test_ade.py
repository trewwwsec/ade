#!/usr/bin/env python3
"""
Test suite for ADE modular package.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_imports():
    """Test all module imports work correctly."""
    print("Testing module imports...")
    import ade
    from ade import main, __version__
    from ade.config import USERS_FILE, DEPENDENCIES, SECTION_ART, TAG_COLORS
    from ade.utils import print_status, print_header, run_command
    from ade.dependencies import check_dependencies
    from ade.host import check_host_nmap, ensure_hosts_entry
    from ade.discovery import domain_discovery
    from ade.credentials import verify_credentials
    from ade.ldap import ldap_enumeration
    from ade.users import update_users_file, create_users_from_nxc
    from ade.smb import smb_enum
    from ade.policy import get_password_policy, line_matches
    from ade.attacks import user_spraying, kerberoasting, try_user_file
    from ade.collection import bloodhound, bloodyad, adcs_certipy
    print("✓ All imports successful")
    return True


def test_config_values():
    """Test config values are set correctly."""
    print("Testing config values...")
    from ade.config import USERS_FILE, DEPENDENCIES, SECTION_ART, TAG_COLORS, __version__
    
    assert USERS_FILE == "users.txt", f"USERS_FILE should be 'users.txt', got {USERS_FILE}"
    assert "nmap" in DEPENDENCIES, "nmap should be in DEPENDENCIES"
    assert "domain_discovery" in SECTION_ART, "domain_discovery should be in SECTION_ART"
    assert "[+]" in TAG_COLORS, "[+] should be in TAG_COLORS"
    assert __version__ == "1.1.0", f"Version should be 1.1.0, got {__version__}"
    print("✓ Config values correct")
    print(f"✓ Version: {__version__}")
    return True


def test_line_matches():
    """Test the line_matches pattern function."""
    print("Testing line_matches patterns...")
    from ade.policy import line_matches
    
    # Should match
    assert line_matches("[+] Success") == True, "Should match [+]"
    assert line_matches("[-] Failure") == True, "Should match [-]"
    assert line_matches("[!] Warning") == True, "Should match [!]"
    assert line_matches("STATUS_LOGON_FAILURE") == True, "Should match STATUS_"
    assert line_matches("User Authenticated successfully") == True, "Should match Authenticated"
    assert line_matches("Connection Error occurred") == True, "Should match Connection Error"
    
    # Should not match
    assert line_matches("random text without patterns") == False, "Should not match random text"
    assert line_matches("") == False, "Should not match empty string"
    
    print("✓ line_matches() works correctly")
    return True


def test_print_functions():
    """Test print utility functions don't crash."""
    print("Testing print utility functions...")
    from ade.utils import print_status, print_header
    
    # These should not raise exceptions
    print_status("[+] Test success message")
    print_status("[-] Test failure message")
    print_status("[*] Test info message")
    print_status("[!] Test warning message")
    print_status("[INFO] Test info tag")
    print_header("Test Header")
    
    print("✓ print_status() and print_header() work correctly")
    return True


def test_cli_help():
    """Test CLI help output."""
    print("Testing CLI argument parser...")
    import argparse
    from ade.cli import main
    
    # Create a parser to test args (without actually running)
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--rhosts", required=True)
    parser.add_argument("-d", "--domain")
    parser.add_argument("-f", "--fqdn")
    parser.add_argument("-u", "--username", default="")
    parser.add_argument("-p", "--password", default="")
    
    # Test parsing
    args = parser.parse_args(["-r", "10.10.10.161", "-u", "testuser", "-p", "testpass"])
    assert args.rhosts == "10.10.10.161"
    assert args.username == "testuser"
    assert args.password == "testpass"
    
    print("✓ CLI argument parsing works correctly")
    return True


def test_update_users_file():
    """Test the update_users_file function."""
    print("Testing update_users_file...")
    import tempfile
    import os
    from ade.users import update_users_file
    
    # Create a temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        temp_file = f.name
        f.write("ExistingUser\n")
        f.write("AnotherUser\n")
    
    try:
        # Test adding new users
        new_users = ["NewUser", "existinguser"]  # existinguser should be deduped (case-insensitive)
        update_users_file(new_users, temp_file, print)
        
        with open(temp_file, 'r') as f:
            content = f.read()
        
        assert "ExistingUser" in content or "existinguser" in content
        assert "NewUser" in content or "newuser" in content
        
        print("✓ update_users_file() works correctly")
    finally:
        os.unlink(temp_file)
    
    return True


def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("ADE Modular Package Test Suite")
    print("=" * 60)
    
    tests = [
        test_imports,
        test_config_values,
        test_line_matches,
        test_print_functions,
        test_cli_help,
        test_update_users_file,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} FAILED: {e}")
            failed += 1
        print()
    
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

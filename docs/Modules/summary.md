---
tags: [ade, module, summary, report, exam]
---

# summary

> **Order:** 12 of 12  
> **Auth:** none (reads existing artifacts)  
> **Prerequisites:** none  
> **Tools:** none (pure Python)

Generates a structured findings report and writes it to disk.

## What It Does

1. **Artifact inventory** — lists every generated file, path, size, and hashcat crack commands
2. **Attack path suggestions** — prioritized escalation routes based on findings
3. **Quick reference commands** — WinRM, secretsdump, spray commands
4. **Writes `ade_summary.txt`** to the output directory

## Artifact Inventory

| File | Hashcat Mode | Purpose |
|------|:---:|---|
| [[users.txt]] | — | Username list |
| [[asrep_hashes.txt]] | 18200 | AS-REP roastable hashes |
| [[kerberoast_hashes.txt]] | 13100 | Kerberoastable TGS hashes |
| `certipy/` | — | ADCS findings (JSON, TXT, ZIP) |

## Attack Path Suggestions

The summary adapts to what was found:

**Anonymous context:**
- SMB share enumeration → sensitive files
- AS-REP → Kerberoast chain (no-auth SPN requests)

**Authenticated context:**
- BloodHound analysis (shortest path to DA)
- Kerberoasting → crack service accounts
- ADCS escalation (ESC1-ESC13)
- RBCD via MachineAccountQuota
- Lateral movement (LSASS dump, session hunting)

## Quick Reference Commands

```bash
# WinRM (NTLM)
evil-winrm -i 10.10.10.161 -u user -p '<password>'

# WinRM (Kerberos)
KRB5CCNAME=loot/user.ccache evil-winrm -i dc01.corp.local -r CORP.LOCAL

# NTDS dump (Domain Admin)
secretsdump.py CORP.LOCAL/user:'<password>'@10.10.10.161 -just-dc

# Spray cracked password
crackmapexec smb 10.10.10.161 -u loot/users.txt -p '<cracked>' --continue-on-success
```

## Summary File

The report is written to `<output-dir>/ade_summary.txt`.

## Related

- [[CPTS Exam Guide]] — how to use this in exams
- [[Output Artifacts]] — all output files
- [[maq]] — previous module
- [[Modules]] — full module list
- [[ADE]] — back to hub

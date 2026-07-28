---
tags: [ade, modules, reference]
---

# Modules

ADE has 14 modules executed in a fixed order. Each module can be individually enabled or disabled with `--modules` or `--skip`.

## Execution Order

1. [[discovery]] — Domain/FQDN discovery via anonymous LDAP
2. [[creds]] — Credential validation and Kerberos detection
3. [[ldap]] — User enumeration and description extraction
4. [[smb]] — Share enumeration, RID brute-force, Kerberos tickets
5. [[asrep]] — AS-REP roasting, user:user spraying
6. [[kerberoast]] — Kerberoasting, TGS hash extraction
7. [[bloodhound]] — BloodHound CE data collection
8. [[bloodyad]] — Writable object permission checks
9. [[adcs]] — ADCS enumeration via Certipy
10. [[smb-signing]] — SMB signing requirement check
11. [[gpp]] — GPP/cpassword credential recovery
12. [[maq]] — MachineAccountQuota check
13. [[laps]] — LAPS password readability check
14. [[summary]] — Findings summary and exam report

## Prerequisites Matrix

| Module | Credentials | Domain | FQDN | Kerberos-aware |
|--------|:---:|:---:|:---:|:---:|
| [[discovery]] | ❌ | ❌ | ❌ | ❌ |
| [[creds]] | ✅ | ❌ | ❌ | ✅ (detects) |
| [[ldap]] | ❌ | ❌ | ❌ | ✅ |
| [[smb]] | ❌ | ❌ | ❌ | ✅ |
| [[asrep]] | ❌ | ✅ | ○ (opt) | ✅ |
| [[kerberoast]] | ✅ | ✅ | ✅ | ✅ |
| [[bloodhound]] | ✅ | ✅ | ✅ | ✅ |
| [[bloodyad]] | ✅ | ✅ | ✅ | ✅ |
| [[adcs]] | ✅ | ✅ | ✅ | ✅ |
| [[smb-signing]] | ❌ | ❌ | ❌ | ❌ |
| [[gpp]] | ❌ | ❌ | ❌ | ❌ |
| [[maq]] | ✅ | ✅ | ❌ | ✅ |
| [[laps]] | ✅ | ✅ | ❌ | ✅ |
| [[summary]] | ❌ | ❌ | ❌ | ✅ (reports) |

> ✅ = required, ❌ = not required, ○ = optional (enables additional features)

## Module Selection

### Exact (`--modules`)

```bash
ade -r 10.10.10.161 --modules smb,asrep
```

Runs **only** `smb` and `asrep`. If a requested module has unmet prerequisites, ADE skips it with a clear message.

### Skip (`--skip`)

```bash
ade -r 10.10.10.161 --skip bloodhound,adcs
```

Runs **all modules except** `bloodhound` and `adcs`.

### Prerequisite Handling

When a module is enabled but lacks prerequisites, ADE prints:

```
[!] Skipping kerberoast: missing required credentials, domain, fqdn.
```

No hard crash — enumeration continues with remaining modules.

## Kerberos Auto-Rerun

If [[creds]] or [[kerberoast]] detects that Kerberos is required (NTLM blocked), ADE:
1. Sets Kerberos mode
2. Restarts the workflow from the top
3. Skips dependency/host checks on the second pass
4. Re-runs all enabled modules with `-k` flags

See [[Workflows#Kerberos]] for details.

## Next

- [[CLI Reference]] — all command-line flags
- [[Workflows]] — step-by-step workflows
- [[ADE]] — back to hub

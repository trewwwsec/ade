---
tags: [ade, module, bloodyad, permissions, acl]
---

# bloodyad

> **Order:** 8 of 14  
> **Auth:** authenticated  
> **Prerequisites:** domain, fqdn, credentials  
> **Tools:** bloodyAD

Checks for AD objects writable by the current user.

## What It Does

Runs `bloodyAD get writable` to enumerate objects the authenticated user can modify:

```bash
bloodyAD -u user -p pass -d CORP.LOCAL --dc-ip 10.10.10.161 --host dc01.corp.local get writable
```

With Kerberos:
```bash
bloodyAD -u user -p pass -k -d CORP.LOCAL --dc-ip 10.10.10.161 --host dc01.corp.local get writable
```

## Why This Matters

Writable objects are direct escalation paths:
- **Writable user** → ForceChangePassword, targeted Kerberoasting
- **Writable group** → Add yourself to privileged groups
- **Writable computer** → Resource-Based Constrained Delegation (RBCD)
- **Writable GPO** → Deploy malicious policies

## Interpreting Output

Look for:
- `GenericAll` / `GenericWrite` on users or groups
- `WriteDacl` — can modify permissions
- `WriteOwner` — can take ownership
- `Self` — can modify own attributes (less critical)

## Related

- [[bloodhound]] — previous module (cross-reference findings)
- [[adcs]] — next module
- [[maq]] — MachineAccountQuota (enables RBCD)
- [[Attack Paths]] — escalation routes
- [[Modules]] — full module list
- [[ADE]] — back to hub

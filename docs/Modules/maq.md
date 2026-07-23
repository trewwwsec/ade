---
tags: [ade, module, maq, rbcd, machine-account]
---

# maq

> **Order:** 11 of 12  
> **Auth:** authenticated  
> **Prerequisites:** domain, credentials  
> **Tools:** nxc

Checks the MachineAccountQuota attribute (`ms-DS-MachineAccountQuota`).

## What It Does

```bash
nxc ldap <target> -u user -p pass -M maq
```

Parses the quota value and reports viability for machine account creation.

## Why This Matters

If `MachineAccountQuota > 0`, **any authenticated user** can create a machine account. This enables:

- **Resource-Based Constrained Delegation (RBCD)** — abuse delegation to impersonate any user
- **Shadow Credentials** — add alternative key material to accounts
- **AD CS escalation** — in combination with certificate templates

## Output

### Quota > 0
```
[+] MachineAccountQuota = 10 — you CAN add machine accounts!
    → RBCD / shadow credentials attacks are viable.
    → impacket-addcomputer -dc-ip 10.10.10.161 -computer-pass 'Passw0rd!' 'CORP.LOCAL/user:pass'
```

### Quota = 0
```
[!] MachineAccountQuota = 0 — cannot add machine accounts.
```

## RBCD Attack Overview

1. Create a fake computer: `impacket-addcomputer`
2. Configure RBCD delegation from a target to your fake computer
3. Request a service ticket impersonating a high-value user to the target
4. Authenticate as that user to the target

## Related

- [[smb-signing]] — previous module
- [[summary]] — next module
- [[bloodyad]] — writable computer objects (alternative)
- [[Attack Paths#RBCD|RBCD Attack Path]]
- [[Modules]] — full module list
- [[ADE]] — back to hub

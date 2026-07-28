---
tags: [ade, module, asrep, spraying, kerberos]
---

# asrep

> **Order:** 5 of 14  
> **Auth:** anonymous or authenticated  
> **Prerequisites:** domain (FQDN optional for no-auth SPN)  
> **Tools:** GetNPUsers.py, GetUserSPNs.py, nxc

AS-REP roasting and user:user password spraying.

## What It Does

### 1. AS-REP Roasting

Runs `GetNPUsers.py` against all users in [[users.txt]] to find accounts with Kerberos pre-authentication disabled:

```bash
GetNPUsers.py CORP.LOCAL/ -no-pass -usersfile users.txt -dc-ip 10.10.10.161
```

Captured hashes are saved to [[asrep_hashes.txt]] (hashcat mode 18200).

### 2. No-Auth SPN Requests

If AS-REP roastable users are found **and** FQDN is available, ADE uses those accounts to request Kerberos service tickets without valid credentials:

```bash
GetUserSPNs.py -no-preauth <roastable_user> -usersfile users.txt -dc-host dc01.corp.local CORP.LOCAL/
```

Results saved to [[kerberoast_hashes.txt]] (hashcat mode 13100).

### 3. Password Policy Check

Retrieves domain password policy via `nxc --pass-pol` before spraying.

### 4. User:User Spraying

If no credentials provided (anonymous mode), attempts `user:user` login for every account in [[users.txt]].

**Safety gate:** If lockout threshold ≤ 3, spraying is **skipped** with a warning.

## Prerequisites

| Context | Required |
|---------|----------|
| AS-REP roasting | `-d <domain>` |
| No-auth SPN | `-d <domain>` + `-f <fqdn>` |
| Spraying | [[users.txt]] must exist |

## Output Files

- [[asrep_hashes.txt]] — AS-REP roastable hashes (mode 18200)
- [[kerberoast_hashes.txt]] — Kerberoast hashes from no-auth SPN requests (mode 13100)

## Credential States

When called with credentials, `asrep` uses the `cred_status` from [[creds]]:
- `ok` / `kerberos` / `ambiguous` → proceeds with AS-REP roasting
- `bad` → skips with warning

## Related

- [[kerberoast]] — next module (authenticated Kerberoasting)
- [[smb]] — previous module
- [[users.txt]] — user list
- [[asrep_hashes.txt]] — hash output
- [[Modules]] — full module list
- [[ADE]] — back to hub

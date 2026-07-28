---
tags: [ade, module, ldap, users]
---

# ldap

> **Order:** 3 of 14  
> **Auth:** anonymous or authenticated  
> **Prerequisites:** none  
> **Tools:** nxc

Performs LDAP enumeration to extract user descriptions and `sAMAccountName` values.

## What It Does

1. Queries LDAP for `(objectclass=user)` attributes
2. Extracts `description` and `sAMAccountName` pairs using awk
3. Collects all unique usernames (case-insensitive dedup)
4. Updates [[users.txt]] via `update_users_file()`

## Output

### Descriptions

```
[+] Description: IT Administrator         User: jsmith
[+] Description: Service Account - Web    User: svc-web
```

### Usernames

```
[+] Found unique usernames from LDAP.
[+] Appended new username(s) to users.txt.
[+] Appended lowercase name(s) to users.txt.
```

## users.txt Format

The file contains both case-preserved originals and lowercase duplicates:
```
JSmith
Administrator
jsmith
administrator
```

This dual format supports both case-sensitive and case-insensitive cracking tools.

## Kerberos Mode

When Kerberos is active, the `-k` flag is appended to nxc commands:
```bash
nxc ldap <target> -u <user> -p <pass> -k --query '(objectclass=user)' ''
```

## Related

- [[users.txt]] — output file format and purpose
- [[smb]] — next module (also updates users.txt via RID brute)
- [[creds]] — previous module
- [[Modules]] — full module list
- [[ADE]] — back to hub

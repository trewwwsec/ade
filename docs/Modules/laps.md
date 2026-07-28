---
tags: [ade, module, laps, credentials, lateral-movement]
---

# laps

> **Order:** 13 of 14
> **Auth:** authenticated
> **Prerequisites:** domain, credentials
> **Tools:** nxc

Checks whether the current credentials can read LAPS (Local Administrator
Password Solution) passwords for any computer object.

## What It Does

```bash
nxc ldap <target> -u user -p pass -M laps
```

Queries LDAP for `ms-MCS-AdmPwd`, `msLAPS-Password`, and
`msLAPS-EncryptedPassword` attributes across all computer objects, decrypting
LAPS v2 blobs where needed. Only accounts explicitly delegated read access
(directly or via group membership) will see results — most accounts return
nothing, which is expected and not an error.

## Why This Matters for CPTS

If any LAPS password is readable, it's an immediate, ready-to-use local
administrator credential for that machine — no cracking, no exploitation
required. This is one of the fastest wins available once you have any
authenticated foothold, and it's easy to forget to check.

## Output

### Passwords Readable
```
[+] Recovered 1 LAPS password(s) — saved to loot/laps_passwords.txt
    → DC01$: R4nd0mL@psPassw0rd!
```

### Nothing Readable
```
[!] No LAPS passwords readable with current credentials.
```

## Attack Path

1. Authenticate as local Administrator on the target computer using the
   recovered password:
   ```bash
   nxc smb <target> -u administrator -p '<laps-password>' -x whoami
   ```
2. Dump SAM/LSASS if further credentials are needed.
3. Check BloodHound for `Session`/`AdminTo` edges from that host to expand
   lateral movement.

## Related

- [[maq]] — previous module
- [[summary]] — next module
- [[gpp]] — another fast credential-recovery check
- [[Modules]] — full module list
- [[ADE]] — back to hub

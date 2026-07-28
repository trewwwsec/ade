---
tags: [ade, module, gpp, cpassword, sysvol, credentials]
---

# gpp

> **Order:** 11 of 14
> **Auth:** anonymous or authenticated
> **Prerequisites:** none
> **Tools:** nxc

Checks SYSVOL for Group Policy Preferences (GPP) cached credentials —
`cpassword` values and cached autologon passwords.

## What It Does

```bash
nxc smb <target> -u <user> -p <pass> -M gpp_password
nxc smb <target> -u <user> -p <pass> -M gpp_autologin
```

Both modules only need `READ` access to the `SYSVOL` share (frequently
available anonymously). `gpp_password` spiders `Groups.xml`, `Services.xml`,
`ScheduledTasks.xml`, `DataSources.xml`, `Printers.xml`, and `Drives.xml` for
`cpassword` attributes and decrypts them with Microsoft's published AES key.
`gpp_autologin` checks `Registry.xml` for cached `DefaultUserName`/
`DefaultPassword` autologon values.

## Why This Matters for CPTS

GPP credentials were pushed to client machines via Group Policy before
Microsoft patched the underlying mechanism (MS14-025), but old `SYSVOL` files
are still frequently left behind in labs and real environments. The
`cpassword` field is AES-encrypted with a key Microsoft published in its own
documentation, so recovery is instant — no cracking required.

## Output

### Credentials Found
```
[+] Recovered 1 GPP credential(s) — saved to loot/gpp_passwords.txt
```

### Nothing Found
```
[!] No GPP credentials recovered.
```

## Attack Path

1. Recovered credentials are cleartext — try them directly against SMB/LDAP/WinRM.
2. If the account is a local admin on other hosts, pivot immediately.
3. Even a low-privilege GPP account is often enough to bootstrap further
   enumeration (RID brute, LDAP queries) with real credentials instead of
   anonymous access.

## Related

- [[smb-signing]] — previous module
- [[maq]] — next module
- [[laps]] — another fast credential-recovery check
- [[Modules]] — full module list
- [[ADE]] — back to hub

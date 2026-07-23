---
tags: [ade, module, smb, shares, kerberos, rid-brute]
---

# smb

> **Order:** 4 of 12  
> **Auth:** anonymous or authenticated  
> **Prerequisites:** none  
> **Tools:** nxc, getTGT.py

Enumerates SMB shares and discovers users via RID brute-force.

## What It Does

### Authenticated Path

When credentials are provided:
1. If Kerberos mode: obtains TGT with `getTGT.py`, exports `KRB5CCNAME`, then enumerates shares
2. If NTLM mode: enumerates shares directly
3. Prints manual `smbclient.py -k` connection command for Kerberos
4. Refreshes [[users.txt]] via RID brute-force

### Anonymous Path

When no credentials:
1. Tries anonymous share enumeration (`-u anonymous -p ''`)
2. Tries guest share enumeration (`-u guest -p ''`)
3. Runs RID brute-force to build users.txt

## Kerberos Ticket Handling

In Kerberos mode:
```bash
getTGT.py CORP.LOCAL/user:pass -k -dc-ip 10.10.10.161
# → creates user.ccache

export KRB5CCNAME=/path/to/loot/user.ccache
```

The `.ccache` file is copied to the output directory. ADE prints:
```
KRB5CCNAME=/path/to/loot/alice.ccache smbclient.py -k dc01.corp.local
```

## Share Output

Results show only lines with `[+]`, `READ`, `WRITE`, or `Authenticated` indicators (in normal mode). Use `-v` for full raw output.

## Intelligent Retries

SMB share enumeration uses `retry_on_invalid=True` — if output is empty, too short, or lacks success indicators, ADE retries up to 2 times with a 2-second delay.

## Related

- [[ldap]] — previous module (also updates users.txt)
- [[asrep]] — next module (uses users.txt for roasting/spraying)
- [[users.txt]] — output file
- [[Workflows#Kerberos|Kerberos Mode]] — ticket workflow
- [[Modules]] — full module list
- [[ADE]] — back to hub

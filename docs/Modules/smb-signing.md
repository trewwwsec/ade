---
tags: [ade, module, smb, signing, relay]
---

# smb-signing

> **Order:** 10 of 12  
> **Auth:** anonymous or authenticated  
> **Prerequisites:** none  
> **Tools:** nxc

Checks whether SMB signing is required on the target.

## What It Does

```bash
nxc smb <target> -u <user> -p <pass> -M smb_signing
```

Interprets the output and reports signing status.

## Why This Matters for CPTS

SMB signing controls whether relay attacks work:

| Signing Status | Relay Viability |
|:---|---|
| **Disabled** | ✅ Relay attacks viable |
| **Enabled, not required** | ⚠️ May still work |
| **Required** | ❌ SMB relay blocked |

## Output

### Signing Disabled
```
[+] SMB signing is DISABLED — relay attacks are viable!
    Run Responder + ntlmrelayx.
```

### Signing Enabled but Not Required
```
[!] SMB signing is ENABLED but not required — relay attacks may still work.
```

### Signing Required
```
[+] SMB signing is REQUIRED — relay attacks against SMB are blocked.
```

## Attack Path

If signing is disabled:
1. Start Responder: `sudo responder -I tun0`
2. Start ntlmrelayx: `ntlmrelayx.py -tf targets.txt -smb2support`
3. Wait for coercion or spontaneous authentication

## Related

- [[adcs]] — previous module (ESC8 needs no signing)
- [[maq]] — next module
- [[Attack Paths#Relay|Relay Attack Paths]]
- [[Modules]] — full module list
- [[ADE]] — back to hub

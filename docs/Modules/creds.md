---
tags: [ade, module, credentials, kerberos]
---

# creds

> **Order:** 2 of 14  
> **Auth:** authenticated  
> **Prerequisites:** username, password  
> **Tools:** nxc

Validates supplied credentials via SMB and detects Kerberos-only environments.

## What It Does

1. Runs `nxc smb <target> --shares -u <user> -p <pass>`
2. Interprets the output to determine credential status
3. If Kerberos is required, triggers an auto-rerun of the entire workflow

## Return Values

| Status | Meaning | Behavior |
|--------|---------|----------|
| `ok` | Credentials valid | Continue with authenticated modules |
| `bad` | `STATUS_LOGON_FAILURE` | **Exit** — fix creds or rerun without them |
| `kerberos` | NTLM blocked | **Rerun** — restarts workflow with Kerberos auth |
| `ambiguous` | Unclear output | Continue cautiously (warned) |
| `no-creds` | No username/password given | Continue with anonymous modules |

## Kerberos Detection

Triggers when output contains:
- `STATUS_NOT_SUPPORTED`
- `KDC_ERR`
- `SPNEGO`
- `NTLM negotiation failed`

When detected without credentials → exits with instructions.  
When detected with credentials → auto-restarts in Kerberos mode.

## Important

- If `bad` status: ADE **exits immediately** before any module runs
- If `ambiguous`: ADE continues but warns — you may want to rerun without creds
- On Kerberos rerun, this module is skipped on the second pass

## Related

- [[Workflows#Kerberos|Kerberos Mode Workflow]] — full rerun flow
- [[discovery]] — previous module
- [[ldap]] — next module
- [[Modules]] — full module list
- [[ADE]] — back to hub

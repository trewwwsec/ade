---
tags: [ade, mindmap, moc, index]
---

# ADE Mindmap

```mermaid
mindmap
  root((ADE v1.2.0))
    Installation
      pip
      pipx
      uv venv
      uv tool
      install.sh helper
    Dependencies
      nmap
      nxc :: NetExec
      Impacket
        GetNPUsers.py
        getTGT.py
        GetUserSPNs.py
      Certipy
      BloodHound CE
      bloodyAD
    CLI
      -r :: Target IP
      -d :: Domain
      -f :: FQDN
      -u :: Username
      -p :: Password
      -v :: Verbose/Debug
      -o :: Output Directory
      --modules :: Exact selection
      --skip :: Exclude modules
    Modules
      Phase 1::Discovery
        discovery :: Domain/FQDN via LDAP
        creds :: Validate + Kerberos detect
      Phase 2::Enumeration
        ldap :: Users + descriptions
        smb :: Shares + RID brute
        smb-signing :: Relay viability
      Phase 3::Attacks
        asrep :: Roasting + spraying
        kerberoast :: TGS hashes
      Phase 4::Collection
        bloodhound :: AD data ZIP
        bloodyad :: Writable objects
        adcs :: Certipy scan
      Phase 5::CPTS
        maq :: MachineAccountQuota
        summary :: Findings report
    Workflows
      Anonymous
        No credentials
        AS-REP + spraying
      Authenticated
        Full creds
        All modules
      Kerberos
        Auto-detected
        TGT + .ccache
      CPTS Exam
        Phase 1::Recon
        Phase 2::Auth Enum
        Phase 3::Crack + Exploit
        Phase 4::BloodHound
        Phase 5::Lateral + DA
    Attack Paths
      AS-REP → Crack → Spray
      Kerberoast → Crack → Silver ticket
      ADCS ESC1 → certipy req → auth
      ADCS ESC8 → Relay → Cert
      SMB Signing → Disabled → Relay
      MAQ > 0 → AddComputer → RBCD
      Writable User → ForceChangePassword
      Writable Group → Add self to DA
    Output Artifacts
      users.txt
      asrep_hashes.txt :: Mode 18200
      kerberoast_hashes.txt :: Mode 13100
      user.ccache :: Kerberos ticket
      certipy/ :: ADCS findings
      username/ :: BloodHound ZIP
      ade_summary.txt :: Exam report
    Exams
      CPTS
        Time-optimized
        Phase-by-phase
        Quick ref commands
      OSCP
        AD sets
        Similar workflow
```

---

## Full Wikilink Index

### Hub
- [[ADE]]

### Setup
- [[Installation]]
- [[Dependencies]]

### Reference
- [[CLI Reference]]
- [[Modules]]
- [[Output Artifacts]]

### Modules (1-12)
- [[discovery]]
- [[creds]]
- [[ldap]]
- [[smb]]
- [[asrep]]
- [[kerberoast]]
- [[bloodhound]]
- [[bloodyad]]
- [[adcs]]
- [[smb-signing]]
- [[maq]]
- [[summary]]

### Artifacts
- [[users.txt]]
- [[asrep_hashes.txt]]
- [[kerberoast_hashes.txt]]
- [[ade_summary.txt]]

### Guides
- [[Workflows]]
- [[Attack Paths]]
- [[CPTS Exam Guide]]

### Meta
- [[Mindmap]] _(this note)_

---

## Graph View

For the best Obsidian graph experience:

1. Open the graph view
2. Filter to `path:docs/`
3. Group by `tags` or folder
4. The central nodes will be: [[ADE]], [[Modules]], [[Workflows]], [[Attack Paths]], [[CPTS Exam Guide]]

## Related

- [[ADE]] — start here

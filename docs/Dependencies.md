---
tags: [ade, dependencies, tools]
---

# Dependencies

ADE orchestrates these external tools. All must be on `$PATH`.

## Required Tools

| Tool | CLI Name | Install Key | Purpose |
|------|----------|:-----------:|---------|
| nmap | `nmap` | `nmap` | Host alive checks |
| NetExec | `nxc` | `netexec` | SMB, LDAP, RID brute, policy, signing, MAQ |
| Certipy | `certipy` | `certipy` | ADCS enumeration |
| BloodHound CE | `bloodhound-ce-python` | `bloodhound` | AD data collection |
| bloodyAD | `bloodyAD` | `bloodyad` | Permission checks |
| GetNPUsers.py | `GetNPUsers.py` | `impacket` | AS-REP roasting |
| getTGT.py | `getTGT.py` | `impacket` | Kerberos TGT acquisition |
| GetUserSPNs.py | `GetUserSPNs.py` | `impacket` | Kerberoasting |

## Install Commands

```bash
# nmap
sudo apt update && sudo apt install nmap -y

# NetExec
pipx install git+https://github.com/Pennyw0rth/NetExec

# Certipy
pipx install certipy-ad

# BloodHound
pipx install bloodhound-ce-python

# bloodyAD
pipx install bloodyAD

# Impacket (GetNPUsers, getTGT, GetUserSPNs)
pipx install impacket
```

Or use the helper: `./install.sh` — see [[Installation]].

## Module Dependency Map

| Module | Tools Used |
|--------|-----------|
| [[discovery]] | nxc |
| [[creds]] | nxc |
| [[ldap]] | nxc |
| [[smb]] | nxc, getTGT.py |
| [[asrep]] | GetNPUsers.py, nxc |
| [[kerberoast]] | GetUserSPNs.py |
| [[bloodhound]] | bloodhound-ce-python |
| [[bloodyad]] | bloodyAD |
| [[adcs]] | nxc, certipy |
| [[smb-signing]] | nxc |
| [[gpp]] | nxc |
| [[maq]] | nxc |
| [[laps]] | nxc |
| [[summary]] | _(none — reads artifacts)_ |

## Detection

ADE checks all dependencies on startup (before any network activity). If any are missing, it prints install commands and exits.

```bash
ade -r 10.10.10.161
# → Checking external dependencies...
# → [+] All dependencies found.
```

## Next

- [[Installation]] — how to install ADE itself
- [[ADE]] — back to hub

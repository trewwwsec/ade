# ADE
ADE is a Python package and CLI that automates Active Directory (AD) enumeration in lab environments, helping users on Hack The Box, Hack Smarter, TryHackMe, Proving Grounds, or exams like OSCP and CPTS streamline initial AD recon.

![](https://github.com/user-attachments/assets/2e6ef45a-6347-41f2-9681-63496ded9f12)

## Examples 

### No Credentials Provided

![](https://github.com/user-attachments/assets/95f34be4-796c-471a-a4c5-dd978c4287bb)

### Credentials Provided

![](https://github.com/user-attachments/assets/ce921476-d4e6-4987-b265-5b884a8b5fae)

### Kerberos

![](https://github.com/user-attachments/assets/0196e056-d4a0-48f2-bfb4-81f0140330ee)


## Installation

Install from the current checkout with `pip`, `pipx`, or `uv pip`:

```
git clone https://github.com/trewwwsec/ade.git
cd ade
python -m pip install .
```

Install as an isolated CLI app with `pipx`:

```sh
git clone https://github.com/trewwwsec/ade.git
cd ade
pipx install .
```

Install into a `uv`-managed virtual environment:

```sh
git clone https://github.com/trewwwsec/ade.git
cd ade
uv venv .venv
source .venv/bin/activate
uv pip install .
```

> [!NOTE]
> ADE configures `uv pip` to use `link-mode = "copy"` so installs stay quiet on
> cross-filesystem setups like Docker bind mounts and lab containers.

Install as a standalone CLI with `uv tool`:

```sh
git clone https://github.com/trewwwsec/ade.git
cd ade
uv tool install --link-mode copy .
```

Use the helper installer if you want ADE plus the external toolchain:

```sh
git clone https://github.com/trewwwsec/ade.git
cd ade
./install.sh
```


## Dependencies
The dependencies for ADE are [certipy-ad](https://github.com/ly4k/Certipy), [netexec](https://github.com/Pennyw0rth/NetExec), [bloodhound-ce](https://github.com/dirkjanm/), [bloodyAD](https://github.com/CravateRouge/bloodyAD), and [Impacket](https://github.com/fortra/impacket)


## Key Features
### Initial Discovery & Host Setup
- **Target Alive Checks:** Pings the target with nmap before starting to ensure the IP is correct and the host is online.
- **/etc/hosts Management:** Discovers the target's FQDN and domain, then maps them in /etc/hosts for name resolution.
- **Credential Validation:** Checks if supplied credentials are valid before launching deeper scans to avoid failed authenticated runs.
- **User & Description Enumeration:** Collects sAMAccountName and description attributes via LDAP, and uses SMB-based RID cycling as a fallback to find accounts that LDAP queries might not return

### Initial Access & Credential Attacks
- **User Spraying:** If run without credentials, it attempts user:user logins for all discovered accounts.
- **AS-REP Roasting:** Uses the generated users.txt to find accounts vulnerable to offline password cracking, then uses any AS-REP roastable accounts to request SPN/TGS roast material without valid credentials when FQDN context is available.
- **Kerberoasting:** Searches for service accounts and requests their tickets, providing hashes to crack offline.
- **Auto-Kerberos Switching:** Detects if Kerberos is required. If NTLM is unsupported, ADE enables Kerberos mode and restarts the workflow.

### Post-Authentication Enumeration
- **Kerberos Ticket Management:** Gets a Kerberos ticket, saves it as a .ccache file you can reuse, and tells you the command to connect to SMB using that ticket.
- **SMB Share Enumeration:** Enumerates SMB shares on the target, attempts access with anonymous/guest or supplied credentials, and reports access permissions (e.g., READ, WRITE).
- **Intelligent Retries:** Automatically retries SMB checks when they fail to ensure more reliable results.
- **BloodHound Collection:** Executes the BloodHound data collector, automatically retrying on failure, and outputs a ZIP that can be imported into BloodHound.
- **Permission Checks:** Scans Active Directory with bloodyAD to find items your credentials can change (like user accounts or groups).
- **ADCS Checks:** Probes for Active Directory Certificate Services and then uses Certipy to find misconfigured templates that allow for privilege escalation.
- **Security Checks:** Probes for SMB signing requirements (relay attack viability) and MachineAccountQuota (RBCD attack surface).
- **GPP Credential Recovery:** Recovers plaintext credentials cached in SYSVOL via Group Policy Preferences (cpassword) and autologon registry entries.
- **LAPS Password Check:** Checks whether the current credentials can read LAPS local administrator passwords.
- **Findings Summary:** Generates a structured `ade_summary.txt` report with artifact inventory, attack path suggestions, and quick-reference commands — ready for your exam writeup.

## Usage
> [!TIP]
> Wait at least 5 minutes after starting your lab before running the script to make sure `nxc --shares` works. 
> </br> This is because some labs take longer to start up.

Without credentials (anonymous/guest checks):
```
ade -r <box-ip>
```

With credentials (authenticated checks):
```
ade -r <box-ip> -u <user> -p <password> 
```

Write loot into a specific output directory:
```
ade -r <box-ip> -o <output-dir>
```

Run only selected modules:
```
ade -r <box-ip> --modules smb,asrep
```

Skip selected modules:
```
ade -r <box-ip> --skip bloodhound,adcs
```

Current module names:
```
discovery, creds, ldap, smb, asrep, kerberoast, bloodhound, bloodyad, adcs,
smb-signing, gpp, maq, laps, summary
```

Notes:
- `--modules` is exact. ADE only runs the modules you name.
- Some modules require prerequisites. For example, `asrep` needs a domain for AS-REP roasting and uses FQDN when available for no-auth SPN requests; `kerberoast` / `bloodhound` / `bloodyad` / `adcs` / `maq` / `laps` need credentials plus discovered or supplied domain/FQDN context.
- `smb-signing`, `gpp`, and `summary` work with or without credentials.
- The output directory is resolved at startup but created only when ADE actually writes the first artifact.

See the [docs/](docs/ADE.md) directory for the full Obsidian wiki: module references, workflows, attack paths, and a CPTS exam guide.

## Development / Testing

Run the package directly from the checkout with `uv`:
```
uv run python -m ade -r <box-ip>
```

Run the test suite with `uv`:
```
uv run python tests/test_ade.py
```

---

## Thank You

[Schlop](https://github.com/schlopshow) made the script that installs ADE.

---

> [!NOTE]
> If you have any issues or requests, reach out on [Discord](https://discord.gg/TujAjYXJjr) (Blue Pho3nix).

---

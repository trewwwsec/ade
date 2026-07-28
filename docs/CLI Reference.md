---
tags: [ade, cli, reference]
---

# CLI Reference

## Syntax

```
ade -r <target-ip> [options]
```

## Required

| Flag | Description |
|------|-------------|
| `-r`, `--rhosts` | Target DC IP address |

## Optional

| Flag | Default | Description |
|------|---------|-------------|
| `-d`, `--domain` | _auto-discovered_ | Domain name (e.g., `CORP.LOCAL`) |
| `-f`, `--fqdn` | _auto-discovered_ | FQDN of DC (e.g., `dc01.corp.local`) |
| `-u`, `--username` | `""` (anonymous) | Username for authenticated scans |
| `-p`, `--password` | `""` | Password for authenticated scans |
| `-v`, `--verbose` | off | Show raw tool output + debug log |
| `-o`, `--output-dir` | `ade_<IP>_<YYYYMMDD>/` | Loot directory |
| `-W`, `--wait-host` | `0` (single check) | Minutes to keep retrying the host-up check instead of exiting immediately |
| `--modules` | _all modules_ | Comma-separated list of modules to run |
| `--skip` | _none_ | Comma-separated list of modules to skip |

## Examples

### Basic anonymous run

```bash
ade -r 10.10.10.161
```

Runs all modules that work without credentials: [[discovery]], [[ldap]], [[smb]] (anonymous/guest), [[asrep]], [[smb-signing]], [[gpp]], and [[summary]].

### Authenticated run

```bash
ade -r 10.10.10.161 -u jsmith -p 'Password123!'
```

Runs all modules. [[creds]] validates credentials first.

### Full context (skip discovery)

```bash
ade -r 10.10.10.161 -u jsmith -p 'Password123!' -d CORP.LOCAL -f dc01.corp.local
```

### Targeted modules

```bash
ade -r 10.10.10.161 -u admin -p pass --modules smb,kerberoast,adcs
```

Runs **only** `smb`, `kerberoast`, and `adcs`. No implicit dependency injection.

### Skip heavy modules

```bash
ade -r 10.10.10.161 -u admin -p pass --skip bloodhound,adcs
```

Runs everything except BloodHound and Certipy.

### Custom output directory

```bash
ade -r 10.10.10.161 -u admin -p pass -o /root/loot/htb-forest
```

### Verbose / debug mode

```bash
ade -r 10.10.10.161 -u admin -p pass -v
```

Prints all raw tool output to terminal **and** writes `ade_debug_<timestamp>.log`.

### Wait for a booting lab

```bash
ade -r 10.10.10.161 --wait-host 5
```

Retries the host-up check for up to 5 minutes instead of exiting immediately.
Launch this right after starting the lab instead of manually waiting and
re-invoking ADE once it's up.

## `--modules` vs `--skip`

| Behavior | `--modules` | `--skip` |
|----------|:-----------:|:--------:|
| Selection | exact set | all minus listed |
| Mutually exclusive | ✅ (errors if both) | ✅ |
| Unknown module | exits with message | exits with message |

## Module Names

```
discovery, creds, ldap, smb, asrep, kerberoast, bloodhound, bloodyad, adcs,
smb-signing, gpp, maq, laps, summary
```

Full details: [[Modules]]

## Exit Codes

| Code | Meaning |
|:----:|---------|
| 0 | Success (all enabled modules ran) |
| 1 | Error (invalid args, missing deps, host down, bad creds) |

## Output Directory

- Default: `ade_<IP>_<YYYYMMDD>/` in CWD
- Custom: `-o /path/to/loot`
- Created lazily — only on first artifact write
- Not created on startup failures (host down, bad deps)

## Next

- [[Modules]] — module details and prerequisites
- [[Workflows]] — step-by-step workflow guides
- [[ADE]] — back to hub

---
tags: [ade, module, bloodhound, collection]
---

# bloodhound

> **Order:** 7 of 12  
> **Auth:** authenticated  
> **Prerequisites:** domain, fqdn, credentials  
> **Tools:** bloodhound-ce-python

Collects Active Directory data for BloodHound CE analysis.

## What It Does

1. Runs `bloodhound-ce-python` with `-c all --zip`
2. Retries once on failure (5-second delay)
3. Outputs a ZIP file into the output directory

```bash
bloodhound-ce-python -d CORP.LOCAL -u user -p pass -dc dc01.corp.local \
  -ns 10.10.10.161 --dns-timeout 10 -c all -op <user> --zip
```

## Output Structure

```
<output-dir>/
└── <username>/           # bloodhound-ce-python output dir
    └── *.zip             # BloodHound ZIP for import
```

## Retry Logic

- Attempt 1: normal run
- Attempt 2: retry after 5-second delay
- If both fail: prints `[!!!] BLOODHOUND FAILURE DETECTED`

## Import

```bash
# Start BloodHound CE
sudo bloodhound-ce

# Or upload ZIP to the web UI
```

## Tips for CPTS

- BloodHound is **slow** in time-limited exams
- Skip this module with `--skip bloodhound` if you need speed
- Run it last (or in a separate terminal) while you work on other attack paths
- The ZIP is the single most valuable artifact for finding escalation paths

## Related

- [[kerberoast]] — previous module
- [[bloodyad]] — next module
- [[CPTS Exam Guide]] — exam time management
- [[Modules]] — full module list
- [[ADE]] — back to hub

---
tags: [ade, installation, setup]
---

# Installation

## Prerequisites

- Python ≥ 3.10
- Linux (target OS for the external toolchain)
- sudo access (for `/etc/hosts` management and nmap)

## Quick Install

### pip (system/user)

```bash
git clone https://github.com/trewwwsec/ade.git
cd ade
python -m pip install .
```

### pipx (isolated CLI)

```bash
git clone https://github.com/trewwwsec/ade.git
cd ade
pipx install .
```

### uv venv (managed virtualenv)

```bash
git clone https://github.com/trewwwsec/ade.git
cd ade
uv venv .venv
source .venv/bin/activate
uv pip install .
```

> ADE's `pyproject.toml` sets `link-mode = "copy"` so installs work across filesystem boundaries (Docker bind mounts, lab containers).

### uv tool (standalone CLI)

```bash
git clone https://github.com/trewwwsec/ade.git
cd ade
uv tool install --link-mode copy .
```

### Helper installer (ADE + all external deps)

```bash
git clone https://github.com/trewwwsec/ade.git
cd ade
./install.sh
```

This installs ADE plus [[Dependencies|all external tools]] (nxc, Certipy, Impacket, BloodHound, bloodyAD).

## Development Install

```bash
git clone https://github.com/trewwwsec/ade.git
cd ade
uv venv .venv
source .venv/bin/activate
uv pip install -e .
```

Run tests:
```bash
uv run python tests/test_ade.py
```

Run directly:
```bash
uv run python -m ade -r <target-ip>
```

## Verification

```bash
ade --help
ade -r 10.10.10.161 -v   # verbose mode shows all tool output
```

## Next Steps

- [[Dependencies]] — required external tools
- [[CLI Reference]] — all command-line flags
- [[ADE]] — back to hub

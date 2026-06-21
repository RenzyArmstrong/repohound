# repohound

> Search GitHub repos by keyword — **auto-scans for malware, token stealers, and viruses.**

<p align="center">
  <img src="https://img.shields.io/pypi/v/repohound?color=red&label=PyPI" alt="PyPI">
  <img src="https://img.shields.io/pypi/pyversions/repohound" alt="Python">
  <img src="https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-blue" alt="Platforms">
  <img src="https://img.shields.io/github/license/RenzyArmstrong/repohound" alt="License">
</p>

## Install

```bash
pip install repohound
```

Works on **Linux, macOS, and Windows** (Python 3.8+). Zero dependencies.

For deep scan mode, [git](https://git-scm.com/) must be installed.

## Quick Start

```bash
# Basic search — scans README for tokens and malware
repohound "discord bot"

# Deep scan — clones repo and scans every file
repohound "crypto wallet" --deep -n 5

# Filter by language
repohound "proxy" -l Go -n 20

# Support all token patterns detected
repohound --tokens

# Pipe-friendly JSON output
repohound "telegram" --json | jq '.[].name'
```

## Features

| Command | What it does |
|---------|--------------|
| `repohound <keyword>` | Search GitHub + quick README scan |
| `--deep` | Clone repo, scan every source file (200 file cap) |
| `-l <lang>` | Filter by programming language |
| `-n <count>` | Max results (default 10) |
| `--no-scan` | Search only, skip security check |
| `--no-color` | Plain text output |
| `--json` | JSON output for scripts |
| `--tokens` | List all token patterns detected |

## What it detects

### Token leaks

GitHub PAT, Discord webhooks/bot tokens, AWS access keys, Stripe secrets, Telegram bot tokens, Slack webhooks, Google API keys, SSH private keys, and more.

### Malware patterns

Reverse shells, crypto miners, obfuscated eval, curl-bash chains, process injection, keyloggers, token stealers, encoded payloads, auto-run persistence.

### Suspicious code

Large base64 blobs, hidden windows, suspicious imports, registry manipulation.

## Configuration

Set a GitHub token for higher API rate limits:

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
```

Or save it to a file:

```bash
mkdir -p ~/.repohound
echo "ghp_xxxxxxxxxxxx" > ~/.repohound/token
chmod 600 ~/.repohound/token
```

Without a token, you get 60 requests/hour (GitHub API limit). With a token, 5,000/hour.

## Known Limitations

- **False positives**: `keylogger_import` may flag innocent uses of `keyboard` — always review flagged repos manually
- **Deep scan**: Clones with `--depth 1`, scans max 200 files per repo
- **GitHub only**: GitLab support planned
- **Git required**: Deep scan needs git installed (`apt install git` / `brew install git` / [Git for Windows](https://git-scm.com/))

## Related Projects

- [repohound](https://github.com/RenzyArmstrong/repohound) — this project
- [gitleaks](https://github.com/gitleaks/gitleaks) — Git secret scanner
- [trufflehog](https://github.com/trufflesecurity/trufflehog) — Credential scanner

## License

MIT

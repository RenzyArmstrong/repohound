# repohound 🐕

Search GitHub repos by keyword — **auto-scans for malware, token stealers, and viruses.**

```bash
pip install repohound
repohound "discord bot" -n 15
```

## Features

- 🔍 **Keyword search** across GitHub repositories
- 🛡️ **Auto security scan** — detects:
  - Leaked API tokens (GitHub, AWS, Discord, Slack, Stripe, Telegram...)
  - Malware patterns (reverse shells, crypto miners, obfuscated code)
  - Token stealers and keyloggers
- ⚠️ **Risk scoring** — every repo gets a safety score (LOW / MEDIUM / HIGH)
- 🌐 **Language filter** — `repohound "proxy scraper" -l Python`
- 🔬 **Deep scan mode** — clones repo and scans ALL files (not just README)
- 🎨 **Color-coded output** — tokens in red, malware flagged, clean repos in green
- 📋 **JSON output** — `--json` for piping to other tools

## Install

```bash
git clone https://github.com/RenzyArmstrong/repohound.git
cd repohound
pip install -e .
```

Or once published to PyPI:
```bash
pip install repohound
```

## Usage

```bash
# Basic search — quick README scan
repohound "game cheat"

# Deep scan — clones & scans every file
repohound "proxy tool" --deep

# Search without scan
repohound "http server" --no-scan

# Filter by language + limit
repohound "crypto bot" -l Go -n 20

# JSON output for piping
repohound "telegram bot" --json | jq '.[].name'

# List supported token detections
repohound --tokens
```

## Flags

| Flag | Description |
|------|-------------|
| `-n, --count N` | Max results (default: 10) |
| `-l, --language LANG` | Filter by language |
| `--deep` | Deep scan: clone repo → scan all files |
| `--no-scan` | Skip security scan |
| `--json` | Output JSON |
| `--tokens` | List token patterns detected |

## What it detects

| Category | Examples |
|----------|----------|
| **Tokens** | GitHub PAT, Discord webhooks, AWS keys, Stripe secrets, Telegram bot tokens, SSH private keys, Slack webhooks, Google API keys |
| **Malware** | Reverse shells, crypto miners, obfuscated eval, curl-bash chains, process injection, keyloggers, token stealers |
| **Suspicious** | Large base64 blobs, auto-run registry entries, hidden windows, encoded payloads |

## Known Limitations

- **False positives**: `keylogger_import` pattern flags any mention of `keyboard` — review flagged repos manually
- **Deep scan cap**: Clones repos shallow (`--depth 1`), scans max 200 files
- **GitHub only**: Currently GitHub API only (GitLab planned)
- **Token**: Uses `GITHUB_TOKEN` env var, or `~/.repohound/token` file

## Disclaimer

This tool is for **security research and educational purposes**. Always respect repo licenses and GitHub's ToS. Don't use found tokens — report them responsibly.

## Author

**RenzyArmstrong** — [github.com/RenzyArmstrong](https://github.com/RenzyArmstrong)

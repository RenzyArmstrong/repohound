"""repohound CLI — search source code repos with auto security scanning."""

import argparse
import sys
import subprocess
import json
import os
import tempfile
import shutil
import urllib.request
from pathlib import Path
from .search import search_github
from .scanner import scan_quick, scan_code_snippet, TOKEN_PATTERNS

# ── ANSI colors (disabled on old Windows cmd / --no-color / NO_COLOR) ──
_has_color = sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""

R = "\033[91m" if _has_color else ""
G = "\033[92m" if _has_color else ""
Y = "\033[93m" if _has_color else ""
B = "\033[94m" if _has_color else ""
C = "\033[96m" if _has_color else ""
W = "\033[97m" if _has_color else ""
D = "\033[90m" if _has_color else ""
N = "\033[0m" if _has_color else ""
BOLD = "\033[1m" if _has_color else ""

ICONS = {
    "LOW_RISK": G + "\u2713" + N,
    "MEDIUM_RISK": Y + "\u26a0" + N,
    "HIGH_RISK": R + "\u2717" + N,
    "CRITICAL": R + "\u2620" + N,
}

HOME = Path.home()


def _get_token():
    tok = os.environ.get("GITHUB_TOKEN", "")
    if tok:
        return tok
    for p in [
        HOME / ".repohound" / "token",
        HOME / ".config" / "repohound" / "token",
        HOME / ".hermes" / "tokens" / "github_renzy.token",
        HOME / ".hermes" / "tokens" / "github.token",
    ]:
        if p.exists():
            return p.read_text().strip()
    return ""


def _git_available():
    """Check if git is installed and usable."""
    try:
        r = subprocess.run(["git", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def fetch_readme(owner, repo, branch="main"):
    """Quick fetch README.md for scanning."""
    token = _get_token()
    for br in [branch, "main", "master"]:
        url = "https://raw.githubusercontent.com/" + owner + "/" + repo + "/" + br + "/README.md"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "repohound")
        if token:
            auth = "Bearer " + token
            req.add_header("Authorization", auth)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                if len(body) > 20 and "404" not in body[:100]:
                    return body[:5000]
        except Exception:
            continue
    return ""


def clone_and_scan(url, branch="main", shallow=True):
    """Clone repo to temp dir, scan all files, return (score, findings)."""
    if not _git_available():
        return 0, ["GIT_MISSING: git not found — install git for deep scan"]

    tmp = tempfile.mkdtemp(prefix="repohound_")
    try:
        cmd = ["git", "clone", "-q"]
        if shallow:
            cmd += ["--depth", "1"]
        cmd += ["-b", branch, url, tmp]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return 0, ["CLONE_FAILED: " + r.stderr[:200]]

        total_score = 0
        all_findings = []
        file_count = 0

        skip_dirs = {".git", "node_modules", "__pycache__", "vendor", ".venv", "venv"}
        skip_exts = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
                     ".ttf", ".eot", ".exe", ".dll", ".bin", ".so", ".dylib", ".mp4",
                     ".mp3", ".wav", ".zip", ".tar", ".gz", ".pdf", ".webp"}

        for root, dirs, files in os.walk(tmp):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                ext = os.path.splitext(fname)[1].lower()
                if ext in skip_exts:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > 1_000_000:
                        continue
                except OSError:
                    continue
                try:
                    with open(fpath, "r", errors="replace", encoding="utf-8") as f:
                        content = f.read()
                except Exception:
                    continue
                score, findings = scan_code_snippet(content, fname)
                total_score += score
                all_findings.extend(findings)
                file_count += 1
                if file_count > 200:
                    break
            if file_count > 200:
                all_findings.append("TRUNCATED: scanned 200 files only")
                break

        return total_score, all_findings
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def banner(keyword):
    print()
    print("  " + BOLD + R + "r" + Y + "e" + G + "p" + C + "o" + B + "h" + W + "ound" + N + " — hunting: " + BOLD + keyword + N)
    print("  " + D + "\u2500" * 55 + N)


def print_finding(text):
    """Color-code finding output."""
    if "TOKEN:" in text:
        prefix = R + "[TOKEN]" + N
    elif "MALWARE:" in text:
        prefix = R + "[MALWARE]" + N
    elif "SUSPICIOUS:" in text:
        prefix = Y + "[SUSPICIOUS]" + N
    elif "CRITICAL:" in text:
        prefix = R + BOLD + "[CRITICAL]" + N + R
    else:
        prefix = D + "[INFO]" + N
    rest = text.split(": ", 1)[-1] if ": " in text else text
    print("      " + prefix + " " + rest[:110])


def main():
    parser = argparse.ArgumentParser(
        prog="repohound",
        description="Search source code repos by keyword — auto-scans for malware and token leaks",
    )
    parser.add_argument("keyword", nargs="*", help="Search keyword(s)")
    parser.add_argument("-n", "--count", type=int, default=10, help="Max results (default: 10)")
    parser.add_argument("-l", "--language", help="Filter by programming language")
    parser.add_argument("--scan", action="store_true", default=True, help="Enable security scan (default)")
    parser.add_argument("--no-scan", action="store_false", dest="scan", help="Disable security scan")
    parser.add_argument("--deep", action="store_true", help="Deep scan: clone + scan all files")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--tokens", action="store_true", help="List supported token detections")

    args = parser.parse_args()

    # Handle --no-color (re-apply after argparse parses)
    if args.no_color:
        global R, G, Y, B, C, W, D, N, BOLD, ICONS
        R = G = Y = B = C = W = D = N = BOLD = ""
        ICONS = {k: v.replace("\033[91m", "").replace("\033[92m", "").replace("\033[93m", "")
                 .replace("\033[94m", "").replace("\033[96m", "").replace("\033[97m", "")
                 .replace("\033[90m", "").replace("\033[0m", "").replace("\033[1m", "")
                 for k, v in ICONS.items()}

    if args.tokens:
        print(BOLD + "\n  Token Patterns Detected:" + N)
        for name in sorted(TOKEN_PATTERNS.keys()):
            print("    " + C + "\u25b8" + N + " " + name)
        print()
        return

    if not args.keyword:
        parser.print_help()
        print("\n  " + R + "Error: keyword required (or use --tokens to list patterns)" + N + "\n")
        sys.exit(1)

    keyword = " ".join(args.keyword)
    banner(keyword)

    results = search_github(keyword, max_results=args.count, language=args.language)

    if not results:
        print("\n  " + D + "No results found." + N + "\n")
        return

    if args.json:
        print(json.dumps(results, indent=2))
        return

    for i, repo in enumerate(results):
        num = i + 1
        risk, risk_score = scan_quick(repo["name"], repo.get("description", ""), repo.get("topics", []))
        icon = ICONS.get(risk, "  ")

        print("  {}. {} {}".format(BOLD + str(num) + N, repo["name"], icon))
        print(
            "     "
            + Y + "\u2605 " + str(repo["stars"]) + N
            + " | " + C + str(repo.get("language", "?")) + N
            + " | " + D + "pushed " + str(repo["pushed"]) + N
        )

        desc = repo.get("description", "")
        if desc:
            print("     " + desc[:120])

        if args.scan and risk in ("MEDIUM_RISK", "HIGH_RISK"):
            print("     " + R + BOLD + risk + N + " " + D + "(score: " + str(risk_score) + ")" + N)

        print("     " + B + repo["url"] + N)

        if args.scan:
            if args.deep:
                print("     " + D + "\u25b9 deep scanning..." + N)
                parts = repo["name"].split("/")
                deep_score, deep_findings = clone_and_scan(
                    repo["clone_url"], branch=repo.get("default_branch", "main")
                )
                if deep_findings:
                    shown = 0
                    for f in deep_findings:
                        if shown >= 8:
                            remaining = len(deep_findings) - 8
                            if remaining > 0:
                                print("      " + D + "... +" + str(remaining) + " more findings" + N)
                            break
                        print_finding(f)
                        shown += 1
                if deep_score == 0 and not any(
                    "CLONE_FAILED" in x or "GIT_MISSING" in x for x in deep_findings
                ):
                    print("      " + G + "\u2713 clean" + N)
            else:
                parts = repo["name"].split("/")
                readme = fetch_readme(parts[0], parts[1])
                if readme:
                    score, findings = scan_code_snippet(readme, "README.md")
                    for f in findings[:3]:
                        print_finding(f)
                else:
                    print("     " + D + "(no README found)" + N)

        print()

    print("  " + D + "Found " + str(len(results)) + " results" + N)
    if args.deep:
        print("  " + R + BOLD + "\u2620  Deep scan mode active — cloned & scanned all files" + N)
    print()


if __name__ == "__main__":
    main()

"""GitHub repository search engine."""

import json
import os
import urllib.request
import urllib.parse


def _get_token():
    tok = os.environ.get("GITHUB_TOKEN", "")
    if tok:
        return tok
    for p in [
        os.path.expanduser("~/.repohound/token"),
        os.path.expanduser("~/.config/repohound/token"),
        os.path.expanduser("~/.hermes/tokens/github_renzy.token"),
        os.path.expanduser("~/.hermes/tokens/github.token"),
    ]:
        if os.path.exists(p):
            with open(p) as f:
                return f.read().strip()
    return ""


def search_github(keyword, max_results=20, language=None):
    """Search GitHub repositories by keyword."""
    q = keyword
    if language:
        q = q + " language:" + language

    token = _get_token()
    params = {
        "q": q,
        "sort": "stars",
        "order": "desc",
        "per_page": str(max_results),
    }
    url = "https://api.github.com/search/repositories?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "repohound")
    if token:
        req.add_header("Authorization", "Bearer " + token)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return []

    if "items" not in data:
        return []

    results = []
    for repo in data["items"]:
        results.append(
            dict(
                name=repo["full_name"],
                url=repo["html_url"],
                stars=repo["stargazers_count"],
                language=repo.get("language", "?"),
                description=(repo.get("description") or "")[:200],
                pushed=repo["pushed_at"][:10],
                topics=repo.get("topics", []),
                clone_url=repo["clone_url"],
                default_branch=repo["default_branch"],
            )
        )
    return results

"""Security scanner — malware, tokens, suspicious patterns."""
import re

TOKEN_PATTERNS = {
    "GitHub PAT": r"ghp_[A-Za-z0-9]{36}",
    "GitHub OAuth": r"gho_[A-Za-z0-9]{36}",
    "Discord Webhook": r"https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
    "Discord Bot Token": r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+]{40}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Secret": r"sk_live_[0-9a-zA-Z]{24}",
    "Private SSH Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
    "Telegram Bot Token": r"\d{9,10}:AA[A-Za-z0-9\-_]{33}",
}

MALWARE_PATTERNS = {
    "obfuscated_eval": r"eval\s*\(\s*(atob|btoa|unescape|String\.fromCharCode|base64)",
    "encoded_payload": r"(base64\.b64decode|from base64 import|atob\(|btoa\()",
    "reverse_shell": r"(bash -i >&|nc -e /bin/sh|/dev/tcp/)",
    "crypto_miner": r"(stratum\+tcp://|xmr-stak|minerd|xmrig|coinhive)",
    "stealer_webhook": r"(fetch|axios|requests)\.(post|get)\(.*webhook",
    "auto_run_registry": r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "suspicious_curl_bash": r"curl\s+.*\s*\|\s*(bash|sh|python)",
    "process_injection": r"(VirtualAlloc|WriteProcessMemory|CreateRemoteThread)",
    "keylogger_import": r"(pynput|xlib|pyHook|keyboard|GetAsyncKeyState)",
    "hidden_window": r"SW_HIDE|SW_SHOWMINIMIZED|CREATE_NO_WINDOW",
}

WEIGHTS = {
    "token_leak": 10,
    "obfuscated_eval": 8,
    "reverse_shell": 10,
    "crypto_miner": 10,
    "stealer_webhook": 9,
    "suspicious_curl_bash": 7,
    "base64_blob": 3,
}

def scan_code_snippet(code, filename=""):
    """Scan a code snippet for threats. Returns (score, findings)."""
    findings = []
    score = 0
    for name, pattern in TOKEN_PATTERNS.items():
        matches = re.findall(pattern, code, re.IGNORECASE | re.MULTILINE)
        for match in matches[:3]:
            masked = match[:6] + "..." + match[-4:] if len(match) > 12 else match
            findings.append("TOKEN: " + name + " in " + filename + " (" + masked + ")")
            score += WEIGHTS.get("token_leak", 10)
    for name, pattern in MALWARE_PATTERNS.items():
        matches = re.findall(pattern, code, re.IGNORECASE | re.MULTILINE)
        if matches:
            findings.append("MALWARE: " + name + " in " + filename)
            score += WEIGHTS.get(name, 5)
    b64 = re.findall(r"[A-Za-z0-9+/]{500,}={0,2}", code)
    if b64:
        findings.append("SUSPICIOUS: large base64 blob (" + str(len(b64[0])) + " chars)")
        score += WEIGHTS.get("base64_blob", 3)
    return score, findings

def scan_quick(name, desc, topics):
    """Pre-scan based on metadata. Returns (risk_level, score)."""
    risk = 0
    text = name + " " + (desc or "") + " " + " ".join(topics or [])
    flags = ["stealer", "token grabber", "crack", "keygen", "keylogger",
             "rat ", "botnet", "exploit", "malware", "virus", "trojan",
             "miner", "phishing", "backdoor", "rootkit"]
    for flag in flags:
        if flag.lower() in text.lower():
            risk += 25
    if risk >= 50:
        return "HIGH_RISK", risk
    elif risk >= 25:
        return "MEDIUM_RISK", risk
    return "LOW_RISK", risk

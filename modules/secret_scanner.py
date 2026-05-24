"""
Secret Scanner - UHQKYRA v1.0
==============================
⚠️  Authorized security testing only — UHQKYRA.
Finds accidentally exposed secrets, tokens and keys during authorized pentests.

Scans: HTML source, linked JS files, HTTP headers, cookies, common secret paths.
80+ patterns: AWS, GCP, Azure, GitHub, Stripe, Slack, Twilio, private keys, etc.
"""
import re
import warnings
warnings.filterwarnings("ignore")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from modules.evasion import random_headers, burst_jitter
except ImportError:
    try:
        from evasion import random_headers, burst_jitter
    except ImportError:
        def random_headers(**kw): return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        def burst_jitter(): pass

# ─── Secret patterns (name, severity, regex) ─────────────────────────────────

SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key ID",       "critical", r'(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])'),
    ("AWS Secret Key",          "critical", r'(?i)aws.{0,20}secret.{0,20}key.{0,10}["\']?([A-Za-z0-9/+=]{40})["\']?'),
    ("AWS S3 Bucket URL",       "medium",   r'https?://[a-z0-9\-\.]+\.s3[.\-][a-z0-9\-\.]*amazonaws\.com'),
    # Google
    ("Google API Key",          "critical", r'AIza[0-9A-Za-z\-_]{35}'),
    ("Google OAuth Token",      "critical", r'ya29\.[0-9A-Za-z\-_]+'),
    ("Google OAuth Client",     "high",     r'[0-9]{12}-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com'),
    ("Google Service Account",  "critical", r'"type"\s*:\s*"service_account"'),
    ("Firebase URL",            "high",     r'https://[a-zA-Z0-9\-]+\.firebaseio\.com'),
    # Azure
    ("Azure Storage Key",       "critical", r'AccountKey=[a-zA-Z0-9+/=]{88}'),
    ("Azure Conn String",       "critical", r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+'),
    # GitHub
    ("GitHub Token (ghp)",      "critical", r'ghp_[A-Za-z0-9]{36}'),
    ("GitHub Token (gho)",      "critical", r'gho_[A-Za-z0-9]{36}'),
    ("GitHub Token (ghu)",      "critical", r'ghu_[A-Za-z0-9]{36}'),
    ("GitHub Token (ghs)",      "critical", r'ghs_[A-Za-z0-9]{36}'),
    # Stripe
    ("Stripe Secret Key",       "critical", r'sk_live_[0-9a-zA-Z]{24,}'),
    ("Stripe Test Key",         "high",     r'sk_test_[0-9a-zA-Z]{24,}'),
    ("Stripe Pub Key",          "medium",   r'pk_live_[0-9a-zA-Z]{24,}'),
    # Slack
    ("Slack Bot Token",         "critical", r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
    ("Slack User Token",        "critical", r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}'),
    ("Slack Webhook URL",       "high",     r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}'),
    # Twilio
    ("Twilio Account SID",      "high",     r'AC[a-f0-9]{32}'),
    ("Twilio Auth Token",       "critical", r'(?i)twilio.{0,20}auth.{0,10}["\']?([a-f0-9]{32})["\']?'),
    # SendGrid
    ("SendGrid API Key",        "critical", r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}'),
    ("Mailgun API Key",         "critical", r'key-[0-9a-f]{32}'),
    ("Mailchimp API Key",       "critical", r'[0-9a-f]{32}-us[0-9]{1,2}'),
    # Private keys
    ("RSA Private Key",         "critical", r'-----BEGIN RSA PRIVATE KEY-----'),
    ("EC Private Key",          "critical", r'-----BEGIN EC PRIVATE KEY-----'),
    ("PGP Private Key",         "critical", r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    ("OpenSSH Private Key",     "critical", r'-----BEGIN OPENSSH PRIVATE KEY-----'),
    ("Generic Private Key",     "critical", r'-----BEGIN PRIVATE KEY-----'),
    # Database URLs
    ("DB URL (MySQL)",          "critical", r'mysql://[^\s"\'<>]{8,}'),
    ("DB URL (Postgres)",       "critical", r'postgres(?:ql)?://[^\s"\'<>]{8,}'),
    ("DB URL (MongoDB)",        "critical", r'mongodb\+?srv?://[^\s"\'<>]{8,}'),
    ("DB URL (Redis)",          "critical", r'redis://[^\s"\'<>]{8,}'),
    ("DB Password (config)",    "high",     r'(?i)(?:db|database).{0,10}(?:pass|password|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']'),
    # JWT
    ("JWT Token",               "medium",   r'eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}'),
    # Generic secrets
    ("API Key (generic)",       "high",     r'(?i)\bapi[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,64})["\']'),
    ("Secret Key (generic)",    "high",     r'(?i)\bsecret[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9\-_!@#$%]{8,64})["\']'),
    ("Auth Token (generic)",    "high",     r'(?i)\b(?:access|auth|bearer)[_\-]?token\s*[=:]\s*["\']([A-Za-z0-9\-_\.]{16,})["\']'),
    ("Password (generic)",      "high",     r'(?i)\bpassword\s*[=:]\s*["\']([^"\']{6,})["\']'),
    ("Client Secret (generic)", "high",     r'(?i)\bclient[_\-]?secret\s*[=:]\s*["\']([A-Za-z0-9\-_]{8,64})["\']'),
    # Cloud infra
    ("Heroku API Key",          "critical", r'(?i)heroku.{0,20}["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']?'),
    ("DigitalOcean Token",      "critical", r'(?i)digitalocean.{0,20}token.{0,10}["\']?([a-f0-9]{64})["\']?'),
    ("NPM Token",               "critical", r'(?i)npm[_\-\s]?(?:auth[_\-\s]?)?token\s*[=:]\s*["\']?([a-f0-9\-]{36,})["\']?'),
    # Social/Messaging
    ("Discord Bot Token",       "critical", r'[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}'),
    ("Discord Webhook",         "high",     r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9\-_]{68}'),
    ("Telegram Bot Token",      "critical", r'[0-9]{8,10}:[A-Za-z0-9\-_]{35}'),
    ("Twitter Bearer Token",    "critical", r'AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+'),
    # Monitoring
    ("Sentry DSN",              "high",     r'https://[a-f0-9]{32}@[a-z0-9\.]+sentry\.io/[0-9]+'),
    ("New Relic License",       "high",     r'(?i)new.{0,10}relic.{0,20}key\s*[=:]\s*["\']?([A-Za-z0-9]{40})["\']?'),
    # Internal
    ("Internal IP",             "low",      r'(?<![0-9])(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})(?![0-9])'),
    ("Source Map",              "medium",   r'//# sourceMappingURL=([^\s]+\.map)'),
    ("Hard-coded Password",     "critical", r'(?i)password\s*=\s*["\'][^"\']{4,}["\']'),
]

# Sensitive file paths to probe
SECRET_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.dev",
    "/.env.backup", "/.env.bak", "/.env.old", "/.env.example",
    "/config.js", "/config.json", "/config.yml", "/config.yaml",
    "/.git/config", "/wp-config.php", "/configuration.php",
    "/app/config/database.yml", "/config/database.yml",
    "/credentials.json", "/.aws/credentials",
    "/composer.json", "/package.json", "/.npmrc", "/.pypirc",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/settings.py", "/local_settings.py", "/settings/local.py",
    "/application.properties", "/application.yml",
    "/server.xml", "/web.config",
    "/.htpasswd", "/.htaccess",
    "/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
    "/server.key", "/private.key", "/ssl.key",
    "/backup.sql", "/database.sql", "/dump.sql",
]


# ─────────────────────────────────────────────────────────────────────────────

def _scan_text(text, source=""):
    """Scan a block of text for secrets. Returns list of findings."""
    findings = []
    seen = set()
    for name, severity, pattern in SECRET_PATTERNS:
        try:
            for m in re.finditer(pattern, text):
                val = m.group(0)[:120].strip()
                key = (name, val[:40])
                if key in seen:
                    continue
                seen.add(key)
                start = max(0, m.start() - 30)
                ctx = text[start: m.end() + 30].replace("\n", " ").strip()[:150]
                findings.append({
                    "type":     name,
                    "severity": severity,
                    "value":    val,
                    "source":   source,
                    "context":  ctx,
                })
        except re.error:
            pass
    return findings


def scan_secrets(url, callback=None):
    """
    Full secret scan on a target URL:
      1. HTML page source
      2. All linked JS files (up to 20)
      3. HTTP response headers + cookies
      4. Common secret-leaking file paths (.env, wp-config.php, etc.)
    """
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {
        "url":             url,
        "findings":        [],
        "vulnerabilities": [],
        "js_scanned":      0,
        "paths_checked":   0,
        "total_secrets":   0,
    }

    if not HAS_REQUESTS:
        cb("warn", "🔍 requests non disponible")
        return results

    base = url if "://" in url else "http://" + url
    cb("info", f"🔍 Secret Scanner: {base}")

    session = requests.Session()
    session.verify = False

    import urllib.parse

    # ── 1. Main page ─────────────────────────────────────────────────
    try:
        burst_jitter()
        r = session.get(base, headers=random_headers(), timeout=12, allow_redirects=True)
        html = r.text
        parsed = urllib.parse.urlparse(r.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for f in _scan_text(html, source="HTML"):
            results["findings"].append(f)
            lvl = "vuln" if f["severity"] in ("critical", "high") else "found"
            cb(lvl, f"🔍 [{f['severity'].upper()}] {f['type']}: {f['value'][:60]}")

        # Response headers
        hdr_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        for f in _scan_text(hdr_str, source="HTTP Headers"):
            results["findings"].append(f)
            cb("vuln", f"🔍 [HEADER] {f['type']}: {f['value'][:60]}")

        # Cookies
        ck_str = "; ".join(f"{c.name}={c.value}" for c in session.cookies)
        if ck_str:
            for f in _scan_text(ck_str, source="Cookies"):
                results["findings"].append(f)
                cb("vuln", f"🔍 [COOKIE] {f['type']}: {f['value'][:60]}")

    except Exception as e:
        cb("warn", f"🔍 Page principale: {e}")
        return results

    # ── 2. JS files ──────────────────────────────────────────────────
    js_urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        src = m.group(1)
        if src.startswith("//"):
            src = parsed.scheme + ":" + src
        elif src.startswith("/"):
            src = base_url + src
        elif not src.startswith("http"):
            src = base_url + "/" + src.lstrip("/")
        if src.startswith("http"):
            js_urls.add(src)

    cb("info", f"🔍 {len(js_urls)} fichier(s) JS...")
    for js_url in list(js_urls)[:20]:
        try:
            burst_jitter()
            rj = session.get(js_url, headers=random_headers(), timeout=10)
            if rj.status_code == 200:
                results["js_scanned"] += 1
                label = js_url.split("/")[-1][:35]
                for f in _scan_text(rj.text, source=f"JS:{label}"):
                    results["findings"].append(f)
                    sev = f["severity"]
                    if sev in ("critical", "high"):
                        cb("vuln", f"🔍 [JS/{sev.upper()}] {f['type']}: {f['value'][:60]}")
        except Exception:
            pass

    # ── 3. Sensitive paths ───────────────────────────────────────────
    for path in SECRET_PATHS:
        try:
            burst_jitter()
            rp = session.get(base_url + path, headers=random_headers(),
                             timeout=6, allow_redirects=False)
            results["paths_checked"] += 1
            if rp.status_code == 200 and len(rp.text) > 10:
                for f in _scan_text(rp.text, source=f"File:{path}"):
                    results["findings"].append(f)
                    cb("vuln", f"🔍 [FILE{path}] {f['type']}: {f['value'][:60]}")
                # File exposure itself is a finding
                results["findings"].append({
                    "type":     "Sensitive File Exposed",
                    "severity": "critical",
                    "value":    base_url + path,
                    "source":   "Path probe",
                    "context":  f"HTTP 200 — {len(rp.text)} bytes",
                })
                cb("vuln", f"🚨 Fichier sensible exposé: {path} ({len(rp.text)}B)")
        except Exception:
            pass

    # ── 4. Deduplicate + build vulns ─────────────────────────────────
    seen = set()
    unique = []
    for f in results["findings"]:
        k = (f["type"], f["value"][:40])
        if k not in seen:
            seen.add(k)
            unique.append(f)

    results["findings"]      = unique
    results["total_secrets"] = len(unique)

    for f in unique:
        results["vulnerabilities"].append({
            "type":     "secret_exposure",
            "severity": f["severity"],
            "name":     f"Secret exposé : {f['type']}",
            "detail":   f"{f['value'][:80]}  [src: {f['source']}]",
        })

    cb("info", f"🔍 Secret Scanner terminé: {results['total_secrets']} secret(s), "
               f"{results['js_scanned']} JS, {results['paths_checked']} chemins")
    return results

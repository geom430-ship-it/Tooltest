"""
JavaScript Analyzer Module - UHQKYRA
Extract API endpoints, secrets, emails, and intelligence from JS files
"""
import requests
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings("ignore")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# (name, pattern)
SECRET_PATTERNS = [
    ("AWS Access Key",      r'AKIA[0-9A-Z]{16}'),
    ("AWS Secret Key",      r'(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
    ("Google API Key",      r'AIza[0-9A-Za-z\-_]{35}'),
    ("Google OAuth",        r'[0-9]{12}-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com'),
    ("Firebase URL",        r'https://[a-zA-Z0-9\-]+\.firebaseio\.com'),
    ("GitHub Token",        r'gh[pousr]_[A-Za-z0-9]{36,255}'),
    ("GitHub OAuth",        r'gho_[A-Za-z0-9]{36}'),
    ("Stripe Live Key",     r'sk_live_[0-9a-zA-Z]{24,}'),
    ("Stripe Pub Key",      r'pk_live_[0-9a-zA-Z]{24,}'),
    ("Twilio SID",          r'AC[a-z0-9]{32}'),
    ("Twilio Token",        r'SK[a-z0-9]{32}'),
    ("Slack Bot Token",     r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
    ("Slack User Token",    r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}'),
    ("Slack Webhook",       r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
    ("JWT Token",           r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    ("Private Key",         r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY'),
    ("Hardcoded Password",  r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']'),
    ("API Key Generic",     r'(?i)api[_-]?key\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']'),
    ("Secret Generic",      r'(?i)(?:secret|auth_secret)\s*[=:]\s*["\'][A-Za-z0-9_\-]{8,}["\']'),
    ("Access Token",        r'(?i)access[_-]?token\s*[=:]\s*["\'][A-Za-z0-9_\-\.]{20,}["\']'),
    ("DB Connection",       r'(?i)(mysql|postgres|mongodb|redis|mssql):\/\/[^\s"\'<>{}\[\]]+'),
    ("Heroku API Key",      r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),
    ("Mailchimp Key",       r'[0-9a-f]{32}-us[0-9]{1,2}'),
    ("SendGrid Key",        r'SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}'),
    ("PayPal Token",        r'access_token\$production\$[a-z0-9]+\$[a-f0-9]+'),
    ("NPM Token",           r'npm_[A-Za-z0-9]{36}'),
    ("Telegram Bot Token",  r'[0-9]{8,10}:[A-Za-z0-9_-]{35}'),
]

ENDPOINT_PATTERNS = [
    r'["\`](/api/[A-Za-z0-9_/\-?=&.]+)["\`]',
    r'["\`](/v[0-9]+/[A-Za-z0-9_/\-?=&.]+)["\`]',
    r'["\`](/graphql[A-Za-z0-9_/\-?=&.]*)["\`]',
    r'["\`](/rest/[A-Za-z0-9_/\-?=&.]+)["\`]',
    r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(["\`]([^"\'`\s]+)["\`]',
    r'(?:url|endpoint|baseURL|API_URL|apiUrl)\s*[=:]\s*["\`]([^"\'`\s]{5,})["\`]',
    r'(?:get|post|put|delete|patch)\s*\(["\`](/[^"\'`\s]{3,})["\`]',
]

CDN_SKIP = [
    'jquery', 'bootstrap', 'google', 'facebook', 'twitter',
    'cloudflare', 'jsdelivr', 'unpkg', 'cdnjs', 'fontawesome',
    'googleapis', 'gstatic', 'analytics', 'gtag', 'pixel',
]


def analyze_js(url, callback=None):
    """Main JS analysis function"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {
        "js_files_found": 0,
        "js_analyzed": 0,
        "endpoints": [],
        "secrets": [],
        "emails": [],
        "internal_ips": [],
        "interesting_comments": [],
        "source_maps": [],
    }

    if not url.startswith("http"):
        url = "http://" + url

    cb("info", "🔍 Analyse des fichiers JavaScript...")

    try:
        resp = requests.get(url, headers=HEADERS, timeout=12, verify=False, allow_redirects=True)
        html = resp.text

        # Collect JS URLs from HTML
        js_urls = _collect_js_urls(html, url)
        results["js_files_found"] = len(js_urls)
        cb("info", f"📜 {len(js_urls)} fichiers JS trouvés")

        # Also check for source maps
        for js_url in list(js_urls)[:5]:
            map_url = js_url + ".map"
            st_map = _head_check(map_url)
            if st_map == 200:
                results["source_maps"].append(map_url)
                cb("warn", f"⚠️ Source map exposée: {map_url}")

        # Analyze JS files (limit to 20 to avoid timeout)
        js_to_analyze = list(js_urls)[:20]

        with ThreadPoolExecutor(max_workers=6) as executor:
            futs = {executor.submit(_analyze_file, js_url): js_url
                    for js_url in js_to_analyze}
            for fut in as_completed(futs):
                js_url = futs[fut]
                try:
                    file_res = fut.result()
                    results["js_analyzed"] += 1
                    _merge_results(results, file_res, js_url, cb)
                except Exception:
                    pass

        # Analyze inline scripts too
        inline_res = _analyze_content(html)
        _merge_results(results, inline_res, "<inline>", cb)

        # Summary
        if results["secrets"]:
            cb("vuln", f"🚨 {len(results['secrets'])} secret(s) dans les JS !")
        if results["endpoints"]:
            cb("found", f"🔗 {len(results['endpoints'])} endpoint(s) API dans les JS")
        if results["emails"]:
            cb("found", f"📧 {len(results['emails'])} email(s) dans les JS")
        if not results["secrets"] and not results["endpoints"]:
            cb("ok", "✅ Pas de secrets évidents dans les JS")

    except Exception as e:
        cb("warn", f"JS analyze: {e}")

    return results


def _collect_js_urls(html, base_url):
    js_urls = set()
    patterns = [
        r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        r'<script[^>]+src=["\']([^"\']+)["\']',
    ]
    for pat in patterns:
        for m in re.finditer(pat, html, re.I):
            js_url = m.group(1)
            if not js_url.startswith("http"):
                js_url = urljoin(base_url, js_url)
            if any(cdn in js_url.lower() for cdn in CDN_SKIP):
                continue
            if not js_url.endswith((".css", ".png", ".jpg", ".svg", ".ico")):
                js_urls.add(js_url)
    return js_urls


def _head_check(url):
    try:
        r = requests.head(url, headers=HEADERS, timeout=5, verify=False)
        return r.status_code
    except Exception:
        return None


def _analyze_file(js_url):
    try:
        r = requests.get(js_url, headers=HEADERS, timeout=10, verify=False)
        if r.status_code == 200:
            return _analyze_content(r.text)
    except Exception:
        pass
    return {}


def _analyze_content(content):
    res = {
        "secrets": [],
        "endpoints": [],
        "emails": [],
        "internal_ips": [],
        "interesting_comments": [],
    }

    # Secrets
    for stype, pattern in SECRET_PATTERNS:
        for m in re.finditer(pattern, content):
            val = m.group(0)
            if len(val) > 8 and val not in [s["value"] for s in res["secrets"]]:
                res["secrets"].append({"type": stype, "value": val[:300]})

    # Endpoints
    for pat in ENDPOINT_PATTERNS:
        for m in re.finditer(pat, content):
            ep = m.group(1) if m.lastindex else m.group(0)
            if ep and len(ep) > 3 and ep not in res["endpoints"]:
                if not any(skip in ep.lower() for skip in ['cdn', 'fonts', 'analytics', 'pixel']):
                    res["endpoints"].append(ep)

    # Emails
    for m in re.finditer(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', content):
        email = m.group(0)
        if email not in res["emails"]:
            if not any(x in email.lower() for x in ['example', 'sentry', 'karma', 'bower', 'eslint', 'webpack']):
                res["emails"].append(email)

    # Internal IPs
    for m in re.finditer(
        r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})',
        content
    ):
        ip = m.group(0)
        if ip not in res["internal_ips"]:
            res["internal_ips"].append(ip)

    # Interesting comments
    for m in re.finditer(r'/\*\*?(.{10,200})\*/', content, re.S):
        comment = m.group(1).strip()
        if any(kw in comment.lower() for kw in ['todo', 'hack', 'fixme', 'password', 'secret', 'debug', 'backdoor', 'key', 'token']):
            res["interesting_comments"].append(comment[:200])

    return res


def _merge_results(results, file_res, source, cb):
    if not file_res:
        return
    for s in file_res.get("secrets", []):
        exists = any(x["value"] == s["value"] for x in results["secrets"])
        if not exists:
            results["secrets"].append({**s, "source": source})
            cb("vuln", f"🚨 SECRET [{s['type']}]: {s['value'][:60]}")
    for ep in file_res.get("endpoints", []):
        if ep not in results["endpoints"]:
            results["endpoints"].append(ep)
    for em in file_res.get("emails", []):
        if em not in results["emails"]:
            results["emails"].append(em)
    for ip in file_res.get("internal_ips", []):
        if ip not in results["internal_ips"]:
            results["internal_ips"].append(ip)
            cb("warn", f"⚠️ IP interne dans JS: {ip}")
    for c in file_res.get("interesting_comments", []):
        if c not in results["interesting_comments"]:
            results["interesting_comments"].append(c)

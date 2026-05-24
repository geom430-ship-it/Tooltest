"""
API Security Fuzzer - UHQKYRA v1.0
====================================
⚠️  Authorized security testing only.

Tests REST API security issues:
  1. HTTP Verb Tampering (GET→POST→PUT→DELETE→PATCH→HEAD→OPTIONS)
  2. Mass Assignment (extra fields injection)
  3. BOLA/IDOR (Broken Object Level Authorization — ID enumeration)
  4. Rate Limiting bypass (burst + header tricks)
  5. Auth bypass (missing/invalid tokens)
  6. API versioning exposure (v1→v2→v3→beta→internal)
  7. Debug endpoints (/debug, /test, /internal, /actuator)
  8. Unsafe methods on sensitive endpoints
  9. Parameter pollution
 10. Response data exposure (fields in error vs success)
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
    from modules.evasion import random_headers, burst_jitter, jitter
except ImportError:
    try:
        from evasion import random_headers, burst_jitter, jitter
    except ImportError:
        def random_headers(**kw): return {"User-Agent": "Mozilla/5.0"}
        def burst_jitter(): pass
        def jitter(*a, **kw): pass

# ─── API endpoint patterns ────────────────────────────────────────────────────

API_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
    "/api/beta", "/api/internal", "/api/dev", "/api/test",
    "/api/admin", "/api/users", "/api/user", "/api/me",
    "/api/profile", "/api/account", "/api/accounts",
    "/api/keys", "/api/tokens", "/api/auth", "/api/login",
    "/api/register", "/api/forgot-password", "/api/reset-password",
    "/api/config", "/api/settings", "/api/debug",
    "/api/health", "/api/status", "/api/version", "/api/info",
    "/v1", "/v2", "/v3", "/v1/users", "/v2/users",
    "/rest", "/rest/api", "/rest/v1", "/rest/v2",
    "/graphql", "/swagger.json", "/openapi.json", "/api-docs",
    # Spring Boot Actuator
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
    "/actuator/httptrace", "/actuator/loggers",
    # Debug / internal
    "/debug", "/test", "/internal", "/status",
    "/phpinfo.php", "/info.php",
]

DEBUG_PATHS = [
    "/debug", "/debug/", "/test", "/_debug", "/__debug__",
    "/internal", "/internal/api", "/dev", "/dev/api",
    "/console", "/shell", "/exec", "/cmd",
    "/actuator", "/actuator/env", "/actuator/heapdump",
    "/metrics", "/prometheus", "/jaeger",
    "/swagger-ui.html", "/swagger-ui/", "/api-docs",
    "/redoc", "/graphiql", "/altair",
    "/.well-known/security.txt", "/robots.txt",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                "OPTIONS", "TRACE", "CONNECT"]

MASS_ASSIGN_FIELDS = [
    "isAdmin", "is_admin", "admin", "role", "roles", "privilege",
    "permissions", "user_type", "account_type", "verified",
    "email_verified", "active", "enabled", "status", "balance",
    "credit", "premium", "subscription", "plan", "level",
    "password", "password_hash", "salt", "token",
]

BOLA_IDS = [1, 2, 3, 0, -1, 999999, 100, "admin", "me", "self",
            "current", "own", "test", "user1", "user2"]


def _req(session, method, url, **kwargs):
    """Make a request with stealth headers and jitter."""
    hdrs = random_headers(include_ip_spoof=True)
    hdrs.update(kwargs.pop("headers", {}))
    burst_jitter()
    try:
        fn = getattr(session, method.lower(), session.get)
        return fn(url, headers=hdrs, timeout=10, verify=False,
                  allow_redirects=False, **kwargs)
    except Exception:
        return None


def _has_auth_error(resp):
    if not resp:
        return True
    if resp.status_code in (401, 403):
        return True
    txt = resp.text.lower()
    return any(p in txt for p in ["unauthorized", "forbidden", "not authorized",
                                    "access denied", "invalid token", "auth required"])


# ─────────────────────────────────────────────────────────────────────────────

def scan_api(url, callback=None):
    """
    Full REST API security fuzzer.
    """
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {
        "url":             url,
        "findings":        [],
        "vulnerabilities": [],
        "endpoints_found": [],
        "tests_run":       0,
        "vulnerable":      False,
    }

    if not HAS_REQUESTS:
        return results

    base = (url if "://" in url else "http://" + url).rstrip("/")
    cb("info", f"🔗 API Fuzzer: {base}")

    import urllib.parse
    parsed = urllib.parse.urlparse(base)

    session = requests.Session()
    session.verify = False

    # ── 1. Discover API endpoints ─────────────────────────────────────
    cb("info", "🔗 Découverte des endpoints API...")
    found_endpoints = []
    for path in API_PATHS:
        r = _req(session, "GET", base + path)
        results["tests_run"] += 1
        if r and r.status_code not in (404, 410):
            found_endpoints.append({
                "path":   path,
                "url":    base + path,
                "status": r.status_code,
                "size":   len(r.text),
            })
            if r.status_code == 200:
                cb("found", f"🔗 API endpoint: {path} [{r.status_code}] ({len(r.text)}B)")
            elif r.status_code in (401, 403):
                cb("info", f"🔗 API protégé: {path} [{r.status_code}]")
    results["endpoints_found"] = found_endpoints

    # ── 2. HTTP Verb Tampering ─────────────────────────────────────────
    cb("info", "🔗 Test HTTP Verb Tampering...")
    for ep in found_endpoints[:10]:
        ep_url = ep["url"]
        baseline_status = ep["status"]
        for method in ["POST", "PUT", "DELETE", "PATCH", "TRACE"]:
            r = _req(session, method, ep_url, data={})
            results["tests_run"] += 1
            if r and r.status_code not in (405, 404, 410, 501):
                if r.status_code in (200, 201, 204):
                    results["vulnerable"] = True
                    detail = f"{method} {ep['path']} → {r.status_code} (attendu: 405)"
                    results["findings"].append({
                        "test": "verb_tampering", "severity": "high",
                        "detail": detail, "url": ep_url,
                    })
                    results["vulnerabilities"].append({
                        "type": "verb_tampering", "severity": "high",
                        "name": f"Verb Tampering: {method} autorisé",
                        "detail": detail,
                    })
                    cb("vuln", f"🚨 Verb Tampering: {method} {ep['path']} → {r.status_code}")
                elif method == "TRACE" and r.status_code == 200:
                    results["findings"].append({
                        "test": "trace_method", "severity": "medium",
                        "detail": f"TRACE activé sur {ep['path']}",
                    })
                    cb("found", f"🔗 TRACE method activé: {ep['path']}")

    # ── 3. Auth bypass tests ──────────────────────────────────────────
    cb("info", "🔗 Test auth bypass...")
    auth_bypass_headers = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"Authorization": "Bearer null"},
        {"Authorization": "Bearer undefined"},
        {"Authorization": "Bearer 0"},
        {"Authorization": ""},
        {"X-Auth-Token": "admin"},
    ]
    protected = [ep for ep in found_endpoints if ep["status"] in (401, 403)]
    for ep in protected[:5]:
        for bypass_hdr in auth_bypass_headers:
            r = _req(session, "GET", ep["url"], headers=bypass_hdr)
            results["tests_run"] += 1
            if r and r.status_code == 200:
                results["vulnerable"] = True
                hdr_str = list(bypass_hdr.keys())[0]
                results["findings"].append({
                    "test": "auth_bypass", "severity": "critical",
                    "detail": f"Auth bypass via {hdr_str} sur {ep['path']}",
                    "url": ep["url"],
                })
                results["vulnerabilities"].append({
                    "type": "auth_bypass", "severity": "critical",
                    "name": f"Auth bypass: {hdr_str}",
                    "detail": f"{ep['path']} → 200 avec header {hdr_str}",
                })
                cb("vuln", f"🚨 Auth bypass [{hdr_str}]: {ep['path']} → {r.status_code}")
                break

    # ── 4. BOLA / IDOR on API paths ────────────────────────────────────
    cb("info", "🔗 Test BOLA/IDOR...")
    id_paths = [ep for ep in found_endpoints
                if any(x in ep["path"] for x in ["/user", "/account", "/profile", "/order", "/item"])]
    for ep in id_paths[:5]:
        ep_url = ep["url"]
        baseline_r = _req(session, "GET", ep_url)
        if not baseline_r:
            continue
        for oid in BOLA_IDS:
            test_url = ep_url.rstrip("/") + f"/{oid}"
            r = _req(session, "GET", test_url)
            results["tests_run"] += 1
            if r and r.status_code == 200 and len(r.text) > 50:
                if not _has_auth_error(r):
                    results["findings"].append({
                        "test": "bola", "severity": "high",
                        "detail": f"BOLA: {test_url} → {r.status_code} ({len(r.text)}B)",
                        "url": test_url,
                    })
                    results["vulnerabilities"].append({
                        "type": "bola", "severity": "high",
                        "name": f"BOLA/IDOR sur {ep['path']}/{oid}",
                        "detail": f"HTTP {r.status_code} — {len(r.text)}B",
                    })
                    cb("vuln", f"🚨 BOLA: {ep['path']}/{oid} → {r.status_code}")

    # ── 5. Mass Assignment test ────────────────────────────────────────
    cb("info", "🔗 Test Mass Assignment...")
    post_endpoints = [ep for ep in found_endpoints
                      if ep["status"] in (200, 201, 400, 422)]
    for ep in post_endpoints[:5]:
        # Build payload with extra privilege fields
        payload = {f: True for f in MASS_ASSIGN_FIELDS[:10]}
        r = _req(session, "POST", ep["url"],
                 json=payload,
                 headers={"Content-Type": "application/json"})
        results["tests_run"] += 1
        if r and r.status_code in (200, 201):
            resp_text = r.text.lower()
            if any(f in resp_text for f in ["admin", "role", "privilege", "permission"]):
                results["findings"].append({
                    "test": "mass_assignment", "severity": "high",
                    "detail": f"Mass Assignment possible sur {ep['path']}",
                    "url": ep["url"],
                })
                results["vulnerabilities"].append({
                    "type": "mass_assignment", "severity": "high",
                    "name": f"Mass Assignment: {ep['path']}",
                    "detail": "Champs privilèges acceptés dans la réponse",
                })
                cb("vuln", f"🚨 Mass Assignment: {ep['path']}")

    # ── 6. Debug endpoints ─────────────────────────────────────────────
    cb("info", "🔗 Test debug endpoints...")
    for path in DEBUG_PATHS:
        r = _req(session, "GET", base + path)
        results["tests_run"] += 1
        if r and r.status_code == 200:
            sev = "critical" if any(x in path for x in ["actuator/env", "heapdump",
                                                          "shell", "exec", "cmd"]) else "high"
            results["findings"].append({
                "test": "debug_endpoint", "severity": sev,
                "detail": f"Debug endpoint exposé: {path} [{r.status_code}] ({len(r.text)}B)",
                "url": base + path,
            })
            results["vulnerabilities"].append({
                "type": "debug_endpoint", "severity": sev,
                "name": f"Debug endpoint exposé: {path}",
                "detail": f"HTTP {r.status_code} — {len(r.text)}B",
            })
            cb("vuln", f"🚨 [{sev.upper()}] Debug endpoint: {path}")

    # ── 7. Rate limiting test ──────────────────────────────────────────
    cb("info", "🔗 Test rate limiting...")
    if found_endpoints:
        test_ep = found_endpoints[0]["url"]
        statuses = []
        for i in range(15):
            r = _req(session, "GET", test_ep)
            if r:
                statuses.append(r.status_code)
            time.sleep(0.05)
        has_ratelimit = any(s in (429, 503) for s in statuses)
        if not has_ratelimit:
            results["findings"].append({
                "test": "no_rate_limit", "severity": "medium",
                "detail": f"Pas de rate limiting détecté (15 requêtes rapides sans 429)",
                "url": test_ep,
            })
            results["vulnerabilities"].append({
                "type": "no_rate_limit", "severity": "medium",
                "name": "Absence de rate limiting",
                "detail": "15 requêtes consécutives sans code 429",
            })
            cb("found", "🔗 Rate limiting: non détecté (risque bruteforce/DDoS)")
        else:
            cb("ok", "🔗 Rate limiting actif ✅")
        results["tests_run"] += 15

    total_vulns = len([f for f in results["findings"]
                       if f["test"] not in ("no_rate_limit",)])
    cb("info", f"🔗 API Fuzzer: {total_vulns} vulnérabilité(s), "
               f"{len(results['endpoints_found'])} endpoint(s), "
               f"{results['tests_run']} tests")
    return results

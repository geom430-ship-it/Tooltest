"""
CORS Misconfiguration Scanner - UHQKYRA v1.0
=============================================
⚠️  Authorized security testing only.

Tests for CORS misconfigurations:
  1. Wildcard origin (*) with credentials
  2. Origin reflection (any Origin header echoed back)
  3. Null origin bypass
  4. Subdomain wildcard (*.victim.com)
  5. Pre-flight bypass (non-simple methods)
  6. Trusted subdomains that can be taken over
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
        def random_headers(**kw): return {"User-Agent": "Mozilla/5.0"}
        def burst_jitter(): pass

# Malicious origins to test
_EVIL_ORIGINS = [
    "null",
    "https://evil.com",
    "https://attacker.com",
    "http://localhost",
    "http://127.0.0.1",
    "https://victim.evil.com",   # filled in with real domain below
]

_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
_SENSITIVE_HEADERS = [
    "Authorization", "X-Auth-Token", "X-API-Key",
    "Cookie", "X-CSRF-Token",
]


def _cors_request(session, url, origin, method="GET", with_credentials=True):
    """Send CORS preflight + actual request. Returns (acao, acac, acam, status)."""
    hdrs = random_headers(include_ip_spoof=False, include_referrer=False)
    hdrs["Origin"] = origin
    if with_credentials:
        hdrs["Cookie"] = "session=test"

    # Preflight OPTIONS
    pf_acao = pf_acac = pf_acam = ""
    try:
        burst_jitter()
        pf_hdrs = dict(hdrs)
        pf_hdrs["Access-Control-Request-Method"]  = method
        pf_hdrs["Access-Control-Request-Headers"] = "Authorization,Content-Type"
        pf = session.options(url, headers=pf_hdrs, timeout=8, verify=False,
                             allow_redirects=False)
        pf_acao = pf.headers.get("Access-Control-Allow-Origin", "")
        pf_acac = pf.headers.get("Access-Control-Allow-Credentials", "")
        pf_acam = pf.headers.get("Access-Control-Allow-Methods", "")
    except Exception:
        pass

    # Actual request
    acao = acac = ""
    status = 0
    try:
        burst_jitter()
        r = session.get(url, headers=hdrs, timeout=8, verify=False,
                        allow_redirects=True)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        status = r.status_code
    except Exception:
        pass

    return {
        "acao": acao or pf_acao,
        "acac": acac or pf_acac,
        "acam": pf_acam,
        "status": status,
        "origin_sent": origin,
    }


def scan_cors(url, callback=None):
    """
    Full CORS misconfiguration audit.
    Returns dict with findings, severity, and recommendations.
    """
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {
        "url":             url,
        "findings":        [],
        "vulnerabilities": [],
        "tests_run":       0,
        "misconfigured":   False,
    }

    if not HAS_REQUESTS:
        return results

    base = url if "://" in url else "http://" + url
    cb("info", f"🌐 CORS Scanner: {base}")

    import urllib.parse
    parsed = urllib.parse.urlparse(base if "://" in base else "http://" + base)
    domain = parsed.netloc.split(":")[0]

    session = requests.Session()
    session.verify = False

    # Build domain-specific evil origins
    evil_origins = list(_EVIL_ORIGINS)
    evil_origins += [
        f"https://{domain}.evil.com",
        f"https://evil.{domain}",
        f"https://not{domain}",
        f"https://sub.{domain}",
    ]

    # ── Test 1: Wildcard ACAO ─────────────────────────────────────────
    try:
        burst_jitter()
        r0 = session.get(base, headers=random_headers(), timeout=10,
                         verify=False, allow_redirects=True)
        acao0 = r0.headers.get("Access-Control-Allow-Origin", "")
        acac0 = r0.headers.get("Access-Control-Allow-Credentials", "")
        if acao0 == "*":
            sev = "high" if acac0.lower() != "true" else "critical"
            msg = f"CORS wildcard (*)"
            if acac0.lower() == "true":
                msg += " + credentials=true (CRITICAL — RFC violation permet quand même l'exploitation)"
            results["findings"].append({
                "test": "wildcard", "severity": sev,
                "detail": f"Access-Control-Allow-Origin: *  |  ACAC: {acac0}",
                "impact": "Tout site peut lire les réponses",
            })
            cb("vuln", f"🚨 CORS: {msg}")
    except Exception:
        pass

    # ── Test 2: Origin reflection ─────────────────────────────────────
    for origin in evil_origins:
        result = _cors_request(session, base, origin)
        results["tests_run"] += 1
        acao = result["acao"]
        acac = result["acac"]

        if not acao:
            continue

        # Exact reflection of evil origin
        if acao == origin:
            sev = "critical" if acac.lower() == "true" else "high"
            results["misconfigured"] = True
            results["findings"].append({
                "test":     "origin_reflection",
                "severity": sev,
                "origin":   origin,
                "acao":     acao,
                "acac":     acac,
                "detail":   f"Origin '{origin}' reflété → ACAO: {acao}  ACAC: {acac}",
                "impact":   ("Exfiltration données avec credentials" if sev == "critical"
                             else "Lecture réponses cross-origin"),
            })
            cb("vuln", f"🚨 CORS reflection [{sev.upper()}]: Origin={origin} → ACAO={acao} ACAC={acac}")

        # Null origin bypass
        if origin == "null" and acao == "null":
            results["misconfigured"] = True
            sev = "critical" if acac.lower() == "true" else "high"
            results["findings"].append({
                "test":     "null_origin",
                "severity": sev,
                "detail":   "null origin accepté (sandbox iframe bypass)",
                "impact":   "Exploitable via sandboxed iframe",
            })
            cb("vuln", f"🚨 CORS null origin [{sev.upper()}]")

    # ── Test 3: Pre-flight bypass (non-simple methods) ────────────────
    dangerous_methods = ["DELETE", "PUT", "PATCH"]
    for method in dangerous_methods:
        try:
            burst_jitter()
            hdrs = random_headers()
            hdrs["Origin"] = "https://evil.com"
            hdrs["Access-Control-Request-Method"] = method
            r_pf = session.options(base, headers=hdrs, timeout=8,
                                   verify=False, allow_redirects=False)
            acam = r_pf.headers.get("Access-Control-Allow-Methods", "")
            if method in acam or "*" in acam:
                results["findings"].append({
                    "test":     "preflight_dangerous_method",
                    "severity": "high",
                    "method":   method,
                    "detail":   f"Pre-flight autorise {method}: ACAM={acam}",
                    "impact":   f"Mutations cross-origin possibles ({method})",
                })
                cb("vuln", f"🚨 CORS pre-flight: {method} autorisé depuis evil.com")
            results["tests_run"] += 1
        except Exception:
            pass

    # ── Test 4: CORS on sensitive endpoints ───────────────────────────
    sensitive_paths = ["/api/user", "/api/me", "/api/profile", "/api/admin",
                       "/api/v1/user", "/api/v1/me", "/user", "/profile",
                       "/account", "/api/keys", "/api/tokens"]
    for path in sensitive_paths[:8]:
        ep = (base.rstrip("/") + path)
        try:
            burst_jitter()
            hdrs = random_headers()
            hdrs["Origin"] = "https://evil.com"
            r_ep = session.get(ep, headers=hdrs, timeout=6,
                               verify=False, allow_redirects=False)
            acao_ep = r_ep.headers.get("Access-Control-Allow-Origin", "")
            acac_ep = r_ep.headers.get("Access-Control-Allow-Credentials", "")
            if acao_ep and acao_ep != "" and r_ep.status_code == 200:
                sev = "critical" if acac_ep.lower() == "true" else "high"
                results["findings"].append({
                    "test":     "sensitive_endpoint",
                    "severity": sev,
                    "endpoint": ep,
                    "detail":   f"CORS sur endpoint sensible {path}: ACAO={acao_ep} ACAC={acac_ep}",
                    "impact":   "Accès données utilisateur cross-origin",
                })
                cb("vuln", f"🚨 CORS [{sev.upper()}] endpoint sensible: {path}")
            results["tests_run"] += 1
        except Exception:
            pass

    # ── Build vulnerabilities ─────────────────────────────────────────
    for f in results["findings"]:
        results["vulnerabilities"].append({
            "type":     "cors_misconfiguration",
            "severity": f["severity"],
            "name":     f"CORS Misconfiguration: {f['test']}",
            "detail":   f.get("detail", ""),
        })

    if results["misconfigured"] or results["findings"]:
        cb("found", f"🌐 CORS: {len(results['findings'])} problème(s) détecté(s) sur {results['tests_run']} tests")
    else:
        cb("ok", f"🌐 CORS: pas de misconfiguration évidente ({results['tests_run']} tests)")

    return results

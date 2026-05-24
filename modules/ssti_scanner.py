"""
SSTI (Server-Side Template Injection) Scanner - UHQKYRA v1.0
=============================================================
⚠️  Authorized security testing only.

Detects Server-Side Template Injection vulnerabilities in:
  - Jinja2 / Python (Flask, Django)
  - Twig / PHP (Symfony, Craft CMS)
  - Freemarker / Java
  - Velocity / Java
  - Smarty / PHP
  - Pebble / Java
  - Mako / Python
  - Handlebars / Node.js
  - ERB / Ruby (Rails)

Detection is safe — uses math/string probes ({{7*7}} → 49) only.
No code execution payloads are used.
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

# ── SSTI detection payloads ───────────────────────────────────────────────────
# Safe math/string payloads that don't execute OS commands
SSTI_PROBES = [
    # (payload, expected_output, engine_hint)
    ("{{7*7}}", "49", "Jinja2/Twig/Pebble"),
    ("${7*7}", "49", "Freemarker/Velocity/EL"),
    ("#{7*7}", "49", "Pebble/Thymeleaf"),
    ("<%= 7*7 %>", "49", "ERB/EJS"),
    ("{{7*'7'}}", "7777777", "Jinja2"),
    ("${\"abc\".length()}", "3", "Freemarker/OGNL"),
    ("{{\"abc\"|length}}", "3", "Jinja2/Twig"),
    ("{7*7}", "49", "Smarty/custom"),
    ("[7*7]", "49", "Pebble/custom"),
    ("@(7*7)", "49", "Razor/.NET"),
    ("{{7*7}}{{7*7}}", "4949", "Jinja2/Twig"),
    ("%{7*7}", "49", "Velocity/Struts2"),
    ("*{7*7}", "49", "Spring SpEL"),
    ("T(7).multiply(7)", "49", "SpEL"),
    ("{{config}}", "Config", "Jinja2 Flask config"),
]

# More aggressive SSTI payloads for fingerprinting (still non-destructive)
ENGINE_FINGERPRINTS = {
    "Jinja2":      ("{{7*'7'}}", "7777777"),
    "Twig":        ("{{7*'7'}}", "49"),
    "Freemarker":  ("${\"abc\"?length}", "3"),
    "Velocity":    ("#set($x=7*7)${x}", "49"),
    "Smarty":      ("{7*7}", "49"),
    "Mako":        ("${7*7}", "49"),
    "ERB":         ("<%= 7*7 %>", "49"),
    "EJS":         ("<%= 7*7 %>", "49"),
    "Pebble":      ("{{7*7}}", "49"),
    "Handlebars":  ("{{7*7}}", ""),     # Handlebars doesn't eval math
}

# Common parameter names to test
TEST_PARAMS = [
    "name", "q", "query", "search", "text", "message", "msg",
    "input", "content", "data", "value", "val", "template",
    "subject", "body", "title", "description", "comment",
    "field", "label", "hint", "placeholder", "error",
    "username", "email", "page", "id", "type",
    "format", "output", "render", "view",
    "to", "from", "cc", "greeting",
    "lang", "locale", "timezone",
]

# URL path fuzzing for SSTI
PATH_SSTI_PATTERNS = [
    "/{{7*7}}",
    "/%7B%7B7*7%7D%7D",  # URL-encoded {{7*7}}
    "/${7*7}",
]

# Headers that may be reflected in templates
HEADER_SSTI = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "Accept-Language",
    "X-Custom-Header",
]


def _req(session, method, url, **kwargs):
    """Request with stealth headers."""
    hdrs = random_headers(include_ip_spoof=True)
    hdrs.update(kwargs.pop("headers", {}))
    burst_jitter()
    try:
        fn = getattr(session, method.lower(), session.get)
        return fn(url, headers=hdrs, timeout=8, verify=False,
                  allow_redirects=True, **kwargs)
    except Exception:
        return None


def _check_reflection(text, payload):
    """Check if the payload or its evaluation appears in response."""
    # Direct reflection
    if payload in text:
        return "reflected", None

    # Evaluated math results
    for probe, expected, _ in SSTI_PROBES:
        if probe in payload and expected and expected in text:
            return "evaluated", expected

    # Check for specific math result
    if "49" in text and "*7" in payload:
        return "evaluated", "49"
    if "3" in text and "length" in payload.lower():
        return "evaluated", "3"

    return None, None


def _identify_engine(session, base_url, param, method="GET"):
    """Try to identify the template engine."""
    for engine, (payload, expected) in ENGINE_FINGERPRINTS.items():
        if not expected:
            continue
        if method == "GET":
            import urllib.parse
            test_url = base_url + f"?{param}={urllib.parse.quote(payload)}"
            r = _req(session, "GET", test_url)
        else:
            r = _req(session, "POST", base_url, data={param: payload})

        if r and expected in r.text:
            return engine
    return "Unknown"


def scan_ssti(url, callback=None):
    """
    Scan for Server-Side Template Injection vulnerabilities.
    Non-destructive — uses math/string probes only.
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
    cb("info", f"🧩 SSTI Scanner: {base}")

    import urllib.parse
    parsed = urllib.parse.urlparse(base)
    existing_params = dict(urllib.parse.parse_qsl(parsed.query))

    session = requests.Session()
    session.verify = False

    # ── Get baseline response ────────────────────────────────────────
    baseline_r = _req(session, "GET", base)
    baseline_text = baseline_r.text if baseline_r else ""
    baseline_len = len(baseline_text)

    # ── 1. GET parameter SSTI ────────────────────────────────────────
    cb("info", "🧩 Test GET params...")
    # Use existing params + common ones
    params_to_test = list(existing_params.keys()) + [
        p for p in TEST_PARAMS if p not in existing_params
    ]

    for param in params_to_test[:20]:
        for payload, expected, engine_hint in SSTI_PROBES[:8]:
            results["tests_run"] += 1
            test_params = dict(existing_params)
            test_params[param] = payload
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(test_params))
            )

            r = _req(session, "GET", test_url)
            if not r:
                continue

            kind, match = _check_reflection(r.text, payload)
            if kind == "evaluated" and match:
                results["vulnerable"] = True
                # Try to identify template engine
                engine = _identify_engine(session, base, param, "GET")
                detail = (f"SSTI [{engine_hint}]: ?{param}={payload!r} → "
                          f"résultat '{match}' dans la réponse")
                results["findings"].append({
                    "test": "ssti_get", "severity": "critical",
                    "detail": detail, "url": test_url,
                    "param": param, "payload": payload, "engine": engine,
                })
                results["vulnerabilities"].append({
                    "type": "ssti", "severity": "critical",
                    "name": f"SSTI [{engine}] — param GET: {param}",
                    "detail": detail,
                })
                cb("vuln", f"🚨 SSTI [{engine}]: ?{param}={payload!r} → {match}")
                break  # One confirmed finding per param is enough

    # ── 2. POST parameter SSTI ───────────────────────────────────────
    cb("info", "🧩 Test POST params...")
    for param in TEST_PARAMS[:15]:
        for payload, expected, engine_hint in SSTI_PROBES[:5]:
            results["tests_run"] += 1
            r = _req(session, "POST", base, data={param: payload})
            if not r:
                continue
            kind, match = _check_reflection(r.text, payload)
            if kind == "evaluated" and match:
                results["vulnerable"] = True
                engine = _identify_engine(session, base, param, "POST")
                detail = f"SSTI [{engine}] POST: {param}={payload!r} → '{match}'"
                results["findings"].append({
                    "test": "ssti_post", "severity": "critical",
                    "detail": detail, "url": base,
                    "param": param, "payload": payload, "engine": engine,
                })
                results["vulnerabilities"].append({
                    "type": "ssti", "severity": "critical",
                    "name": f"SSTI [{engine}] — param POST: {param}",
                    "detail": detail,
                })
                cb("vuln", f"🚨 SSTI POST [{engine}]: {param}={payload!r} → {match}")
                break

    # ── 3. JSON body SSTI ────────────────────────────────────────────
    cb("info", "🧩 Test JSON body...")
    for payload, expected, engine_hint in SSTI_PROBES[:3]:
        for field in ["name", "message", "text", "template"]:
            results["tests_run"] += 1
            r = _req(session, "POST", base,
                     json={field: payload},
                     headers={"Content-Type": "application/json"})
            if not r:
                continue
            kind, match = _check_reflection(r.text, payload)
            if kind == "evaluated" and match:
                results["vulnerable"] = True
                detail = f"SSTI JSON: body[{field!r}]={payload!r} → '{match}'"
                results["findings"].append({
                    "test": "ssti_json", "severity": "critical",
                    "detail": detail, "url": base,
                })
                results["vulnerabilities"].append({
                    "type": "ssti", "severity": "critical",
                    "name": f"SSTI via JSON body: {field}",
                    "detail": detail,
                })
                cb("vuln", f"🚨 SSTI JSON: {field}={payload!r}")
                break

    # ── 4. Header reflection SSTI ────────────────────────────────────
    cb("info", "🧩 Test header reflection SSTI...")
    for payload, expected, engine_hint in SSTI_PROBES[:3]:
        for hdr in HEADER_SSTI:
            results["tests_run"] += 1
            r = _req(session, "GET", base, headers={hdr: payload})
            if not r:
                continue
            kind, match = _check_reflection(r.text, payload)
            if kind == "evaluated" and match:
                results["vulnerable"] = True
                detail = f"SSTI Header: {hdr}={payload!r} → '{match}'"
                results["findings"].append({
                    "test": "ssti_header", "severity": "critical",
                    "detail": detail, "url": base,
                })
                results["vulnerabilities"].append({
                    "type": "ssti", "severity": "critical",
                    "name": f"SSTI via header: {hdr}",
                    "detail": detail,
                })
                cb("vuln", f"🚨 SSTI Header: {hdr}={payload!r}")
                break

    # ── 5. URL path SSTI ─────────────────────────────────────────────
    cb("info", "🧩 Test SSTI dans le chemin URL...")
    for path_pattern in PATH_SSTI_PATTERNS:
        results["tests_run"] += 1
        test_url = base + path_pattern
        r = _req(session, "GET", test_url)
        if r and "49" in r.text:
            results["findings"].append({
                "test": "ssti_path", "severity": "high",
                "detail": f"SSTI URL path: {path_pattern} → '49' dans réponse",
                "url": test_url,
            })
            results["vulnerabilities"].append({
                "type": "ssti", "severity": "high",
                "name": "SSTI dans le chemin URL",
                "detail": f"Path: {path_pattern}",
            })
            cb("vuln", f"🚨 SSTI chemin: {path_pattern}")

    # ── Summary ───────────────────────────────────────────────────────
    total_vulns = len(results["vulnerabilities"])
    if total_vulns:
        cb("vuln", f"🚨 SSTI: {total_vulns} vulnérabilité(s) sur {results['tests_run']} tests")
    else:
        cb("ok", f"🧩 SSTI: aucune injection détectée ({results['tests_run']} tests)")

    return results

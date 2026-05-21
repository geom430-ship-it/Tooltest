"""
HTTP Security Analyzer Module
Analyzes HTTP headers, cookies, redirects, and security configurations
"""
import re
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
import http.client
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# Security headers to check
SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "severity": "high",
        "description": "Enforces HTTPS connections",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "content-security-policy": {
        "name": "CSP",
        "severity": "high",
        "description": "Prevents XSS and injection attacks",
        "recommendation": "Add a strict Content-Security-Policy header"
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Prevents MIME type sniffing",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Prevents clickjacking",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "severity": "low",
        "description": "Legacy XSS filter (deprecated but still useful)",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block"
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "medium",
        "description": "Controls referrer information",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "medium",
        "description": "Controls browser features",
        "recommendation": "Add Permissions-Policy to restrict dangerous APIs"
    },
    "cache-control": {
        "name": "Cache-Control",
        "severity": "low",
        "description": "Controls caching behavior",
        "recommendation": "Add: Cache-Control: no-store for sensitive pages"
    },
    "x-powered-by": {
        "name": "X-Powered-By (information leak)",
        "severity": "low",
        "description": "Reveals server technology",
        "recommendation": "Remove X-Powered-By header"
    },
    "server": {
        "name": "Server (information leak)",
        "severity": "low",
        "description": "Reveals server software version",
        "recommendation": "Remove or obscure the Server header"
    },
    "access-control-allow-origin": {
        "name": "CORS Policy",
        "severity": "medium",
        "description": "Cross-Origin Resource Sharing policy",
        "recommendation": "Avoid Access-Control-Allow-Origin: *"
    }
}

INTERESTING_HEADERS = [
    "x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-varnish", "x-cache",
    "x-backend", "x-forwarded-for", "x-real-ip", "x-original-url",
    "x-rewrite-url", "x-debug", "x-request-id", "x-correlation-id"
]


def make_request(url, timeout=10, follow_redirects=True, method="GET"):
    """Make HTTP request and return response info"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    if HAS_REQUESTS:
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; PentestKit/1.0; Security Assessment)",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
            response = requests.request(
                method, url, headers=headers, timeout=timeout,
                allow_redirects=follow_redirects, verify=False
            )
            return {
                "url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text[:50000],
                "redirect_chain": [r.url for r in response.history] if follow_redirects else [],
                "elapsed": response.elapsed.total_seconds()
            }
        except requests.exceptions.SSLError as e:
            return {"error": f"SSL Error: {str(e)}", "url": url}
        except requests.exceptions.ConnectionError as e:
            return {"error": f"Connection Error: {str(e)}", "url": url}
        except Exception as e:
            return {"error": str(e), "url": url}
    else:
        # Fallback to urllib
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "PentestKit/1.0 Security Assessment"
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return {
                    "url": resp.url,
                    "status_code": resp.status,
                    "headers": dict(resp.headers),
                    "body": resp.read(50000).decode('utf-8', errors='ignore'),
                    "redirect_chain": [],
                    "elapsed": 0
                }
        except Exception as e:
            return {"error": str(e), "url": url}


def analyze_security_headers(headers, callback=None):
    """Analyze HTTP headers for security issues"""
    findings = {
        "present": [],
        "missing": [],
        "warnings": [],
        "score": 0
    }

    headers_lower = {k.lower(): v for k, v in headers.items()}
    total_checks = 8  # Main security headers
    passed = 0

    if callback:
        callback({"type": "info", "message": "🔍 Analyzing security headers..."})

    # Check HSTS
    if "strict-transport-security" in headers_lower:
        hsts_value = headers_lower["strict-transport-security"]
        passed += 1
        findings["present"].append({"header": "HSTS", "value": hsts_value, "status": "ok"})
        if callback:
            callback({"type": "ok", "message": f"✅ HSTS present: {hsts_value}"})

        # Check max-age
        max_age_match = re.search(r'max-age=(\d+)', hsts_value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                findings["warnings"].append(f"HSTS max-age is {max_age} (recommended: 31536000+)")
                if callback:
                    callback({"type": "warn", "message": f"⚠️  HSTS max-age too short: {max_age}s"})
        if "includesubdomains" not in hsts_value.lower():
            findings["warnings"].append("HSTS missing includeSubDomains")
    else:
        findings["missing"].append(SECURITY_HEADERS["strict-transport-security"])
        if callback:
            callback({"type": "vuln", "message": "❌ HSTS header missing (HIGH)"})

    # Check CSP
    if "content-security-policy" in headers_lower:
        csp_value = headers_lower["content-security-policy"]
        passed += 1
        findings["present"].append({"header": "CSP", "value": csp_value[:200], "status": "ok"})
        if callback:
            callback({"type": "ok", "message": f"✅ CSP present"})

        # Check for unsafe directives
        if "unsafe-inline" in csp_value or "unsafe-eval" in csp_value:
            findings["warnings"].append("CSP contains unsafe directives (unsafe-inline or unsafe-eval)")
            if callback:
                callback({"type": "warn", "message": "⚠️  CSP has unsafe directives!"})
        if "'unsafe-inline'" in csp_value:
            if callback:
                callback({"type": "warn", "message": "⚠️  CSP: 'unsafe-inline' detected - reduces XSS protection"})
    else:
        findings["missing"].append(SECURITY_HEADERS["content-security-policy"])
        if callback:
            callback({"type": "vuln", "message": "❌ Content-Security-Policy missing (HIGH)"})

    # Check X-Content-Type-Options
    if "x-content-type-options" in headers_lower:
        passed += 1
        findings["present"].append({"header": "X-Content-Type-Options", "value": headers_lower["x-content-type-options"], "status": "ok"})
        if callback:
            callback({"type": "ok", "message": "✅ X-Content-Type-Options present"})
    else:
        findings["missing"].append(SECURITY_HEADERS["x-content-type-options"])
        if callback:
            callback({"type": "vuln", "message": "❌ X-Content-Type-Options missing (MEDIUM)"})

    # Check X-Frame-Options
    if "x-frame-options" in headers_lower:
        passed += 1
        xfo = headers_lower["x-frame-options"]
        findings["present"].append({"header": "X-Frame-Options", "value": xfo, "status": "ok"})
        if callback:
            callback({"type": "ok", "message": f"✅ X-Frame-Options: {xfo}"})
    else:
        findings["missing"].append(SECURITY_HEADERS["x-frame-options"])
        if callback:
            callback({"type": "vuln", "message": "❌ X-Frame-Options missing (MEDIUM) - Clickjacking risk"})

    # Check Referrer-Policy
    if "referrer-policy" in headers_lower:
        passed += 1
        findings["present"].append({"header": "Referrer-Policy", "value": headers_lower["referrer-policy"], "status": "ok"})
        if callback:
            callback({"type": "ok", "message": f"✅ Referrer-Policy: {headers_lower['referrer-policy']}"})
    else:
        findings["missing"].append(SECURITY_HEADERS["referrer-policy"])
        if callback:
            callback({"type": "warn", "message": "⚠️  Referrer-Policy missing (MEDIUM)"})

    # Check Permissions-Policy
    if "permissions-policy" in headers_lower:
        passed += 1
        findings["present"].append({"header": "Permissions-Policy", "value": headers_lower["permissions-policy"][:100], "status": "ok"})
        if callback:
            callback({"type": "ok", "message": "✅ Permissions-Policy present"})

    # Check information disclosure
    if "x-powered-by" in headers_lower:
        val = headers_lower["x-powered-by"]
        findings["warnings"].append(f"Information disclosure: X-Powered-By: {val}")
        if callback:
            callback({"type": "warn", "message": f"⚠️  Information leak - X-Powered-By: {val}"})

    if "server" in headers_lower:
        val = headers_lower["server"]
        if any(v in val.lower() for v in ["apache/", "nginx/", "iis/", "php/", "tomcat/"]):
            findings["warnings"].append(f"Server version disclosure: {val}")
            if callback:
                callback({"type": "warn", "message": f"⚠️  Server version leak: {val}"})
        else:
            if callback:
                callback({"type": "info", "message": f"ℹ️  Server: {val}"})

    # Check CORS
    if "access-control-allow-origin" in headers_lower:
        cors = headers_lower["access-control-allow-origin"]
        if cors == "*":
            findings["warnings"].append("CORS wildcard origin (*) - potential security risk")
            if callback:
                callback({"type": "vuln", "message": "🚨 CORS wildcard (*) detected!"})
        else:
            if callback:
                callback({"type": "info", "message": f"ℹ️  CORS: {cors}"})

    # Calculate score
    findings["score"] = int((passed / total_checks) * 100)

    if callback:
        grade = "A+" if findings["score"] >= 90 else "A" if findings["score"] >= 80 else "B" if findings["score"] >= 70 else "C" if findings["score"] >= 60 else "D" if findings["score"] >= 50 else "F"
        callback({"type": "complete", "message": f"📊 Security Header Score: {findings['score']}/100 (Grade: {grade})"})

    return findings


def analyze_cookies(headers, callback=None):
    """Analyze cookies for security flags"""
    cookies = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    set_cookie_headers = [v for k, v in headers.items() if k.lower() == "set-cookie"]

    if not set_cookie_headers and callback:
        callback({"type": "info", "message": "ℹ️  No cookies found"})
        return cookies

    if callback:
        callback({"type": "info", "message": f"🍪 Analyzing {len(set_cookie_headers)} cookie(s)..."})

    for cookie_str in set_cookie_headers:
        parts = [p.strip() for p in cookie_str.split(';')]
        name_val = parts[0].split('=', 1)
        name = name_val[0] if name_val else "unknown"

        cookie = {
            "name": name,
            "value": name_val[1][:50] + "..." if len(name_val) > 1 and len(name_val[1]) > 50 else (name_val[1] if len(name_val) > 1 else ""),
            "secure": False,
            "httponly": False,
            "samesite": None,
            "issues": []
        }

        attrs_lower = [p.lower() for p in parts[1:]]

        if "secure" in attrs_lower:
            cookie["secure"] = True
        else:
            cookie["issues"].append("Missing Secure flag")

        if "httponly" in attrs_lower:
            cookie["httponly"] = True
        else:
            cookie["issues"].append("Missing HttpOnly flag (XSS risk)")

        for attr in parts[1:]:
            if attr.lower().startswith("samesite="):
                cookie["samesite"] = attr.split('=', 1)[1]

        if not cookie["samesite"]:
            cookie["issues"].append("Missing SameSite attribute (CSRF risk)")
        elif cookie["samesite"].lower() == "none":
            if not cookie["secure"]:
                cookie["issues"].append("SameSite=None requires Secure flag")

        cookies.append(cookie)

        if callback:
            status = "✅" if not cookie["issues"] else "⚠️ "
            issues_str = f" | Issues: {', '.join(cookie['issues'])}" if cookie["issues"] else ""
            flags = f"Secure:{cookie['secure']} HttpOnly:{cookie['httponly']} SameSite:{cookie['samesite'] or 'None'}"
            callback({"type": "found" if not cookie["issues"] else "warn",
                     "message": f"{status} Cookie '{name}': {flags}{issues_str}"})

    return cookies


def check_cors(url, origins=None, callback=None):
    """Test CORS configuration"""
    if not origins:
        origins = ["https://evil.com", "null", "https://attacker.example.com"]

    results = []
    if callback:
        callback({"type": "info", "message": f"🌐 Testing CORS misconfiguration..."})

    for origin in origins:
        try:
            if HAS_REQUESTS:
                resp = requests.options(url, headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET"
                }, timeout=5, verify=False)

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                result = {
                    "origin_tested": origin,
                    "allowed_origin": acao,
                    "allow_credentials": acac,
                    "vulnerable": False
                }

                if acao == origin or acao == "*":
                    result["vulnerable"] = True
                    if acac.lower() == "true":
                        result["severity"] = "critical"
                        if callback:
                            callback({"type": "vuln", "message": f"🚨 CRITICAL CORS: {origin} reflected with credentials!"})
                    else:
                        result["severity"] = "high"
                        if callback:
                            callback({"type": "vuln", "message": f"⚠️  CORS vulnerable: {origin} allowed"})
                else:
                    if callback:
                        callback({"type": "ok", "message": f"✅ CORS rejected: {origin}"})

                results.append(result)
        except Exception as e:
            pass

    return results


def detect_technologies(response_data, callback=None):
    """Detect web technologies from response"""
    techs = []
    headers = response_data.get("headers", {})
    body = response_data.get("body", "")
    url = response_data.get("url", "")

    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    # Server detection
    server = headers_lower.get("server", "")
    if "apache" in server:
        techs.append({"name": "Apache", "category": "Web Server", "confidence": "high"})
    if "nginx" in server:
        techs.append({"name": "Nginx", "category": "Web Server", "confidence": "high"})
    if "iis" in server:
        techs.append({"name": "IIS", "category": "Web Server", "confidence": "high"})
    if "cloudflare" in server:
        techs.append({"name": "Cloudflare", "category": "CDN/WAF", "confidence": "high"})

    # Language/Framework detection from headers
    powered_by = headers_lower.get("x-powered-by", "")
    if "php" in powered_by:
        techs.append({"name": f"PHP {powered_by}", "category": "Language", "confidence": "high"})
    if "asp.net" in powered_by:
        techs.append({"name": "ASP.NET", "category": "Framework", "confidence": "high"})
    if "express" in powered_by:
        techs.append({"name": "Express.js", "category": "Framework", "confidence": "high"})

    # Body-based detection
    if body:
        body_lower = body.lower()

        # CMS Detection
        if "wp-content" in body_lower or "wp-includes" in body_lower:
            techs.append({"name": "WordPress", "category": "CMS", "confidence": "high"})
        if "sites/default/files" in body_lower or "drupal" in body_lower:
            techs.append({"name": "Drupal", "category": "CMS", "confidence": "high"})
        if "joomla" in body_lower:
            techs.append({"name": "Joomla", "category": "CMS", "confidence": "high"})
        if "prestashop" in body_lower:
            techs.append({"name": "PrestaShop", "category": "E-Commerce", "confidence": "high"})
        if "shopify" in body_lower:
            techs.append({"name": "Shopify", "category": "E-Commerce", "confidence": "high"})
        if "woocommerce" in body_lower:
            techs.append({"name": "WooCommerce", "category": "E-Commerce", "confidence": "high"})

        # JS Frameworks
        if "react" in body_lower and ("reactdom" in body_lower or "react.js" in body_lower):
            techs.append({"name": "React", "category": "JS Framework", "confidence": "medium"})
        if "angular" in body_lower and "ng-" in body_lower:
            techs.append({"name": "Angular", "category": "JS Framework", "confidence": "medium"})
        if "vue.js" in body_lower or "vuejs" in body_lower:
            techs.append({"name": "Vue.js", "category": "JS Framework", "confidence": "medium"})
        if "jquery" in body_lower:
            techs.append({"name": "jQuery", "category": "JS Library", "confidence": "high"})
        if "bootstrap" in body_lower:
            techs.append({"name": "Bootstrap", "category": "CSS Framework", "confidence": "high"})
        if "tailwind" in body_lower:
            techs.append({"name": "Tailwind CSS", "category": "CSS Framework", "confidence": "high"})

        # Analytics
        if "google-analytics" in body_lower or "gtag(" in body_lower:
            techs.append({"name": "Google Analytics", "category": "Analytics", "confidence": "high"})
        if "gtm.js" in body_lower:
            techs.append({"name": "Google Tag Manager", "category": "Analytics", "confidence": "high"})

        # Security
        if "recaptcha" in body_lower:
            techs.append({"name": "reCAPTCHA", "category": "Security", "confidence": "high"})

    if callback:
        for tech in techs:
            callback({"type": "found", "message": f"🔧 {tech['name']} ({tech['category']}) - {tech['confidence']} confidence"})

    return techs


def full_http_analysis(url, callback=None):
    """Perform complete HTTP security analysis"""
    if callback:
        callback({"type": "info", "message": f"🌐 Starting HTTP analysis for {url}..."})

    # Ensure URL has scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    results = {
        "url": url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "response_info": None,
        "security_headers": None,
        "cookies": None,
        "technologies": [],
        "redirects": [],
        "errors": []
    }

    # Make request
    response = make_request(url, follow_redirects=True)

    if "error" in response:
        results["errors"].append(response["error"])
        if callback:
            callback({"type": "error", "message": f"❌ Request failed: {response['error']}"})
        return results

    results["response_info"] = {
        "final_url": response.get("url", url),
        "status_code": response.get("status_code"),
        "elapsed": response.get("elapsed", 0),
        "redirect_chain": response.get("redirect_chain", [])
    }

    if callback:
        status = response.get("status_code", "?")
        elapsed = response.get("elapsed", 0)
        callback({"type": "ok", "message": f"📡 Response: {status} ({elapsed:.2f}s)"})

        if response.get("redirect_chain"):
            for r in response["redirect_chain"]:
                callback({"type": "info", "message": f"  ↳ Redirect: {r}"})

    headers = response.get("headers", {})

    # Analyze security headers
    if callback:
        callback({"type": "info", "message": "\n--- Security Headers ---"})
    results["security_headers"] = analyze_security_headers(headers, callback)

    # Analyze cookies
    if callback:
        callback({"type": "info", "message": "\n--- Cookies ---"})
    results["cookies"] = analyze_cookies(headers, callback)

    # Detect technologies
    if callback:
        callback({"type": "info", "message": "\n--- Technology Detection ---"})
    results["technologies"] = detect_technologies(response, callback)

    # Check HTTPS redirect
    if url.startswith("http://"):
        https_url = "https://" + url[7:]
        https_response = make_request(https_url, follow_redirects=False)
        if "error" not in https_response:
            if callback:
                callback({"type": "ok", "message": "✅ HTTPS available"})
        else:
            if callback:
                callback({"type": "warn", "message": "⚠️  HTTPS not available"})

    if callback:
        callback({"type": "complete", "message": "\n✅ HTTP analysis complete!"})

    return results

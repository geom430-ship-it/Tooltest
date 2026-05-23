"""
CMS Scanner Module - UHQKYRA
Detect and deeply analyze CMS platforms: WordPress, Joomla, Drupal, etc.
"""
import requests
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings("ignore")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

WP_COMMON_PLUGINS = [
    "contact-form-7", "woocommerce", "elementor", "elementor-pro",
    "yoast-seo", "wordfence", "jetpack", "akismet",
    "all-in-one-wp-migration", "duplicator", "wp-file-manager",
    "revslider", "slider-revolution", "gravityforms",
    "wpforms-lite", "wp-super-cache", "w3-total-cache",
    "loginizer", "really-simple-ssl", "all-in-one-seo-pack",
    "ninja-forms", "tablepress", "advanced-custom-fields",
    "timber", "wp-mail-smtp", "updraftplus",
    "cookie-law-info", "siteground-optimizer",
]

COMMON_ADMIN_PATHS = [
    "/admin", "/admin/", "/login", "/login.php",
    "/wp-admin", "/wp-login.php", "/administrator", "/administrator/",
    "/phpmyadmin", "/phpmyadmin/", "/pma/",
    "/cpanel", "/user/login", "/account/login",
    "/admin/login", "/admin/index.php", "/adminpanel",
    "/manager/html", "/manage", "/control",
    "/backend", "/backend/", "/cms", "/cms/admin",
    "/webmaster", "/secure/", "/sysadmin",
]


def _fetch(url, timeout=8):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout,
                         verify=False, allow_redirects=False)
        return r.status_code, len(r.content), r.text[:3000]
    except Exception:
        return None, 0, ""


def scan_cms(url, callback=None):
    """Full CMS detection and analysis"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    if not url.startswith("http"):
        url = "http://" + url
    base = url.rstrip("/")

    results = {
        "cms": None,
        "version": None,
        "confidence": 0,
        "login_pages": [],
        "exposed_files": [],
        "plugins": [],
        "themes": [],
        "vulnerabilities": [],
        "api_endpoints": [],
        "interesting_paths": [],
    }

    cb("info", "🔍 Détection CMS...")

    try:
        resp = requests.get(base, headers=HEADERS, timeout=12,
                            verify=False, allow_redirects=True)
        html = resp.text
        server = (resp.headers.get("X-Powered-By", "") + " " +
                  resp.headers.get("Server", "")).lower()

        # ── CMS fingerprinting ────────────────────────────────────
        cms_scores = {}
        version_found = {}

        # WordPress
        wp_score = 0
        if re.search(r"/wp-content/|/wp-includes/|wp-json", html):
            wp_score += 4
        if re.search(r'name="generator"[^>]*content="WordPress\s*([\d.]+)?', html, re.I):
            wp_score += 3
            m = re.search(r'name="generator"[^>]*content="WordPress\s*([\d.]+)', html, re.I)
            if m and m.lastindex:
                version_found["WordPress"] = m.group(1)
        if wp_score:
            cms_scores["WordPress"] = wp_score

        # Joomla
        joomla_score = 0
        if re.search(r'name="generator"[^>]*content="Joomla', html, re.I):
            joomla_score += 4
        if re.search(r'/templates/|Joomla!', html):
            joomla_score += 2
        if joomla_score:
            cms_scores["Joomla"] = joomla_score

        # Drupal
        drupal_score = 0
        if re.search(r'name="Generator"[^>]*content="Drupal', html, re.I):
            drupal_score += 4
        if re.search(r'drupal\.settings|Drupal\.behaviors|/sites/default/', html):
            drupal_score += 3
        if drupal_score:
            cms_scores["Drupal"] = drupal_score

        # Magento
        if re.search(r'Mage\.cookies|skin\/frontend|\/pub\/static|magento', html, re.I):
            cms_scores["Magento"] = 3

        # PrestaShop
        if re.search(r'prestashop|\/modules\/|PrestaShop', html, re.I):
            cms_scores["PrestaShop"] = 3

        # Laravel
        if re.search(r'laravel|XSRF-TOKEN', html) or "laravel" in server:
            cms_scores["Laravel"] = 3

        # Django
        if re.search(r'csrfmiddlewaretoken', html) or "django" in server:
            cms_scores["Django"] = 3

        # ASP.NET
        if re.search(r'__VIEWSTATE|__RequestVerificationToken', html) or "asp.net" in server:
            cms_scores["ASP.NET"] = 3

        # Symfony
        if re.search(r'_symfony_|Symfony\b', html) or "symfony" in server:
            cms_scores["Symfony"] = 3

        # Shopify
        if re.search(r'cdn\.shopify\.com|Shopify\.theme', html):
            cms_scores["Shopify"] = 4

        # Ghost
        if re.search(r'ghost\.io|content/themes/casper', html):
            cms_scores["Ghost CMS"] = 3

        if cms_scores:
            top = max(cms_scores, key=cms_scores.get)
            results["cms"] = top
            results["confidence"] = cms_scores[top]
            results["version"] = version_found.get(top)
            ver_str = f" v{results['version']}" if results["version"] else ""
            cb("found", f"🎯 CMS détecté : {top}{ver_str} (score: {cms_scores[top]})")

        # ── Deep scans ───────────────────────────────────────────
        if results["cms"] == "WordPress":
            _deep_wordpress(base, results, cb)
        elif results["cms"] == "Joomla":
            _deep_joomla(base, results, cb)
        elif results["cms"] == "Drupal":
            _deep_drupal(base, results, cb)
        else:
            _check_admin_pages(base, results, cb)

        # Always check common admin pages if login list is short
        if len(results["login_pages"]) < 2:
            _check_admin_pages(base, results, cb)

    except Exception as e:
        cb("warn", f"CMS scan: {e}")

    return results


def _deep_wordpress(base, results, cb):
    """Deep WordPress analysis"""
    cb("info", "📦 Analyse WordPress approfondie...")

    # Version from readme.html
    st, sz, body = _fetch(base + "/readme.html")
    if st == 200:
        m = re.search(r'Version ([\d.]+)', body)
        if m:
            results["version"] = m.group(1)
            cb("found", f"📌 WP Version: {m.group(1)}")
        results["exposed_files"].append(
            {"path": "/readme.html", "severity": "low", "detail": "Version disclosed"})

    # License.txt
    st, sz, body = _fetch(base + "/license.txt")
    if st == 200:
        results["exposed_files"].append(
            {"path": "/license.txt", "severity": "info", "detail": "License file"})

    # wp-json users API (User Enumeration)
    st, sz, body = _fetch(base + "/wp-json/wp/v2/users?per_page=100")
    if st == 200:
        try:
            users = json.loads(body)
            if isinstance(users, list) and users:
                usernames = [u.get("slug", u.get("name", "?")) for u in users[:10]]
                cb("warn", f"⚠️ WP API expose {len(users)} utilisateur(s): {', '.join(usernames[:5])}")
                results["vulnerabilities"].append({
                    "type": "wp_user_enum",
                    "severity": "medium",
                    "name": f"Énumération users via WP REST API ({len(users)} users)",
                    "detail": f"/wp-json/wp/v2/users — utilisateurs: {', '.join(usernames[:5])}"
                })
        except Exception:
            pass

    # XML-RPC
    st, sz, body = _fetch(base + "/xmlrpc.php")
    if st == 200 and ("XML-RPC" in body or "xmlrpc" in body.lower()):
        cb("warn", "⚠️ XML-RPC activé (brute-force & pingback DDoS possible)")
        results["vulnerabilities"].append({
            "type": "wp_xmlrpc",
            "severity": "medium",
            "name": "WordPress XML-RPC activé",
            "detail": "Brute-force credentials et pingback DDoS possible"
        })

    # wp-login.php
    st, sz, body = _fetch(base + "/wp-login.php")
    if st == 200:
        results["login_pages"].append(base + "/wp-login.php")
        cb("found", "🔑 WP Login: /wp-login.php")

    # wp-config.php backups
    sensitive = [
        "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~",
        "/.wp-config.php.swp", "/wp-config.bak",
        "/wp-content/debug.log", "/wp-content/uploads/.htaccess",
        "/wp-content/uploads/wp-config.php",
    ]
    for path in sensitive:
        st, sz, body = _fetch(base + path)
        if st == 200 and sz > 0:
            cb("vuln", f"🚨 Fichier sensible WP: {path}")
            results["exposed_files"].append({"path": path, "severity": "critical"})
            results["vulnerabilities"].append({
                "type": "wp_sensitive_file",
                "severity": "critical",
                "name": f"Fichier sensible exposé: {path}",
                "detail": base + path
            })

    # WP REST API info
    st, sz, body = _fetch(base + "/wp-json/")
    if st == 200:
        try:
            api_data = json.loads(body)
            if api_data.get("name"):
                cb("found", f"📡 WP REST API: {api_data['name']}")
            results["api_endpoints"].append("/wp-json/")
        except Exception:
            pass

    # Plugin scan
    cb("info", f"🔍 Scan de {len(WP_COMMON_PLUGINS)} plugins WordPress...")
    found = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futs = {
            ex.submit(_fetch, f"{base}/wp-content/plugins/{p}/readme.txt"): p
            for p in WP_COMMON_PLUGINS
        }
        for fut in as_completed(futs):
            plugin = futs[fut]
            st, sz, body = fut.result()
            if st == 200 and sz > 10:
                ver_m = re.search(r'Stable tag:\s*([\d.]+)', body)
                ver = ver_m.group(1) if ver_m else "?"
                found.append({"name": plugin, "version": ver})
                cb("found", f"📦 Plugin WP: {plugin} v{ver}")
    results["plugins"] = found


def _deep_joomla(base, results, cb):
    """Deep Joomla analysis"""
    cb("info", "📦 Analyse Joomla approfondie...")

    st, sz, body = _fetch(base + "/administrator/")
    if st == 200:
        results["login_pages"].append(base + "/administrator/")
        cb("found", "🔑 Admin Joomla: /administrator/")

    for path in ["/configuration.php.bak", "/joomla.xml", "/language/en-GB/en-GB.xml"]:
        st, sz, body = _fetch(base + path)
        if st == 200 and sz > 0:
            if "joomla" in path or "configuration" in path:
                cb("warn", f"⚠️ Fichier Joomla sensible: {path}")
                results["exposed_files"].append({"path": path, "severity": "high"})

    # Version from joomla.xml or manifest
    st, sz, body = _fetch(base + "/administrator/manifests/files/joomla.xml")
    if st == 200:
        m = re.search(r'<version>([\d.]+)</version>', body)
        if m:
            results["version"] = m.group(1)
            cb("found", f"📌 Joomla version: {m.group(1)}")


def _deep_drupal(base, results, cb):
    """Deep Drupal analysis"""
    cb("info", "📦 Analyse Drupal approfondie...")

    st, sz, body = _fetch(base + "/CHANGELOG.txt")
    if st == 200:
        m = re.search(r'Drupal ([\d.]+),', body)
        if m:
            results["version"] = m.group(1)
            cb("found", f"📌 Drupal version: {m.group(1)}")
        results["exposed_files"].append(
            {"path": "/CHANGELOG.txt", "severity": "low", "detail": "Version disclosed"})
        results["vulnerabilities"].append({
            "type": "drupal_version",
            "severity": "low",
            "name": f"Version Drupal exposée: {results.get('version','?')}",
            "detail": base + "/CHANGELOG.txt"
        })

    for path in ["/user/login", "/user/register"]:
        st, sz, body = _fetch(base + path)
        if st == 200:
            results["login_pages"].append(base + path)
            cb("found", f"🔑 Drupal login: {path}")

    # Drupalgeddon2 hint (SA-CORE-2018-002)
    st, sz, body = _fetch(base + "/?q=user/password&name[%23post_render][]=passthru&name[%23markup]=id&name[%23type]=markup")
    if st == 200 and re.search(r'uid=\d+', body):
        results["vulnerabilities"].append({
            "type": "drupalgeddon2",
            "severity": "critical",
            "name": "Drupalgeddon2 RCE (SA-CORE-2018-002)",
            "detail": "Remote Code Execution possible !"
        })
        cb("vuln", "🚨 Drupalgeddon2 RCE détecté !")


def _check_admin_pages(base, results, cb):
    """Check common admin/login pages"""
    found = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        futs = {ex.submit(_fetch, base + p): p for p in COMMON_ADMIN_PATHS}
        for fut in as_completed(futs):
            path = futs[fut]
            st, sz, body = fut.result()
            if st == 200 and ("login" in body.lower() or "password" in body.lower() or "username" in body.lower()):
                found.append(base + path)
                cb("found", f"🔑 Page admin/login: {path}")
            elif st in (401, 403):
                results["interesting_paths"].append({"path": path, "status": st})
    for url in found:
        if url not in results["login_pages"]:
            results["login_pages"].append(url)

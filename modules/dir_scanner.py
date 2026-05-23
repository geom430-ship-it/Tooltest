"""
Directory & File Scanner Module
Discovers hidden directories, files, and admin panels
"""
import concurrent.futures
import time
import random

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from modules.evasion import random_ua, random_headers, burst_jitter
    _EVASION = True
except ImportError:
    try:
        from evasion import random_ua, random_headers, burst_jitter
        _EVASION = True
    except ImportError:
        _EVASION = False
        def random_ua(): return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        def random_headers(**kw): return {"User-Agent": random_ua()}
        def burst_jitter(): pass

# Built-in wordlists
COMMON_DIRS = [
    "admin", "administrator", "login", "dashboard", "panel", "control",
    "cpanel", "wp-admin", "phpmyadmin", "pma", "adminer", "dbadmin",
    "manager", "management", "backend", "console", "portal",
    "api", "api/v1", "api/v2", "graphql", "rest", "swagger", "docs",
    "backup", "backups", "bak", "old", "archive", "archives",
    "config", "configuration", "settings", "setup", "install",
    "test", "testing", "dev", "development", "debug", "staging",
    "upload", "uploads", "files", "media", "images", "img", "assets",
    "static", "css", "js", "javascript", "lib", "libs",
    "include", "includes", "common", "shared", "vendor",
    "git", ".git", ".svn", ".hg", ".env", ".htaccess",
    "robots.txt", "sitemap.xml", "security.txt", ".well-known",
    "phpinfo.php", "info.php", "test.php", "shell.php",
    "readme.md", "README.md", "README.txt", "changelog.txt",
    "CHANGELOG.md", "LICENSE", "license.txt",
    "wp-content", "wp-includes", "wp-login.php", "xmlrpc.php",
    "wp-config.php", "wp-config.php.bak",
    "web.config", "web.config.bak", "app.config",
    "database.yml", "database.php", "db.php", "db.sql",
    "composer.json", "package.json", "Gemfile", "requirements.txt",
    "Dockerfile", "docker-compose.yml", ".dockerignore",
    "Makefile", ".travis.yml", ".github",
    "server-status", "server-info", "nginx_status", "status",
    "health", "healthz", "ping", "version",
    "metrics", "prometheus", "grafana",
    "jenkins", "hudson", "bamboo", "teamcity",
    "jira", "confluence", "gitlab", "gitea",
    "kibana", "elasticsearch", "logstash",
    "zabbix", "nagios", "icinga", "munin",
    "roundcube", "squirrelmail", "horde", "webmail",
    "mail", "email", "smtp", "imap",
    "register", "signup", "logout", "forgot-password",
    "reset-password", "account", "profile", "user", "users",
    "forum", "community", "blog", "news",
    "shop", "store", "cart", "checkout",
    "invoice", "invoices", "billing", "payment",
    "report", "reports", "analytics", "stats", "statistics",
    "download", "downloads", "update", "updates",
    "cgi-bin", "cgi", "scripts", "bin",
    "tmp", "temp", "cache", "log", "logs",
    "error_log", "access.log", "debug.log",
    "trace.log", "application.log",
    "private", "secret", "hidden", "internal",
    "intranet", "extranet", "network",
    "vpn", "remote", "ssh", "ftp",
    "socket.io", "ws", "wss",
    "apple-touch-icon.png", "favicon.ico",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "humans.txt", "ads.txt", "app-ads.txt",
]

SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git/config", ".git/HEAD", ".git/FETCH_HEAD",
    ".svn/entries", ".htpasswd", ".htaccess",
    "config.php", "config.ini", "config.yaml", "config.yml",
    "settings.php", "settings.py", "local_settings.py",
    "database.yml", "database.php", "db.php",
    "wp-config.php", "wp-config.php.bak", "wp-config.php~",
    "phpinfo.php", "info.php", "php.ini",
    "server.key", "server.crt", "private.key",
    "id_rsa", "id_dsa", "id_ecdsa",
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    "site.zip", "web.zip", "source.zip",
    "Thumbs.db", ".DS_Store",
    "composer.lock", "yarn.lock", "package-lock.json",
    "Gemfile.lock", "requirements.txt",
    "web.config", "applicationHost.config",
    "crossdomain.xml", "flash.xml",
]

STATUS_CODES = {
    200: {"label": "OK", "color": "success"},
    201: {"label": "Created", "color": "success"},
    204: {"label": "No Content", "color": "info"},
    301: {"label": "Redirect", "color": "warning"},
    302: {"label": "Redirect", "color": "warning"},
    304: {"label": "Not Modified", "color": "info"},
    400: {"label": "Bad Request", "color": "danger"},
    401: {"label": "Unauthorized", "color": "warning"},
    403: {"label": "Forbidden", "color": "warning"},
    404: {"label": "Not Found", "color": "secondary"},
    405: {"label": "Method Not Allowed", "color": "info"},
    500: {"label": "Server Error", "color": "danger"},
    502: {"label": "Bad Gateway", "color": "danger"},
    503: {"label": "Service Unavailable", "color": "danger"},
}

INTERESTING_CODES = {200, 201, 204, 301, 302, 401, 403}


def check_path(base_url, path, session=None, timeout=5):
    """Check if a path exists on the server — stealth: random UA per request"""
    url = base_url.rstrip('/') + '/' + path.lstrip('/')
    hdrs = random_headers(include_ip_spoof=True, include_referrer=True)
    burst_jitter()

    try:
        if HAS_REQUESTS:
            if session:
                session.headers.update(hdrs)
            resp = session.get(url, timeout=timeout, allow_redirects=False,
                              verify=False) if session else \
                   __import__('requests').get(url, timeout=timeout, allow_redirects=False,
                                             verify=False, headers=hdrs)

            result = {
                "path": path,
                "url": url,
                "status": resp.status_code,
                "size": len(resp.content),
                "redirect": resp.headers.get("Location", ""),
                "server": resp.headers.get("Server", ""),
                "content_type": resp.headers.get("Content-Type", ""),
                "interesting": resp.status_code in INTERESTING_CODES
            }
            return result
        else:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "PentestKit/1.0"})
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return {
                        "path": path, "url": url, "status": resp.status,
                        "size": 0, "redirect": "", "server": "", "content_type": "",
                        "interesting": resp.status in INTERESTING_CODES
                    }
            except urllib.error.HTTPError as e:
                return {
                    "path": path, "url": url, "status": e.code,
                    "size": 0, "redirect": "", "server": "", "content_type": "",
                    "interesting": e.code in INTERESTING_CODES
                }
    except Exception as e:
        return None


def scan_directories(base_url, wordlist=None, extensions=None, max_workers=30,
                    interesting_only=True, callback=None):
    """Scan for directories and files"""
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'http://' + base_url

    results = {
        "base_url": base_url,
        "found": [],
        "interesting": [],
        "total_checked": 0,
        "errors": 0
    }

    # Build path list
    paths = list(wordlist if wordlist else COMMON_DIRS)

    # Add file extensions
    if extensions:
        base_paths = paths.copy()
        for path in base_paths:
            if '.' not in path.split('/')[-1]:
                for ext in extensions:
                    paths.append(f"{path}.{ext}")

    # Add sensitive files
    paths.extend(SENSITIVE_FILES)
    paths = list(set(paths))  # Deduplicate

    if callback:
        callback({"type": "info", "message": f"🔍 Scanning {len(paths)} paths on {base_url}..."})
        callback({"type": "info", "message": f"   Workers: {max_workers} | Extensions: {extensions or 'none'}"})

    # Create session for connection pooling
    session = None
    if HAS_REQUESTS:
        session = __import__('requests').Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; PentestKit/1.0; Security Assessment)"
        })

    checked = 0
    found_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {
            executor.submit(check_path, base_url, path, session): path
            for path in paths
        }

        for future in concurrent.futures.as_completed(future_to_path):
            path = future_to_path[future]
            checked += 1
            results["total_checked"] = checked

            try:
                result = future.result()
                if result and result.get("interesting"):
                    results["found"].append(result)
                    found_count += 1

                    status = result["status"]
                    size = result["size"]
                    url = result["url"]

                    # Determine icon and priority
                    if status == 200:
                        icon = "✅"
                        ptype = "found"
                    elif status in [401, 403]:
                        icon = "🔒"
                        ptype = "warn"
                    elif status in [301, 302]:
                        icon = "➡️ "
                        ptype = "info"
                    else:
                        icon = "📄"
                        ptype = "info"

                    # Highlight sensitive files
                    is_sensitive = any(sf in path for sf in [".env", "config", "backup", ".git", "password", "secret", ".sql", "phpinfo"])
                    if is_sensitive and status == 200:
                        ptype = "vuln"
                        icon = "🚨"

                    msg = f"{icon} [{status}] {path} ({size} bytes)"
                    if result.get("redirect"):
                        msg += f" → {result['redirect']}"

                    if callback:
                        callback({"type": ptype, "message": msg, "data": result})

            except Exception as e:
                results["errors"] += 1

            # Progress update
            if callback and checked % 100 == 0:
                callback({"type": "progress",
                         "message": f"Progress: {checked}/{len(paths)} | Found: {found_count}",
                         "percent": int(checked/len(paths)*100)})

    if callback:
        callback({"type": "complete",
                 "message": f"✅ Scan complete! Found {found_count} interesting paths out of {checked} checked"})

    return results


def check_robots_txt(base_url, callback=None):
    """Fetch and analyze robots.txt"""
    url = base_url.rstrip('/') + '/robots.txt'

    if callback:
        callback({"type": "info", "message": f"🤖 Fetching robots.txt..."})

    try:
        if HAS_REQUESTS:
            resp = __import__('requests').get(url, timeout=10, verify=False,
                                             headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                content = resp.text
                disallowed = [line.split(':', 1)[1].strip() for line in content.split('\n')
                            if line.lower().startswith('disallow:') and ':' in line]
                allowed = [line.split(':', 1)[1].strip() for line in content.split('\n')
                          if line.lower().startswith('allow:') and ':' in line]
                sitemaps = [line.split(':', 1)[1].strip() for line in content.split('\n')
                           if line.lower().startswith('sitemap:') and ':' in line]

                if callback:
                    callback({"type": "found", "message": f"✅ robots.txt found ({len(disallowed)} disallowed entries)"})
                    for path in disallowed[:20]:
                        if path and path != '/':
                            callback({"type": "info", "message": f"  🚫 Disallowed: {path}"})
                    for sitemap in sitemaps:
                        callback({"type": "info", "message": f"  🗺️  Sitemap: {sitemap}"})

                return {
                    "found": True, "content": content,
                    "disallowed": disallowed, "allowed": allowed, "sitemaps": sitemaps
                }
            else:
                if callback:
                    callback({"type": "info", "message": "ℹ️  robots.txt not found"})
                return {"found": False}
    except Exception as e:
        if callback:
            callback({"type": "error", "message": f"❌ Error fetching robots.txt: {e}"})
        return {"found": False, "error": str(e)}

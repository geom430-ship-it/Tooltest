"""
OSINT Recon Module - UHQKYRA
Open Source Intelligence gathering: emails, breaches, dorks, social media
"""

import re
import hashlib
import urllib.parse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    from xml.etree import ElementTree as ET
    XML_OK = True
except ImportError:
    XML_OK = False

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

SOCIAL_PATTERNS = {
    "twitter": r'https?://(?:www\.)?(?:twitter|x)\.com/[A-Za-z0-9_]+',
    "linkedin": r'https?://(?:www\.)?linkedin\.com/(?:company|in|profile)/[A-Za-z0-9_\-]+',
    "github": r'https?://(?:www\.)?github\.com/[A-Za-z0-9_\-]+',
    "facebook": r'https?://(?:www\.)?facebook\.com/[A-Za-z0-9_\.\-]+',
    "instagram": r'https?://(?:www\.)?instagram\.com/[A-Za-z0-9_\.]+',
    "youtube": r'https?://(?:www\.)?youtube\.com/(?:channel|user|c)/[A-Za-z0-9_\-]+',
}

DORK_TEMPLATES = [
    ("leaks", "site:{domain} filetype:sql"),
    ("leaks", "site:{domain} filetype:env"),
    ("leaks", "site:{domain} filetype:log"),
    ("leaks", "site:{domain} filetype:bak"),
    ("leaks", "site:{domain} filetype:old"),
    ("leaks", "site:{domain} filetype:backup"),
    ("leaks", "site:{domain} filetype:conf"),
    ("leaks", "site:{domain} filetype:config"),
    ("leaks", 'intext:"{domain}" site:pastebin.com'),
    ("leaks", 'site:github.com "{domain}" password'),
    ("leaks", 'site:github.com "{domain}" secret'),
    ("leaks", 'site:github.com "{domain}" token'),
    ("admin", "site:{domain} inurl:admin"),
    ("admin", "site:{domain} inurl:administrator"),
    ("admin", "site:{domain} inurl:login"),
    ("admin", "site:{domain} inurl:dashboard"),
    ("admin", "site:{domain} inurl:panel"),
    ("admin", "site:{domain} inurl:cpanel"),
    ("admin", "site:{domain} inurl:wp-admin"),
    ("config", 'site:{domain} "password"'),
    ("config", 'site:{domain} "api_key"'),
    ("config", 'site:{domain} "secret_key"'),
    ("config", 'site:{domain} "access_token"'),
    ("config", "site:{domain} filetype:xml inurl:config"),
    ("config", "site:{domain} filetype:yml"),
    ("config", "site:{domain} filetype:yaml"),
    ("sqli", "site:{domain} filetype:php inurl:?id="),
    ("sqli", "site:{domain} inurl:index.php?id="),
    ("sqli", "site:{domain} inurl:page.php?id="),
    ("sqli", "site:{domain} inurl:view.php?id="),
    ("exposures", "site:{domain} intitle:index.of"),
    ("exposures", "site:{domain} intitle:open.directory"),
    ("exposures", 'site:{domain} "directory listing"'),
    ("exposures", "site:{domain} inurl:.git"),
    ("exposures", "site:{domain} inurl:.svn"),
    ("exposures", "site:{domain} inurl:.htaccess"),
    ("exposures", "site:{domain} inurl:phpinfo.php"),
    ("exposures", "site:{domain} inurl:test.php"),
    ("exposures", "site:{domain} inurl:debug"),
]


def _extract_domain(domain):
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0].strip()
    return domain


def _fetch(url, session=None):
    try:
        s = session or requests
        resp = s.get(url, headers=HEADERS, verify=False, timeout=8, allow_redirects=True)
        return resp
    except Exception:
        return None


def _extract_emails(text, domain):
    pattern = re.compile(r'[a-zA-Z0-9_.+\-]+@' + re.escape(domain), re.IGNORECASE)
    generic = re.compile(r'[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}')
    emails = set(pattern.findall(text))
    for m in generic.findall(text):
        if domain.lower() in m.lower():
            emails.add(m)
    return list(emails)


def _extract_metadata(html):
    meta = {}
    title_m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if title_m:
        meta["title"] = title_m.group(1).strip()
    desc_m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if desc_m:
        meta["description"] = desc_m.group(1).strip()
    kw_m = re.search(r'<meta[^>]+name=["\']keywords["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if kw_m:
        meta["keywords"] = kw_m.group(1).strip()
    og = {}
    for m in re.finditer(r'<meta[^>]+property=["\']og:(\w+)["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE):
        og[m.group(1)] = m.group(2).strip()
    if og:
        meta["og"] = og
    return meta


def _extract_tech(resp):
    tech = {}
    if resp is None:
        return tech
    server = resp.headers.get("Server", "")
    if server:
        tech["server"] = server
    powered = resp.headers.get("X-Powered-By", "")
    if powered:
        tech["powered_by"] = powered
    ct = resp.headers.get("Content-Type", "")
    if ct:
        tech["content_type"] = ct
    frameworks = []
    html = resp.text.lower()
    if "wp-content" in html or "wp-includes" in html:
        frameworks.append("WordPress")
    if "drupal" in html:
        frameworks.append("Drupal")
    if "joomla" in html:
        frameworks.append("Joomla")
    if "laravel" in html:
        frameworks.append("Laravel")
    if "django" in html:
        frameworks.append("Django")
    if "rails" in html or "ruby on rails" in html:
        frameworks.append("Rails")
    if frameworks:
        tech["frameworks"] = frameworks
    return tech


def _parse_robots(text):
    disallowed = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
    return disallowed


def _parse_sitemap(text):
    urls = []
    if XML_OK:
        try:
            root = ET.fromstring(text)
            ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for loc in root.findall(".//sm:loc", ns):
                if loc.text:
                    urls.append(loc.text.strip())
            if not urls:
                for loc in root.iter():
                    if loc.tag.endswith("loc") and loc.text:
                        urls.append(loc.text.strip())
        except Exception:
            pass
    if not urls:
        for m in re.finditer(r'<loc>(.*?)</loc>', text, re.IGNORECASE):
            urls.append(m.group(1).strip())
    return urls


def _social_links(html):
    found = {}
    for platform, pattern in SOCIAL_PATTERNS.items():
        matches = re.findall(pattern, html)
        if matches:
            found[platform] = list(set(matches))
    return found


def _favicon_hash(url, session):
    favicon_url = url.rstrip("/") + "/favicon.ico"
    resp = _fetch(favicon_url, session)
    if resp and resp.status_code == 200 and resp.content:
        return hashlib.md5(resp.content).hexdigest()
    meta_icon = None
    main_resp = _fetch(url, session)
    if main_resp:
        m = re.search(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']', main_resp.text, re.IGNORECASE)
        if not m:
            m = re.search(r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\'](?:shortcut )?icon["\']', main_resp.text, re.IGNORECASE)
        if m:
            meta_icon = m.group(1)
            if not meta_icon.startswith("http"):
                meta_icon = url.rstrip("/") + "/" + meta_icon.lstrip("/")
            resp2 = _fetch(meta_icon, session)
            if resp2 and resp2.status_code == 200 and resp2.content:
                return hashlib.md5(resp2.content).hexdigest()
    return None


def run_osint(domain, callback=None):
    domain = _extract_domain(domain)
    base_url = f"https://{domain}"

    result = {
        "domain": domain,
        "emails": [],
        "dorks": [],
        "social": {},
        "metadata": {},
        "tech": {},
        "robots": [],
        "sitemap": [],
        "security_txt": None,
        "favicon_hash": None,
    }

    if not REQUESTS_OK:
        if callback:
            callback({"type": "error", "message": "requests library not available"})
        return result

    session = requests.Session()

    if callback:
        callback({"type": "info", "message": f"Starting OSINT recon on {domain}"})

    main_resp = _fetch(base_url, session)
    if main_resp is None:
        base_url = f"http://{domain}"
        main_resp = _fetch(base_url, session)

    if main_resp:
        html = main_resp.text
        result["emails"] = _extract_emails(html, domain)
        result["metadata"] = _extract_metadata(html)
        result["tech"] = _extract_tech(main_resp)
        result["social"] = _social_links(html)
        if callback:
            if result["emails"]:
                callback({"type": "found", "message": f"Emails found: {result['emails']}"})
            if result["social"]:
                callback({"type": "found", "message": f"Social links: {list(result['social'].keys())}"})
    else:
        if callback:
            callback({"type": "warning", "message": f"Could not fetch main page for {domain}"})

    dorks = []
    for category, template in DORK_TEMPLATES:
        query = template.replace("{domain}", domain)
        encoded = urllib.parse.quote_plus(query)
        dorks.append({
            "category": category,
            "query": query,
            "google_url": f"https://www.google.com/search?q={encoded}",
        })
    result["dorks"] = dorks
    if callback:
        callback({"type": "info", "message": f"Generated {len(dorks)} Google dorks"})

    robots_resp = _fetch(f"{base_url}/robots.txt", session)
    if robots_resp and robots_resp.status_code == 200:
        result["robots"] = _parse_robots(robots_resp.text)
        if callback:
            callback({"type": "found", "message": f"robots.txt: {len(result['robots'])} disallowed paths"})

    sitemap_resp = _fetch(f"{base_url}/sitemap.xml", session)
    if sitemap_resp and sitemap_resp.status_code == 200:
        result["sitemap"] = _parse_sitemap(sitemap_resp.text)
        if callback:
            callback({"type": "found", "message": f"sitemap.xml: {len(result['sitemap'])} URLs"})

    for sec_path in ["/.well-known/security.txt", "/security.txt"]:
        sec_resp = _fetch(f"{base_url}{sec_path}", session)
        if sec_resp and sec_resp.status_code == 200 and "contact" in sec_resp.text.lower():
            result["security_txt"] = sec_resp.text.strip()
            if callback:
                callback({"type": "found", "message": f"security.txt found at {sec_path}"})
            break

    result["favicon_hash"] = _favicon_hash(base_url, session)
    if result["favicon_hash"] and callback:
        callback({"type": "found", "message": f"Favicon MD5: {result['favicon_hash']}"})

    session.close()

    if callback:
        callback({"type": "done", "message": f"OSINT recon complete for {domain}"})

    return result

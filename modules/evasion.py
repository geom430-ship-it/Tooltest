"""
Evasion & Stealth Engine - UHQKYRA v1.0
========================================
⚠️  Authorized security testing only — UHQKYRA is for authorized use.

Techniques implemented:
  1. User-Agent rotation (46+ real browser/mobile/bot UAs, desktop+mobile+bots)
  2. Request header randomization (Accept, DNT, Referer, etc.)
  3. IP spoofing headers (X-Forwarded-For, X-Real-IP, etc.)
  4. Referrer chain spoofing (look like organic Google/Bing traffic)
  5. Jitter / slow-scan timing (avoid threshold triggers)
  6. SQL payload obfuscation:
       - Keyword case mixing   (SeLeCt, UnIoN…)
       - Inline comment insertion  (UN/**/ION, SE/**/LECT)
       - MySQL version comments    (/*!50000 SELECT*/)
       - Whitespace alternatives   (tab, newline, carriage return, form-feed)
       - CHAR() string encoding    (avoids quote filters)
       - Hex literal encoding      (0x61646d696e → 'admin')
  7. WAF bypass header tricks (content-type confusion, chunked transfer)
  8. Request fragmentation (split payload across parameters)
  9. Session cookie simulation (real browser cookie jar)
 10. Random viewport/screen hints (looks like a browser, not a script)
"""

import random
import time
import re
import urllib.parse

# ─────────────────────────────────────────────────────────────────────────────
# USER-AGENT POOL (120+)
# ─────────────────────────────────────────────────────────────────────────────

_UA_DESKTOP = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    # Brave
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

_UA_MOBILE = [
    # Chrome Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; Redmi Note 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; CPH2505) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.193 Mobile Safari/537.36",
    # Safari iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    # Firefox Android
    "Mozilla/5.0 (Android 14; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0",
    "Mozilla/5.0 (Android 13; Mobile; rv:123.0) Gecko/123.0 Firefox/123.0",
    # Samsung Browser
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36",
    # Termux/Android (natural for this tool's origin)
    "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
]

_UA_LEGIT_BOTS = [
    # Search engine bots (sometimes let through WAFs)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Twitterbot/1.0",
    "LinkedInBot/1.0 (compatible; Mozilla/5.0; Jakarta Commons-HttpClient/3.1 +http://www.linkedin.com)",
]

ALL_UAS = _UA_DESKTOP + _UA_MOBILE + _UA_LEGIT_BOTS

# ─────────────────────────────────────────────────────────────────────────────
# REFERRER POOL (organic-looking)
# ─────────────────────────────────────────────────────────────────────────────

_REFERRERS = [
    "https://www.google.com/",
    "https://www.google.fr/",
    "https://www.google.co.uk/",
    "https://www.bing.com/search",
    "https://search.yahoo.com/",
    "https://duckduckgo.com/",
    "https://www.baidu.com/s",
    "https://yandex.ru/search/",
    "https://www.facebook.com/",
    "https://twitter.com/",
    "https://t.co/",
    "https://www.linkedin.com/",
    "https://www.reddit.com/",
    "https://news.ycombinator.com/",
    "https://www.instagram.com/",
    None,   # no referrer (direct visit)
    None,
    None,   # more weight to "direct"
]

# ─────────────────────────────────────────────────────────────────────────────
# ACCEPT HEADERS
# ─────────────────────────────────────────────────────────────────────────────

_ACCEPT_HTML = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
]

_ACCEPT_LANG = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.8,fr;q=0.5",
    "en-US,en;q=0.9,fr-FR;q=0.8,fr;q=0.7",
]

_ACCEPT_ENC = [
    "gzip, deflate, br",
    "gzip, deflate, br, zstd",
    "gzip, deflate",
    "br, gzip, deflate",
]

# ─────────────────────────────────────────────────────────────────────────────
# FAKE IP POOL (for X-Forwarded-For spoofing)
# ─────────────────────────────────────────────────────────────────────────────

_FAKE_IPS = [
    # Google DNS / popular IPs that may be whitelisted
    "8.8.8.8", "8.8.4.4",
    "1.1.1.1", "1.0.0.1",
    # Cloudflare
    "104.16.0.1", "104.16.1.1",
    # Random-looking residential IPs
    "192.168.1.1", "10.0.0.1",
    "172.16.0.1",
    # Various
    "185.220.101.1", "91.108.4.1",
    "213.180.204.3",
]


def _rand_ip():
    """Generate a random-looking IP"""
    return f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API — HEADER BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def random_ua(mobile_weight=0.25, bot_weight=0.05):
    """Return a random User-Agent string"""
    r = random.random()
    if r < bot_weight:
        return random.choice(_UA_LEGIT_BOTS)
    elif r < bot_weight + mobile_weight:
        return random.choice(_UA_MOBILE)
    else:
        return random.choice(_UA_DESKTOP)


# ─────────────────────────────────────────────────────────────────────────────
# CHROME CLIENT HINTS (sec-ch-ua) — modern browser fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

_CHROME_HINTS = [
    # (sec-ch-ua, sec-ch-ua-platform, sec-ch-ua-mobile, sec-ch-ua-platform-version)
    ('"Chromium";v="124","Google Chrome";v="124","Not-A.Brand";v="99"', '"Windows"', '?0', '"10.0.0"'),
    ('"Chromium";v="123","Google Chrome";v="123","Not-A.Brand";v="99"', '"Windows"', '?0', '"10.0.0"'),
    ('"Chromium";v="124","Google Chrome";v="124","Not-A.Brand";v="99"', '"macOS"',   '?0', '"14.4.1"'),
    ('"Chromium";v="124","Google Chrome";v="124","Not-A.Brand";v="99"', '"Linux"',   '?0', '""'),
    ('"Chromium";v="124","Google Chrome";v="124","Not-A.Brand";v="99"', '"Android"', '?1', '"14.0.0"'),
    ('"Chromium";v="120","Google Chrome";v="120","Not-A.Brand";v="99"', '"Windows"', '?0', '"11.0.0"'),
]

# Realistic Sec-GPC values
_SEC_GPC = [None, None, None, "1"]  # mostly absent, sometimes 1

# Realistic priority headers
_PRIORITY = ["u=0, i", "u=1", "u=3, i", None, None]


def random_headers(include_ip_spoof=True, include_referrer=True, custom_host=None):
    """
    Build a maximally realistic HTTP header dict for one request.
    Includes Chrome Client Hints, Sec-Fetch-*, Priority headers.
    include_ip_spoof: add X-Forwarded-For / X-Real-IP
    include_referrer: add Referer header
    custom_host: override Host header (subdomain takeover tests etc.)
    """
    ua = random_ua()
    is_chrome = "Chrome/" in ua and "Edg/" not in ua and "OPR/" not in ua
    is_mobile  = "Mobile" in ua or "Android" in ua

    headers = {
        "User-Agent":       ua,
        "Accept":           random.choice(_ACCEPT_HTML),
        "Accept-Language":  random.choice(_ACCEPT_LANG),
        "Accept-Encoding":  random.choice(_ACCEPT_ENC),
        "Connection":       random.choice(["keep-alive", "keep-alive"]),
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control":    random.choice(["no-cache", "max-age=0", "no-cache", ""]),
    }

    # Sec-Fetch-* headers (Chrome sends these)
    if is_chrome and random.random() < 0.85:
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = random.choice(["none", "cross-site"])
        headers["Sec-Fetch-User"] = "?1"
    elif random.random() < 0.3:
        headers["Sec-Fetch-Dest"] = random.choice(["document", "empty"])
        headers["Sec-Fetch-Mode"] = random.choice(["navigate", "cors"])
        headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin"])

    # Chrome Client Hints (sec-ch-ua) — critical for bypassing modern WAFs
    if is_chrome and random.random() < 0.75:
        hint = random.choice(_CHROME_HINTS)
        headers["sec-ch-ua"]                  = hint[0]
        headers["sec-ch-ua-platform"]         = hint[1]
        headers["sec-ch-ua-mobile"]           = "?1" if is_mobile else hint[2]
        # Sometimes add platform version
        if random.random() < 0.5:
            headers["sec-ch-ua-platform-version"] = hint[3]

    # DNT (not tracked)
    dnt = random.choice(["1", None, None, None])
    if dnt:
        headers["DNT"] = dnt

    # Sec-GPC (Global Privacy Control)
    gpc = random.choice(_SEC_GPC)
    if gpc:
        headers["Sec-GPC"] = gpc

    # Priority header (HTTP/2 style, Chrome 117+)
    prio = random.choice(_PRIORITY)
    if prio:
        headers["Priority"] = prio

    # IP spoofing headers (WAF bypass — make it look like request from allowed network)
    if include_ip_spoof and random.random() < 0.65:
        ip = _rand_ip() if random.random() > 0.35 else random.choice(_FAKE_IPS)
        spoof_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Originating-IP",
            "X-Remote-Addr",
            "X-Client-IP",
            "True-Client-IP",
            "CF-Connecting-IP",
            "X-Cluster-Client-IP",
        ]
        # Pick 1-2 spoof headers (fewer = less suspicious)
        for h in random.sample(spoof_headers, k=random.randint(1, 2)):
            headers[h] = ip

    # Referrer
    if include_referrer:
        ref = random.choice(_REFERRERS)
        if ref:
            headers["Referer"] = ref

    # Custom host
    if custom_host:
        headers["Host"] = custom_host

    # Remove None values
    headers = {k: v for k, v in headers.items() if v is not None and v != ""}

    return headers


def waf_bypass_headers():
    """
    Extra headers specifically to confuse WAFs:
    - Content-Type tricks
    - X-WAF-Bypass / X-Security-Token lookalikes
    - X-HTTP-Method-Override
    """
    headers = random_headers()
    tricks = {
        "X-Originating-IP":     "127.0.0.1",
        "X-Forwarded-Host":     "127.0.0.1",
        "X-Remote-IP":          "127.0.0.1",
        "X-Remote-Addr":        "127.0.0.1",
        "X-Host":               "127.0.0.1",
        "X-Custom-IP-Authorization": "127.0.0.1",
    }
    # Only add a random subset to avoid header bloat
    for k, v in random.sample(list(tricks.items()), k=random.randint(2, 4)):
        headers[k] = v
    return headers


# ─────────────────────────────────────────────────────────────────────────────
# TIMING / JITTER
# ─────────────────────────────────────────────────────────────────────────────

def jitter(min_s=0.05, max_s=0.4):
    """Sleep a random amount — mimic human/organic pacing"""
    time.sleep(random.uniform(min_s, max_s))


def slow_jitter(min_s=0.5, max_s=2.5):
    """Slower jitter for rate-limit evasion"""
    time.sleep(random.uniform(min_s, max_s))


def burst_jitter():
    """
    Intelligent jitter: mimics real browser request patterns.
    - Occasionally long pause (page reading time)
    - Frequent micro-pauses (browser processing)
    - Rare total break (user distraction / tab switching)
    """
    r = random.random()
    if r < 0.02:        # 2% — long break (user went for coffee)
        time.sleep(random.uniform(8, 25))
    elif r < 0.07:      # 5% — page read time
        time.sleep(random.uniform(2.5, 7))
    elif r < 0.20:      # 13% — normal page load gap
        time.sleep(random.uniform(0.8, 2.2))
    elif r < 0.45:      # 25% — fast click
        time.sleep(random.uniform(0.15, 0.6))
    else:               # 55% — rapid fire (API / XHR-style)
        time.sleep(random.uniform(0.01, 0.12))


def adaptive_jitter(requests_done=0, rate_limited=False):
    """
    Adaptive timing: slows down as requests accumulate or when rate-limited.
    Use this in tight scan loops to avoid threshold triggers.
    """
    if rate_limited:
        time.sleep(random.uniform(5, 15))
        return
    # Progressive slowdown every ~50 requests
    base = 0.05 + (requests_done // 50) * 0.1
    time.sleep(random.uniform(base, base + random.uniform(0.1, 0.5)))


# ─────────────────────────────────────────────────────────────────────────────
# SQL PAYLOAD OBFUSCATION
# ─────────────────────────────────────────────────────────────────────────────

_SQL_KEYWORDS = [
    "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "NULL",
    "UNION", "ORDER", "BY", "GROUP", "HAVING", "LIMIT",
    "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
    "TABLE", "DATABASE", "SCHEMA", "COLUMN", "INDEX",
    "EXTRACTVALUE", "UPDATEXML", "CONCAT", "CONCAT_WS",
    "SUBSTRING", "LENGTH", "ASCII", "CHAR", "VERSION",
    "SLEEP", "BENCHMARK", "IF", "CASE", "WHEN", "THEN",
    "INFORMATION_SCHEMA", "SCHEMATA", "TABLES", "COLUMNS",
]

_COMMENT_VARIANTS = [
    "/**/",
    "/*!*/",
    "/*--*/",
    "/*!50000*/",
    "/*!50001*/",
    " ",   # plain space (also valid between keywords)
]

_WHITESPACE_ALTS = ["\t", "\n", "\r", "%09", "%0a", "%0d", "%0c", "+"]


def random_case(keyword):
    """Randomly mix upper/lower case in a SQL keyword"""
    return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in keyword)


def obfuscate_keywords(sql, intensity=0.5):
    """
    Replace SQL keywords with randomly-cased versions (intensity 0..1).
    intensity: fraction of keywords to obfuscate
    """
    result = sql
    for kw in sorted(_SQL_KEYWORDS, key=len, reverse=True):
        if random.random() < intensity:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            result = pattern.sub(lambda m: random_case(m.group()), result, count=1)
    return result


def inject_sql_comments(sql, intensity=0.4):
    """
    Insert inline SQL comments between keywords to break WAF pattern matching.
    e.g.  UNION SELECT → UN/**/ION SE/**/LECT
    """
    result = sql
    for kw in sorted(_SQL_KEYWORDS, key=len, reverse=True):
        if random.random() < intensity and len(kw) >= 4:
            split_at  = random.randint(2, len(kw) - 2)
            comment   = random.choice(["/**/", "/*!*/", "/*!50000*/"])
            obfuscated = kw[:split_at] + comment + kw[split_at:]
            # Case-insensitive replace, first occurrence
            result = re.sub(re.escape(kw), obfuscated, result, count=1, flags=re.IGNORECASE)
    return result


def hex_encode_string(s):
    """Encode a string as SQL hex literal: 'admin' → 0x61646d696e"""
    return "0x" + s.encode("utf-8").hex()


def char_encode_string(s):
    """Encode a string as CHAR() function: 'admin' → CHAR(97,100,109,105,110)"""
    return "CHAR(" + ",".join(str(ord(c)) for c in s) + ")"


def encode_string_value(s, method=None):
    """
    Encode a string literal value using a random evasion method.
    Returns the SQL expression (no surrounding quotes needed).
    method: None=random, 'hex', 'char', 'plain'
    """
    if method is None:
        method = random.choice(["hex", "char", "hex", "plain"])
    if method == "hex":
        return hex_encode_string(s)
    elif method == "char":
        return char_encode_string(s)
    else:
        return f"'{s}'"


def url_encode_payload(payload, double=False):
    """URL-encode a payload (optionally double-encode)"""
    encoded = urllib.parse.quote(payload, safe="")
    if double:
        encoded = urllib.parse.quote(encoded, safe="")
    return encoded


def randomize_spaces(sql):
    """Replace single spaces with tab/newline/double-space variants"""
    parts = sql.split(" ")
    return random.choice(["\t", " \t", "\n", "  "]).join(parts)


def obfuscate_sql(sql, level=2):
    """
    Apply multiple layers of SQL obfuscation.
    level 1: light (case only)
    level 2: medium (case + comments)
    level 3: heavy (case + comments + whitespace + encoding hints)
    """
    result = sql
    if level >= 1:
        result = obfuscate_keywords(result, intensity=0.5)
    if level >= 2:
        result = inject_sql_comments(result, intensity=0.3)
    if level >= 3:
        result = randomize_spaces(result)
    return result


def mysql_version_comment(sql):
    """
    Wrap SQL in MySQL version comment: /*!50000 sql */
    This executes on MySQL >= 5.0.0 but appears as a comment to other parsers.
    """
    return f"/*!50000 {sql}*/"


# ─────────────────────────────────────────────────────────────────────────────
# PATH / PARAM OBFUSCATION
# ─────────────────────────────────────────────────────────────────────────────

def obfuscate_path(path):
    """
    Apply path obfuscation techniques:
    - Double URL encoding of slashes
    - Case variation for Windows/IIS
    - Path traversal normalization tricks
    """
    techniques = [
        lambda p: p,                              # plain
        lambda p: p.replace("/", "//"),           # double slash
        lambda p: p.replace("/", "/%2f"),         # encoded slash
        lambda p: p.replace("/", "/./"),          # dot segment
        lambda p: p.upper(),                      # uppercase (IIS case-insensitive)
        lambda p: p + "/",                        # trailing slash
        lambda p: p + "?",                        # trailing question mark
    ]
    fn = random.choice(techniques)
    return fn(path)


# ─────────────────────────────────────────────────────────────────────────────
# REQUESTS SESSION FACTORY
# ─────────────────────────────────────────────────────────────────────────────

def make_stealth_session(rotate_ua_per_req=False):
    """
    Create a requests.Session with:
    - Random UA
    - Random realistic headers
    - SSL warning suppression
    - Redirect following
    Returns the session object.
    """
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except ImportError:
        return None

    s = requests.Session()
    hdrs = random_headers(include_ip_spoof=True, include_referrer=True)
    s.headers.update(hdrs)
    s.verify = False
    s.max_redirects = 5

    if rotate_ua_per_req:
        # Monkey-patch send to rotate UA per request
        _orig_send = s.send
        def _send_with_rotation(prepared, **kwargs):
            prepared.headers["User-Agent"] = random_ua()
            return _orig_send(prepared, **kwargs)
        s.send = _send_with_rotation

    return s


def stealth_get(session, url, **kwargs):
    """GET request with random headers injected per call"""
    hdrs = random_headers()
    # Merge with any caller-supplied headers
    merged = {**hdrs, **kwargs.pop("headers", {})}
    burst_jitter()
    return session.get(url, headers=merged, **kwargs)


def stealth_post(session, url, **kwargs):
    """POST request with random headers injected per call"""
    hdrs = random_headers()
    merged = {**hdrs, **kwargs.pop("headers", {})}
    burst_jitter()
    return session.post(url, headers=merged, **kwargs)


# ─────────────────────────────────────────────────────────────────────────────
# WAF BYPASS PAYLOAD VARIANTS
# ─────────────────────────────────────────────────────────────────────────────

def sql_bypass_variants(payload):
    """
    Generate multiple evasion variants of a SQL injection payload.
    Returns list of (variant_name, transformed_payload).
    """
    variants = [
        ("plain",         payload),
        ("case_mix",      obfuscate_keywords(payload, intensity=1.0)),
        ("comment_inj",   inject_sql_comments(payload, intensity=0.6)),
        ("url_enc",       url_encode_payload(payload)),
        ("double_url",    url_encode_payload(payload, double=True)),
        ("version_cmt",   mysql_version_comment(payload)),
        ("whitespace",    randomize_spaces(payload)),
        ("multi",         inject_sql_comments(obfuscate_keywords(payload, 0.8), 0.5)),
    ]
    return variants


def waf_test_payload(base_payload, max_variants=4):
    """
    Try up to max_variants obfuscated versions of base_payload.
    Returns list of payload strings.
    """
    variants = sql_bypass_variants(base_payload)
    random.shuffle(variants)
    return [v[1] for v in variants[:max_variants]]


# ─────────────────────────────────────────────────────────────────────────────
# FINGERPRINT EVASION
# ─────────────────────────────────────────────────────────────────────────────

def random_viewport():
    """Return a random viewport hint (for canvas/JS fingerprinting bypass)"""
    resolutions = [
        "1920x1080", "1366x768", "1440x900", "1280x720",
        "1536x864", "1600x900", "2560x1440", "1280x800",
        "390x844",   "414x896",  "375x812",  "360x800",
    ]
    return random.choice(resolutions)


def random_timezone():
    """Return a random timezone offset"""
    return random.choice([-5, -6, -7, -8, 0, 1, 2, 3, 5, 8, 9])


# ─────────────────────────────────────────────────────────────────────────────
# CONVENIENCE: APPLY TO EXISTING REQUEST DICT
# ─────────────────────────────────────────────────────────────────────────────

def stealthify(headers_dict, spoof_ip=True, add_ref=True):
    """
    Merge evasion headers into an existing headers dict in-place.
    Returns the modified dict.
    """
    evasion = random_headers(include_ip_spoof=spoof_ip, include_referrer=add_ref)
    # evasion headers take priority unless caller already set them
    for k, v in evasion.items():
        if k not in headers_dict:
            headers_dict[k] = v
    return headers_dict


def stealth_request(session, method, url, **kwargs):
    """Universal stealth request (GET or POST)"""
    hdrs = random_headers()
    merged = {**hdrs, **kwargs.pop("headers", {})}
    burst_jitter()
    fn = session.get if method.upper() == "GET" else session.post
    return fn(url, headers=merged, **kwargs)


# ─────────────────────────────────────────────────────────────────────────────
# SESSION ROTATION — switch identity periodically
# ─────────────────────────────────────────────────────────────────────────────

class StealthRotator:
    """
    Manages a pool of session identities, rotating UA/headers every N requests.
    Prevents WAFs from correlating many requests to one fingerprint.

    Usage:
        rotator = StealthRotator(rotate_every=20)
        session = rotator.session
        r = rotator.get(url)
    """
    def __init__(self, rotate_every=25, pool_size=3):
        self.rotate_every  = rotate_every
        self.pool_size     = pool_size
        self._count        = 0
        self._sessions     = []
        self._cur          = 0
        self._build_pool()

    def _build_pool(self):
        try:
            import requests
            requests.packages.urllib3.disable_warnings()
        except ImportError:
            return
        self._sessions = [make_stealth_session(rotate_ua_per_req=True)
                          for _ in range(self.pool_size)]

    @property
    def session(self):
        if not self._sessions:
            return None
        return self._sessions[self._cur % len(self._sessions)]

    def rotate(self):
        """Force a session rotation."""
        self._cur = (self._cur + 1) % max(len(self._sessions), 1)
        self._count = 0

    def _maybe_rotate(self):
        self._count += 1
        if self._count >= self.rotate_every:
            self.rotate()

    def get(self, url, **kwargs):
        self._maybe_rotate()
        return stealth_get(self.session, url, **kwargs) if self.session else None

    def post(self, url, **kwargs):
        self._maybe_rotate()
        return stealth_post(self.session, url, **kwargs) if self.session else None


# ─────────────────────────────────────────────────────────────────────────────
# TLS / FINGERPRINT HINTS
# ─────────────────────────────────────────────────────────────────────────────

def tls_like_headers():
    """
    Extra headers that match common TLS fingerprints used by WAF bypass tools.
    Based on Chrome 124 TLS/HTTP2 fingerprint.
    """
    return {
        "te":              "trailers",          # HTTP/2 trailer support
        "Accept-Encoding": "gzip, deflate, br, zstd",
    }


def anti_bot_headers():
    """
    Headers that some anti-bot systems check for.
    Having these makes requests look more legitimate.
    """
    hdrs = random_headers(include_ip_spoof=False, include_referrer=False)
    # Add some very browser-specific headers
    if random.random() < 0.6:
        hdrs["Purpose"] = "prefetch"
    if random.random() < 0.4:
        hdrs["X-Requested-With"] = random.choice(["XMLHttpRequest", None]) or "XMLHttpRequest"
    return hdrs

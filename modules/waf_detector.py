"""
WAF/CDN Detector Module - UHQKYRA
Detect Web Application Firewalls, CDNs, and DDoS protection
"""
import requests
import re
import warnings
warnings.filterwarnings("ignore")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

# (header_name_lowercase, value_regex_or_None, waf_name, confidence_pts)
WAF_HEADER_SIGS = [
    # Cloudflare
    ("cf-ray",              None,           "Cloudflare",           3),
    ("cf-cache-status",     None,           "Cloudflare",           3),
    ("cf-request-id",       None,           "Cloudflare",           2),
    ("server",              r"cloudflare",  "Cloudflare",           3),
    # AWS CloudFront / WAF
    ("x-amz-cf-id",         None,           "Amazon CloudFront",    3),
    ("x-cache",             r"cloudfront",  "Amazon CloudFront",    2),
    ("x-amzn-requestid",    None,           "AWS WAF",              2),
    # Akamai
    ("x-akamai-transformed",None,           "Akamai",               3),
    ("akamai-origin-hop",   None,           "Akamai",               3),
    ("x-check-cacheable",   None,           "Akamai",               2),
    ("x-akamai-request-id", None,           "Akamai Kona",          3),
    # Imperva / Incapsula
    ("x-iinfo",             None,           "Imperva Incapsula",    3),
    ("x-cdn",               r"incapsula",   "Imperva Incapsula",    3),
    ("incap-ses",           None,           "Imperva Incapsula",    3),
    # Sucuri
    ("x-sucuri-id",         None,           "Sucuri",               3),
    ("x-sucuri-cache",      None,           "Sucuri",               3),
    ("server",              r"sucuri",      "Sucuri",               3),
    # F5 BIG-IP ASM
    ("x-wa-info",           None,           "F5 BIG-IP",            3),
    ("server",              r"big-ip",      "F5 BIG-IP",            3),
    ("x-cnection",          None,           "F5 BIG-IP ASM",        2),
    # Fastly
    ("x-fastly-request-id", None,           "Fastly CDN",           3),
    ("fastly-io-info",      None,           "Fastly",               3),
    # Varnish
    ("x-varnish",           None,           "Varnish Cache",        2),
    ("via",                 r"varnish",     "Varnish",              2),
    # Azure Front Door
    ("x-azure-ref",         None,           "Azure Front Door",     3),
    ("x-ms-request-id",     None,           "Azure WAF",            2),
    # Barracuda
    ("barra_counter_session",None,          "Barracuda WAF",        3),
    # Reblaze
    ("x-reblaze-protection",None,           "Reblaze WAF",          3),
    # DDoS-Guard
    ("ddos-guard",          None,           "DDoS-Guard",           3),
    # StackPath
    ("x-sp-url",            None,           "StackPath",            3),
    # Pantheon
    ("x-pantheon-styx-hostname",None,       "Pantheon CDN",         2),
    # Wordfence WordPress
    ("x-wordfence-blocked", None,           "Wordfence",            3),
    # Nginx WAF / OpenResty
    ("server",              r"openresty",   "OpenResty/WAF",        2),
]

BODY_WAF_SIGS = [
    (r"cloudflare",                     "Cloudflare",           3),
    (r"attention required.*cloudflare", "Cloudflare",           3),
    (r"ddos protection by cloudflare",  "Cloudflare",           3),
    (r"incapsula incident",             "Imperva Incapsula",    3),
    (r"incapsula",                      "Imperva Incapsula",    2),
    (r"sucuri cloudproxy",              "Sucuri",               3),
    (r"barracuda networks",             "Barracuda WAF",        3),
    (r"perimeterx",                     "PerimeterX",           3),
    (r"you have been blocked.*f5",      "F5 BIG-IP",            3),
    (r"forcepoint",                     "Forcepoint WAF",       3),
    (r"access denied.*asm",             "F5 ASM",               2),
    (r"this website is using a security service to protect", "Cloudflare", 2),
    (r"request unsuccessful.*incapsula","Imperva",              3),
    (r"ddos-guard",                     "DDoS-Guard",           3),
    (r"reblaze",                        "Reblaze WAF",          3),
]

# Payloads that trigger WAF blocking
ATTACK_PAYLOADS = [
    "/?test=<script>alert(1)</script>",
    "/?test=1' OR 1=1--",
    "/?test=../../../etc/passwd",
]

WAF_BLOCK_CODES = {403, 406, 419, 429, 500, 501, 503}


def detect_waf(url, callback=None):
    """Detect WAF/CDN/DDoS protection in front of the target"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {
        "detected": False,
        "waf_name": None,
        "confidence": "none",
        "cdn": None,
        "ip_info": {},
        "findings": [],
        "raw_headers": {}
    }

    import urllib.parse
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    waf_hits = {}

    # ── Normal request ───────────────────────────────────────────
    try:
        resp = requests.get(base, headers=HEADERS, timeout=12, allow_redirects=True, verify=False)
        results["raw_headers"] = dict(resp.headers)
        headers_lc = {k.lower(): v.lower() for k, v in resp.headers.items()}

        for hname, pattern, waf, pts in WAF_HEADER_SIGS:
            if hname in headers_lc:
                val = headers_lc[hname]
                if pattern is None or re.search(pattern, val, re.I):
                    waf_hits[waf] = waf_hits.get(waf, 0) + pts

        body = resp.text[:6000]
        for pattern, waf, pts in BODY_WAF_SIGS:
            if re.search(pattern, body, re.I):
                waf_hits[waf] = waf_hits.get(waf, 0) + pts

    except Exception as e:
        cb("warn", f"WAF probe (normal): {e}")

    # ── Attack probe ─────────────────────────────────────────────
    for payload in ATTACK_PAYLOADS[:2]:
        try:
            r2 = requests.get(base + payload, headers=HEADERS, timeout=8,
                              allow_redirects=False, verify=False)
            headers_lc2 = {k.lower(): v.lower() for k, v in r2.headers.items()}

            for hname, pattern, waf, pts in WAF_HEADER_SIGS:
                if hname in headers_lc2:
                    val = headers_lc2[hname]
                    if pattern is None or re.search(pattern, val, re.I):
                        waf_hits[waf] = waf_hits.get(waf, 0) + pts // 2

            if r2.status_code in WAF_BLOCK_CODES:
                body2 = r2.text[:3000]
                for pattern, waf, pts in BODY_WAF_SIGS:
                    if re.search(pattern, body2, re.I):
                        waf_hits[waf] = waf_hits.get(waf, 0) + pts

                if not waf_hits and r2.status_code in {403, 406}:
                    waf_hits["WAF/IPS Inconnu"] = waf_hits.get("WAF/IPS Inconnu", 0) + 2
        except Exception:
            pass

    # ── Evaluate ─────────────────────────────────────────────────
    if waf_hits:
        top_waf = max(waf_hits, key=waf_hits.get)
        score = waf_hits[top_waf]
        results["detected"] = True
        results["waf_name"] = top_waf
        results["confidence"] = "high" if score >= 5 else "medium" if score >= 3 else "low"
        results["findings"] = [
            {"waf": w, "score": s} for w, s in sorted(waf_hits.items(), key=lambda x: -x[1])
        ]
        cb("warn", f"🛡️  WAF/CDN : {top_waf} (confiance: {results['confidence']}, score: {score})")
    else:
        cb("ok", "✅ Aucun WAF/CDN détecté")

    return results

"""
Subdomain Takeover Checker - UHQKYRA v3.0
Detects dangling DNS records pointing to unclaimed services
"""
import warnings
warnings.filterwarnings("ignore")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# Service fingerprints for takeover detection
TAKEOVER_SIGS = [
    {"service": "GitHub Pages",    "cname": "github.io",           "fingerprint": "There isn't a GitHub Pages site here"},
    {"service": "Heroku",          "cname": "heroku.com",          "fingerprint": "No such app"},
    {"service": "Shopify",         "cname": "shopify.com",         "fingerprint": "Sorry, this shop is currently unavailable"},
    {"service": "Fastly",          "cname": "fastly.net",          "fingerprint": "Fastly error: unknown domain"},
    {"service": "Ghost",           "cname": "ghost.io",            "fingerprint": "The thing you were looking for is no longer here"},
    {"service": "Surge.sh",        "cname": "surge.sh",            "fingerprint": "project not found"},
    {"service": "AWS S3",          "cname": "s3.amazonaws.com",    "fingerprint": "NoSuchBucket"},
    {"service": "AWS CloudFront",  "cname": "cloudfront.net",      "fingerprint": "Bad request"},
    {"service": "Azure",           "cname": "azurewebsites.net",   "fingerprint": "404 Web Site not found"},
    {"service": "Zendesk",         "cname": "zendesk.com",         "fingerprint": "Help Center Closed"},
    {"service": "Tumblr",          "cname": "tumblr.com",          "fingerprint": "There's nothing here"},
    {"service": "Squarespace",     "cname": "squarespace.com",     "fingerprint": "No Such Account"},
    {"service": "Unbounce",        "cname": "unbounce.com",        "fingerprint": "The requested URL was not found"},
    {"service": "Statuspage",      "cname": "statuspage.io",       "fingerprint": "Better luck next time"},
    {"service": "Pantheon",        "cname": "pantheonsite.io",     "fingerprint": "The gods are wise"},
    {"service": "Helpscout",       "cname": "helpscout.net",       "fingerprint": "No settings were found for this company"},
    {"service": "Pingdom",         "cname": "pingdom.com",         "fingerprint": "This public report page has not been activated"},
    {"service": "Tilda",           "cname": "tilda.ws",            "fingerprint": "Please renew your subscription"},
    {"service": "WP Engine",       "cname": "wpengine.com",        "fingerprint": "The site you were looking for couldn't be found"},
    {"service": "Webflow",         "cname": "webflow.io",          "fingerprint": "The page you are looking for doesn't exist"},
    {"service": "Readme.io",       "cname": "readme.io",           "fingerprint": "Project doesnt exist"},
    {"service": "Intercom",        "cname": "intercom.io",         "fingerprint": "This page is reserved for artistic"},
    {"service": "Netlify",         "cname": "netlify.com",         "fingerprint": "Not Found - Request ID"},
    {"service": "HubSpot",         "cname": "hubspot.net",         "fingerprint": "Domain not found"},
]


def check_takeover(domain, subdomains=None, callback=None):
    """Check for subdomain takeover vulnerabilities"""
    def cb(t, m):
        if callback: callback({"type": t, "message": m})

    results = {"domain": domain, "vulnerable": [], "checked": 0}

    if not HAS_DNSPYTHON:
        cb("warn", "dnspython non disponible -- takeover check limite")
        return results

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    subs_to_check = subdomains or [domain]
    cb("info", f"Takeover check: {len(subs_to_check)} subdomain(s)...")

    if HAS_REQUESTS:
        s = requests.Session()
        s.headers.update(HEADERS)
        s.verify = False
    else:
        s = None

    for sub in subs_to_check:
        results["checked"] += 1
        fqdn = sub if isinstance(sub, str) else sub.get("subdomain", "")
        if not fqdn:
            continue

        # Get CNAME record
        try:
            cname_ans = resolver.resolve(fqdn, "CNAME")
            cname = str(cname_ans[0].target).lower().rstrip(".")
        except Exception:
            continue

        # Check against known service signatures
        for sig in TAKEOVER_SIGS:
            if sig["cname"] in cname:
                if s:
                    # Fetch the subdomain and check for takeover fingerprint
                    try:
                        r = s.get(f"http://{fqdn}", timeout=8)
                        if sig["fingerprint"].lower() in r.text.lower():
                            results["vulnerable"].append({
                                "subdomain": fqdn,
                                "cname": cname,
                                "service": sig["service"],
                                "fingerprint": sig["fingerprint"]
                            })
                            cb("vuln", f"TAKEOVER POSSIBLE: {fqdn} -> {sig['service']}")
                    except Exception:
                        # DNS resolves but no HTTP -- might still be vulnerable
                        results["vulnerable"].append({
                            "subdomain": fqdn,
                            "cname": cname,
                            "service": sig["service"],
                            "status": "dns_only"
                        })
                        cb("warn", f"CNAME dangling: {fqdn} -> {cname} ({sig['service']})")
                else:
                    results["vulnerable"].append({
                        "subdomain": fqdn,
                        "cname": cname,
                        "service": sig["service"],
                        "status": "dns_only"
                    })
                    cb("warn", f"CNAME dangling: {fqdn} -> {cname} ({sig['service']})")

    if not results["vulnerable"]:
        cb("ok", f"Pas de takeover detecte ({results['checked']} verifie(s))")
    else:
        cb("vuln", f"{len(results['vulnerable'])} takeover(s) detecte(s) !")

    return results

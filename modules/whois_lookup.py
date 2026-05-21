"""
WHOIS Lookup Module
Domain and IP WHOIS information retrieval
"""
import socket
import re
import subprocess
from datetime import datetime

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


WHOIS_SERVERS = {
    ".com": "whois.verisign-grs.com",
    ".net": "whois.verisign-grs.com",
    ".org": "whois.pir.org",
    ".info": "whois.afilias.net",
    ".io": "whois.nic.io",
    ".co": "whois.nic.co",
    ".uk": "whois.nic.uk",
    ".de": "whois.denic.de",
    ".fr": "whois.nic.fr",
    ".nl": "whois.sidn.nl",
    ".eu": "whois.eu",
    ".ru": "whois.tcinet.ru",
    ".cn": "whois.cnnic.cn",
    ".jp": "whois.jprs.jp",
}


def raw_whois(domain, server=None, port=43):
    """Perform raw WHOIS query"""
    if not server:
        # Determine WHOIS server from TLD
        tld = '.' + domain.split('.')[-1].lower()
        server = WHOIS_SERVERS.get(tld, "whois.iana.org")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, port))
        sock.send((domain + "\r\n").encode())

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        return response.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error: {str(e)}"


def parse_whois_data(raw_data):
    """Parse raw WHOIS data into structured format"""
    parsed = {}

    patterns = {
        "domain_name": r"(?:Domain Name|domain):\s*(.+)",
        "registrar": r"Registrar:\s*(.+)",
        "registrar_url": r"Registrar URL:\s*(.+)",
        "creation_date": r"(?:Creation Date|Created|created):\s*(.+)",
        "expiry_date": r"(?:Expiry Date|Expiration Date|expires):\s*(.+)",
        "updated_date": r"(?:Updated Date|last-updated):\s*(.+)",
        "status": r"(?:Domain Status|status):\s*(.+)",
        "registrant_org": r"Registrant Organization:\s*(.+)",
        "registrant_country": r"Registrant Country:\s*(.+)",
        "registrant_email": r"Registrant Email:\s*(.+)",
        "admin_email": r"Admin Email:\s*(.+)",
        "name_servers": r"Name Server:\s*(.+)",
        "dnssec": r"DNSSEC:\s*(.+)",
        "registrant_name": r"Registrant Name:\s*(.+)",
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, raw_data, re.IGNORECASE)
        if matches:
            if key in ["name_servers", "status"]:
                parsed[key] = [m.strip() for m in matches]
            else:
                parsed[key] = matches[0].strip()

    return parsed


def lookup_whois(target, callback=None):
    """Perform WHOIS lookup for domain or IP"""
    results = {
        "target": target,
        "type": "domain" if not _is_ip(target) else "ip",
        "raw": None,
        "parsed": {},
        "error": None
    }

    if callback:
        callback({"type": "info", "message": f"🔍 WHOIS lookup for {target}..."})

    if HAS_WHOIS:
        try:
            w = whois.whois(target)
            parsed = {}

            if w:
                # Extract fields
                for field in ["domain_name", "registrar", "creation_date", "expiration_date",
                             "updated_date", "status", "name_servers", "dnssec",
                             "registrant_name", "org", "country", "emails"]:
                    val = getattr(w, field, None)
                    if val:
                        if isinstance(val, list):
                            parsed[field] = [str(v) for v in val[:5]]
                        else:
                            parsed[field] = str(val)

                results["parsed"] = parsed

                if callback:
                    if "registrar" in parsed:
                        callback({"type": "found", "message": f"🏢 Registrar: {parsed['registrar']}"})
                    if "creation_date" in parsed:
                        callback({"type": "found", "message": f"📅 Created: {parsed['creation_date']}"})
                    if "expiration_date" in parsed:
                        exp = parsed["expiration_date"]
                        callback({"type": "found", "message": f"⏰ Expires: {exp}"})
                    if "name_servers" in parsed:
                        ns_list = parsed["name_servers"] if isinstance(parsed["name_servers"], list) else [parsed["name_servers"]]
                        for ns in ns_list[:4]:
                            callback({"type": "found", "message": f"🌐 NS: {ns}"})
                    if "country" in parsed:
                        callback({"type": "found", "message": f"🌍 Country: {parsed['country']}"})
                    if "org" in parsed:
                        callback({"type": "found", "message": f"🏛️  Org: {parsed['org']}"})
                    if "status" in parsed:
                        status_list = parsed["status"] if isinstance(parsed["status"], list) else [parsed["status"]]
                        for s in status_list[:3]:
                            callback({"type": "info", "message": f"📊 Status: {s[:80]}"})

        except Exception as e:
            # Fallback to raw WHOIS
            raw = raw_whois(target)
            results["raw"] = raw
            results["parsed"] = parse_whois_data(raw)

            if callback:
                parsed = results["parsed"]
                for k, v in parsed.items():
                    if v:
                        if isinstance(v, list):
                            for item in v[:3]:
                                callback({"type": "found", "message": f"  {k}: {item}"})
                        else:
                            callback({"type": "found", "message": f"  {k.replace('_', ' ').title()}: {v}"})
    else:
        # Raw WHOIS fallback
        raw = raw_whois(target)
        results["raw"] = raw
        results["parsed"] = parse_whois_data(raw)

        if callback:
            for k, v in results["parsed"].items():
                if v:
                    callback({"type": "found", "message": f"  {k.replace('_', ' ').title()}: {v if isinstance(v, str) else ', '.join(v)}"})

    # Check privacy protection
    if results["parsed"]:
        reg_email = results["parsed"].get("registrant_email", "") or results["parsed"].get("emails", "")
        if reg_email and any(p in str(reg_email).lower() for p in ["privacy", "whoisguard", "protect", "redacted"]):
            if callback:
                callback({"type": "info", "message": "🔒 WHOIS privacy protection active"})
        elif not reg_email:
            if callback:
                callback({"type": "info", "message": "ℹ️  Contact information hidden/redacted (GDPR)"})

    if callback:
        callback({"type": "complete", "message": "✅ WHOIS lookup complete"})

    return results


def _is_ip(target):
    """Check if target is an IP address"""
    try:
        socket.inet_aton(target)
        return True
    except:
        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except:
            return False


def get_ip_geolocation(ip, callback=None):
    """Get geolocation info for an IP address"""
    try:
        import requests
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query",
                          timeout=5)
        data = resp.json()

        if data.get("status") == "success":
            if callback:
                callback({"type": "found", "message": f"🌍 Country: {data.get('country')} ({data.get('countryCode')})"})
                callback({"type": "found", "message": f"🏙️  City: {data.get('city')}, {data.get('regionName')}"})
                callback({"type": "found", "message": f"📍 Coordinates: {data.get('lat')}, {data.get('lon')}"})
                callback({"type": "found", "message": f"🌐 ISP: {data.get('isp')}"})
                callback({"type": "found", "message": f"🔢 ASN: {data.get('as')}"})
                callback({"type": "found", "message": f"⏰ Timezone: {data.get('timezone')}"})
            return data
    except Exception as e:
        if callback:
            callback({"type": "error", "message": f"Geolocation lookup failed: {e}"})
    return {}

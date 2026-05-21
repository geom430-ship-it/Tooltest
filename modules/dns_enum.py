"""
DNS Enumeration Module
Comprehensive DNS reconnaissance including record enumeration and subdomain discovery
"""
import socket
import concurrent.futures
import time

try:
    import dns.resolver
    import dns.reversename
    import dns.zone
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# Common subdomains for bruteforce
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "blog", "dev", "test", "stage", "staging",
    "api", "app", "cdn", "cloud", "cpanel", "db", "demo", "dns", "docs",
    "email", "forum", "git", "help", "images", "img", "jenkins", "jira",
    "ldap", "login", "m", "media", "mobile", "monitor", "ns1", "ns2",
    "old", "panel", "portal", "proxy", "remote", "secure", "shop", "smtp",
    "ssh", "store", "support", "vpn", "web", "webmail", "wiki", "wp",
    "static", "assets", "files", "backup", "beta", "auth", "oauth",
    "gateway", "hub", "internal", "labs", "legacy", "new", "office",
    "ops", "preview", "private", "prod", "public", "qa", "research",
    "sandbox", "server", "service", "services", "status", "upload",
    "video", "www2", "www3", "intranet", "extranet", "exchange",
    "outlook", "calendar", "meet", "conference", "chat", "slack",
    "kibana", "grafana", "prometheus", "elasticsearch", "redis",
    "mysql", "postgres", "mongodb", "cassandra", "kafka", "rabbitmq",
    "ns3", "ns4", "mx1", "mx2", "smtp2", "pop", "pop3", "imap",
    "autodiscover", "autoconfig", "webdisk", "cpcalendars", "cpcontacts",
    "whm", "cpanel2", "ftp2", "direct", "bounce",
    "uat", "sit", "perf", "preprod", "integration", "acceptance",
    "hotfix", "release", "canary", "edge", "origin", "mirror",
    "download", "downloads", "update", "updates", "patch",
    "manage", "management", "dashboard", "console", "control",
    "monitoring", "alerting", "logging", "metrics", "analytics",
    "tracking", "reporting", "reports", "data", "datadog",
    "splunk", "siem", "waf", "firewall", "ids", "ips",
    "router", "switch", "gateway2", "ap", "wifi", "wireless",
    "printer", "scanner", "camera", "iot", "device",
]

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA"]


def resolve_record(domain, record_type, nameserver=None):
    """Resolve a specific DNS record type"""
    if not HAS_DNSPYTHON:
        return _fallback_resolve(domain, record_type)

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        if nameserver:
            resolver.nameservers = [nameserver]

        answers = resolver.resolve(domain, record_type)
        results = []

        for rdata in answers:
            if record_type == "MX":
                results.append({"priority": rdata.preference, "value": str(rdata.exchange)})
            elif record_type == "SOA":
                results.append({
                    "mname": str(rdata.mname),
                    "rname": str(rdata.rname),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "ttl": rdata.minimum
                })
            elif record_type == "SRV":
                results.append({
                    "priority": rdata.priority,
                    "weight": rdata.weight,
                    "port": rdata.port,
                    "target": str(rdata.target)
                })
            else:
                results.append(str(rdata))

        return results
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return []
    except Exception:
        return None


def _fallback_resolve(domain, record_type):
    """Fallback DNS resolution using socket"""
    if record_type == "A":
        try:
            ip = socket.gethostbyname(domain)
            return [ip]
        except:
            return None
    return []


def enumerate_records(domain, callback=None):
    """Enumerate all DNS record types for a domain"""
    results = {
        "domain": domain,
        "records": {},
        "nameservers": [],
        "zone_transfer": False,
        "errors": []
    }

    if callback:
        callback({"type": "info", "message": f"🔍 Enumerating DNS records for {domain}..."})

    for record_type in DNS_RECORD_TYPES:
        try:
            records = resolve_record(domain, record_type)
            if records is not None and records != []:
                results["records"][record_type] = records
                if callback:
                    if record_type == "MX":
                        for r in records:
                            callback({"type": "found", "message": f"📧 MX: {r['priority']} {r['value']}"})
                    elif record_type == "NS":
                        results["nameservers"] = records
                        for r in records:
                            callback({"type": "found", "message": f"🌐 NS: {r}"})
                    elif record_type == "TXT":
                        for r in records:
                            callback({"type": "found", "message": f"📝 TXT: {r}"})
                            # Check for interesting TXT records
                            if "spf" in r.lower():
                                callback({"type": "info", "message": f"  ↳ SPF record found"})
                            if "dkim" in r.lower():
                                callback({"type": "info", "message": f"  ↳ DKIM record found"})
                            if "dmarc" in r.lower():
                                callback({"type": "info", "message": f"  ↳ DMARC record found"})
                            if "google-site-verification" in r.lower():
                                callback({"type": "info", "message": f"  ↳ Google verification found"})
                    elif record_type in ["A", "AAAA"]:
                        for r in records:
                            callback({"type": "found", "message": f"🖥️  {record_type}: {r}"})
                    elif record_type == "SOA":
                        for r in records:
                            callback({"type": "found", "message": f"🔑 SOA: {r.get('mname', 'N/A')} (serial: {r.get('serial', 'N/A')})"})
                    else:
                        for r in records:
                            callback({"type": "found", "message": f"📌 {record_type}: {r}"})
        except Exception as e:
            results["errors"].append(f"{record_type}: {str(e)}")

    # Try zone transfer
    if results["nameservers"]:
        if callback:
            callback({"type": "info", "message": "⚡ Testing zone transfer (AXFR)..."})
        for ns in results["nameservers"][:3]:
            ns_str = str(ns).rstrip('.')
            try:
                if HAS_DNSPYTHON:
                    z = dns.zone.from_xfr(dns.query.xfr(ns_str, domain))
                    results["zone_transfer"] = True
                    results["zone_data"] = [str(n) for n in z.nodes.keys()]
                    if callback:
                        callback({"type": "vuln", "message": f"🚨 ZONE TRANSFER ALLOWED on {ns_str}! (Critical vulnerability)"})
                    break
            except Exception:
                pass

    if not results["zone_transfer"] and callback:
        callback({"type": "ok", "message": "✅ Zone transfer not allowed (secure)"})

    return results


def enumerate_subdomains(domain, wordlist=None, max_workers=50, callback=None):
    """Enumerate subdomains via DNS brute force"""
    results = {
        "domain": domain,
        "found": [],
        "total_checked": 0
    }

    subdomains = wordlist if wordlist else COMMON_SUBDOMAINS

    if callback:
        callback({"type": "info", "message": f"🔎 Bruteforcing {len(subdomains)} subdomains for {domain}..."})

    def check_subdomain(sub):
        full_domain = f"{sub}.{domain}"
        try:
            if HAS_DNSPYTHON:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 3
                answers = resolver.resolve(full_domain, "A")
                ips = [str(r) for r in answers]
                return {"subdomain": full_domain, "ips": ips}
            else:
                ip = socket.gethostbyname(full_domain)
                return {"subdomain": full_domain, "ips": [ip]}
        except:
            return None

    checked = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_sub = {executor.submit(check_subdomain, sub): sub for sub in subdomains}

        for future in concurrent.futures.as_completed(future_to_sub):
            sub = future_to_sub[future]
            checked += 1
            results["total_checked"] = checked

            try:
                result = future.result()
                if result:
                    results["found"].append(result)
                    ips_str = ", ".join(result["ips"])
                    if callback:
                        callback({"type": "found", "message": f"✅ {result['subdomain']} → {ips_str}", "data": result})
            except Exception:
                pass

            if callback and checked % 50 == 0:
                callback({"type": "progress", "message": f"Checked {checked}/{len(subdomains)}...", "percent": int(checked/len(subdomains)*100)})

    if callback:
        callback({"type": "complete", "message": f"✅ Found {len(results['found'])} subdomains out of {checked} checked"})

    return results


def reverse_dns(ip, callback=None):
    """Perform reverse DNS lookup"""
    try:
        if HAS_DNSPYTHON:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, "PTR")
            hostnames = [str(r) for r in answers]
        else:
            hostname = socket.gethostbyaddr(ip)
            hostnames = [hostname[0]]

        if callback:
            for h in hostnames:
                callback({"type": "found", "message": f"🔄 {ip} → {h}"})
        return hostnames
    except Exception as e:
        if callback:
            callback({"type": "error", "message": f"No PTR record for {ip}"})
        return []


def check_dnssec(domain, callback=None):
    """Check if DNSSEC is enabled"""
    if not HAS_DNSPYTHON:
        return False
    try:
        resolver = dns.resolver.Resolver()
        resolver.use_dnssec = True
        answers = resolver.resolve(domain, "DNSKEY")
        if answers:
            if callback:
                callback({"type": "ok", "message": f"✅ DNSSEC enabled for {domain}"})
            return True
    except Exception:
        if callback:
            callback({"type": "warn", "message": f"⚠️  DNSSEC not enabled for {domain}"})
        return False

"""
Subdomain Enumerator - UHQKYRA v3.0
DNS brute-force subdomain enumeration with 500+ wordlist
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings("ignore")

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

SUBDOMAIN_WORDLIST = [
    "www","mail","ftp","admin","api","app","blog","cdn","chat","cloud","cms","code",
    "cpanel","dashboard","db","dev","docs","download","email","files","forum","git",
    "help","home","host","images","img","intranet","jenkins","jira","ldap","login",
    "m","manage","mobile","monitor","mx","mysql","nagios","news","ns1","ns2","ns3",
    "ns4","old","ops","panel","pay","portal","prod","remote","reports","secure",
    "server","shop","smtp","sql","ssh","ssl","staging","static","stats","status",
    "support","test","vpn","web","webmail","wiki","www2","backup","beta","billing",
    "office","crm","erp","hr","uat","qa","demo","upload","assets","media","api2",
    "v1","v2","v3","internal","ext","external","public","private","s3","aws","azure",
    "gcp","docker","k8s","kubernetes","ci","cd","gitlab","github","bitbucket","jira",
    "confluence","redmine","jenkins2","nagios3","zabbix","grafana","kibana","elastic",
    "logstash","prometheus","vault","consul","nomad","traefik","nginx","apache",
    "imap","pop","pop3","relay","gateway","proxy","mx1","mx2","ns","dns","rdp",
    "sftp","scp","terminal","shell","bash","python","node","php","java","ruby",
    "postgres","redis","mongo","cassandra","memcache","kafka","rabbitmq","celery",
    "broker","worker","scheduler","cron","task","queue","stream","event","webhook",
    "auth","oauth","sso","saml","ldap2","ad","activedirectory","radius","kerberos",
    "pki","ca","cert","ssl2","tls","waf","lb","haproxy","varnish","squid","cdn2",
    "edge","origin","assets2","static2","img2","media2","video","audio","docs2",
    "kb","faq","forum2","community","social","connect","link","click","track",
    "analytics","metrics","log","logs","audit","security","compliance","legal",
    "privacy","terms","about","contact","career","jobs","partners","affiliates",
    "blog2","news2","press","ir","investor","annual","report","archive","old2",
    "legacy","classic","v0","v4","v5","latest","new","next","alpha","preview",
]


def enumerate_subdomains_fast(domain, callback=None):
    """Fast subdomain enumeration"""
    def cb(t, m):
        if callback: callback({"type": t, "message": m})

    results = {"domain": domain, "found": [], "count": 0}
    cb("info", f"Enumeration subdomains: {domain} ({len(SUBDOMAIN_WORDLIST)} wordlist)...")

    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        def check(sub):
            fqdn = f"{sub}.{domain}"
            try:
                answers = resolver.resolve(fqdn, "A")
                ips = [str(r) for r in answers]
                return {"subdomain": fqdn, "ips": ips, "type": "A"}
            except Exception:
                return None
    else:
        def check(sub):
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                return {"subdomain": fqdn, "ips": [ip], "type": "A"}
            except Exception:
                return None

    found = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(check, sub): sub for sub in SUBDOMAIN_WORDLIST}
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                found.append(res)
                cb("found", f"FOUND: {res['subdomain']} -> {', '.join(res['ips'])}")

    found.sort(key=lambda x: x["subdomain"])
    results["found"] = found
    results["count"] = len(found)
    cb("ok" if found else "warn", f"{len(found)} subdomain(s) trouve(s)")
    return results

"""
UHQKYRA v3.0 - Web-Based Penetration Testing Tool
Flask backend with real-time streaming via SSE
IMPORTANT: For authorized security testing only
"""

from flask import Flask, render_template, request, jsonify, Response, send_file
from flask_cors import CORS
import json
import os
import threading
import queue
import time
from datetime import datetime

# Import our modules
from modules.port_scanner import scan_ports, parse_port_input, get_common_ports
from modules.dns_enum import enumerate_records, enumerate_subdomains, reverse_dns, check_dnssec
from modules.http_analyzer import full_http_analysis, check_cors
from modules.ssl_analyzer import full_ssl_analysis
from modules.dir_scanner import scan_directories, check_robots_txt
from modules.whois_lookup import lookup_whois, get_ip_geolocation
from modules.network_tools import ping_host, traceroute, banner_grab, nslookup, check_firewall
from modules.vuln_scanner import (
    test_sqli, test_xss, test_lfi, test_open_redirect, check_security_misconfigs,
    test_command_injection, test_nosql_injection, test_crlf_injection,
    test_xxe, test_ldap_injection
)
from modules.db_extractor import full_db_extraction, detect_db_type, get_databases, get_tables, get_columns, dump_table
from modules.hash_tools import identify_hash, generate_hash, crack_hash, analyze_password_strength, generate_password
from modules.report_generator import generate_html_report, save_report
# New modules v3.0
from modules.waf_detector import detect_waf
from modules.cms_scanner import scan_cms
from modules.js_analyzer import analyze_js
from modules.advanced_vuln import (
    run_all_advanced, discover_api_endpoints,
    discover_parameters, test_ssrf, test_ssti
)
from modules.email_security import check_email_security
# New modules v4.0
from modules.subdomain_enum import enumerate_subdomains_fast
from modules.jwt_analyzer import analyze_jwt, find_jwt_in_response, find_jwts_on_page
from modules.login_bruteforce import scan_login_bruteforce
from modules.graphql_auditor import scan_graphql
from modules.idor_scanner import scan_idor
from modules.takeover_checker import check_takeover

app = Flask(__name__)
CORS(app)

# Store active scan queues
scan_queues = {}
scan_results_store = {}


def run_scan_with_queue(scan_func, scan_id, *args, **kwargs):
    """Run a scan function and store results in a queue"""
    q = queue.Queue()
    scan_queues[scan_id] = q
    scan_results_store[scan_id] = {"status": "running", "data": None}

    def callback(msg):
        q.put(msg)

    def run():
        try:
            kwargs['callback'] = callback
            result = scan_func(*args, **kwargs)
            scan_results_store[scan_id]["data"] = result
            scan_results_store[scan_id]["status"] = "complete"
            q.put({"type": "done", "message": "Scan complete", "data": result})
        except Exception as e:
            scan_results_store[scan_id]["status"] = "error"
            q.put({"type": "error", "message": f"Error: {str(e)}"})
            q.put({"type": "done", "message": "Error occurred"})

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return scan_id


def stream_scan(scan_id):
    """Generator for SSE streaming of scan results"""
    q = scan_queues.get(scan_id)
    if not q:
        yield f"data: {json.dumps({'type': 'error', 'message': 'Scan not found'})}\n\n"
        return

    while True:
        try:
            msg = q.get(timeout=30)
            yield f"data: {json.dumps(msg)}\n\n"
            if msg.get("type") == "done":
                break
        except queue.Empty:
            yield f"data: {json.dumps({'type': 'keepalive'})}\n\n"


# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    return render_template('index.html')


# --- Port Scanner ---
@app.route('/api/scan/ports', methods=['POST'])
def api_port_scan():
    data = request.json
    target = data.get('target', '').strip()
    port_type = data.get('port_type', 'common')
    custom_ports = data.get('custom_ports', '')
    threads = int(data.get('threads', 100))

    if not target:
        return jsonify({"error": "Target required"}), 400

    # Parse ports
    if port_type == 'custom' and custom_ports:
        ports = parse_port_input(custom_ports)
    elif port_type == 'common':
        ports = get_common_ports()
    elif port_type == 'full':
        ports = list(range(1, 65536))
    else:
        ports = get_common_ports()

    scan_id = f"ports_{int(time.time()*1000)}"
    run_scan_with_queue(scan_ports, scan_id, target, ports=ports, max_workers=threads)

    return jsonify({"scan_id": scan_id})


@app.route('/api/stream/<scan_id>')
def stream_results(scan_id):
    return Response(
        stream_scan(scan_id),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Access-Control-Allow-Origin': '*'
        }
    )


# --- DNS Enumeration ---
@app.route('/api/scan/dns', methods=['POST'])
def api_dns_scan():
    data = request.json
    target = data.get('target', '').strip()
    mode = data.get('mode', 'records')  # records, subdomains, reverse

    if not target:
        return jsonify({"error": "Target required"}), 400

    scan_id = f"dns_{int(time.time()*1000)}"

    if mode == 'records':
        run_scan_with_queue(enumerate_records, scan_id, target)
    elif mode == 'subdomains':
        run_scan_with_queue(enumerate_subdomains, scan_id, target)
    elif mode == 'reverse':
        run_scan_with_queue(reverse_dns, scan_id, target)
    else:
        run_scan_with_queue(enumerate_records, scan_id, target)

    return jsonify({"scan_id": scan_id})


# --- HTTP Analysis ---
@app.route('/api/scan/http', methods=['POST'])
def api_http_scan():
    data = request.json
    target = data.get('target', '').strip()

    if not target:
        return jsonify({"error": "Target required"}), 400

    scan_id = f"http_{int(time.time()*1000)}"
    run_scan_with_queue(full_http_analysis, scan_id, target)

    return jsonify({"scan_id": scan_id})


# --- SSL Analysis ---
@app.route('/api/scan/ssl', methods=['POST'])
def api_ssl_scan():
    data = request.json
    target = data.get('target', '').strip()
    port = int(data.get('port', 443))

    if not target:
        return jsonify({"error": "Target required"}), 400

    scan_id = f"ssl_{int(time.time()*1000)}"
    run_scan_with_queue(full_ssl_analysis, scan_id, target, port=port)

    return jsonify({"scan_id": scan_id})


# --- Directory Scanner ---
@app.route('/api/scan/dirs', methods=['POST'])
def api_dir_scan():
    data = request.json
    target = data.get('target', '').strip()
    extensions = data.get('extensions', '').split(',') if data.get('extensions') else None
    threads = int(data.get('threads', 30))

    if not target:
        return jsonify({"error": "Target required"}), 400

    if extensions:
        extensions = [e.strip().lstrip('.') for e in extensions if e.strip()]

    scan_id = f"dirs_{int(time.time()*1000)}"
    run_scan_with_queue(scan_directories, scan_id, target, extensions=extensions, max_workers=threads)

    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/robots', methods=['POST'])
def api_robots():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"robots_{int(time.time()*1000)}"
    run_scan_with_queue(check_robots_txt, scan_id, target)
    return jsonify({"scan_id": scan_id})


# --- WHOIS ---
@app.route('/api/scan/whois', methods=['POST'])
def api_whois():
    data = request.json
    target = data.get('target', '').strip()

    if not target:
        return jsonify({"error": "Target required"}), 400

    scan_id = f"whois_{int(time.time()*1000)}"
    run_scan_with_queue(lookup_whois, scan_id, target)

    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/geoip', methods=['POST'])
def api_geoip():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"geoip_{int(time.time()*1000)}"
    run_scan_with_queue(get_ip_geolocation, scan_id, target)
    return jsonify({"scan_id": scan_id})


# --- Network Tools ---
@app.route('/api/scan/ping', methods=['POST'])
def api_ping():
    data = request.json
    target = data.get('target', '').strip()
    count = int(data.get('count', 4))

    if not target:
        return jsonify({"error": "Target required"}), 400

    scan_id = f"ping_{int(time.time()*1000)}"
    run_scan_with_queue(ping_host, scan_id, target, count=count)

    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/traceroute', methods=['POST'])
def api_traceroute():
    data = request.json
    target = data.get('target', '').strip()

    if not target:
        return jsonify({"error": "Target required"}), 400

    scan_id = f"trace_{int(time.time()*1000)}"
    run_scan_with_queue(traceroute, scan_id, target)

    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/banner', methods=['POST'])
def api_banner():
    data = request.json
    target = data.get('target', '').strip()
    ports_str = data.get('ports', '21,22,25,80,110,143,443,8080')
    ports = parse_port_input(ports_str)

    if not target:
        return jsonify({"error": "Target required"}), 400

    scan_id = f"banner_{int(time.time()*1000)}"
    run_scan_with_queue(banner_grab, scan_id, target, ports=ports)

    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/nslookup', methods=['POST'])
def api_nslookup():
    data = request.json
    target = data.get('target', '').strip()
    record_type = data.get('record_type', 'A')
    scan_id = f"nslookup_{int(time.time()*1000)}"
    run_scan_with_queue(nslookup, scan_id, target, record_type=record_type)
    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/firewall', methods=['POST'])
def api_firewall():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"fw_{int(time.time()*1000)}"
    run_scan_with_queue(check_firewall, scan_id, target)
    return jsonify({"scan_id": scan_id})


# --- Vulnerability Scanner ---
@app.route('/api/scan/sqli', methods=['POST'])
def api_sqli():
    data = request.json
    target = data.get('target', '').strip()
    param = data.get('param', '').strip() or None

    if not target:
        return jsonify({"error": "Target required"}), 400

    scan_id = f"sqli_{int(time.time()*1000)}"
    run_scan_with_queue(test_sqli, scan_id, target, param=param)

    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/xss', methods=['POST'])
def api_xss():
    data = request.json
    target = data.get('target', '').strip()
    param = data.get('param', '').strip() or None

    scan_id = f"xss_{int(time.time()*1000)}"
    run_scan_with_queue(test_xss, scan_id, target, param=param)

    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/lfi', methods=['POST'])
def api_lfi():
    data = request.json
    target = data.get('target', '').strip()
    param = data.get('param', '').strip() or None

    scan_id = f"lfi_{int(time.time()*1000)}"
    run_scan_with_queue(test_lfi, scan_id, target, param=param)

    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/redirect', methods=['POST'])
def api_redirect():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"redir_{int(time.time()*1000)}"
    run_scan_with_queue(test_open_redirect, scan_id, target)
    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/misconfig', methods=['POST'])
def api_misconfig():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"misc_{int(time.time()*1000)}"
    run_scan_with_queue(check_security_misconfigs, scan_id, target)
    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/cmdi', methods=['POST'])
def api_cmdi():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"cmdi_{int(time.time()*1000)}"
    run_scan_with_queue(test_command_injection, scan_id, target)
    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/nosql', methods=['POST'])
def api_nosql():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"nosql_{int(time.time()*1000)}"
    run_scan_with_queue(test_nosql_injection, scan_id, target)
    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/crlf', methods=['POST'])
def api_crlf():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"crlf_{int(time.time()*1000)}"
    run_scan_with_queue(test_crlf_injection, scan_id, target)
    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/xxe', methods=['POST'])
def api_xxe():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"xxe_{int(time.time()*1000)}"
    run_scan_with_queue(test_xxe, scan_id, target)
    return jsonify({"scan_id": scan_id})


# --- Database Extraction ---
@app.route('/api/scan/db', methods=['POST'])
def api_db_extract():
    data = request.json
    target = data.get('target', '').strip()
    param = data.get('param', '').strip()
    mode = data.get('mode', 'basic')
    db_type = data.get('db_type') or None
    target_table = data.get('table') or None
    target_columns = data.get('columns', '').split(',') if data.get('columns') else None
    limit = int(data.get('limit', 20))

    if not target or not param:
        return jsonify({"error": "Target URL and parameter required"}), 400

    scan_id = f"db_{int(time.time()*1000)}"
    run_scan_with_queue(
        full_db_extraction, scan_id, target, param,
        mode=mode, db_type=db_type, target_table=target_table,
        target_columns=target_columns, limit=limit
    )

    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/db/detect', methods=['POST'])
def api_db_detect():
    data = request.json
    target = data.get('target', '').strip()
    param = data.get('param', '').strip()

    if not target or not param:
        return jsonify({"error": "Target and param required"}), 400

    scan_id = f"dbdetect_{int(time.time()*1000)}"
    run_scan_with_queue(detect_db_type, scan_id, target, param)
    return jsonify({"scan_id": scan_id})


# --- Hash Tools ---
@app.route('/api/hash/identify', methods=['POST'])
def api_hash_identify():
    data = request.json
    hash_str = data.get('hash', '').strip()
    types = identify_hash(hash_str)
    return jsonify({"hash": hash_str, "possible_types": types})


@app.route('/api/hash/generate', methods=['POST'])
def api_hash_generate():
    data = request.json
    text = data.get('text', '')
    algorithm = data.get('algorithm', 'md5')
    result = generate_hash(text, algorithm)
    return jsonify({"text": text, "algorithm": algorithm, "hash": result})


@app.route('/api/hash/crack', methods=['POST'])
def api_hash_crack():
    data = request.json
    hash_str = data.get('hash', '').strip()
    wordlist = data.get('wordlist', '').split('\n') if data.get('wordlist') else None

    scan_id = f"crack_{int(time.time()*1000)}"
    run_scan_with_queue(crack_hash, scan_id, hash_str, wordlist=wordlist)

    return jsonify({"scan_id": scan_id})


@app.route('/api/hash/analyze', methods=['POST'])
def api_password_analyze():
    data = request.json
    password = data.get('password', '')
    result = analyze_password_strength(password)
    return jsonify(result)


@app.route('/api/hash/generate-password', methods=['POST'])
def api_generate_password():
    data = request.json
    length = int(data.get('length', 16))
    use_upper = data.get('upper', True)
    use_digits = data.get('digits', True)
    use_special = data.get('special', True)
    password = generate_password(length, use_upper, use_digits, use_special)
    strength = analyze_password_strength(password)
    return jsonify({"password": password, "strength": strength})


# --- Report Generation ---
@app.route('/api/report/generate', methods=['POST'])
def api_generate_report():
    data = request.json
    title = data.get('title', 'Security Assessment Report')
    target = data.get('target', 'Unknown')
    sections = data.get('sections', {})

    scan_data = {"target": target, "sections": sections}
    html = generate_html_report(scan_data, title)

    # Save to file
    filename = save_report(html)

    return jsonify({"success": True, "filename": filename, "html": html})


@app.route('/api/report/download/<path:filename>')
def api_download_report(filename):
    try:
        return send_file(filename, as_attachment=True)
    except:
        return jsonify({"error": "File not found"}), 404


# --- Results ---
@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    result = scan_results_store.get(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(result)


# --- Dork Generator ---
@app.route('/api/dorks', methods=['POST'])
def api_dorks():
    data = request.json
    target = data.get('target', '').strip()
    category = data.get('category', 'all')

    dorks = generate_dorks(target, category)
    return jsonify({"dorks": dorks})


def generate_dorks(target, category="all"):
    """Generate Google dork queries"""
    dorks = []
    domain = target.replace('https://', '').replace('http://', '').split('/')[0]

    categories = {
        "files": [
            f'site:{domain} ext:pdf',
            f'site:{domain} ext:doc OR ext:docx',
            f'site:{domain} ext:xls OR ext:xlsx',
            f'site:{domain} ext:sql',
            f'site:{domain} ext:bak OR ext:backup',
            f'site:{domain} ext:log',
            f'site:{domain} ext:cfg OR ext:conf',
            f'site:{domain} ext:xml',
            f'site:{domain} ext:json',
            f'site:{domain} ext:env',
        ],
        "admin": [
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:dashboard',
            f'site:{domain} inurl:panel',
            f'site:{domain} inurl:cpanel',
            f'site:{domain} inurl:phpmyadmin',
            f'site:{domain} inurl:wp-admin',
            f'site:{domain} intitle:"admin"',
            f'site:{domain} intitle:"login"',
            f'site:{domain} "admin" "password"',
        ],
        "sensitive": [
            f'site:{domain} "password" filetype:log',
            f'site:{domain} "api_key" OR "apikey" OR "api_secret"',
            f'site:{domain} "AWS_SECRET_ACCESS_KEY"',
            f'site:{domain} "BEGIN RSA PRIVATE KEY"',
            f'site:{domain} "credentials"',
            f'site:{domain} intext:"index of /"',
            f'site:{domain} intitle:"Index of"',
            f'site:{domain} "error" "mysql"',
            f'site:{domain} "ORA-" "Oracle"',
            f'site:{domain} "Warning: mysql"',
        ],
        "subdomains": [
            f'site:*.{domain}',
            f'site:{domain} -www',
            f'site:{domain} -www -mail',
            f'inurl:{domain}',
        ],
        "vulnerabilities": [
            f'site:{domain} inurl:"?id="',
            f'site:{domain} inurl:"?page="',
            f'site:{domain} inurl:"?file="',
            f'site:{domain} inurl:"?include="',
            f'site:{domain} inurl:"?search="',
            f'site:{domain} inurl:"?q="',
            f'site:{domain} inurl:".php?"',
            f'site:{domain} inurl:".asp?"',
            f'site:{domain} inurl:"redirect="',
            f'site:{domain} inurl:"url="',
        ],
        "info": [
            f'"{domain}" email "@{domain}"',
            f'"{domain}" employee site:linkedin.com',
            f'"{domain}" filetype:pdf',
            f'"{domain}" "phone" OR "contact"',
            f'site:{domain} "powered by"',
            f'site:{domain} "version"',
            f'"@{domain}" email',
        ]
    }

    if category == "all":
        for cat, cat_dorks in categories.items():
            for d in cat_dorks:
                dorks.append({"query": d, "category": cat, "search_url": f"https://www.google.com/search?q={d.replace(' ', '+')}"})
    else:
        for d in categories.get(category, []):
            dorks.append({"query": d, "category": category, "search_url": f"https://www.google.com/search?q={d.replace(' ', '+')}"})

    return dorks


# ============================================================
# FULL AUTO SCAN v3.0
# ============================================================

# Store full scan results for download
full_scan_store = {}

TOTAL_STEPS = 18

def full_auto_scan(url, scan_id, callback):
    """Run all modules automatically on a target URL — v4.0 with 18 steps, 22 modules"""
    import socket, urllib.parse

    results = {
        "url": url,
        "domain": "",
        "ip": "",
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ports": [],
        "dns": {},
        "whois": {},
        "http": {},
        "ssl": {},
        "directories": [],
        "robots": {},
        "technologies": [],
        "vulnerabilities": [],
        "database": None,
        "waf": None,
        "cms": None,
        "js": None,
        "email_security": None,
        "api_endpoints": [],
        "subdomains": [],
        "emails_found": [],
        "jwt_findings": [],
        "login_findings": [],
        "graphql_findings": [],
        "idor_findings": [],
        "takeover_findings": [],
        "summary": {}
    }

    # Parse domain
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    domain = domain.split(":")[0]
    results["domain"] = domain

    try:
        results["ip"] = socket.gethostbyname(domain)
    except:
        results["ip"] = "N/A"

    callback({"type": "info", "message": f"🎯 Cible : {domain} ({results['ip']})"})
    callback({"type": "info", "message": f"🚀 UHQKYRA v4.0 — Scan complet ({TOTAL_STEPS} étapes, 22 modules)..."})
    callback({"type": "progress", "step": 0, "total": TOTAL_STEPS, "label": "Démarrage..."})

    # ── STEP 1 : WHOIS + GeoIP ──────────────────────────────
    callback({"type": "section", "message": "\n━━━ 📋 WHOIS & GÉOLOCALISATION ━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 1, "total": TOTAL_STEPS, "label": "WHOIS..."})
    try:
        whois_data = lookup_whois(domain, callback=callback)
        results["whois"] = whois_data.get("parsed", {})
    except Exception as e:
        callback({"type": "warn", "message": f"WHOIS: {e}"})
    try:
        if results["ip"] and results["ip"] != "N/A":
            geo_data = get_ip_geolocation(results["ip"], callback=callback)
            if geo_data:
                results["whois"].update({"geo_country": geo_data.get("country", ""),
                                          "geo_city": geo_data.get("city", ""),
                                          "geo_isp": geo_data.get("isp", ""),
                                          "geo_org": geo_data.get("org", "")})
    except Exception:
        pass

    # ── STEP 2 : DNS + Email Security ───────────────────────
    callback({"type": "section", "message": "\n━━━ 🌐 DNS & SÉCURITÉ EMAIL ━━━━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 2, "total": TOTAL_STEPS, "label": "DNS + Email sec..."})
    try:
        dns_data = enumerate_records(domain, callback=callback)
        results["dns"] = dns_data.get("records", {})
    except Exception as e:
        callback({"type": "warn", "message": f"DNS: {e}"})
    try:
        email_sec = check_email_security(domain, callback=callback)
        results["email_security"] = email_sec
        for v in email_sec.get("vulnerabilities", []):
            results["vulnerabilities"].append(v)
    except Exception as e:
        callback({"type": "warn", "message": f"Email security: {e}"})

    # ── STEP 3 : SUBDOMAIN ENUMERATION ─────────────────────
    callback({"type": "section", "message": "\n━━━ 🌐 ÉNUMÉRATION SOUS-DOMAINES ━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 3, "total": TOTAL_STEPS, "label": "Sous-domaines..."})
    try:
        sub_data = enumerate_subdomains_fast(domain, callback=callback)
        results["subdomains"] = sub_data.get("found", [])
        if sub_data.get("wildcard"):
            results["vulnerabilities"].append({
                "type": "wildcard_dns", "severity": "info",
                "name": "Wildcard DNS détecté",
                "detail": f"IP: {sub_data.get('wildcard_ip','')}"
            })
    except Exception as e:
        callback({"type": "warn", "message": f"Subdomain enum: {e}"})

    # ── STEP 4 : SUBDOMAIN TAKEOVER ─────────────────────────
    callback({"type": "section", "message": "\n━━━ 🎯 SUBDOMAIN TAKEOVER CHECK ━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 4, "total": TOTAL_STEPS, "label": "Takeover check..."})
    try:
        if results["subdomains"]:
            sub_fqdns = [s.get("subdomain", s) if isinstance(s, dict) else s
                         for s in results["subdomains"]]
            to_data = check_takeover(domain, subdomains=sub_fqdns, callback=callback)
            results["takeover_findings"] = to_data.get("vulnerable", [])
            for tf in to_data.get("vulnerable", []):
                results["vulnerabilities"].append({
                    "type": "subdomain_takeover",
                    "severity": "critical",
                    "name": f"Subdomain Takeover: {tf.get('subdomain','')}",
                    "detail": f"→ {tf.get('service','')} (CNAME: {tf.get('cname','')})"
                })
        else:
            callback({"type": "info", "message": "🎯 Aucun sous-domaine trouvé — skip takeover"})
    except Exception as e:
        callback({"type": "warn", "message": f"Takeover check: {e}"})

    # ── STEP 5 : PORT SCAN ──────────────────────────────────
    callback({"type": "section", "message": "\n━━━ 🔍 SCAN DE PORTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 5, "total": TOTAL_STEPS, "label": "Port scan..."})
    try:
        port_data = scan_ports(domain, ports=get_common_ports(), max_workers=150, callback=callback)
        results["ports"] = port_data.get("open_ports", [])
    except Exception as e:
        callback({"type": "warn", "message": f"Port scan: {e}"})

    # ── STEP 6 : WAF DETECTION ──────────────────────────────
    callback({"type": "section", "message": "\n━━━ 🛡️ DÉTECTION WAF/CDN ━━━━━━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 6, "total": TOTAL_STEPS, "label": "WAF..."})
    try:
        waf_data = detect_waf(url, callback=callback)
        results["waf"] = waf_data
        if waf_data.get("detected"):
            waf_name = waf_data.get("waf_name", "WAF")
            results["vulnerabilities"].append({
                "type": "waf_info",
                "severity": "info",
                "name": f"WAF/CDN détecté : {waf_name}",
                "detail": f"Confiance: {waf_data.get('confidence','?')}"
            })
    except Exception as e:
        callback({"type": "warn", "message": f"WAF: {e}"})

    # ── STEP 7 : HTTP ANALYSIS ──────────────────────────────
    callback({"type": "section", "message": "\n━━━ 🌍 ANALYSE HTTP ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 7, "total": TOTAL_STEPS, "label": "HTTP..."})
    try:
        http_data = full_http_analysis(url, callback=callback)
        results["http"] = http_data.get("security_headers", {})
        results["technologies"] = http_data.get("technologies", [])
        sec = http_data.get("security_headers", {})
        for missing in sec.get("missing", []):
            results["vulnerabilities"].append({
                "type": "header",
                "severity": missing.get("severity", "medium"),
                "name": f"Header manquant : {missing.get('name','')}",
                "detail": missing.get("recommendation", "")
            })
        for warn_item in sec.get("warnings", []):
            results["vulnerabilities"].append({"type": "header", "severity": "low", "name": str(warn_item), "detail": ""})
    except Exception as e:
        callback({"type": "warn", "message": f"HTTP: {e}"})

    # ── STEP 8 : SSL/TLS ────────────────────────────────────
    callback({"type": "section", "message": "\n━━━ 🔒 SSL / TLS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 8, "total": TOTAL_STEPS, "label": "SSL/TLS..."})
    try:
        ssl_data = full_ssl_analysis(domain, 443, callback=callback)
        results["ssl"] = ssl_data
        for v in ssl_data.get("vulnerabilities", []):
            results["vulnerabilities"].append({
                "type": "ssl", "severity": v.get("severity","medium"),
                "name": v.get("name",""), "detail": v.get("description","")
            })
        cert = ssl_data.get("certificate") or {}
        if cert.get("is_expired"):
            results["vulnerabilities"].append({
                "type": "ssl", "severity": "critical",
                "name": "Certificat SSL expiré !", "detail": ""
            })
        elif cert.get("is_expiring_soon"):
            results["vulnerabilities"].append({
                "type": "ssl", "severity": "high",
                "name": f"Certificat expire dans {cert.get('days_remaining')} jours", "detail": ""
            })
    except Exception as e:
        callback({"type": "warn", "message": f"SSL: {e}"})

    # ── STEP 9 : CMS DETECTION ──────────────────────────────
    callback({"type": "section", "message": "\n━━━ 🎯 DÉTECTION CMS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 9, "total": TOTAL_STEPS, "label": "CMS..."})
    try:
        cms_data = scan_cms(url, callback=callback)
        results["cms"] = cms_data
        for v in cms_data.get("vulnerabilities", []):
            results["vulnerabilities"].append(v)
        # Add login pages as findings
        for lp in cms_data.get("login_pages", [])[:5]:
            results["vulnerabilities"].append({
                "type": "login_page",
                "severity": "info",
                "name": f"Page admin/login exposée",
                "detail": lp
            })
        # Add exposed files
        for ef in cms_data.get("exposed_files", []):
            if ef.get("severity") in ("critical", "high"):
                results["vulnerabilities"].append({
                    "type": "exposure",
                    "severity": ef["severity"],
                    "name": f"Fichier sensible exposé : {ef.get('path','')}",
                    "detail": url + ef.get("path", "")
                })
    except Exception as e:
        callback({"type": "warn", "message": f"CMS: {e}"})

    # ── STEP 10 : LOGIN BRUTEFORCE ──────────────────────────
    callback({"type": "section", "message": "\n━━━ 🔑 LOGIN BRUTEFORCE (DEFAULT CREDS) ━━━━━━━━━━━"})
    callback({"type": "progress", "step": 10, "total": TOTAL_STEPS, "label": "Login bruteforce..."})
    try:
        login_data = scan_login_bruteforce(url, callback=callback)
        results["login_findings"] = login_data.get("successes", [])
        for v in login_data.get("vulnerabilities", []):
            results["vulnerabilities"].append(v)
    except Exception as e:
        callback({"type": "warn", "message": f"Login bruteforce: {e}"})

    # ── STEP 11 : DIRECTORIES & FILES ───────────────────────
    callback({"type": "section", "message": "\n━━━ 📂 RÉPERTOIRES & FICHIERS ━━━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 11, "total": TOTAL_STEPS, "label": "Directories..."})
    try:
        dirs_data = scan_directories(url, max_workers=40, callback=callback)
        results["directories"] = dirs_data.get("found", [])
        for d in results["directories"]:
            path = d.get("path", "")
            if any(s in path.lower() for s in [".env", ".git", "backup", ".sql", "phpinfo",
                                                "config", "password", ".aws", "credentials",
                                                "wp-config", "database", "dump"]):
                if d.get("status") == 200:
                    results["vulnerabilities"].append({
                        "type": "exposure", "severity": "critical",
                        "name": f"Fichier sensible exposé : /{path}",
                        "detail": d.get("url", "")
                    })
        robots_data = check_robots_txt(url, callback=callback)
        results["robots"] = robots_data
    except Exception as e:
        callback({"type": "warn", "message": f"Dirs: {e}"})

    # ── STEP 12 : JS ANALYSIS + JWT ─────────────────────────
    callback({"type": "section", "message": "\n━━━ 📜 ANALYSE JAVASCRIPT & JWT ━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 12, "total": TOTAL_STEPS, "label": "JavaScript + JWT..."})
    try:
        js_data = analyze_js(url, callback=callback)
        results["js"] = js_data
        results["emails_found"].extend(js_data.get("emails", []))
        for secret in js_data.get("secrets", []):
            results["vulnerabilities"].append({
                "type": "secret_exposure",
                "severity": "critical",
                "name": f"Secret dans JS : {secret.get('type','')}",
                "detail": secret.get("value", "")[:80]
            })
        if js_data.get("internal_ips"):
            for ip in js_data["internal_ips"]:
                results["vulnerabilities"].append({
                    "type": "ip_disclosure",
                    "severity": "medium",
                    "name": f"IP interne dans JS : {ip}",
                    "detail": "Exposition de l'architecture réseau interne"
                })
        if js_data.get("source_maps"):
            for sm in js_data["source_maps"]:
                results["vulnerabilities"].append({
                    "type": "source_map",
                    "severity": "medium",
                    "name": f"Source map exposée",
                    "detail": sm
                })
    except Exception as e:
        callback({"type": "warn", "message": f"JS analysis: {e}"})

    # JWT analysis on page
    try:
        jwt_page = find_jwts_on_page(url, callback=callback)
        results["jwt_findings"] = jwt_page.get("analyses", [])
        for analysis in jwt_page.get("analyses", []):
            for v in analysis.get("vulnerabilities", []):
                results["vulnerabilities"].append(v)
        if jwt_page.get("tokens_found"):
            callback({"type": "found", "message": f"🔑 {len(jwt_page['tokens_found'])} JWT token(s) trouvé(s)"})
    except Exception as e:
        callback({"type": "warn", "message": f"JWT analysis: {e}"})

    # ── STEP 13 : API DISCOVERY + GRAPHQL ───────────────────
    callback({"type": "section", "message": "\n━━━ 🔗 API, ENDPOINTS & GRAPHQL ━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 13, "total": TOTAL_STEPS, "label": "API + GraphQL..."})
    try:
        api_data = discover_api_endpoints(url, callback=callback)
        results["api_endpoints"] = api_data.get("found", [])
        # Critical sensitive files
        for sf in api_data.get("sensitive_files", []):
            if sf.get("status") == 200:
                results["vulnerabilities"].append({
                    "type": "sensitive_file",
                    "severity": sf.get("severity", "high"),
                    "name": f"Fichier critique accessible : {sf.get('path','')}",
                    "detail": f"Status {sf.get('status')} — {sf.get('size',0)} bytes"
                })
        if api_data.get("swagger_found"):
            results["vulnerabilities"].append({
                "type": "api_docs_exposed",
                "severity": "medium",
                "name": "Documentation API (Swagger/OpenAPI) exposée publiquement",
                "detail": "Peut révéler tous les endpoints et paramètres de l'API"
            })
        if api_data.get("actuator_found"):
            results["vulnerabilities"].append({
                "type": "spring_actuator",
                "severity": "critical",
                "name": "Spring Boot Actuator exposé",
                "detail": "Accès aux métriques, configs, beans de l'application"
            })
        if api_data.get("graphql_found"):
            results["vulnerabilities"].append({
                "type": "graphql_exposed",
                "severity": "medium",
                "name": "GraphQL endpoint exposé",
                "detail": "Tester introspection, injections, etc."
            })
    except Exception as e:
        callback({"type": "warn", "message": f"API discovery: {e}"})

    # GraphQL audit
    try:
        gql_results = scan_graphql(url, callback=callback)
        results["graphql_findings"] = gql_results
        for gql in gql_results:
            for v in gql.get("vulnerabilities", []):
                results["vulnerabilities"].append(v)
    except Exception as e:
        callback({"type": "warn", "message": f"GraphQL audit: {e}"})

    # ── STEP 14 : IDOR SCANNER ──────────────────────────────
    callback({"type": "section", "message": "\n━━━ 🔓 IDOR SCAN ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 14, "total": TOTAL_STEPS, "label": "IDOR scan..."})
    try:
        idor_data = scan_idor(url, callback=callback)
        results["idor_findings"] = (idor_data.get("param_findings", []) +
                                    idor_data.get("path_findings", []))
        for v in idor_data.get("vulnerabilities", []):
            results["vulnerabilities"].append(v)
    except Exception as e:
        callback({"type": "warn", "message": f"IDOR scan: {e}"})

    # ── STEP 15 : VULNERABILITY SCAN ────────────────────────
    callback({"type": "section", "message": "\n━━━ 💥 SCAN DE VULNÉRABILITÉS ━━━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 15, "total": TOTAL_STEPS, "label": "Vulnérabilités..."})

    # Security misconfigs
    try:
        misc = check_security_misconfigs(url, callback=callback)
        for f in misc.get("findings", []):
            results["vulnerabilities"].append({
                "type": "misconfig",
                "severity": f.get("severity", "medium"),
                "name": f.get("type", ""),
                "detail": f.get("detail", "")
            })
    except Exception as e:
        callback({"type": "warn", "message": f"Misconfig: {e}"})

    # Advanced vulns: clickjacking, CORS, HTTP methods, header injection
    try:
        adv = run_all_advanced(url, callback=callback)
        for f in adv.get("findings", []):
            results["vulnerabilities"].append(f)
    except Exception as e:
        callback({"type": "warn", "message": f"Advanced vuln: {e}"})

    # SQLi/XSS/LFI if URL has params
    if "?" in url and "=" in url:
        callback({"type": "info", "message": "💉 Paramètres URL détectés — injection tests..."})
        try:
            sqli = test_sqli(url, callback=callback)
            if sqli.get("vulnerable"):
                for f in sqli.get("findings", []):
                    results["vulnerabilities"].append({
                        "type": "sqli", "severity": "critical",
                        "name": f"SQL Injection : {f.get('type','')} (param: {f.get('param','')})",
                        "detail": f.get("payload", "")
                    })
                callback({"type": "vuln", "message": "🗄️  SQLi confirmée — extraction DB..."})
                try:
                    first_param = sqli["findings"][0].get("param", "id")
                    db_res = full_db_extraction(url, first_param, mode="enum", callback=callback)
                    results["database"] = db_res
                    callback({"type": "vuln", "message": "🚨 BASE DE DONNÉES EXTRAITE !"})
                except Exception as de:
                    callback({"type": "warn", "message": f"DB extraction: {de}"})
        except Exception as e:
            callback({"type": "warn", "message": f"SQLi: {e}"})

        try:
            xss = test_xss(url, callback=callback)
            if xss.get("vulnerable"):
                for f in xss.get("findings", []):
                    results["vulnerabilities"].append({
                        "type": "xss", "severity": "high",
                        "name": f"XSS (param: {f.get('param','')})",
                        "detail": f.get("payload", "")
                    })
        except Exception:
            pass

        try:
            lfi = test_lfi(url, callback=callback)
            if lfi.get("vulnerable"):
                for f in lfi.get("findings", []):
                    results["vulnerabilities"].append({
                        "type": "lfi", "severity": "critical",
                        "name": f"LFI / Path Traversal (param: {f.get('param','')})",
                        "detail": f.get("payload", "")
                    })
        except Exception:
            pass

        try:
            redirect = test_open_redirect(url, callback=callback)
            if redirect.get("vulnerable"):
                for f in redirect.get("findings", []):
                    results["vulnerabilities"].append({
                        "type": "open_redirect", "severity": "medium",
                        "name": f"Open Redirect (param: {f.get('param','')})",
                        "detail": f.get("payload", "")
                    })
        except Exception:
            pass

        # Command injection
        try:
            cmdi = test_command_injection(url, callback=callback)
            if cmdi.get("vulnerable"):
                for f in cmdi.get("findings", []):
                    results["vulnerabilities"].append({
                        "type": "command_injection", "severity": "critical",
                        "name": f"Injection de commande OS ! (param: {f.get('param','')})",
                        "detail": f.get("payload", "")
                    })
        except Exception:
            pass

        # NoSQL injection
        try:
            nosql = test_nosql_injection(url, callback=callback)
            if nosql.get("vulnerable"):
                for f in nosql.get("findings", []):
                    results["vulnerabilities"].append({
                        "type": "nosql_injection", "severity": f.get("severity","high"),
                        "name": f"NoSQL Injection (param: {f.get('param','')})",
                        "detail": f.get("payload", "")
                    })
        except Exception:
            pass

        # LDAP injection
        try:
            ldap = test_ldap_injection(url, callback=callback)
            if ldap.get("vulnerable"):
                for f in ldap.get("findings", []):
                    results["vulnerabilities"].append({
                        "type": "ldap_injection", "severity": "high",
                        "name": f"LDAP Injection (param: {f.get('param','')})",
                        "detail": f.get("indicator", "")
                    })
        except Exception:
            pass

    # CRLF injection (always test, not just when params in URL)
    try:
        crlf = test_crlf_injection(url, callback=callback)
        if crlf.get("vulnerable"):
            for f in crlf.get("findings", []):
                results["vulnerabilities"].append({
                    "type": "crlf", "severity": f.get("severity","high"),
                    "name": f"CRLF Injection / HTTP Response Splitting",
                    "detail": f.get("payload","")
                })
    except Exception:
        pass

    # XXE (test on POST endpoints, always attempt)
    try:
        xxe = test_xxe(url, callback=callback)
        if xxe.get("vulnerable"):
            for f in xxe.get("findings", []):
                results["vulnerabilities"].append({
                    "type": "xxe", "severity": "critical",
                    "name": "XXE (XML External Entity) Injection",
                    "detail": f.get("payload","")[:80]
                })
    except Exception:
        pass

    # ── STEP 18 : SUMMARY ───────────────────────────────────
    callback({"type": "section", "message": "\n━━━ 📊 RAPPORT FINAL ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"})
    callback({"type": "progress", "step": 18, "total": TOTAL_STEPS, "label": "Finalisation..."})

    # Deduplicate vulnerabilities
    seen = set()
    unique_vulns = []
    for v in results["vulnerabilities"]:
        key = (v.get("type",""), v.get("name","")[:60])
        if key not in seen:
            seen.add(key)
            unique_vulns.append(v)
    results["vulnerabilities"] = unique_vulns

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in results["vulnerabilities"]:
        sev = v.get("severity", "low")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    risk_score = (sev_counts["critical"]*10 + sev_counts["high"]*7 +
                  sev_counts["medium"]*4 + sev_counts["low"]*1)
    overall = ("CRITIQUE" if risk_score >= 30 else "ÉLEVÉ" if risk_score >= 15
               else "MOYEN" if risk_score >= 5 else "FAIBLE")

    results["summary"] = {
        "open_ports": len(results["ports"]),
        "dirs_found": len([d for d in results["directories"] if d.get("status") == 200]),
        "vulns_critical": sev_counts["critical"],
        "vulns_high": sev_counts["high"],
        "vulns_medium": sev_counts["medium"],
        "vulns_low": sev_counts["low"],
        "total_vulns": sum(v for k,v in sev_counts.items() if k != "info"),
        "technologies": len(results["technologies"]),
        "risk_score": risk_score,
        "overall_risk": overall,
        "has_database": results["database"] is not None,
        "waf_name": (results["waf"] or {}).get("waf_name"),
        "cms_name": (results["cms"] or {}).get("cms"),
        "js_secrets": len((results["js"] or {}).get("secrets", [])),
        "api_endpoints": len(results["api_endpoints"]),
        "emails_found": len(results["emails_found"]),
        "subdomains": len(results["subdomains"]),
        "email_grade": (results["email_security"] or {}).get("grade", "?"),
        # New v4.0
        "jwt_tokens": len(results["jwt_findings"]),
        "login_successes": len(results["login_findings"]),
        "graphql_endpoints": len(results["graphql_findings"]),
        "idor_findings": len(results["idor_findings"]),
        "takeover_findings": len(results["takeover_findings"]),
    }

    full_scan_store[scan_id] = results
    callback({"type": "done_full", "message": "SCAN_COMPLETE", "data": results["summary"]})
    return results


@app.route('/api/fullscan', methods=['POST'])
def api_fullscan():
    data = request.json
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "URL requise"}), 400

    scan_id = f"full_{int(time.time()*1000)}"
    scan_queues[scan_id] = queue.Queue()
    scan_results_store[scan_id] = {"status": "running"}

    def run():
        q = scan_queues[scan_id]
        def cb(msg):
            q.put(msg)
        try:
            full_auto_scan(url, scan_id, cb)
        except Exception as e:
            q.put({"type": "error", "message": str(e)})
        finally:
            q.put({"type": "done", "message": "Terminé"})
            scan_results_store[scan_id]["status"] = "complete"

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"scan_id": scan_id})


@app.route('/api/download/txt/<scan_id>')
def download_txt(scan_id):
    """Generate and download .txt report"""
    res = full_scan_store.get(scan_id)
    if not res:
        return jsonify({"error": "Résultats introuvables"}), 404

    lines = []
    lines.append("=" * 65)
    lines.append(f"  UHQKYRA v4.0 — RAPPORT D'AUDIT DE SÉCURITÉ (22 modules)")
    lines.append("=" * 65)
    lines.append(f"Cible     : {res['url']}")
    lines.append(f"Domaine   : {res['domain']}")
    lines.append(f"IP        : {res['ip']}")
    lines.append(f"Date      : {res['scan_time']}")
    s = res.get("summary", {})
    lines.append(f"Risque    : {s.get('overall_risk','?')} (score: {s.get('risk_score',0)})")
    lines.append("")

    lines.append("─" * 60)
    lines.append("RÉSUMÉ")
    lines.append("─" * 60)
    lines.append(f"  Ports ouverts      : {s.get('open_ports',0)}")
    lines.append(f"  Répertoires trouvés: {s.get('dirs_found',0)}")
    lines.append(f"  Vulnérabilités     : {s.get('total_vulns',0)}")
    lines.append(f"    ├─ Critiques     : {s.get('vulns_critical',0)}")
    lines.append(f"    ├─ Élevées       : {s.get('vulns_high',0)}")
    lines.append(f"    ├─ Moyennes      : {s.get('vulns_medium',0)}")
    lines.append(f"    └─ Faibles       : {s.get('vulns_low',0)}")
    lines.append(f"  Technologies       : {s.get('technologies',0)}")
    lines.append(f"  Base de données    : {'OUI ⚠️' if s.get('has_database') else 'Non'}")
    lines.append(f"  Sous-domaines      : {s.get('subdomains',0)}")
    lines.append(f"  Takeover détectés  : {s.get('takeover_findings',0)}")
    lines.append(f"  JWT trouvés        : {s.get('jwt_tokens',0)}")
    lines.append(f"  Logins compromis   : {s.get('login_successes',0)}")
    lines.append(f"  GraphQL endpoints  : {s.get('graphql_endpoints',0)}")
    lines.append(f"  IDOR détectés      : {s.get('idor_findings',0)}")
    lines.append("")

    lines.append("─" * 60)
    lines.append("PORTS OUVERTS")
    lines.append("─" * 60)
    ports = res.get("ports", [])
    if ports:
        lines.append(f"  {'PORT':<8} {'SERVICE':<15} {'RISQUE':<8} BANNER")
        lines.append(f"  {'─'*6:<8} {'─'*13:<15} {'─'*6:<8} {'─'*20}")
        for p in sorted(ports, key=lambda x: x.get("port", 0)):
            port = p.get("port","")
            svc = p.get("service","?")
            risk = p.get("risk","?").upper()
            banner = (p.get("banner") or "")[:50]
            lines.append(f"  {port:<8} {svc:<15} {risk:<8} {banner}")
    else:
        lines.append("  Aucun port ouvert détecté")
    lines.append("")

    lines.append("─" * 60)
    lines.append("INFORMATIONS DNS")
    lines.append("─" * 60)
    dns = res.get("dns", {})
    for rtype, records in dns.items():
        if records:
            for r in (records if isinstance(records, list) else [records])[:5]:
                lines.append(f"  {rtype:<8} {str(r)[:70]}")
    lines.append("")

    lines.append("─" * 60)
    lines.append("WHOIS")
    lines.append("─" * 60)
    whois = res.get("whois", {})
    for k, v in whois.items():
        if v:
            lines.append(f"  {k.replace('_',' ').title():<20}: {str(v)[:60]}")
    lines.append("")

    lines.append("─" * 60)
    lines.append("TECHNOLOGIES DÉTECTÉES")
    lines.append("─" * 60)
    for t in res.get("technologies", []):
        lines.append(f"  [{t.get('category','?')}] {t.get('name','?')} ({t.get('confidence','?')})")
    if not res.get("technologies"):
        lines.append("  Aucune technologie détectée")
    lines.append("")

    lines.append("─" * 60)
    lines.append("RÉPERTOIRES ET FICHIERS TROUVÉS")
    lines.append("─" * 60)
    dirs_200 = [d for d in res.get("directories", []) if d.get("status") == 200]
    dirs_other = [d for d in res.get("directories", []) if d.get("status") in [401, 403]]
    for d in dirs_200[:50]:
        lines.append(f"  [200] /{d.get('path','')}  ({d.get('size',0)} bytes)")
    for d in dirs_other[:20]:
        lines.append(f"  [{d.get('status')}] /{d.get('path','')}  (accès refusé)")
    if not dirs_200 and not dirs_other:
        lines.append("  Aucun répertoire trouvé")
    lines.append("")

    if res.get("robots", {}).get("found"):
        lines.append("─" * 60)
        lines.append("ROBOTS.TXT")
        lines.append("─" * 60)
        for p in res["robots"].get("disallowed", [])[:20]:
            if p:
                lines.append(f"  Disallow: {p}")
        lines.append("")

    lines.append("─" * 60)
    lines.append("VULNÉRABILITÉS")
    lines.append("─" * 60)
    vulns = res.get("vulnerabilities", [])
    if vulns:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for v in sorted(vulns, key=lambda x: sev_order.get(x.get("severity","low"), 4)):
            sev = v.get("severity","?").upper()
            name = v.get("name","?")
            detail = v.get("detail","")
            lines.append(f"  [{sev}] {name}")
            if detail:
                lines.append(f"         → {detail[:80]}")
    else:
        lines.append("  Aucune vulnérabilité critique détectée")
    lines.append("")

    if res.get("database"):
        db = res["database"]
        lines.append("─" * 60)
        lines.append("BASE DE DONNÉES EXTRAITE ⚠️")
        lines.append("─" * 60)
        lines.append(f"  Type    : {db.get('db_type','?')}")
        lines.append(f"  Version : {db.get('version','?')}")
        lines.append(f"  User    : {db.get('current_user','?')}")
        lines.append(f"  DB      : {db.get('current_db','?')}")
        lines.append(f"  Bases   : {', '.join(db.get('databases',[]))}")
        lines.append(f"  Tables  : {', '.join(db.get('tables',[]))}")
        lines.append("")

    # WAF
    waf = res.get("waf") or {}
    if waf:
        lines.append("─" * 65)
        lines.append("WAF / CDN")
        lines.append("─" * 65)
        if waf.get("detected"):
            lines.append(f"  Détecté : {waf.get('waf_name','?')} (confiance: {waf.get('confidence','?')})")
        else:
            lines.append("  Aucun WAF/CDN détecté")
        lines.append("")

    # CMS
    cms = res.get("cms") or {}
    if cms and cms.get("cms"):
        lines.append("─" * 65)
        lines.append("CMS DÉTECTÉ")
        lines.append("─" * 65)
        lines.append(f"  CMS     : {cms.get('cms','?')}")
        if cms.get("version"):
            lines.append(f"  Version : {cms.get('version','?')}")
        if cms.get("login_pages"):
            for lp in cms["login_pages"][:3]:
                lines.append(f"  Login   : {lp}")
        if cms.get("plugins"):
            for p in cms["plugins"][:10]:
                lines.append(f"  Plugin  : {p.get('name','?')} v{p.get('version','?')}")
        lines.append("")

    # JS findings
    js = res.get("js") or {}
    if js and (js.get("secrets") or js.get("endpoints") or js.get("emails")):
        lines.append("─" * 65)
        lines.append("ANALYSE JAVASCRIPT")
        lines.append("─" * 65)
        lines.append(f"  Fichiers JS analysés : {js.get('js_analyzed',0)}")
        lines.append(f"  Secrets trouvés      : {len(js.get('secrets',[]))}")
        lines.append(f"  Endpoints API        : {len(js.get('endpoints',[]))}")
        lines.append(f"  Emails               : {len(js.get('emails',[]))}")
        for sec in js.get("secrets", [])[:5]:
            lines.append(f"  🚨 [{sec.get('type','?')}] {sec.get('value','')[:80]}")
        for ep in js.get("endpoints", [])[:10]:
            lines.append(f"  🔗 {ep[:80]}")
        lines.append("")

    # Email Security
    email_sec = res.get("email_security") or {}
    if email_sec:
        lines.append("─" * 65)
        lines.append("SÉCURITÉ EMAIL (SPF/DMARC/DKIM)")
        lines.append("─" * 65)
        lines.append(f"  Grade   : {email_sec.get('grade','?')} ({email_sec.get('score',0)}/10)")
        spf = email_sec.get("spf", {})
        lines.append(f"  SPF     : {'✅ ' + spf.get('record','?')[:60] if spf.get('found') else '❌ Absent'}")
        dmarc = email_sec.get("dmarc", {})
        lines.append(f"  DMARC   : {'✅ p=' + str(dmarc.get('policy','?')) if dmarc.get('found') else '❌ Absent'}")
        dkim = email_sec.get("dkim", {})
        sels = ', '.join(dkim.get('selectors', [])[:5])
        lines.append(f"  DKIM    : {'✅ ' + sels if dkim.get('found') else '❌ Non trouvé'}")
        lines.append("")

    # API Endpoints
    api_eps = res.get("api_endpoints") or []
    if api_eps:
        lines.append("─" * 65)
        lines.append("ENDPOINTS API DÉCOUVERTS")
        lines.append("─" * 65)
        for ep in api_eps[:20]:
            lines.append(f"  [{ep.get('status')}] {ep.get('path','')}  ({ep.get('size',0)}B)")
        lines.append("")

    # Subdomains
    subs = res.get("subdomains") or []
    if subs:
        lines.append("─" * 65)
        lines.append(f"SOUS-DOMAINES ({len(subs)} trouvés)")
        lines.append("─" * 65)
        for sub in subs[:30]:
            ips = ", ".join(sub.get("ips", []))
            lines.append(f"  {sub.get('subdomain','')}  → {ips}")
        lines.append("")

    # Takeover findings
    to_finds = res.get("takeover_findings") or []
    if to_finds:
        lines.append("─" * 65)
        lines.append(f"SUBDOMAIN TAKEOVER ({len(to_finds)} détecté(s))")
        lines.append("─" * 65)
        for tf in to_finds:
            lines.append(f"  🚨 {tf.get('subdomain','')} → {tf.get('service','')} [{tf.get('confidence','')}]")
            if tf.get("detail"):
                lines.append(f"     {tf['detail']}")
        lines.append("")

    # JWT findings
    jwt_finds = res.get("jwt_findings") or []
    if jwt_finds:
        lines.append("─" * 65)
        lines.append(f"JWT TOKENS ({len(jwt_finds)} analysés)")
        lines.append("─" * 65)
        for jf in jwt_finds:
            lines.append(f"  Algorithme : {jf.get('algorithm','?')}")
            if jf.get("cracked_secret"):
                lines.append(f"  🚨 Secret cracké : {jf['cracked_secret']}")
            if jf.get("expired"):
                lines.append(f"  ⚠️  Token expiré")
            for v in jf.get("vulnerabilities", [])[:3]:
                lines.append(f"  [{v.get('severity','?').upper()}] {v.get('name','')}")
        lines.append("")

    # Login findings
    login_finds = res.get("login_findings") or []
    if login_finds:
        lines.append("─" * 65)
        lines.append(f"CREDENTIALS PAR DÉFAUT TROUVÉS ({len(login_finds)})")
        lines.append("─" * 65)
        for lf in login_finds:
            lines.append(f"  🚨 {lf.get('username','')} / {lf.get('password','')} @ {lf.get('url','')}")
        lines.append("")

    # GraphQL findings
    gql_finds = res.get("graphql_findings") or []
    if gql_finds:
        lines.append("─" * 65)
        lines.append(f"GRAPHQL ({len(gql_finds)} endpoint(s))")
        lines.append("─" * 65)
        for gf in gql_finds:
            lines.append(f"  Endpoint : {gf.get('endpoint','')}")
            if gf.get("introspection_enabled"):
                lines.append(f"  ⚠️  Introspection activée — {len(gf.get('types',[]))} types exposés")
            for v in gf.get("vulnerabilities", [])[:3]:
                lines.append(f"  [{v.get('severity','?').upper()}] {v.get('name','')}")
        lines.append("")

    # IDOR findings
    idor_finds = res.get("idor_findings") or []
    if idor_finds:
        lines.append("─" * 65)
        lines.append(f"IDOR ({len(idor_finds)} détecté(s))")
        lines.append("─" * 65)
        for iff in idor_finds:
            lines.append(f"  🚨 {iff.get('url','')} [param={iff.get('param','')}]")
        lines.append("")

    lines.append("=" * 65)
    lines.append("  ⚠️  RAPPORT CONFIDENTIEL — USAGE AUTORISÉ UNIQUEMENT")
    lines.append(f"  Généré par UHQKYRA v4.0 (22 modules) — {res['scan_time']}")
    lines.append("=" * 65)

    content = "\n".join(lines)
    fname = f"pentest_{res['domain']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    os.makedirs("reports", exist_ok=True)
    path = f"reports/{fname}"
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    return send_file(path, as_attachment=True, download_name=fname, mimetype="text/plain")


@app.route('/api/download/db/<scan_id>')
def download_db(scan_id):
    """Download extracted database as JSON"""
    res = full_scan_store.get(scan_id)
    if not res or not res.get("database"):
        return jsonify({"error": "Pas de données DB pour ce scan"}), 404

    db_data = res["database"]
    fname = f"database_{res['domain']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    os.makedirs("reports", exist_ok=True)
    path = f"reports/{fname}"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(db_data, f, indent=2, ensure_ascii=False, default=str)

    return send_file(path, as_attachment=True, download_name=fname, mimetype="application/json")


@app.route('/api/fullscan/results/<scan_id>')
def get_full_results(scan_id):
    res = full_scan_store.get(scan_id)
    if not res:
        return jsonify({"error": "Introuvable"}), 404
    return jsonify(res)


@app.route('/api/download/html/<scan_id>')
def download_html_report(scan_id):
    """Generate and download full HTML report"""
    res = full_scan_store.get(scan_id)
    if not res:
        return jsonify({"error": "Résultats introuvables"}), 404

    # Build scan_data for report generator
    scan_data = {
        "target": res.get("url", "?"),
        "sections": {}
    }

    # Build sections from results
    vulns = res.get("vulnerabilities", [])
    if vulns:
        scan_data["sections"]["Vulnérabilités"] = [
            {"type": v.get("name","?"), "severity": v.get("severity","low"),
             "description": v.get("detail",""), "payload": v.get("detail","")}
            for v in vulns
        ]

    ports = [p for p in res.get("ports", []) if p.get("state") == "open"]
    if ports:
        scan_data["sections"]["Ports Ouverts"] = {
            p.get("port",""): f"{p.get('service','?')} — Risque: {p.get('risk','?')} {p.get('banner','')}"
            for p in ports[:30]
        }

    techs = res.get("technologies", [])
    if techs:
        scan_data["sections"]["Technologies"] = {
            t.get("name","?"): f"{t.get('category','?')} — {t.get('confidence','?')}"
            for t in techs
        }

    dns = res.get("dns", {})
    if dns:
        scan_data["sections"]["DNS"] = {
            k: str(v)[:200] for k,v in dns.items() if v
        }

    whois = res.get("whois", {})
    if whois:
        scan_data["sections"]["WHOIS"] = {k: str(v)[:200] for k,v in whois.items() if v}

    waf = res.get("waf") or {}
    cms = res.get("cms") or {}
    info_section = {}
    if waf.get("detected"):
        info_section["WAF/CDN"] = waf.get("waf_name", "?")
    if cms.get("cms"):
        info_section["CMS"] = f"{cms.get('cms','')} {cms.get('version','')}"
    email_sec = res.get("email_security") or {}
    if email_sec:
        info_section["Email Security Grade"] = email_sec.get("grade","?")
    if info_section:
        scan_data["sections"]["Informations Générales"] = info_section

    html = generate_html_report(scan_data, title=f"UHQKYRA — {res.get('domain','?')}")
    fname = f"uhqkyra_{res['domain']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    os.makedirs("reports", exist_ok=True)
    path = f"reports/{fname}"
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return send_file(path, as_attachment=True, download_name=fname, mimetype="text/html")


# ── New module API routes ──────────────────────────────────────────

@app.route('/api/scan/waf', methods=['POST'])
def api_waf():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"waf_{int(time.time()*1000)}"
    run_scan_with_queue(detect_waf, scan_id, target)
    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/cms', methods=['POST'])
def api_cms():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"cms_{int(time.time()*1000)}"
    run_scan_with_queue(scan_cms, scan_id, target)
    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/js', methods=['POST'])
def api_js():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"js_{int(time.time()*1000)}"
    run_scan_with_queue(analyze_js, scan_id, target)
    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/email', methods=['POST'])
def api_email_sec():
    data = request.json
    target = data.get('target', '').strip()
    # Strip to domain
    import urllib.parse
    parsed = urllib.parse.urlparse(target if "://" in target else "http://"+target)
    domain = parsed.netloc.split(":")[0] or parsed.path.split("/")[0]
    scan_id = f"email_{int(time.time()*1000)}"
    run_scan_with_queue(check_email_security, scan_id, domain)
    return jsonify({"scan_id": scan_id})


@app.route('/api/scan/api-discover', methods=['POST'])
def api_api_discover():
    data = request.json
    target = data.get('target', '').strip()
    scan_id = f"apidisc_{int(time.time()*1000)}"
    run_scan_with_queue(discover_api_endpoints, scan_id, target)
    return jsonify({"scan_id": scan_id})


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='UHQKYRA v3.0')
    parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', 5000)), help='Port (default: 5000)')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host (default: 0.0.0.0)')
    args = parser.parse_args()

    os.makedirs('reports', exist_ok=True)
    print(f"""
╔═══════════════════════════════════════════════╗
║       UHQKYRA v3.0 - Web Security Tool      ║
║  ⚠️  For authorized security testing only!     ║
╠═══════════════════════════════════════════════╣
║  🌐 Interface: http://127.0.0.1:{args.port:<14}║
║  📡 12 modules: WAF·CMS·JS·Email·API+more    ║
╚═══════════════════════════════════════════════╝
    """)
    app.run(debug=False, host=args.host, port=args.port, threaded=True)

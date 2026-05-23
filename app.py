"""
PentestKit v1.0 - Web-Based Penetration Testing Tool
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
from modules.vuln_scanner import test_sqli, test_xss, test_lfi, test_open_redirect, check_security_misconfigs
from modules.db_extractor import full_db_extraction, detect_db_type, get_databases, get_tables, get_columns, dump_table
from modules.hash_tools import identify_hash, generate_hash, crack_hash, analyze_password_strength, generate_password
from modules.report_generator import generate_html_report, save_report

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


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='PentestKit v1.0')
    parser.add_argument('--port', type=int, default=int(os.environ.get('PORT', 5000)), help='Port (default: 5000)')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host (default: 0.0.0.0)')
    args = parser.parse_args()

    os.makedirs('reports', exist_ok=True)
    print(f"""
╔═══════════════════════════════════════════════╗
║       PentestKit v1.0 - Web Security Tool      ║
║  ⚠️  For authorized security testing only!     ║
╠═══════════════════════════════════════════════╣
║  🌐 Interface: http://127.0.0.1:{args.port:<14}║
║  📡 API: http://127.0.0.1:{args.port}/api/          ║
╚═══════════════════════════════════════════════╝
    """)
    app.run(debug=False, host=args.host, port=args.port, threaded=True)

"""
Port Scanner Module
Performs TCP/UDP port scanning with service detection and banner grabbing
"""
import socket
import concurrent.futures
import time
from datetime import datetime

# Common port to service mapping
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt2", 9200: "Elasticsearch", 27017: "MongoDB",
    11211: "Memcached", 6667: "IRC", 25565: "Minecraft",
    3000: "Node.js", 4000: "HTTP-Alt3", 5000: "Flask/UPnP",
    8000: "HTTP-Alt4", 8008: "HTTP-Alt5", 9090: "HTTP-Alt6",
    10000: "Webmin", 2222: "SSH-Alt", 2082: "cPanel", 2083: "cPanel-SSL",
    2086: "WHM", 2087: "WHM-SSL", 7777: "HTTP-Alt7", 9000: "HTTP-Alt8",
    6000: "X11", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    554: "RTSP", 873: "rsync", 2049: "NFS", 161: "SNMP", 162: "SNMPTRAP",
    389: "LDAP", 636: "LDAPS", 5601: "Kibana", 9300: "Elasticsearch-Node",
    4444: "Metasploit", 4899: "Radmin", 5800: "VNC-HTTP", 5985: "WinRM",
    5986: "WinRM-SSL", 47001: "WinRM-Alt", 49152: "Windows-Dynamic",
    179: "BGP", 194: "IRC", 465: "SMTPS", 587: "SMTP-Submission",
    631: "IPP", 902: "VMware", 1194: "OpenVPN", 1883: "MQTT",
    8883: "MQTT-SSL", 502: "Modbus", 102: "Siemens-S7",
}

RISKY_PORTS = {
    21, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 11211,
    27017, 9200, 161, 2049, 873, 4444, 1080
}

def grab_banner(host, port, timeout=2):
    """Try to grab service banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send probe based on port
        if port in [80, 8080, 8000, 8888]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        elif port == 21:
            pass  # FTP sends banner automatically
        elif port == 22:
            pass  # SSH sends banner automatically
        elif port == 25:
            pass  # SMTP sends banner automatically
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:200] if banner else None
    except:
        return None

def scan_port(host, port, timeout=1):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            service = PORT_SERVICES.get(port, "Unknown")
            banner = grab_banner(host, port)
            is_risky = port in RISKY_PORTS
            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
                "risk": "high" if is_risky else "medium" if port < 1024 else "low"
            }
    except:
        pass
    return None

def scan_ports(host, ports=None, port_range=None, max_workers=100, callback=None):
    """
    Scan ports on a host

    Args:
        host: Target hostname or IP
        ports: List of specific ports to scan
        port_range: Tuple of (start, end) for range scanning
        max_workers: Number of concurrent threads
        callback: Function to call with progress updates
    """
    results = {
        "host": host,
        "ip": None,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": [],
        "total_scanned": 0,
        "scan_duration": 0
    }

    # Resolve hostname
    try:
        results["ip"] = socket.gethostbyname(host)
    except socket.gaierror as e:
        results["error"] = f"Cannot resolve host: {str(e)}"
        return results

    # Determine ports to scan
    if ports:
        target_ports = ports
    elif port_range:
        target_ports = list(range(port_range[0], port_range[1] + 1))
    else:
        # Default: top 1000 common ports
        target_ports = list(PORT_SERVICES.keys()) + list(range(1, 1025))
        target_ports = sorted(set(target_ports))

    results["total_scanned"] = len(target_ports)
    start_time = time.time()

    if callback:
        callback({"type": "info", "message": f"🎯 Target: {host} ({results['ip']})"})
        callback({"type": "info", "message": f"📡 Scanning {len(target_ports)} ports with {max_workers} threads..."})

    open_count = 0
    scanned = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, results["ip"], port): port for port in target_ports}

        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            scanned += 1

            try:
                result = future.result()
                if result:
                    results["open_ports"].append(result)
                    open_count += 1
                    risk_icon = "🔴" if result["risk"] == "high" else "🟡" if result["risk"] == "medium" else "🟢"
                    msg = f"{risk_icon} Port {result['port']}/tcp OPEN - {result['service']}"
                    if result["banner"]:
                        msg += f" | {result['banner'][:80]}"
                    if callback:
                        callback({"type": "found", "message": msg, "data": result})
            except Exception as e:
                pass

            # Progress update every 100 ports
            if callback and scanned % 100 == 0:
                callback({"type": "progress", "message": f"Progress: {scanned}/{len(target_ports)} ports scanned...", "percent": int(scanned/len(target_ports)*100)})

    results["scan_duration"] = round(time.time() - start_time, 2)
    results["open_ports"] = sorted(results["open_ports"], key=lambda x: x["port"])

    if callback:
        callback({"type": "complete", "message": f"✅ Scan complete! Found {open_count} open ports in {results['scan_duration']}s"})

    return results


def get_common_ports():
    """Return list of common ports for quick scan"""
    return sorted(PORT_SERVICES.keys())


def parse_port_input(port_str):
    """Parse port input string like '80,443,8080-8090'"""
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            start, end = part.split('-', 1)
            try:
                ports.extend(range(int(start.strip()), int(end.strip()) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.append(int(part))
            except ValueError:
                pass
    return sorted(set(p for p in ports if 1 <= p <= 65535))

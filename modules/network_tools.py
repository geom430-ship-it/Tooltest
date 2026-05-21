"""
Network Tools Module
Ping, Traceroute, Banner Grabbing, and network utilities
"""
import socket
import subprocess
import platform
import time
import re
import concurrent.futures


def ping_host(host, count=4, callback=None):
    """Ping a host and return results"""
    results = {
        "host": host,
        "alive": False,
        "min_rtt": None,
        "avg_rtt": None,
        "max_rtt": None,
        "packets_sent": count,
        "packets_received": 0,
        "packet_loss": 100.0
    }

    if callback:
        callback({"type": "info", "message": f"📡 Pinging {host} ({count} packets)..."})

    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = proc.stdout + proc.stderr

        if proc.returncode == 0:
            results["alive"] = True

        # Parse output
        lines = output.split('\n')
        for line in lines:
            if callback and line.strip():
                callback({"type": "info", "message": f"  {line.rstrip()}"})

        # Extract statistics
        if system != "windows":
            # Linux/Mac: round-trip min/avg/max/mdev
            stats_match = re.search(r'(\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)', output)
            if stats_match:
                results["min_rtt"] = float(stats_match.group(1))
                results["avg_rtt"] = float(stats_match.group(2))
                results["max_rtt"] = float(stats_match.group(3))

            # Packet loss
            loss_match = re.search(r'(\d+)%\s+packet loss', output)
            if loss_match:
                results["packet_loss"] = float(loss_match.group(1))
                results["packets_received"] = int(count * (1 - results["packet_loss"]/100))

        if results["alive"]:
            if callback:
                callback({"type": "ok", "message": f"✅ Host is UP | Avg RTT: {results.get('avg_rtt', 'N/A')}ms | Loss: {results['packet_loss']}%"})
        else:
            if callback:
                callback({"type": "warn", "message": f"❌ Host appears to be DOWN or blocking ICMP"})

    except subprocess.TimeoutExpired:
        results["error"] = "Ping timeout"
        if callback:
            callback({"type": "error", "message": "⏰ Ping timeout"})
    except FileNotFoundError:
        # Fallback to socket-based check
        try:
            sock = socket.create_connection((host, 80), timeout=3)
            sock.close()
            results["alive"] = True
            results["packet_loss"] = 0
            if callback:
                callback({"type": "ok", "message": f"✅ Host is reachable (TCP check on port 80)"})
        except:
            if callback:
                callback({"type": "warn", "message": "❌ Host unreachable"})
    except Exception as e:
        results["error"] = str(e)
        if callback:
            callback({"type": "error", "message": f"❌ Error: {e}"})

    return results


def traceroute(host, max_hops=30, callback=None):
    """Perform traceroute to host"""
    results = {
        "host": host,
        "hops": [],
        "total_hops": 0
    }

    if callback:
        callback({"type": "info", "message": f"🗺️  Traceroute to {host} (max {max_hops} hops)..."})

    system = platform.system().lower()
    if system == "windows":
        cmd = ["tracert", "-h", str(max_hops), "-w", "1000", host]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", "2", host]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, bufsize=1)

        hop_num = 0
        for line in proc.stdout:
            line = line.rstrip()
            if callback and line:
                callback({"type": "info", "message": f"  {line}"})

            # Parse hop
            hop_match = re.match(r'\s*(\d+)\s+(.+)', line)
            if hop_match:
                hop_num = int(hop_match.group(1))
                hop_info = hop_match.group(2)
                results["hops"].append({"hop": hop_num, "info": hop_info})

        proc.wait()
        results["total_hops"] = hop_num

        if callback:
            callback({"type": "complete", "message": f"✅ Traceroute complete ({hop_num} hops)"})

    except FileNotFoundError:
        if callback:
            callback({"type": "warn", "message": "⚠️  traceroute not available, using fallback..."})
        # Simple fallback using socket TTL
        _simple_traceroute(host, max_hops, results, callback)
    except Exception as e:
        results["error"] = str(e)
        if callback:
            callback({"type": "error", "message": f"❌ Error: {e}"})

    return results


def _simple_traceroute(host, max_hops, results, callback):
    """Simple traceroute using ICMP or UDP"""
    try:
        dst_ip = socket.gethostbyname(host)
        port = 33434

        for ttl in range(1, max_hops + 1):
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            recv_sock.settimeout(2)

            recv_sock.bind(("", port))
            send_sock.sendto(b"", (dst_ip, port))

            hop_ip = None
            try:
                _, curr_addr = recv_sock.recvfrom(512)
                hop_ip = curr_addr[0]
            except socket.timeout:
                hop_ip = "*"
            finally:
                send_sock.close()
                recv_sock.close()

            hop = {"hop": ttl, "ip": hop_ip}
            results["hops"].append(hop)

            if callback:
                callback({"type": "info", "message": f"  {ttl:3d}  {hop_ip}"})

            if hop_ip == dst_ip:
                results["total_hops"] = ttl
                break
    except Exception:
        pass


def banner_grab(host, ports=None, timeout=3, callback=None):
    """Grab service banners from open ports"""
    if not ports:
        ports = [21, 22, 23, 25, 80, 110, 143, 443, 8080]

    results = {
        "host": host,
        "banners": []
    }

    # Resolve IP
    try:
        ip = socket.gethostbyname(host)
    except:
        ip = host

    if callback:
        callback({"type": "info", "message": f"🎯 Grabbing banners from {host} on {len(ports)} ports..."})

    probes = {
        21: b"",        # FTP banner on connect
        22: b"",        # SSH banner on connect
        25: b"EHLO test\r\n",
        80: b"HEAD / HTTP/1.0\r\n\r\n",
        110: b"",       # POP3 banner on connect
        143: b"",       # IMAP banner on connect
        443: b"HEAD / HTTP/1.0\r\n\r\n",
        3306: b"",      # MySQL banner
        8080: b"HEAD / HTTP/1.0\r\n\r\n",
        8443: b"HEAD / HTTP/1.0\r\n\r\n",
        5432: b"",      # PostgreSQL
        6379: b"INFO\r\n",  # Redis
        27017: b"",     # MongoDB
    }

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))

            probe = probes.get(port, b"\r\n")
            if probe:
                sock.send(probe)

            time.sleep(0.3)
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            sock.close()

            if banner:
                # Truncate and clean
                banner_clean = ' '.join(banner.split()[:30])[:300]
                result = {
                    "port": port,
                    "banner": banner_clean,
                    "raw": banner[:500]
                }
                results["banners"].append(result)

                if callback:
                    callback({"type": "found",
                             "message": f"🎯 Port {port}: {banner_clean[:100]}"})

                # Check for sensitive info in banner
                sensitive_patterns = [
                    (r'(\d+\.\d+\.\d+)', "Version number detected"),
                    (r'(Ubuntu|Debian|CentOS|RedHat|Windows Server)', "OS information leaked"),
                    (r'(OpenSSH|Apache|nginx|IIS|PHP)', "Software version leaked"),
                ]
                for pattern, message in sensitive_patterns:
                    if re.search(pattern, banner, re.IGNORECASE):
                        if callback:
                            callback({"type": "warn", "message": f"  ⚠️  {message} in port {port} banner"})

        except (socket.timeout, ConnectionRefusedError):
            pass
        except Exception as e:
            pass

    if callback:
        callback({"type": "complete", "message": f"✅ Banner grabbing complete. Got {len(results['banners'])} banners"})

    return results


def check_firewall(host, callback=None):
    """Basic firewall detection by probing filtered vs closed ports"""
    if callback:
        callback({"type": "info", "message": f"🔥 Testing firewall presence on {host}..."})

    # Test a mix of common and random high ports
    test_ports = [80, 443, 22, 21, 23, 25, 3389, 31337, 12345, 54321]
    filtered_count = 0
    closed_count = 0
    open_count = 0

    try:
        ip = socket.gethostbyname(host)
    except:
        ip = host

    for port in test_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                open_count += 1
            elif result in [111, 61]:  # ECONNREFUSED
                closed_count += 1
            else:
                filtered_count += 1  # Timeout = filtered
        except socket.timeout:
            filtered_count += 1
        except:
            pass

    has_firewall = filtered_count > 2

    if callback:
        callback({"type": "info", "message": f"  Open: {open_count} | Closed: {closed_count} | Filtered: {filtered_count}"})
        if has_firewall:
            callback({"type": "warn", "message": "⚠️  Firewall likely present (filtered ports detected)"})
        else:
            callback({"type": "info", "message": "ℹ️  No obvious firewall filtering detected"})

    return {
        "host": host,
        "firewall_detected": has_firewall,
        "open": open_count,
        "closed": closed_count,
        "filtered": filtered_count
    }


def nslookup(domain, record_type="A", callback=None):
    """Perform nslookup"""
    if callback:
        callback({"type": "info", "message": f"🔍 NSLookup: {domain} ({record_type})..."})

    try:
        cmd = ["nslookup", f"-type={record_type}", domain]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        output = proc.stdout

        if callback:
            for line in output.split('\n'):
                if line.strip() and not line.startswith('>'):
                    callback({"type": "info", "message": f"  {line.rstrip()}"})

        return {"output": output, "record_type": record_type, "domain": domain}
    except FileNotFoundError:
        # Fallback to socket
        try:
            results = socket.getaddrinfo(domain, None)
            ips = list(set([r[4][0] for r in results]))
            for ip in ips:
                if callback:
                    callback({"type": "found", "message": f"  {domain} → {ip}"})
            return {"ips": ips, "domain": domain}
        except Exception as e:
            if callback:
                callback({"type": "error", "message": f"❌ {e}"})
            return {"error": str(e)}

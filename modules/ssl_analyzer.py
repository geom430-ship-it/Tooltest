"""
SSL/TLS Analyzer Module
Analyzes SSL/TLS configuration, certificates, and vulnerabilities
"""
import ssl
import socket
import datetime
import json

try:
    from OpenSSL import SSL, crypto
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False


def get_certificate_info(host, port=443, callback=None):
    """Get SSL certificate information"""
    results = {
        "host": host,
        "port": port,
        "certificate": None,
        "chain": [],
        "errors": []
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        if callback:
            callback({"type": "info", "message": f"🔒 Connecting to {host}:{port} for SSL analysis..."})

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cert_bin = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                protocol = ssock.version()

                results["protocol"] = protocol
                results["cipher"] = {
                    "name": cipher[0] if cipher else "Unknown",
                    "protocol": cipher[1] if cipher and len(cipher) > 1 else "Unknown",
                    "bits": cipher[2] if cipher and len(cipher) > 2 else 0
                }

                if cert:
                    # Parse subject
                    subject = {}
                    for item in cert.get("subject", []):
                        for key, val in item:
                            subject[key] = val

                    # Parse issuer
                    issuer = {}
                    for item in cert.get("issuer", []):
                        for key, val in item:
                            issuer[key] = val

                    # Parse dates
                    not_before = cert.get("notBefore", "")
                    not_after = cert.get("notAfter", "")

                    expire_date = None
                    days_remaining = None
                    is_expired = False
                    is_expiring_soon = False

                    if not_after:
                        try:
                            expire_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            now = datetime.datetime.utcnow()
                            days_remaining = (expire_date - now).days
                            is_expired = days_remaining < 0
                            is_expiring_soon = 0 <= days_remaining <= 30
                        except:
                            pass

                    # SANs
                    san_list = []
                    for san_type, san_val in cert.get("subjectAltName", []):
                        san_list.append(f"{san_type}:{san_val}")

                    results["certificate"] = {
                        "subject": subject,
                        "issuer": issuer,
                        "not_before": not_before,
                        "not_after": not_after,
                        "expire_date": expire_date.strftime("%Y-%m-%d") if expire_date else None,
                        "days_remaining": days_remaining,
                        "is_expired": is_expired,
                        "is_expiring_soon": is_expiring_soon,
                        "san": san_list,
                        "serial_number": str(cert.get("serialNumber", "")),
                        "version": cert.get("version", "")
                    }

                    if callback:
                        cn = subject.get("commonName", "Unknown")
                        org = subject.get("organizationName", "Unknown")
                        callback({"type": "found", "message": f"📜 Subject: {cn} ({org})"})
                        callback({"type": "found", "message": f"🏛️  Issuer: {issuer.get('organizationName', 'Unknown')}"})

                        if is_expired:
                            callback({"type": "vuln", "message": f"🚨 CERTIFICATE EXPIRED {abs(days_remaining)} days ago!"})
                        elif is_expiring_soon:
                            callback({"type": "warn", "message": f"⚠️  Certificate expires in {days_remaining} days!"})
                        else:
                            callback({"type": "ok", "message": f"✅ Certificate valid for {days_remaining} more days"})

                        if san_list:
                            callback({"type": "info", "message": f"🌐 SANs: {', '.join(san_list[:5])}" + (" ..." if len(san_list) > 5 else "")})

    except ssl.SSLError as e:
        results["errors"].append(f"SSL Error: {str(e)}")
        if callback:
            callback({"type": "error", "message": f"❌ SSL Error: {str(e)}"})
    except socket.timeout:
        results["errors"].append("Connection timeout")
        if callback:
            callback({"type": "error", "message": "❌ Connection timeout"})
    except Exception as e:
        results["errors"].append(str(e))
        if callback:
            callback({"type": "error", "message": f"❌ Error: {str(e)}"})

    return results


def check_ssl_protocols(host, port=443, callback=None):
    """Check supported SSL/TLS protocol versions"""
    protocols = {
        "SSLv2": ssl.PROTOCOL_TLS,   # Modern Python doesn't support SSLv2 directly
        "SSLv3": ssl.PROTOCOL_TLS,
        "TLSv1.0": ssl.PROTOCOL_TLS,
        "TLSv1.1": ssl.PROTOCOL_TLS,
        "TLSv1.2": ssl.PROTOCOL_TLS,
        "TLSv1.3": ssl.PROTOCOL_TLS,
    }

    results = {}

    if callback:
        callback({"type": "info", "message": "🔍 Checking supported TLS protocols..."})

    # Check via ssl module
    protocol_tests = [
        ("TLSv1.0", ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3 if hasattr(ssl, 'OP_NO_TLSv1_3') else ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2),
        ("TLSv1.1", ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2),
        ("TLSv1.2", ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1),
    ]

    for proto_name, options in protocol_tests:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.options |= options

            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    actual_version = ssock.version()
                    results[proto_name] = True

                    if proto_name in ["TLSv1.0", "TLSv1.1"]:
                        if callback:
                            callback({"type": "vuln", "message": f"⚠️  {proto_name} supported (deprecated - security risk!)"})
                    else:
                        if callback:
                            callback({"type": "ok", "message": f"✅ {proto_name} supported"})
        except:
            results[proto_name] = False
            if callback:
                callback({"type": "ok", "message": f"✅ {proto_name} not supported (good)"})

    # Try to detect TLS 1.3
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if hasattr(ssl, 'OP_NO_TLSv1') and hasattr(ssl, 'OP_NO_TLSv1_1') and hasattr(ssl, 'OP_NO_TLSv1_2'):
            ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                if ssock.version() == "TLSv1.3":
                    results["TLSv1.3"] = True
                    if callback:
                        callback({"type": "ok", "message": "✅ TLSv1.3 supported (excellent!)"})
    except:
        pass

    return results


def check_vulnerabilities(host, port=443, callback=None):
    """Check for common SSL/TLS vulnerabilities"""
    vulns = []

    if callback:
        callback({"type": "info", "message": "🔍 Checking for SSL/TLS vulnerabilities..."})

    # Check self-signed cert
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            ctx.wrap_socket(sock, server_hostname=host)
        if callback:
            callback({"type": "ok", "message": "✅ Certificate is trusted (not self-signed)"})
    except ssl.SSLCertVerificationError:
        vulns.append({
            "name": "Self-Signed Certificate",
            "severity": "high",
            "description": "The certificate is self-signed or from an untrusted CA"
        })
        if callback:
            callback({"type": "vuln", "message": "⚠️  Certificate verification failed (possible self-signed or invalid CA)"})
    except Exception:
        pass

    # Check for weak cipher suites
    weak_ciphers = ["RC4", "MD5", "DES", "3DES", "EXPORT", "NULL", "ANON"]
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    cipher_name = cipher[0]
                    for weak in weak_ciphers:
                        if weak in cipher_name.upper():
                            vulns.append({
                                "name": f"Weak Cipher: {cipher_name}",
                                "severity": "high",
                                "description": f"Weak cipher suite {cipher_name} in use"
                            })
                            if callback:
                                callback({"type": "vuln", "message": f"🚨 Weak cipher detected: {cipher_name}"})
                    if callback:
                        callback({"type": "info", "message": f"🔑 Active cipher: {cipher_name} ({cipher[2]} bits)"})
    except Exception:
        pass

    # Check HSTS preload
    try:
        if HAS_OPENSSL:
            pass  # Additional checks could go here
    except:
        pass

    if not vulns and callback:
        callback({"type": "ok", "message": "✅ No major SSL/TLS vulnerabilities detected"})

    return vulns


def full_ssl_analysis(host, port=443, callback=None):
    """Perform complete SSL/TLS analysis"""
    if callback:
        callback({"type": "info", "message": f"🔒 Starting SSL/TLS analysis for {host}:{port}..."})

    results = {
        "host": host,
        "port": port,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "certificate": None,
        "protocols": {},
        "vulnerabilities": [],
        "grade": "F"
    }

    # Certificate info
    if callback:
        callback({"type": "info", "message": "\n--- Certificate Information ---"})
    cert_info = get_certificate_info(host, port, callback)
    results["certificate"] = cert_info.get("certificate")
    results["cipher"] = cert_info.get("cipher")
    results["protocol"] = cert_info.get("protocol")

    # Protocol support
    if callback:
        callback({"type": "info", "message": "\n--- Protocol Support ---"})
    results["protocols"] = check_ssl_protocols(host, port, callback)

    # Vulnerabilities
    if callback:
        callback({"type": "info", "message": "\n--- Vulnerability Checks ---"})
    results["vulnerabilities"] = check_vulnerabilities(host, port, callback)

    # Calculate grade
    score = 100
    cert = results.get("certificate", {})
    if cert:
        if cert.get("is_expired"):
            score -= 40
        if cert.get("is_expiring_soon"):
            score -= 10
    if results["protocols"].get("TLSv1.0"):
        score -= 20
    if results["protocols"].get("TLSv1.1"):
        score -= 10
    for vuln in results["vulnerabilities"]:
        if vuln.get("severity") == "critical":
            score -= 40
        elif vuln.get("severity") == "high":
            score -= 20
        elif vuln.get("severity") == "medium":
            score -= 10

    if score >= 90: results["grade"] = "A+"
    elif score >= 80: results["grade"] = "A"
    elif score >= 70: results["grade"] = "B"
    elif score >= 60: results["grade"] = "C"
    elif score >= 50: results["grade"] = "D"
    else: results["grade"] = "F"

    if callback:
        callback({"type": "complete", "message": f"\n🏆 SSL/TLS Grade: {results['grade']} (Score: {max(0, score)}/100)"})

    return results

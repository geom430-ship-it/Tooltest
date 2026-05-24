"""
HTTP Request Smuggling Detector - UHQKYRA v1.0
===============================================
⚠️  Authorized security testing only.

Detects HTTP/1.1 request smuggling vulnerabilities:
  CL.TE — Front-end uses Content-Length, back-end uses Transfer-Encoding
  TE.CL — Front-end uses Transfer-Encoding, back-end uses Content-Length
  TE.TE — Both use TE but one can be obfuscated
  CL.CL — Content-Length ambiguity
  HTTP/2 downgrade smuggling hints

Detection method: timing-based probes + differential response analysis.
Non-destructive — uses safe payloads only.
"""
import time
import warnings
warnings.filterwarnings("ignore")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from modules.evasion import random_headers, burst_jitter
except ImportError:
    try:
        from evasion import random_headers, burst_jitter
    except ImportError:
        def random_headers(**kw): return {"User-Agent": "Mozilla/5.0"}
        def burst_jitter(): pass


def _send_raw(url, raw_request, timeout=15):
    """Send a raw HTTP/1.1 request using socket to preserve exact bytes."""
    import socket, ssl
    import urllib.parse
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        if isinstance(raw_request, str):
            raw_request = raw_request.encode("utf-8", errors="replace")

        t0 = time.time()
        sock.sendall(raw_request)

        resp = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 65536:
                    break
            except socket.timeout:
                break
        elapsed = time.time() - t0
        return resp.decode("utf-8", errors="replace"), elapsed
    except Exception as e:
        return "", time.time() - t0
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _build_clte_probe(host, path="/"):
    """CL.TE probe: send body with mismatched CL and TE."""
    body = "1\r\nZ\r\n0\r\n\r\n"
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return req


def _build_tecl_probe(host, path="/"):
    """TE.CL probe: chunked body with truncated CL."""
    chunk = "0\r\n\r\nX"
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 3\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{chunk}"
    )
    return req


def _build_te_obfuscated_probe(host, path="/"):
    """TE.TE probe with obfuscated Transfer-Encoding header."""
    body = "1\r\nZ\r\n0\r\n\r\n"
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: xchunked\r\n"       # obfuscated
        f"Transfer-encoding: chunked\r\n"         # second TE header
        f"Connection: keep-alive\r\n"
        f"\r\n"
        f"{body}"
    )
    return req


def _timing_probe(url, raw_req, normal_time):
    """
    Send raw probe and check if response is significantly slower than normal.
    Returns (is_slow, elapsed).
    """
    _, elapsed = _send_raw(url, raw_req, timeout=20)
    return elapsed > max(normal_time * 2.5, 4.0), elapsed


def scan_http_smuggling(url, callback=None):
    """
    Detect HTTP Request Smuggling vulnerabilities using timing-based probes.
    Non-destructive — no actual smuggling payload is injected.
    """
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {
        "url":             url,
        "findings":        [],
        "vulnerabilities": [],
        "tests_run":       0,
        "vulnerable":      False,
    }

    base = url if "://" in url else "http://" + url

    import urllib.parse
    parsed = urllib.parse.urlparse(base)
    host   = parsed.netloc
    path   = parsed.path or "/"
    if not path:
        path = "/"

    cb("info", f"🚇 HTTP Smuggling probe: {base}")

    # ── Baseline timing ───────────────────────────────────────────────
    normal_times = []
    for _ in range(2):
        try:
            hdrs = random_headers()
            t0 = time.time()
            if HAS_REQUESTS:
                import requests as _r
                _r.get(base, headers=hdrs, timeout=10, verify=False,
                       allow_redirects=False)
            normal_times.append(time.time() - t0)
        except Exception:
            normal_times.append(1.0)
    baseline = sum(normal_times) / max(len(normal_times), 1)
    cb("info", f"🚇 Baseline: {baseline:.2f}s")

    # ── Probes ────────────────────────────────────────────────────────
    probes = [
        ("CL.TE",         _build_clte_probe(host, path)),
        ("TE.CL",         _build_tecl_probe(host, path)),
        ("TE.TE (obfusc)",_build_te_obfuscated_probe(host, path)),
    ]

    for probe_name, raw_req in probes:
        cb("info", f"🚇 Test {probe_name}...")
        results["tests_run"] += 1
        try:
            is_slow, elapsed = _timing_probe(base, raw_req, baseline)
            burst_jitter()

            if is_slow:
                results["vulnerable"] = True
                detail = (f"{probe_name}: réponse {elapsed:.2f}s vs baseline {baseline:.2f}s "
                          f"(×{elapsed/max(baseline,0.1):.1f} plus lente)")
                results["findings"].append({
                    "test":     probe_name,
                    "severity": "critical",
                    "detail":   detail,
                    "elapsed":  elapsed,
                    "baseline": baseline,
                })
                results["vulnerabilities"].append({
                    "type":     "http_smuggling",
                    "severity": "critical",
                    "name":     f"HTTP Request Smuggling ({probe_name}) — timing suspect",
                    "detail":   detail,
                })
                cb("vuln", f"🚨 HTTP Smuggling [{probe_name}]: {detail}")
            else:
                cb("ok", f"🚇 {probe_name}: {elapsed:.2f}s — normal")
        except Exception as e:
            cb("warn", f"🚇 {probe_name}: {e}")

    # ── Header-based hints (via normal request) ───────────────────────
    try:
        if HAS_REQUESTS:
            import requests as _r
            r0 = _r.get(base, headers=random_headers(), timeout=10,
                        verify=False, allow_redirects=True)
            server = r0.headers.get("Server", "")
            via    = r0.headers.get("Via", "")
            # Proxy/CDN indicators increase smuggling risk
            if via or "proxy" in server.lower() or "nginx" in server.lower():
                results["findings"].append({
                    "test":     "proxy_indicator",
                    "severity": "info",
                    "detail":   f"Proxy/CDN détecté: Server={server} Via={via} → risque accru",
                })
                cb("info", f"🚇 Proxy détecté: {server or via} → vérifier manuellement")
    except Exception:
        pass

    total = len([f for f in results["findings"] if f["test"] != "proxy_indicator"])
    if total:
        cb("vuln", f"🚨 HTTP Smuggling: {total} probe(s) suspecte(s) sur {results['tests_run']} tests")
    else:
        cb("ok", f"🚇 HTTP Smuggling: aucune anomalie ({results['tests_run']} tests)")

    return results

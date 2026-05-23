"""
IDOR Scanner - UHQKYRA v3.0
Detect Insecure Direct Object Reference vulnerabilities
"""
import re
import warnings
warnings.filterwarnings("ignore")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

IDOR_PARAMS = [
    "id", "user_id", "uid", "account_id", "doc_id", "file_id",
    "order_id", "invoice_id", "record_id", "item_id", "product_id",
    "page_id", "post_id", "comment_id", "message_id", "ticket_id",
    "customer_id", "employee_id", "report_id", "session", "token",
]


def scan_idor(url, callback=None):
    """Scan for IDOR vulnerabilities"""
    def cb(t, m):
        if callback: callback({"type": t, "message": m})

    results = {"vulnerable": False, "findings": [], "idor_params": []}

    if not HAS_REQUESTS:
        cb("error", "requests non disponible")
        return results

    s = requests.Session()
    s.headers.update(HEADERS)
    s.verify = False

    parsed = urlparse(url if "://" in url else "http://" + url)
    params = dict(parse_qs(parsed.query))
    base = url.split('?')[0]

    cb("info", f"IDOR scan: {base}")

    # Find numeric params
    numeric_params = [
        k for k, v in params.items()
        if (v[0] if isinstance(v, list) else v).isdigit()
    ]
    idor_params_found = [p for p in IDOR_PARAMS if p in params]
    all_test = list(set(numeric_params + idor_params_found))

    if not all_test:
        cb("info", "Aucun parametre IDOR evident detecte")
        return results

    results["idor_params"] = all_test

    try:
        base_resp = s.get(url, timeout=10)
        base_body = base_resp.text
        base_size = len(base_body)
    except Exception:
        return results

    for param in all_test:
        current_val = (params[param][0] if isinstance(params[param], list) else params[param])
        if not current_val.isdigit():
            continue

        current_id = int(current_val)
        test_ids = list(set([
            current_id - 1, current_id + 1,
            current_id - 10, current_id + 10,
            1, 2, 3, 100, 999
        ]))

        for test_id in test_ids:
            if test_id <= 0:
                continue
            tp = params.copy()
            tp[param] = [str(test_id)]
            new_url = urlunparse(parsed._replace(query=urlencode(tp, doseq=True)))
            try:
                resp = s.get(new_url, timeout=8)
                if resp.status_code == 200 and abs(len(resp.text) - base_size) > 100:
                    # Different content returned -- possible IDOR
                    if not _is_error_page(resp.text):
                        results["vulnerable"] = True
                        results["findings"].append({
                            "type": "idor_possible",
                            "severity": "high",
                            "name": f"IDOR possible: param '{param}' id={test_id}",
                            "detail": f"Contenu different ({base_size}B vs {len(resp.text)}B)"
                        })
                        cb("warn", f"IDOR possible: {param}={test_id} ({base_size}->{len(resp.text)} bytes)")
            except Exception:
                pass

    # Path-based IDOR (e.g., /api/users/123)
    path_idor_pattern = re.compile(r'/(\d+)(?:/|$)')
    path = parsed.path
    for m in path_idor_pattern.finditer(path):
        orig_id = int(m.group(1))
        for test_id in [orig_id - 1, orig_id + 1, 1, 2]:
            if test_id <= 0:
                continue
            new_path = path[:m.start(1)] + str(test_id) + path[m.end(1):]
            try:
                new_url = urlunparse(parsed._replace(path=new_path))
                resp = s.get(new_url, timeout=8)
                if resp.status_code == 200 and not _is_error_page(resp.text):
                    results["findings"].append({
                        "type": "idor_path",
                        "severity": "high",
                        "name": f"IDOR path: {new_path} (id={test_id})",
                        "detail": f"Status 200, {len(resp.text)} bytes"
                    })
                    cb("warn", f"IDOR path: {new_path}")
                    results["vulnerable"] = True
            except Exception:
                pass

    if not results["vulnerable"]:
        cb("ok", "Pas d'IDOR evident detecte")
    return results


def _is_error_page(text):
    error_patterns = ["404", "not found", "error", "invalid", "forbidden",
                      "access denied", "unauthorized", "does not exist"]
    return any(p in text.lower() for p in error_patterns)

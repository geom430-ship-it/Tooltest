"""
Parameter Miner - UHQKYRA
Discover hidden/undocumented HTTP parameters by fuzzing parameter names.
"""

import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

PARAM_WORDLIST = [
    "debug", "test", "admin", "id", "user", "username", "password", "passwd",
    "token", "key", "api_key", "access_token", "auth", "authorization", "secret",
    "action", "cmd", "exec", "command", "execute", "run", "shell",
    "file", "path", "filepath", "filename", "dir", "directory", "folder",
    "url", "uri", "link", "href", "src", "redirect", "return", "next", "goto",
    "callback", "cb", "jsonp", "format", "type", "output", "mode", "lang",
    "language", "locale", "country", "region", "timezone",
    "page", "p", "pg", "pagenum", "limit", "offset", "start", "end",
    "sort", "order", "orderby", "sortby", "direction", "asc", "desc",
    "filter", "search", "q", "query", "keyword", "keywords", "term",
    "cache", "no_cache", "nocache", "bypass", "skip",
    "dev", "developer", "internal", "private", "hidden", "beta",
    "role", "privilege", "scope", "grant", "permission", "level", "group",
    "account", "profile", "member", "customer", "client", "owner",
    "email", "phone", "mobile", "address", "zip", "country_code",
    "name", "fullname", "firstname", "lastname", "nickname",
    "age", "dob", "birthdate", "gender", "sex",
    "status", "state", "active", "enabled", "disabled", "flag",
    "version", "ver", "v", "build", "release", "env", "environment",
    "config", "configuration", "setting", "settings", "option", "options",
    "data", "payload", "body", "content", "message", "text", "value",
    "param", "parameter", "arg", "argument", "input", "output",
    "from", "to", "subject", "reply", "sender", "receiver",
    "date", "time", "timestamp", "created", "updated", "deleted",
    "ip", "host", "hostname", "server", "port", "proto", "protocol",
    "proxy", "agent", "browser", "client_id", "client_secret",
    "code", "ref", "referral", "invite", "voucher", "coupon", "promo",
    "hash", "checksum", "signature", "nonce", "csrf", "xsrf",
    "session", "sid", "ssid", "cookie", "remember",
    "plan", "tier", "package", "product", "item", "category",
    "price", "amount", "qty", "quantity", "total", "subtotal",
    "currency", "payment", "method", "gateway",
    "template", "theme", "skin", "layout", "view", "widget",
    "include", "require", "load", "fetch", "import",
    "tag", "label", "class", "css", "style", "color",
    "width", "height", "size", "thumb", "thumbnail", "image", "img",
    "video", "audio", "media", "attachment", "upload",
    "download", "export", "import", "backup", "restore",
    "log", "logs", "trace", "verbose", "verbose_output",
    "print", "show", "display", "render", "preview",
    "report", "stats", "analytics", "metrics", "monitor",
    "alert", "notify", "notification", "subscribe", "unsubscribe",
    "enable", "disable", "toggle", "switch",
    "new", "old", "current", "previous", "next_page",
    "forward", "back", "home", "index", "default",
    "null", "none", "true", "false", "yes", "no",
    "raw", "plain", "json", "xml", "csv", "pdf", "html",
    "compress", "gzip", "encoding", "charset",
    "origin", "referer", "referrer", "source",
    "target", "destination", "location",
    "open", "close", "read", "write", "delete", "remove",
    "create", "add", "update", "edit", "modify", "change",
    "list", "get", "set", "post", "put", "patch",
    "inject", "sql", "xss", "rce", "lfi", "rfi",
    "dbg", "xdebug", "profiler", "trace_id",
    "user_id", "userid", "uid", "gid", "pid",
    "article_id", "post_id", "comment_id", "order_id",
    "transaction_id", "request_id", "job_id",
    "parent", "child", "node", "leaf", "root",
    "before", "after", "between", "range",
    "fields", "columns", "rows", "table", "database", "schema",
    "model", "controller", "service", "module",
    "help", "support", "contact", "feedback",
    "captcha", "verify", "validation", "otp", "2fa",
    "webhook", "endpoint", "api", "rest", "graphql",
    "tag_id", "ref_id", "doc_id", "file_id", "record_id",
    "populate", "expand", "embed", "include_deleted",
    "pretty", "indent", "minify",
    "timeout", "ttl", "expiry", "expires",
    "max", "min", "threshold", "quota",
    "operator", "condition", "rule", "policy",
    "namespace", "prefix", "suffix",
    "debug_mode", "test_mode", "maintenance",
    "override", "force", "strict", "safe",
]

INTERESTING_KEYWORDS = [
    "error", "exception", "stack", "trace", "debug", "warning",
    "root", "admin", "administrator", "password", "passwd", "secret",
    "token", "key", "credential", "private", "internal",
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "sql", "mysql", "postgres", "mongodb", "redis",
    "aws", "s3", "azure", "gcp", "bucket",
    "php", "java", "python", "ruby", "node",
]

EXTRA_HEADERS = [
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Host", "localhost"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("Forwarded", "for=127.0.0.1"),
]

PROBE_VALUE = "uhqkyra_test_1337"


def _get_baseline(url, session):
    try:
        resp = session.get(url, headers=HEADERS, verify=False, timeout=8)
        return resp.status_code, len(resp.text), resp.text
    except Exception:
        return None, 0, ""


def _test_param(url, param, baseline_len, baseline_text, session):
    sep = "&" if "?" in url else "?"
    test_url = f"{url}{sep}{param}={PROBE_VALUE}"
    try:
        resp = session.get(test_url, headers=HEADERS, verify=False, timeout=8)
        resp_len = len(resp.text)
        reflected = PROBE_VALUE in resp.text
        diff_ratio = abs(resp_len - baseline_len) / max(baseline_len, 1)
        interesting_hit = any(kw in resp.text.lower() for kw in INTERESTING_KEYWORDS
                               if kw not in baseline_text.lower())
        status_changed = resp.status_code != 200
        return {
            "param": param,
            "status": resp.status_code,
            "length": resp_len,
            "reflected": reflected,
            "diff_ratio": diff_ratio,
            "interesting_content": interesting_hit,
            "notable": reflected or diff_ratio > 0.05 or interesting_hit or status_changed,
        }
    except Exception:
        return None


def _test_header(url, header_name, header_value, session):
    h = dict(HEADERS)
    h[header_name] = header_value
    try:
        resp = session.get(url, headers=h, verify=False, timeout=8)
        return {"header": header_name, "value": header_value, "status": resp.status_code, "length": len(resp.text)}
    except Exception:
        return None


def mine_params(url, callback=None):
    found = []
    interesting = []
    vulnerabilities = []

    session = requests.Session()

    if callback:
        callback({"type": "info", "message": f"Starting parameter mining on {url}"})

    baseline_status, baseline_len, baseline_text = _get_baseline(url, session)
    if baseline_status is None:
        if callback:
            callback({"type": "error", "message": "Could not reach target URL"})
        return {"found": found, "interesting": interesting, "vulnerabilities": vulnerabilities}

    if callback:
        callback({"type": "info", "message": f"Baseline: status={baseline_status}, length={baseline_len}"})
        callback({"type": "info", "message": f"Testing {len(PARAM_WORDLIST)} parameters with 30 workers..."})

    def worker(param):
        return _test_param(url, param, baseline_len, baseline_text, session)

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(worker, p): p for p in PARAM_WORDLIST}
        for future in as_completed(futures):
            result = future.result()
            if result is None:
                continue
            if result["notable"]:
                found.append(result)
                if callback:
                    callback({"type": "found", "message": f"Interesting param: {result['param']} (reflected={result['reflected']}, diff={result['diff_ratio']:.2%})"})
                if result["reflected"]:
                    interesting.append(result["param"])
                    vuln = {
                        "type": "Reflected Parameter (Potential XSS)",
                        "param": result["param"],
                        "severity": "MEDIUM",
                        "detail": f"Parameter '{result['param']}' value is reflected in response",
                    }
                    vulnerabilities.append(vuln)
                    if callback:
                        callback({"type": "vulnerability", "message": f"[MEDIUM] Reflected param: {result['param']}"})
                if result["interesting_content"]:
                    interesting.append(result["param"])
                    if callback:
                        callback({"type": "found", "message": f"Param triggers interesting content: {result['param']}"})

    if callback:
        callback({"type": "info", "message": "Testing bypass headers..."})

    for hname, hval in EXTRA_HEADERS:
        res = _test_header(url, hname, hval, session)
        if res:
            if res["status"] in (200, 302, 301):
                finding = {
                    "type": "Header Bypass",
                    "header": hname,
                    "value": hval,
                    "status": res["status"],
                    "severity": "MEDIUM",
                }
                vulnerabilities.append(finding)
                if callback:
                    callback({"type": "found", "message": f"[MEDIUM] Header bypass candidate: {hname}: {hval} → {res['status']}"})

    session.close()

    if callback:
        callback({"type": "done", "message": f"Parameter mining complete. Found {len(found)} notable params, {len(vulnerabilities)} potential issues."})

    return {
        "found": found,
        "interesting": list(set(interesting)),
        "vulnerabilities": vulnerabilities,
    }

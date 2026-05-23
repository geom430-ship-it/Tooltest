"""
Cloud Storage Scanner - UHQKYRA
Detect misconfigured cloud storage: AWS S3, Azure Blob, GCP Cloud Storage
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

CLOUD_URL_PATTERNS = [
    re.compile(r's3://([a-z0-9\-\.]+)', re.IGNORECASE),
    re.compile(r'gs://([a-z0-9\-\.]+)', re.IGNORECASE),
    re.compile(r'azureblob://([a-z0-9\-\.]+)', re.IGNORECASE),
    re.compile(r'https?://([a-z0-9\-\.]+)\.s3\.amazonaws\.com', re.IGNORECASE),
    re.compile(r'https?://s3\.amazonaws\.com/([a-z0-9\-\.]+)', re.IGNORECASE),
    re.compile(r'https?://([a-z0-9\-\.]+)\.s3[-\.](?:[a-z0-9\-]+\.)?amazonaws\.com', re.IGNORECASE),
    re.compile(r'https?://([a-z0-9\-\.]+)\.blob\.core\.windows\.net', re.IGNORECASE),
    re.compile(r'https?://storage\.googleapis\.com/([a-z0-9\-\.]+)', re.IGNORECASE),
    re.compile(r'https?://([a-z0-9\-\.]+)\.storage\.googleapis\.com', re.IGNORECASE),
    re.compile(r'https?://([a-z0-9\-\.]+)\.r2\.cloudflarestorage\.com', re.IGNORECASE),
]


def _extract_base_domain(domain):
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0].strip()
    parts = domain.split('.')
    if len(parts) >= 2:
        return parts[-2]
    return domain


def _generate_bucket_names(domain):
    base = _extract_base_domain(domain)
    fqdn = domain if '.' in domain else domain
    clean = re.sub(r'^www\.', '', fqdn).split('.')[0]
    names = set()
    for b in [base, clean]:
        names.update([
            b,
            f"www.{b}",
            f"{b}-backup",
            f"{b}-static",
            f"{b}-assets",
            f"{b}-media",
            f"{b}-uploads",
            f"{b}-files",
            f"{b}-dev",
            f"{b}-staging",
            f"{b}-prod",
            f"{b}-production",
            f"backup-{b}",
            f"static-{b}",
            f"assets-{b}",
            f"media-{b}",
            f"uploads-{b}",
            f"files-{b}",
            f"dev-{b}",
            f"staging-{b}",
            f"prod-{b}",
            f"{b}-data",
            f"data-{b}",
            f"{b}-logs",
            f"logs-{b}",
            f"{b}-images",
            f"images-{b}",
            f"{b}-img",
            f"{b}-cdn",
            f"cdn-{b}",
            f"{b}-public",
            f"public-{b}",
            f"{b}-private",
            f"{b}-internal",
            f"{b}-archive",
            f"archive-{b}",
            f"{b}-downloads",
            f"{b}-test",
            f"test-{b}",
            f"{b}-qa",
            f"{b}-uat",
            f"{b}-demo",
        ])
    return list(names)


def _check_s3_bucket(bucket_name, session):
    results = []
    urls = [
        (f"http://{bucket_name}.s3.amazonaws.com/", "path-style-subdomain"),
        (f"https://s3.amazonaws.com/{bucket_name}/", "path-style"),
    ]
    for url, style in urls:
        try:
            resp = session.get(url, headers=HEADERS, verify=False, timeout=8, allow_redirects=False)
            if resp.status_code == 200:
                results.append({
                    "bucket": bucket_name,
                    "url": url,
                    "style": style,
                    "provider": "aws_s3",
                    "status": 200,
                    "severity": "CRITICAL",
                    "issue": "Public readable S3 bucket",
                    "content_snippet": resp.text[:300] if resp.text else "",
                })
            elif resp.status_code == 403:
                results.append({
                    "bucket": bucket_name,
                    "url": url,
                    "style": style,
                    "provider": "aws_s3",
                    "status": 403,
                    "severity": "LOW",
                    "issue": "S3 bucket exists but is private (access denied)",
                })
        except Exception:
            pass
    return results


def _check_azure_blob(bucket_name, session):
    url = f"https://{bucket_name}.blob.core.windows.net"
    try:
        resp = session.get(url, headers=HEADERS, verify=False, timeout=8, allow_redirects=False)
        if resp.status_code == 200:
            return {
                "bucket": bucket_name,
                "url": url,
                "provider": "azure_blob",
                "status": 200,
                "severity": "CRITICAL",
                "issue": "Public Azure Blob Storage container",
                "content_snippet": resp.text[:300] if resp.text else "",
            }
        if resp.status_code in (400, 403, 409):
            return {
                "bucket": bucket_name,
                "url": url,
                "provider": "azure_blob",
                "status": resp.status_code,
                "severity": "LOW",
                "issue": "Azure Blob Storage account exists",
            }
    except Exception:
        pass
    return None


def _check_gcp_bucket(bucket_name, session):
    url = f"https://storage.googleapis.com/{bucket_name}/"
    try:
        resp = session.get(url, headers=HEADERS, verify=False, timeout=8, allow_redirects=False)
        if resp.status_code == 200:
            return {
                "bucket": bucket_name,
                "url": url,
                "provider": "gcp_storage",
                "status": 200,
                "severity": "CRITICAL",
                "issue": "Public GCP Cloud Storage bucket",
                "content_snippet": resp.text[:300] if resp.text else "",
            }
        if resp.status_code == 403:
            return {
                "bucket": bucket_name,
                "url": url,
                "provider": "gcp_storage",
                "status": 403,
                "severity": "LOW",
                "issue": "GCP bucket exists but is private",
            }
    except Exception:
        pass
    return None


def _extract_cloud_urls(html):
    found = []
    for pattern in CLOUD_URL_PATTERNS:
        for m in pattern.finditer(html):
            bucket = m.group(1) if m.lastindex else m.group(0)
            found.append({
                "raw_match": m.group(0),
                "bucket": bucket,
                "severity": "MEDIUM",
                "issue": "Cloud storage URL exposed in page source",
            })
    return found


def scan_cloud(domain, callback=None):
    findings = []
    vulnerabilities = []

    if not REQUESTS_OK:
        if callback:
            callback({"type": "error", "message": "requests library not available"})
        return {"findings": findings, "vulnerabilities": vulnerabilities}

    session = requests.Session()
    bucket_names = _generate_bucket_names(domain)

    if callback:
        callback({"type": "info", "message": f"Starting cloud storage scan for {domain}"})
        callback({"type": "info", "message": f"Generated {len(bucket_names)} bucket name candidates"})

    base_url = f"https://{domain}" if not domain.startswith("http") else domain
    main_resp = None
    try:
        main_resp = session.get(base_url, headers=HEADERS, verify=False, timeout=8)
    except Exception:
        try:
            main_resp = session.get(f"http://{domain}", headers=HEADERS, verify=False, timeout=8)
        except Exception:
            pass

    if main_resp:
        html_urls = _extract_cloud_urls(main_resp.text)
        for item in html_urls:
            findings.append(item)
            vulnerabilities.append(item)
            if callback:
                callback({"type": "found", "message": f"[MEDIUM] Cloud URL in HTML: {item['raw_match']}"})

        js_links = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', main_resp.text, re.IGNORECASE)
        for js_src in js_links[:10]:
            if not js_src.startswith("http"):
                js_src = base_url.rstrip("/") + "/" + js_src.lstrip("/")
            try:
                js_resp = session.get(js_src, headers=HEADERS, verify=False, timeout=8)
                if js_resp.status_code == 200:
                    js_urls = _extract_cloud_urls(js_resp.text)
                    for item in js_urls:
                        item["source"] = js_src
                        findings.append(item)
                        vulnerabilities.append(item)
                        if callback:
                            callback({"type": "found", "message": f"[MEDIUM] Cloud URL in JS {js_src}: {item['raw_match']}"})
            except Exception:
                pass

    def check_all(name):
        hits = []
        s3_results = _check_s3_bucket(name, session)
        hits.extend(s3_results)
        azure_result = _check_azure_blob(name, session)
        if azure_result:
            hits.append(azure_result)
        gcp_result = _check_gcp_bucket(name, session)
        if gcp_result:
            hits.append(gcp_result)
        return hits

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_all, n): n for n in bucket_names}
        for future in as_completed(futures):
            results = future.result()
            for res in results:
                findings.append(res)
                if res["severity"] in ("CRITICAL", "HIGH"):
                    vulnerabilities.append(res)
                    if callback:
                        callback({"type": "vulnerability", "message": f"[{res['severity']}] {res['issue']}: {res['url']}"})
                elif res["severity"] == "LOW":
                    if callback:
                        callback({"type": "found", "message": f"[LOW] {res['issue']}: {res['url']}"})

    session.close()

    if callback:
        callback({"type": "done", "message": f"Cloud scan complete. {len(findings)} findings, {len(vulnerabilities)} vulnerabilities."})

    return {
        "findings": findings,
        "vulnerabilities": vulnerabilities,
    }

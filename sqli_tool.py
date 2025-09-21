#!/usr/bin/python3
import difflib, http.client, itertools, optparse, random, re, urllib, urllib.parse, urllib.request
import asyncio
import time
from typing import Tuple, Optional
import re
import sys
import hashlib

PREFIXES = (
    " ",   
    "' ",    
    "\" ",   
    ") ",    
    "' OR '1'='1' -- ", 
    "\" OR \"1\"=\"1\" -- "
)


SUFFIXES = (
    "",      
    "-- ", 
    "#",     
    "/*",  
    "';",    
    "\";",   
)


TAMPER_SQL_CHAR_POOL = (
    "'", "\"", ")", "(", ";", "-- ", "#", "%00", " OR 1=1", " AND 1=2"
)

BOOLEAN_TESTS = (
    "AND %d=%d",        
    "OR NOT (%d>%d)",     
    "AND 1=1",         
    "AND 1=2",           
    "OR 'a'='a'",        
    "OR 'a'='b'",        
)

COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"
GET, POST = "GET", "POST"
TEXT, HTTPCODE, TITLE, HTML = range(4)
FUZZY_THRESHOLD = 0.95
TIMEOUT = 25
RANDINT = random.randint(1, 255)
BLOCKED_IP_REGEX = r"(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)"

DBMS_ERRORS = {
    "MySQL": (
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


def _retrieve_content(url, data=None):
    retval = {HTTPCODE: http.client.OK}
    try:
        req = urllib.request.Request("".join(url[_].replace(' ', "%20") if _ > url.find('?') else url[_] for _ in range(len(url))), data.encode("utf8", "ignore") if data else None, globals().get("_headers", {}))
        retval[HTML] = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    except Exception as ex:
        retval[HTTPCODE] = getattr(ex, "code", None)
        retval[HTML] = ex.read() if hasattr(ex, "read") else str(ex.args[-1])
    retval[HTML] = (retval[HTML].decode("utf8", "ignore") if hasattr(retval[HTML], "decode") else "") or ""
    retval[HTML] = "" if re.search(BLOCKED_IP_REGEX, retval[HTML]) else retval[HTML]
    retval[HTML] = re.sub(r"(?i)[^>]*(AND|OR)[^<]*%d[^<]*" % RANDINT, "__REFLECTED__", retval[HTML])
    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    return retval

import hashlib

def scan_page(url, data=None):
    retval, usable = False, False
    url = re.sub(r"=(&|\Z)", r"=1\g<1>", url) if url else url
    data = re.sub(r"=(&|\Z)", r"=1\g<1>", data) if data else data

    def _safe_format(template: str, *args):
        if any(x in template for x in ("%d", "%s")):
            try:
                return template % args
            except Exception:
                return template
        return template

    def _count_resources(html: str) -> int:
        return len(re.findall(r"<img\b|<script\b|<link\b", html, re.I))

    def _count_tags(html: str) -> int:
        return len(re.findall(r"<\w+", html))

    def _hash_html(html: str) -> str:
        return hashlib.sha256(html.encode("utf-8")).hexdigest()

    try:
        for phase in (GET, POST):
            original, current = None, url if phase == GET else (data or "")
            parameters = list(re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", current))
            if not parameters:
                continue

            usable = True
            print(f"[*] Found {len(parameters)} {phase} parameters to test")

            for i, match in enumerate(parameters):
                vulnerable = False
                print(f"[*] Testing {phase} parameter '{match.group('parameter')}' ({i+1}/{len(parameters)})")
                original = original or (_retrieve_content(current, data) if phase == GET else _retrieve_content(url, current))

                # Original metrics
                original_hash = _hash_html(original[HTML])
                original_resources = _count_resources(original[HTML])
                original_tags = _count_tags(original[HTML])

                # Tampered payload
                tampered_value = urllib.parse.quote("".join(random.sample(TAMPER_SQL_CHAR_POOL, len(TAMPER_SQL_CHAR_POOL))))
                tampered = current.replace(match.group(0), f"{match.group(0)}{tampered_value}")
                content = _retrieve_content(tampered, data) if phase == GET else _retrieve_content(url, tampered)

                tampered_hash = _hash_html(content[HTML])
                tampered_resources = _count_resources(content[HTML])
                tampered_tags = _count_tags(content[HTML])

                # Check error-based SQLi
                for dbms, regex_list in DBMS_ERRORS.items():
                    for regex in regex_list:
                        if re.search(regex, content[HTML], re.I) and not re.search(regex, original[HTML], re.I):
                            print(f"\n[*] {phase} parameter '{match.group('parameter')}' appears to be error SQLi vulnerable ({dbms})")
                            retval = vulnerable = True
                            break
                    if vulnerable:
                        break

                # Check resource/tag/hash-based blind SQLi
                if not vulnerable:
                    hash_changed = original_hash != tampered_hash
                    resource_changed = original_resources != tampered_resources
                    tags_changed = original_tags != tampered_tags

                    if hash_changed or resource_changed or tags_changed:
                        print(f"\n[*] {phase} parameter '{match.group('parameter')}' shows content/resource changes, possible SQLi.")
                        retval = vulnerable = True
                        
                if not vulnerable:
                    test_combinations = [
                        (" ", "AND %d=%d", ""),
                        (" ", "OR NOT (%d>%d)", ""),
                        ("'", "AND %d=%d", ""),
                        ("'", "OR NOT (%d>%d)", ""),
                        ("\"", "AND %d=%d", ""),
                        ("\"", "OR NOT (%d>%d)", ""),
                        (")", "AND %d=%d", ""),
                        (")", "OR NOT (%d>%d)", ""),
                        (" ", "AND 1=1", ""),
                        (" ", "AND 1=2", ""),
                        ("'", "OR 'a'='a'", ""),
                        ("'", "OR 'a'='b'", ""),
                    ]

                    for prefix, boolean, suffix in test_combinations:
                        if vulnerable:
                            break
                        template = f"{prefix}{boolean}{suffix}"
                        payloads = {}
                        for flag in (True, False):
                            formatted = _safe_format(template, RANDINT if flag else RANDINT + 1, RANDINT)
                            payload_value = current.replace(match.group(0), f"{match.group(0)}{urllib.parse.quote(formatted, safe='%')}")
                            payloads[flag] = payload_value

                        contents = {flag: _retrieve_content(payloads[flag], data) if phase == GET else _retrieve_content(url, payloads[flag]) for flag in (False, True)}

                        if all(_[HTTPCODE] and _[HTTPCODE] < http.client.INTERNAL_SERVER_ERROR for _ in (original, contents[True], contents[False])):
                            if any(original[_] == contents[True][_] != contents[False][_] for _ in (HTTPCODE, TITLE)):
                                vulnerable = True
                            else:
                                ratios = {flag: difflib.SequenceMatcher(None, original[TEXT], contents[flag][TEXT]).quick_ratio() for flag in (False, True)}
                                vulnerable = all(ratios.values()) and min(ratios.values()) < FUZZY_THRESHOLD < max(ratios.values()) and abs(ratios[True] - ratios[False]) > FUZZY_THRESHOLD / 10

                        if vulnerable:
                            print(f"\n[*] {phase} parameter '{match.group('parameter')}' appears to be blind SQLi vulnerable (e.g.: '{payloads[True]}')")
                            retval = True
                            break

                if retval:
                    break

            if retval:
                break

        if not usable:
            print(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")
    return retval


def init_options(proxy=None, cookie=None, ua=None, referer=None):
    globals()["_headers"] = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua ), (REFERER, referer))))
    urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy})) if proxy else None)


_URL_REGEX = re.compile(r"^(https?://)?([\w.-]+)(:[0-9]{1,5})?(/[\w\-./%]*|/)?(\?[\w\-=.&%]*)?$", re.IGNORECASE)

def _validate_url_for_bot(url: str) -> Tuple[bool, str]:
    if not url or not _URL_REGEX.match(url):
        return False, "Invalid URL. Example: https://example.com/page?id=1"
    return True, "ok"

class BotSQLiTool:
    def __init__(self):
        self._sem = asyncio.Semaphore(2)

    async def execute(self, command: str) -> Tuple[bool, str]:
        try:
            parts = command.split()
            if len(parts) < 3 or parts[0] != 'sqli' or parts[1] != '-u':
                return False, "Invalid command. Usage: sqli -u <url> [--data 'a=1']"

            url = parts[2]
            ok, msg = _validate_url_for_bot(url)
            if not ok:
                return False, msg

            data: Optional[str] = None
            cookie: Optional[str] = None
            ua: Optional[str] = None
            referer: Optional[str] = None
            proxy: Optional[str] = None

            i = 3
            while i < len(parts):
                if parts[i] == '--data' and i + 1 < len(parts):
                    data = parts[i + 1]
                    i += 2
                elif parts[i] == '--cookie' and i + 1 < len(parts):
                    cookie = parts[i + 1]
                    i += 2
                elif parts[i] == '--user-agent' and i + 1 < len(parts):
                    ua = parts[i + 1]
                    i += 2
                elif parts[i] == '--referer' and i + 1 < len(parts):
                    referer = parts[i + 1]
                    i += 2
                elif parts[i] == '--proxy' and i + 1 < len(parts):
                    proxy = parts[i + 1]
                    i += 2
                else:
                    i += 1

            async with self._sem:
                start = time.time()

                def run_scan_sync():
                    init_options(proxy, cookie, ua, referer)
                    return scan_page(url if url.startswith('http') else f"http://{url}", data)

                loop = asyncio.get_event_loop()
                try:
                    found = await asyncio.wait_for(loop.run_in_executor(None, run_scan_sync), timeout=70)
                except asyncio.TimeoutError:
                    return False, "SQLi scan timed out after 70 seconds"

                elapsed = time.time() - start
                if found:
                    return True, (
                        "✅ Possible SQLi vulnerabilities detected.\n\n"
                        f"📍 Target: {url}\n"
                        f"⏱️ Time: {elapsed:.1f}s\n"
                        "ℹ️ Consider refining parameters (e.g., --data/headers)."
                    )
                else:
                    return True, (
                        "🛡️ No obvious SQLi vulnerabilities detected.\n\n"
                        f"📍 Target: {url}\n"
                        f"⏱️ Time: {elapsed:.1f}s\n"
                        "🔎 Try different parameters or POST data to improve coverage."
                    )
        except Exception as e:
            return False, f"Error running SQLi scan: {str(e)}"

def create_sqli_tool() -> BotSQLiTool:
    return BotSQLiTool()


async def main():
    tool = create_sqli_tool()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python sqli_detector.py 'sqli -u http://example.com/page?id=1'")
        print("  python sqli_detector.py 'sqli -u http://example.com/login --data \"username=admin&password=123\"'")
        print("  python sqli_detector.py 'sqli -u http://example.com --cookie \"session=abc123\"'")
        return
    
    command = " ".join(sys.argv[1:])
    
    print(f"🔍 Starting SQL Injection scan...")
    print(f"📝 Command: {command}\n")
    
    success, result = await tool.execute(command)
    
    if success:
        print(result)
    else:
        print(f"❌ Error: {result}")

if __name__ == "__main__":
    asyncio.run(main())

